"""Small metadata checks for the D34/D35 WHIR trace."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_whir_trace as whir


class Fp3:
    """Tiny independent F97[u]/(u^3-2) oracle for the prefix identity."""

    def __init__(self, a=0, b=0, c=0):
        self.x = (a % 97, b % 97, c % 97)

    def __add__(self, other):
        other = other if isinstance(other, Fp3) else Fp3(other)
        return Fp3(*(a + b for a, b in zip(self.x, other.x)))

    __radd__ = __add__

    def __sub__(self, other):
        other = other if isinstance(other, Fp3) else Fp3(other)
        return Fp3(*(a - b for a, b in zip(self.x, other.x)))

    def __mul__(self, other):
        other = other if isinstance(other, Fp3) else Fp3(other)
        a, b, c = self.x
        d, e, f = other.x
        return Fp3(a * d + 2 * (b * f + c * e), a * e + b * d + 2 * c * f,
                   a * f + b * e + c * d)

    __rmul__ = __mul__

    def __pow__(self, exponent):
        result, base = Fp3(1), self
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        return result

    def __eq__(self, other):
        other = other if isinstance(other, Fp3) else Fp3(other)
        return self.x == other.x


def eq_table(point):
    values = [Fp3(1)]
    for coordinate in point:
        values = [term for value in values
                  for term in (value * (Fp3(1) - coordinate), value * coordinate)]
    return values


def fold(values, challenge):
    half = len(values) // 2
    return [low + challenge * (high - low) for low, high in zip(values[:half], values[half:])]


def round_coefficients(left, right):
    half = len(left) // 2
    out = [Fp3(), Fp3(), Fp3()]
    for a0, a1, b0, b1 in zip(left[:half], left[half:], right[:half], right[half:]):
        da, db = a1 - a0, b1 - b0
        out[0] += a0 * b0
        out[1] += a0 * db + da * b0
        out[2] += da * db
    return out


def poly_mul(left, right):
    out = [Fp3()] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] += a * b
    return out


def rational_geometric_block(amplitudes, bases, size):
    factors = [[Fp3(1), Fp3() - base] for base in bases]
    denominator = [Fp3(1)]
    for factor in factors:
        denominator = poly_mul(denominator, factor)
    numerator = [Fp3()] * len(bases)
    for i, amplitude in enumerate(amplitudes):
        quotient = [Fp3(1)]
        for j, factor in enumerate(factors):
            if i != j:
                quotient = poly_mul(quotient, factor)
        for j, value in enumerate(quotient):
            numerator[j] += amplitude * value
    inverse = [Fp3(1)]
    for degree in range(1, size):
        inverse.append(Fp3() - sum(
            (denominator[j] * inverse[degree - j]
             for j in range(1, min(degree, len(denominator) - 1) + 1)), Fp3()
        ))
    return poly_mul(numerator, inverse)[:size]


def test_whir_trace_covers_native_geometry_and_fails_closed():
    for dimension, first_switch_replays in ((35, 64), (34, 32)):
        report = whir.trace(dimension)
        assert len(report["oracles"]) == 12
        assert [row["fold"] for row in report["oracles"]] == [7] + [2] * 11
        assert len(report["mask_groups"]) == 23
        assert sum(group["width"] for group in report["mask_groups"]) == 40
        assert report["commit_source_replays_by_oracle"][1] == first_switch_replays
        assert report["opening_source_replays_total"] == 12
        assert report["ood_source_replays_if_no_folded_state"] == 11
        assert report["complete_peak_bytes"] is None
        assert report["shared_initial_root_reservation_do_not_sum_across_traces"] == (
            whir.SHARED_INITIAL_ROOT_CACHE + whir.SHARED_INITIAL_ROOT_SECRETS
        )
        assert report["complete_work_upper"] is None
        assert report["runtime_upper_seconds"] is None and not report["admitted"]
        assert report["native_dense_guard_bytes"] > whir.ARENA
        assert report["post_fold7_eval_plus_weights_bytes"] >= whir.ARENA
        assert report["events"][-1]["known_live_bytes_after"] == (
            whir.SHARED_INITIAL_ROOT_CACHE + whir.SHARED_INITIAL_ROOT_SECRETS
        )
        assert all(key.startswith("shared:")
                   for key in report["events"][-1]["known_live_buffers_after"])
        initial = report["selected_initial_sumcheck"]
        assert initial["selected_claim_count"] == initial["source_passes"] == 1
        assert initial["prefix_accumulator_fp3_cells"] == 128
        assert initial["full_s1_getter_original_cell_reads"] == 1 << dimension
        later = report["later_covector_candidate"]
        assert later["maximum_power_terms"] == 11 * 513
        assert later["maximum_terms_including_eq"] == 1 + 11 * 513
        assert later["total_source_scans"] == 22
        assert later["total_rational_blocks"] == (269 if dimension == 35 else 142)
        assert later["weighted_numerator_product_tree_leaf_terms"] == (
            229_824 if dimension == 35 else 144_666
        )
        assert later["block_convolution_fp3_butterflies_excluding_inverse_precomputation"] == (
            23_613_929_984 if dimension == 35 else 11_802_770_816
        )
        assert later["block_convolution_base_coordinate_butterflies"] == 3 * (
            23_613_929_984 if dimension == 35 else 11_802_770_816
        )
        assert later["block_scratch_peak_named_bytes"] == 507_445_224
        assert later["block_amplitude_advance_fp3_products"] == (
            162_108 if dimension == 35 else 76_950
        )
        assert later["two_prefix_folds_amplitude_fp3_products_upper"] == 135_432
        reference = later["finite_reference_precompute"]
        assert reference["Q_build_fp3_products_and_additions_upper"] == 66_598_686
        assert reference["all_block_numerator_fp3_products_and_additions_upper"] == (
            785_296_296 if dimension == 35 else 647_395_740
        )
        assert reference["Q_inverse_recurrence_fp3_products_and_additions_upper"] == (
            14_539_536_648 if dimension == 35 else 12_633_300_552
        )
        assert not reference["optimized_product_tree_or_Newton_credit"]
        assert not later["native_implementation_present"]

        names = [event["event"] for event in report["events"]]
        initial_commit = report["events"][names.index("commit_data_0")]
        assert "shared:initial_root_caches" in initial_commit["known_live_buffers_after"]
        assert "commit:twiddles" in initial_commit["known_live_buffers_after"]
        assert not any(key.startswith("data:0:cache") for key in initial_commit["known_live_buffers_after"])
        for round_index in range(11):
            commit = report["events"][names.index(f"commit_data_{round_index + 1}")]
            assert f"data:{round_index + 1}:cache" in commit["known_live_buffers_after"]
            assert f"commit:{round_index + 1}:twiddles" in commit["known_live_buffers_after"]
            assert names.index(f"commit_data_{round_index + 1}") < names.index(
                f"ood_{round_index}"
            ) < names.index(f"query_open_data_{round_index}") < names.index(
                f"sumcheck_fold_2_round_{round_index}"
            )


def test_remainder_geometry_counts_padding_and_base_limbs_once():
    w, a = whir.oracle_geometry(35), whir.oracle_geometry(34)
    assert w[0]["base_columns"] == a[0]["base_columns"] == 128
    assert w[1]["base_columns"] == a[1]["base_columns"] == 12
    assert w[0]["remainder_blocks_per_base_column"] == 129
    assert a[0]["remainder_blocks_per_base_column"] == 65
    assert sum(row["remainder_butterflies"] for row in w) == 3_152_737_468_416
    assert sum(row["remainder_butterflies"] for row in a) == 1_593_688_457_216


def test_one_pass_rank_one_contraction_matches_seven_dense_prefix_rounds():
    dimension, prefix_rounds = 10, 7
    values = [Fp3(i * i + 3, 5 * i + 1, 7 * i * i + 2) for i in range(1 << dimension)]
    point = [Fp3(i + 2, 2 * i + 3, 3 * i + 5) for i in range(dimension)]
    challenges = [Fp3(11 * i + 1, 13 * i + 2, 17 * i + 3) for i in range(prefix_rounds)]

    suffix_weights = eq_table(point[prefix_rounds:])
    suffix = len(suffix_weights)
    contracted = [
        sum((values[prefix * suffix + j] * weight for j, weight in enumerate(suffix_weights)), Fp3())
        for prefix in range(1 << prefix_rounds)
    ]
    prefix_weights = eq_table(point[:prefix_rounds])
    dense_values, dense_weights = values[:], eq_table(point)

    for challenge in challenges:
        assert round_coefficients(contracted, prefix_weights) == round_coefficients(
            dense_values, dense_weights
        )
        contracted, prefix_weights = fold(contracted, challenge), fold(prefix_weights, challenge)
        dense_values, dense_weights = fold(dense_values, challenge), fold(dense_weights, challenge)
    assert contracted[0] * prefix_weights[0] == sum(
        (value * weight for value, weight in zip(dense_values, dense_weights)), Fp3()
    )


def test_rational_blocks_and_prefix_fold_match_dense_power_covectors():
    amplitudes = [Fp3(i + 2, i * i + 1, 3 * i + 4) for i in range(5)]
    bases = [Fp3(2 * i + 1, 3 * i + 2, 5 * i + 3) for i in range(5)]
    block, total = 8, 64
    generated = []
    current = amplitudes[:]
    for _ in range(total // block):
        generated.extend(rational_geometric_block(current, bases, block))
        current = [amplitude * (base ** block) for amplitude, base in zip(current, bases)]
    direct = [sum((a * (x ** j) for a, x in zip(amplitudes, bases)), Fp3())
              for j in range(total)]
    assert generated == direct

    challenge, variables = Fp3(7, 11, 13), 6
    dense = direct[:1 << variables]
    folded = fold(dense, challenge)
    scaled = [
        amplitude * (Fp3(1) - challenge + challenge * (base ** (1 << (variables - 1))))
        for amplitude, base in zip(amplitudes, bases)
    ]
    assert folded == [sum((a * (x ** j) for a, x in zip(scaled, bases)), Fp3())
                      for j in range(1 << (variables - 1))]


def test_alloc_free_trace_rejects_invalid_lifetimes():
    events = whir.Events()
    events.add("allocate", "none", allocate={"x": 1})
    try:
        events.add("duplicate", "none", allocate={"x": 1})
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate allocation accepted")
    try:
        events.add("missing", "none", free=("y",))
    except ValueError:
        pass
    else:
        raise AssertionError("missing free accepted")


def test_a_s1_retention_opens_immutable_s1_before_in_place_fold():
    schedule = whir.a_s1_retention_schedule()
    assert schedule["original_A_source_passes_through_S1"] == 36
    assert schedule["current_A_passes_with_external_512_commit_and_26_range"] == 574
    assert schedule["retained_S1_read_passes_through_S2_birth"] == 21
    assert schedule["S1_bytes"] == 3_221_225_472
    assert schedule["S2_bytes"] == 805_306_368
    assert schedule["S1_query_named_workspace_bytes"] == 145_752_056
    assert schedule["S1_query_remainder_fp_butterflies"] == 29_104_275_456
    assert schedule["retained_S1_read_bytes_through_S2_birth"] == 67_645_734_912
    assert schedule["retained_state_read_passes_total"] == 80
    assert schedule["retained_state_logical_read_bytes_total"] == 74_893_479_936
    assert schedule["all_retained_state_write_bytes"] == 4_294_966_272
    assert schedule["fp3_interpolations_all_retained_folds_and_virtual_getters"] == 2_027_246_624
    assert schedule["all_data_commit_encoded_write_bytes"] == 68_720_787_456
    assert schedule["all_data_commit_source_replays"] == 58
    assert schedule["all_query_remainder_fp_butterflies"] == 1_574_902_169_600
    assert sum(schedule["retained_state_read_passes_breakdown"].values()) == 80
    assert schedule["fp3_interpolations_total_before_later_S2_work"] == 1_879_048_192
    assert schedule["margin_after_illustrative_extra_bytes"] == 173_610_944
    assert schedule["root_cache_bytes"]["S1_h8"] == 150_994_912
    assert schedule["root_cache_bytes"]["S2_h12"] == 2_359_264
    assert schedule["known_named_peak_fits_arena"]
    assert schedule["complete_peak_bytes"] is None
    assert not schedule["native_implementation_present"]

    events = {event["event"]: event for event in schedule["events"]}
    commit = events["a_commit_s2_with_s1_immutable"]
    assert "retained:S1_values" in commit["known_live_buffers_after"]
    assert "s2_root:cache_h12" in commit["known_live_buffers_after"]
    assert "s2_commit:twiddles" in commit["known_live_buffers_after"]
    ordered = [event["event"] for event in schedule["events"]]
    assert ordered.index("a_open_s1_with_fixed_B17") < ordered.index(
        "a_fold_s1_to_s2_in_place_and_fence"
    )
    folded = events["a_fold_s1_to_s2_in_place_and_fence"]
    assert "retained:S1_values" not in folded["known_live_buffers_after"]
    assert "retained:S2_values_in_s1_allocation" in folded["known_live_buffers_after"]
    for state_index in range(2, 11):
        commit_name = f"a_commit_s{state_index + 1}_with_s{state_index}_immutable"
        assert ordered.index(commit_name) < ordered.index(f"a_open_s{state_index}_before_mutation")
        assert ordered.index(f"a_open_s{state_index}_before_mutation") < ordered.index(
            f"a_fold_s{state_index}_to_s{state_index + 1}_in_place_and_fence"
        )
        commit_state = events[commit_name]["known_live_buffers_after"]
        assert any(key.startswith(f"retained:S{state_index}_values") for key in commit_state)
        assert f"s{state_index + 1}_root:cache_h12" in commit_state
    assert schedule["analytic_lifecycle_reaches_final_opening"]
    assert ordered[-1] == "a_release_attempt_keep_shared_roots"
    assert schedule["events"][-1]["known_live_bytes_after"] == (
        whir.SHARED_INITIAL_ROOT_CACHE + whir.SHARED_INITIAL_ROOT_SECRETS
    )
    base = events["a_base_open_s11_and_masks"]
    assert sum(key.startswith("mask:") for key in base["known_live_buffers_after"]) == 23
    assert "s11_root:cache_h12" in base["known_live_buffers_after"]


def test_native_salted_hash_census_includes_chunk_parents_and_no_digest_buffer():
    # Native CPU check uses these four row widths and 16 leaves.
    for columns in (4, 7, 128, 384):
        r=whir.salted_hash_work(16,columns)
        leaf=len(b'volta-zk/c71/b12/merkle/leaf/v1\0')+8*(columns+4)
        chunks=[min(1024,leaf-i) for i in range(0,leaf,1024)]
        leaf_compressions=sum((n+63)//64 for n in chunks)+len(chunks)-1
        assert r['blake3_compressions']==16*leaf_compressions+15*2
        assert r['leaf_field_read_bytes']==16*columns*8
        assert r['extra_global_leaf_digest_buffer_bytes']==0
        assert r['salt_candidates_depend_on_rejection']
    assert whir.salted_hash_work(1<<31,128)['leaf_field_read_bytes']==1<<41

    # Exact small strided native case: 128 leaves in eight 16-row cosets.
    r=whir.salted_hash_work(128,128,16)
    assert r['internal_digest_read_bytes']==32*128+32*112+64*15
    assert r['internal_digest_write_bytes']==32*112+32*16+32*15
    assert r['salt_start_write_current_copy_bytes']==24*16

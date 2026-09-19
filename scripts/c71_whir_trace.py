#!/usr/bin/env python3
"""Metadata-only trace of the selected B12 WHIR D34/D35 schedules.

The trace follows the Rust transcript and buffer geometry.  It deliberately
leaves source getters, small-space sumcheck and native allocator/hash costs
unknown; consequently it grants no runtime or protocol admission.
"""

import json


ARENA = 6_442_450_944
FP_BYTES = 8
FP3_BYTES = 24
QUERIES = 512
TREE_CUT = 12
INITIAL_COSET_ROWS = 1 << 22
SWITCH_COSET_ROWS = 1 << 24
MASK_MESSAGE = 2048
MASK_RANDOMNESS = 512
MASK_DOMAIN = 1 << 15
SALT_ELEMENTS = 4
SHARED_INITIAL_ROOT_CACHE = 188_743_552
SHARED_INITIAL_ROOT_SECRETS = 4 * (1536 * 128 * FP_BYTES + 32)


def top_cache_bytes(height, cut=TREE_CUT):
    subtrees = height >> cut
    return (2 * subtrees - 1) * 32 + subtrees * 8


def oracle_geometry(dimension):
    remaining, rows = dimension, []
    while remaining > 6:
        first = not rows
        fold = 7 if first else 2
        columns = 1 << fold
        limbs = 1 if first else 3
        randomness_rows = 1536 if first else 512
        message_rows = 1 << (remaining - fold)
        occupied = 8 * (message_rows + randomness_rows)
        height = 1 << (occupied - 1).bit_length()
        base_columns = columns * limbs
        cap = min(1 << 21, height)
        coefficient_rows = message_rows + randomness_rows
        blocks = (coefficient_rows + cap - 1) // cap
        rounded_cells = base_columns * blocks * cap
        log_fft = (2 * cap).bit_length() - 1
        rows.append({
            "oracle": len(rows),
            "source_dimension": remaining,
            "fold": fold,
            "field": "Fp" if first else "Fp3",
            "columns": columns,
            "base_columns": base_columns,
            "message_rows_per_column": message_rows,
            "randomness_rows_per_column": randomness_rows,
            "height": height,
            "encoded_bytes": height * base_columns * FP_BYTES,
            "top_cache_and_offsets_bytes": top_cache_bytes(height),
            "salt_elements_per_row": SALT_ELEMENTS,
            "salt_xof_bytes_per_commit_or_full_replay": height * SALT_ELEMENTS * FP_BYTES,
            "remainder_cap": cap,
            "remainder_blocks_per_base_column": blocks,
            "remainder_source_base_cells": base_columns * coefficient_rows,
            "remainder_rounded_base_cells": rounded_cells,
            "remainder_butterflies": rounded_cells * 4 * log_fft,
            "remainder_pointwise_products": rounded_cells * 4,
            "remainder_inverse_normalizations": rounded_cells * 4,
        })
        remaining -= fold
    return rows


def mask_groups(folds):
    widths = [folds[0]]
    for fold in folds[1:]:
        widths.extend((1, fold))
    groups = []
    for index, width in enumerate(widths):
        codeword = MASK_DOMAIN * width * FP3_BYTES
        salts = MASK_DOMAIN * SALT_ELEMENTS * FP_BYTES
        # Conservative explicit tree: one digest for every leaf and internal node.
        digests = (2 * MASK_DOMAIN - 1) * 32
        secrets = width * (MASK_MESSAGE + MASK_RANDOMNESS + MASK_MESSAGE) * FP3_BYTES
        groups.append({
            "group": index,
            "kind": "sumcheck" if index == 0 or index % 2 == 0 else "switch",
            "width": width,
            "message_length": MASK_MESSAGE,
            "randomness_length": MASK_RANDOMNESS,
            "height": MASK_DOMAIN,
            "codeword_bytes": codeword,
            "salt_bytes_if_retained": salts,
            "tree_digest_bytes_upper": digests,
            "message_randomness_covector_bytes_upper": secrets,
            "retained_bytes_upper": codeword + salts + digests + secrets,
        })
    return groups


def mask_commit_work(group):
    return {
        "codeword_bytes": group["codeword_bytes"],
        "salt_bytes": group["salt_bytes_if_retained"],
        "leaf_hashes": MASK_DOMAIN,
        "binary_internal_hashes": MASK_DOMAIN - 1,
    }


def salted_hash_work(height, base_columns, coset_rows=INITIAL_COSET_ROWS):
    """Native b12/streaming.rs codec, one completed binary Merkle tree.

    These are exact algorithmic reads/writes, not physical transactions. Salt
    rejection consumes variable bytes; recorded XOF offsets preserve that order.
    CPU Hasher/PrivateRng states are measured separately, never GPU scratch credit.
    """
    if height < 1 or height & (height-1) or base_columns < 4:
        raise ValueError('power-of-two tree and at least four columns required')
    if coset_rows < 1 or coset_rows & (coset_rows-1):
        raise ValueError('power-of-two coset required')
    rows=min(height,coset_rows)
    leaf = len(b'volta-zk/c71/b12/merkle/leaf/v1\0') + 8*(base_columns+4)
    node = len(b'volta-zk/c71/b12/merkle/node/v1\0') + 64
    def compressions(n): return (n+63)//64+(n+1023)//1024-1
    return {
        'leaf_hashes':height, 'internal_hashes':height-1,
        'leaf_field_read_bytes':height*base_columns*8,
        'leaf_digest_write_bytes':height*32,
        'internal_digest_read_bytes':32*height+32*(height-rows)+64*(rows-1),
        'internal_digest_write_bytes':32*(height-rows)+32*rows+32*(rows-1),
        'frontier_leaf_digest_reads_bytes':32*height,
        'frontier_reads_bytes':32*(height-rows),
        'frontier_writes_bytes':32*(height-rows),
        'coset_roots_write_bytes':32*rows,
        'upper_tree_read_bytes':64*(rows-1),
        'upper_tree_write_bytes':32*(rows-1),
        'salt_start_write_current_copy_bytes':24*rows,
        'retained_subtree_offset_write_bytes':8*((height+(1<<TREE_CUT)-1)>>TREE_CUT),
        'hash_input_bytes':height*leaf+(height-1)*node,
        'blake3_compressions':height*compressions(leaf)+(height-1)*compressions(node),
        'salt_candidate_bytes_lower':height*32,
        'salt_prescan_candidate_bytes_lower':height*32,
        'salt_prescan_and_replay_candidate_bytes_lower':height*64,
        'salt_cursor_logical_read_write_bytes':height*16,
        'salt_offsets_are_inside_existing_start_current_slots':True,
        'private_coin_stream_byte_cap':1 << 40,
        'salt_candidates_depend_on_rejection':True,
        'sampler_offsets_retained_per_subtree':True,
        'extra_global_leaf_digest_buffer_bytes':0,
        'CPU_refinement_only':True,
    }


def commit_fft_work(height, columns, coset_rows):
    """Algorithmic traffic of the square kernels plus odd-log parity merge.

    The producer writes parity-scattered coefficients for odd log sizes; no
    extra full-array shuffle is hidden here. That producer integration is an
    open gate. Twiddle initialization, coefficient scatter and hash are separate.
    Logical accesses are not an HBM measurement or a service-rate guarantee.
    """
    rows = min(height, coset_rows)
    if rows < 4 or rows & (rows - 1) or height % rows:
        raise ValueError("FFT requires power-of-two cosets of at least four rows")
    log = rows.bit_length() - 1
    odd = log % 2
    cells = height * columns
    butterflies = cells * log // 2
    return {
        "log2_coset_rows": log,
        "cosets": height // rows,
        "whole_value_array_passes_per_coset": 5 + odd,
        "radix2_butterflies": butterflies,
        "square_transpose_twiddle_products": cells,
        "odd_merge_butterflies": cells // 2 if odd else 0,
        "value_logical_read_bytes": (5 + odd) * cells * 8,
        "value_logical_write_bytes": (5 + odd) * cells * 8,
        "twiddle_logical_read_bytes": (butterflies + cells) * 8,
        "extra_global_shuffle_buffer_bytes": 0,
        "producer_parity_scatter_required": bool(odd),
        "producer_scatter_integrated": False,
        "physical_HBM_complete": False,
    }


def commit_workspace(oracle, coset_rows=None):
    if coset_rows is None:
        coset_rows = INITIAL_COSET_ROWS if oracle["oracle"] == 0 else SWITCH_COSET_ROWS
    if not isinstance(coset_rows, int) or coset_rows <= 0 or coset_rows & (coset_rows - 1):
        raise ValueError("coset rows must be a positive power of two")
    coset_rows = min(coset_rows, oracle["height"])
    cosets = oracle["height"] // coset_rows
    frontier = 32 * coset_rows * ((cosets).bit_length() - 1)
    return {
        "coset_rows": coset_rows,
        "source_replays": cosets,
        "coset_buffer_bytes": coset_rows * oracle["base_columns"] * FP_BYTES,
        "frontier_bytes": frontier,
        "twiddle_bytes": 8 * coset_rows,
        "salt_offsets_bytes": 16 * coset_rows,
        "coefficient_pad_bytes": (
            oracle["randomness_rows_per_column"] * oracle["base_columns"] * FP_BYTES
        ),
        "encoded_write_bytes": oracle["encoded_bytes"],
        "salt_xof_bytes": oracle["salt_xof_bytes_per_commit_or_full_replay"],
        "salted_hash_work": salted_hash_work(oracle["height"], oracle["base_columns"], coset_rows),
        "fft_work": commit_fft_work(oracle["height"], oracle["base_columns"], coset_rows),
    }


def remainder_workspace(oracle, cap=None):
    cap = oracle["remainder_cap"] if cap is None else min(cap, oracle["height"])
    columns = oracle["base_columns"]
    levels = cap.bit_length() - 1
    parts = {
        "selected_rows": cap * columns * FP_BYTES,
        "product_tree": 8 * ((levels + 3) * cap - 1),
        "reciprocals": 8 * (levels + 1) * cap,
        "fixed_spectra": 32 * (levels + 1) * cap,
        "fft_work": 64 * cap,
        "remainder_pingpong": 16 * cap,
        "source_remainder": 8 * cap,
        "points": 8 * cap,
        "twiddles": 16 * cap,
        "pad_shift_and_spectrum": 24 * cap,
    }
    coefficient_rows = oracle["message_rows_per_column"] + oracle["randomness_rows_per_column"]
    blocks = (coefficient_rows + cap - 1) // cap
    rounded = oracle["base_columns"] * blocks * cap
    log_fft = (2 * cap).bit_length() - 1
    return {
        "buffers": parts,
        "bytes": sum(parts.values()),
        "cap": cap,
        "blocks_per_base_column": blocks,
        "rounded_base_cells": rounded,
        "fp_butterflies": rounded * 4 * log_fft,
        "fp_pointwise_products": rounded * 4,
        "fp_inverse_normalizations": rounded * 4,
    }


def a_s1_retention_schedule(s2_coset_rows=1 << 23, successor_coset_rows=1 << 24,
                            reserve_s1_capacity=False):
    """Bounded A-only alternative from the installed root through the base opening."""
    dimension = 34
    oracles = oracle_geometry(dimension)
    masks = mask_groups([row["fold"] for row in oracles])
    covector = later_covector_schedule(dimension)
    events = Events()
    events.add(
        "a_reserve_shared_initial_roots",
        "reuse the single global W plus three-A initial-root reservation",
        allocate={
            "shared:initial_root_caches": SHARED_INITIAL_ROOT_CACHE,
            "shared:initial_root_pad_and_seed_descriptors": SHARED_INITIAL_ROOT_SECRETS,
        },
    )
    events.add(
        "a_initial_sumcheck",
        "one original-A scan contracts the singleton claim before the first switch",
        allocate={"mask:0": masks[0]["retained_bytes_upper"],
                  "prefix:accumulators": 128 * FP3_BYTES,
                  "prefix:equality": 128 * FP3_BYTES},
        work={**selected_initial_sumcheck(dimension), **mask_commit_work(masks[0])},
    )
    events.add(
        "a_release_prefix_sumcheck_arrays",
        "seven challenges fixed; virtual S1 needs only the retained transcript coordinates",
        free=("prefix:accumulators", "prefix:equality"),
    )

    s1 = oracles[1]
    commit1 = commit_workspace(s1, 1 << 24)
    commit1_live = {
        "s1_commit:coset": commit1["coset_buffer_bytes"],
        "s1_commit:frontier": commit1["frontier_bytes"],
        "s1_commit:twiddles": commit1["twiddle_bytes"],
        "s1_commit:salt_offsets": commit1["salt_offsets_bytes"],
        "s1_root:pad_secret": commit1["coefficient_pad_bytes"],
        "s1_root:cache_h8": top_cache_bytes(s1["height"], 8),
        "s1_root:seed": 32,
    }
    events.add(
        "a_commit_s1_without_value_retention",
        "build and observe S1 root; cache h8 is born while the hashes are available",
        allocate=commit1_live,
        work={
            "original_A_source_passes": commit1["source_replays"],
            "encoded_write_bytes": commit1["encoded_write_bytes"],
            "salt_xof_bytes": commit1["salt_xof_bytes"],
        },
        unknown=("native folded getter/hash traffic",),
    )
    events.add(
        "a_retain_s1_root",
        "retain S1 pad, seed and h8 cache; no S1 value array exists yet",
        free=tuple(key for key in commit1_live if key.startswith("s1_commit:")),
    )
    events.add(
        "a_commit_switch_mask_0",
        "observe the first switch-mask root before OOD",
        allocate={"mask:1": masks[1]["retained_bytes_upper"]},
        work=mask_commit_work(masks[1]),
    )
    events.add(
        "a_ood_s1",
        "post-root OOD evaluation costs one additional original-A pass",
        work={"original_A_source_passes": 1},
    )
    initial_open = remainder_workspace(oracles[0])
    initial_open_live = {
        f"a_open_initial:{key}": value for key, value in initial_open["buffers"].items()
    }
    events.add(
        "a_open_initial",
        "open the immutable installed A root before any S1 value retention",
        allocate=initial_open_live,
        work={
            "original_A_source_passes": 1,
            "remainder_fp_butterflies": initial_open["fp_butterflies"],
            "remainder_fp_pointwise_products": initial_open["fp_pointwise_products"],
        },
        unknown=("hash/reader/proof traffic",),
    )
    events.add(
        "a_release_initial_open",
        "initial A query fixed",
        free=tuple(initial_open_live),
    )
    s1_bytes = (1 << s1["source_dimension"]) * FP3_BYTES
    events.add(
        "a_regenerate_and_retain_s1",
        "one post-opening A scan writes immutable S1; later virtual getters read this array",
        allocate={"retained:S1_values": s1_bytes},
        work={"original_A_source_passes": 1, "S1_fp3_write_bytes": s1_bytes},
        unknown=("physical getter/write traffic",),
    )
    events.add(
        "a_sumcheck_s1_two_rounds",
        "two adaptive scans read retained S1 and define the virtual S2 getter",
        allocate={
            "mask:2": masks[2]["retained_bytes_upper"],
            "covector:0:symbolic_terms": (QUERIES + 1) * (s1["source_dimension"] + 1) * FP3_BYTES,
            "covector:0:block_scratch": covector["block_scratch_peak_named_bytes"],
        },
        work={
            "retained_S1_read_passes": 2,
            "fold1_fp3_interpolations": 1 << (s1["source_dimension"] - 1),
            "candidate_power_terms": covector["batches"][0]["power_terms"],
            "candidate_rational_blocks": (
                covector["batches"][0]["rational_blocks_first_round"]
                + covector["batches"][0]["rational_blocks_second_round"]
            ),
        },
        unknown=("native rational-covector adapter",),
    )
    events.add(
        "a_release_s1_sumcheck_scratch",
        "second challenge fixed; keep only symbolic terms and the immutable S1 array",
        free=("covector:0:block_scratch",),
    )

    s2 = oracles[2]
    commit2 = commit_workspace(s2, s2_coset_rows)
    commit2_live = {
        "s2_commit:coset": commit2["coset_buffer_bytes"],
        "s2_commit:frontier": commit2["frontier_bytes"],
        "s2_commit:twiddles": commit2["twiddle_bytes"],
        "s2_commit:salt_offsets": commit2["salt_offsets_bytes"],
        "s2_root:pad_secret": commit2["coefficient_pad_bytes"],
        "s2_root:cache_h12": top_cache_bytes(s2["height"]),
        "s2_root:seed": 32,
    }
    events.add(
        "a_commit_s2_with_s1_immutable",
        "commit virtual fold2(S1); S1 and both pending roots coexist until S1 is opened",
        allocate=commit2_live,
        work={
            "retained_S1_read_passes": commit2["source_replays"],
            "encoded_write_bytes": commit2["encoded_write_bytes"],
            "salt_xof_bytes": commit2["salt_xof_bytes"],
        },
        unknown=("native fold/FFT/hash traffic",),
    )
    events.add(
        "a_retain_s2_root",
        "retain S2 root state and release its commit workspace",
        free=tuple(key for key in commit2_live if key.startswith("s2_commit:")),
    )
    events.add(
        "a_commit_switch_mask_1",
        "observe the second switch-mask root before OOD",
        allocate={"mask:3": masks[3]["retained_bytes_upper"]},
        work=mask_commit_work(masks[3]),
    )
    events.add(
        "a_ood_s2",
        "evaluate virtual S2 after its root; retained S1 remains immutable",
        work={"retained_S1_read_passes": 1},
    )
    s1_open = remainder_workspace(s1, 1 << 17)
    s1_open_cap = 1 << 17
    s1_open_blocks = (
        s1["message_rows_per_column"] + s1["randomness_rows_per_column"]
        + s1_open_cap - 1
    ) // s1_open_cap
    s1_open_rounded = s1["base_columns"] * s1_open_blocks * s1_open_cap
    s1_open_live = {f"a_open_s1:{key}": value for key, value in s1_open["buffers"].items()}
    events.add(
        "a_open_s1_with_fixed_B17",
        "query S1 under its h8 cache before any in-place mutation",
        allocate=s1_open_live,
        work={
            "retained_S1_read_passes": 1,
            "remainder_fp_butterflies": s1_open_rounded * 4 * 18,
            "remainder_fp_pointwise_products": s1_open_rounded * 4,
        },
        unknown=("hash/reader/proof traffic",),
    )
    events.add(
        "a_release_s1_open_and_root",
        "S1 opening fixed; its old root, pad and seed have reached their last consumer",
        free=tuple(s1_open_live) + ("s1_root:pad_secret", "s1_root:cache_h8", "s1_root:seed"),
    )
    s2_bytes = (1 << s2["source_dimension"]) * FP3_BYTES
    events.add(
        "a_fold_s1_to_s2_in_place_and_fence",
        ("fold in place after predecessor release; preserve the full S1 allocation" if reserve_s1_capacity
         else "fold four prefix chunks into the first quarter, fence, then release the S1 tail"),
        free=("retained:S1_values",),
        allocate={"retained:S2_values_in_s1_allocation": s1_bytes if reserve_s1_capacity else s2_bytes},
        work={
            "retained_S1_read_passes": 1,
            "S2_fp3_write_bytes": s2_bytes,
            "fold2_output_fp3_cells": 1 << s2["source_dimension"],
        },
        unknown=("native in-place kernel/fence",),
    )
    retained_states = [{
        "state": "S1",
        "dimension": s1["source_dimension"],
        "bytes": s1_bytes,
        "read_passes": 2 + commit2["source_replays"] + 1 + 1 + 1,
    }]
    current_value_key = "retained:S2_values_in_s1_allocation"

    for state_index in range(2, len(oracles)):
        current = oracles[state_index]
        round_index = state_index - 1
        covector_batch = covector["batches"][round_index]
        scratch_key = f"covector:{round_index}:block_scratch"
        events.add(
            f"a_sumcheck_s{state_index}_two_rounds",
            f"two adaptive scans read retained S{state_index}",
            allocate={
                f"mask:{2 * state_index}": masks[2 * state_index]["retained_bytes_upper"],
                f"covector:{round_index}:symbolic_terms": (
                    (QUERIES + 1) * (current["source_dimension"] + 1) * FP3_BYTES
                ),
                scratch_key: covector["block_scratch_peak_named_bytes"],
            },
            work={
                f"retained_S{state_index}_read_passes": 2,
                "fold1_fp3_interpolations": 1 << (current["source_dimension"] - 1),
                "candidate_power_terms": covector_batch["power_terms"],
                "candidate_rational_blocks": (
                    covector_batch["rational_blocks_first_round"]
                    + covector_batch["rational_blocks_second_round"]
                ),
            },
            unknown=("native rational-covector adapter",),
        )
        events.add(
            f"a_release_s{state_index}_sumcheck_scratch",
            "second adaptive message fixed; retain symbolic terms only",
            free=(scratch_key,),
        )

        if state_index == len(oracles) - 1:
            # The final two challenges define a dimension-five virtual source.
            # Construction 7.2 reveals that source before drawing final queries.
            final_message = 1 << (current["source_dimension"] - current["fold"])
            fresh_main_bytes = (
                current["height"] * FP3_BYTES
                + current["height"] * SALT_ELEMENTS * FP_BYTES
                + (2 * current["height"] - 1) * 32
                + (final_message + current["randomness_rows_per_column"]) * FP3_BYTES
            )
            events.add(
                "a_base_fresh_commitments",
                "commit fresh main mask and all 23 fresh group blinds before base gamma",
                allocate={
                    "base:fresh_main_and_mask_groups": (
                        fresh_main_bytes + sum(mask["retained_bytes_upper"] for mask in masks)
                    )
                },
                work={
                    "fresh_main_codeword_bytes": current["height"] * FP3_BYTES,
                    "fresh_mask_codeword_bytes": sum(mask["codeword_bytes"] for mask in masks),
                },
                unknown=("base-case dot products",),
            )
            events.add(
                "a_base_reveal_virtual_final",
                "after gamma, one S11 scan forms the small blinded dimension-five source",
                work={"retained_S11_read_passes": 1,
                "virtual_fold2_fp3_interpolations": 3 * final_message},
            )
            final_open = remainder_workspace(current, 1 << 17)
            final_open_live = {
                f"a_base_open_s11:{key}": value for key, value in final_open["buffers"].items()
            }
            events.add(
                "a_base_open_s11_and_masks",
                "draw final positions, open immutable S11 plus fresh and carried mask groups",
                allocate=final_open_live,
                work={
                    "retained_S11_read_passes": 1,
                    "remainder_fp_butterflies": final_open["fp_butterflies"],
                    "remainder_fp_pointwise_products": final_open["fp_pointwise_products"],
                    "mask_groups_opened": len(masks),
                    "mask_vectors_opened": sum(mask["width"] for mask in masks),
                },
                unknown=("mask multiproofs/hash work", "proof bytes", "terminal OpeningMac work"),
            )
            events.add(
                "a_release_attempt_keep_shared_roots",
                "final opening fixed; release all proof-local arrays, roots, pads, seeds and masks",
                free=tuple(key for key in events.live if not key.startswith("shared:")),
            )
            retained_states.append({
                "state": "S11",
                "dimension": current["source_dimension"],
                "bytes": (1 << current["source_dimension"]) * FP3_BYTES,
                "read_passes": 4,
            })
            break

        successor = oracles[state_index + 1]
        commit = commit_workspace(successor, successor_coset_rows)
        commit_live = {
            f"s{state_index + 1}_commit:coset": commit["coset_buffer_bytes"],
            f"s{state_index + 1}_commit:frontier": commit["frontier_bytes"],
            f"s{state_index + 1}_commit:twiddles": commit["twiddle_bytes"],
            f"s{state_index + 1}_commit:salt_offsets": commit["salt_offsets_bytes"],
            f"s{state_index + 1}_root:pad_secret": commit["coefficient_pad_bytes"],
            f"s{state_index + 1}_root:cache_h12": top_cache_bytes(successor["height"]),
            f"s{state_index + 1}_root:seed": 32,
        }
        events.add(
            f"a_commit_s{state_index + 1}_with_s{state_index}_immutable",
            "commit the virtual fold2 successor while predecessor values and root remain immutable",
            allocate=commit_live,
            work={
                f"retained_S{state_index}_read_passes": commit["source_replays"],
                "encoded_write_bytes": commit["encoded_write_bytes"],
                "salt_xof_bytes": commit["salt_xof_bytes"],
            },
            unknown=("native fold/FFT/hash traffic",),
        )
        events.add(
            f"a_retain_s{state_index + 1}_root",
            "successor root fixed; release commit workspace only",
            free=tuple(key for key in commit_live if f"s{state_index + 1}_commit:" in key),
        )
        events.add(
            f"a_commit_switch_mask_{state_index}",
            "observe successor switch-mask root before OOD",
            allocate={
                f"mask:{2 * state_index + 1}": masks[2 * state_index + 1]["retained_bytes_upper"]
            },
            work=mask_commit_work(masks[2 * state_index + 1]),
        )
        events.add(
            f"a_ood_s{state_index + 1}",
            "evaluate virtual successor after both roots",
            work={f"retained_S{state_index}_read_passes": 1},
        )
        current_open = remainder_workspace(current, 1 << 17)
        current_open_live = {
            f"a_open_s{state_index}:{key}": value
            for key, value in current_open["buffers"].items()
        }
        events.add(
            f"a_open_s{state_index}_before_mutation",
            "open predecessor root before its values may be overwritten",
            allocate=current_open_live,
            work={
                f"retained_S{state_index}_read_passes": 1,
                "remainder_fp_butterflies": current_open["fp_butterflies"],
                "remainder_fp_pointwise_products": current_open["fp_pointwise_products"],
            },
            unknown=("hash/reader/proof traffic",),
        )
        events.add(
            f"a_release_s{state_index}_open_and_root",
            "predecessor opening fixed; release its root, pad and seed",
            free=tuple(current_open_live) + (
                f"s{state_index}_root:pad_secret",
                f"s{state_index}_root:cache_h12",
                f"s{state_index}_root:seed",
            ),
        )
        successor_value_key = (
            f"retained:S{state_index + 1}_values_in_s{state_index}_allocation"
        )
        successor_bytes = (1 << successor["source_dimension"]) * FP3_BYTES
        events.add(
            f"a_fold_s{state_index}_to_s{state_index + 1}_in_place_and_fence",
            ("fold in place after predecessor release; preserve the full S1 allocation" if reserve_s1_capacity
             else "fold four prefix chunks, fence, then release the predecessor tail"),
            free=(current_value_key,),
            allocate={successor_value_key: s1_bytes if reserve_s1_capacity else successor_bytes},
            work={
                f"retained_S{state_index}_read_passes": 1,
                "successor_fp3_write_bytes": successor_bytes,
                "fold2_fp3_interpolations": 3 * (1 << successor["source_dimension"]),
            },
            unknown=("native in-place kernel/fence",),
        )
        retained_states.append({
            "state": f"S{state_index}",
            "dimension": current["source_dimension"],
            "bytes": (1 << current["source_dimension"]) * FP3_BYTES,
            "read_passes": 2 + commit["source_replays"] + 1 + 1 + 1,
        })
        current_value_key = successor_value_key

    original_passes = commit1["source_replays"] + 4
    retained_s1_passes = 2 + commit2["source_replays"] + 1 + 1 + 1
    retained_read_passes = sum(row["read_passes"] for row in retained_states)
    retained_read_bytes = sum(row["read_passes"] * row["bytes"] for row in retained_states)
    query_workspaces = [initial_open, s1_open] + [
        remainder_workspace(oracles[index], 1 << 17) for index in range(2, len(oracles))
    ]
    commit_rows = [commit1, commit2] + [
        commit_workspace(oracles[index], successor_coset_rows) for index in range(3, len(oracles))
    ]
    fold_interpolations = sum(
        (1 << (oracles[index]["source_dimension"] - 1))
        + (commit_rows[index]["source_replays"] + 2)
        * 3 * (1 << oracles[index + 1]["source_dimension"])
        for index in range(1, len(oracles) - 1)
    )
    final_virtual_cells = 1 << (oracles[-1]["source_dimension"] - oracles[-1]["fold"])
    fold_interpolations += (
        (1 << (oracles[-1]["source_dimension"] - 1)) + 3 * final_virtual_cells
    )
    named_plus_extra = events.peak + 600_000_000
    return {
        "credit": False,
        "scope": "one complete A proof, from installed initial root through the final base opening",
        "events": events.rows,
        "known_named_peak_bytes": events.peak,
        "arena_bytes": ARENA,
        "known_named_peak_fits_arena": events.peak <= ARENA,
        "illustrative_unresolved_extra_slot_bytes": 600_000_000,
        "known_peak_plus_illustrative_extra_bytes": named_plus_extra,
        "margin_after_illustrative_extra_bytes": ARENA - named_plus_extra,
        "complete_peak_bytes": None,
        "original_A_source_passes_through_S1": original_passes,
        "current_A_passes_with_external_512_commit_and_26_range": 512 + 26 + original_passes,
        "retained_S1_read_passes_through_S2_birth": retained_s1_passes,
        "retained_S1_read_bytes_through_S2_birth": retained_s1_passes * s1_bytes,
        "retained_state_rows": retained_states,
        "full_S1_capacity_reserved_through_last_consumer": reserve_s1_capacity,
        "successor_coset_rows_cap": successor_coset_rows,
        "s2_coset_rows_cap": s2_coset_rows,
        "retained_capacity_bytes": s1_bytes if reserve_s1_capacity else 0,
        "retained_state_read_passes_total": retained_read_passes,
        "retained_state_read_passes_breakdown": {
            "two_adaptive_sumcheck_scans": 22,
            "successor_commits": sum(row["source_replays"] for row in commit_rows[1:]),
            "successor_OOD": 10,
            "predecessor_queries": 11,
            "in_place_folds": 10,
            "base_virtual_final_reveal": 1,
        },
        "retained_state_logical_read_bytes_total": retained_read_bytes,
        "retained_S1_read_bytes_are_logical_payload_only": True,
        "original_A_weighted_source_cells": original_passes * (1 << dimension),
        "S1_regeneration_write_bytes": s1_bytes,
        "S2_in_place_write_bytes": s2_bytes,
        "all_retained_state_write_bytes": sum(row["bytes"] for row in retained_states),
        "virtual_fold2_fp3_interpolations_commit_and_ood": (
            (commit2["source_replays"] + 1) * 3 * (1 << s2["source_dimension"])
        ),
        "sumcheck_second_scan_fold1_fp3_interpolations": 1 << (s1["source_dimension"] - 1),
        "in_place_fold2_fp3_interpolations": 3 * (1 << s2["source_dimension"]),
        "fp3_interpolations_total_before_later_S2_work": (
            (commit2["source_replays"] + 1) * 3 * (1 << s2["source_dimension"])
            + (1 << (s1["source_dimension"] - 1))
            + 3 * (1 << s2["source_dimension"])
        ),
        "fp3_interpolations_all_retained_folds_and_virtual_getters": fold_interpolations,
        "S1_bytes": s1_bytes,
        "S2_bytes": s2_bytes,
        "S1_query_cap": 1 << 17,
        "S1_query_named_workspace_bytes": s1_open["bytes"],
        "S1_query_remainder_fp_butterflies": s1_open_rounded * 4 * 18,
        "S1_query_remainder_fp_pointwise_products": s1_open_rounded * 4,
        "all_data_commit_encoded_write_bytes": sum(row["encoded_write_bytes"] for row in commit_rows),
        "all_data_commit_source_replays": sum(row["source_replays"] for row in commit_rows),
        "all_data_commit_fft_work": {key: sum(row["fft_work"][key] for row in commit_rows)
            for key in ("radix2_butterflies", "square_transpose_twiddle_products",
                        "odd_merge_butterflies", "value_logical_read_bytes",
                        "value_logical_write_bytes", "twiddle_logical_read_bytes")},
        "data_commit_fft_by_oracle": [row["fft_work"] for row in commit_rows],
        "all_data_commit_salt_xof_bytes": sum(row["salt_xof_bytes"] for row in commit_rows),
        "all_query_remainder_fp_butterflies": sum(row["fp_butterflies"] for row in query_workspaces),
        "all_query_remainder_fp_pointwise_products": sum(
            row["fp_pointwise_products"] for row in query_workspaces
        ),
        "root_cache_bytes": {
            "S1_h8": top_cache_bytes(s1["height"], 8),
            **{
                f"S{index}_h12": top_cache_bytes(oracles[index]["height"])
                for index in range(2, len(oracles))
            },
        },
        "immutable_until": "S1 query opening is fixed",
        "analytic_lifecycle_reaches_final_opening": True,
        "unknown_residue": [
            "canonical accelerated retained getter/fold and GPU fence; bounded CPU lifecycle checked",
            "rational-covector adapter and its product-tree/Q-inverse arithmetic",
            "FFT/hash/reader/allocator traffic and proof accumulation",
            "mask multiproofs, terminal OpeningMac and complete service-rate bounds",
        ],
        "native_implementation_present": False,
    }


def selected_initial_sumcheck(dimension):
    """One-claim prefix contraction selected by c71_matrix::prove_pcs.

    The first seven variables are the original MSB prefix.  One source pass
    contracts the independent suffix equality weights into 2^7 accumulators;
    the seven ordinary rank-one sumcheck rounds then use only those arrays.
    Their challenges define the virtual S1 getter used by the next commit.
    """
    prefix_rounds = 7
    return {
        "selected_claim_count": 1,
        "original_source_cells": 1 << dimension,
        "source_passes": 1,
        "weighted_source_accumulations": 1 << dimension,
        "prefix_accumulator_fp3_cells": 1 << prefix_rounds,
        "prefix_accumulator_bytes": (1 << prefix_rounds) * FP3_BYTES,
        "prefix_sumcheck_pair_terms": (1 << prefix_rounds) - 1,
        "prefix_rounds": prefix_rounds,
        "prefix_order": "original MSB-first variables",
        "s1_source_dimension": dimension - prefix_rounds,
        "s1_virtual_cells": 1 << (dimension - prefix_rounds),
        "original_values_per_s1_cell": 1 << prefix_rounds,
        "full_s1_getter_original_cell_reads": 1 << dimension,
        "s1_retained": False,
        "endpoint": "the original terminal.x claim at the original PCS point",
        "work_class": "c_source*N + P(1, dimension)",
        "algebraically_source_uniform": True,
        "c71_native_small_space_implementation_present": False,
    }


def later_covector_schedule(dimension):
    """Algebraic source-uniform candidate for the eleven two-round batches.

    The native symbolic verifier carries one Eq term and adds one OOD plus 512
    Pow terms before each batch.  For Pow terms, Q(X)=prod_i(1-x_i X) and the
    weighted numerator generate a fixed block without q work per source cell.
    Prefix folding preserves every base x_i and only rescales its amplitude.
    """
    batches = []
    residual_dimension = dimension - 7
    for batch in range(11):
        cells = 1 << residual_dimension
        first_block = min(1 << 21, cells)
        second_block = min(1 << 21, cells // 2)
        power_terms = (batch + 1) * (QUERIES + 1)
        batches.append({
            "batch": batch,
            "residual_dimension_before_two_rounds": residual_dimension,
            "power_terms": power_terms,
            "terms_including_single_eq": power_terms + 1,
            "source_scans_for_two_sequential_challenges": 2,
            "original_getter_cell_reads": 2 * (1 << dimension),
            "first_round_block_cells": first_block,
            "second_round_block_cells": second_block,
            "rational_blocks_first_round": (cells + first_block - 1) // first_block,
            "rational_blocks_second_round": ((cells // 2) + second_block - 1) // second_block,
            "power_denominator_reusable_across_two_rounds": True,
        })
        residual_dimension -= 2
    fp3_butterflies = sum(
        row[f"rational_blocks_{which}_round"]
        * 2 * row[f"{which}_round_block_cells"]
        * ((2 * row[f"{which}_round_block_cells"]).bit_length() - 1)
        for row in batches for which in ("first", "second")
    )
    fp3_pointwise = sum(
        row[f"rational_blocks_{which}_round"] * 2 * row[f"{which}_round_block_cells"]
        for row in batches for which in ("first", "second")
    )
    denominator_terms = sum(row["power_terms"] for row in batches)
    amplitude_advances = sum(
        row["power_terms"]
        * (row["rational_blocks_first_round"] + row["rational_blocks_second_round"] - 2)
        for row in batches
    )
    reference_q_products = sum(
        row["power_terms"] * (row["power_terms"] + 1) // 2 for row in batches
    )
    reference_numerator_products = sum(
        2 * row["power_terms"] * row["power_terms"]
        * (row["rational_blocks_first_round"] + row["rational_blocks_second_round"])
        for row in batches
    )
    reference_inverse_products = 0
    reference_inverse_spectrum_butterflies = 0
    for row in batches:
        maximum_block = max(row["first_round_block_cells"], row["second_round_block_cells"])
        active_q = min(row["power_terms"], maximum_block - 1)
        reference_inverse_products += (
            active_q * (active_q + 1) // 2
            + (maximum_block - 1 - active_q) * active_q
        )
        for block in {row["first_round_block_cells"], row["second_round_block_cells"]}:
            reference_inverse_spectrum_butterflies += block * ((2 * block).bit_length() - 1)
    # Three reusable length-2B Fp3 arrays, four length-B arrays, a full padded
    # denominator tree, numerator ping-pong, and three q-cap work vectors.
    block_scratch_peak = (
        10 * (1 << 21) * FP3_BYTES
        + 131_071 * FP3_BYTES
        + 2 * 8192 * FP3_BYTES
        + 3 * 8192 * FP3_BYTES
    )
    return {
        "basis_identity": "one folded Eq term plus accumulated scaled Pow(x_i) terms",
        "new_power_terms_per_batch": QUERIES + 1,
        "maximum_power_terms": 11 * (QUERIES + 1),
        "maximum_terms_including_eq": 1 + 11 * (QUERIES + 1),
        "batches": batches,
        "total_source_scans": 2 * len(batches),
        "total_original_getter_cell_reads": 2 * len(batches) * (1 << dimension),
        "total_rational_blocks": sum(
            row["rational_blocks_first_round"] + row["rational_blocks_second_round"]
            for row in batches
        ),
        "denominator_product_tree_leaf_terms": denominator_terms,
        "weighted_numerator_product_tree_leaf_terms": sum(
            row["power_terms"]
            * (row["rational_blocks_first_round"] + row["rational_blocks_second_round"])
            for row in batches
        ),
        "block_convolution_fp3_butterflies_excluding_inverse_precomputation": fp3_butterflies,
        "block_convolution_base_coordinate_butterflies": 3 * fp3_butterflies,
        "block_convolution_pointwise_fp3_products": fp3_pointwise,
        "pointwise_base_products_at_six_mul_per_fp3": 6 * fp3_pointwise,
        "block_amplitude_advance_fp3_products": amplitude_advances,
        "two_prefix_folds_amplitude_fp3_products_upper": 4 * denominator_terms,
        "two_prefix_folds_amplitude_fp3_additions_upper": 4 * denominator_terms,
        "new_base_square_ladder_fp3_squarings_upper": sum(
            (QUERIES + 1) * (row["residual_dimension_before_two_rounds"] - 2)
            for row in batches
        ),
        "Q_constant_term_normalizations": 0,
        "finite_reference_precompute": {
            "strategy": (
                "build Q by descending linear-factor updates; derive each Q/(1-x_i X) by "
                "synthetic recurrence and accumulate P; derive Q^-1 coefficients by recurrence"
            ),
            "Q_build_fp3_products_and_additions_upper": reference_q_products,
            "all_block_numerator_fp3_products_and_additions_upper": reference_numerator_products,
            "Q_inverse_recurrence_fp3_products_and_additions_upper": reference_inverse_products,
            "inverse_spectrum_fp3_butterflies": reference_inverse_spectrum_butterflies,
            "inverse_spectrum_base_coordinate_butterflies": (
                3 * reference_inverse_spectrum_butterflies
            ),
            "normalization_inversions": 0,
            "fits_inside_named_block_scratch": True,
            "optimized_product_tree_or_Newton_credit": False,
            "source_uniform_admission_credit": False,
            "source_uniform_obligation": (
                "bound block-count times numerator work with a source coefficient independent "
                "of q/h; finite D34/D35 arithmetic alone does not discharge this"
            ),
        },
        "block_scratch_peak_named_bytes": block_scratch_peak,
        "block_scratch_parts": {
            "three_length_2B_fp3_arrays": 6 * (1 << 21) * FP3_BYTES,
            "four_length_B_fp3_arrays": 4 * (1 << 21) * FP3_BYTES,
            "padded_denominator_tree_fp3": 131_071 * FP3_BYTES,
            "weighted_numerator_tree_pingpong_fp3": 2 * 8192 * FP3_BYTES,
            "three_q_cap_work_vectors_fp3": 3 * 8192 * FP3_BYTES,
        },
        "block_size_policy": (
            "B_i=min(2^21,current round cells); all selected lengths are powers of two, so no "
            "ragged block exists, and the named peak uses the maximum B=2^21"
        ),
        "block_scratch_last_consumer": (
            "second sumcheck message of that batch; denominator tree and inverse spectrum are "
            "reused across both challenges, then freed"
        ),
        "coefficient_field": (
            "Fp3: STIR bases embed Fp, but each batch also includes an OOD base rho in Fp3"
        ),
        "block_generator": (
            "Q=product(1-x_i*X), P=sum_i a_i*product_{j!=i}(1-x_j*X); "
            "multiply P by Q^-1 mod X^B with two length-2B FFTs after fixed spectra"
        ),
        "next_block": "a_i <- a_i*x_i^B",
        "prefix_fold": "a_i <- a_i*(1-r+r*x_i^(2^(m-1))); x_i unchanged",
        "eq_term": "generate independently from its remaining tensor coordinates in O(source cells)",
        "work_class_conditional": "c_source*N + P(q,h), with fixed B=2^21 and D34/D35 caps",
        "native_implementation_present": False,
        "excluded_work": (
            "optimized Q/product-tree and Newton arithmetic, tensor-Eq generation, source "
            "folding/getter, hashing and allocator traffic; the separate schoolbook/recurrence "
            "reference bounds only P/Q precomputation"
        ),
    }


class Events:
    def __init__(self):
        self.live = {}
        self.rows = []
        self.peak = 0

    def add(self, name, transcript, allocate=None, free=(), work=None, unknown=()):
        allocate = allocate or {}
        for key in free:
            if key not in self.live:
                raise ValueError(f"free of absent buffer {key} at {name}")
            del self.live[key]
        for key, value in allocate.items():
            if key in self.live or value < 0:
                raise ValueError(f"invalid allocation {key} at {name}")
            self.live[key] = value
        total = sum(self.live.values())
        self.peak = max(self.peak, total)
        self.rows.append({
            "sequence": len(self.rows),
            "event": name,
            "transcript": transcript,
            "allocate": allocate,
            "free": list(free),
            "known_live_bytes_after": total,
            "known_live_buffers_after": dict(self.live),
            "work": work or {},
            "unknown": list(unknown),
        })


def trace(dimension, initial_coset_rows=INITIAL_COSET_ROWS):
    if dimension not in (34, 35):
        raise ValueError("only the selected D34/D35 profiles are traced")
    oracles = oracle_geometry(dimension)
    covector = later_covector_schedule(dimension)
    folds = [row["fold"] for row in oracles]
    masks = mask_groups(folds)
    events = Events()

    events.add(
        "reserve_shared_initial_roots",
        "worst response keeps installed W and three A initial roots and replay secrets",
        allocate={
            "shared:initial_root_caches": SHARED_INITIAL_ROOT_CACHE,
            "shared:initial_root_pad_and_seed_descriptors": SHARED_INITIAL_ROOT_SECRETS,
        },
    )

    initial = oracles[0]
    c = commit_workspace(initial, initial_coset_rows)
    events.add(
        "commit_data_0",
        "observe initial data root before opening claims",
        allocate={
            "commit:coset": c["coset_buffer_bytes"],
            "commit:frontier": c["frontier_bytes"],
            "commit:twiddles": c["twiddle_bytes"],
            "commit:salt_offsets": c["salt_offsets_bytes"],
        },
        work={"source_replays": c["source_replays"], "encoded_write_bytes": c["encoded_write_bytes"],
              "salt_xof_bytes": c["salt_xof_bytes"]},
        unknown=("native FFT/hash/reader traffic", "physical getter bytes"),
    )
    events.add(
        "retain_data_0_root",
        "initial root fixed inside the shared persistent reservation",
        free=("commit:coset", "commit:frontier", "commit:twiddles", "commit:salt_offsets"),
    )
    events.add(
        "initial_sumcheck_fold_7",
        "observe sumcheck-mask root/endpoints, sample eps, then seven messages/challenges",
        allocate={"mask:0": masks[0]["retained_bytes_upper"],
                  "prefix:accumulators": 128 * FP3_BYTES,
                  "prefix:equality": 128 * FP3_BYTES},
        work={**selected_initial_sumcheck(dimension), **mask_commit_work(masks[0])},
        unknown=("physical source getter/weight generation traffic",),
    )
    events.add(
        "release_prefix_sumcheck_arrays",
        "seven challenges fixed; keep only transcript coordinates for the virtual getter",
        free=("prefix:accumulators", "prefix:equality"),
    )

    for round_index in range(len(oracles) - 1):
        previous, successor = oracles[round_index], oracles[round_index + 1]
        commit = commit_workspace(successor)
        workspace = {
            f"commit:{round_index + 1}:coset": commit["coset_buffer_bytes"],
            f"commit:{round_index + 1}:frontier": commit["frontier_bytes"],
            f"commit:{round_index + 1}:twiddles": commit["twiddle_bytes"],
            f"commit:{round_index + 1}:salt_offsets": commit["salt_offsets_bytes"],
            f"data:{round_index + 1}:pad_secret": commit["coefficient_pad_bytes"],
            f"data:{round_index + 1}:cache": successor["top_cache_and_offsets_bytes"],
            f"data:{round_index + 1}:seed": 32,
        }
        events.add(
            f"commit_data_{round_index + 1}",
            "commit and observe successor root before its OOD point and previous-oracle queries",
            allocate=workspace,
            work={"source_replays": commit["source_replays"],
                  "virtual_source_cells_per_replay": 1 << successor["source_dimension"],
                  "encoded_write_bytes": commit["encoded_write_bytes"],
                  "salt_xof_bytes": commit["salt_xof_bytes"]},
            unknown=("source getter/fold arithmetic", "native FFT/hash traffic"),
        )
        events.add(
            f"retain_data_{round_index + 1}_root",
            "successor root fixed; retain only top cache, salt offsets and a one-time seed",
            free=tuple(
                key for key in workspace
                if not key.endswith((":pad_secret", ":cache", ":seed"))
            ),
        )

        switch_group, sumcheck_group = masks[1 + 2 * round_index:3 + 2 * round_index]
        events.add(
            f"commit_switch_mask_{round_index}",
            "observe switch-mask root before OOD",
            allocate={f"mask:{1 + 2 * round_index}": switch_group["retained_bytes_upper"]},
            work=mask_commit_work(switch_group),
        )
        events.add(
            f"ood_{round_index}",
            "sample rho after successor and switch-mask roots; observe one private OOD answer",
            work={"source_replays_if_no_folded_state": 1},
            unknown=("source-uniform OOD evaluation/getter traffic",),
        )

        rem = remainder_workspace(previous)
        rem_keys = {f"open:{round_index}:{key}": value for key, value in rem["buffers"].items()}
        events.add(
            f"query_open_data_{round_index}",
            "sample 512 distinct STIR positions, rebuild original salted rows, then open/fold",
            allocate=rem_keys,
            work={
                "source_replays": 1,
                "remainder_source_base_cells": previous["remainder_source_base_cells"],
                "remainder_butterflies": previous["remainder_butterflies"],
                "remainder_pointwise_products": previous["remainder_pointwise_products"],
                "remainder_inverse_normalizations": previous["remainder_inverse_normalizations"],
                "salt_xof_bytes_upper": previous["salt_xof_bytes_per_commit_or_full_replay"],
            },
            unknown=("multipoint descent/hash/reader traffic", "proof accumulator bytes"),
        )
        events.add(
            f"release_open_data_{round_index}",
            "opened rows fixed; only their small folded values enter later batching",
            free=tuple(rem_keys)
            + (() if round_index == 0 else (
                f"data:{round_index}:cache",
                f"data:{round_index}:seed",
                f"data:{round_index}:pad_secret",
            )),
        )
        events.add(
            f"sumcheck_fold_2_round_{round_index}",
            "after batching, observe sumcheck-mask root/endpoints and run two messages/challenges",
            allocate={
                f"mask:{2 + 2 * round_index}": sumcheck_group["retained_bytes_upper"],
                f"covector:{round_index}:symbolic_terms": (
                    (QUERIES + 1) * (successor["source_dimension"] + 1) * FP3_BYTES
                ),
                f"covector:{round_index}:block_scratch": covector["block_scratch_peak_named_bytes"],
            },
            work={
                "fold_rounds": 2,
                "native_round_claim_ntt_domain_cells": previous["height"],
                "native_round_claim_ntt_log2_domain": previous["height"].bit_length() - 1,
                "native_round_claim_dense_dot_add_cells": 1 << successor["source_dimension"],
                "candidate_power_terms": covector["batches"][round_index]["power_terms"],
                "candidate_source_scans": 2,
                "candidate_original_getter_cell_reads": 2 * (1 << dimension),
                "candidate_rational_blocks": (
                    covector["batches"][round_index]["rational_blocks_first_round"]
                    + covector["batches"][round_index]["rational_blocks_second_round"]
                ),
                **mask_commit_work(sumcheck_group),
            },
            unknown=("native rational-covector adapter", "physical getter/FFT/hash traffic"),
        )
        events.add(
            f"release_covector_block_scratch_{round_index}",
            "second adaptive message fixed; preserve symbolic terms but release P/Q block workspace",
            free=(f"covector:{round_index}:block_scratch",),
        )

    final = oracles[-1]
    final_message = 1 << (final["source_dimension"] - final["fold"])
    fresh_main_bytes = (
        final["height"] * FP3_BYTES
        + final["height"] * SALT_ELEMENTS * FP_BYTES
        + (2 * final["height"] - 1) * 32
        + (final_message + final["randomness_rows_per_column"]) * FP3_BYTES
    )
    events.add(
        "base_case_fresh_commitments",
        "commit fresh main mask and 23 fresh group blinds before base challenge",
        allocate={
            "base:fresh_main_and_mask_groups": (
                fresh_main_bytes + sum(m["retained_bytes_upper"] for m in masks)
            )
        },
        work={
            "fresh_main_codeword_bytes": final["height"] * FP3_BYTES,
            "fresh_mask_group_codeword_bytes": sum(m["codeword_bytes"] for m in masks),
            "fresh_mask_group_salt_bytes": sum(m["salt_bytes_if_retained"] for m in masks),
        },
        unknown=("base-case dot products",),
    )
    final_rem = remainder_workspace(final)
    final_keys = {f"base:open:{key}": value for key, value in final_rem["buffers"].items()}
    events.add(
        "base_case_open_all",
        "after base challenge reveal pads and query final data oracle plus every mask group",
        allocate=final_keys,
        work={"source_replays": 1, "remainder_butterflies": final["remainder_butterflies"],
              "mask_groups_opened": len(masks), "mask_vectors_opened": sum(m["width"] for m in masks)},
        unknown=("mask multiproofs/hash work", "proof accumulator bytes", "terminal OpeningMac work"),
    )
    events.add(
        "release_attempt_only",
        "proof assembled; burn attempt-local state but retain installed-root pads, seeds and caches",
        free=tuple(key for key in events.live if not key.startswith("shared:")),
    )

    commit_replays = [commit_workspace(row, initial_coset_rows if row["oracle"] == 0 else None)["source_replays"] for row in oracles]
    return {
        "credit": False,
        "dimension": dimension,
        "coverage": "all 12 data oracles, 23 mask groups/40 masks, OOD, queries and base case",
        "candidate_folded_state_policy": (
            "retain no folded source array; conditional replay counters describe regeneration from "
            "the original getter, and must be removed if a future schedule retains that source"
        ),
        "transcript_source": "p3-whir-c61 zk prover native ordering and zk_padded_matrix layout",
        "bounded_native_refinement": {
            "dimension": 10, "first_fold": 1, "queries": 512,
            "canonical_codec_bytes": 2_289_176,
            "C71_ObservedMmcs_opening_binding": True,
            "native_OpeningMac_positive_and_wrong_endpoint_rejection": True,
            "original_A_getter_reduced_contexts": [0, 2, 4],
            "A_first_state_retained_after_predecessor_opening": True,
            "A_retained_allocation_single_Vec_shared_without_full_copy": True,
            "canonical_inplace_successor_release_complete": False,
            "prior_plain_WHir_record_codec_bytes": 2_277_848,
            "same_root_proof_transcript_affine_and_base_closure": True,
            "large_dense_fallbacks_forbidden": True,
            "reference_only_no_canonical_service_or_peak_credit": True,
            "source": "rust/volta-pcs/src/c71_matrix/b12/replay.rs",
        },
        "oracles": oracles,
        "selected_initial_sumcheck": selected_initial_sumcheck(dimension),
        "later_covector_candidate": covector,
        "selected_caller_evidence": (
            "rust/volta-pcs/src/c71_matrix.rs:865 constructs exactly one (point, terminal.x) claim"
        ),
        "symbolic_covector_evidence": (
            "p3-whir-c61 pcs/zk/constraint/source.rs carries Eq and Pow terms and folds them MSB-first"
        ),
        "mask_groups": masks,
        "events": events.rows,
        "known_named_peak_bytes": events.peak,
        "arena_bytes": ARENA,
        "known_named_peak_fits_arena": events.peak <= ARENA,
        "shared_initial_root_reservation_do_not_sum_across_traces": (
            SHARED_INITIAL_ROOT_CACHE + SHARED_INITIAL_ROOT_SECRETS
        ),
        "complete_peak_bytes": None,
        "persistent_live_bytes_after_attempt": sum(events.live.values()),
        "shared_initial_roots_release": "fixed-run teardown, outside this per-proof trace",
        "commit_source_replays_by_oracle": commit_replays,
        "commit_source_replays_total": sum(commit_replays),
        "commit_root_source_virtual_cell_requests_if_no_folded_state": (
            sum(commit_replays) * (1 << dimension)
        ),
        "data_commit_encoded_write_bytes_total": sum(row["encoded_bytes"] for row in oracles),
        "data_commit_salt_xof_bytes_total": sum(
            row["salt_xof_bytes_per_commit_or_full_replay"] for row in oracles
        ),
        "opening_source_replays_total": len(oracles),
        "opening_root_source_virtual_cell_requests_if_no_folded_state": (
            len(oracles) * (1 << dimension)
        ),
        "ood_source_replays_if_no_folded_state": len(oracles) - 1,
        "ood_root_source_virtual_cell_requests_if_no_folded_state": (
            (len(oracles) - 1) * (1 << dimension)
        ),
        "remainder_butterflies_total": sum(row["remainder_butterflies"] for row in oracles),
        "remainder_source_base_cells_total": sum(
            row["remainder_source_base_cells"] for row in oracles
        ),
        "mask_codeword_bytes_original_and_fresh": 2 * sum(
            group["codeword_bytes"] for group in masks
        ),
        "mask_salt_bytes_original_and_fresh": 2 * sum(
            group["salt_bytes_if_retained"] for group in masks
        ),
        "native_dense_guard_bytes": 40 * (1 << dimension),
        "post_fold7_eval_plus_weights_bytes": 48 * (1 << (dimension - 7)),
        "source_uniformity": {
            "remainder": "one source pass per oracle: c_source*N + P(q,h)",
            "coset_commit": "replay count grows with H/arena; rejected by the selected uniformity rule",
            "sumcheck": (
                "the selected single initial claim has an admitted one-pass rank-one contraction; "
                "the later Eq+Pow generating-function schedule is source-uniform algebraically, "
                "but is not implemented; the selected native path still uses an H-point NTT"
            ),
            "minimum_sumcheck_replacement_obligation": (
                "implement the fixed-block rational Pow generator plus tensor Eq stream for every "
                "later round, with explicit buffer lifetimes and an original-getter refinement"
            ),
        },
        "selected_initial_claim_count": 1,
        "selected_initial_svo_message_cell_reads": 1 << dimension,
        "native_round_claim_work": "scatter q points; NTT over folded domain; dense dot/add",
        "incompatibilities": [
            "current native 40N admission and post-fold7 eval+weights exceed the arena",
            "literal coset commitments use dimension-dependent source replays",
            "bounded D10 sourcewise replay matches native codec; fast canonical covector/liveness remain open",
            "canonical hash/reader/terminal MAC liveness is not yet a complete physical plan",
        ],
        "complete_work_upper": None,
        "runtime_upper_seconds": None,
        "admitted": False,
    }


def report():
    return {
        "credit": False,
        "traces": {str(d): trace(d) for d in (35, 34)},
        "A_S1_retention_candidate": a_s1_retention_schedule(),
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))

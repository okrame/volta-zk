#!/usr/bin/env python3
"""C7.1: exact, small algebra checks and planning arithmetic; NOT a prover.

No old protocol implementation is imported. Historical inputs are only the
digest-pinned model metadata and logical config. No weights, network or build.
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
QSPEC_SHA256 = "1af05e2b8d617e261ee20988618a0d05fe1ea5f9f217f04b28c391815e050687"
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


def pinned_model_config():
    path = Path(__file__).resolve().parents[1] / "manifests/c7-d126-gemma31b-qspec-dag-v1.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != QSPEC_SHA256:
        raise ValueError("logical model config changed")
    return json.loads(raw)["model_config"]


def cut_witness_screen(old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """Conditional W-cut storage, NOT a scalar lowering or proof schedule.

    Raw i16 dot accumulators use signed 48-bit STORAGE (i64 arithmetic).
    Weighted RMS uses exact x*w before W-free scaling/rounding; this choice
    must be respected by the still-uninstantiated integer lowering.
    Counts cover terminal absorption and raw global K/V aliasing.
    """
    natural(old_tokens, "old KV tokens", 0, CONTEXT_CAP)
    natural(prompt_tokens, "prompt tokens", 1, CONTEXT_CAP)
    natural(generated_tokens, "generated tokens", 1, CONTEXT_CAP)
    tokens = prompt_tokens + generated_tokens
    if old_tokens + tokens > CONTEXT_CAP:
        raise ValueError("conversation exceeds 4096; no eviction")
    config = pinned_model_config()
    hidden, ffw = config["hidden_size"], config["intermediate_size"]
    matrix_per_token = norm_per_token = 0
    for kind in ("local", "global"):
        layers = config[kind + "_layers"]
        query = config["query_heads"]*config[kind + "_head_dim"]
        kv = config[kind + "_kv_heads"]*config[kind + "_head_dim"]
        # Global v_source aliases RAW K, not normalized K; v_norm is unweighted.
        value = 0 if kind == "global" else kv
        matrix_per_token += layers*(query + kv + value + 2*hidden + 2*ffw)
        norm_per_token += layers*(4*hidden + query + kv)
    matrix = tokens*matrix_per_token + generated_tokens*config["vocab_size"]
    norm = tokens*norm_per_token + (tokens-1)*hidden
    embedding = tokens*hidden
    storage = 6*matrix + 4*norm + 2*embedding
    # Rectangular eager scores, including masked entries. One prefill plus
    # generated_tokens single-row executions, the last with no decision head.
    pairs = (prompt_tokens*(old_tokens+prompt_tokens)
             + generated_tokens*(old_tokens+prompt_tokens)
             + generated_tokens*(generated_tokens+1)//2)
    score_cells = config["layers"]*config["query_heads"]*pairs
    arena = 6_442_450_944
    return {
        "credit": False,
        "old_kv_tokens": old_tokens,
        "new_processed_tokens_including_terminal_absorb": tokens,
        "matrix_accumulator_cells": matrix,
        "weighted_norm_product_cells": norm,
        "embedding_cells": embedding,
        "checkpoint_scalar_cells": matrix+norm+embedding,
        "checkpoint_storage_bytes": storage,
        "arena_bytes_after_checkpoint_only": arena-storage,
        "checkpoint_only_fits_arena": storage <= arena,
        "all_i64_matrix_storage_bytes_with_same_other_cuts": 8*matrix+4*norm+2*embedding,
        "max_i16_dot_abs_bound": ffw*32768**2,
        "rectangular_attention_cells_per_plane": score_cells,
        "three_retained_i16_attention_planes_only_bytes": 6*score_cells,
        "three_attention_planes_alone_exceed_arena": 6*score_cells > arena,
        "w_free_replay_requires_declared_lowering_and_kv_consistency": True,
        "complete_proof_w_passes": None,
        "complete_live_memory_bytes": None,
    }


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


def rne_i48_to_i16(value, shift):
    """Exact RNE(value / 2**shift), symmetric i16 or reject; no floating point."""
    natural(value, "signed i48", -(1 << 47), (1 << 47)-1)
    if type(shift) is not int:
        raise ValueError("shift must be an integer")
    if shift >= 48:
        result = 0
    elif shift <= -15:
        if value:
            raise ValueError("requantization overflows symmetric i16")
        result = 0
    elif shift <= 0:
        result = value << -shift
    else:
        divisor = 1 << shift
        result, remainder = divmod(value, divisor)  # floor quotient, also for negatives
        result += int(2*remainder > divisor or (2*remainder == divisor and result & 1))
    return natural(result, "requantized symmetric i16", -32767, 32767)


def byte_lagrange_basis(value):
    """Degree-255 basis on 0..255, including at roots; only public inverses.

    Prefix/suffix products realize at most 762 private products at a MAC
    endpoint. This clear Fp diagnostic is not the private circuit backend.
    """
    natural(value, "canonical Fp byte-polynomial point", 0, P-1)
    prefix, suffix = [1]*257, [1]*257
    for j in range(255):
        prefix[j+1] = prefix[j]*(value-j) % P
    for j in reversed(range(1, 256)):
        suffix[j] = suffix[j+1]*(value-j) % P
    inverse_factorial = pow(math.factorial(255), -1, P)
    return [prefix[j]*suffix[j+1]*(-1 if (255-j) & 1 else 1)
            * math.comb(255, j)*inverse_factorial % P for j in range(256)]


def byte_product_tree(value):
    """Clear Fp reference for R1's range circuit, including NON-byte inputs.

    Heap node 1 is P256(value), leaves 256+j are value-j; index 0 is unused.
    Honest precomputation on 256 bytes is an optimization, not a premise.
    """
    natural(value, "canonical Fp range-circuit input", 0, P-1)
    tree = [0]*256+[(value-j) % P for j in range(256)]
    for node in range(255, 0, -1):
        tree[node] = tree[2*node]*tree[2*node+1] % P
    return tree


def byte_range_tree_screen(byte_bits):
    """Eight degree-3 GKR layers, one SAME-B endpoint; no FS/hardware credit."""
    natural(byte_bits, "byte source log domain", 1, 35)
    n, depth = 1 << byte_bits, 8
    rounds = sum(byte_bits+d for d in range(depth))
    prefix = min(10, byte_bits)
    tail, visits = n >> prefix, depth*(prefix+1)+depth-1
    per_layer_work = (2*(prefix+1)*n+7*(n-1)+2*(tail-1)
                      +(1 << (prefix+1))+16*(byte_bits+depth))
    return {
        "credit": False,
        "layers": depth,
        "sumcheck_round_degree": 3,
        "sumcheck_rounds": rounds,
        "extension_corrections": 4*rounds+3*depth,
        "payload_before_framing_and_shared_closures": 24*(4*rounds+3*depth),
        "private_products": depth,
        "zero_residuals": rounds+depth,
        "extension_challenges": byte_bits+rounds+depth,
        "interactive_error_numerator_before_b_mac_and_fs": byte_bits+3*rounds+depth,
        "source_endpoints": 1,
        "extra_endpoint_corrections": 0,
        "extra_trace_commitments": 0,
        "fixed_cell_prefix_rounds": prefix,
        "source_visits_including_gate_histograms": visits,
        "public_node_table_bytes": 511*256*8,
        "public_node_table_base_products": 255*256,
        "gate_phase_public_folded_tables_bytes_upper": 256*256*24,
        "gate_histogram_bytes": 256*24,
        "cell_phase_two_public_functions_bytes": 2*256*24,
        "cell_prefix_eq_weights_bytes": 24*(1 << prefix),
        "two_cached_cell_tail_vectors_bytes": 48*tail,
        "control_points_and_round_scratch_bytes_upper": 8192,
        "extension_products_upper_before_mac_and_metadata": depth*per_layer_work
            +(depth-1)*(n-1)+64*256*((1 << depth)-1),
        "verifier_extension_products_before_fs_b_and_shared_closures_upper": 9*rounds+5*depth+9,
        "additional_w_reads": 0,
        "proves_zero_padding": False,
        "full_gamma_liveness_or_feasibility": False,
    }


def byte_lagrange_tree(value, weights):
    """P/S tree for ONE public linear combination of all byte indicators.

    No function-index axis is needed in GKR: every merge is linear in S.
    This clear Fp reference also accepts values outside the byte alphabet.
    """
    if len(weights) != 256:
        raise ValueError("256 public Lagrange weights required")
    for weight in weights:
        natural(weight, "canonical public Lagrange weight", 0, P-1)
    products = byte_product_tree(value)
    inverse_factorial = pow(math.factorial(255), -1, P)
    sums = [0]*256+[w*(-1 if (255-j) & 1 else 1)*math.comb(255, j)*inverse_factorial % P
                    for j, w in enumerate(weights)]
    for node in range(255, 0, -1):
        sums[node] = (sums[2*node]*products[2*node+1]+products[2*node]*sums[2*node+1]) % P
    return products, sums


def rne_indicator_screen(cell_bits, top_prefix_bits=17, link_prefix_bits=10):
    """R2: degree-7 RNE and one public-function P/S GKR, not full Gamma."""
    natural(cell_bits, "RQ source log domain", 1, 32)
    natural(top_prefix_bits, "RNE top prefix", 1, 32)
    natural(link_prefix_bits, "RNE link prefix", 1, 32)
    cells, layers = 1 << cell_bits, 8
    top_prefix, link_prefix = min(top_prefix_bits, cell_bits), min(link_prefix_bits, cell_bits)
    top_tail, link_tail = cells >> top_prefix, cells >> link_prefix
    source, bits = 8*cells, cell_bits+3
    rounds = sum(bits+d for d in range(layers))
    top_corrections, link_corrections = 8*cell_bits+1536+595, 4*rounds+7*layers+6
    link_work = (4*(link_prefix+1)*source+19*(source-1)+4*(8*link_tail-1)
                 +(1 << (link_prefix+1))+32*(bits+layers))
    return {
        "credit": False,
        "top_round_degree": 7,
        "top_extension_corrections": top_corrections,
        "link_round_degree": 3,
        "link_rounds": rounds,
        "link_extension_corrections": link_corrections,
        "extension_corrections": top_corrections+link_corrections,
        "payload_before_framing_and_shared_closures": 24*(top_corrections+link_corrections),
        "private_products": 595+3*layers,
        "zero_residuals": cell_bits+1+rounds+layers+1,
        "extension_challenges": 2*cell_bits+2+11+rounds+2*layers,
        "link_interactive_error_numerator_before_b_mac_and_fs": 11+3*rounds+2*layers,
        "rne_error_numerator_before_output_batch_size_range_b_mac_fs": 8*cell_bits+11+3*rounds+2*layers,
        "source_endpoints": 6,
        "function_axis_sumcheck_rounds": 0,
        "extra_trace_commitments": 0,
        "top_fixed_cell_prefix": top_prefix,
        "top_indicator_tail_bytes": 1536*24*top_tail,
        "top_prefix_weights_bytes": 24*(1 << top_prefix),
        "top_two_local_histograms_bytes": 2*1536*24,
        "top_control_and_evaluation_scratch_bytes_upper": 1 << 18,
        "top_rq_visits": top_prefix+1,
        "link_fixed_cell_prefix": link_prefix,
        "link_six_lane_four_function_tail_bytes": 4*6*24*link_tail,
        "link_counterfactual_eight_lane_tail_bytes": 4*8*24*link_tail,
        "link_public_p_s_tree_bytes": 511*256*(8+24),
        "link_public_child_fold_tables_bytes_upper": 2*256*256*24,
        "link_public_four_function_tables_bytes": 4*256*24,
        "link_prefix_weights_bytes": 24*(1 << link_prefix),
        "link_control_and_terminal_scratch_bytes_upper": 32768,
        "link_retained_source_endpoint_bytes": 6*24,
        "link_rq_visits": layers*(link_prefix+1)+layers-1,
        "source_rq_visits": top_prefix+1+layers*(link_prefix+1)+layers-1,
        "top_extension_products_upper_before_public_forms_mac_metadata": 8*(1 << 14)*(cells-1)
            +1536*(top_tail-1)+(1 << (top_prefix+1))+128*cell_bits+(1 << 14),
        "link_extension_products_upper_before_mac_metadata": layers*link_work
            +(layers-1)*(source-1)+128*256*((1 << layers)-1)+2*255*256+511,
        "link_public_base_products_upper": 255*256+894,
        "verifier_extension_products_before_forms_fs_b_shared_closures_upper": top_corrections+link_corrections
            +7*cell_bits+(1 << 14)+2062+5*rounds+5*layers+535,
        "additional_w_reads": 0,
        "all_shifts_gamma_liveness_or_feasibility_compiled": False,
    }


def rne48_byte_polynomials(values, shift):
    """(rounded-value polynomial, validity polynomial) on six BIASED bytes.

    The integer is sum(256**j * values[j]) - 2**47. Correct rounding/range
    semantics REQUIRE each digit in 0..255 and a binding byte source.
    No auxiliary private digits are authenticated or presumed available.
    """
    if len(values) != 6 or type(shift) is not int:
        raise ValueError("six biased bytes and an integer shift required")
    return rne48_indicator_polynomials([byte_lagrange_basis(x) for x in values], shift)


def rne48_indicator_polynomials(basis, shift):
    """Degree-six lifted RNE formula, NOT free/unproved indicator wires.

    For the real RNE relation, basis[lane][j] must be the MLE of delta_j
    on that byte plane, linked by the P/S tree to the same B source.
    """
    if len(basis) != 6 or any(len(row) != 256 for row in basis) or type(shift) is not int:
        raise ValueError("six 256-entry indicator rows and an integer shift required")
    for row in basis:
        for value in row:
            natural(value, "canonical diagnostic indicator value", 0, P-1)
    values = [sum(j*a for j, a in enumerate(row)) % P for row in basis]
    def table(lane, fn):
        return sum(fn(j)*a for j, a in enumerate(basis[lane])) % P
    def less_than(bound):
        if bound <= 0:
            return 0
        if bound >= 1 << 48:
            return 1
        result = 0
        for lane in range(6):  # low digit first: a higher unequal digit overrides it
            digit = (bound >> (8*lane)) & 255
            result = (table(lane, lambda j: int(j < digit))+basis[lane][digit]*result) % P
        return result

    raw = (sum((1 << (8*j))*x for j, x in enumerate(values))-(1 << 47)) % P
    if shift >= 48:
        return 0, 1
    if shift <= -15:
        valid = math.prod(basis[j][128 if j == 5 else 0] for j in range(6)) % P
        return 0, valid  # every nonzero raw value would overflow
    if shift <= 0:
        rounded, bound = raw*(1 << -shift) % P, 32767 >> -shift
    else:
        lane, bit = divmod(shift, 8)
        quotient = (table(lane, lambda j: j >> bit)
                    + sum((1 << (8*j-shift))*values[j] for j in range(lane+1, 6))
                    - (1 << (47-shift))) % P
        half_lane, half_bit = divmod(shift-1, 8)
        half = table(half_lane, lambda j: (j >> half_bit) & 1)
        low_zero = math.prod(basis[j][0] for j in range(half_lane)) % P
        if half_bit < 7:
            # At shift 47 the bias subtraction is odd and flips quotient parity.
            suppress = table(half_lane, lambda j: ((j >> half_bit) & 1)
                             * int(j % (1 << half_bit) == 0)
                             * (1-(((j >> (half_bit+1)) & 1) ^ int(shift == 47))))
        else:
            suppress = basis[half_lane][128]*(1-table(half_lane+1, lambda j: j & 1)) % P
        rounded = (quotient+half-suppress*low_zero) % P
        bound = 65535*(1 << (shift-1))-1  # strict threshold: endpoint rounds to +/-32768
    valid = (less_than((1 << 47)+bound+1)-less_than((1 << 47)-bound)) % P
    return rounded, valid


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


def private_hobbit_arithmetic_hash_screen(n, block, queries, group_size=6):
    """Grouped width-16/rate-12 arithmetic hash + power-layer GKR screen.

    Up to six code rows per chain compression; paths are NOT deduplicated. Uses
    the locked permutation's 8 full/22 partial degree-7 rounds, not a new
    hash implementation or a security claim. Excludes the encoder scratch,
    inner PCS and all non-hash parts of the prover. The separate anchor
    upper count fixes a 136-byte BLAKE3 message, no salt PRF or extra blocks.
    """
    if (type(n) is not int or type(block) is not int or block < 1 or n < block
            or n & (n - 1) or block & (block - 1)):
        raise ValueError("n and block must be powers of two, with block <= n")
    natural(queries, "distinct unmasked columns", 1, 4*block)
    natural(group_size, "source words per hash group", 1, 6)
    rows, domain = n // block, 4*block
    groups, depth = (rows + group_size-1) // group_size, domain.bit_length() - 1
    calls = queries*(groups + depth)
    padded_calls = 1 << (calls - 1).bit_length()
    variables = padded_calls.bit_length() - 1 + 4
    # Leaf words; chain outputs; path siblings AND outputs; shared root.
    inputs = queries*(rows + 4*groups + 8*depth) + 4
    coefficients = (8*9 + 22*10)*variables
    # One input evaluation and four products for x^7 per permutation round.
    extension_corrections = coefficients + 30 + 4*30
    # 32-bit ripple add: 63 products; XOR: 32. Seven rounds, eight Gs,
    # six adds/four XORs per G, then eight output-word XORs.
    blake_products = 3*(7*8*(6*63 + 4*32) + 8*32)
    anchor_corrections = 512 + blake_products + 4*64
    return {
        "credit": False,
        "carrier_block_cells": block,
        "queries_not_a_security_derivation": queries,
        "chain_groups": groups,
        "source_words_per_hash_group": group_size,
        "private_hash_calls_without_inner_pcs_or_anchor": calls,
        "padded_permutation_instances": padded_calls,
        "base_input_corrections": inputs,
        "base_input_correction_bytes": 8*inputs,
        "power_gkr_extension_corrections": extension_corrections,
        "anchor_base_corrections_upper": anchor_corrections,
        "anchor_correction_bytes_upper": 8*anchor_corrections,
        "hash_payload_bytes_before_framing_and_other_components": (
            8*inputs + 24*extension_corrections + 72),
        "hash_and_anchor_payload_bytes_before_framing_and_other_components": (
            8*(inputs + anchor_corrections) + 24*extension_corrections + 72),
        "hash_trace_and_four_fold_tables_bytes": 16*padded_calls*(31*8 + 4*24),
        "boundary_plaintexts_and_tags_bytes": 32*inputs,
        "setup_code_rows_and_chain_digests_bytes": domain*(group_size*8 + 4*8),
        "retained_full_column_tree_bytes": (2*domain - 1)*32,
        "setup_hash_permutations_before_anchor": domain*groups + domain - 1,
        "queried_hash_sbox_multiplications_before_gkr": calls*(8*16 + 22)*4,
        # Evaluate degree <=9 at <=10 points: <=10 E multiplications per
        # pair/point; fold four tables; interpolate with <=100 products.
        # Excludes construction of public tables and MAC operations.
        "hash_sumcheck_fp3_mul_upper_before_public_forms_and_mac": (
            30*104*(16*padded_calls - 1) + 30*100*variables),
        "clear_hash_reduction_error_numerator_not_fs_or_mac": (
            (8*8 + 22*9)*variables + variables - 2),
    }


def ibcs_rewinding_screen(hash_output_bits, adversary_size_bits=0, tolerance_bits=100):
    """FAVORABLE bound-template screen for CDGS24, not a C7.1 security bound.

    One outer oracle of 2^26 column symbols, one round, unit hidden constant;
    ideal birthday envelope at the INFLATED adversary size. Actual circuit
    costs, other rounds/oracles, IOP errors and FS are deliberately omitted.
    """
    natural(hash_output_bits, 'hypothetical uniform hash output bits', 1, 1024)
    natural(adversary_size_bits, 'hypothetical log2 circuit size', 0, 256)
    natural(tolerance_bits, 'rewinding error tolerance bits', 1, 256)
    log_a = 26+adversary_size_bits  # A=L*t; NOT Q_FS
    # f(e)=e+K/e^2, K=A^2/2^lambda. min f=(27K/4)^(1/3).
    best_bits = max(0.0, (hash_output_bits-2*log_a-math.log2(27/4))/3)
    required_bits = 3*tolerance_bits+2*log_a+math.log2(27/4)
    return {
        'credit': False,
        'hypothetical_uniform_hash_output_bits': hash_output_bits,
        'hypothetical_adversary_size_bits_not_q_fs': adversary_size_bits,
        'optimistic_oracle_length_columns': 1 << 26,
        'optimistic_oracle_rounds_and_hidden_constant': 1,
        'tolerance_bits': tolerance_bits,
        'sampler_runs_at_selected_tolerance': 1 << (26+tolerance_bits),
        'optimistic_rewinder_circuit_size_bits': log_a+tolerance_bits,
        'selected_birthday_envelope_log2_before_clipping': 2*(log_a+tolerance_bits)-hash_output_bits,
        'best_template_interactive_error_bits': best_bits,
        'template_minimum_integer_output_bits_to_beat_tolerance': math.floor(required_bits)+1,
        'best_template_interactive_error_below_2_neg_78': best_bits > 78,
        'full_compiler_constants_relation_hash_assumptions_and_fs_instantiated': False,
        'complete_security_bits': None,
    }


def dot(a, b):
    if len(a) != len(b):
        raise ValueError("different vector lengths")
    return sum(x * y for x, y in zip(a, b)) % P


def small_goldilocks_fft(values):
    """Forward FFT algebra diagnostic, deliberately limited to 256 cells."""
    size = len(values)
    if not size or size > 256 or size & (size - 1):
        raise ValueError("small FFT requires a power-of-two length <= 256")
    if any(type(v) is not int or not 0 <= v < P for v in values):
        raise ValueError("FFT inputs must be canonical Fp values")
    result = list(values)
    j = 0
    for i in range(1, size):
        bit = size >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            result[i], result[j] = result[j], result[i]
    width = 2
    while width <= size:
        root = pow(7, (P-1)//width, P)
        for start in range(0, size, width):
            twiddle = 1
            for i in range(start, start + width//2):
                a, b = result[i], result[i + width//2]*twiddle % P
                result[i], result[i + width//2] = (a+b) % P, (a-b) % P
                twiddle = twiddle*root % P
        width *= 2
    return result


def rs_generator_mle(t, point):
    """MLE of (1,t,...,t^(2^len(point)-1)), little-endian Boolean indices."""
    result = 1
    for v in point:
        result = result*(1-v+v*t) % P
        t = t*t % P
    return result


def recursive_rs_opening_screen(n, block, queries, outer_group_size=6):
    """A3: bounded RS, double outer fold, single-fold resident recursion.

    Only accounting and ideal-oracle error terms. No PCS/MAC/ROM security
    credit, framing, PCG staging or Gemma witness liveness is inferred.
    The cap is a fixed algorithm constant, NEVER selected as a function of n.
    """
    outer = private_hobbit_arithmetic_hash_screen(n, block, queries, outer_group_size)
    if block > 1 << 24 or queries > block or n // block >= P:
        raise ValueError("A3 requires block <= 2^24, queries <= block, rows < p")
    levels = []
    size, calls, inputs, rounds, trees = 2*block, 0, 0, 0, 0
    while size > 512:
        width = size // 32
        domain, words = 4*width, 3*32
        q = min(queries, domain)
        depth, groups = domain.bit_length()-1, (words+5)//6
        level_calls = q*(groups+depth)
        level_inputs = q*(words+4*groups+8*depth)+4
        levels.append({"resident_cells": size, "block_cells": width,
                       "queries": q, "domain": domain,
                       "hash_calls": level_calls, "base_corrections": level_inputs})
        calls += level_calls
        inputs += level_inputs
        rounds += 5
        trees += 32*(2*domain-1)
        size = width
    groups = (3*size+5)//6
    calls += outer["private_hash_calls_without_inner_pcs_or_anchor"] + groups
    inputs += outer["base_input_corrections"] + 3*size+4*groups+4
    padded = 1 << (calls-1).bit_length()
    variables = padded.bit_length()-1+4
    extension = 292*variables+150+3*rounds
    anchor = outer["anchor_base_corrections_upper"]
    # Conservative union of proof arrays: compact source, scratch copy and
    # public form; one FFT slot; twiddles; all inner trees; authenticated
    # boundaries; and the hash trace, even though it can run after freeing X.
    known_arrays = (3*24*2*block + 24*4*block + 16*block + trees
                    + 32*(inputs+anchor) + 48*extension
                    + 16*padded*(31*8+4*24))
    return {
        "credit": False,
        "fixed_algorithm_block_cap": 1 << 24,
        "levels": levels,
        "terminal_private_extension_cells": size,
        "private_hash_calls_including_recursion": calls,
        "padded_permutation_instances": padded,
        "base_corrections_including_anchor_upper": inputs+anchor,
        "extension_corrections_including_partial_sumchecks": extension,
        "fresh_extension_correlations_including_product_mask": extension+1,
        "component_payload_before_framing_and_other_components": (
            8*(inputs+anchor)+24*extension+72),
        "model_setup_known_arrays_bytes": (16+32*(outer_group_size+4))*block,
        "proof_known_arrays_conservative_union_bytes": known_arrays,
        "all_inner_trees_bytes": trees,
        "outer_source_fft_butterflies": 2*n*(block.bit_length()+1),
        "outer_source_fft_uniform_butterfly_coefficient": 52,
        "ideal_oracle_error_bound": (
            "sum_i ((1-d_i/(3D_i))^q_i + d_i*log2(rows_i)/(3*|E|))"
            " + (1-d_0/(2D_0))^q_0 + (2q_0 + sum_i>0 q_i + 2*sumcheck_rounds)/|E|;"
            " query terms are zero when q_i=D_i; NOT a FS bound"),
    }


def combine(a, b, r):
    if len(a) != len(b):
        raise ValueError("different vector lengths")
    return [(x + r * y) % P for x, y in zip(a, b)]


def dyadic_intervals(length):
    """Disjoint aligned power-of-two intervals covering [0,length)."""
    natural(length, "axis length", 1, P-1)
    start, result = 0, []
    while length:
        width = 1 << (length.bit_length()-1)
        result.append((start, width))
        start, length = start+width, length-width
    return result


def dyadic_weight_layout(shapes):
    """Metadata-only virtual layout, never a second packed weight array.

    Tuples are (tensor, source_row, source_col, rows, cols, virtual_offset).
    Each 1D/2D source is partitioned, then tiles are sorted largest first.
    No per-axis padding is stored or committed inside the live prefix.
    """
    tiles = []
    for index, shape in enumerate(shapes):
        if len(shape) not in (1, 2):
            raise ValueError("only vector or matrix weight shapes are admitted")
        rows, cols = (1, shape[0]) if len(shape) == 1 else shape
        for row, height in dyadic_intervals(rows):
            for col, width in dyadic_intervals(cols):
                tiles.append((index, row, col, height, width))
    tiles.sort(key=lambda tile: (-tile[3]*tile[4], *tile[:3]))
    offset, result = 0, []
    for tile in tiles:
        size = tile[3]*tile[4]
        assert offset % size == 0
        result.append((*tile, offset))
        offset += size
    return result


def folded_cube_form(offset, point, row_weights, inner_point):
    """Evaluate an aligned EQ-supported form after arbitrary public row fold.

    Diagnostic over Fp; no source vector, N-cell table or protocol messages.
    The caller multiplies this result by its public term coefficient.
    """
    size, block = 1 << len(point), 1 << len(inner_point)
    natural(offset, "cube offset", 0, P-1)
    if offset % size or offset+size > len(row_weights)*block:
        raise ValueError("cube must be aligned and within the source domain")
    def kernel(a, b):
        return math.prod((1-x)*(1-y)+x*y for x, y in zip(a, b)) % P
    if size >= block:
        start, count = offset//block, size//block
        return (mle(row_weights[start:start+count], point[len(inner_point):])
                * kernel(point[:len(inner_point)], inner_point)) % P
    prefix = (offset % block)//size
    prefix_weight = math.prod(r if (prefix >> i) & 1 else 1-r
                              for i, r in enumerate(inner_point[len(point):])) % P
    return (row_weights[offset//block] * prefix_weight
            * kernel(point, inner_point[:len(point)])) % P


def paired_rs_opening_screen(n, block, queries, outer_group_size=6):
    """A4 fused reduction/PCS accounting, conditional on fixed ideal oracles.

    No GKR caller, framing, concrete-hash compilation or full-prover credit.
    """
    pcs = recursive_rs_opening_screen(n, block, queries, outer_group_size)
    rows, bits = n//block, block.bit_length()-1
    extra = 2*rows-1 + 3*bits + 1  # s/t, product SC coefficients, same endpoint
    return {
        "credit": False,
        "weight_source_reads_for_fused_opening_only": 2,
        "additional_extension_corrections": extra,
        "additional_extension_challenges": rows-1+bits,
        "component_payload_before_framing_and_caller": (
            pcs["component_payload_before_framing_and_other_components"]+24*extra),
        "extension_correlations_including_shared_product_mask": (
            pcs["fresh_extension_correlations_including_product_mask"]+extra),
        "paired_reduction_interactive_error_numerator": 2*(rows-1)+2*bits,
        "first_pass_products_before_forms_and_compact_proofs": 6*n-4*block,
        "first_pass_f_f2_g_and_decoded_source_block_bytes": 80*block,
        "known_array_union_with_added_message_plaintexts_and_tags_bytes": (
            pcs["proof_known_arrays_conservative_union_bytes"]+48*extra),
        "requires_succinct_public_folded_form": True,
        "complete_prover_weight_reads": None,
    }


def gemma_weight_cohorts(tensors, prompt_tokens=100, generated_tokens=50):
    """Emit P0's W-dependent relations and physical cut offsets, metadata only.

    Validates all named private weights; does NOT compile non-W Replay or
    its input-evaluation links. Norm rows flatten token/head, head fastest.
    """
    natural(prompt_tokens, "prompt tokens", 1, CONTEXT_CAP)
    natural(generated_tokens, "generated tokens", 1, CONTEXT_CAP)
    tokens = natural(prompt_tokens+generated_tokens, "new context", 2, CONTEXT_CAP)
    cfg = pinned_model_config()
    hidden, ffw, vocab = cfg["hidden_size"], cfg["intermediate_size"], cfg["vocab_size"]
    records, expected = [], {}
    cell_offset = byte_offset = 0
    producers = {
        "embedding_lookup": "token_input", "q_proj": "input_rms", "q_norm": "q_proj",
        "k_proj": "input_rms", "k_norm": "k_proj", "v_source": "input_rms",
        "o_proj": "pv_matmul", "post_attention_rms": "o_proj",
        "pre_ffw_rms": "attention_residual_add", "gate_proj": "pre_ffw_rms",
        "up_proj": "pre_ffw_rms", "down_proj": "gate_up_mul",
        "post_ffw_rms": "down_proj", "lm_head": "last_row_select",
    }

    def add(kind, layer, op, key, rows, cols, inner=0, heads=1):
        nonlocal cell_offset, byte_offset
        shape = (cols, inner) if kind == "matrix" else (cols,) if kind == "norm" else (vocab, cols)
        if expected.setdefault(key, shape) != shape:
            raise ValueError("inconsistent tied weight geometry")
        width = {"matrix": 6, "norm": 4, "lookup": 2}[kind]
        producer_layer = layer
        if op == "input_rms":
            producer = "layer_scalar_mul" if layer else "embedding_scale"
            producer_layer = layer-1 if layer else None
        elif op == "final_rms":
            producer, producer_layer = "layer_scalar_mul", cfg["layers"]-1
        else:
            producer = producers[op]
        records.append({"ordinal": len(records), "kind": kind, "layer": layer,
                        "operation": op, "weight_key": key, "weight_shape": shape,
                        "rows": rows, "columns": cols, "inner": inner, "heads": heads,
                        "row_schedule": ("decisions" if op == "lm_head" else
                                         "except_terminal_absorb" if op == "final_rms" else "all_new_tokens"),
                        "input_producer": {"layer": producer_layer, "operation": producer},
                        "input_stage": "public_token_id" if kind == "lookup" else "replay_i16_output",
                        "cut_cell_offset": cell_offset, "cut_byte_offset": byte_offset,
                        "cut_scalar_bytes": width})
        cell_offset += rows*cols
        byte_offset += rows*cols*width

    base = "model.language_model."
    embedding = base+"embed_tokens.weight"
    add("lookup", None, "embedding_lookup", embedding, tokens, hidden)
    for layer in range(cfg["layers"]):
        kind = "global" if layer % 6 == 5 else "local"
        hd, kh, qh = cfg[kind+"_head_dim"], cfg[kind+"_kv_heads"], cfg["query_heads"]
        prefix = base+f"layers.{layer}."
        add("norm", layer, "input_rms", prefix+"input_layernorm.weight", tokens, hidden)
        add("matrix", layer, "q_proj", prefix+"self_attn.q_proj.weight", tokens, qh*hd, hidden)
        add("norm", layer, "q_norm", prefix+"self_attn.q_norm.weight", tokens*qh, hd, heads=qh)
        add("matrix", layer, "k_proj", prefix+"self_attn.k_proj.weight", tokens, kh*hd, hidden)
        add("norm", layer, "k_norm", prefix+"self_attn.k_norm.weight", tokens*kh, hd, heads=kh)
        if kind == "local":
            add("matrix", layer, "v_source", prefix+"self_attn.v_proj.weight", tokens, kh*hd, hidden)
        add("matrix", layer, "o_proj", prefix+"self_attn.o_proj.weight", tokens, hidden, qh*hd)
        add("norm", layer, "post_attention_rms", prefix+"post_attention_layernorm.weight", tokens, hidden)
        add("norm", layer, "pre_ffw_rms", prefix+"pre_feedforward_layernorm.weight", tokens, hidden)
        for op in ("gate_proj", "up_proj"):
            add("matrix", layer, op, prefix+f"mlp.{op}.weight", tokens, ffw, hidden)
        add("matrix", layer, "down_proj", prefix+"mlp.down_proj.weight", tokens, hidden, ffw)
        add("norm", layer, "post_ffw_rms", prefix+"post_feedforward_layernorm.weight", tokens, hidden)
    add("norm", None, "final_rms", base+"norm.weight", tokens-1, hidden)
    add("matrix", None, "lm_head", embedding, generated_tokens, vocab, hidden)
    actual = {t["name"]: tuple(t["shape"]) for t in tensors}
    if len(actual) != len(tensors) or actual != expected:
        raise ValueError("private source names/shapes do not match P0 exactly")
    return records


def weight_cohort_screen(cohorts):
    """P0 exact schema counts, conditional on all C/X/W endpoint links."""
    counts, coefficients, rounds, out_bits, products = Counter(), 0, 0, 0, 0
    matrix_widths = norm_widths = compact_input_cells = 0
    for c in cohorts:
        kind, rows, cols = c["kind"], c["rows"], c["columns"]
        counts[kind] += 1
        out_bits += (rows-1).bit_length()+(cols-1).bit_length()
        if kind == "lookup":
            continue
        bits = ((c["inner"] if kind == "matrix" else cols)-1).bit_length()
        degree = 2 if kind == "matrix" else 3
        rounds += bits
        coefficients += (degree+1)*bits
        products += 1
        compact_input_cells += rows*(c["inner"] if kind == "matrix" else cols)
        if kind == "matrix":
            matrix_widths += 1 << bits
        else:
            norm_widths += 1 << bits
    corrections = len(cohorts)+coefficients+3*products  # C, SC coefficients, X/W/product
    vectors = 48*matrix_widths + 32*norm_widths  # matrix X/W in E; norm X in E, W in Fp
    cut_bytes = sum(c["rows"]*c["columns"]*c["cut_scalar_bytes"] for c in cohorts)
    b_tree = 32*(8*(1 << 20)-1)
    scratch = 3*24*max(1 << (c["columns"]-1).bit_length()
                       for c in cohorts if c["kind"] == "norm")
    return {
        "credit": False,
        "cohorts_by_kind": dict(counts),
        "cohort_manifest_sha256": hashlib.sha256(json.dumps(
            cohorts, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "cut_dyadic_tiles": len(dyadic_weight_layout([(c["rows"], c["columns"]) for c in cohorts])),
        "sumcheck_rounds": rounds,
        "sumcheck_extension_coefficients": coefficients,
        "output_point_extension_coordinates": out_bits,
        "extension_challenges_before_A4_and_link_batches": out_bits+rounds,
        "private_product_equations": products,
        "zero_residual_equations": rounds+products,
        "extension_corrections_before_other_circuits": corrections,
        "message_bytes_before_framing_and_shared_closures": 24*corrections,
        "fixed_oracle_interactive_error_numerator": out_bits+coefficients-rounds,
        "single_weight_batch_extension_challenges": 1,
        "weight_batch_interactive_error_numerator": len(cohorts),
        "cut_output_evaluation_obligations": len(cohorts),
        "w_free_input_evaluation_obligations": products,
        "weight_claims_for_one_A4_batch_including_lookup": len(cohorts),
        "matrix_padded_inner_cells": matrix_widths,
        "norm_padded_width_cells": norm_widths,
        "compact_operand_vectors_bytes": vectors,
        "norm_sumcheck_scratch_upper_bytes": scratch,
        "input_cells_folded_during_one_w_free_replay": compact_input_cells,
        "known_b_tree_vectors_scratch_and_messages_union_bytes": (
            cut_bytes+b_tree+vectors+scratch+48*corrections),
        "w_dependent_subsystem_source_reads_with_A4": 3,
        "complete_prover_weight_reads": None,
        "non_w_input_links_or_range_proofs_compiled": False,
    }


def cut_byte_layout(cohorts):
    """R1 virtual byte/column/row cubes; physical packed B is unchanged.

    Byte records: cohort, row, col, rows, cols, first_byte, byte_count, offset.
    RQ records use the existing six-word 2D layout on matrix cells only.
    """
    physical = 0
    for i, c in enumerate(cohorts):
        width = {"matrix": 6, "norm": 4, "lookup": 2}.get(c["kind"])
        if (width is None or c["cut_scalar_bytes"] != width
                or c["ordinal"] != i or c["cut_byte_offset"] != physical):
            raise ValueError("cut byte geometry is not canonical")
        physical += width*c["rows"]*c["columns"]
    scalar_tiles = dyadic_weight_layout([(c["rows"], c["columns"]) for c in cohorts])
    byte_tiles, rq_tiles, rq_offset = [], [], 0
    for i, row, col, height, width, _ in scalar_tiles:
        for first, count in dyadic_intervals(cohorts[i]["cut_scalar_bytes"]):
            byte_tiles.append((i, row, col, height, width, first, count))
        if cohorts[i]["kind"] == "matrix":
            assert rq_offset % (height*width) == 0
            rq_tiles.append((i, row, col, height, width, rq_offset))
            rq_offset += height*width
    byte_tiles.sort(key=lambda t: (-t[3]*t[4]*t[6], *t[:3], t[5]))
    offset, result = 0, []
    for tile in byte_tiles:
        size = tile[3]*tile[4]*tile[6]
        assert offset % size == 0
        result.append((*tile, offset))
        offset += size
    assert offset == physical
    return result, rq_tiles


def cut_byte_opening_forms(cohorts, cut_points, rq_point, range_point, pad_point, coin):
    """Known P0/R1 barrier only: aligned (offset, point, coefficient) terms.

    Returns terms and the PUBLIC biases to add to the existing P0 MACs.
    Six RNE endpoints share rq_point. Late Gamma claims must join BEFORE
    batching; this diagnostic does not silently discard those consumers.
    """
    byte_tiles, rq_tiles = cut_byte_layout(cohorts)
    live = sum(c["rows"]*c["columns"]*c["cut_scalar_bytes"] for c in cohorts)
    matrices = sum(t[3]*t[4] for t in rq_tiles)
    byte_bits, rq_bits = (live-1).bit_length(), (matrices-1).bit_length()
    if (not matrices or len(cut_points) != len(cohorts) or len(rq_point) != rq_bits
            or len(range_point) != byte_bits or len(pad_point) != byte_bits):
        raise ValueError("byte-opening points do not match the cut domains")
    natural(coin, "byte-opening batch coin", 0, P-1)
    for c, (r, s) in zip(cohorts, cut_points):
        if len(r) != (c["rows"]-1).bit_length() or len(s) != (c["columns"]-1).bit_length():
            raise ValueError("P0 cut point has the wrong axes")
    for point in [rq_point, range_point, pad_point, *(q for pair in cut_points for q in pair)]:
        for value in point:
            natural(value, "canonical diagnostic point coordinate", 0, P-1)
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % P
    def prefix_weight(point, count):
        return sum(eq(point[width.bit_length()-1:], offset//width)
                   for offset, width in dyadic_intervals(count)) % P
    biases = [(1 << (8*c["cut_scalar_bytes"]-1))*prefix_weight(r, c["rows"])
              * prefix_weight(s, c["columns"]) % P for c, (r, s) in zip(cohorts, cut_points)]
    powers = [pow(coin, j, P) for j in range(len(cohorts)+8)]
    rq_offsets = {t[:5]: t[5] for t in rq_tiles}
    terms = []
    for i, row, col, height, width, first, count, offset in byte_tiles:
        rb, cb, bb = height.bit_length()-1, width.bit_length()-1, count.bit_length()-1
        r, s = cut_points[i]
        coefficient = powers[i]*eq(r[rb:], row//height)*eq(s[cb:], col//width) % P
        byte_values = [pow(256, 1 << j, P) for j in range(bb)]
        byte_point = [v*pow(1+v, -1, P) % P for v in byte_values]  # public 257/65537
        byte_scale = pow(256, first, P)*math.prod(1+v for v in byte_values) % P
        terms.append((offset, byte_point+list(s[:cb])+list(r[:rb]), coefficient*byte_scale % P))
        if cohorts[i]["kind"] == "matrix":
            rq_offset = rq_offsets[i, row, col, height, width]
            high = eq(rq_point[rb+cb:], rq_offset >> (rb+cb))
            for lane in range(first, first+count):
                local_point = [((lane-first) >> j) & 1 for j in range(bb)]+list(rq_point[:rb+cb])
                terms.append((offset, local_point, powers[len(cohorts)+lane]*high % P))
    terms.append((0, list(range_point), powers[-2]))
    # Padding form = full EQ minus its live-prefix restrictions, not a free claim.
    terms.append((0, list(pad_point), powers[-1]))
    for offset, width in dyadic_intervals(live):
        bits = width.bit_length()-1
        terms.append((offset, list(pad_point[:bits]), -powers[-1]*eq(pad_point[bits:], offset//width) % P))
    return terms, biases


def cut_byte_opening_screen(cohorts):
    """R1's known P0+RNE+range+padding claims; not the final Gamma barrier."""
    byte_tiles, rq_tiles = cut_byte_layout(cohorts)
    live = sum(c["rows"]*c["columns"]*c["cut_scalar_bytes"] for c in cohorts)
    bits, claims = (live-1).bit_length(), len(cohorts)+8
    corrections = 3*bits+1
    padded, tail, visits = 1 << bits, 1 << max(0,bits-10), min(10,bits)+1
    descriptor_bytes = 64*len(byte_tiles)+48*len(rq_tiles)
    paired = paired_rs_opening_screen(padded, 1 << 22, 357, 4)
    pcs = recursive_rs_opening_screen(padded, 1 << 22, 357, 4)
    baseline = requantization_screen(cohorts)
    block, queries, rows = 1 << 22, 357, padded >> 22
    internal_tree = 32*(4*block-1)
    caller_e = (weight_cohort_screen(cohorts)["extension_corrections_before_other_circuits"]
                +input_link_screen(cohorts)["extension_corrections"]
                +baseline["requantization_extension_corrections_upper"]+baseline["byte_range_extension_corrections"])
    records = (32*pcs["base_corrections_including_anchor_upper"]
               +48*(caller_e+pcs["extension_corrections_including_partial_sumchecks"]+paired["additional_extension_corrections"])
               +descriptor_bytes+24*rows)
    byte_tree = baseline["byte_range_product_tree"]
    rne = baseline["rne_indicator_opening"]
    gather_bytes = sum(c["rows"]*c["columns"]*c["cut_scalar_bytes"]
                       *(2 if c["kind"] == "matrix" else 1) for c in cohorts)
    rne_link_union = live+internal_tree+records+sum(rne[key] for key in (
        "link_six_lane_four_function_tail_bytes", "link_public_p_s_tree_bytes",
        "link_public_four_function_tables_bytes", "link_prefix_weights_bytes", "link_control_and_terminal_scratch_bytes_upper"))
    return {
        "credit": False,
        "byte_tiles": len(byte_tiles),
        "matrix_cell_tiles": len(rq_tiles),
        "byte_and_rq_descriptor_bytes": descriptor_bytes,
        "layout_diagnostic_sha256": hashlib.sha256(json.dumps(
            [byte_tiles, rq_tiles], separators=(",", ":")).encode()).hexdigest(),
        "known_claims_including_padding": claims,
        "public_cube_terms_for_known_claims": len(byte_tiles)+6*len(rq_tiles)+2+live.bit_count(),
        "byte_range_tree_known_union_bytes": live+internal_tree+records+sum(byte_tree[key] for key in (
            "public_node_table_bytes", "cell_phase_two_public_functions_bytes", "cell_prefix_eq_weights_bytes",
            "two_cached_cell_tail_vectors_bytes", "control_points_and_round_scratch_bytes_upper")),
        "byte_range_requested_packed_bytes_upper": gather_bytes*byte_tree["source_visits_including_gate_histograms"],
        "rne_top_known_union_bytes": live+internal_tree+records+baseline["sparse_rne_public_coefficient_tail_bytes_upper"]
            +sum(rne[key] for key in ("top_indicator_tail_bytes", "top_prefix_weights_bytes",
                                     "top_two_local_histograms_bytes", "top_control_and_evaluation_scratch_bytes_upper")),
        "rne_ps_link_known_union_bytes": rne_link_union,
        "rne_ps_counterfactual_eight_lane_known_union_bytes": rne_link_union
            +rne["link_counterfactual_eight_lane_tail_bytes"]-rne["link_six_lane_four_function_tail_bytes"],
        "rne_requested_matrix_packed_bytes_upper": 6*baseline["matrix_raw_cells"]*rne["source_rq_visits"],
        "selected_paired_opening": {
            "additional_extension_corrections_over_A3": paired["additional_extension_corrections"],
            "added_payload_before_framing_and_shared_closures": 24*paired["additional_extension_corrections"],
            "component_payload_with_byte_pcs_before_framing": paired["component_payload_before_framing_and_caller"],
            "additional_extension_challenges_including_padding_and_batch": bits+1+paired["additional_extension_challenges"],
            "interactive_transfer_error_numerator_before_A3_and_mac": bits+claims-1+paired["paired_reduction_interactive_error_numerator"],
            "additional_zero_residuals_over_A3": 24,
            "additional_private_products": 0,
            "source_traversals_after_commit": 2,
            "x1_regeneration_required": False,
            "retained_alpha_bytes": 24*rows,
            "retained_outer_internal_nodes_bytes": internal_tree,
            "queried_and_sibling_columns_upper": 2*queries,
            "postcommit_outer_column_hash_calls_upper": 2*queries*((rows+3)//4),
            "known_message_descriptor_alpha_union_bytes": records,
            "first_pass_f_f2_g_and_decoded_block_bytes": paired["first_pass_f_f2_g_and_decoded_source_block_bytes"],
            "first_pass_extension_products_before_public_forms_and_compact_proofs": paired["first_pass_products_before_forms_and_compact_proofs"],
            "known_first_pass_products_with_two_public_form_generations": paired["first_pass_products_before_forms_and_compact_proofs"]+8*padded,
            "commit_preparation_with_b_and_descriptors_bytes": live+272*block+descriptor_bytes,
            "staged_tree_build_with_b_and_descriptors_bytes": live+32*4*block+internal_tree+descriptor_bytes,
            "first_pass_known_union_bytes": live+internal_tree+80*block+records,
            "compact_commit_and_sumcheck_known_union_bytes": live+internal_tree+96*block
                +pcs["all_inner_trees_bytes"]+336*(block//16)+records,
            "queried_columns_known_union_bytes": live+internal_tree+96*block
                +pcs["all_inner_trees_bytes"]+128*queries+records,
        },
        "simple_sumcheck_reference": {
            "extension_corrections": corrections,
            "payload_before_framing_and_shared_closures": 24*corrections,
            "zero_residual_equations": bits+1,
            "additional_private_products": 0,
            "extension_challenges_including_padding_probe": 2*bits+1,
            "interactive_transfer_error_numerator_including_padding_probe": claims-1+3*bits,
            "two_cached_tail_vectors_bytes": 48*tail,
            "source_traversals_before_cached_tail": visits,
            "extension_mul_upper_before_form_generation_and_mac": 2*visits*padded+3*(padded-1)+2*(tail-1),
            "known_barrier_extension_mul_upper_before_metadata_and_mac": 6*visits*padded+3*(padded-1)+2*(tail-1),
        },
        "gather_requested_packed_bytes_upper_per_byte_source_traversal": gather_bytes,
        "known_claim_forms_compiled": True,
        "changes_byte_and_rq_virtual_layouts": True,
        "physical_b_copy_created": False,
        "complete_gamma_consumers_or_liveness_compiled": False,
        "additional_weight_reads": 0,
    }


def gemma_input_routes(cohorts):
    """P0 input claims -> canonical W-free producer tensors, not free roots.

    Head-first norm flattening changes the split of a point, not its bit
    order. The final norm and decision head need actual row selectors.
    """
    by_op = {(c["layer"], c["operation"]): c for c in cohorts}
    if len(by_op) != len(cohorts):
        raise ValueError("duplicate cohort operator")
    tokens = by_op[None, "embedding_lookup"]["rows"]
    generated = by_op[None, "lm_head"]["rows"]
    routes = []
    for c in cohorts:
        if c["kind"] == "lookup":
            continue
        if c["input_stage"] != "replay_i16_output":
            raise ValueError("P0 route requires the exact replay i16 stage")
        if c["kind"] == "norm" and (c["heads"] & (c["heads"]-1)
                or c["rows"] % c["heads"]
                or c["heads"] > 1 and c["columns"] & (c["columns"]-1)):
            raise ValueError("head reshape requires aligned power-of-two heads/lanes")
        width = c["inner"] if c["kind"] == "matrix" else c["columns"]*c["heads"]
        count = c["rows"] if c["kind"] == "matrix" else c["rows"]//c["heads"]
        source, source_rows, offset = dict(c["input_producer"]), tokens, 0
        if c["operation"] == "lm_head":
            source = {"layer": None, "operation": "final_rms"}
            source_rows, offset = tokens-1, tokens-generated-1
        if not 0 <= offset < offset+count <= source_rows:
            raise ValueError("input selection exceeds its producer")
        column_bits, row_bits = (width-1).bit_length(), (count-1).bit_length()
        p0_bits = ((c["inner"] if c["kind"] == "matrix" else c["columns"])-1).bit_length()
        p0_bits += (c["rows"]-1).bit_length()
        if column_bits+row_bits != p0_bits:
            raise ValueError("head reshape does not preserve the padded domain")
        routes.append({"cohort_ordinal": c["ordinal"],
                       "logical_producer": c["input_producer"], "source_producer": source,
                       "source_shape": (source_rows, width),
                       "selected_rows": count, "row_offset": offset,
                       "column_point_bits": column_bits, "row_point_bits": row_bits,
                       "same_i16_stage": c["input_stage"] == "replay_i16_output"})
    return routes


def shifted_eq_form(input_point, source_point, offset, count):
    """Fp diagnostic of sum_{d<count} EQ(input_point,d)*EQ(source_point,offset+d).

    Four-state carry/borrow digit DP; O(bits), no row-sized verifier table.
    Algebra uses only +/*, so the derivation also holds over E. This is not
    the FS codec or a production field implementation.
    """
    source_bits, input_bits = len(source_point), len(input_point)
    natural(count, "selected rows", 0, 1 << input_bits)
    natural(offset, "row offset", 0, 1 << source_bits)
    if input_bits > source_bits or offset+count > 1 << source_bits:
        raise ValueError("selector outside padded producer")
    states = {(0, 0): 1}  # carry of offset+d, borrow of d-count
    for i in range(source_bits+1):  # extra high bit handles count = full domain
        nxt = {}
        for (carry, borrow), value in states.items():
            for bit in ((0, 1) if i < input_bits else (0,)):
                added = bit+((offset >> i) & 1)+carry
                source_bit = added & 1
                state = (added >> 1, int(bit-((count >> i) & 1)-borrow < 0))
                a = (input_point[i] if bit else 1-input_point[i]) if i < input_bits else 1
                b = ((source_point[i] if source_bit else 1-source_point[i])
                     if i < source_bits else int(source_bit == 0))
                nxt[state] = (nxt.get(state, 0)+value*a*b) % P
        states = nxt
    return states.get((0, 1), 0)  # no overflow, d < count


def input_route_form(route, input_point, source_point):
    """Evaluate a route's public coefficient MLE at a producer point."""
    rows, width = route["source_shape"]
    cb, rb = route["column_point_bits"], route["row_point_bits"]
    if len(input_point) != cb+rb or len(source_point) != cb+(rows-1).bit_length():
        raise ValueError("route point has the wrong axes")
    columns = shifted_eq_form(input_point[:cb], source_point[:cb], 0, width)
    selected = shifted_eq_form(input_point[cb:], source_point[cb:],
                               route["row_offset"], route["selected_rows"])
    return columns*selected % P


def kv_view_schedule(old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """Logical append/read lengths, including absorption; NOT attention masks.

    Prefill reads its entire rectangle, including later prompt keys before
    causal masking. Subsequent executions append/read one token each.
    """
    natural(old_tokens, "old KV tokens", 0, CONTEXT_CAP)
    natural(prompt_tokens, "prompt tokens", 1, CONTEXT_CAP)
    natural(generated_tokens, "generated tokens", 1, CONTEXT_CAP)
    if old_tokens+prompt_tokens+generated_tokens > CONTEXT_CAP:
        raise ValueError("conversation exceeds 4096; no eviction")
    return [{"execution": e, "first_new_row": 0 if e == 0 else prompt_tokens+e-1,
             "query_rows": prompt_tokens if e == 0 else 1,
             "kv_view_rows": old_tokens+prompt_tokens+e,
             "emits_decision": e < generated_tokens}
            for e in range(generated_tokens+1)]


def kv_append_form(target_point, tail_point, width, old_rows, tail_rows):
    """MLE of EQ(target, (old+t, column)) as a form on the new-tail producer.

    Reversing ShiftEQ's point arguments is essential: it shifts the target
    row, not the tail row. Algebraic routing only, not a KV PCS opening.
    """
    natural(width, "KV plane width", 1, CONTEXT_CAP)
    if width & (width-1):
        raise ValueError("KV head/lane flattening must be power-of-two aligned")
    natural(old_rows, "old KV rows", 0, CONTEXT_CAP)
    natural(tail_rows, "new KV rows", 1, CONTEXT_CAP)
    rows = old_rows+tail_rows
    if rows > CONTEXT_CAP:
        raise ValueError("KV append exceeds capacity")
    cb, tb, nb = width.bit_length()-1, (tail_rows-1).bit_length(), (rows-1).bit_length()
    if len(target_point) != cb+nb or len(tail_point) != cb+tb:
        raise ValueError("KV append points have the wrong axes")
    return (shifted_eq_form(target_point[:cb], tail_point[:cb], 0, width)
            *shifted_eq_form(tail_point[cb:], target_point[cb:], old_rows, tail_rows)) % P


def kv_transition_screen(old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """K1 concatenation core ONLY; KV PCS, read consumers and Replay remain open."""
    views = kv_view_schedule(old_tokens, prompt_tokens, generated_tokens)
    rows, tail = views[-1]["kv_view_rows"], prompt_tokens+generated_tokens
    config = pinned_model_config()
    widths = [config[kind+"_kv_heads"]*config[kind+"_head_dim"]
              for kind in ("local", "global") for _ in range(2*config[kind+"_layers"])]
    tail_pad, new_pad = 1 << (tail-1).bit_length(), 1 << (rows-1).bit_length()
    old_pad = 1 << (old_tokens-1).bit_length() if old_tokens else 0
    tail_bits = [w.bit_length()-1+(tail-1).bit_length() for w in widths]
    new_bits = [w.bit_length()-1+(rows-1).bit_length() for w in widths]
    rounds, probes, planes = sum(tail_bits) if old_tokens else 0, sum(new_bits), len(widths)
    corrections = 3*rounds+(3 if old_tokens else 1)*planes
    return {
        "credit": False,
        "old_tokens": old_tokens, "new_tokens": rows,
        "logical_executions": len(views), "state_planes": planes,
        "tail_producer_obligations": planes,
        "tail_producer_operations": {"k_rope": config["layers"], "v_norm": config["layers"]},
        "tail_direct_point_aliases": 0 if old_tokens else planes,
        "append_sumchecks": planes if old_tokens else 0,
        "new_state_opening_claims": planes,
        "predecessor_opening_claims": planes if old_tokens else 0,
        "sumcheck_round_degree": 2, "sumcheck_rounds": rounds,
        "extension_corrections": corrections,
        "payload_before_read_routes_pcs_framing_and_shared_closures": 24*corrections,
        "private_products": 0, "zero_residuals": rounds+(planes if old_tokens else 0),
        "extension_challenges": probes+rounds,
        "field_sampling_u64_words_upper": 12*(probes+rounds),
        "fixed_state_interactive_error_numerator_before_mac_pcs_fs": probes+2*rounds,
        "single_plane_two_extension_vectors_bytes": 48*max(widths)*tail_pad if old_tokens else 0,
        "single_plane_public_eq_tables_bytes_upper": 24*(max(widths)+new_pad+old_pad),
        "core_plaintext_and_mac_record_bytes": 48*corrections,
        "core_requested_packed_kv_bytes_one_fused_visit": 2*sum(widths)*rows,
        "read_route_literal_two_full_extension_vectors_bytes_at_capacity": 48*max(widths)*CONTEXT_CAP,
        "read_route_one_bit_prefix_two_tail_vectors_bytes_at_capacity": 24*max(widths)*CONTEXT_CAP,
        "read_route_source_visits_with_one_prefix_bit": 2,
        "prover_extension_products_upper_before_mac_metadata_and_replay": sum(
            (7*w*tail_pad-6 if old_tokens else 0)+2*w*(rows+old_tokens)+2*(w+new_pad+old_pad)
            +64*(2*(w.bit_length()-1)+(rows-1).bit_length()+(tail-1).bit_length()+1)
            for w in widths),
        "additional_weight_reads": 0,
        "per_token_commitments": 0,
        "kv_pcs_read_consumers_and_full_liveness_compiled": False,
        "complete_certificate_bytes": None,
    }


def attention_rectangle_form(row_claim, key_claim, row_point, key_point,
                             old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """MLE of EQ(row_claim,t)*EQ(key_claim,s)*logical_view(t,s), not causal mask.

    Eight-state carry/borrow DP for each of two staircases; no private
    divisions or query-by-key table on the verifier. Fp diagnostic of E algebra.
    """
    natural(old_tokens, "old KV tokens", 0, CONTEXT_CAP)
    natural(prompt_tokens, "prompt tokens", 1, CONTEXT_CAP)
    natural(generated_tokens, "generated tokens", 1, CONTEXT_CAP)
    rows = prompt_tokens+generated_tokens
    keys = natural(old_tokens+rows, "new KV tokens", 1, CONTEXT_CAP)
    tb, sb = (rows-1).bit_length(), (keys-1).bit_length()
    if any(len(p) != n for p, n in ((row_claim, tb), (row_point, tb), (key_claim, sb), (key_point, sb))):
        raise ValueError("attention rectangle points have the wrong axes")

    def staircase(count):
        states = {(0, 0, 0): 1}  # carry of O+1+t; borrows s-(O+1+t), t-count
        for i in range(max(tb, sb)+1):
            nxt = {}
            tw = [(row_claim[i] if bit else 1-row_claim[i])
                  *(row_point[i] if bit else 1-row_point[i]) % P for bit in (0, 1)] if i < tb else [1]
            sw = [(key_claim[i] if bit else 1-key_claim[i])
                  *(key_point[i] if bit else 1-key_point[i]) % P for bit in (0, 1)] if i < sb else [1]
            for (carry, key_borrow, row_borrow), weight in states.items():
                for t, a in enumerate(tw):
                    added = t+(((old_tokens+1) >> i) & 1)+carry
                    for s, b in enumerate(sw):
                        state = (added >> 1, int(s-(added & 1)-key_borrow < 0),
                                 int(t-((count >> i) & 1)-row_borrow < 0))
                        nxt[state] = (nxt.get(state, 0)+weight*a*b) % P
            states = nxt
        return states.get((0, 1, 1), 0)

    prefill = (shifted_eq_form(row_claim, row_point, 0, prompt_tokens)
               *shifted_eq_form(key_claim, key_point, 0, old_tokens+prompt_tokens))
    return (prefill+staircase(rows)-staircase(prompt_tokens)) % P


def attention_product_screen(old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """T1 raw QK/PV, ONE normalized output point per kernel/layer; not i16 proof."""
    views = kv_view_schedule(old_tokens, prompt_tokens, generated_tokens)
    t, s = prompt_tokens+generated_tokens, views[-1]['kv_view_rows']
    nt, ns = (t-1).bit_length(), (s-1).bit_length()
    tp, sp, config = 1 << nt, 1 << ns, pinned_model_config()
    heads = config['query_heads']
    rectangle = sum(v['query_rows']*v['kv_view_rows'] for v in views)
    cases = []
    for kind in ('local', 'global'):
        groups, lanes = config[kind+'_kv_heads'], config[kind+'_head_dim']
        repeats, c = heads//groups, groups*lanes
        ng, nd = groups.bit_length()-1, lanes.bit_length()-1
        q_rounds, v_rounds = nt+ns+ng+nd, nt+ng+2*ns
        q_fields, v_fields = 3*q_rounds+ng+3, 3*v_rounds+ng+4
        control = 16*(tp+sp+heads+lanes)+512*(nt+ns+ng+nd+1)
        eq_bytes = 24*(tp+sp+groups+repeats+lanes)
        cases.append({
            'kind': kind, 'layers': config[kind+'_layers'],
            'qk_rounds': q_rounds, 'pv_rounds_including_probability_link': v_rounds,
            'qk_extension_corrections': q_fields, 'pv_extension_corrections': v_fields,
            'qk_error_numerator_before_input_links_mac_fs': 2*q_rounds+ng,
            'pv_error_numerator_before_input_links_mac_fs': 2*v_rounds+ng,
            'qk_query_phase_arrays_bytes': 2*tp*heads*lanes+48*tp*c+24*c+eq_bytes+65536,
            'qk_key_phase_arrays_bytes': 24*sp*c+48*c+48*sp+eq_bytes+65536,
            'pv_group_phase_arrays_bytes': 2*heads*tp*sp+48*groups*sp+eq_bytes+65536,
            'pv_probability_link_arrays_bytes': 2*heads*tp*sp+48*tp*sp+eq_bytes+65536,
            'qk_literal_dense_product_extension_table_bytes': 24*tp*sp*heads*lanes,
            'qk_prover_extension_products_before_replay_mac_metadata_upper': (
                heads*tp*lanes+2*s*c+2*tp*c+6*(tp-1)*c+c+(sp-1)*c
                +6*(sp-1)+12*(groups-1)*lanes+6*(lanes-1)+control),
            'pv_prover_extension_products_before_replay_mac_metadata_upper': (
                s*c+2*heads*rectangle+tp*repeats+heads+tp*sp
                +12*(groups-1)*sp+6*(sp-1)+6*(tp*sp-1)+control),
            'verifier_extension_products_before_inputs_fs_shared_closures_upper': (
                q_fields+v_fields+2*(q_rounds+v_rounds)+2*ng
                +1024*(nt+ns+1)+16*ng+64),
            'qk_requested_packed_k_bytes_two_visits': 4*s*c,
            'qk_requested_query_i16_bytes_one_visit': 2*t*heads*lanes,
            'pv_requested_packed_v_bytes_one_visit': 2*s*c,
            'pv_requested_probability_i16_bytes_two_live_visits': 4*heads*rectangle,
            'pv_padded_probability_cache_write_bytes': 2*heads*tp*sp,
        })
    rounds = sum(c['layers']*(c['qk_rounds']+c['pv_rounds_including_probability_link']) for c in cases)
    fields = sum(c['layers']*(c['qk_extension_corrections']+c['pv_extension_corrections']) for c in cases)
    errors = sum(c['layers']*(c['qk_error_numerator_before_input_links_mac_fs']
                            +c['pv_error_numerator_before_input_links_mac_fs']) for c in cases)
    kv_rounds = sum(2*c['layers']*(ns+config[c['kind']+'_kv_heads'].bit_length()-1
                                 +config[c['kind']+'_head_dim'].bit_length()-1) for c in cases)
    kernels = 2*config['layers']
    return {
        'credit': False, 'one_normalized_raw_output_claim_per_layer_and_kernel_required': True,
        'old_tokens': old_tokens, 'new_tokens': s, 'raw_kernels': kernels,
        'rectangular_score_cells_per_layer': heads*rectangle, 'cases': cases,
        'sumcheck_rounds_and_extension_challenges': rounds, 'extension_corrections': fields,
        'payload_before_output_normalizers_integer_links_kv_pcs_framing_shared_closures': 24*fields,
        'field_sampling_u64_words_upper': 12*rounds,
        'private_products': kernels, 'zero_residuals': rounds+3*config['layers'],
        'interactive_error_numerator_before_input_links_mac_fs': errors,
        'new_kv_point_demands': kernels, 'q_rope_point_demands': config['layers'],
        'softmax_point_demands': config['layers'], 'additional_weight_reads': 0,
        'new_trace_commitments': 0,
        'kv_router_with_k1_and_one_call_each': {
            'planes_with_two_point_claims': kernels, 'rounds': kv_rounds,
            'extension_corrections': 3*kv_rounds+kernels,
            'payload_before_kv_pcs_framing_shared_closures': 24*(3*kv_rounds+kernels),
            'extension_challenges': kv_rounds+kernels, 'zero_residuals': kv_rounds+kernels,
            'private_products': 0, 'conditional_interactive_error_numerator': 2*kv_rounds+kernels,
        },
        'integer_lowering_output_normalizers_kv_pcs_and_full_liveness_compiled': False,
        'complete_certificate_bytes': None,
    }


def input_link_screen(cohorts):
    """Cost of normalizing P0's seed demands ONLY; Gamma may add consumers."""
    routes, groups = gemma_input_routes(cohorts), {}
    for r in routes:
        key = (r["source_producer"]["layer"], r["source_producer"]["operation"])
        group = groups.setdefault(key, [])
        if group and group[0]["source_shape"] != r["source_shape"]:
            raise ValueError("producer shapes disagree")
        group.append(r)
    reducers = [group for group in groups.values()
                if len(group) > 1 or group[0]["row_offset"] != 0
                or group[0]["selected_rows"] != group[0]["source_shape"][0]]
    bits = [sum((d-1).bit_length() for d in group[0]["source_shape"]) for group in reducers]
    rounds, batching_degree = sum(bits), sum(len(group)-1 for group in groups.values())
    corrections = 3*rounds+len(reducers)  # same input MACs; only SC and final X
    return {
        "credit": False,
        "input_route_manifest_sha256": hashlib.sha256(json.dumps(
            routes, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "p0_input_demands": len(routes),
        "distinct_producer_point_obligations": len(groups),
        "producer_operations": dict(Counter(key[1] for key in groups)),
        "producer_seed_fanout_histogram": dict(Counter(len(g) for g in groups.values())),
        "direct_point_aliases": len(groups)-len(reducers),
        "seed_form_sumchecks": len(reducers),
        "sumcheck_rounds": rounds,
        "extension_corrections": corrections,
        "message_bytes_before_framing_and_shared_closures": 24*corrections,
        "additional_private_product_equations": 0,
        "additional_zero_residual_equations": rounds+len(reducers),
        "extension_challenges": rounds+sum(len(g) > 1 for g in groups.values()),
        "fixed_replay_interactive_error_numerator": 2*rounds+batching_degree,
        "single_reducer_two_extension_vectors_bytes": 48*(1 << max(bits, default=0)),
        "total_padded_producer_cells_for_seed_reducers": sum(1 << n for n in bits),
        "additional_weight_reads": 0,
        "full_gamma_record_or_workspace_counts": None,
        "producer_values_proved_as_replay": False,
    }


def auxiliary_word_sources(cohorts, old_tokens=0, prompt_tokens=100, generated_tokens=50):
    """R3 candidate source schema: physical B plus unretained full-rectangle raws."""
    views = kv_view_schedule(old_tokens, prompt_tokens, generated_tokens)
    # Validate B's existing geometry without claiming new W cohorts.
    cut_byte_layout(cohorts)
    config = pinned_model_config()
    if cohorts[0]['rows'] != prompt_tokens+generated_tokens:
        raise ValueError("B and auxiliary workload disagree")
    sources = [{'source': 'B', 'source_id': c['ordinal'], 'layer': c['layer'],
                'operation': c['operation'], 'execution': None, 'token_offset': 0,
                'shape': (1, c['rows'], c['columns']), 'word_bytes': c['cut_scalar_bytes'],
                'rne': c['kind'] == 'matrix', 'physical_b_offset': c['cut_byte_offset']}
               for c in cohorts]
    for layer in range(config['layers']):
        for v in views:
            sources.append({'source': 'Replay', 'source_id': layer, 'layer': layer,
                            'operation': 'qk_raw', 'execution': v['execution'],
                            'token_offset': v['first_new_row'],
                            'shape': (config['query_heads'], v['query_rows'], v['kv_view_rows']),
                            'word_bytes': 6, 'rne': True, 'physical_b_offset': None})
        kind = 'global' if layer % 6 == 5 else 'local'
        sources.append({'source': 'Replay', 'source_id': layer, 'layer': layer,
                        'operation': 'pv_raw', 'execution': None, 'token_offset': 0,
                        'shape': (config['query_heads'], prompt_tokens+generated_tokens, config[kind+'_head_dim']),
                        'word_bytes': 6, 'rne': True, 'physical_b_offset': None})
    return sources


def auxiliary_word_layout(sources):
    """R3 cubes: byte/column/row/head, head axis whole and power-of-two aligned.

    Byte records: source,row,col,heads,rows,cols,byte0,bytes,offset (9 u64).
    RQ records: source,row,col,heads,rows,cols,offset (7 u64). No values stored.
    """
    byte_tiles, word_tiles = [], []
    for i, source in enumerate(sources):
        heads, rows, cols = source['shape']
        natural(heads, 'whole head axis', 1, 32)
        if heads & (heads-1) or source['word_bytes'] not in (2, 4, 6):
            raise ValueError('invalid auxiliary word geometry')
        if source['rne'] and source['word_bytes'] != 6:
            raise ValueError('R3 RNE source must be exact i48')
        for r, height in dyadic_intervals(rows):
            for c, width in dyadic_intervals(cols):
                tile = (i, r, c, heads, height, width)
                if source['rne']:
                    word_tiles.append(tile)
                for j, count in dyadic_intervals(source['word_bytes']):
                    byte_tiles.append((*tile, j, count))
    result = []
    for tiles, byte_axis in ((byte_tiles, True), (word_tiles, False)):
        tiles.sort(key=lambda t: (-math.prod(t[3:6])*(t[7] if byte_axis else 1), *t[:3],
                                  t[6] if byte_axis else 0))
        offset, placed = 0, []
        for tile in tiles:
            size = math.prod(tile[3:6])*(tile[7] if byte_axis else 1)
            assert offset % size == 0
            placed.append((*tile, offset))
            offset += size
        result.append(placed)
    return tuple(result)


def auxiliary_probe_terms(byte_tiles, sources, source_points):
    """Pull back raw point claims: source -> (head,row,column points, coefficient).

    row is a GLOBAL-token point for attention; each execution's token offset
    must align with its dyadic row cube. Returns EQ cube terms and signed bias.
    """
    terms, bias = [], 0
    for i, r, c, heads, height, width, j, count, offset in byte_tiles:
        if i not in source_points:
            continue
        hp, rp, cp, scale = source_points[i]
        source = sources[i]
        hb, rb, cb, jb = (heads-1).bit_length(), (height-1).bit_length(), (width-1).bit_length(), (count-1).bit_length()
        row = source['token_offset']+r
        if (len(hp) != hb or len(rp) < rb or len(cp) < cb or row % height
                or row+height > 1 << len(rp) or c+width > 1 << len(cp)):
            raise ValueError('raw probe axes or row offset do not match the cube')
        high = (math.prod(x if (row//height >> k) & 1 else 1-x for k, x in enumerate(rp[rb:]))
                *math.prod(x if (c//width >> k) & 1 else 1-x for k, x in enumerate(cp[cb:]))) % P
        weights = [pow(256, 1 << k, P) for k in range(jb)]
        bp = [w*pow(1+w, -1, P) % P for w in weights]
        coefficient = scale*high*pow(256, j, P)*math.prod(1+w for w in weights) % P
        terms.append((offset, bp+list(cp[:cb])+list(rp[:rb])+list(hp), coefficient))
        if j == 0:  # exactly once per word cube, not once per byte group
            bias = (bias+scale*high*(1 << (8*source['word_bytes']-1))) % P
    return terms, bias


def auxiliary_rq_terms(byte_tiles, rq_tiles, point, byte):
    """One R2 endpoint on the unified RQ layout, including public zero padding."""
    natural(byte, 'RNE byte plane', 0, 5)
    live = sum(heads*height*width for _, _, _, heads, height, width, _ in rq_tiles)
    if not live or len(point) != (live-1).bit_length():
        raise ValueError('RNE point does not match the unified RQ domain')
    positions = {t[:6]: t[6] for t in rq_tiles}
    terms = []
    for i, r, c, heads, height, width, j, count, offset in byte_tiles:
        key = (i, r, c, heads, height, width)
        if key not in positions or not j <= byte < j+count:
            continue
        size, jb = heads*height*width, (count-1).bit_length()
        bits = (size-1).bit_length()
        high = math.prod(x if (positions[key]//size >> k) & 1 else 1-x
                         for k, x in enumerate(point[bits:])) % P
        local = [(byte-j >> k) & 1 for k in range(jb)]+list(point[:bits])
        terms.append((offset, local, high))
    return terms


def small_striped_rs(values, stripe_cells):
    """Small honest R3 encoder check (<=64 source cells), NOT a PCS or GPU path."""
    block = len(values)
    natural(stripe_cells, 'stripe cells', 1, block)
    if block > 64 or block & (block-1) or stripe_cells & (stripe_cells-1):
        raise ValueError('small striped RS needs power-of-two sizes <=64')
    if any(type(v) is not int or not 0 <= v < P for v in values):
        raise ValueError('RS inputs must be canonical Fp')
    domain, stride = 4*block, 4*block//stripe_cells
    root, result = pow(7, (P-1)//domain, P), [0]*domain
    for residue in range(stride):
        folded, power, step = [0]*stripe_cells, 1, pow(root, residue, P)
        for k, value in enumerate(values):
            folded[k % stripe_cells] = (folded[k % stripe_cells]+value*power) % P
            if k+1 < block:
                power = power*step % P
        for j, value in enumerate(small_goldilocks_fft(folded)):
            result[residue+stride*j] = value
    return result


def auxiliary_witness_screen(cohorts, old_tokens=0):
    """R3 candidate: unified witness source, not adopted final Gamma/PCS/liveness."""
    sources = auxiliary_word_sources(cohorts, old_tokens)
    byte_tiles, rq_tiles = auxiliary_word_layout(sources)
    live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
    rq_live = sum(math.prod(s['shape']) for s in sources if s['rne'])
    bits, rq_bits = (live-1).bit_length(), (rq_live-1).bit_length()
    n, block, stripe, queries, drop = 1 << bits, 1 << 23, 1 << 19, 357, 3
    rows, domain = n//block, 4*block
    pcs = recursive_rs_opening_screen(n, block, queries, 4)
    paired = paired_rs_opening_screen(n, block, queries, 4)
    rne, alphabet = rne_indicator_screen(rq_bits, 18, 11), byte_range_tree_screen(bits)
    descriptors = 96*len(sources)+72*len(byte_tiles)+56*len(rq_tiles)
    p0, seed, k1 = weight_cohort_screen(cohorts), input_link_screen(cohorts), kv_transition_screen(old_tokens)
    attention = attention_product_screen(old_tokens)
    raw_probe_bits = sum(5+(150-1).bit_length()+(old_tokens+150-1).bit_length()
                         +5+(150-1).bit_length()+(511 if layer % 6 == 5 else 255).bit_length()
                         for layer in range(60))
    caller_e = (p0['extension_corrections_before_other_circuits']+seed['extension_corrections']
                +k1['extension_corrections']+attention['extension_corrections']
                +attention['kv_router_with_k1_and_one_call_each']['extension_corrections']
                +rne['extension_corrections']+alphabet['extension_corrections']+120)
    records = (32*pcs['base_corrections_including_anchor_upper']
               +48*(caller_e+pcs['extension_corrections_including_partial_sumchecks']
                    +paired['additional_extension_corrections'])+descriptors+24*rows)
    b_bytes = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources if s['source'] == 'B')
    cache = 32*((2*domain >> drop)-1)
    head_arrays = 8*150*(old_tokens+150+512)  # one head's raw/Q/PI/PV known arrays, not full Replay
    source_control = descriptors+head_arrays+65536
    root_peak = b_bytes+32*domain+48*stripe+source_control  # four row stripes, twiddles
    common = b_bytes+cache+records+head_arrays+65536
    subgroup_columns = min(domain, queries*(1 << drop))
    rne_link_arrays = sum(rne[k] for k in ('link_six_lane_four_function_tail_bytes',
        'link_public_p_s_tree_bytes', 'link_public_four_function_tables_bytes',
        'link_prefix_weights_bytes', 'link_control_and_terminal_scratch_bytes_upper'))
    range_arrays = sum(alphabet[k] for k in ('public_node_table_bytes',
        'cell_phase_two_public_functions_bytes', 'cell_prefix_eq_weights_bytes',
        'two_cached_cell_tail_vectors_bytes', 'control_points_and_round_scratch_bytes_upper'))
    compact_block = block//16
    compact_cache = 32*(4*compact_block-1)
    top_arrays = (rne['top_indicator_tail_bytes']+rne['top_prefix_weights_bytes']
                  +rne['top_two_local_histograms_bytes']+rne['top_control_and_evaluation_scratch_bytes_upper']
                  +48*((1 << rq_bits)//(1 << min(18, rq_bits))+len(rq_tiles)-1))
    return {
        'credit': False, 'old_tokens': old_tokens, 'source_templates': len(sources),
        'source_byte_cells': live, 'source_padded_byte_cells': n,
        'auxiliary_i48_cells': (live-b_bytes)//6, 'rq_live_cells': rq_live,
        'rq_padded_cells': 1 << rq_bits, 'byte_cubes': len(byte_tiles), 'rq_cubes': len(rq_tiles),
        'source_descriptors_bytes': descriptors,
        'layout_sha256': hashlib.sha256(json.dumps([sources, byte_tiles, rq_tiles], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'raw_probe_extension_corrections': 120, 'raw_probe_payload_bytes': 2880,
        'raw_probe_extension_challenges_and_error_numerator_before_t1_mac_pcs_fs': raw_probe_bits,
        'unified_pcs_payload_before_framing_shared_closures': paired['component_payload_before_framing_and_caller'],
        'literal_full_source_retention_bytes': live,
        'literal_four_row_commit_with_b_bytes': b_bytes+pcs['model_setup_known_arrays_bytes']+descriptors,
        'fixed_carrier_block_cells': block, 'fixed_encoder_stripe_cells': stripe,
        'commit_source_traversals': domain//stripe,
        'commit_padded_source_element_visits': n*(domain//stripe),
        'commit_coefficient_scaling_base_products_upper_before_fft_hash_replay': rows*(domain//stripe)*(2*block-1),
        'commit_stripe_fft_butterflies': rows*(domain//stripe)*(stripe//2)*(stripe.bit_length()-1),
        'commit_outer_hash_calls': domain*((rows+3)//4)+domain-1,
        'commit_known_union_before_replay_runtime': root_peak,
        'cached_outer_tree_first_height': drop, 'cached_outer_tree_bytes': cache,
        'segmented_leaf_digest_buffers_bytes': [8*domain]*4,
        'query_reconstructed_columns_upper': subgroup_columns,
        'query_extra_stripe_and_digest_bytes': 64*subgroup_columns,
        'postcommit_outer_hash_calls_upper': subgroup_columns*((rows+3)//4)+queries*((1 << drop)-1),
        'opening_source_traversals_after_commit': 2,
        'opening_first_pass_known_union_before_replay_runtime': common+80*block,
        'compact_c1_internal_tree_cache_bytes': compact_cache,
        'compact_c1_commit_known_union_before_replay_runtime': common+72*block+336*compact_block,
        'compact_c1_sumcheck_known_union_before_replay_runtime': common+96*block+compact_cache,
        'opening_query_known_union_before_replay_runtime': common+96*block+compact_cache+64*subgroup_columns,
        'compact_c1_extra_query_leaf_columns_upper': 2*queries,
        'compact_c1_query_leaf_hash_calls_upper': 2*queries*16,
        'known_message_descriptor_alpha_union_bytes': records,
        'rne_indicator_screen': rne, 'byte_range_screen': alphabet,
        'rne_link_known_union_before_replay_runtime': common+rne_link_arrays,
        'rne_top_known_union_before_replay_runtime': common+top_arrays,
        'range_known_union_before_replay_runtime': common+range_arrays,
        'post_b_release_pcs_known_arrays_bytes': pcs['proof_known_arrays_conservative_union_bytes'],
        'additional_weight_reads_given_w_free_source_reader': 0,
        'full_auxiliary_source_retained': False,
        'requires_new_common_witness_profile_and_all_form_rerouting': True,
        'source_reader_all_gamma_forms_and_full_liveness_compiled': False,
        'complete_certificate_bytes': None,
    }


def requantization_screen(cohorts):
    """R1 byte-lift candidate, not adopted B PCS or complete Gemma feasibility."""
    matrix_cells = sum(c["rows"]*c["columns"] for c in cohorts if c["kind"] == "matrix")
    raw_bytes = sum(c["rows"]*c["columns"]*c["cut_scalar_bytes"] for c in cohorts)
    rq_bits, byte_bits = (matrix_cells-1).bit_length(), (raw_bytes-1).bit_length()
    anchor = private_hobbit_arithmetic_hash_screen(1 << 35, 1 << 24, 357)["anchor_base_corrections_upper"]
    w_pcs = recursive_rs_opening_screen(1 << 35, 1 << 24, 357)
    literal = []
    for bits in (20, 21, 22):
        block = 1 << bits
        b_pcs = recursive_rs_opening_screen(1 << byte_bits, block, 357)
        literal.append({"block_bits": bits,
                        "b_preparation_with_full_tree_bytes": raw_bytes+336*block+32*(8*block-1),
                        "w_plus_b_base_corrections_only_bytes_no_anchors": 8*(
                            w_pcs["base_corrections_including_anchor_upper"]
                            +b_pcs["base_corrections_including_anchor_upper"]-2*anchor)})
    repaired = recursive_rs_opening_screen(1 << byte_bits, 1 << 22, 357, 4)
    endpoint_products = 6*3*(256-2) + 47*10 + sum(s//8 for s in range(1,48)) + 5
    direct_rq_corrections = 1532*rq_bits+6+endpoint_products
    rne = rne_indicator_screen(rq_bits)
    rq_corrections = rne["extension_corrections"]
    direct_byte_corrections = 258*byte_bits+1+255
    byte_tree = byte_range_tree_screen(byte_bits)
    byte_corrections = byte_tree["extension_corrections"]
    p0_corrections = weight_cohort_screen(cohorts)["extension_corrections_before_other_circuits"]
    seed_corrections = input_link_screen(cohorts)["extension_corrections"]
    preparation = raw_bytes+repaired["model_setup_known_arrays_bytes"]
    _, rq_tiles = cut_byte_layout(cohorts)
    return {
        "credit": False,
        "matrix_raw_cells": matrix_cells,
        "matrix_padded_cells": 1 << rq_bits,
        "b_biased_byte_live_cells": raw_bytes,
        "b_biased_byte_padded_cells": 1 << byte_bits,
        "requantization_polynomial_total_degree_upper": 6,
        "requantization_sumcheck_round_degree_upper": 7,
        "all_64_shift_classes_endpoint_products_upper": 595,
        "requantization_extension_corrections_upper": rq_corrections,
        "requantization_payload_upper_before_framing_and_shared_closures": 24*rq_corrections,
        "rne_indicator_opening": rne,
        "rne_direct_reference": {
            "polynomial_degree_upper": 1530,
            "round_degree_upper": 1531,
            "endpoint_products_upper": endpoint_products,
            "extension_corrections": direct_rq_corrections,
            "payload_before_framing_and_shared_closures": 24*direct_rq_corrections,
            "six_byte_plane_cached_tail_bytes": 6*24*(1 << max(0,rq_bits-10)),
            "sparse_public_coefficient_tail_bytes_upper": 48*((1 << max(0,rq_bits-10))+len(rq_tiles)-1),
        },
        "byte_range_extension_corrections": byte_corrections,
        "byte_range_payload_before_framing_and_shared_closures": 24*byte_corrections,
        "byte_range_product_tree": byte_tree,
        "byte_range_direct_reference": {
            "extension_corrections": direct_byte_corrections,
            "payload_before_framing_and_shared_closures": 24*direct_byte_corrections,
            "cached_tail_bytes": 24*(1 << max(0,byte_bits-10)),
        },
        "fixed_prefix_rounds_before_materialization": rne["top_fixed_cell_prefix"],
        "source_scans_per_sumcheck_before_cached_tail_upper": rne["top_rq_visits"],
        "sparse_rne_public_coefficient_tail_bytes_upper": 48*((1 << max(0,rq_bits-17))+len(rq_tiles)-1),
        "literal_six_row_byte_pcs_screens": literal,
        "four_row_no_outer_tree_pcs_payload_before_framing": repaired["component_payload_before_framing_and_other_components"],
        "four_row_no_outer_tree_preparation_with_b_bytes": preparation,
        "queried_tree_rebuild_known_union_without_x1_bytes": (
            preparation+32*repaired["base_corrections_including_anchor_upper"]
            +48*(p0_corrections+seed_corrections+rq_corrections+byte_corrections
                  +repaired["extension_corrections_including_partial_sumchecks"])),
        "repaired_pcs_source_scans_after_commit_including_x1_regeneration": 3,
        "requires_new_b_byte_commitment_profile": True,
        "additional_w_reads_for_these_byte_algorithms": 0,
        "all_matrix_shifts_instantiated": False,
        "byte_pcs_forms_and_complete_liveness_compiled": False,
        "complete_gamma_or_certificate_bytes": None,
    }


def a3_query_indices(domain, count, words):
    """Small reference for A3's bounded PUBLIC sampler, not a PCS prover.

    Four trials per selected index; no fallback on exhaustion. Exhaustive
    sets use natural order and consume no randomness. Input words are a
    supplied diagnostic tape, NOT a production random generator.
    """
    natural(domain, "query domain", 1, 1 << 26)
    natural(count, "query count", 1, min(357, domain))
    if count == domain:
        return list(range(domain))
    tape, swaps, indices = iter(words), {}, []
    for i in range(count):
        remaining = domain-i
        cutoff = (1 << 64) - (1 << 64) % remaining
        for _ in range(4):
            try:
                word = next(tape)
            except StopIteration:
                raise ValueError("truncated query randomness") from None
            natural(word, "random word", 0, (1 << 64)-1)
            if word < cutoff:
                j = word % remaining
                break
        else:
            raise ValueError("query rejection limit exhausted")
        indices.append(swaps.get(j, j))
        last = remaining-1
        swaps[j] = swaps.get(last, last)
        swaps.pop(last, None)
    return indices


def a3_challenge_screen():
    """Finite honest A3 schedule ONLY: excludes caller, setup and Gemma GKR."""
    # Outer proximity point/batch, inner partial SC/batches, hash initial
    # point/30 sumchecks, and common product/zero closing challenges.
    extension = 11 + 1 + 4*5 + 4 + 20 + 30*22 + 2
    base_coordinates, indices = 3*extension, 4*357
    return {
        "credit": False,
        "extension_challenge_elements": extension,
        "base_challenge_coordinates": base_coordinates,
        "random_query_indices": indices,
        "exhaustive_indices_without_draws": 128,
        "max_trials_per_coordinate_or_index": 4,
        "max_u64_draws_per_attempt": 4*(base_coordinates+indices),
        "max_u64_draws_for_response_slots_only": (
            LIFETIME_ATTEMPTS*4*(base_coordinates+indices)),
        "honest_exhaustion_bound_numerator": (
            LIFETIME_ATTEMPTS*(base_coordinates*(1 << 24)+indices)),
        "honest_exhaustion_bound_denominator": 1 << 152,
        "exhaustion_bound_assumes_unbiased_honest_tapes": True,
        "exhaustion_is_rejection_not_false_acceptance": True,
        "complete_honest_fs_query_census": False,
    }


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
    tiles = dyadic_weight_layout([t["shape"] for t in tensors])
    cohorts = gemma_weight_cohorts(tensors)
    n = 1 << (live - 1).bit_length()
    h = n.bit_length() - 1
    matrix_shapes = Counter(tuple(t["shape"]) for t in tensors if len(t["shape"]) == 2)
    max_dot = max(columns for _, columns in matrix_shapes)
    assert max_dot == 21_504
    cut = cut_witness_screen()
    # Candidate B-role cap is fixed at 2^20, not chosen as a function of N/q.
    # These reuse A3 ARRAY formulas only, not an instantiated B/KV protocol.
    b_opening = recursive_rs_opening_screen(1 << 30, 1 << 20, 357)
    b_tree = 32*(8*(1 << 20)-1)
    b_known = b_opening["proof_known_arrays_conservative_union_bytes"]
    b_hash = 5504*b_opening["padded_permutation_instances"]
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
        "hobbit_arithmetic_hash_screens": [
            private_hobbit_arithmetic_hash_screen(n, 1 << bits, 357)
            for bits in (23, 24)
        ],
        "recursive_rs_opening_screen": recursive_rs_opening_screen(n, 1 << 24, 357),
        "a3_challenge_screen": a3_challenge_screen(),
        "ibcs_rewinding_screens": [ibcs_rewinding_screen(bits, time_bits)
                                   for bits, time_bits in ((256, 0), (256, 64), (512, 64))],
        "paired_rs_opening_screen": paired_rs_opening_screen(n, 1 << 24, 357),
        "weight_cohort_screen": weight_cohort_screen(cohorts),
        "input_link_screen": input_link_screen(cohorts),
        "kv_transition_screens": [kv_transition_screen(old) for old in (0, 3900, 3946)],
        "attention_product_screens": [attention_product_screen(old) for old in (0, 3946)],
        "auxiliary_witness_screens": [auxiliary_witness_screen(cohorts, old) for old in (0, 3946)],
        "requantization_screen": requantization_screen(cohorts),
        "cut_byte_opening_screen": cut_byte_opening_screen(cohorts),
        "dyadic_weight_layout_screen": {
            "credit": False,
            "tiles": len(tiles),
            "live_cells_without_per_axis_padding": sum(t[3]*t[4] for t in tiles),
            "virtual_padded_domain_cells": n,
            "counterfactual_fully_axis_padded_cells": sum(
                math.prod(1 << (d-1).bit_length() for d in t["shape"]) for t in tensors),
            "changes_model_commitment_layout_and_profile_digest": True,
            "packed_weight_copy_created": False,
        },
        "cut_witness_screens": [cut_witness_screen(old) for old in (0, 3900, 3946)],
        "candidate_cut_opening_arrays": {
            "credit": False,
            "ephemeral_outer_b_tree_bytes": b_tree,
            "b_plus_prehash_known_arrays_and_outer_tree_bytes": (
                cut["checkpoint_storage_bytes"] + b_known - b_hash + b_tree),
            "post_release_known_arrays_and_outer_tree_bytes": b_known+b_tree,
            "requires_b_final_consumer_before_release": True,
            "excludes_caller_kv_pcg_and_runtime": True,
        },
        "complete_certificate_bytes": None,
        "complete_h100_peak_bytes": None,
        "complete_security_bits": None,
        "warm_prover_seconds": None,
        "four_core_verifier_seconds": None,
    }


if __name__ == "__main__":
    self_check()
    print(json.dumps(report(), indent=2))

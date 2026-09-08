#!/usr/bin/env python3
"""C7.1: exact, small algebra checks and planning arithmetic; NOT a prover.

No old protocol implementation is imported. Historical reuse is limited to
digest-pinned metadata/config and the logical tensor-DAG expander, not its
budget or admission status. No weights, network or build.
The cleartext diagnostic below MUST NOT be used to prove private weights.
"""

import decimal
import hashlib
import json
import math
import runpy
from collections import Counter
from functools import lru_cache
from fractions import Fraction
from graphlib import TopologicalSorter
from pathlib import Path


P = (1 << 64) - (1 << 32) + 1
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
METADATA_SHA256 = "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
QSPEC_SHA256 = "1af05e2b8d617e261ee20988618a0d05fe1ea5f9f217f04b28c391815e050687"
ROPE_Q30_TABLE_SHA256 = "67503dd31c4504bed77f836ac1389d64692cef2a721ad74381d6297071d90951"
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


def pinned_gemma_manifest():
    path = Path(__file__).resolve().parents[1] / "manifests/c7-d126-gemma31b-qspec-dag-v1.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != QSPEC_SHA256:
        raise ValueError("logical model config changed")
    return json.loads(raw)


def pinned_model_config():
    return pinned_gemma_manifest()["model_config"]


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


def rne_dyadic_add_i16(a, b, exponents):
    """Exact rounded sum with bounded integer words, for ANY public exponent gap.

    Close exponents use the i48 helper; distant operands can change the
    high operand's rounded quotient only at a tie when the output is coarser.
    This is an honest getter, not a Gamma/MAC kernel or a calibrated profile.
    """
    natural(a, "left symmetric i16", -32767, 32767)
    natural(b, "right symmetric i16", -32767, 32767)
    if len(exponents) != 3 or any(type(e) is not int for e in exponents):
        raise ValueError("dyadic addition needs three public integer exponents")
    ea, eb, eo = exponents
    if ea < eb:
        a,b,ea,eb = b,a,eb,ea
    gap, shift = ea-eb, eo-ea
    if gap <= 15:
        return rne_i48_to_i16((a << gap)+b,eo-eb)
    if a == 0:
        return rne_i48_to_i16(b,eo-eb)
    if shift >= 16:
        return 0
    if shift <= -16:
        raise ValueError('dyadic addition overflows symmetric i16')
    if shift <= 0:
        # For negative shifts the high integer is even; at shift zero
        # the low contribution has magnitude <1/2 and cannot be a tie.
        result = (a << -shift)+rne_i48_to_i16(b,eo-eb)
    else:
        divisor = 1 << shift
        result, remainder = a >> shift, a & (divisor-1)
        result += int(2*remainder > divisor or 2*remainder == divisor and
                      (b > 0 or b == 0 and result & 1))
    return natural(result, 'rounded dyadic sum', -32767, 32767)


@lru_cache(maxsize=2)
def rope_inverse_frequencies_q96(family):
    """Exact floor(2^96 * inv[j]) for the pinned active RoPE pairs only.

    Powers of ten reduce the local/global root degrees to 32/128.
    Repeated integer square roots preserve the exact floor. Public setup,
    not per-cell witness work; at most two immutable frequency vectors.
    """
    if family not in ('local','global'):
        raise ValueError('RoPE family must be local or global')
    depth, exponent, count = (5,1,128) if family == 'local' else (7,3,64)
    result = []
    for j in range(count):
        v = (1 << (96*(1 << depth))) // 10**(exponent*j)
        for _ in range(depth):
            v = math.isqrt(v)
        result.append(v)
    return tuple(result)


def gemma_rope_q30_coefficients(family, position):
    """C71-RoPE-Q30-v1: a finite integer coefficient recipe, NOT libm.

    The recipe itself defines the quantized model's coefficients. It does
    not claim exact real-output RNE or BF16 equivalence. Q96 Taylor plus
    14 double-angle steps has pre-Q30 component error < 2^-59.
    """
    natural(position, 'absolute RoPE position', 0, CONTEXT_CAP-1)
    frequencies = rope_inverse_frequencies_q96(family)
    q, result = 1 << 96, []
    def rne(n,d):
        a,r = divmod(n,d)
        return a+int(2*r > d or (2*r == d and a & 1))
    for frequency in frequencies:
        x = rne(position*frequency,1 << 14)
        square = rne(x*x,q)
        cosine, sine, tc, ts = q,x,q,x
        for k in range(1,11):
            tc = rne(-tc*square,q*(2*k-1)*(2*k))
            ts = rne(-ts*square,q*(2*k)*(2*k+1))
            cosine, sine = cosine+tc,sine+ts
        for _ in range(14):
            cosine, sine = rne(cosine*cosine-sine*sine,q),rne(2*cosine*sine,q)
        pair = tuple(rne(v,1 << 66) for v in (cosine,sine))
        for v in pair:
            natural(v, 'canonical signed Q30 coefficient', -(1 << 30), 1 << 30)
        result.append(pair)
    return tuple(result)


def rope_raw_row(values, coefficients):
    """Q30 coefficient lowering, before ONE output RNE.

    Pair the two full half-heads. Omitted coefficient pairs are exactly
    (1,0), not a shorter rotate_half. Callers must supply the canonical
    public coefficient window; this scalar helper does not authenticate it.
    """
    width = natural(len(values), 'RoPE head width', 2, 512)
    if width & (width-1) or len(coefficients) > width//2:
        raise ValueError('RoPE needs power-of-two heads and at most half-head coefficients')
    for value in values:
        natural(value, 'RoPE symmetric i16 input', -32767, 32767)
    half, result = width//2, [0]*width
    for j in range(half):
        c,s = coefficients[j] if j < len(coefficients) else (1 << 30,0)
        for v in (c,s):
            natural(v, 'RoPE signed Q30 coefficient', -(1 << 30), 1 << 30)
        a,b = values[j],values[j+half]
        result[j],result[j+half] = c*a-s*b,s*a+c*b
    return result


def rope_linear_input_form(coefficients, output_point, input_point):
    """Fp diagnostic of the adjoint's MLE; points are (lane,head,token).

    Rows are the PUBLIC coefficient window at absolute positions O+t.
    Multiply EQ and coefficients on Boolean vertices, not after MLE.
    """
    rc,rh,rt = output_point
    uc,uh,ut = input_point
    rows = natural(len(coefficients), 'RoPE coefficient rows', 1, CONTEXT_CAP)
    natural(len(rc), 'RoPE lane bits', 1, 9)
    if (len(rh) > 5 or len(rt) != (rows-1).bit_length() or
            any(len(a) != len(b) for a,b in zip(output_point,input_point))):
        raise ValueError('RoPE form points have incompatible axes')
    half = 1 << (len(rc)-1)
    if len({len(row) for row in coefficients}) != 1 or len(coefficients[0]) > half:
        raise ValueError('RoPE coefficient window has inconsistent pair counts')
    for point in (*output_point,*input_point):
        for v in point:
            natural(v, 'RoPE diagnostic point', 0, P-1)
    def eq(point,index):
        return math.prod(v if index >> k & 1 else 1-v for k,v in enumerate(point)) % P
    tw = [eq(rt,t)*eq(ut,t) % P for t in range(rows)]
    jw = [eq(rc[:-1],j)*eq(uc[:-1],j) % P for j in range(half)]
    cosine, sine = 0,0
    for t,row in enumerate(coefficients):
        for j in range(half):
            c,s = row[j] if j < len(row) else (1 << 30,0)
            for v in (c,s):
                natural(v, 'RoPE signed Q30 coefficient', -(1 << 30), 1 << 30)
            weight = tw[t]*jw[j] % P
            cosine, sine = (cosine+weight*c) % P,(sine+weight*s) % P
    head = math.prod((1-a)*(1-b)+a*b for a,b in zip(rh,uh)) % P
    same = (1-rc[-1])*(1-uc[-1])+rc[-1]*uc[-1]
    return head*(same*cosine+(rc[-1]-uc[-1])*sine) % P


def gemma_rope_plan(cohorts, old_tokens=0):
    """Quantized RoPE profile and conditional raw-linear accounting only."""
    cfg, norms = pinned_model_config(), rms_statistic_cohorts(cohorts)
    tokens = cohorts[0]['rows']
    natural(old_tokens, 'RoPE predecessor tokens', 0, CONTEXT_CAP-tokens)
    records = []
    for i,norm in enumerate(norms):
        if norm['operation'] not in ('q_norm','k_norm'):
            continue
        family = 'global' if norm['layer'] % 6 == 5 else 'local'
        width = cfg[family+'_head_dim']
        heads = cfg['query_heads'] if norm['operation'] == 'q_norm' else cfg[family+'_kv_heads']
        if norm['columns'] != width or norm['heads'] != heads or norm['statistic_rows'] != tokens*heads:
            raise ValueError('RoPE producer geometry disagrees with the pinned model')
        records.append({'layer':norm['layer'], 'operation':norm['operation'][0]+'_rope',
                        'rms_source_id':i, 'heads':heads, 'columns':width, 'rows':tokens,
                        'position_start':old_tokens, 'coefficient_family':family,
                        'rotating_pairs':64 if family == 'global' else width//2})
    if (len(records) != 2*cfg['layers'] or
            {(r['layer'],r['operation']) for r in records} !=
            {(l,op) for l in range(cfg['layers']) for op in ('q_rope','k_rope')}):
        raise ValueError('RoPE needs every pinned Q/K producer exactly once')
    rounds = sum((r['rows']-1).bit_length()+(r['heads']-1).bit_length()+(r['columns']-1).bit_length() for r in records)
    cells = [r['rows']*r['heads']*r['columns'] for r in records]
    padded = [(1 << (r['rows']-1).bit_length())*r['heads']*r['columns'] for r in records]
    # F fill: in-place EQ expansion (one product/subtraction per parent),
    # seven products/two sums per token/pair, then one product/output lane.
    axes = [(r['rows'],1 << (r['rows']-1).bit_length(),r['heads'],r['columns']//2) for r in records]
    eq_steps = sum(tp+h+j-3 for t,tp,h,j in axes)
    token_pairs = sum(t*j for t,tp,h,j in axes)
    fill_products = eq_steps+7*token_pairs+sum(cells)
    fill_additions = eq_steps+2*token_pairs+len(records)  # also 1-r_b
    verifier_products = sum((2*((t-1).bit_length())+1)*t+(2*(j.bit_length()-1)+1)*j
                            +3*t*j+3*(h.bit_length()-1)+5 for t,tp,h,j in axes)
    verifier_additions = sum(2*((t-1).bit_length())*t+2*(j.bit_length()-1)*j
                             +2*t*j+3*(h.bit_length()-1)+5 for t,tp,h,j in axes)
    forms = {'credit':False, 'eq_table_expansion_steps':eq_steps, 'live_token_pairs':token_pairs,
             'fill_extension_products_upper':fill_products, 'fill_extension_additions_upper':fill_additions,
             'probe_extension_products_and_additions_each':sum(cells),
             'initial_F_Y_logical_store_bytes':48*sum(padded),
             'maximum_fill_eq_and_row_array_bytes':max(24*(tp+h+3*j) for t,tp,h,j in axes),
             'maximum_verifier_weight_arrays_and_control_bytes':max(24*(t+j)+1024 for t,tp,h,j in axes),
             'fill_public_q30_read_bytes_upper':8*token_pairs,
             'verifier_public_q30_read_bytes_upper':8*token_pairs,
             'verifier_form_extension_products_upper':verifier_products,
             'verifier_form_extension_additions_upper':verifier_additions,
             'verifier_form_and_clear_sumcheck_products_upper':verifier_products+2*rounds+len(records),
             'verifier_form_and_clear_sumcheck_additions_upper':verifier_additions+6*rounds+len(records),
             'prover_fill_probe_and_sumcheck_products_upper':fill_products+sum(cells)+6*(sum(padded)-len(records)),
             'prover_fill_probe_and_sumcheck_additions_upper':fill_additions+sum(cells)+8*(sum(padded)-len(records)),
             'complete_mac_fs_byte_pullback_or_hardware_work':None}
    return {'cohorts':records, 'summary':{
        'credit':False, 'rope_cohorts':len(records), 'live_output_cells':sum(cells),
        'raw_absolute_bound_given_Q30_coefficients':32767*(1 << 31),
        'public_active_Q30_table_bytes_at_capacity':8*CONTEXT_CAP*(128+64),
        'raw_virtual_bytes_if_added_to_sigma':6*sum(cells),
        'one_probe_per_raw_cohort_corrections':len(records), 'raw_linear_sumcheck_rounds':rounds,
        'raw_linear_sumcheck_corrections':3*rounds+len(records),
        'raw_probe_and_linear_payload_before_rne_pcs_framing':24*(3*rounds+2*len(records)),
        'linear_sumcheck_padded_cells':sum(padded), 'maximum_two_field_arrays_without_reader':48*max(padded),
        'linear_sumcheck_field_products_before_fill_reader_mac':6*(sum(padded)-len(records)),
        'public_form_and_linear_field_work':forms,
        'raw_identity_error_numerator_before_source_mac_fs':3*rounds,
        'new_private_products_for_raw_linear_reductions':0,
        'canonical_Q30_substitution_preserves_exact_real_rne':False,
        'coefficient_profile':'C71-RoPE-Q30-v1',
        'canonical_coefficient_recipe_specified':True,
        'canonical_coefficient_table_sha256':ROPE_Q30_TABLE_SHA256,
        'public_setup_root_isqrt_calls':128*5+64*7,
        'public_setup_max_root_operand_bits':96*128+1,
        'public_setup_trig_signed_bits':256,
        'public_setup_main_integer_products':64*CONTEXT_CAP*(128+64),
        'public_setup_rne_divisions':52*CONTEXT_CAP*(128+64),
        'complete_gemma_quantization_and_runtime_refinement':None,
        'raw_rope_common_source_layout_specified':True,
        'raw_rope_adopted_in_active_source_totals':False, 'complete_rope_mac_kernel_and_liveness':None}}


def rope_raw_byte_sources(cohorts):
    """Virtual i48 RoPE cuts for the SAME Sigma/RQ; no retained raw array."""
    return [{'source':'RoPE_raw', 'source_id':i, 'layer':r['layer'], 'operation':r['operation'],
             'execution':None, 'token_offset':0, 'shape':(r['heads'],r['rows'],r['columns']),
             'word_bytes':6, 'rne':True, 'physical_b_offset':None}
            for i,r in enumerate(gemma_rope_plan(cohorts)['cohorts'])]


def rope_output_source_point(source, point, coefficient=1):
    """T1/K1 native lane||head||NEW-token -> one raw RoPE RNE output claim."""
    heads,rows,columns = source['shape']
    if source['source'] != 'RoPE_raw' or source['operation'] not in ('q_rope','k_rope'):
        raise ValueError('RoPE output demand must name its own raw source')
    cb,hb,tb = ((d-1).bit_length() for d in (columns,heads,rows))
    if len(point) != cb+hb+tb or source['token_offset'] != 0:
        raise ValueError('RoPE output point must use the new-token native domain')
    return (list(point[cb:cb+hb]),list(point[cb+hb:]),list(point[:cb]),coefficient)


def rope_read_raw_word(record, reader, first, count, buffers, coefficients, public_row):
    """Honest <=64-lane raw getter in native token/head/lane order.

    public_row is (absolute_position, canonical_Q30_pairs), prepared before
    roots. As with rope_raw_row, this is not a verifier of that public table.
    Two sequential RMS words share one getter wave; no W or full Y/raw array.
    """
    width = natural(record['columns'], 'RoPE reader width', 2, 512)
    heads = natural(record['heads'], 'RoPE reader heads', 1, 32)
    rows = natural(record['rows'], 'RoPE reader tokens', 1, 150)
    start = natural(record['position_start'], 'RoPE absolute start', 0, CONTEXT_CAP-rows)
    natural(count, 'RoPE reader word lanes', 1, 64)
    natural(first, 'RoPE native input index', 0, rows*heads*width-count)
    if (width & (width-1) or heads & (heads-1) or
            record['operation'] not in ('q_rope','k_rope') or
            (reader['norm_source_id'],reader['columns'],reader['rows'],reader['product_word_bytes']) !=
            (record['rms_source_id'],width,rows*heads,4)):
        raise ValueError('RoPE must read its own weighted q_norm/k_norm source')
    half, lane = width//2, first % width
    if lane//half != (lane+count-1)//half:
        raise ValueError('RoPE word cannot cross a half-head or row')
    natural(record['rotating_pairs'], 'RoPE active pairs', 0, half)
    position,pairs = public_row
    if type(position) is not int or position != start+first//(heads*width) or len(pairs) != record['rotating_pairs']:
        raise ValueError('RoPE public row must use the exact absolute position and active pairs')
    natural(len(pairs), 'RoPE active pairs', 0, half)
    for c,s in pairs:
        natural(c, 'RoPE public cosine', -(1 << 30), 1 << 30)
        natural(s, 'RoPE public sine', -(1 << 30), 1 << 30)
    left = first-lane+lane % half
    a = [v[2] for v in rms_read_input_word(reader,left,count,buffers,coefficients)]
    b = [v[2] for v in rms_read_input_word(reader,left+half,count,buffers,coefficients)]
    result = []
    for j,(x,y) in enumerate(zip(a,b),lane % half):
        c,s = pairs[j] if j < len(pairs) else (1 << 30,0)
        result.append(c*x-s*y if lane < half else s*x+c*y)
    return result


def rope_byte_bridge_screen(cohorts):
    """S+Y+RoPE source-path recount; excludes RMS-J, full Gamma and runtime.

    Sweep live lengths without constructing 3947 layouts. Public-zero rows
    reduce transmitted corrections, NOT the conservative array reservation.
    """
    if cohorts[0]['rows'] != 150 or cohorts[-1]['rows'] != 50:
        raise ValueError('RoPE bridge accounting covers pinned 100+50 only')
    extra = rope_raw_byte_sources(cohorts)
    extra_byte,extra_rq = auxiliary_word_layout(extra)
    added_cells = sum(math.prod(s['shape']) for s in extra)
    cases = []
    for old in (0,CONTEXT_CAP-150):
        base = auxiliary_word_sources(cohorts,old)+rms_statistic_byte_sources(cohorts)+rms_output_byte_sources(cohorts)
        old_bytes,old_rq = auxiliary_word_layout(base)
        sources = base+extra
        byte_tiles,rq_tiles = auxiliary_word_layout(sources)
        live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
        rq_live = sum(math.prod(s['shape']) for s in sources if s['rne'])
        cases.append({'old_tokens':old, 'source_templates':len(sources),
                      'source_byte_cells':live, 'source_padded_byte_cells':1 << (live-1).bit_length(),
                      'rq_live_cells':rq_live, 'rq_padded_cells':1 << (rq_live-1).bit_length(),
                      'byte_cubes':len(byte_tiles), 'rq_cubes':len(rq_tiles),
                      'layout_sha256':hashlib.sha256(json.dumps(
                          [sources,byte_tiles,rq_tiles],sort_keys=True,separators=(',',':')).encode()).hexdigest()})
        assert len(byte_tiles)-len(old_bytes) == len(extra_byte)
        assert len(rq_tiles)-len(old_rq) == len(extra_rq)
    base_live = cases[0]['source_byte_cells']-6*added_cells
    base_rq = cases[0]['rq_live_cells']-added_cells
    stride = pinned_model_config()['layers']*pinned_model_config()['query_heads']*150
    changes = {}
    for name,first,step,delta in (('sigma',base_live,6*stride,6*added_cells),('rq',base_rq,stride,added_cells)):
        changes[name] = [o for o in range(CONTEXT_CAP-150+1)
                         if (first+step*o-1).bit_length() != (first+step*o+delta-1).bit_length()]
    rope = gemma_rope_plan(cohorts)['summary']
    linear_e = rope['one_probe_per_raw_cohort_corrections']+rope['raw_linear_sumcheck_corrections']
    sigma = {n:wide_hash_joint_opening_screen([1 << n],1 << 23,357) for n in (33,34)}
    sigma_e = {n:sigma[n]['extension_corrections_including_paired_sumchecks']
               +byte_range_tree_screen(n)['extension_corrections']
               +byte_bit_lift_screen(n)['extension_corrections_excluding_incoming_claims'] for n in sigma}
    rq_e = {n:rne_indicator_screen(n,18,11)['extension_corrections']
            +rne_output_bit_screen(n)['additional_extension_corrections'] for n in (30,31)}
    def source_counts(live, rq_live):
        n,t = (live-1).bit_length(),(rq_live-1).bit_length()
        zeros = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
        return sigma[n]['base_corrections_including_salts']-357*zeros,sigma_e[n]+rq_e[t]

    config = pinned_model_config()
    kv_width = sum(2*config[k+'_layers']*config[k+'_kv_heads']*config[k+'_head_dim']
                   for k in ('local','global'))
    weight_live = sum(math.prod(s) for s in {c['weight_key']:c['weight_shape'] for c in cohorts}.values())
    stats = rms_statistic_screen(cohorts)
    fixed_e = (weight_cohort_screen(cohorts)['extension_corrections_before_other_circuits']
               +input_link_screen(cohorts)['extension_corrections']+stats['extension_corrections']
               +len(rms_statistic_byte_sources(cohorts))+120+2+linear_e)
    k1_e = [kv_transition_screen(o)['extension_corrections'] for o in (0,1)]
    # T1 and its two-point KV router depend on the padded token domain.
    attention = {n:attention_product_screen((1 << n)-150) for n in range(8,13)}
    joint_by_shape, totals, deltas = {}, [], []
    for old in range(CONTEXT_CAP-150+1):
        live,rq_live = base_live+6*stride*old,base_rq+stride*old
        before_b,before_e = source_counts(live,rq_live)
        b,e = source_counts(live+6*added_cells,rq_live+added_cells)
        deltas.append((b-before_b,e-before_e+linear_e))
        prefixes = [weight_live]+[kv_width*(1 << (length-1).bit_length())
                                  for length in (old,old+150) if length]
        shape = (1 << 35,)+tuple(max(1 << 24,1 << (v-1).bit_length()) for v in prefixes[1:])
        if shape not in joint_by_shape:
            joint_by_shape[shape] = wide_hash_joint_opening_screen(shape,1 << 24,357)
        joint = joint_by_shape[shape]
        zeros = sum(n//(1 << 24)-(v+(1 << 24)-1)//(1 << 24) for n,v in zip(shape,prefixes))
        a = attention[(old+149).bit_length()]
        b += joint['base_corrections_including_salts']-357*zeros
        e += (joint['extension_corrections_including_paired_sumchecks']+fixed_e+k1_e[bool(old)]
              +a['extension_corrections']+a['kv_router_with_k1_and_one_call_each']['extension_corrections'])
        # One common closure and every W/KV/Sigma anchor. RMS input split's
        # two E corrections are in fixed_e; incoming T1/K1 wires cost no copy.
        totals.append(8*b+24*e+72+64*(len(shape)+1))
        if old in (0,CONTEXT_CAP-150):
            case = cases[int(bool(old))]
            case['known_partial_payload_before_rms_joint_gamma_and_framing'] = totals[-1]
            case['known_authenticated_record_bytes_before_rms_joint_gamma'] = 32*b+48*(e+1)

    # The capacity domains already bound the extension for EVERY old length.
    # Keep all old (unomitted) reservations: adding the actual record delta at
    # an endpoint instead would mix a payload saving with an allocation bound.
    bridge = rms_byte_bridge_screen(cohorts,True)
    rounds = rope['raw_linear_sumcheck_rounds']
    arrays = {'source_and_cube_descriptors':96*len(extra)+72*len(extra_byte)+56*len(extra_rq),
              'linear_plaintexts_and_tags':48*linear_e,
              'raw_probe_and_y_endpoint_points':48*rounds,
              'incoming_t1_k1_points_and_weights':24*(rounds+len(extra)),
              'linear_cohort_descriptors':72*len(extra),
              'public_q30_coefficients':rope['public_active_Q30_table_bytes_at_capacity'],
              'linear_control':65536}
    arrays = {k:256*((v+255)//256) for k,v in arrays.items()}
    forms = rope['public_form_and_linear_field_work']
    assert max(forms['maximum_fill_eq_and_row_array_bytes']+1024,
               forms['maximum_verifier_weight_arrays_and_control_bytes']) <= arrays['linear_control']
    phases = {k:v+sum(arrays.values())+(48*len(extra_rq) if k == 'rne_top' else 0)
              for k,v in bridge['all_context_arena_phase_upper_bytes'].items()}
    phases['rope_linear'] = (phases['opening_first_pass']-80*(1 << 23)
                             +rope['maximum_two_field_arrays_without_reader'])
    sigma_visits = 16+byte_range_tree_screen(34)['source_visits_including_gate_histograms']+2+byte_bit_lift_screen(34)['source_visits']
    rq_visits = rne_indicator_screen(31,18,11)['source_rq_visits']
    readers = rms_cut_reader_plan(cohorts)
    for r in gemma_rope_plan(cohorts)['cohorts']:
        assert readers[r['rms_source_id']]['product_word_bytes'] == 4
    assert all(t[2] % 64 == 0 and t[5] % 64 == 0 and t[-1] % (64*t[7]) == 0 for t in extra_byte)
    assert all(t[7] in (2,4) for t in extra_byte)
    sigma_raw_cells = sum(math.prod(t[3:6]) for t in extra_byte)
    rq_raw_cells = sum(math.prod(t[3:6]) for t in extra_rq)
    assert sigma_raw_cells == 2*added_cells and rq_raw_cells == added_cells
    raw_generations = sigma_visits*sigma_raw_cells+rq_visits*rq_raw_cells
    y_generations = 2*raw_generations+added_cells  # one Y fill also computes each honest raw probe
    reader_work = {'credit':False, 'raw_word_lanes':64, 'retained_word_buffer_bytes':1024,
                   'public_profile_validation_hoisted_before_replay':True,
                   'sigma_raw_generations_per_live_cell_per_visit':2,
                   'rq_raw_generations_per_live_cell_per_visit':1,
                   'bulk_raw_generations':raw_generations,
                   'y_generations_including_linear_fill':y_generations,
                   'B_S_kappa_logical_read_bytes':4*y_generations+12*(y_generations//64),
                   'public_q30_logical_read_bytes_upper':8*raw_generations+forms['fill_public_q30_read_bytes_upper'],
                   'raw_signed_i64_products_upper':2*raw_generations,
                   'raw_signed_i64_additions_upper':raw_generations,
                   'extra_input_raw_rne_calls':0,
                   'complete_all_gamma_reader_work_and_runtime':None}
    return {'credit':False, 'extends_source':'S+Y', 'raw_rope_sources':len(extra),
            'raw_rope_cells':added_cells, 'extra_virtual_source_bytes':6*added_cells,
            'extra_byte_cubes':len(extra_byte), 'extra_rq_cubes':len(extra_rq),
            'extra_source_and_cube_descriptor_bytes':96*len(extra)+72*len(extra_byte)+56*len(extra_rq),
            'additional_direct_sigma_claim_wires':2*len(extra),
            'known_t1_k1_rope_output_demands':len(extra),
            'contexts_checked':CONTEXT_CAP-150+1, 'changed_padding_contexts':changes,
            'source_path_correction_deltas_by_old_tokens':deltas,
            'source_path_payload_delta_distribution':dict(sorted(Counter(8*b+24*e for b,e in deltas).items())),
            'maximum_source_path_record_delta_bytes':max(32*b+48*e for b,e in deltas),
            'known_partial_payload_by_old_tokens':totals,
            'maximum_known_partial_payload_before_rms_joint_gamma_and_framing':max(totals),
            'remaining_payload_bytes_before_missing_components':35_000_000-max(totals),
            'additional_known_retained_arrays_256_byte_aligned':arrays,
            'source_and_rope_arena_phase_upper_bytes_before_rms_joint_reader_gamma_runtime':phases,
            'known_phase_max_upper_bytes_before_rms_joint_reader_gamma_runtime':max(phases.values()),
            'known_bulk_sigma_visits':sigma_visits, 'known_bulk_rq_visits':rq_visits,
            'base_rms_output_layout_sha256':[c['layout_sha256'] for c in bridge['cases']],
            'word_reader_work':reader_work,
            'raw_byte_requests_in_known_bulk_paths':6*(sigma_visits+rq_visits)*added_cells,
            'raw_linear_field_products_before_fill_reader_mac':rope['linear_sumcheck_field_products_before_fill_reader_mac'],
            'cases':cases, 'same_rq_layout':False, 'additional_pcs_instances':0,
            'additional_weight_reads_given_w_free_reader':0,
            'complete_extended_payload_and_liveness':None}


def rms_integer_coefficients(columns, input_exponent, scale_exponent, output_exponent):
    """Public A,B,C with squared output magnitude A*P^2/(B+C*S).

    P=x*w (or x with scale_exponent=0); S=sum(x^2). This nominates one
    exact-output RNE, not a calibrated Gemma table or a MAC circuit.
    The 4096-bit guard bounds this LOCAL diagnostic, not the design profile.
    """
    natural(columns, "RMS width", 1, 5376)
    if any(type(e) is not int for e in (input_exponent, scale_exponent, output_exponent)):
        raise ValueError("RMS exponents must be public integers")
    exponent = input_exponent+scale_exponent-output_exponent
    shift = max(0, -2*exponent, -2*input_exponent)
    a_shift, c_shift = 2*exponent+shift, 2*input_exponent+shift
    # Bound intermediates BEFORE allocating shifts, independently of P/S.
    top_bits = (4*1_000_000*columns*32767**4).bit_length()+a_shift
    bottom_bits = max(columns.bit_length()+shift,
                      (1_000_000*columns*32767**2).bit_length()+c_shift)+33
    # ponytail: local 4096-bit ceiling; compile the real profile's widths before lifting it.
    if max(top_bits, bottom_bits) > 4096:
        raise ValueError("RMS profile exceeds the local 4096-bit diagnostic limit")
    coefficients = (1_000_000*columns << a_shift, columns << shift, 1_000_000 << c_shift)
    common = math.gcd(*coefficients)
    return tuple(v//common for v in coefficients)


def rne_sqrt_ratio(numerator, denominator):
    """Exact RNE(sqrt(N/D)) in 0..32767, or reject. No floating point.

    Scalar diagnostic only: division/isqrt are NOT authenticated primitives.
    """
    natural(numerator, "squared numerator", 0, (1 << 4096)-1)
    natural(denominator, "squared denominator", 1, (1 << 4096)-1)
    if 4*numerator >= 65535**2*denominator:
        raise ValueError("RMS output overflows symmetric i16")
    floor = math.isqrt(numerator//denominator)
    midpoint = 4*numerator-denominator*(2*floor+1)**2
    return floor+int(midpoint > 0 or midpoint == 0 and floor & 1)


def rms_rne_i16(product, statistic, columns, input_exponent, scale_exponent, output_exponent):
    """Candidate scalar RMS lowering from already source-bound P and S.

    Validating ranges here does not prove P=x*w or S=sum(x^2), nor bind
    bit decompositions in Gamma. Unweighted callers use P=x and e_w=0.
    """
    a, b, c = rms_integer_coefficients(columns, input_exponent, scale_exponent, output_exponent)
    natural(product, "RMS integer product", -32767**2, 32767**2)
    natural(statistic, "RMS integer statistic", 0, columns*32767**2)
    magnitude = rne_sqrt_ratio(a*product**2, b+c*statistic)
    return -magnitude if product < 0 else magnitude


def rms_row_multiplier(numerator, denominator):
    """Six-byte honest cache floor(2^32*sqrt(A/D)), capped at 2^47.

    A is public; D=B+C*S uses the existing row statistic. This cache is
    neither a new authenticated source nor a substitute for the RMS predicate.
    """
    natural(numerator, 'RMS row numerator', 1, (1 << 4096)-1)
    natural(denominator, 'RMS row denominator', 1, (1 << 4096)-1)
    if numerator >= denominator << 30:
        return 1 << 47  # Every nonzero integer P overflows.
    return math.isqrt((numerator << 64)//denominator)


def rms_rne_from_multiplier(product, numerator, denominator, multiplier):
    """Honest getter from rms_row_multiplier's SAME A,D and validated P.

    Requires the prepared multiplier, not an arbitrary prover-supplied hint.
    The unchanged predicate independently checks Y; this is not a verifier.
    One small fixed-point rounding and at most one exact wide comparison.
    """
    natural(product, 'RMS integer product', -32767**2, 32767**2)
    natural(numerator, 'RMS row numerator', 1, (1 << 4096)-1)
    natural(denominator, 'RMS row denominator', 1, (1 << 4096)-1)
    natural(multiplier, 'RMS row multiplier', 0, 1 << 47)
    if product == 0:
        return 0
    if multiplier == 1 << 47:
        raise ValueError('RMS output overflows symmetric i16')
    scaled = abs(product)*multiplier
    floor, remainder = scaled >> 32, scaled & ((1 << 32)-1)
    magnitude = floor+int(remainder > 1 << 31 or remainder == 1 << 31 and floor & 1)
    if magnitude > 32767:
        raise ValueError('RMS output overflows symmetric i16')
    middle = 4*numerator*product**2-denominator*(2*magnitude+1)**2
    magnitude += int(middle > 0 or middle == 0 and magnitude & 1)
    if magnitude > 32767:
        raise ValueError('RMS output overflows symmetric i16')
    return -magnitude if product < 0 else magnitude


def rms_getter_integer_screen(coefficients):
    """Native storage/work contract for the division-free row/lane getter.

    Public A,B,C occupy at most u128 each in this LOCAL profile. The bound
    covers every 0<=S<2^47 and the getter's validated |P|<=32767^2.
    Sixteen 2L-limb banks + 256 control bytes per lane; 64 lanes per wave.
    """
    if len(coefficients) != 3:
        raise ValueError('RMS getter needs A, B and C')
    for v in coefficients:
        natural(v, 'RMS native public coefficient', 1, (1 << 128)-1)
    a,b,c = coefficients
    denominator = b+c*((1 << 47)-1)
    bits = max(a.bit_length()+64, (denominator*((1 << 47)-1)**2).bit_length())
    limbs = (bits+63)//64
    return {'credit': False, 'maximum_intermediate_bits': bits, 'u64_limbs': limbs,
            'scalar_scratch_bytes': 16*2*limbs*8+256,
            'one_64_lane_wave_scratch_bytes': 64*(16*2*limbs*8+256),
            'row_preparation_mul64_wide_upper': 95*limbs*limbs,
            'lane_generation_mul64_wide_upper_with_denominator': 6*limbs*limbs,
            'complete_reader_control_traffic_and_runtime': None}


def rms_boolean_circuit(columns, input_exponent, scale_exponent, output_exponent,
                        weighted=True, verify_output=False):
    """Small explicit AND/XOR DAG for exact RMS, NOT a GKR/MAC prover.

    Inputs are little-endian biased P (32/16 bits), S (48), and optionally
    candidate y (16). Constants have wire IDs 0/1, followed by inputs.
    Public constant folding never inspects input values. The 128-bit cap
    limits this local graph diagnostic, not the Gemma exponent profile.
    """
    if type(weighted) is not bool or type(verify_output) is not bool:
        raise ValueError('RMS circuit modes must be Boolean')
    if not weighted and scale_exponent != 0:
        raise ValueError('unweighted RMS requires scale exponent zero')
    a, b, c = rms_integer_coefficients(columns, input_exponent, scale_exponent, output_exponent)
    pw = 32 if weighted else 16
    limit = 32767**2 if weighted else 32767
    denominator_max = b+c*((1 << 47)-1)
    width = max((4*a*(1 << (pw-1))**2).bit_length(),
                (denominator_max*((1 << 17)-1)**2).bit_length())
    # ponytail: cap local DAG construction; real-profile widths and GKR lowering are separate obligations.
    if width > 128:
        raise ValueError('RMS circuit exceeds the local 128-bit DAG limit')
    inputs = pw+48+(16 if verify_output else 0)
    gates, depths, shared = [], [0]*(2+inputs), {}
    def gate(op, x, y):
        if x == y:
            return x if op == 'and' else 0
        if op == 'and':
            if x == 0 or y == 0:
                return 0
            if x == 1 or y == 1:
                return y if x == 1 else x
        elif x == 0 or y == 0:
            return y if x == 0 else x
        key = (op,min(x,y),max(x,y))  # Public commutative gate identity, never witness values.
        if key in shared:
            return shared[key]
        result = len(depths)
        shared[key] = result
        gates.append((op, x, y))
        depths.append(1+max(depths[x], depths[y]))
        return result
    def both(x, y):
        return gate('and', x, y)
    def xor(x, y):
        return gate('xor', x, y)
    def inv(x):
        return xor(x, 1)
    def either(x, y):
        return xor(xor(x,y), both(x,y))
    def mux(bit, yes, no):
        return xor(no, both(bit, xor(yes,no)))
    def constant(value, n):
        return [(value >> i) & 1 for i in range(n)]
    def pad(word, n):
        return (word+[0]*n)[:n]
    def all_bits(word):
        word = list(word)
        while len(word) > 1:
            word = [both(word[i], word[i+1]) if i+1 < len(word) else word[i]
                    for i in range(0,len(word),2)]
        return word[0] if word else 1
    def prefix(g, p):
        # Compose (generate,propagate) blocks: high block takes precedence.
        distance = 1
        while distance < len(g):
            old_g, old_p = g, p
            g = [xor(old_g[i],both(old_p[i],old_g[i-distance])) if i >= distance else old_g[i]
                 for i in range(len(g))]
            p = [both(old_p[i],old_p[i-distance]) if i >= distance else old_p[i]
                 for i in range(len(p))]
            distance *= 2
        return g, p
    def add(x, y, n):
        x, y = pad(x,n), pad(y,n)
        initial = [xor(u,v) for u,v in zip(x,y)]
        generate, _ = prefix([both(u,v) for u,v in zip(x,y)], initial)
        return [xor(v,generate[i-1]) if i else v for i,v in enumerate(initial)]
    def sum_words(rows, n):
        rows = [pad(row,n) for row in rows if any(row)] or [[0]*n]
        while len(rows) > 2:
            merged = []
            for i in range(0,len(rows)-2,3):
                x,y,z = rows[i:i+3]
                t = [xor(u,v) for u,v in zip(x,y)]
                merged.append([xor(u,v) for u,v in zip(t,z)])
                merged.append([0]+[xor(both(x[j],y[j]),both(t[j],z[j])) for j in range(n-1)])
            rows = merged+rows[len(rows)//3*3:]
        return rows[0] if len(rows) == 1 else add(*rows,n)
    def multiply(x, y, n):
        if len(y) > len(x):
            x,y = y,x
        if x == y:
            # x_i^2=x_i; each off-diagonal pair contributes once at bit i+j+1.
            rows = [[x[i//2] if i % 2 == 0 and i//2 < len(x) else 0 for i in range(n)]]
            rows += [[0]*(2*i+2)+[both(u,v) for v in x[i+1:n-i-1]]
                     for i,u in enumerate(x) if u != 0 and 2*i+2 < n]
        else:
            rows = [[0]*i+[both(u,v) for u in x[:n-i]] for i,v in enumerate(y[:n]) if v != 0]
        return sum_words(rows,n)
    def compare(x, y, n):
        x,y = pad(x,n),pad(y,n)
        lt,eq = prefix([both(inv(u),v) for u,v in zip(x,y)], [inv(xor(u,v)) for u,v in zip(x,y)])
        return lt[-1],eq[-1]
    def le(x, y, n):
        lt,eq = compare(x,y,n)
        return xor(lt,eq)  # disjoint flags, not a general OR shortcut
    def magnitude(word):
        negative = inv(word[-1])
        twos = word[:-1]+[negative]
        return add([xor(x,negative) for x in twos], [negative], len(word)),negative

    product = list(range(2,2+pw))
    statistic = list(range(2+pw,2+pw+48))
    pmag,pneg = magnitude(product)
    # All arithmetic is total: on invalid negative S, use its low 47 bits
    # but keep the sign/range guard FALSE. Never assume D>0 from an unproved S.
    surrogate = statistic[:47]
    pg = le(pmag,constant(limit,pw),pw)
    sg = both(statistic[47],le(surrogate,constant(columns*32767**2,47),47))
    square = multiply(pmag,pmag,2*pw)
    numerator4 = multiply(square,constant(4*a,width),width)
    denominator = add(multiply(surrogate,constant(c,width),width),constant(b,width),width)
    def threshold(odd):
        return multiply(denominator,multiply(odd,odd,2*len(odd)),width)
    if verify_output:
        output = list(range(2+pw+48,2+inputs))
        m,negative = magnitude(output)
        zero = all_bits([inv(v) for v in m])
        yg = inv(all_bits([inv(v) for v in output]))  # excludes exactly -32768
        sign = either(zero,inv(xor(pneg,negative)))
        lower = threshold(add([0]+m,constant((1 << 17)-1,17),17))
        upper = threshold(add([0]+m,[1],17))
        lo,lo_eq = compare(lower,numerator4,width)
        hi,hi_eq = compare(numerator4,upper,width)
        even = inv(m[0])
        between = both(xor(lo,both(lo_eq,even)),xor(hi,both(hi_eq,even)))
        bound = mux(zero,le(numerator4,denominator,width),between)
        valid = all_bits([pg,sg,yg,sign,bound])
    else:
        q = [0]*15
        for i in range(14,-1,-1):
            trial = list(q)
            trial[i] = 1
            trial_cost = threshold(trial)
            q[i] = le([0,0]+trial_cost,numerator4,width)
        odd = add([0]+q,[1],16)
        lt,eq = compare(numerator4,threshold(odd),width)
        up = xor(inv(xor(lt,eq)),both(eq,q[0]))
        m = add(q,[up],16)
        safe,_ = compare(numerator4,threshold(constant(65535,16)),width)
        valid = all_bits([pg,sg,safe])
        signed = add([xor(v,pneg) for v in m],[pneg],16)
        biased = signed[:-1]+[inv(signed[-1])]
        output = [mux(valid,v,int(i == 15)) for i,v in enumerate(biased)]
    return {'gates': gates, 'input_bits': inputs, 'product_bits': pw,
            'output_wires': output, 'valid_wire': valid,
            'summary': {'credit': False, 'weighted': weighted, 'verify_output': verify_output,
                        'coefficients': [a,b,c], 'total_arithmetic_bits': width,
                        'binary_gates_by_op': dict(Counter(op for op,_,_ in gates)),
                        'binary_gate_count': len(gates), 'generated_dag_depth': max(depths),
                        'input_guard_depth': max(depths[pg],depths[sg]),
                        'output_dependency_depth': max(depths[i] for i in [valid,*output]),
                        'largest_unpadded_level': max(Counter(depths[2+inputs:]).values()),
                        'requires_copy_wires_or_general_dag_reduction': True,
                        'requires_separately_bound_candidate_y': verify_output,
                        'complete_mac_records_memory_and_feasibility': None}}


def rms_layered_circuit(circuit):
    """Public RMS DAG lowering: prune dead gates, explicitly carry live wires.

    No cell replicas are allocated. Rows are (AND/XOR/copy, left, right)
    in the preceding layer; input ports keep constants 0/1 then biased bits.
    """
    base = 2+natural(circuit['input_bits'], 'local circuit input bits', 0, 128)
    gates, depths = circuit['gates'], [0]*base
    for op, x, y in gates:
        if op not in ('and', 'xor') or any(type(w) is not int or not 0 <= w < len(depths) for w in (x,y)):
            raise ValueError('invalid topological Boolean gate')
        depths.append(1+max(depths[x],depths[y]))
    roots = [circuit['valid_wire']]+([] if circuit['summary']['verify_output'] else circuit['output_wires'])
    if any(type(w) is not int or not 0 <= w < len(depths) for w in roots):
        raise ValueError('invalid Boolean output wire')
    height = natural(max(depths[w] for w in roots), 'local layered depth', 0, 4096)
    needed, stack = set(), roots[:]
    while stack:
        wire = stack.pop()
        if wire in needed:
            continue
        needed.add(wire)
        if wire >= base:
            stack.extend(gates[wire-base][1:])
    last = {w: 0 for w in range(base)} | {w: 0 for w in needed}
    for w in roots:
        last[w] = height+1
    for w in needed:
        if w >= base:
            for parent in gates[w-base][1:]:
                last[parent] = max(last[parent],depths[w])
    births, expires = [[] for _ in range(height+2)], [[] for _ in range(height+2)]
    for w, end in last.items():
        if w >= base:
            births[depths[w]].append(w)
        expires[max(1,end)].append(w)
    # ponytail: materialize only a small public scalar blueprint, never Gemma's replicated trace.
    expanded = sum(max(0,end-max(1,depths[w])) for w,end in last.items())
    if expanded > 2_000_000:
        raise ValueError('local layered circuit exceeds two million rows')
    active, previous = set(range(base)), {w:w for w in range(base)}
    levels, widths, copies = [], [base], 0
    for depth in range(1,height+1):
        active.difference_update(expires[depth])
        active.update(births[depth])
        wires = sorted(active)
        layer = []
        for w in wires:
            if depths[w] == depth:
                op,x,y = gates[w-base]
                layer.append((op,previous[x],previous[y]))
            else:
                layer.append(('copy',previous[w],previous[w]))
                copies += 1
        levels.append(layer)
        widths.append(len(layer))
        previous = {w:i for i,w in enumerate(wires)}
    return {'input_ports': base, 'levels': levels,
            'output_positions': [previous[w] for w in roots],
            'summary': {'credit': False, 'depth': height, 'level_widths': widths,
                        'reachable_binary_gates': len(needed-set(range(base))),
                        'copy_gates': copies, 'expanded_layer_rows': expanded,
                        'complete_replicated_trace_memory_or_work': None}}


def rms_bitpacked_replay(layered, input_planes, depth, live_mask=(1 << 64)-1):
    """Replay up to 64 Boolean cells of ONE public profile, before E folding.

    Uses rms_layered_circuit's validated program. Bit j of every word is
    cell j, not bit j of an integer arithmetic value. No production prover.
    """
    natural(depth, 'Boolean replay depth', 0, len(layered['levels']))
    natural(live_mask, 'Boolean live-cell mask', 0, (1 << 64)-1)
    if len(input_planes) != layered['input_ports'] or len(input_planes) < 2:
        raise ValueError('Boolean replay input shape mismatch')
    for word in input_planes:
        natural(word, 'Boolean bit plane', 0, (1 << 64)-1)
        if word & ~live_mask:
            raise ValueError('nonzero Boolean cell padding')
    if input_planes[0] != 0 or input_planes[1] != live_mask:
        raise ValueError('Boolean constants must respect live-cell support')
    values = input_planes
    for layer in layered['levels'][:depth]:
        following = []
        for op,a,b in layer:
            if any(type(i) is not int or not 0 <= i < len(values) for i in (a,b)):
                raise ValueError('invalid Boolean replay parent')
            if op == 'and':
                following.append(values[a] & values[b])
            elif op == 'xor':
                following.append(values[a] ^ values[b])
            elif op == 'copy' and a == b:
                following.append(values[a])
            else:
                raise ValueError('invalid Boolean replay gate')
        values = following
    return values


def boolean_word_fold_tables(point):
    """Public subset tables for at most six low cell coordinates (Fp toy).

    At most eight tables of 256 values; bit projections/folds extend to E.
    These are functions of public challenges, not new witness oracles.
    """
    natural(len(point), 'Boolean word fold coordinates', 0, 6)
    for value in point:
        natural(value, 'Boolean fold coordinate', 0, P-1)
    low = min(3,len(point))
    weights = [math.prod(v if j >> k & 1 else 1-v for k,v in enumerate(point[:low])) % P
               for j in range(1 << low)]
    subsets = [0]*(1 << (1 << low))
    for mask in range(1,len(subsets)):
        bit = mask & -mask
        subsets[mask] = (subsets[mask ^ bit]+weights[bit.bit_length()-1]) % P
    scales = [math.prod(v if j >> k & 1 else 1-v for k,v in enumerate(point[low:])) % P
              for j in range(1 << (len(point)-low))]
    return [[scale*v % P for v in subsets] for scale in scales]


def fold_boolean_word(word, tables, word_bits=64):
    """Fold a bit word using boolean_word_fold_tables's public tables.

    Returns word_bits/2^h field values. Applying gates to these folded values as
    though they were bits is invalid; gate replay must precede this step.
    """
    natural(word_bits, 'Boolean word width', 1, 64)
    if word_bits & (word_bits-1):
        raise ValueError('Boolean word width must be a power of two')
    natural(word, 'Boolean cell word', 0, (1 << word_bits)-1)
    if not tables or len(tables) not in (1,2,4,8) or len(tables[0]) not in (2,4,16,256):
        raise ValueError('invalid Boolean fold table shape')
    chunk = (len(tables[0])-1).bit_length()
    if any(len(t) != 1 << chunk for t in tables) or chunk < 8 and len(tables) != 1:
        raise ValueError('noncanonical Boolean fold chunks')
    width = chunk*len(tables)
    if width > word_bits:
        raise ValueError('Boolean fold exceeds the word width')
    return [sum(t[(word >> (offset+chunk*j)) & ((1 << chunk)-1)] for j,t in enumerate(tables)) % P
            for offset in range(0,word_bits,width)]


def split_boolean_word(word):
    """Even/odd cell planes as two u32; 33 word shifts/OR/AND in total."""
    natural(word, 'Boolean cell word', 0, (1 << 64)-1)
    def compact(value):
        value &= 0x5555555555555555
        for shift,mask in ((1,0x3333333333333333), (2,0x0F0F0F0F0F0F0F0F),
                           (4,0x00FF00FF00FF00FF), (8,0x0000FFFF0000FFFF), (16,0xFFFFFFFF)):
            value = (value | (value >> shift)) & mask
        return value
    return compact(word), compact(word >> 1)


def rms_gkr_first_word_coefficients(op, x, y, tables, r0, weight, profile_mask):
    """First cell round on one aligned 64-cell block; same four coefficients.

    x/y are split_boolean_word's planes; tables use r[1:6], weight is
    lambda_g*EQ(r[6:],global_word_index). Only constant public profile masks
    are supported: a mixed mask requires the general field-pair path.
    """
    if op not in ('and','xor','copy') or len(x) != 2 or len(y) != 2:
        raise ValueError('invalid first-round Boolean gate')
    for word in (*x,*y):
        natural(word, 'first-round u32 plane', 0, (1 << 32)-1)
    for value in (r0,weight):
        natural(value, 'first-round field value', 0, P-1)
    natural(profile_mask, 'first-round profile mask', 0, (1 << 64)-1)
    if profile_mask not in (0,(1 << 64)-1):
        raise ValueError('mixed profile block requires the general cell-round path')
    if len(tables) != 4 or any(len(t) != 256 for t in tables):
        raise ValueError('first round requires the five-coordinate public tables')
    if not profile_mask:
        return [0]*4
    moments = [fold_boolean_word(a & b if op == 'and' else a ^ b if op == 'xor' else a,
                                tables,32)[0] for a in x for b in y]
    m00,m01,m10,m11 = moments
    a, b, c = m00, (m01+m10-2*m00) % P, (m11-m01-m10+m00) % P
    f0, df = weight*(1-r0) % P, weight*(2*r0-1) % P
    return [f0*a % P, (f0*b+df*a) % P, (f0*c+df*b) % P, df*c % P]


def rms_gkr_cell_pair_coefficients(op, x0, x1, y0, y1, psi0, psi1, weight):
    """Four Fp coefficients of weight*psi(T)*op(X(T),Y(T)).

    Inputs are FIELD folds, not bits. With a constant X or Y and psi(T)
    equal to T or 1-T, this also supplies the quadratic index-round edge.
    At most 12 products and 14 additions, before four accumulator additions.
    """
    for v in (x0,x1,y0,y1,psi0,psi1,weight):
        natural(v, 'RMS GKR field value', 0, P-1)
    dx, dy = (x1-x0) % P, (y1-y0) % P
    f0, f1 = weight*psi0 % P, weight*psi1 % P
    df = (f1-f0) % P
    if op == 'copy':
        return [f0*x0 % P, (f0*dx+df*x0) % P, df*dx % P, 0]
    if op not in ('and', 'xor'):
        raise ValueError('invalid RMS GKR gate')
    a, b, c = x0*y0 % P, (x0*dy+dx*y0) % P, dx*dy % P
    if op == 'xor':
        a, b, c = (x0+y0-2*a) % P, (dx+dy-2*b) % P, -2*c % P
    return [f0*a % P, (f0*b+df*a) % P, (f0*c+df*b) % P, df*c % P]


def rms_gkr_profile_events(intervals, point, prefix):
    """Public sweep for MLE(mu_t*EQ(point,.)) after fixing low prefix bits.

    Sorted, disjoint dyadic intervals are (start, log2_size, profile).
    At suffix z, apply events <=z, then multiply each profile accumulator
    by EQ(point[h:],z). No private table or inverse; at most two events/cube.
    """
    n, h = len(point), len(prefix)
    natural(n, 'RMS cell dimensions', 1, 32)
    natural(h, 'RMS cell prefix length', 0, n)
    for v in (*point,*prefix):
        natural(v, 'RMS public field coordinate', 0, P-1)
    events, end = [], 0
    for start,d,profile in intervals:
        natural(start, 'RMS cube start', 0, (1 << n)-1)
        natural(d, 'RMS cube dimension', 0, n)
        natural(profile, 'RMS profile index', 0, 2_000_000)
        size = 1 << d
        if start % size or start < end or start+size > 1 << n:
            raise ValueError('RMS cubes must be aligned, sorted and disjoint')
        end = start+size
        gamma = 1
        for i,(r,a) in enumerate(zip(point,prefix)):
            factor = ((1-r)*(1-a)+r*a if i < d else
                      (r if start >> i & 1 else 1-r)*(a if start >> i & 1 else 1-a))
            gamma = gamma*factor % P
        events.extend([(start >> h,profile,gamma), (((end-1) >> h)+1,profile,-gamma % P)])
    events.sort()
    return events


def rms_joint_gkr_screen(profile_widths, cell_bits):
    """Shared cell axis; shorter profiles carry their final table unchanged.

    Four E coefficients per cell round, three per gate-index round;
    two endpoints and one product per layer. Input adapters not included.
    """
    natural(cell_bits, 'RMS joint cell bits', 1, 32)
    if not profile_widths or any(not widths for widths in profile_widths):
        raise ValueError('missing public layer widths')
    for widths in profile_widths:
        for width in widths:
            natural(width, 'local layer width', 1, 2_000_000)
    depth = natural(max(map(len,profile_widths))-1, 'local joint depth', 0, 4096)
    widths = [max(profile[min(d,len(profile)-1)] for profile in profile_widths) for d in range(depth+1)]
    bits = [(w-1).bit_length() for w in widths]
    gate_bits = sum(bits[:-1])
    rounds = depth*cell_bits+2*gate_bits
    coefficients = 4*depth*cell_bits+6*gate_bits
    # ponytail: reference replay, not a fast prover; cache/fuse only with a new liveness/work proof.
    prefixes = [max(0,cell_bits+s-21) for s in bits[:-1]]
    # An aligned 64-cell word executes one public Boolean profile. This counts
    # a conservative padded-domain replay, NOT the SC's remaining field work.
    blocks = ((1 << cell_bits)+63)//64
    cumulative = 0
    word_steps = lookups = chunk_additions = tail_products = table_products = table_additions = 0
    for level,k in enumerate(prefixes):
        if level:
            cumulative += widths[level]
        word_steps += blocks*(k+1)*cumulative
        for h in range(k+1):
            lookups += blocks*widths[level]*(64//min(1 << h,8))
            chunk_additions += blocks*widths[level]*(64//min(1 << h,8)-64//(1 << min(h,6)))
            tail_products += blocks*widths[level]*int(h > 6)
        for h in range(min(k,6)+1):  # Later prefixes reuse the same six-coordinate tables.
            low = min(h,3)
            cells, chunks = 1 << low, 1 << (h-low)
            eq_work = low*cells+(h-low)*chunks
            table_products += eq_work+chunks*(1 << cells)
            table_additions += eq_work+(1 << cells)-1
    return {'credit': False, 'profiles': len(profile_widths), 'depth': depth, 'cell_bits': cell_bits,
            'joint_level_widths': widths, 'gate_index_bits_sum': gate_bits,
            'joint_level_rows_across_profiles': [sum(p[min(d,len(p)-1)] for p in profile_widths)
                                                for d in range(depth+1)],
            'sumcheck_rounds': rounds, 'sumcheck_coefficients': coefficients,
            'endpoint_corrections': 2*depth, 'private_product_equations': depth,
            'zero_residual_equations_before_input_adapters': rounds+depth,
            'endpoint_batch_challenges': depth,
            'interactive_transfer_numerator_before_input_adapters': 3*depth*cell_bits+4*gate_bits+depth,
            'payload_before_incoming_input_adapters_and_shared_closures': 24*(coefficients+3*depth),
            'reference_input_tuple_visits': sum(k+1 for k in prefixes),
            'reference_cell_prefix_bits': prefixes,
            'reference_folded_array_bytes': max([24*(1 << (cell_bits-k+s)) for k,s in zip(prefixes,bits[:-1])] or [0]),
            'reference_two_gate_vectors_bytes': 48*max([1 << s for s in bits[:-1]] or [0]),
            'plaintext_and_tag_records_bytes': 48*(coefficients+3*depth),
            'bitpacked_replay': {
                'credit': False, 'requires_64_cell_aligned_profile_blocks': True,
                'word_gate_or_copy_steps_upper': word_steps,
                'input_bit_transpositions_upper': (1 << cell_bits)*max(0,widths[0]-2)*sum(k+1 for k in prefixes),
                'fold_table_lookups_upper': lookups, 'fold_high_prefix_products_upper': tail_products,
                'fold_chunk_additions_upper': chunk_additions,
                'fold_high_prefix_accumulations_upper': tail_products,
                'fold_table_preparation_products_upper': table_products,
                'fold_table_preparation_additions_upper': table_additions,
                'input_and_two_word_vectors_bytes': 256*((8*((1 << bits[0])+2*(1 << max(bits)))+255)//256),
                'field_block_bytes': 64*24*(1 << max(bits)),
                'public_fold_table_reservation_bytes': 65536,
                'complete_sumcheck_field_work_and_runtime': None},
            'complete_input_forms_and_source_bindings': None,
            'complete_witness_schedule_memory_and_work': None}


def rms_gkr_field_work_screen(joint, interval_count):
    """Conservative clear arithmetic schedule for the validated joint screen.

    One output-flag claim; two public sweep events per dyadic profile cube.
    Includes all cell/index coefficients, folds, kernels and endpoint mix.
    No source adapters/getter/PCG/MAC/FS, integer/control work or timing credit.
    Profiles/exponents must match the caller; widths alone do not establish it.
    """
    natural(interval_count, 'RMS public profile cubes', 0, 2_000_000)
    depth, profiles = joint['depth'], joint['profiles']
    n = joint['cell_bits']
    size = 1 << n
    bits = [(w-1).bit_length() for w in joint['joint_level_widths']]
    edges = joint['joint_level_rows_across_profiles'][1:]
    prefixes = joint['reference_cell_prefix_bits']
    terms = (size-1)*sum(edges)
    products = {'cell_coefficients': 12*terms,
                'index_coefficients': sum(e*(2*s*s+28*s) for e,s in zip(edges,bits)),
                'profile_event_preparation': depth*3*interval_count*n*(n+1)//2,
                'profile_sweep': depth*(4*size-4-2*n+profiles*(2*size-1)),
                'validity_target': interval_count*n}
    additions = {'cell_coefficients': 18*terms,
                 'index_coefficients': sum(e*(2*s*s+35*s) for e,s in zip(edges,bits)),
                 'profile_event_preparation': products['profile_event_preparation']+3*interval_count*(n+1)*depth,
                 'profile_sweep': n*depth, 'validity_target': interval_count*(n+1)}
    folds = sum((1 << s)*((size >> k)-1)+2*((1 << s)-1) for s,k in zip(bits,prefixes))
    products['array_folds'], additions['array_folds'] = folds, 2*folds
    products['high_prefix_weights'] = sum(2*((size >> 6)-(size >> h)) for k in prefixes for h in range(7,k+1))
    additions['high_prefix_weights'] = sum(h-6 for k in prefixes for h in range(7,k+1))
    products['terminal_and_claim_update'] = sum(e*(2*s+3)+(2*s+1)*(1 << s)+5+3*n+4*s
                                               for e,s in zip(edges,bits))
    additions['terminal_and_claim_update'] = sum(e*(2*s+5)+(2*s+1)*(1 << s)+3+3*n+4*s
                                                for e,s in zip(edges,bits))
    packed = joint['bitpacked_replay']
    public_bytes = 80*interval_count+24*(1 << max(bits))+72*profiles+24*(6*(n+max(bits))+32)
    return {'credit': False, 'profile_interval_count': interval_count,
            'cell_pair_gate_terms': terms, 'products_upper_by_stage': products,
            'additions_upper_by_stage': additions,
            'combined_clear_replay_and_sumcheck_products_upper': sum(products.values())+
                packed['fold_high_prefix_products_upper']+packed['fold_table_preparation_products_upper'],
            'combined_clear_replay_and_sumcheck_additions_upper': sum(additions.values())+
                packed['fold_chunk_additions_upper']+packed['fold_high_prefix_accumulations_upper']+
                packed['fold_table_preparation_additions_upper'],
            'additional_public_sweep_and_gate_form_bytes': 256*((public_bytes+255)//256),
            'complete_getter_mac_fs_runtime_and_liveness': None}


def rms_gkr_aligned_word_screen(joint, field):
    """Conditional first-round moments + absent-profile pruning through h=5.

    Uses the validated general screen and homogeneous, aligned 64-cell cubes.
    First source visit must stream (k>0); otherwise it also materializes the
    array, and its input-conversion work cannot be subtracted here.
    """
    n, depth = joint['cell_bits'], joint['depth']
    if n < 6 or not depth or min(joint['reference_cell_prefix_bits']) < 1:
        raise ValueError('aligned-word screen requires a streamed first cell round')
    blocks, early_pairs = 1 << (n-6), sum(1 << (n-h-1) for h in range(1,6))
    inputs = sum(joint['joint_level_widths'][:-1])
    outputs = sum(joint['joint_level_widths'][1:])
    edges = sum(joint['joint_level_rows_across_profiles'][1:])
    word_terms, early_terms, tail_terms = blocks*outputs, early_pairs*outputs, (blocks-1)*edges
    products = 9*word_terms+12*(early_terms+tail_terms)
    additions = 27*word_terms+18*(early_terms+tail_terms)
    packed = joint['bitpacked_replay']
    return {'credit': False, 'requires_64_cell_aligned_homogeneous_profiles': True,
            'first_round_word_gate_terms_upper': word_terms,
            'rounds_1_to_5_gate_pair_terms_upper': early_terms,
            'remaining_cell_gate_pair_terms_upper': tail_terms,
            'cell_coefficient_products_upper': products, 'cell_coefficient_additions_upper': additions,
            'combined_clear_replay_and_sumcheck_products_upper':
                field['combined_clear_replay_and_sumcheck_products_upper']-
                field['products_upper_by_stage']['cell_coefficients']+products+depth*(1054+2*(blocks-1)),
            'combined_clear_replay_and_sumcheck_additions_upper':
                field['combined_clear_replay_and_sumcheck_additions_upper']-
                field['additions_upper_by_stage']['cell_coefficients']+additions+depth*(286+n-6),
            'fold_table_lookups_upper': packed['fold_table_lookups_upper']-64*blocks*inputs+16*word_terms,
            'additional_split_and_gate_word_steps_upper': 33*blocks*inputs+4*word_terms,
            'additional_scratch_bytes': 0,
            'reference_input_tuple_visits': joint['reference_input_tuple_visits'],
            'complete_getter_mac_fs_runtime_and_liveness': None}


def rms_joint_lifetime_screen(joint, field, coefficients, bridge, statistic_inputs, rope=None, gelu=None):
    """RMS-J phase on R3's common B/S/kappa base, not a full-Gamma timeline.

    Screens must describe the SAME compiled profiles and virtual-Y source.
    Keep program/getter/records throughout the known phases conservatively;
    only the RMS kernel arrays are phase-local. No new proof/storage codec.
    """
    if (not bridge['includes_rms_outputs'] or bridge['rms_output_retained_array_bytes'] or
            joint['cell_bits'] != (bridge['rms_output_live_bytes']//2-1).bit_length() or
            len(coefficients) != joint['profiles'] or field['profile_interval_count'] != bridge['rms_output_cell_cubes'] or
            statistic_inputs['initial_S_kappa_write_bytes'] != 12*bridge['rms_row_multiplier_preparations']):
        raise ValueError('RMS lifetime screens must use the same virtual Y/profile domain')
    getters = [rms_getter_integer_screen(c) for c in coefficients]
    rows = sum(joint['joint_level_rows_across_profiles'][1:])
    raw = {'public_gate_triples': 24*rows,
           'public_layer_offsets_and_lengths': 16*joint['profiles']*(joint['depth']+1),
           'public_profile_descriptors': 96*joint['profiles'],
           'public_norm_profile_map': 8*bridge['rms_output_sources'],
           'rms_cut_reader_descriptors': bridge['rms_cut_reader_screen']['descriptor_bytes'],
           'plaintext_and_tag_records': joint['plaintext_and_tag_records_bytes'],
           'integer_getter_wave': max(g['one_64_lane_wave_scratch_bytes'] for g in getters)}
    raw.update(statistic_inputs['reader_raw_reservation_bytes'])
    if rope is not None:
        if (rope['extends_source'] != 'S+Y' or rope['base_rms_output_layout_sha256'] !=
                [c['layout_sha256'] for c in bridge['cases']]):
            raise ValueError('RoPE lifetime must extend the same S+Y source layout')
        raw['rope_reader_word_buffers'] = rope['word_reader_work']['retained_word_buffer_bytes']
    if gelu is not None and (rope is None or gelu['extends_source'] != 'S+Y+RoPE' or
            gelu['base_rope_source_layout_sha256'] != [c['layout_sha256'] for c in rope['cases']]):
        raise ValueError('GELU lifetime must extend the same S+Y+RoPE source layout')
    retained = {k: 256*((v+255)//256) for k,v in raw.items()}
    shared = sum(retained.values())
    packed = joint['bitpacked_replay']
    kernel = (joint['reference_folded_array_bytes']+joint['reference_two_gate_vectors_bytes']+
              field['additional_public_sweep_and_gate_form_bytes']+
              sum(packed[k] for k in ('input_and_two_word_vectors_bytes','field_block_bytes','public_fold_table_reservation_bytes')))
    source_phases = (bridge['all_context_arena_phase_upper_bytes'] if rope is None else
                     rope['source_and_rope_arena_phase_upper_bytes_before_rms_joint_reader_gamma_runtime'])
    if gelu is not None:
        source_phases = gelu['source_and_gelu_arena_phase_upper_bytes_before_rms_joint_gamma_runtime']
    phases = {k:v+shared for k,v in source_phases.items()}
    phases['rms_statistic_prepare'] = phases['opening_first_pass']-80*(1 << 23)
    phases['rms_joint_and_input_split'] = phases['opening_first_pass']-80*(1 << 23)+kernel
    y_visits = bridge['known_bulk_output_reads_before_gamma_and_rms_replay']+joint['reference_input_tuple_visits']
    y_cells = (y_visits*(bridge['rms_output_live_bytes']//2)+statistic_inputs['initial_post_norm_Y_generations']+
               statistic_inputs['sumcheck_input_Y_generations'])
    extra_reads = 0
    if rope is not None:
        y_cells += rope['word_reader_work']['y_generations_including_linear_fill']
        extra_reads = rope['word_reader_work']['B_S_kappa_logical_read_bytes']
    raw_calls = (y_visits*bridge['rms_cut_reader_screen']['raw_rne_calls_per_full_visit']+
                 bridge['rms_input_split_honest_screen']['rne_output_cells']+
                 statistic_inputs['initial_raw_rne_calls_without_K_V_deduplication']+
                 statistic_inputs['sumcheck_input_raw_rne_calls'])
    point_calls = statistic_inputs['initial_pointwise_roundings']+statistic_inputs['sumcheck_input_pointwise_roundings']
    return {'credit': False, 'retained_reservations_256_byte_aligned': retained,
            'retained_reservation_bytes': shared, 'rms_kernel_phase_local_bytes': kernel,
            'all_context_arena_phase_upper_bytes': phases,
            'known_phase_max_upper_bytes': max(phases.values()),
            'remaining_arena_before_uncompiled_components': 6442450944-max(phases.values()),
            'known_y_generations_before_gamma_without_cross_visit_reuse': y_cells,
            'known_rms_input_logical_reads_with_row_reuse_before_gamma':
                y_visits*bridge['rms_cut_reader_screen']['logical_input_read_bytes_per_full_visit']+
                bridge['rms_input_split_honest_screen']['raw_B_logical_bytes']+
                statistic_inputs['initial_B_S_kappa_logical_read_bytes']+
                statistic_inputs['sumcheck_input_B_S_kappa_logical_read_bytes']+extra_reads,
            'known_raw_rne_calls_before_gamma': raw_calls,
            'known_pointwise_roundings_before_gamma': point_calls,
            'raw_rne_word_arithmetic_logic_comparisons_upper': 32*raw_calls,
            'pointwise_word_arithmetic_logic_comparisons_upper': 64*point_calls,
            'scalar_profile_logical_read_bytes_if_once_per_64_lane_word': 8*(raw_calls//64)+32*(point_calls//64),
            'row_preparation_mul64_wide_upper': bridge['rms_row_multiplier_preparations']*
                max(g['row_preparation_mul64_wide_upper'] for g in getters),
            'known_y_generation_mul64_wide_upper': y_cells*
                max(g['lane_generation_mul64_wide_upper_with_denominator'] for g in getters),
            'includes_rope_reader':rope is not None,
            'includes_gelu_reader':gelu is not None,
            'known_source_and_rms_joint_payload_before_remaining_gamma_framing': (
                (gelu if gelu is not None else rope)['maximum_known_partial_payload_before_rms_joint_gamma_and_framing']
                +joint['payload_before_incoming_input_adapters_and_shared_closures'] if rope is not None else None),
            'extra_input_split_rne_getter_words': bridge['rms_input_split_honest_screen']['rne_output_cells'],
            'complete_gamma_liveness_pcg_and_runtime': None}


def rms_boolean_cohort_screen(cohorts):
    """Excludes literal separate cubic-layer GKRs, not all RMS protocols.

    At P=0 (and candidate y=0), validity is exactly S's 48-bit signed
    range guard. For these even positive bounds every S bit is essential;
    binary fan-in requires depth>=6, independently of the public exponents.
    """
    norms = rms_statistic_cohorts(cohorts)
    assert all(r['columns'] % 2 == 0 and 0 < r['columns']*32767**2 < (1 << 47)-1 for r in norms)
    flat = sum((r['statistic_rows']*r['columns']-1).bit_length() for r in norms)
    native = sum((r['statistic_rows']-1).bit_length()+(r['columns']-1).bit_length() for r in norms)
    cells = sum(r['statistic_rows']*r['columns'] for r in norms)
    return {'credit': False, 'norm_cohorts': len(norms), 'minimum_cell_bits_sum': flat,
            'rms_output_live_cells': cells, 'rms_output_packed_bytes_if_retained': 2*cells,
            'joint_cell_bits': (cells-1).bit_length(),
            'native_cell_bits_sum': native, 'minimum_binary_depth_from_input_guard': 6,
            'literal_cubic_coefficients_per_cell_bit_per_layer': 4,
            'coefficient_payload_lower_bound': 24*4*6*flat,
            'excludes_gate_axes_terminal_messages_and_incoming_claims': True,
            'excludes_joint_reductions_or_guard_reuse': False,
            'complete_rms_mac_feasibility': None}


def lookup_fraction_node(leaves, first=0, count=None):
    """Small Fp reference: (denominator, numerator), streamed subtree root.

    The caller owns the small input; recursion retains O(log count) pairs.
    Uses R2's P/S merge, now over lookup/table rows, not over byte values.
    Zero denominators remain representable: the protocol MUST reject them.
    """
    natural(len(leaves), 'diagnostic fraction leaves', 1, 4096)
    count = len(leaves) if count is None else count
    natural(count, 'subtree cells', 1, len(leaves))
    natural(first, 'subtree start', 0, len(leaves)-count)
    if count & (count-1):
        raise ValueError('fraction subtree must have power-of-two size')

    def node(start, size):
        if size == 1:
            denominator, numerator = leaves[start]
            return (natural(denominator, 'Fp denominator', 0, P-1),
                    natural(numerator, 'Fp numerator', 0, P-1))
        lp, ls = node(start, size//2)
        rp, rs = node(start+size//2, size//2)
        return lp*rp % P, (ls*rp+lp*rs) % P
    return node(first, count)


def lookup_fraction_screen(lookup_cells, table_cells, tail_bits=20):
    """Conditional common-source LogUp-GKR core, not an admitted GELU LUT.

    Three leaf forms: input (possibly R2), output, histogram. Source PCS,
    their concrete pullbacks/readers, incoming Gamma and framing excluded.
    """
    natural(lookup_cells, 'lookup cells below characteristic', 1, P-1)
    natural(table_cells, 'distinct public table rows', 1, P-1)
    live = natural(lookup_cells+table_cells, 'fraction live rows', 2, 1 << 35)
    natural(tail_bits, 'cached node suffix bits', 0, 20)
    n = (live-1).bit_length()
    padded, rounds = 1 << n, n*(n-1)//2
    prefixes = [max(0, d-tail_bits) for d in range(n)]
    generations = 1+sum(k+1 for k in prefixes)  # root, then each GKR layer
    merges = padded-1+sum((k+1)*(padded-(1 << (d+1)))
                          for d, k in enumerate(prefixes))
    corrections = 3+4*rounds+7*n+3
    arrays = {'four_node_tails':96*(1 << min(tail_bits,n-1)),
              'prefix_eq_weights':24*(1 << max(prefixes)),
              'subtree_stack_upper':96*(n+1),
              'core_plaintexts_and_tags':48*corrections,
              'control_and_points':8192}
    arrays = {k:256*((v+255)//256) for k,v in arrays.items()}
    return {'credit':False, 'lookup_cells':lookup_cells, 'table_cells':table_cells,
            'fraction_live_rows':live, 'fraction_padded_rows':padded,
            'layers':n, 'rounds':rounds, 'round_degree':3,
            'extension_corrections':corrections,
            'payload_before_source_adapters_framing_and_shared_closures':24*corrections,
            'private_products':3*n+1, 'zero_residuals':rounds+n+2,
            'extension_challenges':rounds+2*n+2,
            'conditional_interactive_error_numerator_before_source_mac_fs':live+3*rounds+2*n,
            'honest_pole_abort_numerator_upper':live,
            'source_leaf_forms':3, 'extra_trace_pcs_instances':0,
            'full_tree_two_field_arrays_bytes':48*(2*padded-1),
            'cached_node_suffix_bits':tail_bits, 'prefix_rounds_by_layer':prefixes,
            'post_alpha_tree_generations':generations,
            'final_source_endpoint_visits':1,
            'post_alpha_source_visits':generations+1,
            'post_alpha_query_row_reads':(generations+1)*lookup_cells,
            'post_alpha_histogram_row_reads':(generations+1)*table_cells,
            'tree_generation_padded_leaf_visits':generations*padded,
            'tree_rebuild_field_products':3*merges,
            'tree_rebuild_field_additions':merges,
            'histogram_preparation_query_reads':lookup_cells,
            'local_arrays_256_byte_aligned':arrays,
            'local_arrays_bytes':sum(arrays.values()),
            'additional_w_reads_given_same_source_w_free_reader':0,
            'complete_field_work_reader_and_global_liveness':None,
            'concrete_table_semantics_and_common_source_adapters':None}


@lru_cache(maxsize=1)
def gelu_coefficient_bounds():
    """Rational enclosure of sqrt(2/pi), not a substituted GELU coefficient.

    Machin's identity, finite alternating sums and two integer square roots.
    One public constant enclosure is shared by all table profiles.
    """
    def atan_bounds(base, terms):
        low = sum((Fraction((-1)**k,(2*k+1)*base**(2*k+1)) for k in range(terms)),Fraction(0))
        return low,low+Fraction(1,(2*terms+1)*base**(2*terms+1))
    a,b = atan_bounds(5,128),atan_bounds(239,32)
    pi_low,pi_high = 16*a[0]-4*b[1],16*a[1]-4*b[0]
    unit = 1 << 512
    low = math.isqrt((2*unit*unit*pi_high.denominator)//pi_high.numerator)
    high = math.isqrt((2*unit*unit*pi_low.denominator)//pi_low.numerator)+1
    return Fraction(low,unit),Fraction(high,unit)


def gelu_i16_pair(magnitude, input_exponent, output_exponent):
    """Certified real tanh-GELU RNE for +/- magnitude; PUBLIC setup only.

    -32768 is an overflow marker, never an accepted output. An unresolved
    interval raises ArithmeticError; no approximation or precision retry.
    Exponent bounds define this finite candidate, not calibrated Gemma data.
    """
    natural(magnitude,'symmetric i16 magnitude',0,32767)
    for exponent in (input_exponent,output_exponent):
        natural(exponent,'GELU table dyadic exponent',-128,128)
    if magnitude == 0:
        return 0,0
    x = magnitude*Fraction(2)**input_exponent
    units = magnitude*Fraction(2)**(input_exponent-output_exponent)
    if x >= 16:
        # Strictly below the positive dyadic value, even at a halfway case.
        integer,remainder = divmod(units.numerator,units.denominator)
        rounded = integer+int(2*remainder > units.denominator)
        return (rounded if rounded <= 32767 else -32768),0
    factor = 2*(x+Fraction(44715,1_000_000)*x*x*x)
    low,high = (factor*c for c in gelu_coefficient_bounds())
    q = []
    for exponent,rounding in ((-high,decimal.ROUND_FLOOR),(-low,decimal.ROUND_CEILING)):
        context = decimal.Context(prec=128,rounding=rounding,Emin=-1000,Emax=1000,
                                  traps=[decimal.InvalidOperation,decimal.DivisionByZero,
                                         decimal.Overflow,decimal.Underflow])
        argument = context.divide(decimal.Decimal(exponent.numerator),decimal.Decimal(exponent.denominator))
        nearest = context.exp(argument)  # correctly rounded, independently of rounding mode
        bound = context.next_minus(nearest) if rounding == decimal.ROUND_FLOOR else context.next_plus(nearest)
        q.append(Fraction(bound))
    if not 0 < q[0] <= q[1] <= 1:
        raise ArithmeticError('invalid exponential enclosure')

    def certify(lower,upper):
        left,right = round(lower),round(upper)
        if left > 32767 or right < -32767:
            return -32768
        if left != right:
            raise ArithmeticError('GELU rounding interval straddles a decision boundary')
        return left
    positive = certify(units/(1+q[1]),units/(1+q[0]))
    negative = certify(-units*q[1]/(1+q[1]),-units*q[0]/(1+q[0]))
    return positive,negative


def gelu_i16_table(input_exponent, output_exponent):
    """C71-GELU-RNE-v1, 65535 signed-i16-LE entries, or setup failure.

    Index is input+32767. No output is silently saturated; -32768 rejects.
    Returning bytes keeps one public table at 131070 bytes, not Python ints.
    """
    gelu_i16_pair(0,input_exponent,output_exponent)  # validate before allocation
    table = bytearray(2*65535)
    for magnitude in range(1,32768):
        positive,negative = gelu_i16_pair(magnitude,input_exponent,output_exponent)
        for value,output in ((magnitude,positive),(-magnitude,negative)):
            offset = 2*(value+32767)
            table[offset:offset+2] = output.to_bytes(2,'little',signed=True)
    return bytes(table)


def gelu_lookup_tag(layer, value, output):
    """Fp3 public table tag. Overflow rows cannot match any query profile."""
    natural(layer,'GELU layer profile',0,59)
    natural(value,'GELU table input',-32767,32767)
    natural(output,'GELU table output or overflow marker',-32768,32767)
    return value % P,output % P,layer+60*int(output == -32768)


def gelu_table_setup_screen(input_exponent, output_exponent):
    """Finite public preparation counts, not chosen Gemma scales or timings."""
    gelu_i16_pair(0,input_exponent,output_exponent)
    interior = (0 if input_exponent >= 4 else
                32767 if input_exponent <= -11 else (1 << (4-input_exponent))-1)
    return {'credit':False, 'profile':'C71-GELU-RNE-v1',
            'input_exponent':input_exponent, 'output_exponent':output_exponent,
            'signed_i16_entries':65535, 'table_bytes':131070,
            'table_copy_peak_bytes_before_scalar_workspace':262140,
            'absolute_input_pairs':32767, 'interior_pairs':interior,
            'analytic_tail_pairs':32767-interior,
            'decimal_precision_digits':128, 'decimal_exponential_calls':2*interior,
            'directed_argument_divisions':2*interior, 'outward_neighbor_steps':2*interior,
            'shared_coefficient_arctangent_terms':160, 'shared_coefficient_integer_square_roots':2,
            'rejects_ambiguous_setup':True, 'overflow_output_marker':-32768,
            'public_invalid_row_profile_offset':60,
            'actual_gemma_exponents_and_complete_setup_work':None}


def gelu_lookup_sources(cohorts):
    """Unadmitted GELU Y and biased-i32 histograms, appended to SAME Sigma.

    One public profile per layer; table index u+32767. No x copy: its raw
    gate_proj is already in B and its RNE already belongs to R2.
    """
    cut_byte_layout(cohorts)
    config = pinned_model_config()
    gates = [c for c in cohorts if c['operation'] == 'gate_proj']
    if [c['layer'] for c in gates] != list(range(config['layers'])):
        raise ValueError('GELU requires every pinned gate_proj, in layer order')
    result = []
    for c in gates:
        if (c['kind'],c['rows'],c['columns'],c['cut_scalar_bytes']) != (
                'matrix',150,config['intermediate_size'],6):
            raise ValueError('GELU lookup geometry disagrees with pinned gate_proj')
        result.append({'source':'GELU_outputs', 'source_id':c['layer'], 'layer':c['layer'],
                       'operation':'gelu_tanh', 'execution':None, 'token_offset':0,
                       'shape':(1,c['rows'],c['columns']), 'word_bytes':2, 'rne':False,
                       'physical_b_offset':None, 'input_source_id':c['ordinal']})
    for c in gates:
        result.append({'source':'GELU_histogram', 'source_id':c['layer'], 'layer':c['layer'],
                       'operation':'gelu_multiplicity', 'execution':None, 'token_offset':0,
                       'shape':(1,1,(1 << 16)-1), 'word_bytes':4, 'rne':False,
                       'physical_b_offset':None})
    return result


def gelu_read_word(source, producer, first, count, packed_b, shift, table):
    """Honest <=64-cell (input, output) getter; only retained signed-i48 B.

    Source descriptors and the certified table/profile are fixed by the
    caller. This does not verify the table identity or authenticate B/Y.
    """
    rows = natural(producer['rows'], 'GELU rows', 1, 150)
    columns = natural(producer['columns'], 'GELU columns', 1, 21504)
    natural(producer['cut_byte_offset'], 'GELU physical B offset', 0)
    natural(producer['ordinal'], 'GELU producer identity', 0)
    natural(producer['layer'], 'GELU producer layer', 0, 59)
    natural(source['input_source_id'], 'GELU input identity', 0)
    natural(source['source_id'], 'GELU source identity', 0, 59)
    natural(source['layer'], 'GELU source layer', 0, 59)
    if (source['source'],source['operation'],source['input_source_id'],source['layer'],source['source_id'],
            source['shape'],source['word_bytes'],source['rne'],source['token_offset']) != (
            'GELU_outputs','gelu_tanh',producer['ordinal'],producer['layer'],producer['layer'],
            (1,rows,columns),2,False,0) or (producer['kind'],producer['operation'],
            producer['cut_scalar_bytes']) != ('matrix','gate_proj',6):
        raise ValueError('GELU must read its own gate_proj cut')
    natural(count, 'GELU live word cells', 1, 64)
    natural(first, 'GELU live word index', 0, rows*columns-count)
    if first//columns != (first+count-1)//columns:
        raise ValueError('GELU word cannot cross a row')
    rne_i48_to_i16(0,shift)  # reject malformed public shifts before reading
    if any(not isinstance(b,(bytes,bytearray,memoryview)) for b in (packed_b,table)):
        raise ValueError('GELU requires packed B and public table bytes')
    raw, lut = (memoryview(b).cast('B') for b in (packed_b,table))
    begin = producer['cut_byte_offset']+6*first
    if len(lut) != 131070 or begin+6*count > len(raw):
        raise ValueError('truncated GELU B or public table')
    result = []
    for offset in range(begin,begin+6*count,6):
        x = rne_i48_to_i16(int.from_bytes(raw[offset:offset+6],'little',signed=True),shift)
        j = 2*(x+32767)
        y = int.from_bytes(lut[j:j+2],'little',signed=True)
        if y == -32768:
            raise ValueError('GELU table row overflows symmetric i16')
        result.append((x,y))
    return result


def gelu_prepare_histogram(source, producer, packed_b, shift, table):
    """One pre-root visit, then retain SAME biased-i32 bytes until Sigma closes.

    No stored Y and no full input array. Returned storage is caller-owned;
    freezing the source means no subsequent mutation, not a second bytes copy.
    """
    gelu_read_word(source,producer,0,1,packed_b,shift,table)  # validate before allocation
    histogram = bytearray(4*65535)
    for row in range(producer['rows']):
        for col in range(0,producer['columns'],64):
            pairs = gelu_read_word(source,producer,row*producer['columns']+col,
                                  min(64,producer['columns']-col),packed_b,shift,table)
            for x,_ in pairs:
                offset = 4*(x+32767)
                count = int.from_bytes(histogram[offset:offset+4],'little')+1
                histogram[offset:offset+4] = count.to_bytes(4,'little')
            del pairs  # the next getter wave reuses the same bounded word budget
    for offset in range(3,len(histogram),4):
        histogram[offset] ^= 128  # count<2^31: exact biased-i32 codec, in place
    return histogram


def gelu_public_table_value(tables, terms):
    """Public Fp3 T from existing (layer,col,width,local_point,weight) terms.

    One <=32768-tag cube is folded in place; no inverses or EQ array.
    Points/weights are canonical THREE-limb tuples, also at Boolean points.
    Tables are already certified public inputs.
    """
    def add(a,b):
        return tuple((x+y) % P for x,y in zip(a,b))
    def sub(a,b):
        return tuple((x-y) % P for x,y in zip(a,b))
    result = (0,0,0)
    for layer,col,width,point,weight in terms:
        natural(layer, 'GELU public table layer', 0, 59)
        natural(width, 'GELU public table cube width', 1, 32768)
        natural(col, 'GELU public table cube start', 0, 65535-width)
        if width & (width-1) or col % width or len(point) != width.bit_length()-1:
            raise ValueError('GELU public table term is not its dyadic cube')
        for value in (*point,weight):
            if not isinstance(value,(tuple,list)) or len(value) != 3:
                raise ValueError('GELU public evaluator requires Fp3 points and weights')
            for x in value:
                natural(x, 'canonical GELU Fp3 limb', 0, P-1)
        if layer not in tables or not isinstance(tables[layer],(bytes,bytearray,memoryview)):
            raise ValueError('missing public GELU profile table')
        table = memoryview(tables[layer]).cast('B')
        if len(table) != 131070:
            raise ValueError('truncated public GELU profile table')
        values = [gelu_lookup_tag(layer,j-32767,
                    int.from_bytes(table[2*j:2*j+2],'little',signed=True))
                  for j in range(col,col+width)]
        active = width
        for r in point:
            for j in range(active//2):
                a,b = values[2*j],values[2*j+1]
                values[j] = add(a,fp3_mul_six(r,sub(b,a)))
            active //= 2
        result = add(result,fp3_mul_six(weight,values[0]))
        del values  # release this cube before allocating the next, possibly equally large one
    return result


def gelu_reader_screen(cohorts):
    """Logical byte/work census for the GELU reader, not a global HBM/time bound."""
    sources = gelu_lookup_sources(cohorts)
    _,cubes = auxiliary_word_layout(sources,all_word_cubes=True)
    queries = sum(math.prod(s['shape']) for s in sources if s['source'] == 'GELU_outputs')
    rows = sum(math.prod(s['shape']) for s in sources if s['source'] == 'GELU_histogram')
    table_cubes = sum(sources[c[0]]['source'] == 'GELU_histogram' for c in cubes)
    profiles = len(sources)//2
    core = lookup_fraction_screen(queries,rows)
    visits = core['post_alpha_source_visits']
    return {'credit':False, 'additional_w_reads_from_retained_b':0,
            'retained_output_array_bytes':0, 'profiles':profiles,
            'query_cells':queries, 'histogram_rows':rows,
            'per_pair_or_single_virtual_y_byte':{'raw_b_bytes':6, 'public_table_bytes':2, 'rne_calls':1},
            'preparation':{'raw_b_bytes':6*(queries+profiles),
                           'public_table_bytes':2*(queries+profiles),
                           'rne_calls':queries+profiles,
                           'validation_probe_rows':profiles,
                           'histogram_zero_fill_bytes':4*rows,
                           'histogram_counter_read_write_bytes':8*queries,
                           'histogram_bias_read_write_bytes':2*rows},
            'post_alpha_core_and_endpoint':{'query_visits':visits,
                                            'raw_b_bytes':6*visits*queries,
                                            'query_table_bytes':2*visits*queries,
                                            'rne_calls':visits*queries,
                                            'histogram_read_bytes':4*visits*rows,
                                            'tree_public_table_bytes':2*(visits-1)*rows},
            'public_evaluator_after_adapter_per_party':{'table_rows':rows, 'cube_terms':table_cubes,
                         'table_read_bytes':2*rows, 'extension_products':rows,
                         'extension_additions_or_subtractions':2*rows-table_cubes,
                         'native_tag_buffer_bytes':24*32768, 'no_eq_array_or_inverses':True},
            'retained_histogram_bytes_256_aligned_per_profile':profiles*262144,
            'resident_public_table_bytes_256_aligned_per_profile':profiles*131072,
            'reader_native_pair_buffer_bytes':256,
            'retained_until':'last common Sigma source visit; B also retained for Y replay',
            'complete_sigma_gamma_work_and_native_liveness':None}


def gelu_lookup_leaf_forms(lookup_sources, sources, byte_tiles, rq_tiles, point):
    """Fp diagnostic: LogUp's three wires -> exact common Sigma/RQ cube forms.

    Fraction rows use ALL word cubes of Y/histogram, independently of byte
    offsets. The public packing may interleave query and table cubes.
    Returned X terms join the EXISTING R2 shift groups; no per-cube wires.
    """
    _, fractions = auxiliary_word_layout(lookup_sources, all_word_cubes=True)
    live = sum(math.prod(s['shape']) for s in lookup_sources)
    if not live or len(point) != (live-1).bit_length():
        raise ValueError('point does not match the fraction domain')
    for x in point:
        natural(x,'canonical Fp fraction coordinate',0,P-1)
    roles = {'B','GELU_outputs','GELU_histogram'}
    indices = {(s['source'],s['source_id']):i for i,s in enumerate(sources) if s['source'] in roles}
    if len(indices) != sum(s['source'] in roles for s in sources):
        raise ValueError('duplicate common-source identity')
    byte_by_word = {t[:6]:t for t in byte_tiles if t[6] == 0}
    rq_by_word = {t[:6]:t[-1] for t in rq_tiles}
    result = {'x_rq_terms_by_source':{}, 'y_byte_terms':[], 'histogram_byte_terms':[],
              'y_bias':0, 'histogram_bias':0, 'query_mass':0, 'histogram_mass':0,
              'profile_moment':0, 'public_table_terms':[], 'additional_mac_corrections':0}
    for local_i,row,col,heads,rows,cols,offset in fractions:
        source = lookup_sources[local_i]
        role = source['source']
        if role not in {'GELU_outputs','GELU_histogram'} or source['rne'] or heads != 1:
            raise ValueError('unexpected lookup leaf source')
        key = role,source['source_id']
        if key not in indices or sources[indices[key]] != source:
            raise ValueError('lookup source must be identical to the common source')
        i = indices[key]
        bits,cb,rb = (heads*rows*cols-1).bit_length(),(cols-1).bit_length(),(rows-1).bit_length()
        weight = math.prod(x if (offset//(1 << bits) >> j) & 1 else 1-x
                           for j,x in enumerate(point[bits:])) % P
        cp = list(point[:cb])+[(col >> j) & 1 for j in range(cb,(source['shape'][2]-1).bit_length())]
        rp = list(point[cb:cb+rb])+[(row >> j) & 1 for j in range(rb,(source['shape'][1]-1).bit_length())]
        claim = ([],rp,cp,weight)
        tile_key = (i,row,col,heads,rows,cols)
        if tile_key not in byte_by_word:
            raise ValueError('missing lookup byte cube in common source')
        terms,bias = auxiliary_probe_terms([byte_by_word[tile_key]],sources,{i:claim})
        if role == 'GELU_outputs':
            raw_key = 'B',source['input_source_id']
            if raw_key not in indices:
                raise ValueError('missing GELU input in B')
            raw_i = indices[raw_key]
            raw = sources[raw_i]
            if (source['word_bytes'],raw['word_bytes'],raw['rne'],raw['operation'],
                    raw['layer'],raw['shape'],raw['token_offset']) != (
                    2,6,True,'gate_proj',source['layer'],source['shape'],0):
                raise ValueError('GELU input is not its exact gate_proj RNE')
            raw_cube = (raw_i,row,col,heads,rows,cols)
            if raw_cube not in rq_by_word:
                raise ValueError('missing gate_proj cube in common RQ')
            local,coefficient = auxiliary_point_restriction(raw,row,col,heads,rows,cols,claim)
            result['x_rq_terms_by_source'].setdefault(raw_i,[]).append((rq_by_word[raw_cube],local,coefficient))
            result['y_byte_terms'].extend(terms)
            result['y_bias'] = (result['y_bias']+bias) % P
            result['query_mass'] = (result['query_mass']+weight) % P
            result['profile_moment'] = (result['profile_moment']+weight*source['layer']) % P
        else:
            if source['word_bytes'] != 4 or source['shape'][:2] != (1,1):
                raise ValueError('histogram must use the biased-i32 row codec')
            result['histogram_byte_terms'].extend(terms)
            result['histogram_bias'] = (result['histogram_bias']+bias) % P
            result['histogram_mass'] = (result['histogram_mass']+weight) % P
            result['public_table_terms'].append((source['layer'],col,cols,list(point[:cb]),weight))
    result['dummy_mass'] = (1-result['query_mass']-result['histogram_mass']) % P
    return result


def gelu_byte_bridge_screen(cohorts, rope=None):
    """S+Y+RoPE+GELU source-path recount; NOT full Gamma/resources/admission."""
    rope = rope_byte_bridge_screen(cohorts) if rope is None else rope
    extra = gelu_lookup_sources(cohorts)
    extra_bytes,fractions = auxiliary_word_layout(extra,all_word_cubes=True)
    added = sum(s['word_bytes']*math.prod(s['shape']) for s in extra)
    query_cells = sum(math.prod(s['shape']) for s in extra if s['source'] == 'GELU_outputs')
    table_cells = sum(math.prod(s['shape']) for s in extra if s['source'] == 'GELU_histogram')
    core = lookup_fraction_screen(query_cells,table_cells)
    sigma = {n:wide_hash_joint_opening_screen([1 << n],1 << 23,357) for n in (33,34)}
    counts = {n:(s['base_corrections_including_salts'],
                 s['extension_corrections_including_paired_sumchecks']
                 +byte_range_tree_screen(n)['extension_corrections']
                 +byte_bit_lift_screen(n)['extension_corrections_excluding_incoming_claims'])
              for n,s in sigma.items()}
    def source_counts(live):
        n = (live-1).bit_length()
        zeros = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
        b,e = counts[n]
        return b-357*zeros,e
    stride = 6*pinned_model_config()['layers']*pinned_model_config()['query_heads']*150
    totals,deltas,changed = [],[],[]
    for old,before_payload in enumerate(rope['known_partial_payload_by_old_tokens']):
        live = rope['cases'][0]['source_byte_cells']+stride*old
        b0,e0 = source_counts(live)
        b1,e1 = source_counts(live+added)
        deltas.append((b1-b0,e1-e0+core['extension_corrections']))
        totals.append(before_payload+8*deltas[-1][0]+24*deltas[-1][1])
        if (live-1).bit_length() != (live+added-1).bit_length():
            changed.append(old)
    cases = []
    for old in (0,CONTEXT_CAP-150):
        base = (auxiliary_word_sources(cohorts,old)+rms_statistic_byte_sources(cohorts)
                +rms_output_byte_sources(cohorts)+rope_raw_byte_sources(cohorts))
        old_bytes,old_rq = auxiliary_word_layout(base)
        sources = base+extra
        byte_tiles,rq = auxiliary_word_layout(sources)
        assert old_rq == rq and len(byte_tiles)-len(old_bytes) == len(extra_bytes)
        live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
        cases.append({'old_tokens':old, 'source_templates':len(sources),
                      'source_byte_cells':live, 'source_padded_byte_cells':1 << (live-1).bit_length(),
                      'byte_cubes':len(byte_tiles), 'rq_cubes':len(rq),
                      'layout_sha256':hashlib.sha256(json.dumps(
                          [sources,byte_tiles,rq],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                      'known_partial_payload_before_rms_joint_gamma_and_framing':totals[old]})
    reader = gelu_reader_screen(cohorts)
    y_tiles = [t for t in extra_bytes if extra[t[0]]['source'] == 'GELU_outputs']
    if not all(t[2] % 64 == t[5] % 64 == 0 and t[6:8] == (0,2) and t[-1] % 128 == 0 for t in y_tiles):
        raise ValueError('GELU Sigma replay requires whole aligned 64-cell words')
    # Maximum Sigma/RQ domains are unchanged; retain ALL previous unomitted
    # record reservations, rather than adding a payload delta as memory.
    raw_arrays = {'private_histograms':reader['retained_histogram_bytes_256_aligned_per_profile'],
                  'public_tables':reader['resident_public_table_bytes_256_aligned_per_profile'],
                  'source_and_byte_cube_descriptors':96*len(extra)+72*len(extra_bytes),
                  'fraction_word_cube_descriptors':56*len(fractions),
                  'reader_profile_descriptors':32*reader['profiles'],
                  'endpoint_form_descriptors_points_weights':3*64+48*len(fractions)+24*core['layers'],
                  'lookup_plaintexts_and_tags':core['local_arrays_256_byte_aligned']['core_plaintexts_and_tags'],
                  'lookup_points_and_control':core['local_arrays_256_byte_aligned']['control_and_points'],
                  'reader_word_and_control':4096}
    arrays = {k:256*((v+255)//256) for k,v in raw_arrays.items()}
    # X overlaps existing RQ forms: charge its own two coefficient values per
    # cube/block intersection after the common 18-bit prefix, not just a term
    # per cube. Its matching RQ cube is aligned to the same dyadic volume.
    rne_extra = 48*sum(max(1,math.prod(t[3:6])//(1 << 18)) for t in fractions
                       if extra[t[0]]['source'] == 'GELU_outputs')
    phases = {k:v+sum(arrays.values())+(rne_extra if k == 'rne_top' else 0) for k,v in
              rope['source_and_rope_arena_phase_upper_bytes_before_rms_joint_reader_gamma_runtime'].items()}
    common = phases['opening_first_pass']-80*(1 << 23)
    scratch = sum(core['local_arrays_256_byte_aligned'][k]
                  for k in ('four_node_tails','prefix_eq_weights','subtree_stack_upper'))
    phases['gelu_histogram_prepare'] = common
    phases['gelu_fraction_core'] = common+scratch
    phases['gelu_final_forms_and_public_table'] = common+reader['public_evaluator_after_adapter_per_party']['native_tag_buffer_bytes']
    sigma_visits = rope['known_bulk_sigma_visits']
    extra_queries = sigma_visits*query_cells
    total_queries = (reader['preparation']['rne_calls']+
                     reader['post_alpha_core_and_endpoint']['rne_calls']+extra_queries)
    replay = {'credit':False, 'known_bulk_sigma_visits':sigma_visits,
              'sigma_y_generations_per_live_word_per_visit':1,
              'sigma_y_generations':extra_queries,
              'sigma_raw_B_read_bytes':6*extra_queries,
              'sigma_public_table_read_bytes':2*extra_queries,
              'sigma_histogram_read_bytes':4*sigma_visits*table_cells,
              'total_rne_calls_preparation_sigma_and_lookup':total_queries,
              'total_raw_B_read_bytes_preparation_sigma_and_lookup':6*total_queries,
              'total_query_table_read_bytes_preparation_sigma_and_lookup':2*total_queries,
              'complete_other_gamma_forms_transactions_and_runtime':None}
    return {'credit':False, 'extends_source':'S+Y+RoPE', 'cases':cases,
            'output_sources':len(extra)//2, 'histogram_sources':len(extra)//2,
            'extra_virtual_source_bytes':added, 'extra_byte_cubes':len(extra_bytes),
            'fraction_word_cubes':len(fractions), 'same_rq_layout':True,
            'fraction_layout_sha256':hashlib.sha256(json.dumps(fractions,separators=(',',':')).encode()).hexdigest(),
            'source_path_correction_deltas_by_old_tokens':deltas,
            'changed_sigma_padding_contexts':changed, 'known_partial_payload_by_old_tokens':totals,
            'maximum_known_partial_payload_before_rms_joint_gamma_and_framing':max(totals),
            'remaining_payload_before_missing_components':35_000_000-max(totals),
            'core':core, 'histogram_live_bytes_before_alignment':4*table_cells,
            'base_rope_source_layout_sha256':[c['layout_sha256'] for c in rope['cases']],
            'word_reader_work_including_known_sigma_paths':replay,
            'additional_known_retained_arrays_256_byte_aligned':arrays,
            'additional_rne_top_form_bytes':rne_extra,
            'lookup_phase_local_array_bytes':scratch,
            'source_and_gelu_arena_phase_upper_bytes_before_rms_joint_gamma_runtime':phases,
            'known_phase_max_upper_bytes_before_rms_joint_gamma_runtime':max(phases.values()),
            'additional_known_sigma_claims':2, 'additional_known_rq_claims':1,
            'additional_pcs_instances':0, 'additional_input_copies':0,
            'complete_tables_reader_work_and_physical_liveness':None}


def gate_up_raw_sources(cohorts):
    """Unretained i48 Hadamard cuts; output RNE stays in the common R2."""
    gelu = gelu_lookup_sources(cohorts)[:60]
    by_op = {(c['layer'],c['operation']):c for c in cohorts}
    result = []
    for g in gelu:
        up = by_op.get((g['layer'],'up_proj'))
        if up is None or (up['kind'],up['cut_scalar_bytes'],up['rows'],up['columns']) != (
                'matrix',6,g['shape'][1],g['shape'][2]):
            raise ValueError('gate product requires its same-layer up_proj geometry')
        result.append(dict(source='Gate_up_raw',source_id=g['layer'],layer=g['layer'],
                           operation='gate_up_raw',shape=g['shape'],word_bytes=6,rne=True,
                           execution=None,token_offset=0,physical_b_offset=None,
                           gelu_source_id=g['source_id'],gate_source_id=g['input_source_id'],
                           up_source_id=up['ordinal']))
    return result


def gate_up_read_word(source, gelu, gate, up, first, count, packed_b, gate_shift, up_shift, table):
    """Honest (GELU i16, up RNE i16, exact i32 product) words, without W.

    Reuses GELU's guarded getter. The six virtual source bytes encode the
    product with bias 2^47, NOT its four-byte native signed representation.
    """
    for key in ('source_id','layer','gelu_source_id','gate_source_id','up_source_id'):
        natural(source[key],'gate product identity',0)
    if (source['source'],source['operation'],source['source_id'],source['layer'],
            source['shape'],source['word_bytes'],source['rne'],source['token_offset'],
            source['gelu_source_id'],source['gate_source_id'],source['up_source_id']) != (
            'Gate_up_raw','gate_up_raw',gelu['layer'],gelu['layer'],gelu['shape'],6,True,0,
            gelu['source_id'],gate['ordinal'],up['ordinal']) or (
            up['layer'],up['operation'],up['kind'],up['rows'],up['columns'],up['cut_scalar_bytes']) != (
            gelu['layer'],'up_proj','matrix',gelu['shape'][1],gelu['shape'][2],6):
        raise ValueError('gate product must use its own GELU and up_proj')
    natural(up['ordinal'],'up producer identity',0)
    natural(up['cut_byte_offset'],'up physical B offset',0)
    rne_i48_to_i16(0,up_shift)
    pairs = gelu_read_word(gelu,gate,first,count,packed_b,gate_shift,table)
    raw = memoryview(packed_b).cast('B')
    begin = up['cut_byte_offset']+6*first
    if begin+6*count > len(raw):
        raise ValueError('truncated up_proj B')
    result = []
    for j,(_,y) in enumerate(pairs):
        offset = begin+6*j
        u = rne_i48_to_i16(int.from_bytes(raw[offset:offset+6],'little',signed=True),up_shift)
        result.append((y,u,y*u))
    return result


def gate_up_product_forms(products, sources, byte_tiles, rq_tiles, point):
    """Packed raw probe / two product endpoints -> SAME Sigma and RQ.

    Fp diagnostic of the public linear forms, not authenticated values.
    The raw probe uses its own point; G/U use the final sumcheck point.
    Calling this at either point constructs the relevant forms without
    treating MLE(G*U) as MLE(G)*MLE(U).
    """
    _,cubes = auxiliary_word_layout(products)
    live = sum(math.prod(s['shape']) for s in products)
    if not live or len(point) != (live-1).bit_length():
        raise ValueError('point does not match packed product domain')
    for v in point:
        natural(v,'canonical product coordinate',0,P-1)
    roles = {'B','GELU_outputs','Gate_up_raw'}
    indices = {(s['source'],s['source_id']):i for i,s in enumerate(sources) if s['source'] in roles}
    if len(indices) != sum(s['source'] in roles for s in sources):
        raise ValueError('duplicate product source identity')
    byte_by_word = {}
    for t in byte_tiles:
        byte_by_word.setdefault(t[:6],[]).append(t)
    rq_by_word = {t[:6]:t[-1] for t in rq_tiles}
    result = dict(raw_byte_terms=[],raw_bias=0,gelu_byte_terms=[],gelu_bias=0,
                  up_rq_terms_by_source={},additional_mac_corrections=0)
    for si,row,col,heads,rows,cols,offset in cubes:
        s = products[si]
        if (s['source'],s['operation'],s['word_bytes'],s['rne'],heads,s['token_offset']) != (
                'Gate_up_raw','gate_up_raw',6,True,1,0):
            raise ValueError('unexpected product cube source')
        keys = [('Gate_up_raw',s['source_id']),('GELU_outputs',s['gelu_source_id']),('B',s['up_source_id'])]
        if any(k not in indices for k in keys):
            raise ValueError('missing product input in common source')
        ri,gi,ui = [indices[k] for k in keys]
        g,u = sources[gi],sources[ui]
        if sources[ri] != s or (g['layer'],g['operation'],g['shape'],g['word_bytes'],g['rne'],
                g['input_source_id'],g['token_offset']) != (
                s['layer'],'gelu_tanh',s['shape'],2,False,s['gate_source_id'],0) or (
                u['layer'],u['operation'],u['shape'],u['word_bytes'],u['rne'],u['token_offset']) != (
                s['layer'],'up_proj',s['shape'],6,True,0):
            raise ValueError('product inputs must use the identical pinned sources')
        b,cb,rb = (heads*rows*cols-1).bit_length(),(cols-1).bit_length(),(rows-1).bit_length()
        w = math.prod(x if (offset//(1 << b) >> j) & 1 else 1-x for j,x in enumerate(point[b:])) % P
        cp = list(point[:cb])+[(col >> j) & 1 for j in range(cb,(s['shape'][2]-1).bit_length())]
        rp = list(point[cb:cb+rb])+[(row >> j) & 1 for j in range(rb,(s['shape'][1]-1).bit_length())]
        claim = ([],rp,cp,w)
        for i,role in ((ri,'raw'),(gi,'gelu')):
            key = (i,row,col,heads,rows,cols)
            tiles = byte_by_word.get(key,[])
            if sorted((t[6],t[7]) for t in tiles) != ([(0,4),(4,2)] if role == 'raw' else [(0,2)]):
                raise ValueError('missing product byte cube')
            terms,bias = auxiliary_probe_terms(tiles,sources,{i:claim})
            result[role+'_byte_terms'].extend(terms)
            result[role+'_bias'] = (result[role+'_bias']+bias) % P
        key = (ui,row,col,heads,rows,cols)
        if key not in rq_by_word:
            raise ValueError('missing up_proj cube in common RQ')
        local,weight = auxiliary_point_restriction(u,row,col,heads,rows,cols,claim)
        result['up_rq_terms_by_source'].setdefault(ui,[]).append((rq_by_word[key],local,weight))
    return result


def gate_up_product_screen(cohorts, gelu=None):
    """Conditional shared Hadamard cut; no complete Gamma/PCG/runtime credit."""
    gelu = gelu_byte_bridge_screen(cohorts) if gelu is None else gelu
    extra = gate_up_raw_sources(cohorts)
    byte,cubes = auxiliary_word_layout(extra)
    assert all(t[2] % 64 == t[5] % 64 == 0 and t[-1] % (64*t[7]) == 0 for t in byte)
    live = sum(math.prod(s['shape']) for s in extra)
    n = (live-1).bit_length()
    padded,prefix = 1 << n,min(5,n)
    corrections = 4*n+4  # raw probe, cubic coefficients, G/U and their product
    sigma = {n:wide_hash_joint_opening_screen([1 << n],1 << 23,357) for n in (33,34)}
    rne = {n:rne_indicator_screen(n,max(18,n-13),max(11,n-20)) for n in (30,31,32)}
    sigma_e = {n:sigma[n]['extension_corrections_including_paired_sumchecks']+
               byte_range_tree_screen(n)['extension_corrections']+
               byte_bit_lift_screen(n)['extension_corrections_excluding_incoming_claims'] for n in sigma}
    def counts(b,r):
        n,t = (b-1).bit_length(),(r-1).bit_length()
        zeros = (1 << n)//(1 << 23)-(b+(1 << 23)-1)//(1 << 23)
        return (sigma[n]['base_corrections_including_salts']-357*zeros,
                sigma_e[n]+rne[t]['extension_corrections'])
    first = (auxiliary_word_sources(cohorts)+rms_statistic_byte_sources(cohorts)+
             rms_output_byte_sources(cohorts)+rope_raw_byte_sources(cohorts)+gelu_lookup_sources(cohorts))
    first_b = sum(math.prod(s['shape'])*s['word_bytes'] for s in first)
    first_r = sum(math.prod(s['shape']) for s in first if s['rne'])
    stride = 60*32*150
    totals,deltas,changes = [],[],dict(sigma=[],rq=[])
    for old,payload in enumerate(gelu['known_partial_payload_by_old_tokens']):
        b,r = first_b+6*stride*old,first_r+stride*old
        b0,e0 = counts(b,r)
        b1,e1 = counts(b+6*live,r+live)
        deltas.append((b1-b0,e1-e0+corrections))
        totals.append(payload+8*deltas[-1][0]+24*deltas[-1][1])
        for name,a,d in (('sigma',b,6*live),('rq',r,live)):
            if (a-1).bit_length() != (a+d-1).bit_length():
                changes[name].append(old)
    cases = []
    for old in (0,CONTEXT_CAP-150):
        sources = (auxiliary_word_sources(cohorts,old)+rms_statistic_byte_sources(cohorts)+
                   rms_output_byte_sources(cohorts)+rope_raw_byte_sources(cohorts)+gelu_lookup_sources(cohorts)+extra)
        before = sources[:-len(extra)]
        before_byte,before_rq = auxiliary_word_layout(before)
        previous_sha = hashlib.sha256(json.dumps(
            [before,before_byte,before_rq],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if previous_sha != gelu['cases'][int(bool(old))]['layout_sha256']:
            raise ValueError('product screen must extend the same GELU layout')
        bt,rq = auxiliary_word_layout(sources)
        b,r = first_b+6*stride*old+6*live,first_r+stride*old+live
        cases.append(dict(old_tokens=old,source_templates=len(sources),source_byte_cells=b,
                          source_padded_byte_cells=1 << (b-1).bit_length(),rq_live_cells=r,
                          rq_padded_cells=1 << (r-1).bit_length(),byte_cubes=len(bt),rq_cubes=len(rq),
                          layout_sha256=hashlib.sha256(json.dumps(
                              [sources,bt,rq],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                          known_partial_payload_before_rms_joint_gamma_and_framing=totals[old]))
    # Keep previous unomitted Sigma reservations; its maximal domain is unchanged.
    # R2 gains 40 E records at capacity. Existing GELU X tail reserve at K=18
    # also bounds K=19; the new up form pays its own intersections at K=19.
    rne_delta = rne[32]['extension_corrections']-rne[31]['extension_corrections']
    raw_arrays = dict(source_and_cube_descriptors=96*len(extra)+72*len(byte)+56*len(cubes),
                      product_records=48*corrections,product_points_forms=48*n+96*len(cubes)+3*64,
                      rne_record_delta=48*rne_delta,
                      rne_challenge_delta=24*(rne[32]['extension_challenges']-rne[31]['extension_challenges']),
                      reader_and_control=8192)
    arrays = {k:256*((v+255)//256) for k,v in raw_arrays.items()}
    up_tail = 48*sum(max(1,math.prod(t[3:6])//(1 << 19)) for t in cubes)
    top_delta = rne[32]['top_prefix_weights_bytes']-rne[31]['top_prefix_weights_bytes']+48*len(cubes)+up_tail
    link_delta = rne[32]['link_prefix_weights_bytes']-rne[31]['link_prefix_weights_bytes']
    phases = {k:v+sum(arrays.values())+({'rne_top':top_delta,'rne_link':link_delta}.get(k,0))
              for k,v in gelu['source_and_gelu_arena_phase_upper_bytes_before_rms_joint_gamma_runtime'].items()}
    scratch = 48*(padded >> prefix)+24*(1 << prefix)
    common = phases['opening_first_pass']-80*(1 << 23)
    phases['gate_up_product'] = common+scratch
    sigma_visits,rq_visits = 231,rne[32]['source_rq_visits']
    generations = (2*sigma_visits+rq_visits+prefix+1)*live
    return dict(credit=False,extends_source='S+Y+RoPE+GELU',cases=cases,
                raw_sources=len(extra),raw_cells=live,extra_virtual_source_bytes=6*live,
                extra_byte_cubes=len(byte),extra_rq_cubes=len(cubes),same_rq_layout=False,
                requires_rebuilding_all_sigma_and_rq_forms=True,
                product_word_layout_sha256=hashlib.sha256(json.dumps(cubes,separators=(',',':')).encode()).hexdigest(),
                changed_padding_contexts=changes,source_path_correction_deltas_by_old_tokens=deltas,
                known_partial_payload_by_old_tokens=totals,
                maximum_known_partial_payload_before_rms_joint_gamma_and_framing=max(totals),
                remaining_payload_before_missing_components=35_000_000-max(totals),
                product_core=dict(cell_bits=n,extension_corrections=corrections,private_products=1,
                    zero_residuals=n+1,extension_challenges=2*n,conditional_interactive_error_numerator=4*n,
                    fixed_prefix_bits=prefix,source_visits=prefix+1,phase_local_array_bytes=scratch,
                    literal_two_full_E_arrays_bytes=48*padded,
                    prefix_fold_E_products_upper=2*(prefix+1)*padded,
                    cubic_pair_E_products_upper=12*(padded-1),
                    cached_fold_E_products=2*((padded >> prefix)-1),
                    public_eq_products_upper=2*sum((1 << h)-1 for h in range(prefix+1))+
                        2*(padded-1-n)+(padded-1)+3*n,
                    prefix_fold_E_additions_upper=2*(prefix+1)*padded,
                    cubic_pair_E_additions_upper=18*(padded-1),
                    cached_fold_E_additions=4*((padded >> prefix)-1),
                    public_eq_additions_upper=prefix*(prefix+1)//2+n*(n-1)//2+3*n,
                    endpoint_and_probe_E_products=2,endpoint_and_probe_E_additions_upper=5),
                rne_maximum_domain_repair=rne[32],
                unchanged_prefix_rne32_link_tail_bytes=rne_indicator_screen(32,18,11)['link_six_lane_four_function_tail_bytes'],
                additional_known_retained_arrays_256_byte_aligned=arrays,
                rne_top_phase_delta_bytes=top_delta,rne_link_phase_delta_bytes=link_delta,
                source_and_product_arena_phase_upper_bytes_before_rms_joint_gamma_runtime=phases,
                known_phase_max_upper_bytes_before_rms_joint_gamma_runtime=max(phases.values()),
                reader_work=dict(raw_generations_including_core=generations,
                    raw_B_logical_read_bytes=12*generations,public_gelu_table_read_bytes=2*generations,
                    rne_calls=2*generations,integer_products=generations,
                    additional_existing_rq_visits_at_capacity=rq_visits-122,
                    additional_existing_rq_raw_byte_requests=6*(rq_visits-122)*(first_r+stride*(CONTEXT_CAP-150)),
                    additional_rope_rms_Y_generations=2*(rq_visits-122)*119808000),
                additional_sigma_claims=2,additional_rq_claims=1,additional_pcs_instances=0,
                additional_w_reads_given_retained_b=0,retained_raw_array_bytes=0,
                complete_gamma_reader_field_work_pcg_and_physical_liveness=None)


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


def byte_bit_lift_screen(byte_bits):
    """One shared bit-function reduction into C_Sigma, not a bit/RMS prover.

    Incoming Gamma bit claims/forms are not yet counted. Reuse R2's P/S
    tree without its lane axis; all eight bit functions share one tree.
    """
    natural(byte_bits, 'byte source log domain', 1, 35)
    cells = 1 << byte_bits
    top_prefix, link_prefix = min(14, byte_bits), min(11, byte_bits)
    top_tail, link_tail = cells >> top_prefix, cells >> link_prefix
    rounds = 8*byte_bits+28
    corrections = 3*byte_bits+8+4*rounds+7*8+1
    top_arrays = {'bit_and_form_tails': 16*24*top_tail,
                  'prefix_weights': 24*(1 << top_prefix), 'pair_values': 32*24,
                  'control': 32768}
    link_arrays = {'four_function_tails': 4*24*link_tail,
                   'public_p_s_tree': 511*256*(8+24),
                   'public_child_fold_tables': 2*256*256*24,
                   'four_byte_functions': 4*256*24, 'histogram': 256*24,
                   'prefix_weights': 24*(1 << link_prefix),
                   'control': 32768, 'retained_source_endpoint': 24}
    top_arrays = {k: 256*((v+255)//256) for k, v in top_arrays.items()}
    link_arrays = {k: 256*((v+255)//256) for k, v in link_arrays.items()}
    visits = top_prefix+1+8*(link_prefix+1)+7
    link_work = (4*(link_prefix+1)*cells+19*(cells-1)+4*(link_tail-1)
                 +(1 << (link_prefix+1))+32*(byte_bits+8))
    return {'credit': False, 'byte_bits': byte_bits, 'top_round_degree': 2,
            'top_rounds': byte_bits, 'link_round_degree': 3, 'link_rounds': rounds,
            'extension_corrections_excluding_incoming_claims': corrections,
            'payload_before_incoming_claims_framing_and_shared_closures': 24*corrections,
            'private_products': 24, 'zero_residuals': 9*byte_bits+38,
            'extension_challenges': 9*byte_bits+48,
            'interactive_error_numerator_excluding_incoming_batch': 26*byte_bits+103,
            'source_endpoints': 1, 'extra_trace_commitments': 0,
            'top_prefix_rounds': top_prefix, 'link_prefix_rounds': link_prefix,
            'top_arrays_256_byte_aligned': top_arrays, 'link_arrays_256_byte_aligned': link_arrays,
            'top_array_bytes': sum(top_arrays.values()), 'link_array_bytes': sum(link_arrays.values()),
            'source_visits': visits, 'padded_source_cells_visited': visits*cells,
            'top_byte_bit_extractions_upper': 8*(top_prefix+1)*cells,
            'top_extension_products_before_public_forms_mac_and_metadata': (
                24*(cells-1)+16*(top_tail-1)+(1 << (top_prefix+1))),
            'link_extension_products_upper_before_mac_and_metadata': (
                8*link_work+7*(cells-1)+128*256*255+2*255*256+511),
            'incoming_claims_and_form_metadata': None, 'complete_rms_circuit': None,
            'additional_weight_reads_given_w_free_reader': 0}


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


def _check_rne_indicators(basis, shift):
    if len(basis) != 6 or any(len(row) != 256 for row in basis) or type(shift) is not int:
        raise ValueError("six 256-entry indicator rows and an integer shift required")
    for row in basis:
        for value in row:
            natural(value, "canonical diagnostic indicator value", 0, P-1)


def rne48_indicator_polynomials(basis, shift):
    """Degree-six lifted RNE formula, NOT free/unproved indicator wires.

    For the real RNE relation, basis[lane][j] must be the MLE of delta_j
    on that byte plane, linked by the P/S tree to the same B source.
    """
    _check_rne_indicators(basis, shift)
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


def rne48_output_bit_polynomials(basis, shift):
    """Six-lane degree<=6 formulas for the BIASED i16 output bits.

    Validity remains rne48_indicator_polynomials's separate obligation.
    Invalid outputs may wrap, except the public shift<=-15 dummy branch.
    Never apply this to bits of an already folded output scalar.
    """
    _check_rne_indicators(basis, shift)
    if shift <= -15 or shift >= 48:
        return [0]*15+[1]  # chosen signed-zero output, even on the invalid branch
    def pattern(ones, zeros=0):
        # Sign extension aliases ALL positions >=47 to the one sign bit.
        low, sign = (1 << 47)-1, 1 << 47
        ones = (ones & low) | (sign if ones >> 47 else 0)
        zeros = (zeros & low) | (sign if zeros >> 47 else 0)
        if ones & zeros:
            return 0
        # The biased encoding flips exactly that sign bit.
        on, off = (ones & low) | (zeros & sign), (zeros & low) | (ones & sign)
        factors = []
        for lane in range(6):
            wanted, mask = (on >> (8*lane)) & 255, ((on | off) >> (8*lane)) & 255
            if mask:
                factors.append(sum(v for j, v in enumerate(basis[lane]) if j & mask == wanted))
        return math.prod(factors) % P
    if shift <= 0:
        bits = [0 if k+shift < 0 else pattern(1 << (k+shift)) for k in range(16)]
    else:
        # C_k: half bit and the k low quotient bits are all one; k=1..16.
        carries = [pattern(((1 << (k+1))-1) << (shift-1)) for k in range(1, 17)]
        tie_even = pattern(1 << (shift-1), ((1 << (shift-1))-1) | (1 << shift))
        bits = [pattern(1 << shift)+pattern(1 << (shift-1))-2*carries[0]-tie_even]
        bits += [pattern(1 << (shift+k))+carries[k-1]-2*carries[k] for k in range(1, 16)]
    bits[15] = 1-bits[15]
    return [b % P for b in bits]


def rne_output_bit_screen(cell_bits):
    """Increment over R2: all 16 bits/all 64 classes, not incoming Gamma."""
    natural(cell_bits, 'RQ source log domain', 1, 32)
    per_class = [s//8+sum(min(s+k-1, 47)//8-(s-1)//8 for k in range(1, 17))
                 for s in range(1, 48)]
    products = sum(per_class)
    arrays = {'product_plaintexts_and_tags': 256*((48*products+255)//256),
              'public_bit_form_accumulators': 16*64*24, 'mask_and_value_scratch': 2048}
    return {'credit': False, 'additional_products_by_positive_shift': per_class,
            'additional_private_products': products, 'additional_extension_corrections': products,
            'additional_payload_before_incoming_claims_and_framing': 24*products,
            'additional_arrays_256_byte_aligned': arrays, 'additional_array_reservation_bytes': sum(arrays.values()),
            'additional_top_extension_products_upper_before_public_forms_and_mac':
                8*(products+16*64)*((1 << cell_bits)-1),
            'additional_sumcheck_rounds': 0, 'additional_source_visits': 0,
            'additional_pcs_instances': 0, 'additional_sigma_claims': 0,
            'incoming_bit_claims_and_public_form_work': None, 'complete_rms_circuit': None}


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


# A5-M candidate 20 of the pinned Grain stream; NOT adopted hash parameters.
# Matrix is diag(d) + J, so these are mu_i - 1, not its diagonal entries.
WIDE_HASH_INTERNAL_D = (
    15870349679768633380, 12798166135728573579, 3886447241503719881, 1162182268630581482,
    524547603630994057, 15049643593856059386, 16968805873296166965, 18056188151758929346,
    10534745617492959487, 2896675392312657074, 5966915426746805143, 4650275556274513670,
    16409025568887257071, 4961735845571844251, 8548187506920504860, 6209465213246826809,
    3498973453296848971, 11276291241872541492, 14404225929935954716, 13055306006344603938,
    18161729332800714500, 11215101012128210805, 10795869152246778728, 13739806737866978719,
    12478697326842823454, 5152228144467302696, 17647949517546001827, 3303522624437253160,
    8714553998730285052, 8851120390247512282, 10130318170785118639, 17336090747027405475,
)


def wide_hash_external_layer(state):
    """Clear A5-M matrix diagnostic: (I_8 + J_8) tensor M4."""
    if (not isinstance(state, (list, tuple)) or len(state) != 32
            or any(type(x) is not int or not 0 <= x < P for x in state)):
        raise ValueError('32 canonical Fp words required')
    m4 = ((5, 7, 1, 3), (4, 6, 1, 1), (1, 3, 5, 7), (1, 1, 4, 6))
    blocks = [[sum(a*x for a, x in zip(row, state[i:i+4])) % P for row in m4]
              for i in range(0, 32, 4)]
    total = [sum(block[j] for block in blocks) % P for j in range(4)]
    return [(block[j]+total[j]) % P for block in blocks for j in range(4)]


def wide_hash_permutation(state, constants):
    """CLEAR scalar A5-M diagnostic, not a production hash/prover or ROM sampler.

    Explicit constants only: 128 initial, 31 partial, 128 final. In particular,
    synthetic KAT constants must never become an implicit protocol default.
    """
    if (not isinstance(constants, (list, tuple)) or len(constants) != 287
            or any(type(x) is not int or not 0 <= x < P for x in constants)):
        raise ValueError('287 canonical Fp round constants required')
    state = wide_hash_external_layer(state)  # includes input validation/copy
    offset = 0
    for round_index in range(39):
        if 4 <= round_index < 35:
            state[0] = pow((state[0]+constants[offset]) % P, 7, P)
            offset += 1
            total = sum(state) % P
            state = [(total+d*x) % P for d, x in zip(WIDE_HASH_INTERNAL_D, state)]
        else:
            state = wide_hash_external_layer([
                pow((x+c) % P, 7, P) for x, c in zip(state, constants[offset:offset+32])])
            offset += 32
    assert offset == 287
    return state


def wide_hash_public_parameters(blocks):
    """A5-P finite public-tape decoder, NOT parameter generation or a hash.

    One 32-byte ROM output per active round-constant position. Each has
    four u64 proposals; exhaustion aborts the ENTIRE parameter publication.
    """
    if (not isinstance(blocks, (list, tuple)) or len(blocks) != 287
            or any(type(b) is not bytes or len(b) != 32 for b in blocks)):
        raise ValueError('287 complete 32-byte public parameter blocks required')
    result = []
    for block in blocks:
        for start in range(0, 32, 8):
            value = int.from_bytes(block[start:start+8], 'little')
            if value < P:
                result.append(value)
                break
        else:
            return None  # no new descriptor/nonce, modulo reduction or fallback
    return tuple(result)


def wide_hash_parameter_screen():
    """A5-P distribution/cost screen; no concrete CR, AI-ROM or FS credit."""
    space, rejected = 1 << 64, (1 << 64)-P
    return {
        'credit': False,
        'public_round_constant_coordinates': 8*32+31,
        'public_parameter_rom_output_blocks': 287,
        'public_parameter_rom_output_bytes': 287*32,
        'canonical_constant_vector_bytes': 287*8,
        'nominated_internal_matrix_grain_candidate': 20,
        'internal_matrix_checked_minimal_polynomial_powers': 64,
        'external_matrix_branch_number_at_width_32': 10,
        'matrix_check_is_not_security_of_the_hash_family': True,
        'public_linear_and_round_parameter_bytes_if_materialized_as_u64': 8*(32+16+287),
        'maximum_u64_proposals': 287*4,
        'parameter_input_bytes_per_coordinate': '20 + len(fixed_preprofile)',
        'setup_exhaustion_union_bound_numerator': 287*((1 << 64)-P)**4,
        'setup_exhaustion_union_bound_denominator': 1 << 256,
        # Only the comparison Gen_bit game uses modulo on exhaustion;
        # the actual public-tape decoder above ALWAYS aborts instead.
        'comparison_gen_bit_min_density_ratio_numerator_per_coordinate': space**4-rejected**4,
        'comparison_gen_bit_max_density_ratio_numerator_per_coordinate': space**4-rejected**4+P*rejected**3,
        'comparison_gen_bit_density_ratio_denominator_per_coordinate': space**4,
        'setup_exhaustion_is_rejection_not_false_acceptance': True,
        'independent_key_embedding_extra_uniform_tape_bytes': 287*32,
        'changes_private_gkr_round_or_correction_counts': False,
        'public_parameters_model_setup_delta_independent': True,
        'requires_fixed_descriptor_before_oracle_and_oracle_independent_advice': True,
        'post_parameter_computation_including_preprocessing_must_be_charged': True,
        'concrete_family_collision_hiding_and_fs_bounds_instantiated': False,
        'complete_security_bits': None,
    }


def wide_hash_fixed_trail_screen():
    """A5-D: ONE pre-key input pair and full differential characteristic.

    Probability is over independent uniform round constants, conditional on
    successful A5-P publication. NOT an adaptive collision/hull/FS bound.
    """
    pairs, branch = 2*(4//2), 10  # four full rounds on EACH side of the partial segment
    active = pairs*branch
    return {
        'credit': False,
        'disjoint_consecutive_full_round_pairs': pairs,
        'active_full_sboxes_lower_bound': active,
        'fixed_trail_probability_bound_numerator': 6**active,
        'fixed_trail_probability_bound_denominator': P**active,
        'fixed_trail_negative_log2_bound_floor': (P**active//6**active).bit_length()-1,
        'removing_one_full_round_per_half_leaves_pairs': 2*(3//2),
        'requires_input_pair_and_characteristic_fixed_before_public_parameters': True,
        'requires_independent_uniform_constants_at_distinct_round_positions': True,
        'repeated_hash_evaluations_have_independent_keys': False,
        'bounds_collision_hulls_or_post_parameter_input_search': False,
        'changes_nominated_rounds_or_component_resource_counts': False,
        'complete_security_bits': None,
    }


def wide_hash_security_assumption_screen():
    """Owner-authorized A5 assumptions, NOT derived concrete hash security.

    The loss/work ceilings are obligations on a future full reduction;
    counting attempts or Q_FS does not establish them. Other seven budget
    families below are reservations, not zeros or completed proofs.
    """
    bind = Fraction(1 << 20,1 << 110)
    hide = Fraction(1,1 << 100)
    others = 7*Fraction(1,1 << 82)
    birthday = Fraction(1 << 400,P**8)
    salt_search = Fraction(1 << 152,P**4)
    def ratio(x):
        return [x.numerator,x.denominator]
    return {'credit':False,'profile':'C71-A5-Assumption-v1',
            'security_basis':'explicit quantitative assumptions, not cryptanalysis',
            'protocol_adversary_u64_work_cap':1 << 64,
            'protocol_global_fs_queries_cap':1 << 64,'attempt_cap':1 << 20,
            'initial_advice_independent_of_rom':True,'post_parameter_preprocessing_is_charged':True,
            'binding_reduction_strict_u64_work_cap':1 << 200,
            'assumed_binding_advantage':ratio(Fraction(1,1 << 110)),
            'binding_total_reduction_loss_ceiling':1 << 20,
            'hiding_reduction_strict_u64_work_cap':1 << 128,
            'hiding_fresh_anchor_cap':1 << 24,
            'assumed_multi_anchor_hiding_advantage':ratio(hide),
            'hiding_total_reduction_loss_ceiling':1,
            'binding_lifetime_reservation':ratio(bind),'hiding_lifetime_reservation':ratio(hide),
            'per_family_lifetime_reservation':ratio(Fraction(1,1 << 82)),
            'other_families_reserved_per_security_game':7,
            'conditional_soundness_budget_sum':ratio(bind+others),
            'conditional_privacy_budget_sum':ratio(hide+others),
            'conditional_budget_sums_strictly_below_2_neg_79':max(bind+others,hide+others) < Fraction(1,1 << 79),
            'ideal_search_comparison_only':{'birthday_expression':ratio(birthday),
                'multi_target_salt_expression':ratio(salt_search),
                'both_below_assumed_advantages':birthday < Fraction(1,1 << 110) and salt_search < hide,
                'proves_a5_security':False},
            'reduction_work_losses_and_anchor_census_verified':False,
            'hash_binding_or_hiding_proved':False,'complete_lifetime_security_bits':None}


def private_projection_compilation_screen(n, block, queries, attempts=1):
    """G2 §3.2: A4/A5 ideal-interactive projection, NOT an executed extractor.

    Reuse A3/A4's same oracle layout. The whole terminal vector is ONE
    committed symbol, not a free direct message at its later opening.
    Include A4 paired records/coins; exclude caller and private hash tail.
    Multiple attempts here share ONE static source anchor; C_Sigma uses
    attempts=1 because a new response has a new auxiliary-source anchor.
    """
    natural(n, 'canonical anchored source length', 1, P-1)
    natural(attempts, 'attempts sharing one source anchor', 1)
    rs = recursive_rs_opening_screen(n, block, queries)
    oracles = [{'symbols': 4*block, 'symbol_fp_words': n//block, 'queries': queries}]
    oracles += [{'symbols': level['domain'], 'symbol_fp_words': 96, 'queries': level['queries']}
                for level in rs['levels']]
    oracles += [{'symbols': 1, 'symbol_fp_words': 3*rs['terminal_private_extension_cells'], 'queries': 1}]
    rows, log_block = n//block, block.bit_length()-1
    direct_rounds = log_block+5*len(rs['levels'])
    pair_values = 2*rows-1
    direct_values = pair_values+3*direct_rounds+1  # same f closes the outer SC
    field_challenges = n.bit_length()-1+rows+6*len(rs['levels'])
    random_indices = sum(o['queries'] for o in oracles if o['queries'] < o['symbols'])
    clear_hash_calls = [
        o['queries']*((o['symbol_fp_words']+9)//10+o['symbols'].bit_length()-1)
        + int(i == 0)  # only the source commitment has a salted public anchor
        for i, o in enumerate(oracles)]
    recursive_symbols = sum(o['symbols'] for o in oracles[1:])
    return {
        'credit': False,
        'committed_oracles': oracles,
        'commitment_boundaries_requiring_sampling': len(oracles),
        'total_committed_symbols': sum(o['symbols'] for o in oracles),
        'maximum_committed_symbols': max(o['symbols'] for o in oracles),
        'maximum_symbol_bytes': 8*max(o['symbol_fp_words'] for o in oracles),
        'dense_extracted_oracles_bytes_not_honest_prover_storage': 8*sum(o['symbols']*o['symbol_fp_words'] for o in oracles),
        'direct_sumcheck_messages': direct_rounds,
        'direct_sumcheck_extension_coefficients': 3*direct_rounds,
        'direct_paired_extension_values': pair_values,
        'direct_final_evaluation_extension_values': 1,
        'direct_extension_values': direct_values,
        'direct_plaintext_bytes_in_projection_only': 24*direct_values,
        'clear_vc_hash_calls_per_sample_by_boundary': clear_hash_calls,
        'public_challenge_u64_upper_before_private_hash': 4*(3*field_challenges+random_indices),
        'static_source_lifetime': {
            'attempts': attempts,
            'source_symbols_sampled_at_one_boundary': 4*block,
            'recursive_symbol_slots': attempts*recursive_symbols,
            'recursive_sampling_boundaries': attempts*(len(oracles)-1),
            'total_symbol_slots': 4*block+attempts*recursive_symbols,
            'maximum_attempts_in_each_source_continuation': attempts,
        },
        'main_execution_wrapper_error_multiplied_by_rewinds': False,
        'sampler_filters_by_direct_clear_vc_check_not_wrapper_acceptance': True,
        'rewind_clones_entire_dealer_and_prover_state': True,
        'changes_real_record_order_or_correlation_reuse_rules': False,
        'full_root_oracle_fs_and_model_relation_instantiated': False,
        'complete_security_bits': None,
    }


def private_targeted_lifetime_screen():
    """G2 §3.4: one hidden target, but one source sampled BEFORE all requests.

    Exact reduction counts for the W-only interactive lemma, not a full
    C7.1/FS compiler. A replay block includes the WHOLE remaining lifetime,
    cloning, direct checks, storage and comparison, not one honest opening.
    """
    profile = wide_hash_security_assumption_screen()
    attempts = profile['attempt_cap']
    layout = private_projection_compilation_screen(1 << 35,1 << 24,357,attempts)
    source, *recursive = [o['symbols'] for o in layout['committed_oracles']]
    source_epsilon = recursive_epsilon = Fraction(1,1 << 83)
    shares = [Fraction(1,1 << min(i+1,len(recursive)-1)) for i in range(len(recursive))]
    source_samples = math.ceil(source/source_epsilon)
    recursive_samples = [math.ceil(attempts*length/(recursive_epsilon*share))
                         for length,share in zip(recursive,shares)]
    source_error = Fraction(source,source_samples)
    recursive_error = attempts*sum(Fraction(length,count)
                                  for length,count in zip(recursive,recursive_samples))
    bind = attempts*Fraction(*profile['assumed_binding_advantage'])
    blocks = 1+source_samples+sum(recursive_samples)
    block_work = 1 << 73  # sufficient caller ceiling; NOT an established runtime bound
    work_cap = profile['binding_reduction_strict_u64_work_cap']
    naive_samples = math.ceil(attempts*sum(recursive)/recursive_epsilon)
    fractions = {'source_missing_reservation':source_error,
                 'recursive_missing_lifetime_reservation':recursive_error,
                 'sampling_lifetime_reservation':source_error+recursive_error,
                 'assumed_binding_lifetime_contribution':bind}
    return {'credit':False,'assumption_profile':profile['profile'],
            'scope':'one static W, ideal interactive closed lifetime; NOT joint W/KV or FS',
            'attempt_slots_including_aborts':attempts,'hidden_target_count':1,
            'source_symbols':source,'recursive_symbols':recursive,
            'source_samples_before_requests':source_samples,
            'recursive_samples_at_target_boundaries':recursive_samples,
            'maximum_attempts_per_source_sample':attempts,
            'binding_reduction_loss':attempts,
            'fits_named_binding_loss_ceiling':attempts <= profile['binding_total_reduction_loss_ceiling'],
            **{name:[x.numerator,x.denominator] for name,x in fractions.items()},
            'replay_blocks_including_initial_main_and_final_work':blocks,
            'sufficient_strict_u64_work_ceiling_per_block':block_work,
            'maximum_uniform_block_work_within_a5_cap':work_cap//blocks,
            'conditional_total_reduction_u64_work':blocks*block_work,
            'conditional_work_strictly_below_a5_cap':blocks*block_work < work_cap,
            'old_uniform_all_boundary_replay_blocks':1+source_samples+attempts*len(recursive)*naive_samples,
            'source_missing_and_main_wrapper_errors_multiplied_by_target_loss':False,
            'caller_block_work_ceiling_verified':False,
            'full_joint_source_hash_fs_loss_composition_verified':False,
            'honest_protocol_changed':False,'complete_security_bits':None}


def wide_hash_rs_screen(n, block, queries, deduplicate_paths=False, outer_public_zero_rows=0):
    """A5 STRUCTURAL candidate, not a generated/justified Poseidon2 profile.

    Reuse A3 geometry only; recompute every hash boundary for width 32,
    eight-word digests, ten-word groups, nominated RF=8/RP=31 and one
    arithmetic salted anchor. The old BLAKE3 anchor is NOT retained.
    Public-zero rows omit only outer payload inputs, never hash calls.
    This count does not prove that the caller's row mask is public/valid.
    """
    if type(deduplicate_paths) is not bool:
        raise ValueError('deduplicate_paths must be Boolean')
    natural(n, 'canonical wide-anchor source length', 1, P-1)
    narrow = recursive_rs_opening_screen(n, block, queries)
    natural(outer_public_zero_rows, 'outer public-zero rows', 0, n//block)
    levels = []
    calls, inputs = 1, 4  # anchor permutation; fresh Fp salt coordinates
    for level_index, (rows, domain, q) in enumerate([(n//block, 4*block, queries)]+[
            (96, level['domain'], level['queries']) for level in narrow['levels']]):
        groups, depth = (rows+9)//10, domain.bit_length()-1
        parents = (sum(min(q, domain >> height) for height in range(1, depth+1))
                   if deduplicate_paths else q*depth)
        siblings = parents+1-q if deduplicate_paths else q*depth
        h, i = q*groups+parents, q*(rows+8*groups)+8*(parents+siblings)+8
        if level_index == 0:
            i -= q*outer_public_zero_rows
        levels.append({'rows': rows, 'domain': domain, 'queries': q,
                       'chain_groups': groups, 'hash_calls': h, 'base_corrections': i,
                       'tree_parent_instances': parents, 'tree_sibling_inputs': siblings})
        calls, inputs = calls+h, inputs+i
    terminal = narrow['terminal_private_extension_cells']
    groups = (3*terminal+9)//10
    calls, inputs = calls+groups, inputs+3*terminal+8*groups+8
    padded = 1 << (calls-1).bit_length()
    variables = padded.bit_length()-1+5
    hash_e = (8*9+31*10)*variables+5*39
    extension = hash_e+15*len(narrow['levels'])
    trees = sum(64*(2*level['domain']-1) for level in narrow['levels'])
    records = 32*inputs+48*extension
    tile = min(1 << 21, 4*block)
    return {
        'credit': False, 'fixed_algorithm_block_cap': 1 << 24,
        'outer_public_zero_rows': outer_public_zero_rows,
        'paths_deduplicated_worst_case': deduplicate_paths,
        'nominated_width_full_partial_rounds': [32, 8, 31],
        'digest_field_words': 8, 'source_words_per_group': 10,
        'digest_space_cardinality': P**8,
        'salt_space_cardinality': P**4,
        'levels': levels, 'terminal_private_extension_cells': terminal,
        'private_hash_calls_including_anchor_and_recursion': calls,
        'padded_permutation_instances': padded,
        'base_corrections_including_salt': inputs,
        'power_gkr_extension_corrections': hash_e,
        'extension_corrections_including_partial_sumchecks': extension,
        'fresh_extension_correlations_including_product_mask': extension+1,
        'private_component_payload_before_framing_and_caller': 8*inputs+24*extension+72,
        'public_anchor_bytes_each_time_sent_not_in_private_payload': 64,
        'hash_trace_and_four_fold_tables_bytes': 13312*padded,
        'known_boundary_and_extension_record_bytes': records,
        'clear_hash_reduction_error_numerator_not_fs_or_mac': 343*variables+variables-2,
        'queried_sbox_base_multiplications_before_gkr': 4*(8*32+31)*calls,
        'hash_sumcheck_fp3_mul_upper_before_public_forms_and_mac': (
            39*104*(32*padded-1)+39*100*variables),
        'literal_full_row_group_encoder_bytes': 592*block,
        'tiled_commit_output_columns': tile,
        'tiled_commit_scratch_before_source_and_retained_cache_bytes': 48*block+144*tile,
        'tiled_commit_source_traversals': 4*block//tile,
        'tiled_commit_native_fft_butterflies': 4*block//tile*2*n*(block.bit_length()+1),
        'commit_outer_hash_calls_before_anchor_and_public_profile': (
            4*block*((n//block+9)//10)+4*block-1),
        'full_outer_tree_bytes': 64*(8*block-1),
        'outer_internal_only_tree_bytes': 64*(4*block-1),
        'query_missing_leaf_buffers_bytes': 144*min(4*block, 2*queries),
        'all_inner_full_trees_bytes': trees,
        # A3 conservative prehash bound, staged before hash trace allocation.
        # Its 96b FFT slot also covers the largest 592*(b/16) encoder.
        'prehash_known_arrays_union_bytes': (
            256*block+trees+records+144*min(4*block, 2*queries)),
        'post_source_and_tree_release_hash_known_union_bytes': 13312*padded+records,
        'outer_source_fft_butterflies_per_native_encode': 2*n*(block.bit_length()+1),
        'matrix_constants_hash_security_and_full_profile_instantiated': False,
        'complete_certificate_bytes': None, 'complete_security_bits': None,
    }


def wide_hash_joint_opening_screen(source_cells, block, queries, public_zero_rows=None):
    """Virtual A4 row stacking with separate anchors, one inner recursion.

    All sources use the SAME block/code domain and common outer query set.
    Canonical role order is the input order, with larger sources placed first.
    This counts the deduplicated candidate, not its full caller or liveness.
    """
    natural(len(source_cells), 'joint source count', 1, 3)
    public_zero_rows = [0]*len(source_cells) if public_zero_rows is None else list(public_zero_rows)
    if len(public_zero_rows) != len(source_cells):
        raise ValueError('one public-zero row count is required per anchored source')
    sources = [wide_hash_rs_screen(n, block, queries, True, zero)
               for n, zero in zip(source_cells, public_zero_rows)]
    first = sources[0]
    calls = first['private_hash_calls_including_anchor_and_recursion']
    inputs = first['base_corrections_including_salt']
    for source in sources[1:]:
        calls += source['levels'][0]['hash_calls']+1  # separate anchor
        inputs += source['levels'][0]['base_corrections']+4  # separate salt
    n = 1 << (sum(source_cells)-1).bit_length()
    natural(n, 'joint padded source length', 1, P-1)
    order = sorted(range(len(source_cells)), key=lambda i: (-source_cells[i], i))
    offsets, cursor = [0]*len(source_cells), 0
    for i in order:
        offsets[i], cursor = cursor, cursor+source_cells[i]
    paired = paired_rs_opening_screen(n, block, queries)
    hash_e = 382*((calls-1).bit_length()+5)+195
    extension = (first['extension_corrections_including_partial_sumchecks']
                 -first['power_gkr_extension_corrections']+hash_e
                 +paired['additional_extension_corrections'])
    return {
        'credit': False, 'source_cells': list(source_cells),
        'public_zero_rows_per_anchored_source': public_zero_rows,
        'source_order': order, 'source_offsets': offsets,
        'joint_padded_source_cells': n, 'joint_rows': n//block,
        'private_hash_calls_including_anchors_and_one_recursion': calls,
        'base_corrections_including_salts': inputs,
        'extension_corrections_including_paired_sumchecks': extension,
        'fresh_extension_correlations_including_product_mask': extension+1,
        'private_component_payload_before_framing_and_caller': 8*inputs+24*extension+72,
        'public_anchor_bytes_if_all_resent': 64*len(sources),
        'paired_reduction_interactive_error_numerator': paired['paired_reduction_interactive_error_numerator'],
        'source_visits_each_after_commit': 2,
        'full_root_compilation_caller_and_liveness_proved': False,
    }


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


def gamma_barrier_plan(cohorts, include_rms_outputs=False, include_rope=False, include_gelu=False,
                       include_gate_up=False):
    """Logical reverse schedule for the pinned 100+50 DAG, NOT kernel lowering.

    Cut raw W/QK/PV products, not weighted RMS statistics. All executed
    kernels retain a validity obligation, including unconsumed outputs.
    The old expander supplies tensor dependencies only; no old gate or
    protocol is imported. This does not bound forms, records or workspace.
    The optional virtual-Y boundary delegates RMS to the existing joint
    predicate/P0/statistic proofs; it does not make RMS an unchecked cut.
    Both modes include the S-source prelude's input demands before Gamma.
    Optional raw RoPE needs the same Y boundary and delegates its linear
    input proof before Gamma; the output RNE is postponed with all others.
    Optional GELU delegates membership to LogUp and its input to gate RNE;
    It does not prove a concrete GELU table. The optional gate product raw
    cut delegates multiplication to its common-source prelude and retains RNE.
    """
    if type(include_rms_outputs) is not bool:
        raise ValueError('Gamma RMS source mode must be Boolean')
    if type(include_rope) is not bool or include_rope and not include_rms_outputs:
        raise ValueError('this raw RoPE construction requires the same RMS Y source')
    if type(include_gelu) is not bool:
        raise ValueError('Gamma GELU source mode must be Boolean')
    if type(include_gate_up) is not bool or include_gate_up and not include_gelu:
        raise ValueError('gate product source mode requires the GELU boundary')
    manifest = pinned_gemma_manifest()
    logical = runpy.run_path(str(Path(__file__).with_name("c7_d126_gemma_qspec_dag.py")))
    executions = logical["_expand_schedule"](manifest["workload_schedule"])
    nodes = logical["expand_dag"](manifest, executions)
    by_cut = {(c["layer"], c["operation"]): c for c in cohorts}
    expected = {}
    for node in nodes:
        if node.weight_terminal is not None:
            expected[node.layer, node.operation] = (
                "lookup" if node.operation == "embedding_lookup" else
                "norm" if node.weight_terminal.endswith(("norm_bundle", "final_norm"))
                else "matrix")
    if len(by_cut) != len(cohorts) or {k: c["kind"] for k, c in by_cut.items()} != expected:
        raise ValueError("Gamma cuts disagree with the pinned weighted operators")
    if by_cut[None, "embedding_lookup"]["rows"] != 150 or by_cut[None, "lm_head"]["rows"] != 50:
        raise ValueError("Gamma dependency plan covers only the pinned 100+50 workload")
    norms = rms_statistic_cohorts(cohorts)
    by_rms = {(n['layer'],n['operation']): (i,n) for i,n in enumerate(norms)}
    by_rope = {(r['layer'],r['operation']): (i,r) for i,r in
               enumerate(gemma_rope_plan(cohorts)['cohorts'])} if include_rope else {}
    by_gelu = {(s['layer'],s['operation']):s for s in gelu_lookup_sources(cohorts)
               if s['source'] == 'GELU_outputs'} if include_gelu else {}
    by_product = {(s['layer'],'gate_up_mul'):s for s in gate_up_raw_sources(cohorts)} if include_gate_up else {}

    records, indices, node_cohorts = [], {}, []
    for node in nodes:
        key = (node.layer, node.operation)
        if key not in indices:
            cut = expected.get(key)
            kind = ({"lookup": "B_lookup", "norm": "weighted_rms", "matrix": "rne48"}.get(cut)
                    or {"qk_matmul": "rne48", "pv_matmul": "rne48",
                        "kv_cache_append": "KV_boundary", "token_input": "public_tokens"}.get(node.operation)
                    or "kernel")
            source = ("B" if cut is not None else
                      "raw_attention" if kind == "rne48" else None)
            if include_rms_outputs and key in by_rms:
                kind, source = 'rms_output_boundary', 'RMS_outputs'
            if key in by_rope:
                kind, source = 'rne48','RoPE_raw'
            if key in by_gelu:
                kind, source = 'gelu_output_boundary','GELU_outputs'
            if key in by_product:
                kind, source = 'rne48','Gate_up_raw'
            indices[key] = len(records)
            records.append({"ordinal": len(records), "layer": node.layer,
                            "operation": node.operation, "kind": kind, "byte_source": source,
                            "dependencies": set(), "seeds": set(),
                            "executions": 0, "query_rows": 0})
            if include_rms_outputs and key in by_rms:
                records[-1]['rms_source_id'] = by_rms[key][0]
            if key in by_rope:
                records[-1]['rope_source_id'] = by_rope[key][0]
        ordinal = indices[key]
        node_cohorts.append(ordinal)
        r = records[ordinal]
        r["executions"] += 1
        r["query_rows"] += (1 if node.operation in {
            "last_row_select", "lm_head", "final_tanh_softcap", "argmax"}
            else executions[node.execution]["query_tokens"])

    delegated = Counter()
    for node in nodes:
        r = records[node_cohorts[node.id]]
        # These incoming edges are proved separately, not silently pruned.
        owner = ("P0" if expected.get((node.layer, node.operation)) in {"matrix", "lookup"}
                 else "T1" if node.operation in {"qk_matmul", "pv_matmul"}
                 else "K1" if node.operation == "kv_cache_append"
                 else "public_decisions" if node.operation == "token_input" else None)
        if (node.layer,node.operation) in by_rope:
            rplan = by_rope[node.layer,node.operation][1]
            if len(node.dependencies) != 1:
                raise ValueError('RoPE must have one pinned normalized input')
            source = nodes[node.dependencies[0]]
            norm = norms[rplan['rms_source_id']]
            if (source.layer,source.operation) != (norm['layer'],norm['operation']):
                raise ValueError('RoPE source disagrees with the pinned normalized input')
            owner = 'RoPE_linear'
        if (node.layer,node.operation) in by_gelu:
            if len(node.dependencies) != 1:
                raise ValueError('GELU must have one pinned gate_proj input')
            source = nodes[node.dependencies[0]]
            if (source.layer,source.operation) != (node.layer,'gate_proj'):
                raise ValueError('GELU lookup input disagrees with the pinned DAG')
            owner = 'GELU_lookup'
        if (node.layer,node.operation) in by_product:
            if len(node.dependencies) != 2 or {(nodes[d].layer,nodes[d].operation) for d in node.dependencies} != {
                    (node.layer,'gelu_tanh'),(node.layer,'up_proj')}:
                raise ValueError('gate product disagrees with pinned GELU/up_proj inputs')
            owner = 'Gate_up_product'
        if (node.layer,node.operation) in by_rms:
            if include_rms_outputs:
                owner = 'RMS_joint_P0_statistics'
            if len(node.dependencies) != 1:
                raise ValueError('RMS source must have the pinned single input')
            producer = nodes[node.dependencies[0]]
            if node.operation == 'v_norm' and (producer.layer,producer.operation) not in by_cut:
                # Global V is the public alias of pre-norm K, not k_norm/k_rope.
                if producer.operation != 'v_source' or len(producer.dependencies) != 1:
                    raise ValueError('RMS V source has an unexpected alias')
                producer = nodes[producer.dependencies[0]]
            source = by_rms[node.layer,node.operation][1]['source_producer']
            if (producer.layer,producer.operation) != (source['layer'],source['operation']):
                raise ValueError('RMS statistic routing disagrees with the pinned input')
        if owner:
            delegated[owner] += len(node.dependencies)
        else:
            r["dependencies"].update(node_cohorts[d] for d in node.dependencies)

    boundary_kinds = {"B_lookup", "KV_boundary", "public_tokens", 'rms_output_boundary', 'gelu_output_boundary'}
    for r in records:
        if r["kind"] not in boundary_kinds:
            r["seeds"].add("validity")  # whole live domain, not only demanded rows
        elif r['kind'] == 'rms_output_boundary':
            r['seeds'].add('RMS_joint_validity')
        elif r['kind'] == 'gelu_output_boundary':
            r['seeds'].add('GELU_lookup_validity')
    for route in gemma_input_routes(cohorts):
        p = route["source_producer"]
        records[indices[p["layer"], p["operation"]]]["seeds"].add("P0")
    for layer in range(manifest["model_config"]["layers"]):
        for role, operations in (("K1", ("k_rope", "v_norm")),
                                 ("T1", ("q_rope", "softmax"))):
            for operation in operations:
                records[indices[layer, operation]]["seeds"].add(role)
    records[indices[None, "argmax"]]["seeds"].add("public_decisions")
    statistic_demands = []
    for i,norm in enumerate(norms):
        output = records[indices[norm['layer'],norm['operation']]]
        if output['query_rows']*norm['heads'] != norm['statistic_rows']:
            raise ValueError('RMS source omits or adds executed output rows')
        source = norm['source_producer']
        producer = indices[source['layer'],source['operation']]
        records[producer]['seeds'].add('RMS_statistic')
        statistic_demands.append((i,producer))  # Keep separate wires, including the ten K/V aliases.

    rope_demands = []
    for i,rplan in by_rope.values():
        norm = norms[rplan['rms_source_id']]
        producer = indices[norm['layer'],norm['operation']]
        records[producer]['seeds'].add('RoPE_linear')
        rope_demands.append((i,producer))  # Existing linear endpoint wire, not another correction.
    gelu_demands = []
    for layer,_ in by_gelu:
        producer = indices[layer,'gate_proj']
        records[producer]['seeds'].add('GELU_lookup_input')
        gelu_demands.append((layer,producer))  # Pieces of ONE aggregate X wire.
    product_demands = []
    for layer,_ in by_product:
        g,u = indices[layer,'gelu_tanh'],indices[layer,'up_proj']
        records[g]['seeds'].add('Gate_up_product')
        records[u]['seeds'].add('Gate_up_product')
        product_demands.append((layer,g,u))  # Pieces of the two global G/U wires.

    for r in records:
        r["dependencies"] = sorted(r["dependencies"])
        r["seeds"] = sorted(r["seeds"])
    reverse = list(reversed(tuple(TopologicalSorter({
        r["ordinal"]: r["dependencies"] for r in records}).static_order())))
    ordinary = [i for i in reverse if records[i]["kind"] not in boundary_kinds | {"rne48"}]
    rne = [i for i in reverse if records[i]["kind"] == "rne48"]
    boundaries = [i for i in reverse if records[i]["kind"] in boundary_kinds]
    order = ordinary + rne + boundaries
    rank = {ordinal: i for i, ordinal in enumerate(order)}
    if any(records[i]["dependencies"] for i in rne + boundaries) or any(
            rank[r["ordinal"]] >= rank[d] for r in records for d in r["dependencies"]):
        raise ValueError("a source/RNE leaf has a late dependency")
    return {"cohorts": records, "reverse_order": order, 'rms_statistic_demands': statistic_demands,
            'rope_input_demands':rope_demands, 'gelu_input_demands':gelu_demands,
            'gate_up_input_demands':product_demands,
            "summary": {"credit": False, "pinned_tensor_nodes": len(nodes),
                        "tensor_edges": sum(len(n.dependencies) for n in nodes),
                        "delegated_tensor_edges": dict(delegated),
                        "cohorts": len(records), "retained_cohort_edges": sum(len(r["dependencies"]) for r in records),
                        "ordinary_kernel_cohorts": len(ordinary), "final_rne_cohorts": len(rne),
                        'ordinary_kernel_operations': dict(Counter(records[i]['operation'] for i in ordinary)),
                        "source_boundary_cohorts": len(boundaries),
                        'includes_rms_outputs': include_rms_outputs,
                        'includes_raw_rope':include_rope, 'rope_input_demands':len(rope_demands),
                        'includes_gelu_outputs':include_gelu, 'gelu_input_demands':len(gelu_demands),
                        'includes_gate_up_raw':include_gate_up, 'gate_up_input_demands':len(product_demands),
                        'rms_statistic_input_demands': len(statistic_demands),
                        'distinct_statistic_input_producers': len({p for _,p in statistic_demands}),
                        "seed_cohorts_by_role": dict(Counter(s for r in records for s in r["seeds"])),
                        "plan_sha256": hashlib.sha256(json.dumps(
                            [records, order], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                        "structural_rne_last_order_verified": True,
                        "complete_gamma_forms_and_workspace": None}}


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


def rms_statistic_cohorts(cohorts):
    """Sum-of-squares consumers from validated P0 metadata, not RMS lowering.

    Keep the full producer row domain, including the final norm's unused
    terminal row. V has the K head geometry, but its own local projection;
    the global V projection is an exact alias of pre-norm K.
    """
    routes = {r["cohort_ordinal"]: r for r in gemma_input_routes(cohorts)}
    by_op = {(c["layer"], c["operation"]): c for c in cohorts}
    records = []
    for c in cohorts:
        if c["kind"] != "norm":
            continue
        route = routes[c["ordinal"]]
        r = {"layer": c["layer"], "operation": c["operation"], "weighted": True,
             "statistic_rows": c["rows"], "source_rows": route["source_shape"][0]*c["heads"],
             "columns": c["columns"], "heads": c["heads"],
             "source_producer": route["source_producer"], "source_shape": route["source_shape"]}
        records.append(r)
        if c["operation"] == "k_norm":
            v_op = "v_source" if (c["layer"], "v_source") in by_op else "k_proj"
            records.append({**r, "operation": "v_norm", "weighted": False,
                            "source_producer": {"layer": c["layer"], "operation": v_op}})
    return records


def rms_square_pair_coefficients(x0, x1, f0, f1):
    """Fp diagnostic of (f0 + (f1-f0)t)*(x0 + (x1-x0)t)^2.

    Nine field products; doubling is addition. The subsequent X fold costs
    one more product. Same identity over E, not a production MAC prover.
    """
    dx, df = (x1-x0) % P, (f1-f0) % P
    a, b, c = x0*x0 % P, x0*dx % P, dx*dx % P
    return [v % P for v in (f0*a, 2*(f0*b)+df*a, f0*c+2*(df*b), df*c)]


def rms_statistic_dependency_plan(cohorts, gamma):
    """Input cones with RMS Y as a cut, and S dependencies needed to build Y.

    Uses the validated Gamma DAG; does not invent forward dependencies from
    a list of operator names. Only B leaves and pointwise residual/scaling
    kernels are admitted in this statistic-reader construction.
    """
    norms = rms_statistic_cohorts(cohorts)
    nodes = gamma['cohorts']
    by_key = {(r['layer'],r['operation']): r['ordinal'] for r in nodes}
    y_sources = {by_key[n['layer'],n['operation']]: i for i,n in enumerate(norms)}
    kernels = {'embedding_scale','attention_residual_add','ffw_residual_add','layer_scalar_mul'}
    dependencies, roots, union, replays = {}, [], set(), []
    cfg, tokens = pinned_model_config(), cohorts[0]['rows']
    for i,norm in enumerate(norms):
        source = norm['source_producer']
        root = by_key[source['layer'],source['operation']]
        roots.append(root)
        todo, seen, required_s = [root], set(), set()
        while todo:
            ordinal = todo.pop()
            if ordinal in seen:
                continue
            seen.add(ordinal)
            r = nodes[ordinal]
            if ordinal in y_sources:
                required_s.add(y_sources[ordinal])
            elif r['kind'] in ('rne48','B_lookup'):
                if r['byte_source'] != 'B' or r['dependencies']:
                    raise ValueError('statistic input requires a non-B raw reader')
            elif r['operation'] in kernels:
                todo.extend(r['dependencies'])
            else:
                raise ValueError('uncompiled kernel in RMS statistic input cone')
        # Gamma is validated, but also fail closed on a malformed ordinary cone.
        tuple(TopologicalSorter({j: [d for d in nodes[j]['dependencies'] if d in seen]
                                 if j not in y_sources else [] for j in seen}).static_order())
        dependencies[i] = sorted(required_s)
        union.update(seen)
        cells = math.prod(norm['source_shape'])  # Includes the final producer's terminal row.
        if required_s or any(nodes[j]['operation'] in kernels for j in seen):
            if tuple(norm['source_shape']) != (tokens,cfg['hidden_size']) or any(
                    norms[j]['statistic_rows']*norms[j]['columns'] != cells or norms[j]['columns'] % 64
                    for j in required_s):
                raise ValueError('residual replay requires equal full hidden tensors and 64-lane Y words')
        counts = Counter('Y' if j in y_sources else 'raw_rne' if nodes[j]['kind'] == 'rne48'
                         else 'lookup' if nodes[j]['kind'] == 'B_lookup' else 'pointwise' for j in seen)
        replays.append({key: cells*counts[key] for key in ('Y','raw_rne','lookup','pointwise')})
    order = list(TopologicalSorter(dependencies).static_order())
    direct = [i for i,root in enumerate(roots) if nodes[root]['kind'] == 'rne48']
    residual = [i for i,root in enumerate(roots) if nodes[root]['operation'] in
                ('attention_residual_add','layer_scalar_mul')]
    raw_cells = sum(norms[i]['statistic_rows']*norms[i]['columns'] for i in direct)
    y = union.intersection(y_sources)
    y_cells = sum(norms[y_sources[j]]['statistic_rows']*norms[y_sources[j]]['columns'] for j in y)
    pointwise = Counter(nodes[j]['operation'] for j in union if j not in y_sources and nodes[j]['operation'] in kernels)
    replay = {key: sum(r[key] for r in replays) for key in ('Y','raw_rne','lookup','pointwise')}
    return {'input_roots': roots, 'statistic_dependencies': dependencies, 'preparation_order': order,
            'input_replay_counts': replays,
            'summary': {'credit': False, 'input_cone_cohorts': len(union),
                        'direct_raw_statistic_sources': len(direct), 'residual_statistic_sources': len(residual),
                        'distinct_raw_B_leaves': sum(nodes[j]['kind'] == 'rne48' for j in union),
                        'rms_Y_leaves': len(y), 'pointwise_kernel_cohorts': dict(pointwise),
                        'statistic_dependency_edges': sum(map(len,dependencies.values())),
                        'all_Y_dependencies_have_B_only_statistics': all(not dependencies[y_sources[j]] for j in y),
                        'initial_raw_rne_calls_without_K_V_deduplication': raw_cells,
                        'initial_post_norm_Y_generations': y_cells,
                        'initial_pointwise_roundings': (1+3*cfg['layers'])*tokens*cfg['hidden_size'],
                        'initial_B_S_kappa_logical_read_bytes': 6*raw_cells+4*y_cells+
                            2*tokens*cfg['hidden_size']+12*(y_cells//64),
                        'initial_S_kappa_write_bytes': 12*sum(n['statistic_rows'] for n in norms),
                        'single_token_residual_vector_bytes': 2*cfg['hidden_size'],
                        'reader_raw_reservation_bytes': {
                            'pointwise_profile_descriptors': 32*sum(pointwise.values()),
                            'raw_shift_by_B_cohort': 8*len(cohorts),
                            'statistic_reader_token_vector': 2*cfg['hidden_size'],
                            'pointwise_integer_wave': 64*(8*8+256)},
                        'sumcheck_input_live_cells': sum(math.prod(n['source_shape']) for n in norms),
                        'sumcheck_input_raw_rne_calls': replay['raw_rne'],
                        'sumcheck_input_Y_generations': replay['Y'],
                        'sumcheck_input_pointwise_roundings': replay['pointwise'],
                        'sumcheck_input_lookup_cells': replay['lookup'],
                        'sumcheck_input_B_S_kappa_logical_read_bytes':
                            6*replay['raw_rne']+4*replay['Y']+12*(replay['Y']//64)+2*replay['lookup'],
                        'complete_native_statistic_reader_and_liveness': None}}


def rms_statistic_byte_sources(cohorts):
    """Candidate retained S cuts in the SAME Sigma, using biased i48 bytes.

    Same 12-u64 source descriptor schema, with a role-specific physical
    offset. Does not add S to raw-RNE's RQ domain or change physical B.
    """
    sources, offset = [], 0
    for i, r in enumerate(rms_statistic_cohorts(cohorts)):
        sources.append({'source': 'RMS_statistics', 'source_id': i, 'layer': r['layer'],
                        'operation': r['operation'], 'execution': None, 'token_offset': 0,
                        'shape': (1, r['statistic_rows'], 1), 'word_bytes': 6, 'rne': False,
                        'physical_statistic_offset': offset})
        offset += 6*r['statistic_rows']
    return sources


def rms_output_byte_sources(cohorts):
    """Candidate Y in the SAME Sigma, not retained storage or an admitted cut."""
    return [{'source': 'RMS_outputs', 'source_id': i, 'layer': r['layer'],
             'operation': r['operation'], 'execution': None, 'token_offset': 0,
             'shape': (1,r['statistic_rows'],r['columns']), 'word_bytes': 2,
             'rne': False, 'physical_b_offset': None}
            for i,r in enumerate(rms_statistic_cohorts(cohorts))]


def rms_cut_reader_plan(cohorts):
    """Seven-u64 descriptors for RMS reads from retained B/S/kappa only.

    Public profile/shift lookup uses the existing norm and product identities.
    Flattened token/head/lane order is physically identical for weighted P
    and the unweighted projection raw; no producer replay or W access.
    """
    cut_byte_layout(cohorts)
    by_op = {(c['layer'],c['operation']): c for c in cohorts}
    if len(by_op) != len(cohorts):
        raise ValueError('duplicate physical B producer')
    readers, statistic_offset = [], 0
    for i,norm in enumerate(rms_statistic_cohorts(cohorts)):
        producer = norm if norm['weighted'] else norm['source_producer']
        source = by_op[producer['layer'],producer['operation']]
        rows, columns, heads = norm['statistic_rows'], norm['columns'], norm['heads']
        expected = (rows,columns,4) if norm['weighted'] else (rows//heads,heads*columns,6)
        if rows % heads or (source['rows'],source['columns'],source['cut_scalar_bytes']) != expected:
            raise ValueError('RMS input must use the exact physical B producer')
        readers.append({'norm_source_id': i, 'product_source_id': source['ordinal'],
                        'product_byte_offset': source['cut_byte_offset'],
                        'statistic_byte_offset': statistic_offset, 'rows': rows,
                        'columns': columns, 'product_word_bytes': expected[2]})
        statistic_offset += 6*rows
    return readers


def rms_read_input_word(reader, first, count, buffers, coefficients, raw_shift=None):
    """Up to 64 live cells in ONE row: signed B, biased S, unsigned kappa.

    Descriptor/profile validated before reading; kappa must be prepared from
    the SAME attempt/A/D (not an authenticated hint). No full Y array. This
    getter is not a verifier and does not establish the S/P source relations.
    """
    natural(count, 'RMS live word lanes', 1, 64)
    natural(first, 'live RMS input index', 0, reader['rows']*reader['columns']-count)
    row = first//reader['columns']
    if row != (first+count-1)//reader['columns']:
        raise ValueError('RMS word cannot cross a statistic row')
    width = reader['product_word_bytes']
    if width not in (4,6) or (width == 4 and raw_shift is not None) or (width == 6 and type(raw_shift) is not int):
        raise ValueError('RMS raw shift must match its weighted/unweighted source')
    if len(buffers) != 3 or any(not isinstance(b,(bytes,bytearray,memoryview)) for b in buffers):
        raise ValueError('RMS reader needs exactly B, S and kappa byte buffers')
    rms_getter_integer_screen(coefficients)  # Native profile validation is hoisted out of the cell loop.
    views = [memoryview(buffer).cast('B') for buffer in buffers]
    spos = reader['statistic_byte_offset']+6*row
    def read(view, offset, size, signed=False):
        if offset < 0 or offset+size > len(view):
            raise ValueError('truncated or out-of-bounds RMS source read')
        return int.from_bytes(view[offset:offset+size],'little',signed=signed)
    statistic = natural(read(views[1],spos,6)-(1 << 47), 'honest RMS statistic', 0, (1 << 47)-1)
    multiplier = read(views[2],spos,6)
    a,b,c = coefficients
    denominator, result = b+c*statistic, []
    for index in range(first,first+count):
        product = read(views[0],reader['product_byte_offset']+width*index,width,True)
        if width == 6:
            product = rne_i48_to_i16(product,raw_shift)
        output = rms_rne_from_multiplier(product,a,denominator,multiplier)
        result.append((product,statistic,output))
    return result


def rms_output_source_point(norm, point, coefficient=1):
    """Native lane||head||token -> Y's column||flattened-row point."""
    heads, columns, rows = norm['heads'], norm['columns'], norm['statistic_rows']
    natural(heads, 'RMS heads', 1, 32)
    natural(columns, 'RMS columns', 1, 5376)
    natural(rows, 'RMS rows', 1)
    if heads & (heads-1) or rows % heads or heads > 1 and columns & (columns-1):
        raise ValueError('RMS head reshape is not the pinned geometry')
    cb, hb, rb = (columns-1).bit_length(), (heads-1).bit_length(), (rows//heads-1).bit_length()
    if len(point) != cb+hb+rb:
        raise ValueError('RMS output point has the wrong native axes')
    return ([], list(point[cb:cb+hb])+list(point[cb+hb:]), list(point[:cb]), coefficient)


def rms_rne_bit_linear_value(raw, shift, weights):
    """Honest split getter: linear form on bits of biased RNE(raw), NOT raw.

    The actual raw B address and public shift come from the existing v_norm
    input view. This scalar helper does not authenticate or bind that source.
    """
    if len(weights) != 16:
        raise ValueError('RMS RNE split needs sixteen port weights')
    for v in weights:
        natural(v, 'RMS RNE port weight', 0, P-1)
    word = rne_i48_to_i16(raw,shift)+(1 << 15)
    return sum(w*(word >> j & 1) for j,w in enumerate(weights)) % P


def rms_joint_input_pullback(norms, sources, byte_tiles, cell_point):
    """Public bottom adapter: compact byte views and RNE-output views.

    A byte view (port,offset,point,scale) contributes
    scale*sum_k lambda[port+k]*MLE(bit_k(Sigma)[cube],point).
    The RNE views use the same lambda with 16 output bits. No new private
    wire per view. Requires auxiliary_word_layout's canonical public tiles.
    Lists here are a small diagnostic; a caller can stream
    one Y cube at a time from the existing source/cube descriptors.
    """
    def source_map(role, key):
        result = {}
        for i,s in enumerate(sources):
            if s['source'] == role:
                value = key(s)
                if value in result:
                    raise ValueError('duplicate RMS source identity')
                result[value] = i
        return result
    by_y = source_map('RMS_outputs', lambda s: s['source_id'])
    by_s = source_map('RMS_statistics', lambda s: s['source_id'])
    by_b = source_map('B', lambda s: (s['layer'],s['operation']))
    if set(by_y) != set(range(len(norms))) or set(by_s) != set(by_y):
        raise ValueError('RMS sources must cover the norm inventory exactly')
    output_sources = [sources[by_y[i]] for i in range(len(norms))]
    y_tiles, _ = auxiliary_word_layout(output_sources)
    cells = sum(math.prod(s['shape']) for s in output_sources)
    if not cells or len(cell_point) != (cells-1).bit_length():
        raise ValueError('RMS cell point has the wrong domain')
    for value in cell_point:
        natural(value, 'public RMS cell coordinate', 0, P-1)
    products = []
    for i,norm in enumerate(norms):
        rows = natural(norm['statistic_rows'], 'RMS rows', 1)
        columns = natural(norm['columns'], 'RMS columns', 1, 5376)
        rms_output_source_point(norm, [0]*((norm['columns']-1).bit_length()+
                                          (norm['statistic_rows']-1).bit_length()))
        if type(norm['weighted']) is not bool:
            raise ValueError('RMS weighted mode must be Boolean')
        heads = norm['heads']
        for index, shape, size in ((by_y[i],(1,rows,columns),2), (by_s[i],(1,rows,1),6)):
            source = sources[index]
            if (tuple(source['shape']) != shape or source['word_bytes'] != size or source['rne'] or source['token_offset']
                    or (source['layer'],source['operation']) != (norm['layer'],norm['operation'])):
                raise ValueError('RMS cut shape or identity mismatch')
        producer = norm if norm['weighted'] else norm['source_producer']
        key = (producer['layer'],producer['operation'])
        if key not in by_b:
            raise ValueError('missing RMS product producer')
        index = by_b[key]
        source = sources[index]
        shape = (1,rows,columns) if norm['weighted'] else (1,rows//heads,heads*columns)
        if (tuple(source['shape']) != shape or source['word_bytes'] != (4 if norm['weighted'] else 6) or source['token_offset']
                or source['rne'] != (not norm['weighted'])):
            raise ValueError('RMS product must use the exact B or pre-norm RNE source')
        products.append(index)
    positions = {}
    for i,r,c,a,h,d,j,count,offset in byte_tiles:
        positions.setdefault((i,r,c,a,h,d), []).append((j,count,offset))
    byte_views, rne_views, public_one = [], [], 0
    def emit(source, row, col, height, width, local, scale, port):
        groups = positions.get((source,row,col,1,height,width), ())
        if sorted(j+k for j,count,_ in groups for k in range(count)) != list(range(sources[source]['word_bytes'])):
            raise ValueError('RMS byte cube coverage mismatch')
        for first,count,offset in groups:
            jb = (count-1).bit_length()
            for byte in range(first,first+count):
                point = [(byte-first >> k) & 1 for k in range(jb)]+local
                byte_views.append((port+8*byte,offset,point,scale))
    for i,row,col,_,height,width,first,count,offset in y_tiles:
        assert first == 0 and count == 2
        cb, rb = (width-1).bit_length(), (height-1).bit_length()
        cell_offset, size = offset//2, height*width
        high = math.prod(v if (cell_offset//size >> k) & 1 else 1-v
                         for k,v in enumerate(cell_point[cb+rb:])) % P
        local = list(cell_point[:cb+rb])
        public_one = (public_one+high) % P
        norm, product = norms[i], products[i]
        pw = 32 if norm['weighted'] else 16
        emit(by_y[i],row,col,height,width,local,high,2+pw+48)
        # Sum of EQ over this complete local column cube is one, not width.
        emit(by_s[i],row,0,height,1,local[cb:],high,2+pw)
        if norm['weighted']:
            emit(product,row,col,height,width,local,high,2)
        else:
            hb = (norm['heads']-1).bit_length()
            if col or width != norm['columns'] or height < norm['heads']:
                raise ValueError('RMS unweighted cube cannot use the native head reshape')
            token_height, token_row = height//norm['heads'], row//norm['heads']
            low = (token_height-1).bit_length()
            total = (sources[product]['shape'][1]-1).bit_length()
            row_point = local[cb+hb:]+[(token_row//token_height >> k) & 1 for k in range(total-low)]
            claim = ([],row_point,local[:cb+hb],high)
            rne_views.append((2,product,claim))
    return {'public_one': public_one, 'sigma_byte_views': byte_views, 'rne_output_views': rne_views,
            'summary': {'credit': False, 'rms_cells': cells, 'rms_cell_cubes': len(y_tiles),
                        'compact_sigma_byte_views': len(byte_views), 'compact_rne_output_views': len(rne_views),
                        'honest_split_rne_output_cells': sum(n['statistic_rows']*n['columns'] for n in norms if not n['weighted']),
                        'input_split_extension_corrections': 2, 'input_split_zero_residuals': 1,
                        'complete_gamma_callers_and_reader': None}}


def rms_statistic_screen(cohorts):
    """One grouped cubic SC per RMS consumer; incoming S claims not counted.

    Statistics are internal demands of the future normalizer, not a new
    committed trace. Work assumes one incoming point per consumer only;
    payload/round counts also hold for multiple points batched beforehand.
    """
    records = rms_statistic_cohorts(cohorts)
    rounds = padded = work = additions = max_arrays = 0
    for r in records:
        rb, cb = (r["source_rows"]-1).bit_length(), (r["columns"]-1).bit_length()
        rows, cols = 1 << rb, 1 << cb
        cells = rows*cols
        rounds += rb+cb
        padded += cells
        # X pairs, selectors, four column scalings, Horner claim updates,
        # terminal factors and one EQ point table. No MAC arithmetic here.
        work += 10*(cells-1)+rows+cols+4*cb+3*(rb+cb)+4+3*rows+1
        additions += 12*(cells-1)+2*(rows+cols)+8*(rb+cb)+5+2*rows+1
        max_arrays = max(max_arrays, 24*(cells+rows+cols))
    count = len(records)
    corrections = 4*rounds+2*count  # four round coefficients, X endpoint, square
    return {"credit": False, "normalization_cohorts": count,
            "weighted_cohorts": sum(r["weighted"] for r in records),
            "statistic_rows": sum(r["statistic_rows"] for r in records),
            "statistic_input_cells": sum(r["statistic_rows"]*r["columns"] for r in records),
            "source_live_cells_read": sum(r["source_rows"]*r["columns"] for r in records),
            "source_padded_cells_processed": padded,
            # Per X pair: two reads for coefficients, then two reads and
            # one write AFTER the challenge. Plus initial array writes.
            "X_array_logical_read_write_bytes_before_selectors_replay_and_mac": 144*padded-120*count,
            "max_integer_statistic_given_i16_ranges": max(r["columns"] for r in records)*32767**2,
            "sumcheck_rounds": rounds, "extension_corrections": corrections,
            "private_square_equations": count, "zero_residual_equations": rounds+count,
            "message_bytes_before_incoming_claims_framing_and_shared_closures": 24*corrections,
            "new_plaintext_and_tag_array_bytes": 48*corrections,
            "fixed_input_error_numerator_before_claim_batching": 3*rounds,
            "single_cohort_X_and_selector_array_bytes": max_arrays,
            "one_point_per_cohort_prover_E_products_before_replay_and_mac_upper": work,
            "one_point_per_cohort_prover_E_additions_before_replay_and_mac_upper": additions,
            "additional_weight_reads_given_w_free_reader": 0,
            "new_statistic_pcs_instances": 0,
            "actual_statistic_claim_count": None,
            "complete_rms_normalizer_and_validity": False,
            "complete_gamma_memory_or_work": None}


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


def auxiliary_word_layout(sources, all_word_cubes=False):
    """R3 cubes: byte/column/row/head, head axis whole and power-of-two aligned.

    Byte records: source,row,col,heads,rows,cols,byte0,bytes,offset (9 u64).
    Word records: source,row,col,heads,rows,cols,offset (7 u64). By default
    only RQ sources; all_word_cubes also includes non-RNE words for LogUp's
    separate fraction index. This never adds those words to the real RQ.
    """
    if type(all_word_cubes) is not bool:
        raise ValueError('word cube selection must be Boolean')
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
                if source['rne'] or all_word_cubes:
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


def auxiliary_point_restriction(source, row, column, heads, height, width, claim):
    """Restrict a public head/global-token/column point to one word cube."""
    hp, rp, cp, scale = claim
    hb, rb, cb = (heads-1).bit_length(), (height-1).bit_length(), (width-1).bit_length()
    row += source['token_offset']
    if (len(hp) != hb or len(rp) < rb or len(cp) < cb or row % height
            or row+height > 1 << len(rp) or column+width > 1 << len(cp)):
        raise ValueError('point axes or row offset do not match the cube')
    high = (math.prod(x if (row//height >> k) & 1 else 1-x for k, x in enumerate(rp[rb:]))
            *math.prod(x if (column//width >> k) & 1 else 1-x for k, x in enumerate(cp[cb:]))) % P
    return list(cp[:cb])+list(rp[:rb])+list(hp), scale*high % P


def auxiliary_probe_terms(byte_tiles, sources, source_points):
    """Pull back raw point claims: source -> (head,row,column points, coefficient).

    row is a GLOBAL-token point for attention; each execution's token offset
    must align with its dyadic row cube. Returns EQ cube terms and signed bias.
    """
    terms, bias = [], 0
    for i, r, c, heads, height, width, j, count, offset in byte_tiles:
        if i not in source_points:
            continue
        source = sources[i]
        local, coefficient = auxiliary_point_restriction(source, r, c, heads, height, width, source_points[i])
        jb = (count-1).bit_length()
        weights = [pow(256, 1 << k, P) for k in range(jb)]
        bp = [w*pow(1+w, -1, P) % P for w in weights]
        terms.append((offset, bp+local, coefficient*pow(256, j, P)*math.prod(1+w for w in weights) % P))
        if j == 0:  # exactly once per word cube, not once per byte group
            bias = (bias+coefficient*(1 << (8*source['word_bytes']-1))) % P
    return terms, bias


def auxiliary_byte_terms(byte_tiles, sources, source_points, byte):
    """Pull back one byte plane at source points; no radix weights or bias.

    These are byte MLE claims, NOT bit extraction from a folded scalar.
    Repeated demands can concatenate calls with their public batch weights.
    """
    natural(byte, 'byte plane', 0, 5)
    for i in source_points:
        natural(i, 'byte source index', 0, len(sources)-1)
        natural(byte, 'source byte plane', 0, sources[i]['word_bytes']-1)
    terms = []
    for i, r, c, heads, height, width, j, count, offset in byte_tiles:
        if i not in source_points or not j <= byte < j+count:
            continue
        local, coefficient = auxiliary_point_restriction(
            sources[i], r, c, heads, height, width, source_points[i])
        point = [(byte-j >> k) & 1 for k in range((count-1).bit_length())]+local
        terms.append((offset, point, coefficient))
    return terms


def gemma_rne_shift_classes(cohorts, weight_exponents, activation_exponents, include_rope=False,
                            include_gate_up=False):
    """531 rules, +120 RoPE/+60 gate products, in a frozen public profile.

    No calibration values are supplied here. This validates the exponents
    read by these rules, not the complete nonlinear/profile grammar.
    Classes -15 and 48 also represent all smaller/larger shifts, respectively.
    """
    if type(include_rope) is not bool:
        raise ValueError('RoPE shift extension mode must be Boolean')
    if type(include_gate_up) is not bool:
        raise ValueError('gate product shift extension mode must be Boolean')
    if set(weight_exponents) != {c['weight_key'] for c in cohorts}:
        raise ValueError('the public W exponent map must cover the P0 inventory exactly')
    if any(type(v) is not int for values in (weight_exponents, activation_exponents) for v in values.values()):
        raise ValueError('public exponents must be fixed integers')
    routes = {r['cohort_ordinal']: r for r in gemma_input_routes(cohorts)}
    def exponent(layer, operation):
        key = f'model/{operation}' if layer is None else f'layer/{layer}/{operation}'
        if key not in activation_exponents:
            raise ValueError(f'missing public activation exponent: {key}')
        return activation_exponents[key]
    def shift(a, b, c):
        return max(-15, min(48, a-b-c))
    result = {}
    for c in cohorts:
        if c['kind'] != 'matrix':
            continue
        source = routes[c['ordinal']]['source_producer']
        result[c['layer'], c['operation']] = shift(
            exponent(c['layer'], c['operation']),
            exponent(source['layer'], source['operation']), weight_exponents[c['weight_key']])
    for layer in range(pinned_model_config()['layers']):
        for op, left, right in (('qk_matmul', 'q_rope', 'k_rope'),
                                ('pv_matmul', 'softmax', 'v_norm')):
            result[layer, op] = shift(exponent(layer, op), exponent(layer, left), exponent(layer, right))
        if include_rope:
            for op,norm in (('q_rope','q_norm'),('k_rope','k_norm')):
                result[layer,op] = shift(exponent(layer,op),exponent(layer,norm),-30)
        if include_gate_up:
            result[layer,'gate_up_mul'] = shift(exponent(layer,'gate_up_mul'),
                                              exponent(layer,'gelu_tanh'),exponent(layer,'up_proj'))
    return result


def auxiliary_rne_forms(rq_tiles, sources, source_points, source_shifts, validity_point):
    """Public f_s/g_s EQ terms for R2 on R3, no new claim wires or byte bias.

    source_points maps a source to a LIST of (head,row,column,coefficient)
    claims, already weighted by their global output-batch powers. QK's
    execution slices receive the same global-token claim. Even sources
    with no output claim retain whole-live-domain validity.
    """
    rne_sources = {i for i, source in enumerate(sources) if source['rne']}
    if set(source_shifts) != rne_sources or not set(source_points) <= rne_sources:
        raise ValueError('RNE shifts/points must name exactly the appropriate sources')
    for shift in source_shifts.values():
        natural(shift, 'public RNE shift class', -15, 48)
    live = sum(h*r*c for _, _, _, h, r, c, _ in rq_tiles)
    if not live or len(validity_point) != (live-1).bit_length():
        raise ValueError('validity point does not match the unified RQ domain')
    forms = {s: {'output': [], 'validity': []} for s in sorted(set(source_shifts.values()))}
    for i, r, c, heads, height, width, offset in rq_tiles:
        group = forms[source_shifts[i]]
        for claim in source_points.get(i, ()):
            local, coefficient = auxiliary_point_restriction(sources[i], r, c, heads, height, width, claim)
            group['output'].append((offset, local, coefficient))
        size, bits = heads*height*width, (heads*height*width-1).bit_length()
        high = math.prod(x if (offset//size >> j) & 1 else 1-x
                         for j, x in enumerate(validity_point[bits:])) % P
        group['validity'].append((offset, list(validity_point[:bits]), high))
    return forms


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
    # Conditional public evaluator count: one output point per raw cohort.
    # Later Gamma fanout changes the multiplicities, not these form identities.
    output_form_work = 0
    for i, _, _, _, _, _, _ in rq_tiles:
        source = sources[i]
        heads, source_rows, columns = source['shape']
        if source['operation'] == 'qk_raw':
            source_rows, columns = 150, old_tokens+150
        output_bits = sum((d-1).bit_length() for d in (heads, source_rows, columns))
        output_form_work += output_bits+2*rq_bits+4
    output_cohorts = len({(s['layer'], s['operation']) for s in sources if s['rne']})
    return {
        'credit': False, 'old_tokens': old_tokens, 'source_templates': len(sources),
        'source_byte_cells': live, 'source_padded_byte_cells': n,
        'auxiliary_i48_cells': (live-b_bytes)//6, 'rq_live_cells': rq_live,
        'rq_padded_cells': 1 << rq_bits, 'byte_cubes': len(byte_tiles), 'rq_cubes': len(rq_tiles),
        'source_descriptors_bytes': descriptors,
        'rne_public_form_screen': {
            'credit': False,
            'output_cohorts': output_cohorts,
            'output_terms_if_one_point_per_cohort': len(rq_tiles),
            'whole_live_domain_validity_terms': len(rq_tiles),
            'verifier_extension_products_at_one_rq_point_upper_if_one_point_per_cohort': (
                2*output_cohorts+output_form_work+(3*rq_bits+4)*len(rq_tiles)),
            'additional_mac_corrections_for_public_pullback': 0,
            'actual_gamma_claim_count_and_public_shifts_instantiated': False},
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
        'known_caller_extension_corrections': caller_e,
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


def wide_hash_witness_screen(cohorts, old_tokens=0):
    """A5 re-accounting of R3's SAME source and caller, not complete liveness.

    Contiguous query tiles replay the native encoder, with all repeated
    source/FFT work charged. Does not replace R3's existing narrow screen.
    """
    old = auxiliary_witness_screen(cohorts, old_tokens)
    n, block, q, tile, drop = old['source_padded_byte_cells'], 1 << 23, 357, 1 << 21, 4
    narrow = recursive_rs_opening_screen(n, block, q, 4)
    wide = wide_hash_rs_screen(n, block, q)
    b_bytes = old['source_byte_cells']-6*old['auxiliary_i48_cells']
    domain, c1_block = 4*block, block//16
    cache, c1_cache = 64*((2*domain >> drop)-1), 64*(2*c1_block-1)
    record_delta = (32*(wide['base_corrections_including_salt']
                       -narrow['base_corrections_including_anchor_upper'])
                    +48*(wide['extension_corrections_including_partial_sumchecks']
                         -narrow['extension_corrections_including_partial_sumchecks']))
    common_delta = cache-old['cached_outer_tree_bytes']+record_delta
    head_arrays = 8*150*(old_tokens+150+512)
    root_peak = (b_bytes+cache+48*block+144*tile
                 +old['source_descriptors_bytes']+head_arrays+65536)
    kv_width = kv_transition_screen(old_tokens)['core_requested_packed_kv_bytes_one_fused_visit']//(2*(old_tokens+150))
    kv_cells = [max(1 << 24, 1 << (kv_width*(1 << (rows-1).bit_length())-1).bit_length())
                for rows in (old_tokens, old_tokens+150) if rows]
    joint = wide_hash_joint_opening_screen([1 << 35, *kv_cells], 1 << 24, q)
    sigma = wide_hash_joint_opening_screen([n], block, q)
    joint_payload = (joint['private_component_payload_before_framing_and_caller']
                     +sigma['private_component_payload_before_framing_and_caller']-72
                     +24*old['known_caller_extension_corrections']
                     +joint['public_anchor_bytes_if_all_resent']+64)
    result = {
        'credit': False, 'old_tokens': old_tokens, 'wide_pcs': wide,
        'same_source_layout_sha256': old['layout_sha256'],
        'private_paired_pcs_payload_before_public_anchor_framing_and_caller': (
            old['unified_pcs_payload_before_framing_shared_closures']
            -narrow['component_payload_before_framing_and_other_components']
            +wide['private_component_payload_before_framing_and_caller']),
        'public_anchor_bytes_each_time_sent': 64,
        'fixed_output_tile_columns': tile,
        'commit_source_traversals': domain//tile,
        'commit_source_element_visits': n*(domain//tile),
        'commit_native_fft_butterflies': domain//tile*2*n*(block.bit_length()+1),
        'commit_hash_calls_before_anchor': domain*((n//block+9)//10)+domain-1,
        'commit_known_union_before_full_replay_runtime': root_peak,
        'cached_outer_tree_first_height': drop, 'cached_outer_tree_bytes': cache,
        'query_reconstructed_columns_upper': min(domain, q*(1 << drop)),
        'query_extra_group_and_digest_bytes': 144*min(domain, q*(1 << drop)),
        'compact_c1_cache_first_height': 2, 'compact_c1_cache_bytes': c1_cache,
        'compact_c1_query_reconstructed_columns_upper': 4*q,
        'opening_first_pass_known_union_before_full_replay_runtime': (
            old['opening_first_pass_known_union_before_replay_runtime']+common_delta),
        'compact_c1_commit_known_union_before_full_replay_runtime': (
            old['compact_c1_commit_known_union_before_replay_runtime']+common_delta
            +(592-336)*c1_block),
        'compact_c1_sumcheck_known_union_before_full_replay_runtime': (
            old['compact_c1_sumcheck_known_union_before_replay_runtime']+common_delta
            +c1_cache-old['compact_c1_internal_tree_cache_bytes']),
        'opening_query_known_union_before_full_replay_runtime': (
            old['opening_query_known_union_before_replay_runtime']+common_delta
            +c1_cache-old['compact_c1_internal_tree_cache_bytes']
            +144*min(domain, q*(1 << drop))-old['query_extra_stripe_and_digest_bytes']),
        'rne_link_known_union_before_full_replay_runtime': (
            old['rne_link_known_union_before_replay_runtime']+common_delta),
        'rne_top_known_union_before_full_replay_runtime': (
            old['rne_top_known_union_before_replay_runtime']+common_delta),
        'range_known_union_before_full_replay_runtime': (
            old['range_known_union_before_replay_runtime']+common_delta),
        'additional_weight_reads_given_w_free_reader': 0,
        'opening_source_traversals_after_commit': 2,
        'joint_w_kv_candidate': {
            'weight_and_state_opening': joint, 'auxiliary_opening': sigma,
            'known_caller_extension_corrections': old['known_caller_extension_corrections'],
            'known_partial_payload_with_all_anchors_and_one_shared_closure': joint_payload,
            'remaining_bytes_before_uncompiled_gamma_framing_refresh': 35_000_000-joint_payload,
            'inherits_previous_memory_peaks': False,
        },
        'source_reader_all_gamma_forms_and_full_liveness_compiled': False,
        'complete_certificate_bytes': None,
    }
    # State trees are charged INSIDE the arena, including the accepted one.
    # W/KV fold/query records come later; early state roots are charged below.
    states, w_block, kv_drop, sigma_drop = len(kv_cells), 1 << 24, 8, 5
    kv_cache = 64*((8*w_block >> kv_drop)-1)
    sigma_cache = 64*((8*block >> sigma_drop)-1)
    descriptors, params = 7680*states+144, 2680
    early_roots = 384*states  # one R/salt plaintext+tag set per state
    extra = states*kv_cache+descriptors+params+early_roots
    paired_e = paired_rs_opening_screen(n, block, q)['additional_extension_corrections']
    record_delta = (32*(sigma['base_corrections_including_salts']
                       -wide['base_corrections_including_salt'])
                    +48*(sigma['extension_corrections_including_paired_sumchecks']
                         -wide['extension_corrections_including_partial_sumchecks']-paired_e))
    change = sigma_cache-cache+record_delta+extra
    phases = {key.removesuffix('_known_union_before_full_replay_runtime'): value+change
              for key, value in result.items()
              if key.endswith('_known_union_before_full_replay_runtime') and key != 'commit_known_union_before_full_replay_runtime'}
    phases['opening_query'] += 144*q*((1 << sigma_drop)-(1 << drop))
    phases['commit_sigma'] = root_peak+sigma_cache-cache+extra
    # Commit the new state BEFORE allocating Sigma's tree; do not rebuild old.
    phases['commit_new_kv'] = (b_bytes+48*w_block+144*tile+extra
                              +old['source_descriptors_bytes']+head_arrays+65536)
    core = phases['opening_first_pass']-80*block
    p0, seed, k1 = weight_cohort_screen(cohorts), input_link_screen(cohorts), kv_transition_screen(old_tokens)
    phases['p0_compact_operands'] = core+p0['compact_operand_vectors_bytes']+p0['norm_sumcheck_scratch_upper_bytes']
    phases['seed_reducer'] = core+seed['single_reducer_two_extension_vectors_bytes']
    phases['k1_append'] = core+k1['single_plane_two_extension_vectors_bytes']+k1['single_plane_public_eq_tables_bytes_upper']+65536
    phases['k1_view_router'] = core+k1['read_route_one_bit_prefix_two_tail_vectors_bytes_at_capacity']+k1['single_plane_public_eq_tables_bytes_upper']+65536
    phases['t1_one_layer'] = core+max(value for case in attention_product_screen(old_tokens)['cases']
                                    for key, value in case.items() if key.endswith('_arrays_bytes'))
    records = (32*(joint['base_corrections_including_salts']+sigma['base_corrections_including_salts'])
               +48*(joint['extension_corrections_including_paired_sumchecks']
                    +sigma['extension_corrections_including_paired_sumchecks']
                    +old['known_caller_extension_corrections']+1))
    post = (records+states*kv_cache+descriptors+params+old['source_descriptors_bytes']
            +24*(joint['joint_rows']+sigma['joint_rows'])+65536)
    w_arrays = wide_hash_rs_screen(1 << 35, w_block, q)
    phases['sigma_tail_after_b_release'] = 256*block+wide['all_inner_full_trees_bytes']+post+144*q*(1 << sigma_drop)
    phases['joint_w_kv_after_sigma_release'] = (256*w_block+w_arrays['all_inner_full_trees_bytes']
                                             +post+144*q*(1 << kv_drop))
    hash_calls = max(joint['private_hash_calls_including_anchors_and_one_recursion'],
                     sigma['private_hash_calls_including_anchors_and_one_recursion'])
    phases['hash_after_compact_release'] = 13312*(1 << (hash_calls-1).bit_length())+post
    arena = 6442450944
    result['joint_w_kv_candidate']['known_state_cache_schedule'] = {
        'credit': False, 'kv_cached_first_height': kv_drop,
        'kv_cache_bytes_each': kv_cache, 'state_cache_count': states,
        'sigma_cached_first_height': sigma_drop, 'sigma_cache_bytes': sigma_cache,
        'state_and_joint_descriptor_bytes': descriptors,
        'early_state_root_record_bytes': early_roots, 'public_parameter_bytes_one_copy': params,
        'sigma_record_delta_from_nondeduplicated_baseline': record_delta,
        'literal_sigma_c1_with_height4_and_state_caches_bytes': phases['compact_c1_commit']+cache-sigma_cache,
        'known_authenticated_record_bytes_after_b_release': records,
        'arena_phases_bytes_before_uncompiled_reader_gamma_runtime': phases,
        'known_phase_max_bytes': max(phases.values()),
        'arena_remaining_before_uncompiled_reader_gamma_runtime': arena-max(phases.values()),
        'new_state_commit_source_visits': 32,
        'new_state_commit_native_fft_butterflies': 32*52*kv_cells[-1],
        'accepted_state_rebuild_visits_if_cache_missing': 32 if old_tokens else 0,
        'query_expanded_kv_columns_each_upper': q*(1 << kv_drop),
        'query_expanded_sigma_columns_upper': q*(1 << sigma_drop),
        'query_kv_group_digest_buffer_bytes_one_at_a_time': 144*q*(1 << kv_drop),
        'query_local_kv_hash_calls_each_upper': [q*(1 << kv_drop)*((cells//w_block+9)//10)
                                               +q*((1 << kv_drop)-1) for cells in kv_cells],
        'query_local_sigma_hash_calls_upper': q*(1 << sigma_drop)*((n//block+9)//10)+q*((1 << sigma_drop)-1),
        'requires_last_b_consumer_before_joint_opening': True,
        'complete_gamma_liveness': None,
    }
    if old_tokens == CONTEXT_CAP-150:
        # Only dyadic metadata is nonmonotone in O among these known arrays.
        # All padded domains, live head arrays, records and other scratch are
        # upper-bounded by the capacity case; no Gamma/reader bound is inferred.
        tilings = [3*(o+100).bit_count()+sum((o+i).bit_count() for i in range(101, 151))
                   for o in range(CONTEXT_CAP-150+1)]
        maximum = max(tilings)
        excess = maximum-tilings[-1]
        descriptor_delta, rq_top_delta = 12000*excess, 48*60*excess
        envelope = {key: value+descriptor_delta+(rq_top_delta if key == 'rne_top' else 0)
                    for key, value in phases.items()}
        result['joint_w_kv_candidate']['known_state_cache_schedule']['all_context_known_array_envelope'] = {
            'credit': False, 'old_lengths_checked': len(tilings),
            'max_qk_dyadic_rectangles_per_layer': maximum,
            'maximizing_old_lengths': [o for o, value in enumerate(tilings) if value == maximum],
            'descriptor_delta_above_capacity_bytes': descriptor_delta,
            'rne_top_additional_rq_form_bytes': rq_top_delta,
            'arena_phase_upper_bytes': envelope,
            'known_phase_max_upper_bytes': max(envelope.values()),
            'arena_remaining_before_uncompiled_reader_gamma_runtime': arena-max(envelope.values()),
        }
    return result


def rms_byte_bridge_screen(cohorts, include_rms_outputs=False):
    """S-byte candidate and optional, unadmitted virtual-Y extension.

    Recount the two endpoints and bound all fixed-100+50 contexts from the
    capacity envelope. The old narrower screens remain explicit comparisons;
    their small-domain counts cannot be reused at the earlier padding jump.
    Use public-zero outer rows for payload; retain the older, larger array
    reservations as conservative bounds, without claiming saved GPU memory.
    """
    if type(include_rms_outputs) is not bool:
        raise ValueError('RMS output extension mode must be Boolean')
    if cohorts[0]['rows'] != 150 or cohorts[-1]['rows'] != 50:
        raise ValueError('RMS byte bridge accounting covers pinned 100+50 only')
    stats = rms_statistic_screen(cohorts)
    statistic_sources = rms_statistic_byte_sources(cohorts)
    output_sources = rms_output_byte_sources(cohorts) if include_rms_outputs else []
    extra_sources = statistic_sources+output_sources
    extra_tiles, no_rq = auxiliary_word_layout(extra_sources)
    assert not no_rq
    count, packed = len(statistic_sources), sum(6*s['shape'][1] for s in statistic_sources)
    output_bytes = sum(2*math.prod(s['shape']) for s in output_sources)
    added_source_bytes = packed+output_bytes
    probe_bits = sum((s['shape'][1]-1).bit_length() for s in statistic_sources)
    corrections = stats['extension_corrections']+count
    descriptors = 96*len(extra_sources)+72*len(extra_tiles)
    raw_arrays = {'packed_statistics': packed, 'source_and_cube_descriptors': descriptors,
                  'new_plaintext_and_tags': 48*corrections,
                  'probe_and_input_points': 24*(probe_bits+stats['sumcheck_rounds']),
                  'statistic_kernel_descriptors': 96*count, 'kernel_control_reserve': 65536}
    output_tiles, split, reader_screen = [], None, None
    if include_rms_outputs:
        # Two split MAC values, one 29-coordinate cell point and 128 port weights.
        # No Y array or actual-profile RMS-J gates/records are reserved here.
        raw_arrays['rms_input_boundary_records_and_forms'] = 2*48+24*(29+128)
        raw_arrays['rms_row_multiplier_cache'] = packed  # Same six-byte row count as S; NOT in Sigma.
        norms = rms_statistic_cohorts(cohorts)
        output_tiles, _ = auxiliary_word_layout(output_sources)
        rne_tiles = [t for t in output_tiles if not norms[t[0]]['weighted']]
        volumes = [math.prod(t[3:6]) for t in rne_tiles]
        n = (output_bytes//2-1).bit_length()
        readers = rms_cut_reader_plan(cohorts)
        if any(t[5] % 64 for t in output_tiles):
            raise ValueError('RMS word reader screen requires 64-lane-aligned column cubes')
        product_bytes = sum(r['product_word_bytes']*r['rows']*r['columns'] for r in readers)
        words = sum(r['rows']*r['columns']//64 for r in readers)
        reader_screen = {'credit': False, 'descriptor_bytes': 56*len(readers),
                         'product_B_bytes_per_full_visit': product_bytes,
                         'live_64_lane_words_per_full_visit': words,
                         'statistic_and_multiplier_bytes_per_full_visit': 12*words,
                         'logical_input_read_bytes_per_full_visit': product_bytes+12*words,
                         'raw_rne_calls_per_full_visit': sum(volumes),
                         'producer_replays_after_S_and_multiplier_preparation': 0,
                         'weight_reads_after_S_and_multiplier_preparation': 0,
                         'complete_all_sigma_reader_and_gamma': None}
        split = {'credit': False, 'rne_output_cells': sum(volumes), 'rne_cubes': len(rne_tiles),
                 'raw_B_logical_bytes': 6*sum(volumes),
                 'field_products_upper': 19*sum(volumes)+sum(n-(v.bit_length()-1)-1 for v in volumes)+n*len(output_tiles)+1,
                 'field_additions_upper': 17*sum(volumes)+(n+1)*(len(rne_tiles)+len(output_tiles))+2,
                 'additional_sigma_source_scans': 0, 'additional_weight_reads_given_raw_B': 0,
                 'requires_final_cell_point_and_port_mix_before_read': True,
                 'complete_reader_and_framing': None}
    arrays = {k: 256*((v+255)//256) for k, v in raw_arrays.items()}
    extra_bytes, cases, final_envelope = sum(arrays.values()), [], None
    config = pinned_model_config()
    weight_live = sum(math.prod(shape) for shape in
                      {c['weight_key']: c['weight_shape'] for c in cohorts}.values())
    kv_width = sum(2*config[k+'_layers']*config[k+'_kv_heads']*config[k+'_head_dim']
                   for k in ('local', 'global'))
    bit_max = byte_bit_lift_screen(34)
    bit_records = 256*((48*bit_max['extension_corrections_excluding_incoming_claims']+255)//256)
    bit_records += 256*((24*bit_max['extension_challenges']+255)//256)
    rne_bits_max = rne_output_bit_screen(31)
    rne_bit_reserve = rne_bits_max['additional_array_reservation_bytes']
    for old_tokens in (0, CONTEXT_CAP-150):
        original = auxiliary_word_sources(cohorts, old_tokens)
        old_tiles, rq = auxiliary_word_layout(original)
        sources = original+extra_sources
        byte_tiles, new_rq = auxiliary_word_layout(sources)
        assert rq == new_rq and len(byte_tiles)-len(old_tiles) == len(extra_tiles)
        live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
        original_live = live-added_source_bytes
        assert (live-1).bit_length() == (original_live-1).bit_length()  # ONLY the endpoints
        bit_lift = byte_bit_lift_screen((live-1).bit_length())
        rne_bits = rne_output_bit_screen((sum(h*r*c for _, _, _, h, r, c, _ in rq)-1).bit_length())
        base = wide_hash_witness_screen(cohorts, old_tokens)['joint_w_kv_candidate']
        schedule = base['known_state_cache_schedule']
        phases = {k: v+extra_bytes+bit_records+rne_bit_reserve for k, v in
                  schedule['arena_phases_bytes_before_uncompiled_reader_gamma_runtime'].items()}
        common = phases['opening_first_pass']-80*(1 << 23)
        phases['rms_statistic'] = common+stats['single_cohort_X_and_selector_array_bytes']
        phases['byte_bit_top'] = common+bit_lift['top_array_bytes']
        phases['byte_bit_link'] = common+bit_lift['link_array_bytes']
        # KV prefix includes each plane's token padding, not packed live KV.
        prefixes = [weight_live]+[kv_width*(1 << (length-1).bit_length())
                                  for length in (old_tokens, old_tokens+150) if length]
        joint_cells = base['weight_and_state_opening']['source_cells']
        zero_rows = [n//(1 << 24)-(prefix+(1 << 24)-1)//(1 << 24)
                     for n, prefix in zip(joint_cells, prefixes)]
        sigma_zero = (1 << (live-1).bit_length())//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
        joint = wide_hash_joint_opening_screen(joint_cells, 1 << 24, 357, zero_rows)
        sigma = wide_hash_joint_opening_screen([1 << (live-1).bit_length()], 1 << 23, 357, [sigma_zero])
        payload = (joint['private_component_payload_before_framing_and_caller']
                   +sigma['private_component_payload_before_framing_and_caller']-72
                   +24*(base['known_caller_extension_corrections']+corrections)
                   +joint['public_anchor_bytes_if_all_resent']+64
                   +bit_lift['payload_before_incoming_claims_framing_and_shared_closures']
                   +rne_bits['additional_payload_before_incoming_claims_and_framing'])
        payload += 48*int(include_rms_outputs)
        cases.append({'old_tokens': old_tokens, 'source_templates': len(sources),
                      'source_byte_cells': live, 'source_padded_byte_cells': 1 << (live-1).bit_length(),
                      'byte_cubes': len(byte_tiles), 'rq_cubes': len(rq),
                      'layout_sha256': hashlib.sha256(json.dumps(
                          [sources, byte_tiles, rq], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                      'public_zero_rows_joint_w_kv': zero_rows, 'public_zero_rows_sigma': sigma_zero,
                      'omitted_outer_base_corrections': 357*(sum(zero_rows)+sigma_zero),
                      'byte_bit_lift': bit_lift,
                      'rne_output_bits': rne_bits,
                      'known_partial_payload_before_rms_circuit_gamma_and_framing': payload,
                      'remaining_payload_bytes_before_missing_components': 35_000_000-payload,
                      'arena_phase_upper_bytes': phases, 'known_phase_max_upper_bytes': max(phases.values())})
        if old_tokens:
            envelope = schedule['all_context_known_array_envelope']['arena_phase_upper_bytes']
            final_envelope = {k: v+extra_bytes+bit_records+rne_bit_reserve for k, v in envelope.items()}
            common = final_envelope['opening_first_pass']-80*(1 << 23)
            final_envelope['rms_statistic'] = common+stats['single_cohort_X_and_selector_array_bytes']
            final_envelope['byte_bit_top'] = common+bit_max['top_array_bytes']
            final_envelope['byte_bit_link'] = common+bit_max['link_array_bytes']
    first_live = cases[0]['source_byte_cells']-added_source_bytes
    stride = 6*config['layers']*config['query_heads']*150
    changed = [o for o in range(CONTEXT_CAP-150+1) if
               (first_live+stride*o-1).bit_length() != (first_live+stride*o+added_source_bytes-1).bit_length()]
    output_comparison = None
    if include_rms_outputs:
        # Only the Sigma/range/bit-lift paths change with Y's earlier domain
        # jump; evaluate their exact delta at EVERY O without rebuilding 3947 layouts.
        sigma = {n: wide_hash_joint_opening_screen([1 << n], 1 << 23, 357, [0])
                 ['private_component_payload_before_framing_and_caller'] for n in (33,34)}
        alphabet = {n: 24*byte_range_tree_screen(n)['extension_corrections'] for n in (33,34)}
        bits = {n: byte_bit_lift_screen(n)['payload_before_incoming_claims_framing_and_shared_closures']
                for n in (33,34)}
        def source_payload(live):
            n = (live-1).bit_length()
            zero_rows = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
            return sigma[n]-8*357*zero_rows+alphabet[n]+bits[n]
        deltas, changed_from_s = [], []
        for old in range(CONTEXT_CAP-150+1):
            before = first_live+packed+stride*old
            after = before+output_bytes
            deltas.append(source_payload(after)-source_payload(before)+48)
            if (before-1).bit_length() != (after-1).bit_length():
                changed_from_s.append(old)
        output_comparison = {'credit': False, 'contexts_checked': len(deltas),
                             'source_path_payload_deltas_including_input_split': deltas,
                             'maximum_source_path_payload_delta': max(deltas),
                             'old_lengths_with_changed_padding_from_s': changed_from_s,
                             'complete_all_context_total_payload': None}
    return {'credit': False, 'statistic_sources': count, 'packed_statistic_bytes': packed,
            'includes_rms_outputs': include_rms_outputs, 'rms_output_sources': len(output_sources),
            'rms_output_live_bytes': output_bytes, 'rms_output_retained_array_bytes': 0,
            'rms_output_cell_cubes': len(output_tiles), 'rms_input_split_honest_screen': split,
            'rms_cut_reader_screen': reader_screen,
            'requires_output_regeneration_or_new_cache_schedule': include_rms_outputs,
            'rms_input_split_corrections': 2*int(include_rms_outputs),
            'rms_output_all_context_comparison': output_comparison,
            'known_bulk_output_reads_before_gamma_and_rms_replay': (16+95+2+bit_max['source_visits'] if include_rms_outputs else 0),
            'rms_row_multiplier_preparations': stats['statistic_rows']*int(include_rms_outputs),
            'rms_row_multiplier_preparation_binary_rounds_upper': 47*stats['statistic_rows']*int(include_rms_outputs),
            'rms_lane_exact_comparisons_upper': int(include_rms_outputs),
            'initial_statistic_i16_squares': stats['statistic_input_cells'],
            'initial_statistic_integer_additions': stats['statistic_input_cells']-stats['statistic_rows'],
            'extra_byte_cubes': len(extra_tiles), 'extra_descriptor_bytes': descriptors,
            'statistic_probe_extension_coordinates': probe_bits,
            'statistic_probe_and_sumcheck_extension_corrections': corrections,
            'additional_payload_before_rms_circuit_gamma_and_framing': 24*corrections+48*int(include_rms_outputs),
            'additional_known_sigma_claims': count+1,
            'known_sigma_claims_before_future_gamma': len(cohorts)+8+2*config['layers']+count+1,
            'fixed_input_probe_and_sumcheck_error_numerator': probe_bits+stats['fixed_input_error_numerator_before_claim_batching'],
            'additional_common_sigma_batch_error_numerator': count+1,
            'bit_lift_record_reservation_bytes': bit_records,
            'rne_output_bit_reservation_bytes': rne_bit_reserve,
            'additional_arrays_reserved_256_byte_aligned': arrays,
            'additional_array_reservation_bytes': extra_bytes,
            'known_bulk_statistic_reads_before_replay_and_normalizer': 16+95+2+1+bit_max['source_visits'],
            'known_bulk_statistic_read_and_initial_write_bytes': (16+95+2+1+bit_max['source_visits']+1)*packed,
            'cases': cases, 'old_lengths_with_changed_byte_padding': changed,
            'all_context_arena_phase_upper_bytes': final_envelope,
            'all_context_known_phase_max_upper_bytes': max(final_envelope.values()),
            'remaining_arena_bytes_before_missing_components': 6442450944-max(final_envelope.values()),
            'array_reservation_includes_omitted_records': True,
            'same_rq_layout': True, 'requires_rebuilding_all_sigma_byte_forms': True,
            'additional_weight_reads_given_w_free_reader': 0, 'additional_pcs_instances': 0,
            'complete_rms_integer_circuit': None, 'complete_gamma_liveness': None,
            'complete_certificate_bytes': None}


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
    gamma = gamma_barrier_plan(cohorts)
    n = 1 << (live - 1).bit_length()
    h = n.bit_length() - 1
    matrix_shapes = Counter(tuple(t["shape"]) for t in tensors if len(t["shape"]) == 2)
    max_dot = max(columns for _, columns in matrix_shapes)
    assert max_dot == 21_504
    cut = cut_witness_screen()
    rope_bridge = rope_byte_bridge_screen(cohorts)
    gelu_bridge = gelu_byte_bridge_screen(cohorts,rope_bridge)
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
        "wide_hash_rs_screen": wide_hash_rs_screen(n, 1 << 24, 357),
        "wide_hash_parameter_screen": wide_hash_parameter_screen(),
        "wide_hash_fixed_trail_screen": wide_hash_fixed_trail_screen(),
        "wide_hash_security_assumption_screen":wide_hash_security_assumption_screen(),
        "private_projection_compilation_screens": [
            private_projection_compilation_screen(size, block, 357, attempts)
            for size, block, attempts in ((n, 1 << 24, LIFETIME_ATTEMPTS),
                                         (1 << 33, 1 << 23, 1), (1 << 34, 1 << 23, 1))],
        "private_targeted_lifetime_screen":private_targeted_lifetime_screen(),
        "wide_hash_witness_screens": [wide_hash_witness_screen(cohorts, old)
                                     for old in (0, 3946)],
        "paired_rs_opening_screen": paired_rs_opening_screen(n, 1 << 24, 357),
        "weight_cohort_screen": weight_cohort_screen(cohorts),
        "input_link_screen": input_link_screen(cohorts),
        "gamma_barrier_screen": gamma["summary"],
        "gamma_rms_source_barrier_screen": gamma_barrier_plan(cohorts,True)['summary'],
        "rope_linear_screen": gemma_rope_plan(cohorts)['summary'],
        "gelu_lookup_fraction_core_screen": lookup_fraction_screen(
            pinned_model_config()['layers']*150*pinned_model_config()['intermediate_size'],
            pinned_model_config()['layers']*((1 << 16)-1)),
        "gelu_public_table_setup_screens": [gelu_table_setup_screen(a,b)
                                            for a,b in ((0,0),(-8,-8),(-8,-12))],
        "gelu_reader_screen":gelu_reader_screen(cohorts),
        "rope_byte_bridge_screen":rope_bridge,
        "gelu_byte_bridge_screen":gelu_bridge,
        "gate_up_product_screen":gate_up_product_screen(cohorts,gelu_bridge),
        "gamma_rope_source_barrier_screen":gamma_barrier_plan(cohorts,True,True)['summary'],
        "gamma_gelu_source_barrier_screen":gamma_barrier_plan(cohorts,True,True,True)['summary'],
        "gamma_gate_product_source_barrier_screen":gamma_barrier_plan(cohorts,True,True,True,True)['summary'],
        "rms_statistic_dependency_screen": rms_statistic_dependency_plan(cohorts,gamma)["summary"],
        "rms_statistic_screen": rms_statistic_screen(cohorts),
        "rms_byte_bridge_screen": rms_byte_bridge_screen(cohorts),
        "rms_output_byte_bridge_screen": rms_byte_bridge_screen(cohorts, True),
        "rms_boolean_cohort_screen": rms_boolean_cohort_screen(cohorts),
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

#!/usr/bin/env python3
"""Bounded C7.1 PCS/rolling-KV screen, never a full-work or security admission."""
import json
from fractions import Fraction

import c7_1_gemma_plan as base


def geometry(h, *, queries=512, exposures=3, first=7, step=2, rate=8, ell=2048):
    remaining, folds, oracles = h, [], []
    while True:
        fold = first if not folds else step
        remaining -= fold
        if remaining < 0:
            raise ValueError('fold exceeds remaining dimension')
        folds.append(fold)
        message = 1 << remaining
        pad = exposures * queries if len(folds) == 1 else queries
        domain = 1 << (rate * (message + pad) - 1).bit_length()
        if domain > 1 << 32 or 3 * (domain // 4) >= domain - message - pad + 1:
            raise ValueError('Goldilocks domain or unique-radius premise')
        oracles.append(dict(message_rows=message, randomness_rows=pad,
                            domain_rows=domain, width=1 << fold))
        if remaining <= 6:
            break
    if ell <= max(o['randomness_rows'] for o in oracles):
        raise ValueError('mask must cover randomness and the OOD coefficient')
    mask = dict(message_rows=ell, randomness_rows=queries,
                domain_rows=1 << (rate * (ell + queries) - 1).bit_length())
    if 3 * (mask['domain_rows'] // 4) >= mask['domain_rows'] - ell - queries + 1:
        raise ValueError('mask unique radius')
    profile = dict(log_message_cells=h, folds=folds, oracles=oracles)
    wire = base.b12_native_linear_pcs_wire(profile, mask, query_count=queries)
    # Exact B12 coin-block expressions, with these candidate parameters.
    q = base.P ** 3
    groups = 2 * len(folds) - 1
    errors = [Fraction(1, q-2)]
    for i, (o, fold) in enumerate(zip(oracles, folds)):
        errors.extend([Fraction(o['domain_rows']//4+1+ell, q-2)] * fold)
        if i != len(oracles)-1:
            errors.extend([Fraction(2*(o['message_rows']+ell-1), q-2),
                Fraction(3, 4)**queries + Fraction(1+queries*o['width'], q-2)])
    errors.extend([Fraction(oracles[-1]['domain_rows']//4+mask['domain_rows']//4+3, q-2),
        Fraction(4*groups-1, 4*groups)**(groups*queries)])
    exact = max(errors)
    # Outward rounding keeps JSON small even when the split-mask power wins.
    maximum = Fraction(((exact.numerator << 256)+exact.denominator-1)//exact.denominator, 1 << 256)
    widths = sum(folds) + len(folds)-1
    # Logical array/FFT geometries, NOT measured operations or total prover work.
    # Per encoding: charge setup and every re-materialization separately.
    initial = oracles[0]
    initial_cells = initial['domain_rows'] * initial['width']
    fresh = [(o['domain_rows'], o['width']) for o in oracles[1:]]
    fresh += [(oracles[-1]['domain_rows'], 1), (mask['domain_rows'], 2*widths)]
    return dict(h=h, queries=queries, exposures=exposures, first=first, step=step,
        rate=rate, ell=ell, folds=folds, wire=wire,
        initial_domain_rows=initial['domain_rows'], initial_width=initial['width'],
        initial_private_pad_fp=initial['randomness_rows']*initial['width'],
        retained_initial_payload_bytes=8*((1 << h)+initial_cells
            +initial['randomness_rows']*initial['width'])
            +32*initial['domain_rows']+32*(2*initial['domain_rows']-1),
        initial_encoded_base_cells=initial_cells,
        initial_radix2_butterflies=initial_cells*(initial['domain_rows'].bit_length()-1)//2,
        fresh_encoded_extension_cells=sum(n*w for n, w in fresh),
        fresh_radix2_butterflies=sum(n*w*(n.bit_length()-1)//2 for n, w in fresh),
        # SelectStatement::combine_packed still dots all t query weights into
        # each of M cells. Splitting reduces scratch, not the t*M products.
        power_covector_dot_terms=queries*sum(o['message_rows'] for o in oracles[:-1]),
        PCS_max_coin_block_error=str(maximum),
        PCS_prefix_error=str((1 << 74)*maximum))


def retained_work(old, rolling):
    """Actual commit/proof multiplicities; separate partial costs, no net-work credit."""
    def count(profiles, commits, openings):
        return dict(initial_commit_calls=commits, PCS_calls=openings,
            initial_DFT_output_base_cells=sum(n*p['initial_encoded_base_cells']
                for n, p in zip(commits, profiles)),
            initial_radix2_butterfly_geometry=sum(n*p['initial_radix2_butterflies']
                for n, p in zip(commits, profiles)),
            initial_salted_rows_created=sum(n*p['initial_domain_rows']
                for n, p in zip(commits, profiles)),
            initial_stored_digests_created=sum(n*(2*p['initial_domain_rows']-1)
                for n, p in zip(commits, profiles)),
            initial_private_pad_fp=sum(n*p['initial_private_pad_fp']
                for n, p in zip(commits, profiles)),
            fresh_PCS_DFT_output_extension_cells=sum(n*p['fresh_encoded_extension_cells']
                for n, p in zip(openings, profiles)),
            power_covector_dot_terms=sum(n*p['power_covector_dot_terms']
                for n, p in zip(openings, profiles)))
    prefixes = []
    for t in (1, 2, 3):
        old_openings = [t, t*(t+1)//2]
        baseline = count(old, [1+t, t+old_openings[1]], old_openings)
        kept = count(old, [1, t], old_openings)
        renewed = count(rolling, [t, t], [2*t-1, 2*t-1])
        prefixes.append(dict(responses=t, baseline=baseline,
            same_protocol_retained=kept, rolling_with_retention=renewed,
            same_protocol_retained_payload_bytes=old[0]['retained_initial_payload_bytes']
                +t*old[1]['retained_initial_payload_bytes'],
            rolling_retained_payload_bytes_before_promotion=(1 if t == 1 else 2)
                *sum(p['retained_initial_payload_bytes'] for p in rolling)))
    return dict(credit=False, native_scope='D12 native wire / D10 serde identity, common FS and initial DFT deletion',
        canonical_scope='arithmetic multiplicities and payload sizes, not materialization',
        new_H100_or_provider_execution=False, prefixes=prefixes,
        payload_excludes=['Vec headers, allocator and page overhead', 'weights/KV/runtime outside the retained object',
            'fresh proof temporaries, PCG and transport staging'],
        full_work_nonincrease_verified=False,
        unresolved=['additional fresh W PCS work, including t*M query covectors', 'RNE weighted first-layer construction and link forms',
            'current KV preparation and range', 'physical cache placement and transfer schedule'])


def rne_tree_core(cells, components, rounds, original_views):
    """Source-expression counts for eight range::prove_tree layers + products.

    A pair costs 27 mul/23 add in cubic coefficients and 5 mul/10 add
    in folds; a round costs 8 mul/17 add; a layer 17 mul/20 add.
    Each component has 24 product triples, at 6 mul/4 add each.
    Seeded first weights use the original views, without an extra cell pass.
    Excludes tables, caller MAC aggregation, FS, memory/IO and all PCS.
    """
    pairs = 255*cells-8*components
    equality_pairs = 255*cells-7*components-original_views
    return dict(cubic_pairs=pairs, cubic_rounds=rounds,
        Fp3_mul_expressions=32*pairs+2*equality_pairs+8*rounds+280*components,
        Fp3_add_sub_expressions=33*pairs+equality_pairs+17*rounds+256*components)


def joint_state(old, rolling_w, rolling_a, cases):
    """One mobile root, retaining the separate pre-prompt W installation link."""
    installed = geometry(35, queries=456, exposures=1, first=7, step=4, rate=4, ell=457)
    state = geometry(36, queries=456, exposures=2, first=8, step=4, rate=4, ell=913)
    wire, work = [], []
    partial_costs = ('initial_encoded_base_cells', 'initial_radix2_butterflies',
                     'fresh_encoded_extension_cells', 'fresh_radix2_butterflies',
                     'power_covector_dot_terms')
    for slot, case in enumerate(cases):
        # S = W[D35] || A_with_old_KV[D34] || zero[D34]. No free padding.
        assert case['rolling_A_live_bytes'] <= 1 << 34
        count = 1 + bool(slot)
        interval = [case['rolling_W_and_KV_interval'][e]
            - count*(rolling_w['wire']['wire_interval'][e]+rolling_a['wire']['wire_interval'][e])
            + count*state['wire']['wire_interval'][e]
            + (installed['wire']['wire_interval'][e]+36 if slot == 0 else 0)
            for e in (0, 1)]
        wire.append(dict(old_tokens=case['old_tokens'], source_PCS_count=2,
            complete_response_interval=interval, current_state_dimension=36,
            explicit_zero_quarter_cells=1 << 34,
            installed_W_PCS_included=(slot == 0), native_certificate_verified=False))
        t = slot+1
        previous = dict(initial_commit_calls=[1+t, t+t*(t+1)//2],
                        PCS_calls=[t, t*(t+1)//2])
        merged = dict(initial_commit_calls=[1, t], PCS_calls=[1, 2*t-1])
        for key in partial_costs:
            calls = 'initial_commit_calls' if key.startswith('initial_') else 'PCS_calls'
            previous[key] = sum(n*p[key] for n, p in zip(previous[calls], old))
            merged[key] = sum(n*p[key] for n, p in zip(merged[calls], (installed, state)))
        # These larger source domains are not concealed by cheaper query/DFT phases.
        previous['initial_sumcheck_source_cells'] = sum(n*(1 << p['h'])
            for n, p in zip(previous['PCS_calls'], old))
        merged['initial_sumcheck_source_cells'] = (1 << 35)+(2*t-1)*(1 << 36)
        work.append(dict(responses=t, baseline=previous, joint=merged,
            retained_payload_bytes_before_promotion=(installed['retained_initial_payload_bytes']
                +state['retained_initial_payload_bytes'] if t == 1
                else 2*state['retained_initial_payload_bytes']),
            full_work_nonincrease_verified=False))
    return dict(credit=False, selected=False, complete_security_proven=False,
        installed_W=installed, state=state, cases=wire, prefixes=work,
        lifetime='three attempts screened; finite-profile security extension unproved',
        full_prover_work=None, full_work_nonincrease_verified=False,
        unresolved=['D36 native dispatch and canonical positive certificate',
            'same installed W and cumulative KV composition, including first-response link',
            'extra zero quarter, larger initial sumchecks and rebased source forms',
            'RNE work and ROM/ZK resource census', 'host storage, peak HBM and all transfers'])


def feasibility(cases):
    """Reject the existing dense candidates; lower bounds, not H100 timings.

    byte_function::required(d) = 169+32*d; the B12 prover sends 576
    eight-byte COPE corrections per base row, three rows per Fp3.
    The dense byte-function tree retains 256+128+...+1 pairs per cell.
    NVIDIA H100 SXM: 3.35 TB/s peak HBM. Never treat peak as effective.
    """
    screened = []
    for slot, case in enumerate(cases):
        bits = case['unpadded_RNE_group_bits']
        cells = sum(1 << d for d in bits)
        fp3_rows = sum(169+32*d for d in bits)
        writes = 48*511*cells
        screened.append(dict(old_tokens=150*slot,
            certificate_cap_bytes=130_000_000 if slot == 0 else 40_000_000,
            RNE_PS_Fp3_rows=fp3_rows,
            # Excludes sacrifices, OT, checks, seal and every response byte.
            verifier_COPE_bytes_lower=576*8*3*fp3_rows,
            dense_RNE_tree_peak_bytes=48*511*(1 << max(bits)),
            dense_RNE_tree_write_bytes_lower=writes,
            dense_RNE_write_seconds_at_HBM_peak_lower=writes/3.35e12,
            # Illustrative 80% efficiency, not a measured or admitted rate.
            dense_RNE_write_seconds_at_80pct_peak=writes/2.68e12,
            full_prover_seconds=None, feasible=False))
    return dict(credit=False, selected=False, hardware_credit=False,
        capacity=dict(attempts=3, new_tokens_per_attempt=150, total_tokens=450),
        complete_certificate_cap_verified=False,
        full_work_nonincrease_verified=False,
        cases=screened,
        conversation_certificate_cap_bytes=210_000_000,
        conversation_RNE_COPE_bytes_lower=sum(c['verifier_COPE_bytes_lower'] for c in screened),
        decision='reject current dense candidates; COPE alone also rejects global-W-only repair')


def shout_residual_screen(current):
    """Necessary residual costs if ONLY the RNE P/S consumer is replaced.

    rne::required minus byte_function::required is >= 8*c+1 for every
    shift. range::prove separately authenticates all 65535 W histogram
    entries. Omitted costs are unknown, not free or a proposed Shout codec.
    """
    shape = current['complete_fixed_run_composition']['native_canonical_transport']
    cases = []
    for slot, bits in enumerate(shape['RNE_cell_bits_sum']):
        rne_rows = 8*bits + shape['mandatory_RNE_records']
        rows = rne_rows + 65535
        cases.append(dict(old_tokens=150*slot,
            RNE_reduction_Fp3_rows_lower=rne_rows,
            RNE_reduction_COPE_bytes_lower=13824*rne_rows,
            RNE_and_W_histogram_Fp3_rows_lower=rows,
            attributable_COPE_bytes_lower=13824*rows,
            prover_COPE_field_outputs_lower=2*576*3*rows))
    # range::prove retains leaves and every internal node, all after alpha FS.
    trees = [48*(2*(1 << d)-1) for d in (35, 34)]
    return dict(credit=False, selected=False, hardware_credit=False,
        scope='replace RNE P/S only; original RNE reductions, W range and bootstrap unchanged',
        capacity=dict(attempts=3, prompt_tokens=100, generated_tokens=50, total_tokens=450),
        certificate_caps_bytes=[130_000_000, 40_000_000, 40_000_000], cases=cases,
        first_certificate_COPE_bytes_lower=sum(c['attributable_COPE_bytes_lower'] for c in cases),
        complete_certificate_bytes=None, complete_certificate_cap_verified=False,
        unchanged_W_A_range_tree_bytes=trees,
        unchanged_range_tree_write_bytes_lower=sum(trees),
        unchanged_range_build_levels=[35, 34],
        unchanged_range_GKR_rounds=[35*34//2, 34*33//2],
        complete_global_bytes=None, complete_dynamic_bytes=None,
        complete_response_traffic_bytes=None, full_prover_seconds=None,
        full_work_nonincrease_verified=False,
        decision='reject local substitution: residual COPE exceeds caps and FS-dependent W tree exceeds arena')


def report():
    current = base.b12_pcs_binding_assessment()
    old = [geometry(h) for h in (35, 34)]
    for ours, known in zip(old, current['native_canonical_linear_PCS_wire']):
        assert ours['wire']['wire_interval'] == known['wire_interval']
    candidates = []
    # Finite explicit search family; no assertion of a globally optimal PCS.
    for queries in (448, 456, 464, 480, 512):
        for first in (6, 7, 8):
            for step in (2, 3, 4, 5):
                pair = [geometry(h, queries=queries, exposures=life, first=first,
                    step=step, rate=4, ell=life*queries+1) for h, life in ((35, 3), (34, 2))]
                # Leave at least 87 bits for this PCS prefix term. This is NOT
                # the full security test, whose undischarged terms remain explicit.
                if max(Fraction(p['PCS_prefix_error']) for p in pair) >= Fraction(1, 1 << 87):
                    continue
                candidates.append(pair)
    best = min(candidates, key=lambda pair: sum(p['wire']['wire_interval'][1] for p in pair))
    # Fixed candidate also tested by the native component; keep the scan's winner visible.
    chosen = [geometry(h, queries=456, exposures=life, first=6, step=4,
                       rate=4, ell=456*life+1) for h, life in ((35, 3), (34, 2))]
    rolling_w = geometry(35, queries=456, exposures=2, first=6, step=4, rate=4, ell=913)
    cases = []
    for slot, c in enumerate(current['native_canonical_certificate_wire']['cases']):
        # Native canonical descriptor census; unpadded dyadic bins are checked
        # independently by c71_b12_rne_joint_bytes_canonical_geometry.
        separate_cells = (23135780864, 24142413824, 24142413824)[slot]
        group_bits = [d for d in range(34, -1, -1) if separate_cells >> d & 1]
        assert sum(1 << d for d in group_bits) == separate_cells
        rne_wire = sum(5004 + 960*d + 6 for d in group_bits)
        previous_functions = (25210128, 25267728, 25267728)[slot]
        assert (previous_functions-892*5004) % 960 == 0
        original_dimension_sum = (previous_functions-892*5004)//960
        baseline_rne_core = rne_tree_core(separate_cells, 892,
            8*original_dimension_sum+28*892, 892)
        grouped_rne_core = rne_tree_core(separate_cells, len(group_bits),
            8*sum(group_bits)+28*len(group_bits), 892)
        saved_rne = (25210128, 25267728, 25267728)[slot] - rne_wire
        intervals = []
        for end in (0, 1):
            total = c['total_wire_interval'][end] - saved_rne
            total -= old[0]['wire']['wire_interval'][end] + (slot+1)*old[1]['wire']['wire_interval'][end]
            total += chosen[0]['wire']['wire_interval'][end] + (1+bool(slot))*chosen[1]['wire']['wire_interval'][end]
            # Constant header retaining one predecessor. Reserve the old gamma
            # vector lengths (larger than the tuned numeric vectors), including
            # a new profile identity; fresh prefix link costs 1 Fp3 + 1 frame.
            if slot:
                total += 30
                total -= 750*(slot-1)  # 720 history + 24 old target + 6 PCS frame
            intervals.append(total)
        live = current['ordinary_KV_output_and_EXP30_composition']['cases'][slot]['auxiliary_live_bytes']
        # 50 local + 10 global layers, original K/V heads and channels; i16 bytes.
        copied = slot * 150 * 2 * 32 * (50*256 + 10*512) * 2
        cases.append(dict(old_tokens=150*slot, baseline_interval=c['total_wire_interval'],
            projected_complete_response_interval=intervals, source_PCS_count=2+bool(slot),
            unpadded_RNE_group_bits=group_bits, RNE_group_bytes_with_frames=rne_wire,
            RNE_weighted_first_GKR=dict(version=2, separate_sumcheck_removed=True,
                removed_wire_bytes=sum(52+96*d for d in group_bits),
                removed_Fp3_rows=sum(1+3*d for d in group_bits),
                removed_quadratic_pair_iterations=separate_cells-len(group_bits),
                added_quadratic_pair_iterations=0,
                # Eight unchanged cubic layers: sum_l (N*2^l-1).
                baseline_cubic_pair_iterations=255*separate_cells-8*892,
                grouped_cubic_pair_iterations=255*separate_cells-8*len(group_bits),
                baseline_shared_core=baseline_rne_core, grouped_shared_core=grouped_rne_core,
                full_work_nonincrease_verified=False),
            RNE_separate_and_unpadded_byte_cells=separate_cells,
            rejected_two_group_padding_byte_cells=(1 << 34)+(1 << 33)-separate_cells,
            old_KV_bytes_copied=copied, rolling_A_live_bytes=live+copied,
            fits_D34=live+copied <= 1 << 34,
            # Refresh W as well, otherwise increasing the number of attempts
            # makes the initial pad budget (and mask wire) linear in that limit.
            # Reserve 128 bytes for working-root metadata, plus a fresh equality
            # MAC/frame and an extra PCS frame after the first response.
            rolling_W_and_KV_interval=[v-chosen[0]['wire']['wire_interval'][end]
                +(1+bool(slot))*rolling_w['wire']['wire_interval'][end]
                +128+36*bool(slot) for end, v in enumerate(intervals)],
            rolling_W_and_KV_PCS_count=2+2*bool(slot),
            full_prover_work=None, full_work_nonincrease_verified=False))
    return dict(credit=False, selected=False, complete_security_proven=False,
        canonical_valid_proof_bytes=None, hardware_credit=False,
        metric='one response, same pinned model and 100+50 tokens; O=0/150/300',
        baseline=old, candidate=chosen, rolling_W_candidate=rolling_w,
        search=dict(family_size=60, passing_PCS_prefix_screen=len(candidates),
            best_parameters={k:best[0][k] for k in ('queries','first','step')},
            best_two_PCS_upper=sum(p['wire']['wire_interval'][1] for p in best)),
        cases=cases, feasibility=feasibility(cases),
        shout_residual_screen=shout_residual_screen(current),
        retained_commit_work=retained_work(old, [rolling_w, chosen[1]]),
        joint_state=joint_state(old, rolling_w, chosen[1], cases),
        full_work_unresolved=['RNE weighted first-layer scheduling (extra sumcheck and padding removed)', 'rolling KV copy and link forms',
            'W refresh commitment, equality form and second W PCS; retained data IO',
            'all FFT/fold/hash/PCG work, setup, replay, serialization and off-H100 IO',
            'canonical physical schedule; array/butterfly proxies do not prove time dominance'],
        security_unresolved=['joint RNE FS/simulator', 'rolling-state FS link and same-W induction',
            'complete new ROM/PCG/private-sampler/reduction resource census'],
        lifetime='three attempts only; no security or growth admission for an unbounded run',
        bytes_scope='response body only; feasibility includes a verifier bootstrap lower bound and rejects the complete certificate caps')


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))

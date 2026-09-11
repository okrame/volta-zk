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
        initial_encoded_base_cells=initial_cells,
        initial_radix2_butterflies=initial_cells*(initial['domain_rows'].bit_length()-1)//2,
        fresh_encoded_extension_cells=sum(n*w for n, w in fresh),
        fresh_radix2_butterflies=sum(n*w*(n.bit_length()-1)//2 for n, w in fresh),
        PCS_max_coin_block_error=str(maximum),
        PCS_prefix_error=str((1 << 74)*maximum))


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
        rne_wire = sum(5056 + 1056*d + 6 for d in group_bits)
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
        cases=cases,
        full_work_unresolved=['RNE added sumcheck and scheduling (new padding removed)', 'rolling KV copy and link forms',
            'W refresh commitment, equality form and second W PCS; retained data IO',
            'all FFT/fold/hash/PCG work, setup, replay, serialization and off-H100 IO',
            'canonical physical schedule; array/butterfly proxies do not prove time dominance'],
        security_unresolved=['joint RNE FS/simulator', 'rolling-state FS link and same-W induction',
            'complete new ROM/PCG/private-sampler/reduction resource census'],
        lifetime='three attempts only; no security or growth admission for an unbounded run',
        bytes_scope='conditional full response wire envelope; offline bootstrap/setup counted separately and not measured')


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))

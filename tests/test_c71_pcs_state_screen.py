"""Small accounting and rolling-prefix identity check; no Gemma execution."""
import json
from pathlib import Path
import subprocess
import sys
from fractions import Fraction
from math import prod


def test_pcs_state_screen_counts_full_envelopes_and_keeps_work_unadmitted():
    root = Path(__file__).resolve().parents[1]
    r = json.loads(subprocess.check_output(
        [sys.executable, str(root/'scripts/c71_pcs_state_screen.py')], cwd=root, text=True))
    assert not r['credit'] and not r['selected'] and not r['complete_security_proven']
    assert r['canonical_valid_proof_bytes'] is None
    assert [c['source_PCS_count'] for c in r['cases']] == [2, 3, 3]
    assert [c['rolling_W_and_KV_PCS_count'] for c in r['cases']] == [2, 4, 4]
    assert r['cases'][0]['projected_complete_response_interval'][1] < 30_000_000
    for old, new in zip(r['baseline'], r['candidate']):
        assert new['ell'] > new['exposures']*new['queries']
        assert Fraction(new['PCS_prefix_error']) < Fraction(1, 1 << 87)
        assert not new['wire']['native_synthetic_codec_checked']
        assert new['wire']['wire_interval'][1] < old['wire']['wire_interval'][1]
        for cost in ('initial_encoded_base_cells', 'initial_radix2_butterflies',
                     'fresh_encoded_extension_cells', 'fresh_radix2_butterflies'):
            assert new[cost] < old[cost]  # geometry only, never full work
    for c in r['cases']:
        assert c['fits_D34'] and c['rolling_A_live_bytes'] <= 1 << 34
        assert c['full_prover_work'] is None and not c['full_work_nonincrease_verified']
        assert sum(1 << d for d in c['unpadded_RNE_group_bits']) == c['RNE_separate_and_unpadded_byte_cells']
        assert all(a < b for a, b in zip(c['rolling_W_and_KV_interval'], c['baseline_interval']))
        assert all(a < b for a, b in zip(c['projected_complete_response_interval'], c['baseline_interval']))

    work = r['retained_commit_work']
    assert not work['credit'] and not work['full_work_nonincrease_verified']
    for t, prefix in enumerate(work['prefixes'], 1):
        old, kept, rolling = (prefix[k] for k in
            ('baseline', 'same_protocol_retained', 'rolling_with_retention'))
        assert old['initial_commit_calls'] == [1+t, t+t*(t+1)//2]
        assert kept['initial_commit_calls'] == [1, t]
        assert rolling['initial_commit_calls'] == [t, t]
        assert kept['PCS_calls'] == old['PCS_calls']
        assert rolling['PCS_calls'] == [2*t-1, 2*t-1]
        assert kept['fresh_PCS_DFT_output_extension_cells'] == old['fresh_PCS_DFT_output_extension_cells']
        assert kept['power_covector_dot_terms'] == old['power_covector_dot_terms']
        # Current first-fold=6 candidate increases this real t*M kernel:
        # smaller DFTs alone must never be promoted to complete-work credit.
        assert rolling['power_covector_dot_terms'] > old['power_covector_dot_terms']
        for key in ('initial_DFT_output_base_cells', 'initial_radix2_butterfly_geometry',
                    'initial_salted_rows_created', 'initial_stored_digests_created', 'initial_private_pad_fp'):
            assert kept[key] < old[key] and rolling[key] < old[key]

    joint = r['joint_state']
    assert not joint['selected'] and not joint['complete_security_proven']
    assert joint['full_prover_work'] is None and not joint['full_work_nonincrease_verified']
    assert [c['source_PCS_count'] for c in joint['cases']] == [2, 2, 2]
    assert [c['complete_response_interval'][1] for c in joint['cases']] == [26653252, 28444684, 28444684]
    assert all(c['complete_response_interval'][1] < 30_000_000 for c in joint['cases'])
    # W is installed before the first prompt: its PCS must not disappear when
    # W is merged into the first state root. A new root alone is insufficient.
    assert joint['installed_W']['exposures'] == 1 and joint['state']['exposures'] == 2
    assert joint['cases'][0]['installed_W_PCS_included']
    assert all(c['explicit_zero_quarter_cells'] == 1 << 34 for c in joint['cases'])
    for t, prefix in enumerate(joint['prefixes'], 1):
        old, new = prefix['baseline'], prefix['joint']
        assert new['initial_commit_calls'] == [1, t]
        assert new['PCS_calls'] == [1, 2*t-1]
        for cost in ('initial_encoded_base_cells', 'initial_radix2_butterflies',
                     'fresh_encoded_extension_cells', 'fresh_radix2_butterflies',
                     'power_covector_dot_terms'):
            assert new[cost] < old[cost]
        assert new['initial_sumcheck_source_cells'] > old['initial_sumcheck_source_cells']
        assert not prefix['full_work_nonincrease_verified']

    # Prefix equality must cover every old cell, including the final accepted K.
    # On a Boolean point eq selects precisely that cell; any single alteration
    # produces a nonzero multilinear difference. Padding is part of the layout.
    p, delta = 101, 19
    old = [3, 5, 7, 11, 13, 17]
    new = old + [23, 29]
    tags = [31+i for i in range(8)]
    for fault in range(len(old)):
        bad = new.copy()
        bad[fault] += 1
        point = [(fault >> i) & 1 for i in (2, 1, 0)]
        weights = []
        for index in range(8):
            w = 1
            for bit, challenge in zip((2, 1, 0), point):
                w = w * (challenge if index >> bit & 1 else 1-challenge) % p
            weights.append(w)
        source = old + [0, 0]
        key = sum(w*(m+delta*x) for w, m, x in zip(weights, tags, source)) % p
        assert (key - sum(w*m for w, m in zip(weights, tags))
                - delta*sum(w*x for w, x in zip(weights, source))) % p == 0
        assert sum(w*(x-y) for w, x, y in zip(weights[:6], old, bad)) % p != 0


def test_joint_root_rebases_original_forms_and_checks_installation_kv_and_padding():
    # Finite algebra check of the proposed routing, NOT a PCS/FS composition test.
    p, delta = 101, 19
    w = [3, -5, 7, 11, 13, 17, 19, 23]
    a0 = [29, 31, 37, 41]
    a1 = [29, 31, 43, 47]  # first two cells are accepted KV, including its tail
    s0, s1 = w+a0+[0]*4, w+a1+[0]*4

    def eq(point):
        return [prod(
            (r if i >> (len(point)-1-j) & 1 else 1-r
             for j, r in enumerate(point))) % p for i in range(1 << len(point))]

    def dot(x, y):
        assert len(x) == len(y)
        return sum(a*b for a, b in zip(x, y)) % p

    # Rebase cubes, retaining the SAME authenticated target/key for both roots.
    for original, offset, point in [(w, 0, [2, 3, 5]), (a0, 8, [7, 11])]:
        form = eq(point)
        merged = [0]*16
        merged[offset:offset+len(form)] = form
        value = dot(original, form)
        tag = 53
        key = (tag+delta*value) % p
        assert dot(s0, merged) == value
        assert (key-tag-delta*dot(s0, merged)) % p == 0
        # An incorrect offset must not silently retarget the original MAC.
        shifted = merged[1:]+merged[:1]
        assert (key-tag-delta*dot(s0, shifted)) % p != 0

    # Every W cell needs the installation link even on the first response.
    # Later links also cover the final accepted KV cell; suffix zero is separate.
    for cell in range(16):
        bad = s1.copy()
        bad[cell] += 1
        if cell < 8:
            assert bad[cell] != w[cell] and s0[cell] == w[cell]
        elif cell < 10:
            assert bad[cell] != s0[cell]
        elif cell >= 12:
            point = [(cell-12) >> 1, (cell-12) & 1]
            assert dot(bad[12:], eq(point)) != 0
        else:
            # Current auxiliary cells are constrained by inference/range,
            # not by equality with the previous response.
            assert s1[cell] != s0[cell]

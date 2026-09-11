"""Small accounting and rolling-prefix identity check; no Gemma execution."""
import json
from pathlib import Path
import subprocess
import sys
from fractions import Fraction


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

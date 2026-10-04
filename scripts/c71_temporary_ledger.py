#!/usr/bin/env python3
"""Reconcile allocation-site geometry and reduced allocator evidence; no GPU/run credit."""
import argparse
import json
from pathlib import Path


def records(directory, marker):
    found = []
    for path in sorted(directory.glob('*.log')):
        for line in path.read_text(errors='replace').splitlines():
            if marker + ' ' in line:
                record = json.loads(line.split(marker + ' ', 1)[1])
                if record not in found:
                    found.append(record)
    return found


def ledger(directory):
    device = records(directory, 'C71_DEVICE_ALLOCATION_GEOMETRY')
    pcs = records(directory, 'C71_PCS_ALLOCATION_GEOMETRY')
    measured = records(directory, 'C71_TEMPORARY_ALLOCATIONS')
    seed6 = records(directory, 'C71_SEED6_NATIVE')
    claims = records(directory, 'C71_CLAIM_ALLOCATION_GEOMETRY')
    stages = records(directory, 'C71_PCS_CHAIN_STAGE')
    if {row['old_tokens'] for row in device} != {0, 150, 300} or not pcs or len(measured) < 2 or not seed6 or not claims or not stages:
        raise ValueError('missing production-shape or reduced allocation evidence')
    assert any(row['OS_rng'] and row['accepted_attempts'] == 1 for row in seed6)
    limit = 6_442_450_944
    allowance = margin = 256 << 20
    payload = limit - allowance - margin
    for row in measured:
        assert row['payload_limit_bytes'] == payload
        assert row['runtime_allowance_bytes'] == allowance
        assert row['temporary_payload_peak_bytes'] <= payload
        assert row['denied_allocations'] == 0 and row['enforced']
    device_upper = max(row['replay_upper_bytes_including_persistent'] for row in device)
    roots = sum(next(row['retained_root_and_salt_offset_bytes'] for row in pcs
                     if row['height'] == height and row['columns'] == 128)
                for height in [1 << 32, 1 << 31, 1 << 31, 1 << 31])
    initial = []
    for row in pcs:
        if row['columns'] != 128:
            continue
        # Conservative: even W installation is charged the final three A roots
        # and complete replay state. Pending cosets and retained Vec capacities
        # are already included by the production geometry emission.
        parts = {key: row[key] for key in (
            'pending_and_current_coset_capacity_bytes', 'frontier_capacity_bytes',
            'salt_cursors_capacity_bytes', 'fft_column_and_twiddle_upper_bytes')}
        parts['all_initial_roots_and_salt_offsets'] = roots
        parts['device_replay_including_persistent'] = device_upper
        parts['all_initial_private_pads'] = 4 * 1536 * 128 * 8
        parts['two_public_table_payloads'] = 2 * 23_954_072
        parts['public_padding_host_upper'] = 106 * 262144 * 2
        subtotal = sum(parts.values())
        assert subtotal < payload
        initial.append({'height': row['height'], 'parts': parts,
                        'named_allocation_subtotal_bytes': subtotal,
                        'remaining_shared_payload_capacity_bytes': payload - subtotal,
                        'is_complete_phase_peak': False})
    claim = claims[0]
    assert claim['construction_capacity_released']
    claim_bytes = {d: claim['max_cubes_per_root'] * (claim['cube_bytes'] + d * claim['field_bytes'])
                  + claim['max_targets_per_root'] * (claim['vector_bytes'] + claim['auth_bytes'])
                  for d in (34, 35)}
    # These cross-checks are envelopes of explicitly named live allocations,
    # not an invented fixed slot for the rest of the process. ALL remaining
    # allocations share the same enforced counter, including Seed6 and GKR.
    phases = []

    def phase(name, parts):
        subtotal = sum(parts.values())
        assert subtotal < payload, (name, subtotal)
        phases.append({'phase': name, 'parts': parts,
                       'named_allocation_subtotal_bytes': subtotal,
                       'remaining_shared_payload_capacity_bytes': payload - subtotal,
                       'is_complete_phase_peak': False})

    persistent = max(row['persistent_device_bytes'] for row in device)
    by_height = {row['height']: row for row in pcs}
    common = {'initial_roots_and_salt_offsets': roots,
              'initial_private_pads': 4 * 1536 * 128 * 8,
              'two_public_table_payloads': 2 * 23_954_072,
              'certificate_capacity_upper': 128 << 20,
              'public_padding_host_upper': 106 * 262144 * 2}
    previous = {}
    for stage in sorted(stages, key=lambda r: (r['dimension'], r['round'])):
        d, n, h = stage['dimension'], stage['round'], stage['height']
        row = by_height[h]
        before = previous.get(d, by_height[1 << (d - 3)])
        cache = row['retained_root_and_salt_offset_bytes']
        if before['columns'] != 128:
            cache += before['retained_root_and_salt_offset_bytes']
        retained = stage['retained_capacity_at_commit_bytes']
        # W closes first with both batches; A closes after W batch release.
        originals = claim_bytes[34] + (claim_bytes[35] if d == 35 else 0)
        base = dict(common, original_claims_at_codec_maximum=originals,
                    extension_roots_and_offsets=cache, retained_S1_capacity=retained)
        commit = {key: row[key] for key in (
            'pending_and_current_coset_capacity_bytes', 'frontier_capacity_bytes',
            'salt_cursors_capacity_bytes', 'fft_column_and_twiddle_upper_bytes')}
        phase(f'D{d}_S{n+1}_commit', dict(base, **commit,
              device_with_replay=device_upper if d == 34 and n == 0 else persistent))
        if before:
            # 32 base words/query bounds the current polynomial/remainder
            # buffers, growing FFT tables and index/point arrays after flattening.
            # The full retained state and both root caches are still charged.
            phase(f'D{d}_S{n}_open_before_release', dict(base,
                  query_matrix=before['query_matrix_capacity_bytes'],
                  query_factors=before['query_factor_capacity_bytes'],
                  query_transients_and_twiddles_upper=32 * before['query_batch_rows'] * 8,
                  query_byte_host_and_device_staging=(2 << 28) if d == 34 and n == 0 else 0,
                  device_with_replay=device_upper if d == 34 and n == 0 else persistent))
        previous[d] = row
    phase('range_A_deep_retention', dict(common,
          both_original_claim_batches=claim_bytes[34]+claim_bytes[35],
          children=96 * (1 << 24), byte_window=1 << 30,
          device_including_replay=device_upper))
    phase('RMS_compact_checkpoint', dict(common,
          both_original_claim_batches=claim_bytes[34]+claim_bytes[35],
          compact_checkpoint_with_descriptors=2_023_511_878,
          device_including_replay=device_upper))
    return {
        'credit': False, 'gpu_execution': False, 'canonical_execution': False,
        'temporary_limit_bytes': limit,
        'enforced_joint_allocation_limit_bytes': payload,
        'runtime_allocator_stack_driver_allowance_bytes': allowance,
        'analytical_admission_ceiling_bytes': payload + allowance,
        'margin_bytes': margin,
        'allowance_physically_verified': False,
        'scope': 'all Rust allocations on both roles plus native owner and aligned CUDA buffers; only immutable packed W payload excluded; retained capacities and moving realloc old+new charged',
        'non_payload_scope': 'glibc retained small chunks, mapping rounding, stack, socket buffers, CUDA context/runtime/kernel stack and allocator bookkeeping must jointly fit the explicit allowance',
        'counter_authority': 'rust/volta-pcs/src/c71_matrix/census.rs and cuda/c71_range_runtime.cpp; sampling does not replace allocation-time high-water accounting',
        'device_shapes': device, 'pcs_shapes': pcs,
        'initial_commit_named_crosscheck': initial,
        'other_phase_named_crosschecks': phases, 'claim_allocation_geometry': claims,
        'crosscheck_scope': 'named allocations plus worst permitted claim batches; the remaining capacity is NOT an omitted/free slot, it is shared by every other allocation through the counter',
        'reduced_simultaneous_allocations': measured, 'real_seed6_reduced': seed6,
        'canonical_success_inferred_from_guard': False,
        'remaining_physical_checks': [
            'complete canonical O=0/150/300 on H100, no rejected allocation, no spill, successful verification and promotion',
            'simultaneous host/device physical residency including non-payload overhead <= admission ceiling; overhead <= allowance, free margin >= 256 MiB',
            'CUDA parity, fences/cleanup and HBM residency; complete wall/CPU time and traffic, including grouped-coset arithmetic'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', type=Path)
    args = parser.parse_args()
    print(json.dumps(ledger(args.logs), indent=2, sort_keys=True))

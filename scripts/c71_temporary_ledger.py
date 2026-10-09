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


def ledger_legacy(directory):
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


def aligned(n):
    return (n + 255) & ~255


def residual_packet(prefix_bits, pad_count=0):
    """native_packet's eight-bit EQ chunks; host Vec growth is an upper."""
    chunks = (prefix_bits + 7) // 8
    entries = sum(1 << min(8, prefix_bits - bit) for bit in range(0, prefix_bits, 8))
    return {'device': aligned(32) + aligned(16 * chunks) + aligned(24 * entries) + aligned(24 * pad_count),
            'host_upper': 80 + 16 * chunks + 48 * entries,
            'eq_entries': entries, 'eq_chunks': chunks}


def extension_query_parts(q, prefix_bits):
    """Exact buffer counts, including each CUDA allocation's 256-byte alignment."""
    levels = q.bit_length()
    packet = residual_packet(prefix_bits, 4 * 512)
    return {
        'E_public_factor_spectra': 2 * levels * aligned(16 * q),
        'E_forward_inverse_twiddles': 2 * sum(aligned(16 * (1 << level)) for level in range(levels)),
        'E_private_three_limb_low': aligned(24 * q),
        'E_four_remainders': 4 * aligned(8 * q),
        'E_work_and_scratch': 2 * aligned(16 * q),
        'E_private_shape_EQ_and_pads': packet['device'],
        'E_private_sticky_flag': aligned(4),
        'E_Rust_EQ_packet_host_upper': packet['host_upper'],
        'E_Rust_pad_marshalling_host_upper': 2 * 4 * 512 * 24,
        'E_returned_matrix_host': 96 * q,
        'E_Rust_column_host': 24 * q,
        'E_C_staged_column_host': 24 * q,
    }


def native_residual_phases(dimension, stages, extensions, initial, common, add, caches):
    previous = initial[1 << (dimension - 3)]
    previous_remaining = None
    for stage in sorted((s for s in stages if s['dimension'] == dimension), key=lambda s: s['round']):
        round_no, height = stage['round'], stage['height']
        row = extensions[height]
        if row['columns'] != 12:
            raise ValueError('native residual stage requires four E columns')
        rows = min(row['coset_rows'], height // 2)
        cosets, groups = height // rows, height // rows // 2
        if rows < 4 or rows > 1 << 23 or cosets < 2 or cosets & (cosets - 1):
            raise ValueError('native group2 geometry differs')
        remaining = dimension - 7 - 2 * round_no
        message_rows = 1 << (remaining - 2)
        # Original W view has every challenge prefix; A S1 uses seven, then
        # only a virtual two-fold prefix over retained planes.
        prefix_bits = dimension - remaining if dimension == 35 else (7 if round_no == 0 else 2)
        packet = residual_packet(prefix_bits, 4 * 512)
        cache = row['retained_root_and_salt_offset_bytes']
        adjacent_cache = cache + (previous['retained_root_and_salt_offset_bytes'] if previous['columns'] != 128 else 0)
        base = dict(common(caches, proof=True, w_closure=dimension == 35),
                    extension_previous_and_current_root_offset_caches=adjacent_cache,
                    extension_previous_and_current_host_pads=4 * 512 * 24 * (2 if previous['columns'] != 128 else 1),
                    retained_predecessor=stage['retained_capacity_at_commit_bytes'])
        if dimension == 35:
            base['sealed_W_mapping_device'] = aligned(3156 * 40)
        current_host = rows * 8
        cut = 4096 if height > (1 << 18) else max(16, height // row['coset_rows'])
        salt_meta = aligned(168)
        band = aligned(32 * min(65536, rows))
        frontier = aligned((groups.bit_length() - 1) * rows * 32)
        capacity = min(1 << 24, max(8, 4 * height))
        candidates = capacity // 8 + 1
        prescan_scratch = (aligned(candidates) + aligned(4 * candidates)
                           + aligned(4 * ((candidates + 255) // 256))
                           + aligned(4 * ((candidates + 65535) // 65536)))
        name = f'native_E_D{dimension}_A{caches}_S{round_no + 1}'
        add(name + '_salt_prescan', dict(base, salt_meta=salt_meta,
            salt_current_device=aligned(8 * rows), salt_current_host=current_host,
            salt_prescan_scratch=prescan_scratch, salt_subtree_offsets_device=aligned(8 * height // cut)),
            'Prescan scratch/device offsets retire before ring/frontier allocation. Current cursor/meta stay for hashing. '
            'The current cache is conservatively charged before its top digests are constructed.')
        shared = {'E_frontier_group2': frontier, 'E_salt_current_device': aligned(8 * rows),
                  'E_salt_current_host': current_host, 'E_salt_meta': salt_meta,
                  'E_original_to_C_pad_marshalling_host_upper': 2 * 4 * 512 * 24}
        high_rows = (message_rows + 512 + rows - 1) // rows
        add(name + '_FFT', dict(base, **shared, E_ring24R=aligned(192 * rows),
            E_low_powers=aligned(16 * rows), E_high_powers=aligned(16 * high_rows),
            E_transpose_scratch=aligned(8 * rows), E_forward_twiddles=aligned(8 * rows),
            E_EQ_shape_chunks_tables_pads=packet['device'], E_sticky_flag=aligned(4),
            E_EQ_packet_host_upper=packet['host_upper'], E_reused_salt_band=band if groups > 1 else 0),
            'All stages use R=min(CPU R,H/2), paired cosets. One scratch/twiddle for24 serial base columns. '
            'A S1 remains original; later stages read retained planes. No extra A reconstruction.')
        add(name + '_hash', dict(base, **shared, E_ring24R=aligned(192 * rows),
            E_paired_hash_states_R=aligned(32 * rows), E_hash_flag=aligned(4), E_salt_band=band),
            'EQ/pad device packet and powers/FFT auxiliaries retire before hash. Two lanes publish R paired roots; '
            'the ring retires before further node outputs, preserving original salts and order.')
        add(name + '_nodes', dict(base, E_frontier_group2=frontier, E_roots_and_next_node_output=aligned(32 * rows) + aligned(16 * rows),
            E_salt_current_host=current_host, E_pad_marshalling_host_upper=2 * 4 * 512 * 24),
            'Upper of final reductions after ring/salt retirement; top cache is already conservatively charged.')
        if previous['columns'] == 128:
            if dimension == 35:
                add(name + '_initial_W_CPU_query_gap', dict(base,
                    query_matrix=previous['query_matrix_capacity_bytes'], query_factors=previous['query_factor_capacity_bytes'],
                    query_transients_and_twiddles_upper=32 * previous['query_batch_rows'] * 8),
                    'Original W query stays CPU. This is an explicit unaccelerated path, with no new W retention.')
        else:
            q = previous['query_batch_rows']
            query_prefix = dimension - previous_remaining if dimension == 35 else 2
            parts = extension_query_parts(q, query_prefix)
            add(name + '_predecessor_E_query_publication', dict(base, **parts),
                'One source loader for all3 limbs;4 remainder buffers, no original getter/D2H. '
                '96q matrix+24q Rust column+24q C staging overlap until canonical check/free/publication. '
                'Both adjacent caches and predecessor planes stay alive through opening/release.')
            construction = {key: parts[key] for key in ('E_public_factor_spectra', 'E_forward_inverse_twiddles')}
            add(name + '_predecessor_E_public_factor_construction', dict(base, **construction,
                public_points=8 * q, current_polynomial_level_upper=16 * q,
                current_inverse_modulus_spectra=32 * q, one_upload_conversion=16 * q),
                'CPU query_tree_with/DFT construction is a preceding lifetime; matrix/private low/work not allocated yet. '
                'Reverse/inverse-series/multiply/DFT caches and Vec growth remain explicitly unquantified additional classes.')
        if dimension == 34:
            if round_no == 0:
                retain_packet = residual_packet(7)
                add(name + '_late_retention', dict(common(caches, proof=True),
                    current_extension_cache=cache, current_extension_host_pads=4 * 512 * 24,
                    retained_three_planes=3 * aligned(8 * (1 << 27)),
                    retention_EQ_packet=retain_packet['device'], retention_EQ_host_upper=retain_packet['host_upper'], retention_flag=aligned(4)),
                    'Exactly once after original A query/lease release; original query scratch is retired. No host duplicate S1.')
            else:
                add(name + '_promotion', dict(common(caches, proof=True), current_extension_cache=cache,
                    current_extension_host_pads=4 * 512 * 24,
                    predecessor_three_planes=stage['retained_capacity_at_commit_bytes'],
                    successor_three_planes=3 * aligned(8 * (1 << remaining)), fold_flag=aligned(4)),
                    'Old+new planes coexist through successful fold/fence/typed retirement; previous cache already released.')
        previous, previous_remaining = row, remaining
    if previous_remaining is not None:
        q = previous['query_batch_rows']
        prefix = dimension - previous_remaining if dimension == 35 else 2
        final = dict(common(caches, proof=True, w_closure=dimension == 35),
                     current_extension_cache=previous['retained_root_and_salt_offset_bytes'],
                     current_extension_host_pads=4 * 512 * 24,
                     retained_three_planes=(3 * aligned(8 * (1 << previous_remaining)) if dimension == 34 else 0))
        if dimension == 35:
            final['sealed_W_mapping_device'] = aligned(3156 * 40)
        add(f'native_E_D{dimension}_A{caches}_final_source_open', dict(final, **extension_query_parts(q, prefix)),
            'Last selected extension also uses native E query; fresh base-case mask/main caches, CPU proof vectors '
            'and already opened paths remain separate additional classes, never silently treated as absent.')
        parts = extension_query_parts(q, prefix)
        add(f'native_E_D{dimension}_A{caches}_final_public_factor_construction', dict(final,
            E_public_factor_spectra=parts['E_public_factor_spectra'], E_forward_inverse_twiddles=parts['E_forward_inverse_twiddles'],
            public_points=8 * q, current_polynomial_level_upper=16 * q,
            current_inverse_modulus_spectra=32 * q, one_upload_conversion=16 * q),
            'Final query construction has the same preceding lifetime and explicit additional CPU temporaries.')


def ledger_native(directory, query_record, linear_record, proposed_s1=False, lifetime_record=None):
    """Source-derived named screens. Missing capacity classes stay explicit.

    This path neither calls legacy fit assertions nor treats the remaining
    payload as a fixed allowance for unlisted owners. It does not change the
    existing census/formal limits or immutable historical results.
    """
    payload, allowance, margin = 5_905_580_032, 256 << 20, 256 << 20
    device = records(directory, 'C71_DEVICE_ALLOCATION_GEOMETRY')
    pcs = records(directory, 'C71_PCS_ALLOCATION_GEOMETRY')
    claims = records(directory, 'C71_CLAIM_ALLOCATION_GEOMETRY')
    stages = records(directory, 'C71_PCS_CHAIN_STAGE')
    measured = records(directory, 'C71_TEMPORARY_ALLOCATIONS')
    w = records(directory, 'C71_NATIVE_W_RESOURCE_ENVELOPE')
    a = records(directory, 'C71_NATIVE_A_RESOURCE_ENVELOPE')
    if ({row['old_tokens'] for row in device} != {0, 150, 300} or not pcs
            or len(claims) != 1 or not stages or len(measured) < 2 or len(w) != 1 or len(a) != 1):
        raise ValueError('missing current native geometry and joint reduced evidence')
    seed = records(directory, 'C71_SEED6_NATIVE')
    if not any(row['OS_rng'] and row['accepted_attempts'] == 1 for row in seed):
        raise ValueError('missing real AES Seed6 evidence')
    for row in measured:
        if (row['payload_limit_bytes'] != payload or row['runtime_allowance_bytes'] != allowance
                or not row['enforced'] or row['denied_allocations'] or row['temporary_payload_peak_bytes'] > payload):
            raise ValueError('incompatible or failed reduced joint allocation evidence')
    qdoc, ldoc = json.loads(query_record.read_text()), json.loads(linear_record.read_text())
    if qdoc['git_dirty'] or ldoc['git_dirty']:
        raise ValueError('native component record requires clean-source provenance')
    q, linear = qdoc['accounting'], ldoc['accounting']
    lifetime_doc = None
    released_w = False
    if lifetime_record is not None:
        lifetime_doc = json.loads(lifetime_record.read_text())
        if (lifetime_doc['git_dirty'] or not lifetime_doc.get('source_git_sha')
                or lifetime_doc['accounting'].get('W_claims_and_proof_released_before_A') is not True):
            raise ValueError('separate clean-source W retirement receipt required')
        released_w = True
    w, a = w[0], a[0]
    owner = linear['owner_host_bytes']
    owner_observations = []
    if proposed_s1:
        if not released_w:
            raise ValueError('S1+E screen requires the separate clean96b69de retirement receipt')
        for marker in ('C71_NATIVE_RESIDUAL_STATE_COMPONENT', 'C71_NATIVE_RESIDUAL_TREE_COMPONENT',
                       'C71_NATIVE_QUERY_E_HORNER', 'C71_NATIVE_RESIDUAL_QUERY_FULL_WIRE',
                       'C71_NATIVE_RESIDUAL_QUERY_A_CHAIN', 'C71_NATIVE_RESIDUAL_QUERY_W_CHAIN'):
            for row in records(directory, marker):
                native = row.get('native', {})
                if native.get('host_owner_bytes'):
                    owner_observations.append({'marker': marker, 'bytes': native['host_owner_bytes']})
        if not owner_observations:
            raise ValueError('missing current S1/query common-owner host bytes; old LINEAR sizeofCtx cannot substitute')
        owner = max(item['bytes'] for item in owner_observations)
    replay = max(row['replay_upper_bytes_including_persistent'] for row in device)
    persistent = max(row['persistent_device_bytes'] for row in device)
    c = claims[0]
    claim = {d: c['max_cubes_per_root']*(c['cube_bytes']+d*c['field_bytes'])
             + c['max_targets_per_root']*(c['vector_bytes']+c['auth_bytes']) for d in (34, 35)}
    initial = {row['height']: row for row in pcs if row['columns'] == 128}
    extensions = {row['height']: row for row in pcs if row['columns'] != 128}
    if set(initial) != {1 << 31, 1 << 32}:
        raise ValueError('initial canonical geometry differs')
    roots_w = initial[1 << 32]['retained_root_and_salt_offset_bytes']
    roots_a = initial[1 << 31]['retained_root_and_salt_offset_bytes']
    pad = 1536*128*8
    # Closed inventory, not a fungible/free slot. Actual capacities and moving
    # realloc overlaps of each class still need a complete canonical census.
    additional = [
        'profile/layout/tile/source/Arc/lock/vector descriptors and public quantization tables beyond named payloads',
        'public query product construction/conversion/reverse/inverse-series/DFT cache during construction',
        'opened rows/salts/pruned paths/index arrays from previous batches; current regeneration is a separate lifetime',
        'AES PCG and fresh VOLE/correlations/masks/journals on both roles',
        'Writer/MatrixProof/codec/receive/send frame capacities and old+new reallocations',
        'GKR/RMS/EXP30/lookup/range and contractions outside the explicitly named replay envelope',
        'sourcewise EQ/adaptive PowerBlocks/denominators/numerator/inverse spectra and host contraction bands',
        'historical endpoint forms/targets/coefficient vectors and public linear marshalling descriptors',
        'common-owner metadata/reservations/flags and producer temporaries not included by the named component',
        'sourcewise last bounded <=128E read: consumed temporary three-plane buffer, EQ packet, flag, Rust result and CPU fresh base-case polynomials',
        'fresh base-case main/mask caches and their private randomness, adjacent to final selected extension query',
    ]
    phases = []

    def add(name, parts, lifetime):
        total = sum(parts.values())
        phases.append({'phase': name, 'parts': parts, 'named_allocation_subtotal_bytes': total,
                       'remaining_shared_payload_capacity_bytes': payload-total,
                       'named_subtotal_exceeds_payload': total > payload,
                       'is_complete_phase_peak': False, 'lifetime': lifetime})

    def common(caches, proof=False, numeric=True, w_closure=False):
        result = {'initial_W_and_A_root_offset_caches': roots_w+caches*roots_a,
                  'retained_initial_private_host_pads': (1+caches)*pad,
                  'two_public_table_host_payloads': 2*23_954_072,
                  'native_common_owner_host': owner}
        if numeric:
            result['device_persistent_or_single_replay_envelope'] = replay
        if proposed_s1:
            result['original_W_tile_descriptors_host_upper'] = 2 * 3156 * 40
            result['public_padding_host_upper'] = 106 * 262144 * 2
            result['full_calibration_table_serialization_difference_upper'] = 2 * (24_414_870 - 23_954_072)
        if proof:
            # Clean3128038 predates explicit bw/W proof drops. The separate
            # optional retirement receipt binds this fact; LINEAR immutable.
            result['original_claim_batch_codec_upper'] = claim[34]+(
                claim[35] if w_closure or not released_w else 0)
        return result

    add('native_initial_W_install', dict(common(0, numeric=False),
        **{f'W_{key}': value for key, value in w['device_parts'].items()},
        host_row_cursors=w['rows']*8, host_weight_tiles=3156*40),
        'Only W cache/pads; no future A caches or proof claim batches. Upload staging is a separate earlier lifetime.')
    for caches in (1, 2, 3):
        base = dict(common(caches), host_row_cursors=a['rows']*8, host_byte_histogram=256*8)
        parts = a['common_device_parts']
        named = sum(parts.values())
        add(f'native_initial_A{caches}_accumulate', dict(base, **{f'A_{key}': value for key, value in parts.items()},
            A_accumulation_additional=a['device_accumulation_phase_bytes']-named),
            'W plus A1..current cache/pads; one replay envelope including persistent; no original proof batches yet.')
        add(f'native_initial_A{caches}_hash', dict(base, **{f'A_{key}': value for key, value in parts.items()},
            A_hash_additional=a['device_hash_phase_bytes']-named),
            'Low/high powers retired before full hash output; values retire before first node output.')
        add(f'native_initial_A{caches}_query_evaluate', dict(common(caches, proof=True),
            **{f'query_device_{key}': value for key, value in q['canonical_query_device_breakdown'].items()},
            gather_flag=q['additional_original_gather_flag_aligned_bytes'],
            returned_matrix_host=q['returned_matrix_host_bytes'],
            returned_column_host=q['returned_column_staging_host_bytes']),
            'Public construction/CPU DFT owner retired; device factors/work/window retire before current Tree regeneration. '
            'Previously opened batches and W proof/claims stay live. Initial S1 retention is still zero.')
        # Native packet is dropped after the fenced upload, before producer
        # scans. Its host construction bound must not be summed with a scan.
        device_packet = linear['Rust_conservative_named_aligned_packet_output_flag_bytes']
        max_cubes, max_points = c['max_cubes_per_root'], linear['Rust_max_residual_points']
        host_packet = 152+5*16+1280*24+35*16+64*max_cubes+24*max_points
        prefix_capacity = 24+5*32+1280*24
        public_capacity = 24+35*32+2*max_cubes*72
        host_prepare = host_packet+2*(prefix_capacity+public_capacity)+35*24
        add(f'native_linear_A{caches}_host_prepare', dict(common(caches, proof=True),
            linear_host_packet_and_marshalling_bound=host_prepare),
            'Borrowed public descriptors/PREFIX EQ coexist with host packet; device packet not uploaded yet.')
        add(f'native_linear_A{caches}_upload', dict(common(caches, proof=True),
            linear_host_packet_payload=host_packet, linear_device_packet_output_flag=device_packet),
            'Public marshalling temporaries returned/dropped; canonical host packet stays alive until begin fence.')
        add(f'native_linear_A{caches}_scan', dict(common(caches, proof=True),
            linear_device_packet_output_flag=device_packet),
            'Host packet retired before A producer scan; exactly one original scan per each of34 rounds. '
            'W35 uses the same phase geometry plus its once-per-proof sealed mapping.')
        w_base = common(caches, proof=True, w_closure=True)
        add(f'native_linear_W_with_A{caches}_host_prepare', dict(w_base,
            linear_host_packet_and_marshalling_bound=host_prepare, sealed_W_mapping_device=126464),
            'First closure: both original batches live. Mapping loads once per proof; public host preparation precedes upload.')
        add(f'native_linear_W_with_A{caches}_upload', dict(w_base,
            linear_host_packet_payload=host_packet, linear_device_packet_output_flag=device_packet,
            sealed_W_mapping_device=126464), 'Both batches; packet and device copy coexist until upload fence.')
        add(f'native_linear_W_with_A{caches}_scan', dict(w_base,
            linear_device_packet_output_flag=device_packet, sealed_W_mapping_device=126464),
            'Host packet retired before exactly35 W scans; both original batches remain live through closeW.')
        for dimension in (35, 34):
            if proposed_s1:
                native_residual_phases(dimension, stages, extensions, initial, common, add, caches)
                continue
            previous = initial[1 << (dimension-3)]
            for stage in sorted((s for s in stages if s['dimension'] == dimension), key=lambda s: s['round']):
                row = extensions[stage['height']]
                extension_cache = row['retained_root_and_salt_offset_bytes']
                if previous['columns'] != 128:
                    extension_cache += previous['retained_root_and_salt_offset_bytes']
                base = dict(common(caches, proof=True, w_closure=dimension == 35),
                            extension_previous_and_current_root_offset_caches=extension_cache,
                            retained_predecessor=stage['retained_capacity_at_commit_bytes'])
                round_no, rows, cosets = stage['round'], row['coset_rows'], stage['height']//row['coset_rows']
                add(f'CPU_D{dimension}_A{caches}_S{round_no+1}_commit', dict(base,
                    **{key: row[key] for key in ('pending_and_current_coset_capacity_bytes',
                        'frontier_capacity_bytes', 'salt_cursors_capacity_bytes', 'fft_column_and_twiddle_upper_bytes')}),
                    'CPU implementation retained in the native initial-only profile.')
                # Initial A native query phases above replace that legacy
                # case. Current W and all extension queries still use CPU.
                # A prepared resident S1 cannot silently fall back to these
                # host queries; its loader/lifetime must be audited separately.
                if previous['columns'] != 128 or dimension == 35:
                    query_parts = dict(base,
                        query_matrix=previous['query_matrix_capacity_bytes'],
                        query_factors=previous['query_factor_capacity_bytes'],
                        query_transients_and_twiddles_upper=32*previous['query_batch_rows']*8)
                    add(f'CPU_D{dimension}_A{caches}_S{round_no}_open', query_parts,
                        'Both adjacent caches and predecessor retained generation stay live until opening/release. '
                        'One current returned matrix plus previously opened rows/salts/paths; regeneration/copy is a later lifetime.')
                previous = row
        if not proposed_s1:
            add(f'A{caches}_S1_retention_after_initial_open_release', dict(common(caches, proof=True),
                retained_device_three_planes=24*(1 << 27)),
                'S1 allocated once only after original opening and lease release. No initial query scratch or host duplicate S1.')
            add(f'A{caches}_S1_promote_after_S1_open_release', dict(common(caches, proof=True),
                predecessor_three_planes=24*(1 << 27), successor_three_planes=24*(1 << 25), fold_flag=256),
                'Old and new generations remain charged through successful out-of-place fold/fence, then predecessor retires. '
                'CPU shrink also has a possible old+new overlap; powers for the preceding two folds already retired.')
    return {'backend': 's1-prepared' if proposed_s1 else 'native-2026-10-09',
            'credit': False, 'gpu_execution': False, 'canonical_execution': False,
            'enforced_joint_allocation_limit_bytes': payload,
            'runtime_allocator_stack_driver_allowance_bytes': allowance, 'margin_bytes': margin,
            'allowance_physically_verified': False, 'complete_joint_phase_peak': False,
            'named_phase_crosschecks': phases, 'additional_capacity_classes_requiring_complete_census': additional,
            'empty_fixed_allowance_for_other_payload': False,
            'component_record_sources': {'query': str(query_record), 'linear': str(linear_record),
                'query_source_sha': qdoc['source_git_sha'], 'linear_source_sha': ldoc['source_git_sha'],
                'lifetime': str(lifetime_record) if lifetime_record is not None else None,
                'lifetime_source_sha': lifetime_doc['source_git_sha'] if lifetime_doc is not None else None},
            'prepared_S1_is_selected_in_canonical_runner': proposed_s1,
            'S1_query_E_all_selected_extension_stages_modeled': proposed_s1,
            'current_owner_host_byte_observations': owner_observations,
            'additional_explicit_component_caps': {
                'residual_dim35_EQ_packet_device': residual_packet(35)['device'],
                'residual_dim35_EQ_packet_host_upper': residual_packet(35)['host_upper'],
                'PCS_E_contraction_public_device_band_max': aligned(48 * (1 << 21)),
                'PCS_E_contraction_result_flag': aligned(48) + aligned(4),
                'PCS_E_round_covector_host_named_upper_excluding_PowerBlocks': 120 * (1 << 21),
                'PCS_E_OOD_power_tables_remaining28_device': 2 * aligned(24 * (1 << 14)),
                'PCS_E_singleton_device_result': aligned(24 * 128),
                'PCS_E_bounded_final_temporary_planes': 3 * aligned(8 * 128),
                'PCS_E_bounded_final_Rust_output': 24 * 128,
            } if proposed_s1 else {},
            'unquantified_additional_classes_are_zero': False,
            'query_E_device_payload_named_q2p20_excluding_metadata_and_flag': 864028160 if proposed_s1 else None,
            'query_E_host_publication_q2p20': 144 * (1 << 20) if proposed_s1 else None,
            'joint_admitted': False,
            'W_claims_and_proof_explicitly_released_before_A_in_clean_receipt': released_w,
            'legacy_shapes_are_not_native_allocation_evidence': True,
            'scope': 'named live allocation upper bounds only; every additional capacity/reallocation is globally charged. '
                     'Immutable packed W alone excluded. No full-fit/physical/H100 claim.'}


def ledger(directory, backend='legacy', query_record=None, linear_record=None, lifetime_record=None):
    if backend == 'legacy':
        return ledger_legacy(directory)
    if backend not in ('native-2026-10-09', 's1-prepared') or query_record is None or linear_record is None:
        raise ValueError('explicit supported backend and both clean component records required')
    return ledger_native(directory, query_record, linear_record, backend == 's1-prepared', lifetime_record)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', type=Path)
    parser.add_argument('--backend', choices=('legacy', 'native-2026-10-09', 's1-prepared'), default='legacy')
    parser.add_argument('--query-record', type=Path)
    parser.add_argument('--linear-record', type=Path)
    parser.add_argument('--lifetime-record', type=Path)
    args = parser.parse_args()
    print(json.dumps(ledger(args.logs, args.backend, args.query_record, args.linear_record, args.lifetime_record), indent=2, sort_keys=True))

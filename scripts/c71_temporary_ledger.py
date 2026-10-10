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


def native_residual_phases(dimension, stages, extensions, initial, common, add, caches, initial_query, replay):
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
        # Host upload padding exists only in the original A producer scan.
        # source_finish/hash and retained-plane stages do not retain this vector.
        scan_padding = ({'public_padding_host_upper': 106 * 262144 * 2,
                         'device_persistent_or_single_replay_envelope': replay}
                        if dimension == 34 and round_no == 0 else {})
        high_rows = (message_rows + 512 + rows - 1) // rows
        add(name + '_FFT', dict(base, **shared, **scan_padding, E_ring24R=aligned(192 * rows),
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
                device = {f'query_device_{key}': value
                          for key, value in initial_query['canonical_query_device_breakdown'].items()
                          if key != 'original_byte_window'}
                # base already includes the 126464-byte sealed mapping. This
                # route has 857338880 B device payload including that mapping;
                # sealed W needs no original-byte producer/window/gather flag.
                add(name + '_initial_W_resident_query_publication', dict(base, **device,
                    returned_matrix_host=initial_query['returned_matrix_host_bytes'],
                    returned_column_host=initial_query['returned_column_staging_host_bytes']),
                    'Selected NativeQuery::Weights reads the sealed original mapping. No byte producer/window '
                    'or W retention. Public factor construction and opened paths remain separate capacity classes.')
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
                    device_persistent_or_single_replay_envelope=replay,
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
    sync_flag = records(directory, 'C71_SYNC_ERROR_FLAG_REUSE')
    if sync_flag:
        if (len(sync_flag) != 1 or sync_flag[0].get('sync_flag_reuse') is not True
                or sync_flag[0].get('flag_count') != 1
                or sync_flag[0].get('retained_device_capacity_bytes') != 256
                or sync_flag[0].get('host_owner_bytes', 0) < owner):
            raise ValueError('incompatible measured synchronous flag retention')
        owner = sync_flag[0]['host_owner_bytes']
        owner_observations.append({'marker': 'C71_SYNC_ERROR_FLAG_REUSE', 'bytes': owner})
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
    # Seven additional classes have finite main-payload/lifetime formulas in
    # the independent closeout; four still need typed capacity closure. This
    # screen does not turn that partial inventory into joint memory admission.
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
        if sync_flag:
            # Keep the old replay bounds: they still include per-operation flags.
            result['native_retained_sync_error_flag_upper'] = 256
        if numeric:
            # Complete producer scans retire their temporary rows. Proof
            # phases charge replay explicitly only while reconstructing A.
            result['device_persistent_or_single_replay_envelope'] = persistent if proposed_s1 and proof else replay
        if proposed_s1:
            result['original_W_tile_descriptors_host_upper'] = 2 * 3156 * 40
            result['full_calibration_table_serialization_difference_upper'] = 2 * (24_414_870 - 23_954_072)
        if proof:
            result['canonical_Writer_fixed_capacity'] = 96 << 20
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
            public_padding_host_upper=106 * 262144 * 2 if proposed_s1 else 0,
            A_accumulation_additional=a['device_accumulation_phase_bytes']-named),
            'W plus A1..current cache/pads; one replay envelope including persistent; no original proof batches yet.')
        hash_base = dict(base, device_persistent_or_single_replay_envelope=persistent)
        add(f'native_initial_A{caches}_hash', dict(hash_base, **{f'A_{key}': value for key, value in parts.items()},
            A_hash_additional=a['device_hash_phase_bytes']-named),
            'The complete canonical scan releases all live producer rows, KV replay copies, duplicate histograms '
            'and public-padding outputs before return. source_finish fences and retires its flag; histogram and '
            'low/high powers retire before full hash output. Only numeric persistent state remains. '
            'Values retire before first node output; host/profile/PCG capacities remain separate additional classes.')
        add(f'native_initial_A{caches}_query_evaluate', dict(common(caches, proof=True),
            device_persistent_or_single_replay_envelope=replay,
            public_padding_host_upper=106 * 262144 * 2 if proposed_s1 else 0,
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
            device_persistent_or_single_replay_envelope=replay,
            public_padding_host_upper=106 * 262144 * 2 if proposed_s1 else 0,
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
                native_residual_phases(dimension, stages, extensions, initial, common, add, caches, q, replay)
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
    complete_capacity = (complete_prepared_phases(phases, directory, common, persistent,
                         replay, initial, extensions, stages, owner) if proposed_s1 else None)
    return {'backend': 's1-prepared' if proposed_s1 else 'native-2026-10-09',
            'credit': False, 'gpu_execution': False, 'canonical_execution': False,
            'enforced_joint_allocation_limit_bytes': payload,
            'runtime_allocator_stack_driver_allowance_bytes': allowance, 'margin_bytes': margin,
            'allowance_physically_verified': False, 'complete_joint_phase_peak': False,
            'named_phase_crosschecks': phases,
            'additional_capacity_classes_requiring_complete_census': (
                complete_capacity['unclosed_capacity_premises'] if complete_capacity is not None else additional),
            'empty_fixed_allowance_for_other_payload': False,
            'component_record_sources': {'query': str(query_record), 'linear': str(linear_record),
                'query_source_sha': qdoc['source_git_sha'], 'linear_source_sha': ldoc['source_git_sha'],
                'lifetime': str(lifetime_record) if lifetime_record is not None else None,
                'lifetime_source_sha': lifetime_doc['source_git_sha'] if lifetime_doc is not None else None},
            'prepared_S1_is_selected_in_canonical_runner': proposed_s1,
            'S1_query_E_all_selected_extension_stages_modeled': proposed_s1,
            'current_owner_host_byte_observations': owner_observations,
            'synchronous_error_flag_retention': sync_flag[0] if sync_flag else None,
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
            'complete_capacity_integration': complete_capacity,
            'query_E_device_payload_named_q2p20_excluding_metadata_and_flag': 864028160 if proposed_s1 else None,
            'query_E_host_publication_q2p20': 144 * (1 << 20) if proposed_s1 else None,
            'joint_admitted': False,
            'W_claims_and_proof_explicitly_released_before_A_in_clean_receipt': released_w,
            'legacy_shapes_are_not_native_allocation_evidence': True,
            'scope': 'named live allocation upper bounds only; every additional capacity/reallocation is globally charged. '
                     'Immutable packed W alone excluded. No full-fit/physical/H100 claim.'}


def prepared_capacity_markers(directory):
    capacity = records(directory, 'C71_PUBLIC_METADATA_CAPACITY')
    telemetry = records(directory, 'C71_PUBLIC_METADATA_TELEMETRY')
    forms = records(directory, 'C71_CLASS8_FORMS')
    wire = records(directory, 'C71_CANONICAL_WIRE_HEAP')
    if len(capacity) != 1 or len(telemetry) != 1:
        raise ValueError('one final typed CAPACITY and TELEMETRY marker required')
    if {r['slot'] for r in forms} != {0, 1, 2} or {r['slot'] for r in wire} != {0, 1, 2}:
        raise ValueError('typed forms and honest wire markers required for all three slots')
    capacity, telemetry = capacity[0], telemetry[0]
    if capacity['profile_count'] != 6 or capacity['private_inputs'] or capacity['gpu_execution']:
        raise ValueError('incompatible public metadata census')
    if capacity['pcs_metadata']['code_tree_count_upper'] != 63:
        raise ValueError('fresh/carried/main/global descriptor pool must include 63 codes')
    if (telemetry['phase_count_upper'], telemetry['resource_count_upper'],
            telemetry['channel_count_upper'], telemetry['active_phase_count_upper']) != (44, 6, 6, 7):
        raise ValueError('canonical telemetry lifecycle changed')
    if any(r['W_targets'] != 775 or r['A_targets'] != 4446 for r in forms):
        raise ValueError('pinned claim schema changed')
    if any(not r.get('current_batch_preflight_cap_through_W_and_history')
           or not r.get('old_KV_compacted') or r.get('P_V_batch_overlap') is not False for r in forms):
        raise ValueError('complete selected claim lifetime markers required')
    if any(r['rne_records'] != 892 or r['pcs_batches'] != 12 for r in wire):
        raise ValueError('pinned wire schema changed')
    return capacity, telemetry, {r['slot']: r for r in forms}, {r['slot']: r for r in wire}


def source_opening_upper(dimension, count):
    logs = ([32, 30, 28, 26, 24, 22, 20, 18, 16, 14, 13, 13, 13]
            if dimension == 35 else [31, 29, 27, 25, 23, 21, 19, 17, 15, 13, 13, 13, 13])
    if not 0 <= count <= 13:
        raise ValueError('source opening prefix changed')
    return sum((1228800 if i == 0 else 278528) + 32768*(h-9)
               for i, h in enumerate(logs[:count]))


def current_opening_parts(height, base_columns, batch_rows, binding=False):
    # q512, cut<=4096, one current subtree; map nodes are typed metadata.
    h, q = height.bit_length()-1, 512
    siblings = q * max(0, h-9)
    if binding:
        body = 12+q*(52+8*base_columns)+32*siblings
        return {'class3_current_observe_binding_moving_bytes': 3*body}
    return {'class3_current_batch_indices_retained_upper': 16*batch_rows,
            'class3_current_path_triple_vec_payload_upper': 294912,
            'class3_current_needed_queries_frontiers_and_sampled_indices_upper': 80*q,
            'class3_current_single_matrix_row_wrapper_upper': 122880,
            'class3_current_one_regenerated_subtree_upper': 393568}


def complete_prepared_phases(phases, directory, common, persistent, replay, initial,
                             extensions, stages, owner):
    """Typed payload integration. Honest-fit and physical credit remain separate."""
    import re
    cap, tele, forms, wire = prepared_capacity_markers(directory)
    producers = cap['producer_metadata']
    metadata = (cap['six_profile_actual_heap_bytes']
                + cap['table_metadata_actual_shape_bytes']
                + cap['borrowed_table_view_heap_upper_bytes']
                + cap['public_gamma_encoding_heap_bytes']
                + cap['fixed_descriptor_heap_upper_bytes']
                + max(p['persistent_descriptor_heap_upper_bytes'] for p in producers)
                + cap['pcs_metadata']['total_metadata_heap_upper_bytes']
                # Metadata-only admission leaves RequiredGeometry=None.
                # Six pinned production caches own keys24B and widths8B;
                # their inline Option is already in the measured profiles.
                + 6*(2*159*24 + 2*129*8))
    # One selected RMS depth, original circuits retained, no N*W table.
    # AND+XOR totals come from the immutable admitted public ledger
    # ledger-20261007T150200Z, recipe d96b9350...1014. Layered Copies
    # are aliases; each original non-Copy gate is born only once.
    replay_programs, binary_gates, max_width = 159, 6519376, 4096
    raw_node_bound, ports, buckets = 174482, 98, 262144
    replay_plans = (24*(2*binary_gates+4*replay_programs)
                    + 8*replay_programs*(2*max_width+4) + 72*replay_programs)
    replay_builder = (3*(33*buckets+32) + 4*24*(2*raw_node_bound+4)
                      + 9*(ports+raw_node_bound) + 8*(4*max_width+4))
    replay_scratch = 2*8*(replay_programs+(2*ports+4)+(ports+raw_node_bound)
                          +(2*max_width+4)+max_width)
    replay_fixed = 768+1032+1536+312+32  # frames/widths/ordinals/Option+cells
    packed_replay_upper = replay_plans+replay_builder+replay_scratch+replay_fixed
    rms_work_records_moving = (4096+2048)*176  # 2871 cell rounds; Vec old/new
    producer = max(p['producer_descriptor_heap_upper_bytes'] for p in producers)
    # Session::census has one lock-protected dedup set, even outside a replay.
    unique = max((3*p['kv_source_count']+1
                  +(3*p['kv_source_count']).bit_length()+1)*p['node_upper_bytes']['set']
                 for p in producers)
    pcg_idle = 383400
    pcg_expand = 2775464  # includes idle; old correlation batch retires first
    carried = 108231968
    pcs_wire = {d: next(p for p in wire[0]['pcs'] if p['dimension'] == d) for d in (34, 35)}
    assert source_opening_upper(35, 13)+22003712 == 31555584
    assert source_opening_upper(34, 13)+22003712 == 31227904
    for d in (34, 35):
        if pcs_wire[d]['opening_heap_upper_class3'] != source_opening_upper(d, 13)+22003712:
            raise ValueError('typed 59-opening capacity differs from configured prefix model')
    def claim_parts(slot, w_live, a_bound=False, verifier=False):
        f = forms[slot]
        # Before the common preflight, constructor counts stay unclamped.
        w = f['W_cube_upper']
        a = min(f['A_constructor_cube_upper'], f['MAX_CUBES']) if a_bound else f['A_constructor_cube_upper']
        P_A = a*(56+34*24)+(2*4446+4)*(24+48)
        V_A = a*(56+34*24)+(2*4446+4)*(24+24)
        P_W = w*(56+35*24)+(2*775+4)*(24+48)
        V_W = w*(56+35*24)+(2*775+4)*(24+24)
        if not a_bound:
            assert P_A+P_W == f['retained_P_payload_upper']
            assert V_A+V_W == f['retained_V_payload_upper']
        # canonical_state returns from prove_body before sending the whole
        # Response. V builds its batches only after that receive; P has dropped
        # bw/ba. Their claim allocations are alternatives, never concurrent.
        return {'class8_retained_current_role_original_claims':
                    (V_A+(V_W if w_live else 0)) if verifier else (P_A+(P_W if w_live else 0)),
                'class8_historical_KV_current_role_upper': f['old_KV_compacted_payload_upper']}
    def refresh(row):
        total = sum(row['parts'].values())
        row.update(named_allocation_subtotal_bytes=total,
                   remaining_shared_payload_capacity_bytes=5905580032-total,
                   named_subtotal_exceeds_payload=total > 5905580032,
                   is_complete_phase_peak=False,
                   counter_is_fit_evidence=False)
    for row in phases:
        name, parts = row['phase'], row['parts']
        slot_match = re.search(r'_A([123])(?:_|$)', name)
        slot = int(slot_match.group(1))-1 if slot_match else 0
        dmatch = re.search(r'_D(34|35)(?:_|$)', name)
        dimension = int(dmatch.group(1)) if dmatch else (34 if name.startswith('native_initial_A') and name.endswith('_query_evaluate') else None)
        proof = 'canonical_Writer_fixed_capacity' in parts
        scan = ('_scan' in name or '_accumulate' in name or '_late_retention' in name
                or name.startswith('native_initial_A') and name.endswith('_query_evaluate')
                or dimension == 34 and '_S1_FFT' in name)
        opening = 'query' in name or name.endswith('_open') or 'factor_construction' in name
        parts.pop('original_W_tile_descriptors_host_upper', None)  # included PCS five-copy mapping
        parts['class1_9_typed_persistent_metadata'] = metadata
        parts['class9_session_census_KV_dedup_set_upper'] = unique
        parts['class9_crypto_telemetry_capacity_upper'] = tele['crypto_live_metadata_heap_upper_bytes']
        parts['class4_idle_real_AES_PCG_payload'] = pcg_idle
        parts['class4_both_role_retained_setup_Audit_Vec_capacity'] = 1792
        if scan:
            parts['class1_9_typed_producer_transient_metadata'] = producer
        if proof:
            parts.pop('original_claim_batch_codec_upper', None)
            parts.update(claim_parts(slot, dimension == 35 or 'native_linear_W_' in name,
                                     a_bound=True))
            parts['class4_current_real_AES_PCG_expansion_including_idle'] = pcg_expand
            parts.pop('class4_idle_real_AES_PCG_payload', None)
            if not name.startswith('native_linear_'):
                parts['class4_carried_original_mask_cache_payload_upper'] = carried
            parts['class4_optional_XOF_buffers_upper'] = cap['pcs_metadata']['optional_rng_buffer_heap_upper_bytes']
        else:
            # Proof-local mask/code descriptors are safely overcounted in the
            # persistent metadata, but their numeric payload is absent.
            parts['class4_original_tree_optional_XOF_buffers_upper'] = 4*4096
        if dimension is not None:
            pcs = pcs_wire[dimension]
            parts['class5_MatrixProof_other_heap_upper'] = pcs['other_heap_upper_class5']
            smatch = re.search(r'_S(\d+)_', name)
            stage = int(smatch.group(1)) if smatch else (1 if name.startswith('native_initial_A') else 12)
            before, after = max(0, stage-1), min(stage, 12)
            parts['class3_retained_source_opening_prefix_upper'] = source_opening_upper(
                dimension, after if opening or name.endswith(('_promotion', '_late_retention')) else before)
            if opening:
                parts['class1_9_pruned_path_BTree_nodes_upper'] = cap['pruned_path_btree_node_heap_upper_bytes']
                if stage == 1:
                    previous = initial[1 << (dimension-3)]
                elif stage <= 11:
                    prev_stage = next(s for s in stages if s['dimension'] == dimension and s['round'] == stage-2)
                    previous = extensions[prev_stage['height']]
                else:
                    last = max((s for s in stages if s['dimension'] == dimension), key=lambda s:s['round'])
                    previous = extensions[last['height']]
                batch = previous['query_batch_rows']
                parts.update(current_opening_parts(previous['height'], previous['columns'], batch))
            if stage == 12:
                parts['class11_blinded_reveal_heap_upper'] = pcs['blinded_reveal_heap_upper_class11']
                parts['class11_fresh_mask_cache_payload_upper'] = carried
                parts['class11_fresh_main_codeword_salt_merkle_payload_upper'] = (
                    8192*4*24+8192*4*8+(2*8192-1)*32)
            if 'factor_construction' in name:
                batch = previous['query_batch_rows']
                for key in ('public_points', 'current_polynomial_level_upper',
                            'current_inverse_modulus_spectra', 'one_upload_conversion'):
                    parts.pop(key, None)
                parts['class2_CPU_query_construction_payload_upper'] = 160*batch
        refresh(row)

    def extra(name, parts, lifetime):
        row = {'phase': name, 'parts': parts, 'lifetime': lifetime,
               'analytic_scope': 'honest pinned allocator payload model; physical allowance unverified'}
        refresh(row)
        phases.append(row)
    # Initial original query factors have the same CPU construction lifetime
    # as E queries; retained publication buffers are not live in that scope.
    for row in list(phases):
        name = row['phase']
        if not (name.endswith('_initial_W_resident_query_publication')
                or name.startswith('native_initial_A') and name.endswith('_query_evaluate')):
            continue
        parts = {key:value for key,value in row['parts'].items()
                 if key not in ('returned_matrix_host','returned_column_host','gather_flag')
                 and (not key.startswith('query_device_') or 'factor' in key or 'twiddle' in key)}
        parts['class2_CPU_query_construction_payload_upper'] = 160*(1 << 20)
        extra(name+'_public_factor_construction',parts,
              'CPU inverse/product/DFT scope precedes private publication; current Tree batch indices stay alive.')
    def proof_base(caches, slot, w_live=True, a_bound=False):
        base = common(caches, proof=True, w_closure=w_live)
        base.pop('original_claim_batch_codec_upper', None)
        base.pop('original_W_tile_descriptors_host_upper', None)
        base.update(claim_parts(slot, w_live, a_bound))
        base.update(class1_9_typed_persistent_metadata=metadata,
                    class9_session_census_KV_dedup_set_upper=unique,
                    class9_crypto_telemetry_capacity_upper=tele['crypto_live_metadata_heap_upper_bytes'],
                    class4_current_real_AES_PCG_expansion_including_idle=pcg_expand,
                    class4_both_role_retained_setup_Audit_Vec_capacity=1792)
        return base
    # This preceding lifetime has no installed numerical state/root caches.
    setup = {'class1_9_public_profiles_tables_fixed_metadata': metadata,
             'two_public_table_host_payloads': 2*24414870,
             'class9_crypto_telemetry_capacity_upper': tele['crypto_live_metadata_heap_upper_bytes'],
             'class4_both_role_retained_setup_Audit_Vec_capacity':1792,
             'class4_current_common_and_full_context_Vec_capacity_upper':12*240}
    extra('public_profile_construction', dict(setup,
          public_profile_build_moving_delta=max(0, cap['profile_build_metadata_only_heap_peak_bytes']
                                                -cap['six_profile_actual_heap_bytes'])),
          'Two role-local three-profile constructions precede installation; requested-layout build peak is measured metadata-only.')
    extra('public_profile_RMS_validation_compile', dict(setup,
          class6_RMS_prior_program_inner_capacity_upper=457616928,
          class6_RMS_Builder_and_prune_capacity_upper=266001396,
          class6_RMS_prepare_map_keys_profiles_outer_capacity_upper=208400,
          class6_RMS_compact_geometry_keys_and_widths_build_upper=140608+2064),
          'One selected public compiler at a time; pw<=32,width<=128 bounds174482 raw gates. Source-derived HashMap/BTreeSet and moving layer growth are charged; no Compact checkpoint.')
    extra('real_AES_seed6_setup', dict(setup,
          both_role_main_and_inverse_setup_vec_payload_upper=152*(17553+2025)+624,
          MR19_both_role384_native_point_scalar_and_wire_capacity_upper=511872,
          AES_COPE_both_role_correction_rows=6144,
          guard_cGGM_equality_and_promoted_seed_capacity_upper=1745956),
          'Both role main setup output may coexist with inverse setup. Pinned p521 native Point216B/Scalar72B and amortized growth are charged; B675,H19 guard paths use stacks, not a full tree.')
    for slot in range(3):
        caches = slot+1
        f = forms[slot]
        base = proof_base(caches, slot)
        pending = f['pending_original_payload_upper']
        extra(f'proof_A{caches}_form_constructor', dict(base,
              class8_pending_original_current_role_upper=pending,
              class8_constructor_moving_payload_upper=f['constructor_payload_upper']),
              'Before Batch shrink/bind; constructor result and scalar temporary may coexist. No private S1 planes.')
        extra(f'proof_A{caches}_component_frame_encode_after_work_retirement', dict(base,
              class5_one_component_proof_and_moving_encoded_body_upper=
                  wire[slot]['max_proof_and_body_encode_moving_upper_bytes']),
              'The per-frame marker bounds every honest component. RMS/Lookup/EXP private checkpoints retire before the returned proof body is encoded; no MatrixProof is added again.')
        # The compact checkpoint and RMS public programs belong to this phase,
        # never to the later lookup/range/PCS phases.
        extra(f'proof_A{caches}_RMS_public_program_build', dict(base,
              class8_pending_original_current_role_upper=pending,
              class6_RMS_final_program_inner_capacity_enclosing_prior_programs=457616928,
              class6_RMS_Builder_and_prune_capacity_upper=266001396,
              class6_RMS_prepare_map_keys_profiles_outer_capacity_upper=208400),
              'Before compact checkpoint construction. Existing final capacities conservatively include the current program; explicit compiler scratch bounds its preceding lifetime.')
        extra(f'proof_A{caches}_RMS_GKR_steady', dict(base,
              class8_pending_original_current_role_upper=pending,
              class6_RMS_compact_checkpoint_payload_and_descriptors=2023511878,
              class6_RMS_public_program_inner_capacity=457616928,
              class6_RMS_program_outer_capacity_upper=35616,
              class6_RMS_retained_profile_indices_capacity_upper=6736,
              class6_RMS_edge_capacity_moving_upper=3*24121920,
              class6_RMS_packed_replay_plans_builder_scratch_fixed_upper=packed_replay_upper,
              class6_RMS_prover_work_records_moving_upper=rms_work_records_moving,
              class6_RMS_coefficient_and_weight_payload_upper=(7*16384+2*421)*24+421),
              'Pinned99-layer159-program RMS; packed plans retain one depth only and retire before index edges/byte LUT. Plans, builder/scratch moving and fixed stacks conservatively overlap here; original Circuit and edge growth are separately charged. Single-program statistic/pattern consumers keep their previous replay schedule.')
        extra(f'proof_A{caches}_EXP30_checkpoint', dict(base,
              class8_pending_original_current_role_upper=pending,
              class6_EXP30_checkpoint_upper=1 << 30),
              'EXP checkpoint retires before the Lookup tree. Source-derived1GiB upper includes the maximum checkpoint.')
        extra(f'proof_A{caches}_softmax_lookup', dict(base,
              class8_pending_original_current_role_upper=pending,
              class6_softmax_wide_cache_upper=6*221184000,
              class6_softmax_histogram_upper=4*3932100,
              class6_softmax_CUT4_tree_upper=(2*((1 << 28)//16)-1)*48,
              class6_lookup_outer_level_descriptors=25*24),
              'Worst O300 source-derived lookup shape bounds each slot; no RMS or EXP checkpoint remains.')
        extra(f'proof_A{caches}_range_A_deep_retention', dict(base,
              device_persistent_or_single_replay_envelope=replay,
              public_padding_host_upper=106*262144*2,
              class1_9_typed_producer_transient_metadata=producer,
              class8_pending_original_current_role_upper=pending,
              class6_range_A_deep_children=96*(1 << 24),
              class6_range_A_original_byte_window=1 << 30),
              'One range source window and retained children; no prior RMS/Lookup buffers or S1 planes.')
        for dimension in (35, 34):
            db = proof_base(caches, slot, dimension == 35, True)
            record = f['W_bind_record_payload_upper' if dimension == 35 else 'A_bind_record_payload_upper']
            bind_extra = f['W_bind_extra_payload_upper' if dimension == 35 else 'A_bind_extra_payload_upper']
            extra(f'proof_A{caches}_D{dimension}_linear_bind', dict(db,
                  class8_bind_record_exact_capacity_upper=record,
                  class8_bind_profile_attempt_and_coefficients_upper=bind_extra),
                  'Exact-reserved record follows aggregate validation and retires before LINEAR packet construction.')
            for s in (s for s in stages if s['dimension'] == dimension):
                remaining = dimension-7-2*s['round']
                state = dict(db, class4_carried_original_mask_cache_payload_upper=carried,
                             class3_retained_source_opening_prefix_upper=source_opening_upper(dimension,s['round']),
                             class5_MatrixProof_other_heap_upper=pcs_wire[dimension]['other_heap_upper_class5'],
                             class7_power_terms_amplitudes_EQ_denominator_descriptor_upper=
                                 6095592+393216+393216+786432+49152+80+256*24,
                             retained_three_planes=s['retained_capacity_at_commit_bytes'],
                             extension_current_root_offset_cache=extensions[s['height']]['retained_root_and_salt_offset_bytes'],
                             extension_current_private_host_pads=4*512*24,
                             class7_native_shape_EQ_packet_device_upper=residual_packet(35 if dimension == 35 else 2)['device'],
                             class7_native_result_and_sticky_flag=aligned(48)+aligned(4))
                extra(f'proof_A{caches}_D{dimension}_S{s["round"]+1}_PowerBlocks_setup', dict(state,
                      class7_CPU_inverse_multiply_DFT_setup_upper=192*(1 << 21)),
                      'Cache rebuilt after take; setup precedes native consumer upload. No simultaneous steady band.')
                extra(f'proof_A{caches}_D{dimension}_S{s["round"]+1}_contraction_steady', dict(state,
                      class7_CPU_cached_inverse_DFT_host_covectors_and_GPU_band_upper=248*(1 << 21)),
                      '248B includes all host outputs/marshalling and paired device public vectors for B2^21; no A reconstruction.')
            pcs = pcs_wire[dimension]
            final = dict(db, class3_complete59_opening_heap_upper=pcs['opening_heap_upper_class3'],
                         class5_MatrixProof_other_heap_upper=pcs['other_heap_upper_class5'],
                         class11_blinded_reveal_heap_upper=pcs['blinded_reveal_heap_upper_class11'],
                         class4_original_and_fresh_mask_caches_upper=2*carried,
                         class11_fresh_main_codeword_salt_merkle_payload_upper=
                             8192*4*24+8192*4*8+(2*8192-1)*32,
                         class10_bounded_temporary_planes_and_two_result_vectors_flag=3072+6144+256,
                         class10_final_source_polynomials_upper=4*64*24)
            extra(f'proof_A{caches}_D{dimension}_basecase_open_and_reveal', final,
                  'Fresh+carried masks and reveals first coexist here, after all high S1 stages; final read is bounded128E.')
            enc = proof_base(caches, slot, dimension == 35, True)
            enc['class5_one_frame_proof_and_moving_encoded_body_upper'] = wire[slot]['max_proof_and_body_encode_moving_upper_bytes']
            extra(f'proof_A{caches}_D{dimension}_frame_encode_after_native_retirement', enc,
                  'The whole typed proof+body marker replaces Classes3/5/11. close_native retires private query/planes first.')
        recv = proof_base(caches, slot, False)
        recv.pop('canonical_Writer_fixed_capacity', None)
        recv.update(claim_parts(slot, True, verifier=True))
        recv['class5_P_certificate_V_receive_and_one_decoder_moving_peak_upper'] = (
            wire[slot]['P_certificate_and_V_receive_and_decoder_class_upper_bytes'])
        recv['class8_pending_original_current_role_upper'] = pending
        recv['class8_constructor_moving_payload_upper'] = f['constructor_payload_upper']
        extra(f'proof_A{caches}_receive_and_decode_one_frame', recv,
              'P proof/private work and P claims retired before send; certificates on both roles, one V decoder and V claim constructors are charged. Reader borrows one frame.')
        extra(f'proof_A{caches}_verify_RMS_public_program_build', dict(recv,
              class6_RMS_prior_program_inner_capacity_upper=457616928,
              class6_RMS_Builder_and_prune_capacity_upper=266001396,
              class6_RMS_prepare_map_keys_profiles_outer_capacity_upper=208400),
              'The verifier compiler coexists with certificates and V claims, after all P claim/private work has retired.')
        extra(f'proof_A{caches}_verify_RMS_public_programs', dict(recv,
              class6_RMS_public_program_inner_capacity=457616928,
              class6_RMS_program_outer_capacity_upper=35616,
              class6_RMS_retained_profile_indices_capacity_upper=6736,
              class6_RMS_edge_capacity_moving_upper=3*24121920,
              class6_RMS_coefficient_and_weight_payload_upper=(7*16384+2*421)*24+421),
              'Verification follows whole-certificate receive; no private Compact checkpoints or GPU PCS planes. Compiler scratch uses the separate public-build bound above.')
        extra(f'proof_A{caches}_opening_binding_after_query_retirement', dict(base,
              class3_complete59_opening_upper=max(pcs_wire[d]['opening_heap_upper_class3'] for d in (34,35)),
              **current_opening_parts(1 << 32,128,1024,binding=True)),
              'Conservative final retained opening heap plus worst binding byte buffer; no current row batch/private query.')
    report = dict(common(3, proof=False, numeric=False),
                  class1_9_typed_persistent_metadata=metadata,
                  class9_after_cleanup_report_metadata_upper=tele['after_cleanup_report_metadata_heap_upper_bytes'],
                  class4_idle_real_AES_PCG_payload=pcg_idle)
    report.pop('original_W_tile_descriptors_host_upper',None)
    report.pop('native_retained_sync_error_flag_upper', None)
    extra('after_crypto_cleanup_report', report,
          'Alternative report clones after native cleanup. Crypto metadata and query/planes are not summed again.')
    return {'markers': {'capacity':cap,'telemetry':tele,'forms':list(forms.values()),'wire':list(wire.values())},
            'typed_persistent_metadata_heap_upper_bytes':metadata,
            'typed_producer_transient_heap_upper_bytes':producer,
            'session_census_dedup_set_heap_upper_bytes':unique,
            'all_eleven_classes_have_explicit_parts':True,
            'complete_joint_phase_peak':False,
            'joint_admitted':False,
            'unclosed_capacity_premises':[
                {'class':1,'phase':'all','source':'C71_PUBLIC_METADATA_CAPACITY',
                 'missing':'run-manifest argv/path capacity<=4096 premise must be bound to final run; marker is conditional on this public shape'},
            ],
            'counter_is_fit_evidence':False,'physical_allowance_verified':False}

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

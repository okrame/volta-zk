#![cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]

use rayon::prelude::*;
use volta_accel::{Backend, DeviceSlice, Operation};
use volta_field::{Fp, Fp2};
use volta_pcs::c62_gpu_whir::{C62GpuMmcs, C62GpuResourceGuard};
use volta_pcs::merkle::{hash_leaf, Hash, MerkleTree};
use volta_pcs::ntt::NttPlan;
use volta_pcs::{
    c63_bolt_correction_index, c63_correction_state_root_reference,
    c63_correction_tile_root_reference, c63_open_correction_rows_reference,
    c63_zero_encoded_sketch_root, C63CorrectionRowReference, C63GpuSetupOwner, C63GpuStateOwner,
    C63GpuTileMetadata, C63SparseSetupReference, C6CacheCell, C6CacheSlotKind, C63_BOLT_COLUMNS,
    C63_BOLT_LDPC_CHECK_DEGREE, C63_BOLT_LDPC_COLUMN_DEGREE, C63_BOLT_LIVE_ROWS_PER_POSITION,
    C63_BOLT_ROWS, C63_BOLT_ROWS_PER_POSITION, C63_BOLT_SKETCH_ROWS, C63_PRODUCTION_SETUP_SEED,
};

const LAYERS: usize = 12;
const WIDTH: usize = 768;
const FOLD_CHUNK: usize = C63_BOLT_SKETCH_ROWS / 2;

fn tapes(value_offset: u64) -> [Vec<Fp>; 2] {
    std::array::from_fn(|tape| {
        let mut values = Vec::with_capacity(2 * LAYERS * WIDTH);
        for kind in 0..2 {
            for layer in 0..LAYERS {
                for channel in 0..WIDTH {
                    values.push(Fp::new(
                        1 + value_offset
                            + tape as u64 * 20_000_003
                            + kind as u64 * 10_000_019
                            + layer as u64 * 100_003
                            + channel as u64 * 17,
                    ));
                }
            }
        }
        values
    })
}

fn cpu_state(
    setup: &C63SparseSetupReference,
    tapes: &[Vec<Fp>; 2],
    position: usize,
    predecessor_corrections: Option<&[Fp]>,
    predecessor_sketch: Option<&[Fp]>,
    metadata: C63GpuTileMetadata,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Hash) {
    let old_correction_len = position * C63_BOLT_LIVE_ROWS_PER_POSITION * C63_BOLT_COLUMNS;
    let mut corrections =
        vec![Fp::ZERO; (position + 1) * C63_BOLT_LIVE_ROWS_PER_POSITION * C63_BOLT_COLUMNS];
    if let Some(predecessor) = predecessor_corrections {
        assert_eq!(predecessor.len(), old_correction_len);
        corrections[..old_correction_len].copy_from_slice(predecessor);
    } else {
        assert_eq!(position, 0);
    }
    let mut sketch = predecessor_sketch
        .map(<[Fp]>::to_vec)
        .unwrap_or_else(|| vec![Fp::ZERO; C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS]);
    for (tape, values) in tapes.iter().enumerate() {
        let mut offset = 0;
        for kind in [C6CacheSlotKind::Key, C6CacheSlotKind::Value] {
            for layer in 0..LAYERS {
                for channel in 0..WIDTH {
                    let value = values[offset];
                    offset += 1;
                    let index = c63_bolt_correction_index(
                        C6CacheCell {
                            kind,
                            layer: layer as u16,
                            position: position as u16,
                            channel: channel as u16,
                        },
                        tape as u8,
                    )
                    .unwrap();
                    let source_row = index.row as usize;
                    let row_in_position = source_row & (C63_BOLT_ROWS_PER_POSITION - 1);
                    let compact_row = position * C63_BOLT_LIVE_ROWS_PER_POSITION + row_in_position;
                    let column = index.column as usize;
                    corrections[compact_row * C63_BOLT_COLUMNS + column] = value;
                    for edge in 0..usize::from(C63_BOLT_LDPC_COLUMN_DEGREE) {
                        let socket = source_row * usize::from(C63_BOLT_LDPC_COLUMN_DEGREE) + edge;
                        let output = setup.permutation()[socket] as usize
                            / usize::from(C63_BOLT_LDPC_CHECK_DEGREE);
                        sketch[column * C63_BOLT_SKETCH_ROWS + output] +=
                            value * setup.coefficients()[socket];
                    }
                }
            }
        }
        assert_eq!(offset, values.len());
    }

    let plan = NttPlan::new(C63_BOLT_SKETCH_ROWS);
    let mut encoded = vec![Fp::ZERO; 2 * C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS];
    encoded.par_chunks_mut(C63_BOLT_SKETCH_ROWS).enumerate().for_each(|(component, output)| {
        let column = component / 2;
        let chunk = component & 1;
        let start = column * C63_BOLT_SKETCH_ROWS + chunk * FOLD_CHUNK;
        output[..FOLD_CHUNK].copy_from_slice(&sketch[start..start + FOLD_CHUNK]);
        plan.forward(output);
    });

    let rows = (0..C63_BOLT_LIVE_ROWS_PER_POSITION)
        .map(|row| C63CorrectionRowReference {
            position: position as u16,
            layer_high: (row >> 9) as u8,
            channel_low: (row & 511) as u16,
            birth_epoch: metadata.birth_epoch,
            allocation_binding_digest: metadata.allocation_binding_digest,
            source_schedule_digest: metadata.source_schedule_digest,
            corrections: std::array::from_fn(|column| {
                corrections
                    [(position * C63_BOLT_LIVE_ROWS_PER_POSITION + row) * C63_BOLT_COLUMNS + column]
            }),
        })
        .collect::<Vec<_>>();
    let tile_root = c63_correction_tile_root_reference(&rows).unwrap();
    (corrections, sketch, encoded, tile_root)
}

fn encoded_root(encoded: &[Fp]) -> Hash {
    let leaves = (0..C63_BOLT_SKETCH_ROWS)
        .into_par_iter()
        .map(|row| {
            let mut frame = [0u8; 2 * C63_BOLT_COLUMNS * 8];
            for component in 0..2 * C63_BOLT_COLUMNS {
                let start = component * 8;
                frame[start..start + 8].copy_from_slice(
                    &encoded[component * C63_BOLT_SKETCH_ROWS + row].value().to_le_bytes(),
                );
            }
            hash_leaf(&frame)
        })
        .collect::<Vec<_>>();
    MerkleTree::from_leaves(leaves).root()
}

fn print_stats(label: &str, stats: &volta_accel::BackendStats) {
    eprintln!(
        "{label}: wall_ns={} kernel_ns={} peak_device_bytes={} h2d_bytes={} d2h_bytes={} d2d_bytes={} synchronizations={} rows_calls={} ntt_calls={} merkle_calls={}",
        stats.measurement_wall_ns,
        stats.kernel_ns(),
        stats.peak_device_bytes,
        stats.h2d_bytes,
        stats.d2h_bytes,
        stats.explicit_d2d_copy_bytes,
        stats.synchronizations,
        stats.operation(Operation::PcsRows).calls,
        stats.operation(Operation::PcsNtt).calls,
        stats.operation(Operation::PcsMerkle).calls,
    );
}

#[test]
#[ignore = "requires the production ABI45 CUDA library and one A100"]
fn production_owner_matches_cpu_for_one_complete_token() {
    let sparse_setup = C63SparseSetupReference::sample(
        C63_PRODUCTION_SETUP_SEED,
        C63_BOLT_ROWS,
        C63_BOLT_SKETCH_ROWS,
        C63_BOLT_LDPC_COLUMN_DEGREE,
        C63_BOLT_LDPC_CHECK_DEGREE,
    )
    .unwrap();
    eprintln!(
        "c63_setup_digest={}",
        sparse_setup
            .expanded_h_digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let genesis_tapes = tapes(0);
    let metadata = C63GpuTileMetadata {
        birth_epoch: 1,
        allocation_binding_digest: [0x71; 32],
        source_schedule_digest: [0x72; 32],
    };
    let profile_digest = sparse_setup.production_profile_digest().unwrap();
    let (expected_corrections, expected_sketch, expected_encoded, tile_root) =
        cpu_state(&sparse_setup, &genesis_tapes, 0, None, None, metadata);
    let expected_correction_root =
        c63_correction_state_root_reference(profile_digest, 1, &[tile_root]).unwrap();
    let expected_encoded_root = encoded_root(&expected_encoded);

    let backend = Backend::cuda_resident().expect("initialize ABI45 resident CUDA backend");
    let guard = C62GpuResourceGuard::for_lane(19, 1, 1 << 19, 19, 1, false, 40u64 << 30).unwrap();
    let mmcs = C62GpuMmcs::new(backend, 19, guard).unwrap();
    let setup = C63GpuSetupOwner::install(&mmcs, &sparse_setup).unwrap();
    let backend = mmcs.backend();
    {
        let mut gpu = backend.lock().unwrap();
        let zero = gpu.alloc_device::<u64>(2 * C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS).unwrap();
        gpu.zero_device(&zero, 0, zero.len()).unwrap();
        let tree =
            gpu.hash_fp_tree_device(&zero, 2 * C63_BOLT_COLUMNS, C63_BOLT_SKETCH_ROWS).unwrap();
        assert_eq!(gpu.merkle_root_device(&tree).unwrap(), c63_zero_encoded_sketch_root());
        gpu.free_device_merkle_tree(tree).unwrap();
        gpu.free_device(zero).unwrap();
    }
    let setup_resident_bytes =
        backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes;
    let tape_words =
        genesis_tapes.map(|values| values.into_iter().map(Fp::value).collect::<Vec<_>>());
    let (tape0, tape1) = {
        let mut gpu = backend.lock().unwrap();
        let tape0 = gpu.upload_new_device(&tape_words[0]).unwrap();
        let tape1 = gpu.upload_new_device(&tape_words[1]).unwrap();
        gpu.begin_measurement().unwrap();
        (tape0, tape1)
    };
    let state = C63GpuStateOwner::propose_append(
        &setup,
        None,
        profile_digest,
        1,
        DeviceSlice::new(&tape0, 0, tape0.len()).unwrap(),
        DeviceSlice::new(&tape1, 0, tape1.len()).unwrap(),
        &[metadata],
    )
    .unwrap();
    let stats = backend.lock().unwrap().finish_measurement().unwrap();
    print_stats("c63_genesis", &stats);
    assert!(stats.operation(Operation::PcsRows).calls > 0);
    assert!(stats.operation(Operation::PcsNtt).calls > 0);
    assert!(stats.operation(Operation::PcsMerkle).calls > 0);

    let (corrections, sketch, encoded) = {
        let mut gpu = backend.lock().unwrap();
        let correction_slice = state.correction_rows();
        let sketch_slice = state.sparse_sketch();
        let encoded_slice = state.encoded_sketch();
        let corrections = gpu
            .download_device(
                correction_slice.buffer(),
                correction_slice.offset(),
                correction_slice.len(),
            )
            .unwrap();
        let sketch = gpu
            .download_device(sketch_slice.buffer(), sketch_slice.offset(), sketch_slice.len())
            .unwrap();
        let encoded = gpu
            .download_device(encoded_slice.buffer(), encoded_slice.offset(), encoded_slice.len())
            .unwrap();
        gpu.free_device(tape0).unwrap();
        gpu.free_device(tape1).unwrap();
        (corrections, sketch, encoded)
    };

    assert!(corrections
        .iter()
        .zip(&expected_corrections)
        .all(|(&got, expected)| got == expected.value()));
    assert!(sketch.iter().zip(&expected_sketch).all(|(&got, expected)| got == expected.value()));
    assert!(encoded.iter().zip(&expected_encoded).all(|(&got, expected)| got == expected.value()));
    assert_eq!(state.correction_root(), expected_correction_root);
    assert_eq!(state.encoded_sketch_root(), expected_encoded_root);
    assert_eq!(state.epoch(), 1);
    assert_eq!(state.accepted_len(), 1);

    let queried_rows = [
        0,
        17,
        C63_BOLT_LIVE_ROWS_PER_POSITION as u32 - 1,
        C63_BOLT_LIVE_ROWS_PER_POSITION as u32,
        C63_BOLT_ROWS_PER_POSITION as u32 - 1,
        C63_BOLT_ROWS_PER_POSITION as u32,
        C63_BOLT_ROWS as u32 - 1,
    ];
    let expected_rows = (0..C63_BOLT_LIVE_ROWS_PER_POSITION)
        .map(|row| C63CorrectionRowReference {
            position: 0,
            layer_high: (row >> 9) as u8,
            channel_low: (row & 511) as u16,
            birth_epoch: metadata.birth_epoch,
            allocation_binding_digest: metadata.allocation_binding_digest,
            source_schedule_digest: metadata.source_schedule_digest,
            corrections: std::array::from_fn(|column| {
                expected_corrections[row * C63_BOLT_COLUMNS + column]
            }),
        })
        .collect::<Vec<_>>();
    let (_, expected_opening) =
        c63_open_correction_rows_reference(profile_digest, 1, 0, &[expected_rows], &queried_rows)
            .unwrap();
    let resident_opening = state.open_correction_rows(&queried_rows).unwrap();
    assert_eq!(
        resident_opening.encode(0, 1, &queried_rows).unwrap(),
        expected_opening.encode(0, 1, &queried_rows).unwrap(),
    );

    let rho: [Fp2; C63_BOLT_COLUMNS] = std::array::from_fn(|column| {
        Fp2::new(Fp::new(11 + column as u64 * 13), Fp::new(17 + column as u64 * 19))
    });
    let mut projected = state.project_transition_messages(None, rho).unwrap();
    let projected_raw: [[Vec<u64>; 2]; 3] = std::array::from_fn(|family| {
        std::array::from_fn(|limb| {
            let buffer = match family {
                0 => projected.take_systematic(limb).unwrap(),
                1 => projected.take_sketch(limb).unwrap(),
                _ => projected.take_encoded_sketch(limb).unwrap(),
            };
            let mut gpu = backend.lock().unwrap();
            let values = gpu.download_device(&buffer, 0, buffer.len()).unwrap();
            gpu.free_device(buffer).unwrap();
            values
        })
    });
    drop(projected);
    for limb in 0..2 {
        assert!(projected_raw[0][limb].par_iter().enumerate().all(|(row, &got)| {
            let position = row / C63_BOLT_ROWS_PER_POSITION;
            let local = row % C63_BOLT_ROWS_PER_POSITION;
            let expected = if position == 0 && local < C63_BOLT_LIVE_ROWS_PER_POSITION {
                (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                    let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                    sum + expected_corrections[local * C63_BOLT_COLUMNS + column] * coefficient
                })
            } else {
                Fp::ZERO
            };
            got == expected.value()
        }));
        assert!(projected_raw[1][limb].par_iter().enumerate().all(|(row, &got)| {
            let expected = (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                sum + expected_sketch[column * C63_BOLT_SKETCH_ROWS + row] * coefficient
            });
            got == expected.value()
        }));
        assert!(projected_raw[2][limb].par_iter().enumerate().all(|(output_row, &got)| {
            let fold = output_row / C63_BOLT_SKETCH_ROWS;
            let row = output_row % C63_BOLT_SKETCH_ROWS;
            let expected = (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                sum + expected_encoded[(2 * column + fold) * C63_BOLT_SKETCH_ROWS + row]
                    * coefficient
            });
            got == expected.value()
        }));
    }

    let accepted_resident_bytes =
        backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes;
    let successor_tapes = tapes(0x1234_5678);
    let successor_metadata = C63GpuTileMetadata {
        birth_epoch: 2,
        allocation_binding_digest: [0x81; 32],
        source_schedule_digest: [0x82; 32],
    };
    let (
        expected_successor_corrections,
        expected_successor_sketch,
        expected_successor_encoded,
        successor_tile_root,
    ) = cpu_state(
        &sparse_setup,
        &successor_tapes,
        1,
        Some(&expected_corrections),
        Some(&expected_sketch),
        successor_metadata,
    );
    let expected_successor_correction_root =
        c63_correction_state_root_reference(profile_digest, 2, &[tile_root, successor_tile_root])
            .unwrap();
    let expected_successor_encoded_root = encoded_root(&expected_successor_encoded);
    let successor_tape_words =
        successor_tapes.map(|values| values.into_iter().map(Fp::value).collect::<Vec<_>>());
    let (successor_tape0, successor_tape1) = {
        let mut gpu = backend.lock().unwrap();
        let tape0 = gpu.upload_new_device(&successor_tape_words[0]).unwrap();
        let tape1 = gpu.upload_new_device(&successor_tape_words[1]).unwrap();
        gpu.begin_measurement().unwrap();
        (tape0, tape1)
    };
    let successor = C63GpuStateOwner::propose_append(
        &setup,
        Some(&state),
        profile_digest,
        2,
        DeviceSlice::new(&successor_tape0, 0, successor_tape0.len()).unwrap(),
        DeviceSlice::new(&successor_tape1, 0, successor_tape1.len()).unwrap(),
        &[successor_metadata],
    )
    .unwrap();
    let successor_stats = backend.lock().unwrap().finish_measurement().unwrap();
    print_stats("c63_successor", &successor_stats);
    let (successor_corrections, successor_sketch, successor_encoded) = {
        let mut gpu = backend.lock().unwrap();
        let corrections = successor.correction_rows();
        let sketch = successor.sparse_sketch();
        let encoded = successor.encoded_sketch();
        let corrections = gpu
            .download_device(corrections.buffer(), corrections.offset(), corrections.len())
            .unwrap();
        let sketch = gpu.download_device(sketch.buffer(), sketch.offset(), sketch.len()).unwrap();
        let encoded =
            gpu.download_device(encoded.buffer(), encoded.offset(), encoded.len()).unwrap();
        gpu.free_device(successor_tape0).unwrap();
        gpu.free_device(successor_tape1).unwrap();
        (corrections, sketch, encoded)
    };
    assert!(
        successor_corrections[..expected_corrections.len()]
            .iter()
            .zip(&expected_corrections)
            .all(|(&got, expected)| got == expected.value()),
        "the accepted prefix changed"
    );
    assert!(successor_corrections
        .iter()
        .zip(&expected_successor_corrections)
        .all(|(&got, expected)| got == expected.value()));
    assert!(successor_sketch
        .iter()
        .zip(&expected_successor_sketch)
        .all(|(&got, expected)| got == expected.value()));
    assert!(successor_encoded
        .iter()
        .zip(&expected_successor_encoded)
        .all(|(&got, expected)| got == expected.value()));
    assert_eq!(successor.correction_root(), expected_successor_correction_root);
    assert_eq!(successor.encoded_sketch_root(), expected_successor_encoded_root);
    assert_ne!(successor.correction_root(), state.correction_root());
    assert_ne!(successor.encoded_sketch_root(), state.encoded_sketch_root());
    assert_eq!(successor.epoch(), 2);
    assert_eq!(successor.accepted_len(), 2);

    let mut transition = successor.project_transition_messages(Some(&state), rho).unwrap();
    let transition_raw: [[Vec<u64>; 2]; 3] = std::array::from_fn(|family| {
        std::array::from_fn(|limb| {
            let buffer = match family {
                0 => transition.take_systematic(limb).unwrap(),
                1 => transition.take_sketch(limb).unwrap(),
                _ => transition.take_encoded_sketch(limb).unwrap(),
            };
            let mut gpu = backend.lock().unwrap();
            let values = gpu.download_device(&buffer, 0, buffer.len()).unwrap();
            gpu.free_device(buffer).unwrap();
            values
        })
    });
    drop(transition);
    for limb in 0..2 {
        assert!(transition_raw[0][limb].par_iter().enumerate().all(|(row, &got)| {
            let position = row / C63_BOLT_ROWS_PER_POSITION;
            let local = row % C63_BOLT_ROWS_PER_POSITION;
            let expected = if position == 1 && local < C63_BOLT_LIVE_ROWS_PER_POSITION {
                (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                    let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                    sum + expected_successor_corrections
                        [(C63_BOLT_LIVE_ROWS_PER_POSITION + local) * C63_BOLT_COLUMNS + column]
                        * coefficient
                })
            } else {
                Fp::ZERO
            };
            got == expected.value()
        }));
        assert!(transition_raw[1][limb].par_iter().enumerate().all(|(row, &got)| {
            let expected = (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                sum + (expected_successor_sketch[column * C63_BOLT_SKETCH_ROWS + row]
                    - expected_sketch[column * C63_BOLT_SKETCH_ROWS + row])
                    * coefficient
            });
            got == expected.value()
        }));
        assert!(transition_raw[2][limb].par_iter().enumerate().all(|(output_row, &got)| {
            let fold = output_row / C63_BOLT_SKETCH_ROWS;
            let row = output_row % C63_BOLT_SKETCH_ROWS;
            let expected = (0..C63_BOLT_COLUMNS).fold(Fp::ZERO, |sum, column| {
                let coefficient = if limb == 0 { rho[column].c0 } else { rho[column].c1 };
                let index = (2 * column + fold) * C63_BOLT_SKETCH_ROWS + row;
                sum + (expected_successor_encoded[index] - expected_encoded[index]) * coefficient
            });
            got == expected.value()
        }));
    }
    drop(successor);
    assert_eq!(
        backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes,
        accepted_resident_bytes,
        "discarding the successor must preserve only the accepted state",
    );
    drop(state);
    assert_eq!(
        backend.lock().unwrap().device_memory_breakdown().unwrap().resident_bytes,
        setup_resident_bytes,
        "discarding a proposal must release every response-owned device buffer",
    );
}

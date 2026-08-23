#![cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]

use rayon::prelude::*;
use volta_accel::{Backend, DeviceSlice, Operation};
use volta_field::Fp;
use volta_pcs::c62_gpu_whir::{C62GpuMmcs, C62GpuResourceGuard};
use volta_pcs::merkle::{hash_leaf, Hash, MerkleTree};
use volta_pcs::ntt::NttPlan;
use volta_pcs::{
    c63_bolt_correction_index, c63_correction_state_root_reference,
    c63_correction_tile_root_reference, C63CorrectionRowReference, C63GpuSetupOwner,
    C63GpuStateOwner, C63GpuTileMetadata, C63SparseSetupReference, C6CacheCell, C6CacheSlotKind,
    C63_BOLT_COLUMNS, C63_BOLT_LDPC_CHECK_DEGREE, C63_BOLT_LDPC_COLUMN_DEGREE,
    C63_BOLT_LIVE_ROWS_PER_POSITION, C63_BOLT_ROWS, C63_BOLT_SKETCH_ROWS,
};

const LAYERS: usize = 12;
const WIDTH: usize = 768;
const FOLD_CHUNK: usize = C63_BOLT_SKETCH_ROWS / 2;

fn tapes() -> [Vec<Fp>; 2] {
    std::array::from_fn(|tape| {
        let mut values = Vec::with_capacity(2 * LAYERS * WIDTH);
        for kind in 0..2 {
            for layer in 0..LAYERS {
                for channel in 0..WIDTH {
                    values.push(Fp::new(
                        1 + tape as u64 * 20_000_003
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
    metadata: C63GpuTileMetadata,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Hash) {
    let mut corrections = vec![Fp::ZERO; C63_BOLT_LIVE_ROWS_PER_POSITION * C63_BOLT_COLUMNS];
    let mut sketch = vec![Fp::ZERO; C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS];
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
                            position: 0,
                            channel: channel as u16,
                        },
                        tape as u8,
                    )
                    .unwrap();
                    let row = index.row as usize;
                    let column = index.column as usize;
                    corrections[row * C63_BOLT_COLUMNS + column] = value;
                    for edge in 0..usize::from(C63_BOLT_LDPC_COLUMN_DEGREE) {
                        let socket = row * usize::from(C63_BOLT_LDPC_COLUMN_DEGREE) + edge;
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
            position: 0,
            layer_high: (row >> 9) as u8,
            channel_low: (row & 511) as u16,
            birth_epoch: metadata.birth_epoch,
            allocation_binding_digest: metadata.allocation_binding_digest,
            source_schedule_digest: metadata.source_schedule_digest,
            corrections: std::array::from_fn(|column| corrections[row * C63_BOLT_COLUMNS + column]),
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

#[test]
#[ignore = "requires the production ABI43 CUDA library and one A100"]
fn production_owner_matches_cpu_for_one_complete_token() {
    let sparse_setup = C63SparseSetupReference::sample(
        [0x63; 32],
        C63_BOLT_ROWS,
        C63_BOLT_SKETCH_ROWS,
        C63_BOLT_LDPC_COLUMN_DEGREE,
        C63_BOLT_LDPC_CHECK_DEGREE,
    )
    .unwrap();
    let tapes = tapes();
    let metadata = C63GpuTileMetadata {
        birth_epoch: 1,
        allocation_binding_digest: [0x71; 32],
        source_schedule_digest: [0x72; 32],
    };
    let profile_digest = [0x73; 32];
    let (expected_corrections, expected_sketch, expected_encoded, tile_root) =
        cpu_state(&sparse_setup, &tapes, metadata);
    let expected_correction_root =
        c63_correction_state_root_reference(profile_digest, 1, &[tile_root]).unwrap();
    let expected_encoded_root = encoded_root(&expected_encoded);

    let backend = Backend::cuda_resident().expect("initialize ABI43 resident CUDA backend");
    let guard = C62GpuResourceGuard::for_lane(19, 1, 1 << 19, 19, 1, false, 40u64 << 30).unwrap();
    let mmcs = C62GpuMmcs::new(backend, 19, guard).unwrap();
    let setup = C63GpuSetupOwner::install(&mmcs, &sparse_setup).unwrap();
    let backend = mmcs.backend();
    let tape_words = tapes.map(|values| values.into_iter().map(Fp::value).collect::<Vec<_>>());
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
}

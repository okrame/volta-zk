//! Minimal resident owner for the persistent C6.3 correction/sketch state.
//!
//! The owner stores only live correction rows, the sparse sketch and
//! Bolt's physical encoded tensor. Virtual zeros are setup-defined.

use std::fmt;
use std::sync::{Arc, Mutex};

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceMerkleTree, DeviceSlice, Fp2Repr};
use volta_field::Fp2;

use crate::c62_gpu_whir::{open_full_base_oracle, C62GpuMmcs, C62GpuMultiProof};
use crate::c63_authenticated_sketch::{
    c63_correction_rows_opening_from_resident_parts, c63_correction_state_root_reference,
    C63CorrectionRowsOpeningReference, C63SparseSetupReference, C63_BOLT_COLUMNS,
    C63_BOLT_LIVE_ROWS_PER_POSITION, C63_BOLT_ROWS, C63_BOLT_ROWS_PER_POSITION,
    C63_BOLT_SKETCH_ROWS,
};
use crate::merkle::Hash;

const C63_PHYSICAL_COMPONENTS: usize = C63_BOLT_COLUMNS * 2;
const C63_TILE_METADATA_WORDS: usize = 9;
const C63_CORRECTION_FRAME_WORDS: usize = 27;
const C63_SETUP_UPLOAD_CHUNK: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63GpuOwnerError(String);

impl C63GpuOwnerError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C63GpuOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C63GpuOwnerError {}

impl From<AccelError> for C63GpuOwnerError {
    fn from(error: AccelError) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63GpuTileMetadata {
    pub birth_epoch: u64,
    pub allocation_binding_digest: Hash,
    pub source_schedule_digest: Hash,
}

impl C63GpuTileMetadata {
    fn validate(self, epoch: u64) -> Result<(), C63GpuOwnerError> {
        if self.birth_epoch != epoch
            || self.allocation_binding_digest == [0; 32]
            || self.source_schedule_digest == [0; 32]
        {
            return Err(C63GpuOwnerError::new("invalid C6.3 append metadata"));
        }
        Ok(())
    }

    fn words(self) -> [u64; C63_TILE_METADATA_WORDS] {
        let mut words = [0u64; C63_TILE_METADATA_WORDS];
        words[0] = self.birth_epoch;
        for (index, bytes) in self.allocation_binding_digest.chunks_exact(8).enumerate() {
            words[1 + index] =
                u64::from_le_bytes(bytes.try_into().expect("eight-byte digest limb"));
        }
        for (index, bytes) in self.source_schedule_digest.chunks_exact(8).enumerate() {
            words[5 + index] =
                u64::from_le_bytes(bytes.try_into().expect("eight-byte digest limb"));
        }
        words
    }
}

/// Fixed provider state. It is uploaded once per model/profile and shared by
/// all connection-scoped accepted owners using the same CUDA backend.
pub struct C63GpuSetupOwner {
    backend: Arc<Mutex<Backend>>,
    permutation: Option<DeviceBuffer<u32>>,
    coefficients: Option<DeviceBuffer<u64>>,
    expanded_h_digest: Hash,
}

impl C63GpuSetupOwner {
    pub fn install(
        mmcs: &C62GpuMmcs,
        setup: &C63SparseSetupReference,
    ) -> Result<Self, C63GpuOwnerError> {
        if setup.dimensions() != (C63_BOLT_ROWS, C63_BOLT_SKETCH_ROWS)
            || setup.permutation().len() != C63_BOLT_ROWS * 16
            || setup.coefficients().len() != C63_BOLT_ROWS * 16
            || setup.expanded_h_digest() == [0; 32]
        {
            return Err(C63GpuOwnerError::new("C6.3 setup is not the production geometry"));
        }
        let backend = mmcs.backend();
        let mut locked = backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        let permutation = locked.upload_new_device(setup.permutation())?;
        let coefficients = match upload_coefficients(&mut locked, setup) {
            Ok(coefficients) => coefficients,
            Err(error) => {
                let _ = locked.free_device(permutation);
                return Err(error);
            }
        };
        drop(locked);
        Ok(Self {
            backend,
            permutation: Some(permutation),
            coefficients: Some(coefficients),
            expanded_h_digest: setup.expanded_h_digest(),
        })
    }

    pub fn expanded_h_digest(&self) -> Hash {
        self.expanded_h_digest
    }

    pub fn device_bytes(&self) -> u64 {
        self.permutation.as_ref().map_or(0, |buffer| buffer.len() as u64 * 4)
            + self.coefficients.as_ref().map_or(0, |buffer| buffer.len() as u64 * 8)
    }
}

impl Drop for C63GpuSetupOwner {
    fn drop(&mut self) {
        if let Ok(mut backend) = self.backend.lock() {
            if let Some(permutation) = self.permutation.take() {
                let _ = backend.free_device(permutation);
            }
            if let Some(coefficients) = self.coefficients.take() {
                let _ = backend.free_device(coefficients);
            }
        }
    }
}

/// Proposed or accepted connection-scoped state. Promotion is an owner swap;
/// constructing a proposal never mutates its predecessor.
pub struct C63GpuStateOwner {
    backend: Arc<Mutex<Backend>>,
    profile_digest: Hash,
    expanded_h_digest: Hash,
    epoch: u64,
    append_start: u16,
    accepted_len: u16,
    metadata: Vec<C63GpuTileMetadata>,
    tile_roots: Vec<Hash>,
    correction_root: Hash,
    encoded_sketch_root: Hash,
    correction_rows: Option<DeviceBuffer<u64>>,
    sketch: Option<DeviceBuffer<u64>>,
    encoded_sketch: Option<DeviceBuffer<u64>>,
    encoded_tree: Option<DeviceMerkleTree>,
}

/// Response-local projected messages. Each limb is transferred exactly once
/// into its WHIR lane; any untaken buffer is released on drop.
pub struct C63GpuProjectedMessages {
    backend: Arc<Mutex<Backend>>,
    systematic: [Option<DeviceBuffer<u64>>; 2],
    sketch: [Option<DeviceBuffer<u64>>; 2],
    encoded_sketch: [Option<DeviceBuffer<u64>>; 2],
}

impl C63GpuProjectedMessages {
    pub fn take_systematic(&mut self, limb: usize) -> Result<DeviceBuffer<u64>, C63GpuOwnerError> {
        self.systematic
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| C63GpuOwnerError::new("C6.3 systematic limb is absent"))
    }

    pub fn take_sketch(&mut self, limb: usize) -> Result<DeviceBuffer<u64>, C63GpuOwnerError> {
        self.sketch
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| C63GpuOwnerError::new("C6.3 sketch limb is absent"))
    }

    pub fn take_encoded_sketch(
        &mut self,
        limb: usize,
    ) -> Result<DeviceBuffer<u64>, C63GpuOwnerError> {
        self.encoded_sketch
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| C63GpuOwnerError::new("C6.3 encoded-sketch limb is absent"))
    }

    /// Combine the two base-field limbs into one resident extension-field
    /// message without consuming either limb.
    pub fn combined_systematic(&self) -> Result<DeviceBuffer<Fp2Repr>, C63GpuOwnerError> {
        self.combine(&self.systematic, "systematic")
    }

    /// Combine the two base-field limbs into one resident extension-field
    /// sketch without consuming either limb.
    pub fn combined_sketch(&self) -> Result<DeviceBuffer<Fp2Repr>, C63GpuOwnerError> {
        self.combine(&self.sketch, "sketch")
    }

    pub fn evaluate_combined_sketch(&self, point: &[Fp2]) -> Result<Fp2, C63GpuOwnerError> {
        self.evaluate_combined(self.combined_sketch()?, point)
    }

    pub fn evaluate_combined_systematic(&self, point: &[Fp2]) -> Result<Fp2, C63GpuOwnerError> {
        self.evaluate_combined(self.combined_systematic()?, point)
    }

    pub fn evaluate_systematic_limb(
        &self,
        limb: usize,
        point: &[Fp2],
    ) -> Result<Fp2, C63GpuOwnerError> {
        self.evaluate_limb(&self.systematic, limb, point, "systematic")
    }

    pub fn evaluate_sketch_limb(
        &self,
        limb: usize,
        point: &[Fp2],
    ) -> Result<Fp2, C63GpuOwnerError> {
        self.evaluate_limb(&self.sketch, limb, point, "sketch")
    }

    fn evaluate_limb(
        &self,
        limbs: &[Option<DeviceBuffer<u64>>; 2],
        limb: usize,
        point: &[Fp2],
        label: &str,
    ) -> Result<Fp2, C63GpuOwnerError> {
        let values = limbs
            .get(limb)
            .and_then(Option::as_ref)
            .ok_or_else(|| C63GpuOwnerError::new(format!("C6.3 {label} limb is absent")))?;
        let mut backend = self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        backend
            .mle_eval_device(DeviceSlice::new(values, 0, values.len())?, point)
            .map_err(Into::into)
    }

    fn evaluate_combined(
        &self,
        combined: DeviceBuffer<Fp2Repr>,
        point: &[Fp2],
    ) -> Result<Fp2, C63GpuOwnerError> {
        let mut backend = self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        let value = backend.mle_eval_device(DeviceSlice::new(&combined, 0, combined.len())?, point);
        let cleanup = backend.free_device(combined);
        match (value, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error.into()),
        }
    }

    fn combine(
        &self,
        limbs: &[Option<DeviceBuffer<u64>>; 2],
        label: &str,
    ) -> Result<DeviceBuffer<Fp2Repr>, C63GpuOwnerError> {
        let [Some(limb0), Some(limb1)] = limbs else {
            return Err(C63GpuOwnerError::new(format!("C6.3 {label} limb is absent")));
        };
        if limb0.len() != limb1.len() {
            return Err(C63GpuOwnerError::new(format!("C6.3 {label} limb lengths differ")));
        }
        let mut backend = self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        let combined = backend.alloc_device::<Fp2Repr>(limb0.len())?;
        let imaginary = match backend.alloc_device::<Fp2Repr>(limb1.len()) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(combined);
                return Err(error.into());
            }
        };
        let result = backend
            .fp_to_fp2_device(limb0, 0, &combined, 0, limb0.len())
            .and_then(|()| backend.fp_to_fp2_device(limb1, 0, &imaginary, 0, limb1.len()))
            .and_then(|()| {
                backend.fp2_scale_inplace_device(
                    &imaginary,
                    0,
                    imaginary.len(),
                    Fp2::new(volta_field::Fp::ZERO, volta_field::Fp::ONE),
                )
            })
            .and_then(|()| {
                backend.fp2_add_inplace_device(&combined, 0, &imaginary, 0, combined.len())
            });
        let imaginary_cleanup = backend.free_device(imaginary);
        if let Err(error) = result.and(imaginary_cleanup) {
            let _ = backend.free_device(combined);
            return Err(error.into());
        }
        Ok(combined)
    }
}

impl Drop for C63GpuProjectedMessages {
    fn drop(&mut self) {
        if let Ok(mut backend) = self.backend.lock() {
            for buffer in
                self.systematic.iter_mut().chain(&mut self.sketch).chain(&mut self.encoded_sketch)
            {
                if let Some(buffer) = buffer.take() {
                    let _ = backend.free_device(buffer);
                }
            }
        }
    }
}

impl C63GpuStateOwner {
    #[allow(clippy::too_many_arguments)]
    pub fn propose_append(
        setup: &C63GpuSetupOwner,
        predecessor: Option<&Self>,
        profile_digest: Hash,
        epoch: u64,
        tape0: DeviceSlice<'_, u64>,
        tape1: DeviceSlice<'_, u64>,
        appended_metadata: &[C63GpuTileMetadata],
    ) -> Result<Self, C63GpuOwnerError> {
        if profile_digest == [0; 32] || appended_metadata.is_empty() {
            return Err(C63GpuOwnerError::new("invalid C6.3 proposed state"));
        }
        let (old_len, mut metadata, mut tile_roots) = match predecessor {
            Some(previous) => {
                if !Arc::ptr_eq(&setup.backend, &previous.backend)
                    || previous.profile_digest != profile_digest
                    || previous.expanded_h_digest != setup.expanded_h_digest
                    || epoch
                        != previous
                            .epoch
                            .checked_add(1)
                            .ok_or_else(|| C63GpuOwnerError::new("C6.3 state epoch overflows"))?
                {
                    return Err(C63GpuOwnerError::new("C6.3 predecessor differs"));
                }
                (
                    usize::from(previous.accepted_len),
                    previous.metadata.clone(),
                    previous.tile_roots.clone(),
                )
            }
            None if epoch == 1 => (0, Vec::new(), Vec::new()),
            None => return Err(C63GpuOwnerError::new("C6.3 genesis must advance to epoch one")),
        };
        for &entry in appended_metadata {
            entry.validate(epoch)?;
        }
        let new_len = old_len
            .checked_add(appended_metadata.len())
            .filter(|&length| length <= 1024)
            .ok_or_else(|| C63GpuOwnerError::new("C6.3 accepted length overflows"))?;
        metadata.extend_from_slice(appended_metadata);

        let backend = Arc::clone(&setup.backend);
        let mut locked = backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        let mut correction_rows = None;
        let mut sketch = None;
        let mut encoded_sketch = None;
        let mut encoded_tree = None;

        let result = (|| {
            let rows = new_len * C63_BOLT_LIVE_ROWS_PER_POSITION * C63_BOLT_COLUMNS;
            correction_rows = Some(locked.alloc_device(rows)?);
            locked.zero_device(
                correction_rows.as_ref().expect("allocated corrections"),
                0,
                rows,
            )?;
            if let Some(previous) = predecessor {
                let old_elements = old_len * C63_BOLT_LIVE_ROWS_PER_POSITION * C63_BOLT_COLUMNS;
                locked.copy_device_rows(
                    DeviceSlice::new(
                        previous.correction_rows.as_ref().expect("live predecessor corrections"),
                        0,
                        old_elements,
                    )?,
                    old_elements,
                    correction_rows.as_ref().expect("allocated corrections"),
                    0,
                    old_elements,
                    1,
                    old_elements,
                )?;
            }

            sketch = Some(locked.alloc_device(C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS)?);
            if let Some(previous) = predecessor {
                let elements = C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS;
                locked.copy_device_rows(
                    DeviceSlice::new(
                        previous.sketch.as_ref().expect("live predecessor sketch"),
                        0,
                        elements,
                    )?,
                    elements,
                    sketch.as_ref().expect("allocated sketch"),
                    0,
                    elements,
                    1,
                    elements,
                )?;
            } else {
                locked.zero_device(
                    sketch.as_ref().expect("allocated sketch"),
                    0,
                    C63_BOLT_COLUMNS * C63_BOLT_SKETCH_ROWS,
                )?;
            }

            locked.c63_append_corrections_device(
                tape0,
                tape1,
                setup.permutation.as_ref().expect("live C6.3 setup permutation"),
                setup.coefficients.as_ref().expect("live C6.3 setup coefficients"),
                correction_rows.as_ref().expect("allocated corrections"),
                sketch.as_ref().expect("allocated sketch"),
                old_len,
                new_len,
            )?;

            let metadata_words =
                metadata.iter().flat_map(|entry| entry.words()).collect::<Vec<_>>();
            let metadata_device = locked.upload_new_device(&metadata_words)?;
            let tile_result = (|| {
                for position in old_len..new_len {
                    let frame = locked.c63_correction_tile_frame_device(
                        correction_rows.as_ref().expect("allocated corrections"),
                        &metadata_device,
                        new_len,
                        position,
                    )?;
                    let tree_result = locked.hash_fp_tree_device(
                        &frame,
                        C63_CORRECTION_FRAME_WORDS,
                        C63_BOLT_ROWS_PER_POSITION,
                    );
                    let frame_cleanup = locked.free_device(frame);
                    let tree = match tree_result {
                        Ok(tree) => tree,
                        Err(error) => {
                            frame_cleanup?;
                            return Err(error.into());
                        }
                    };
                    if let Err(error) = frame_cleanup {
                        let _ = locked.free_device_merkle_tree(tree);
                        return Err(error.into());
                    }
                    let root_result = locked.merkle_root_device(&tree);
                    let tree_cleanup = locked.free_device_merkle_tree(tree);
                    tile_roots.push(root_result?);
                    tree_cleanup?;
                }
                Ok::<_, C63GpuOwnerError>(())
            })();
            let metadata_cleanup = locked.free_device(metadata_device);
            tile_result?;
            metadata_cleanup?;

            let correction_root =
                c63_correction_state_root_reference(profile_digest, epoch, &tile_roots)
                    .map_err(C63GpuOwnerError::new)?;
            let padded = locked
                .c63_pad_sketch_for_encoding_device(sketch.as_ref().expect("allocated sketch"))?;
            let encoded_result = locked.ntt_fp_batch_device(
                &padded,
                0,
                C63_PHYSICAL_COMPONENTS,
                C63_BOLT_SKETCH_ROWS,
            );
            let padded_cleanup = locked.free_device(padded);
            encoded_sketch = Some(encoded_result?);
            padded_cleanup?;
            encoded_tree = Some(locked.hash_fp_tree_device(
                encoded_sketch.as_ref().expect("encoded sketch"),
                C63_PHYSICAL_COMPONENTS,
                C63_BOLT_SKETCH_ROWS,
            )?);
            let encoded_sketch_root =
                locked.merkle_root_device(encoded_tree.as_ref().expect("encoded sketch tree"))?;
            Ok::<_, C63GpuOwnerError>((correction_root, encoded_sketch_root))
        })();

        let (correction_root, encoded_sketch_root) = match result {
            Ok(roots) => roots,
            Err(error) => {
                cleanup_state_allocations(
                    &mut locked,
                    &mut encoded_tree,
                    &mut encoded_sketch,
                    &mut sketch,
                    &mut correction_rows,
                );
                return Err(error);
            }
        };
        drop(locked);
        Ok(Self {
            backend,
            profile_digest,
            expanded_h_digest: setup.expanded_h_digest,
            epoch,
            append_start: old_len as u16,
            accepted_len: new_len as u16,
            metadata,
            tile_roots,
            correction_root,
            encoded_sketch_root,
            correction_rows,
            sketch,
            encoded_sketch,
            encoded_tree,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn accepted_len(&self) -> u16 {
        self.accepted_len
    }

    pub fn append_start(&self) -> u16 {
        self.append_start
    }

    pub fn correction_root(&self) -> Hash {
        self.correction_root
    }

    pub fn encoded_sketch_root(&self) -> Hash {
        self.encoded_sketch_root
    }

    pub fn correction_rows(&self) -> DeviceSlice<'_, u64> {
        let rows = self.correction_rows.as_ref().expect("live C6.3 correction owner");
        DeviceSlice::new(rows, 0, rows.len()).expect("valid C6.3 correction owner")
    }

    pub fn sparse_sketch(&self) -> DeviceSlice<'_, u64> {
        let sketch = self.sketch.as_ref().expect("live C6.3 sketch owner");
        DeviceSlice::new(sketch, 0, sketch.len()).expect("valid C6.3 sketch owner")
    }

    pub fn encoded_sketch(&self) -> DeviceSlice<'_, u64> {
        let encoded = self.encoded_sketch.as_ref().expect("live C6.3 encoded owner");
        DeviceSlice::new(encoded, 0, encoded.len()).expect("valid C6.3 encoded owner")
    }

    pub fn encoded_tree(&self) -> &DeviceMerkleTree {
        self.encoded_tree.as_ref().expect("live C6.3 encoded tree")
    }

    /// Apply the post-root column challenge to this response's transition
    /// without materializing D', S or either projected message in host memory.
    pub fn project_transition_messages(
        &self,
        predecessor: Option<&Self>,
        rho: [Fp2; C63_BOLT_COLUMNS],
    ) -> Result<C63GpuProjectedMessages, C63GpuOwnerError> {
        match predecessor {
            Some(previous)
                if Arc::ptr_eq(&self.backend, &previous.backend)
                    && self.profile_digest == previous.profile_digest
                    && self.expanded_h_digest == previous.expanded_h_digest
                    && self.append_start == previous.accepted_len
                    && self.epoch
                        == previous.epoch.checked_add(1).ok_or_else(|| {
                            C63GpuOwnerError::new("C6.3 projection epoch overflows")
                        })? => {}
            None if self.append_start == 0 && self.epoch == 1 => {}
            _ => return Err(C63GpuOwnerError::new("C6.3 projection predecessor differs")),
        }
        let raw_rho = rho.map(Fp2Repr::from);
        let raw_negative_rho = rho.map(|value| Fp2Repr::from(Fp2::ZERO - value));
        let mut backend = self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
        let rho_device = backend.upload_new_device(&raw_rho)?;
        let negative_rho_device = match predecessor {
            Some(_) => match backend.upload_new_device(&raw_negative_rho) {
                Ok(device) => Some(device),
                Err(error) => {
                    let _ = backend.free_device(rho_device);
                    return Err(error.into());
                }
            },
            None => None,
        };
        let systematic = backend.c63_project_columns_device(
            self.correction_rows.as_ref().expect("live C6.3 correction owner"),
            &rho_device,
            Some(usize::from(self.accepted_len)),
        );
        let systematic = match systematic {
            Ok(messages) => messages,
            Err(error) => {
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        };
        if let Some(previous) = predecessor {
            let negative = backend.c63_project_columns_device(
                previous.correction_rows.as_ref().expect("live predecessor corrections"),
                negative_rho_device.as_ref().expect("uploaded negative challenge"),
                Some(usize::from(previous.accepted_len)),
            );
            if let Err(error) = negative
                .and_then(|negative| add_projected_and_release(&mut backend, &systematic, negative))
            {
                free_projected(&mut backend, systematic);
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        }
        let sketch = backend.c63_project_columns_device(
            self.sketch.as_ref().expect("live C6.3 sketch owner"),
            &rho_device,
            None,
        );
        let sketch = match sketch {
            Ok(messages) => messages,
            Err(error) => {
                free_projected(&mut backend, systematic);
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        };
        if let Some(previous) = predecessor {
            let negative = backend.c63_project_columns_device(
                previous.sketch.as_ref().expect("live predecessor sketch"),
                negative_rho_device.as_ref().expect("uploaded negative challenge"),
                None,
            );
            if let Err(error) = negative
                .and_then(|negative| add_projected_and_release(&mut backend, &sketch, negative))
            {
                free_projected(&mut backend, systematic);
                free_projected(&mut backend, sketch);
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        }
        let encoded_sketch = backend.c63_project_encoded_columns_device(
            self.encoded_sketch.as_ref().expect("live C6.3 encoded owner"),
            &rho_device,
        );
        let encoded_sketch = match encoded_sketch {
            Ok(messages) => messages,
            Err(error) => {
                free_projected(&mut backend, systematic);
                free_projected(&mut backend, sketch);
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        };
        if let Some(previous) = predecessor {
            let negative = backend.c63_project_encoded_columns_device(
                previous.encoded_sketch.as_ref().expect("live predecessor encoded sketch"),
                negative_rho_device.as_ref().expect("uploaded negative challenge"),
            );
            if let Err(error) = negative.and_then(|negative| {
                add_projected_and_release(&mut backend, &encoded_sketch, negative)
            }) {
                free_projected(&mut backend, systematic);
                free_projected(&mut backend, sketch);
                free_projected(&mut backend, encoded_sketch);
                let _ = backend.free_device(rho_device);
                if let Some(device) = negative_rho_device {
                    let _ = backend.free_device(device);
                }
                return Err(error.into());
            }
        }
        let rho_cleanup = backend.free_device(rho_device);
        let negative_cleanup = match negative_rho_device {
            Some(device) => backend.free_device(device),
            None => Ok(()),
        };
        if let Err(error) = rho_cleanup.and(negative_cleanup) {
            free_projected(&mut backend, systematic);
            free_projected(&mut backend, sketch);
            free_projected(&mut backend, encoded_sketch);
            return Err(error.into());
        }
        drop(backend);
        Ok(C63GpuProjectedMessages {
            backend: Arc::clone(&self.backend),
            systematic: systematic.map(Some),
            sketch: sketch.map(Some),
            encoded_sketch: encoded_sketch.map(Some),
        })
    }

    /// Project only one authentication tape. The returned two-limb owners are
    /// consumed before projecting the other tape, so the eight-body repair
    /// reuses the existing lane workspace.
    pub fn project_tape_messages(
        &self,
        predecessor: Option<&Self>,
        rho: [Fp2; C63_BOLT_COLUMNS],
        tape: usize,
    ) -> Result<C63GpuProjectedMessages, C63GpuOwnerError> {
        if tape >= 2 {
            return Err(C63GpuOwnerError::new("C6.3 projection tape is out of range"));
        }
        let mut masked = rho;
        for (column, coefficient) in masked.iter_mut().enumerate() {
            if column & 1 != tape {
                *coefficient = Fp2::ZERO;
            }
        }
        self.project_transition_messages(predecessor, masked)
    }

    pub(crate) fn open_encoded_sketch_rows(
        &self,
        indices: &[usize],
    ) -> Result<(Vec<Vec<Goldilocks>>, C62GpuMultiProof), C63GpuOwnerError> {
        open_full_base_oracle(
            &self.backend,
            self.encoded_sketch.as_ref().expect("live C6.3 encoded owner"),
            self.encoded_tree.as_ref().expect("live C6.3 encoded tree"),
            C63_PHYSICAL_COMPONENTS,
            C63_BOLT_SKETCH_ROWS,
            indices,
        )
        .map_err(|error| C63GpuOwnerError::new(error.to_string()))
    }

    /// Open only sampled correction rows. Accepted tile frames and trees are
    /// regenerated one at a time; the compact correction table never crosses
    /// to host and virtual rows/tiles carry no payload.
    pub fn open_correction_rows(
        &self,
        queried_rows: &[u32],
    ) -> Result<C63CorrectionRowsOpeningReference, C63GpuOwnerError> {
        if queried_rows.is_empty()
            || queried_rows.windows(2).any(|pair| pair[0] >= pair[1])
            || queried_rows.last().is_some_and(|&row| row as usize >= C63_BOLT_ROWS)
        {
            return Err(C63GpuOwnerError::new("C6.3 correction query rows are noncanonical"));
        }
        let mut positions =
            queried_rows.iter().map(|row| (*row as usize) >> 12).collect::<Vec<_>>();
        positions.dedup();
        let metadata_words =
            self.metadata.iter().flat_map(|entry| entry.words()).collect::<Vec<_>>();
        let metadata_device = self
            .backend
            .lock()
            .map_err(|_| C63GpuOwnerError::new("CUDA lock"))?
            .upload_new_device(&metadata_words)?;
        let result = (|| {
            let mut tiles = Vec::new();
            for position in positions.iter().copied().filter(|&position| {
                position >= usize::from(self.append_start)
                    && position < usize::from(self.accepted_len)
            }) {
                let locals = queried_rows
                    .iter()
                    .copied()
                    .filter(|row| (*row as usize) >> 12 == position)
                    .map(|row| (row as usize) & (C63_BOLT_ROWS_PER_POSITION - 1))
                    .collect::<Vec<_>>();
                let (frame, tree) = {
                    let mut backend =
                        self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
                    let frame = backend.c63_correction_tile_frame_device(
                        self.correction_rows.as_ref().expect("live C6.3 correction owner"),
                        &metadata_device,
                        usize::from(self.accepted_len),
                        position,
                    )?;
                    let tree = match backend.hash_fp_tree_device(
                        &frame,
                        C63_CORRECTION_FRAME_WORDS,
                        C63_BOLT_ROWS_PER_POSITION,
                    ) {
                        Ok(tree) => tree,
                        Err(error) => {
                            let _ = backend.free_device(frame);
                            return Err(error.into());
                        }
                    };
                    (frame, tree)
                };
                let opened = open_full_base_oracle(
                    &self.backend,
                    &frame,
                    &tree,
                    C63_CORRECTION_FRAME_WORDS,
                    C63_BOLT_ROWS_PER_POSITION,
                    &locals,
                );
                let cleanup = {
                    let mut backend =
                        self.backend.lock().map_err(|_| C63GpuOwnerError::new("CUDA lock"))?;
                    backend.free_device_merkle_tree(tree).and_then(|()| backend.free_device(frame))
                };
                let (rows, proof) = match (opened, cleanup) {
                    (Ok(opened), Ok(())) => opened,
                    (Err(error), _) => return Err(C63GpuOwnerError::new(error.to_string())),
                    (_, Err(error)) => return Err(error.into()),
                };
                let corrections = locals
                    .iter()
                    .zip(rows)
                    .filter(|(local, _)| **local < C63_BOLT_LIVE_ROWS_PER_POSITION)
                    .map(|(_, row)| {
                        if row.len() != C63_CORRECTION_FRAME_WORDS {
                            return Err(C63GpuOwnerError::new(
                                "C6.3 correction opening row width differs",
                            ));
                        }
                        Ok(std::array::from_fn(|column| {
                            volta_field::Fp::new(row[11 + column].as_canonical_u64())
                        }))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let metadata = (!corrections.is_empty()).then(|| {
                    let metadata = self.metadata[position];
                    (
                        metadata.birth_epoch,
                        metadata.allocation_binding_digest,
                        metadata.source_schedule_digest,
                    )
                });
                tiles.push((metadata, corrections, proof.sibling_hashes));
            }
            c63_correction_rows_opening_from_resident_parts(
                self.append_start,
                self.accepted_len,
                &self.tile_roots,
                queried_rows,
                tiles,
            )
            .map_err(C63GpuOwnerError::new)
        })();
        let cleanup = self
            .backend
            .lock()
            .map_err(|_| C63GpuOwnerError::new("CUDA lock"))?
            .free_device(metadata_device);
        match (result, cleanup) {
            (Ok(opening), Ok(())) => Ok(opening),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error.into()),
        }
    }

    pub fn device_bytes(&self) -> u64 {
        let buffers = self.correction_rows.as_ref().map_or(0, |value| value.len())
            + self.sketch.as_ref().map_or(0, |value| value.len())
            + self.encoded_sketch.as_ref().map_or(0, |value| value.len());
        let tree_hashes = 2 * C63_BOLT_SKETCH_ROWS - 1;
        buffers as u64 * 8 + tree_hashes as u64 * 32
    }
}

impl Drop for C63GpuStateOwner {
    fn drop(&mut self) {
        if let Ok(mut backend) = self.backend.lock() {
            cleanup_state_allocations(
                &mut backend,
                &mut self.encoded_tree,
                &mut self.encoded_sketch,
                &mut self.sketch,
                &mut self.correction_rows,
            );
        }
    }
}

fn add_projected_and_release(
    backend: &mut Backend,
    target: &[DeviceBuffer<u64>; 2],
    addend: [DeviceBuffer<u64>; 2],
) -> Result<(), AccelError> {
    let mut result = Ok(());
    for (target, addend) in target.iter().zip(addend) {
        if result.is_ok() {
            result = backend.fp_add_inplace_device(target, 0, &addend, 0, target.len());
        }
        if let Err(error) = backend.free_device(addend) {
            if result.is_ok() {
                result = Err(error);
            }
        }
    }
    result
}

fn free_projected(backend: &mut Backend, projected: [DeviceBuffer<u64>; 2]) {
    for message in projected {
        let _ = backend.free_device(message);
    }
}

fn upload_coefficients(
    backend: &mut Backend,
    setup: &C63SparseSetupReference,
) -> Result<DeviceBuffer<u64>, C63GpuOwnerError> {
    let output = backend.alloc_device(setup.coefficients().len())?;
    for (chunk_index, chunk) in setup.coefficients().chunks(C63_SETUP_UPLOAD_CHUNK).enumerate() {
        let canonical = chunk.iter().map(|value| value.value()).collect::<Vec<_>>();
        if let Err(error) =
            backend.upload_device(&output, chunk_index * C63_SETUP_UPLOAD_CHUNK, &canonical)
        {
            let _ = backend.free_device(output);
            return Err(error.into());
        }
    }
    Ok(output)
}

fn cleanup_state_allocations(
    backend: &mut Backend,
    tree: &mut Option<DeviceMerkleTree>,
    encoded: &mut Option<DeviceBuffer<u64>>,
    sketch: &mut Option<DeviceBuffer<u64>>,
    corrections: &mut Option<DeviceBuffer<u64>>,
) {
    if let Some(tree) = tree.take() {
        let _ = backend.free_device_merkle_tree(tree);
    }
    for buffer in [encoded, sketch, corrections] {
        if let Some(buffer) = buffer.take() {
            let _ = backend.free_device(buffer);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63GpuResourceCensus {
    pub setup_bytes: u64,
    pub accepted_state_bytes: u64,
    pub proposed_state_bytes: u64,
    pub transient_bytes: u64,
    pub reserve_bytes: u64,
}

impl C63GpuResourceCensus {
    pub fn for_transition(old_len: u16, new_len: u16) -> Result<Self, C63GpuOwnerError> {
        if old_len >= new_len || new_len > 1024 {
            return Err(C63GpuOwnerError::new("invalid C6.3 resource transition"));
        }
        let setup_bytes = C63_BOLT_ROWS as u64 * 16 * 12;
        let state_bytes = |len: u16| {
            u64::from(len) * C63_BOLT_LIVE_ROWS_PER_POSITION as u64 * C63_BOLT_COLUMNS as u64 * 8
                + 3 * C63_BOLT_COLUMNS as u64 * C63_BOLT_SKETCH_ROWS as u64 * 8
                + (2 * C63_BOLT_SKETCH_ROWS as u64 - 1) * 32
        };
        let transient_bytes = 2 * C63_BOLT_COLUMNS as u64 * C63_BOLT_SKETCH_ROWS as u64 * 8
            + C63_CORRECTION_FRAME_WORDS as u64 * C63_BOLT_ROWS_PER_POSITION as u64 * 8
            + (2 * C63_BOLT_ROWS_PER_POSITION as u64 - 1) * 32
            + if old_len == 0 { 0 } else { 2 * C63_BOLT_ROWS as u64 * 8 };
        Ok(Self {
            setup_bytes,
            accepted_state_bytes: if old_len == 0 { 0 } else { state_bytes(old_len) },
            proposed_state_bytes: state_bytes(new_len),
            transient_bytes,
            reserve_bytes: 4u64 << 30,
        })
    }

    pub fn checked_peak_bytes(self) -> Result<u64, C63GpuOwnerError> {
        self.setup_bytes
            .checked_add(self.accepted_state_bytes)
            .and_then(|value| value.checked_add(self.proposed_state_bytes))
            .and_then(|value| value.checked_add(self.transient_bytes))
            .and_then(|value| value.checked_add(self.reserve_bytes))
            .ok_or_else(|| C63GpuOwnerError::new("C6.3 resource census overflows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_resource_census_stays_small_without_dense_cache() {
        let first = C63GpuResourceCensus::for_transition(0, 150).unwrap();
        let warm = C63GpuResourceCensus::for_transition(150, 200).unwrap();
        assert_eq!(first.setup_bytes, 805_306_368);
        assert_eq!(first.checked_peak_bytes().unwrap(), 5_529_501_632);
        assert_eq!(warm.checked_peak_bytes().unwrap(), 5_910_134_688);
    }

    #[test]
    fn metadata_words_match_the_cuda_frame_layout() {
        let metadata = C63GpuTileMetadata {
            birth_epoch: 7,
            allocation_binding_digest: [0x11; 32],
            source_schedule_digest: [0x22; 32],
        };
        let words = metadata.words();
        assert_eq!(words[0], 7);
        assert_eq!(words[1..5], [u64::from_le_bytes([0x11; 8]); 4]);
        assert_eq!(words[5..9], [u64::from_le_bytes([0x22; 8]); 4]);
    }
}

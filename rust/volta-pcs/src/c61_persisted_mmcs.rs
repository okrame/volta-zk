//! Session-bound persisted Merkle prover data for C6SPX1-v1.
//!
//! Commitment and verification remain the pinned Plonky3 implementation.
//! This adapter changes only the prover-data lifecycle: after the ordinary
//! constructor computes a tree, its matrices and digest layers are written to
//! a strict ordinal file and the resident tree is released.  Openings read
//! only requested rows and frontier digests.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleTreeError, PrunedMerklePaths};

use crate::c61_whir_reference::{C61Commitment, C61Mmcs, C61MultiProof};

pub const C61_SPILL_MAGIC: [u8; 8] = *b"C6SPX1\0\0";
pub const C61_SPILL_VERSION: u16 = 1;
const C61_SPILL_FIXED_HEADER_BYTES: usize = 156;
const C61_SPILL_IO_CHUNK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C61PersistedMmcsMetrics {
    pub spill_files: u64,
    pub logical_spill_bytes: u64,
    pub host_bytes_written: u64,
    pub host_bytes_read: u64,
    pub fsync_calls: u64,
    pub current_spill_bytes: u64,
    pub peak_spill_bytes: u64,
}

#[derive(Default)]
struct Metrics {
    spill_files: AtomicU64,
    logical_spill_bytes: AtomicU64,
    host_bytes_written: AtomicU64,
    host_bytes_read: AtomicU64,
    fsync_calls: AtomicU64,
    current_spill_bytes: AtomicU64,
    peak_spill_bytes: AtomicU64,
}

impl Metrics {
    fn snapshot(&self) -> C61PersistedMmcsMetrics {
        C61PersistedMmcsMetrics {
            spill_files: self.spill_files.load(Ordering::Relaxed),
            logical_spill_bytes: self.logical_spill_bytes.load(Ordering::Relaxed),
            host_bytes_written: self.host_bytes_written.load(Ordering::Relaxed),
            host_bytes_read: self.host_bytes_read.load(Ordering::Relaxed),
            fsync_calls: self.fsync_calls.load(Ordering::Relaxed),
            current_spill_bytes: self.current_spill_bytes.load(Ordering::Relaxed),
            peak_spill_bytes: self.peak_spill_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_file(&self, file_bytes: u64, header_bytes: u64) {
        self.spill_files.fetch_add(1, Ordering::Relaxed);
        self.logical_spill_bytes.fetch_add(file_bytes, Ordering::Relaxed);
        self.host_bytes_written.fetch_add(file_bytes + header_bytes, Ordering::Relaxed);
        self.fsync_calls.fetch_add(1, Ordering::Relaxed);
        let current =
            self.current_spill_bytes.fetch_add(file_bytes, Ordering::Relaxed) + file_bytes;
        let mut peak = self.peak_spill_bytes.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_spill_bytes.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MatrixDescriptor {
    height: u64,
    width: u64,
    offset: u64,
    byte_len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LayerDescriptor {
    len: u64,
    offset: u64,
    byte_len: u64,
}

#[derive(Clone)]
pub struct C61PersistedProverData<M> {
    path: PathBuf,
    expected_header: Arc<[u8]>,
    file_len: u64,
    matrices: Arc<[MatrixDescriptor]>,
    layers: Arc<[LayerDescriptor]>,
    arity_schedule: Arc<[usize]>,
    metrics: Arc<Metrics>,
    marker: PhantomData<fn() -> M>,
}

impl<M> C61PersistedProverData<M> {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn checked_file(&self) -> File {
        let file = File::open(&self.path).expect("C6SPX1 spill file is unavailable");
        let actual_len = file.metadata().expect("C6SPX1 spill metadata is unavailable").len();
        assert_eq!(actual_len, self.file_len, "C6SPX1 spill file length changed");
        let mut header = vec![0u8; self.expected_header.len()];
        read_exact_at(&file, &mut header, 0).expect("C6SPX1 spill header read failed");
        self.metrics.host_bytes_read.fetch_add(header.len() as u64, Ordering::Relaxed);
        assert_eq!(header.as_slice(), self.expected_header.as_ref(), "C6SPX1 spill header changed");
        file
    }

    fn read_bytes(&self, file: &File, offset: u64, bytes: &mut [u8]) {
        let end = offset.checked_add(bytes.len() as u64).expect("C6SPX1 read offset overflow");
        assert!(end <= self.file_len, "C6SPX1 read exceeds spill file");
        read_exact_at(file, bytes, offset).expect("C6SPX1 spill payload read failed");
        self.metrics.host_bytes_read.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }

    fn rows_at(&self, file: &File, index: usize) -> Vec<Vec<Goldilocks>> {
        let max_height = self
            .matrices
            .iter()
            .map(|descriptor| descriptor.height as usize)
            .max()
            .expect("C6SPX1 has no matrices");
        assert!(index < max_height, "C6SPX1 opening index is out of bounds");
        let log_max = log2_ceil(max_height);
        self.matrices
            .iter()
            .map(|descriptor| {
                let height = descriptor.height as usize;
                let width = descriptor.width as usize;
                let reduced = index >> (log_max - log2_ceil(height));
                let row_bytes = width.checked_mul(8).expect("C6SPX1 row byte count overflow");
                let offset = descriptor
                    .offset
                    .checked_add((reduced * row_bytes) as u64)
                    .expect("C6SPX1 row offset overflow");
                let mut bytes = vec![0u8; row_bytes];
                self.read_bytes(file, offset, &mut bytes);
                bytes
                    .chunks_exact(8)
                    .map(|chunk| {
                        Goldilocks::from_u64(u64::from_le_bytes(chunk.try_into().unwrap()))
                    })
                    .collect()
            })
            .collect()
    }

    fn digest_at(&self, file: &File, level: usize, index: usize) -> [u8; 32] {
        let layer = self.layers.get(level).expect("C6SPX1 Merkle level is absent");
        assert!(index < layer.len as usize, "C6SPX1 Merkle index is out of bounds");
        let offset =
            layer.offset.checked_add((index * 32) as u64).expect("C6SPX1 digest offset overflow");
        let mut digest = [0u8; 32];
        self.read_bytes(file, offset, &mut digest);
        digest
    }

    fn full_path(&self, file: &File, mut index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        for (level, &arity) in self.arity_schedule.iter().enumerate() {
            let group_start = (index / arity) * arity;
            let position = index % arity;
            for child in 0..arity {
                if child != position {
                    proof.push(self.digest_at(file, level, group_start + child));
                }
            }
            index /= arity;
        }
        proof
    }

    fn pruned_path(&self, file: &File, indices: &[usize]) -> C61MultiProof {
        let mut nodes = indices.to_vec();
        nodes.sort_unstable();
        nodes.dedup();
        let mut parents = Vec::with_capacity(nodes.len());
        let mut sibling_hashes = Vec::new();
        for (level, &arity) in self.arity_schedule.iter().enumerate() {
            parents.clear();
            let mut cursor = 0;
            while cursor < nodes.len() {
                let group = nodes[cursor] / arity;
                let group_start = group * arity;
                let mut member = cursor;
                for child in 0..arity {
                    if member < nodes.len() && nodes[member] == group_start + child {
                        member += 1;
                    } else {
                        sibling_hashes.push(self.digest_at(file, level, group_start + child));
                    }
                }
                parents.push(group);
                cursor = member;
            }
            std::mem::swap(&mut nodes, &mut parents);
        }
        PrunedMerklePaths { sibling_hashes }
    }
}

#[derive(Clone)]
pub struct C61PersistedMmcs {
    inner: C61Mmcs,
    directory: Arc<PathBuf>,
    session_digest: [u8; 32],
    lane: [u8; 8],
    next_ordinal: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
    commit_gate: Arc<Mutex<()>>,
}

pub(crate) trait C61MmcsResourceMetrics {
    fn c61_persisted_metrics(&self) -> Option<C61PersistedMmcsMetrics>;

    fn c61_gpu_performance_credit(&self) -> bool {
        false
    }
}

impl C61MmcsResourceMetrics for C61Mmcs {
    fn c61_persisted_metrics(&self) -> Option<C61PersistedMmcsMetrics> {
        None
    }
}

impl C61MmcsResourceMetrics for C61PersistedMmcs {
    fn c61_persisted_metrics(&self) -> Option<C61PersistedMmcsMetrics> {
        Some(self.metrics())
    }
}

impl C61PersistedMmcs {
    pub fn new(
        inner: C61Mmcs,
        directory: impl Into<PathBuf>,
        session_digest: [u8; 32],
        lane: [u8; 8],
    ) -> Result<Self, String> {
        Self::new_with_commit_gate(inner, directory, session_digest, lane, Arc::new(Mutex::new(())))
    }

    pub fn new_with_commit_gate(
        inner: C61Mmcs,
        directory: impl Into<PathBuf>,
        session_digest: [u8; 32],
        lane: [u8; 8],
        commit_gate: Arc<Mutex<()>>,
    ) -> Result<Self, String> {
        if session_digest == [0u8; 32] || lane == [0u8; 8] {
            return Err("C6SPX1 requires nonzero session and lane bindings".to_owned());
        }
        let directory = directory.into();
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create C6SPX1 spill directory: {error}"))?;
        if !directory
            .metadata()
            .map_err(|error| format!("cannot inspect C6SPX1 spill directory: {error}"))?
            .is_dir()
        {
            return Err("C6SPX1 spill path is not a directory".to_owned());
        }
        Ok(Self {
            inner,
            directory: Arc::new(directory),
            session_digest,
            lane,
            next_ordinal: Arc::new(AtomicU64::new(0)),
            metrics: Arc::new(Metrics::default()),
            commit_gate,
        })
    }

    #[must_use]
    pub fn metrics(&self) -> C61PersistedMmcsMetrics {
        self.metrics.snapshot()
    }

    fn persist<M: Matrix<Goldilocks>>(
        &self,
        commitment: &C61Commitment,
        tree: &p3_merkle_tree::MerkleTree<Goldilocks, u8, M, 2, 32>,
    ) -> C61PersistedProverData<M> {
        assert_eq!(commitment.num_roots(), 1, "C6SPX1 admits only the frozen zero-height cap");
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::Relaxed);
        let filename = format!(
            "{:02x}{:02x}{:02x}{:02x}-oracle-{ordinal:04}.c6spx1",
            self.lane[0], self.lane[1], self.lane[2], self.lane[3]
        );
        let path = self.directory.join(filename);

        let leaves = tree.c61_spill_leaves();
        let digest_layers = tree.c61_spill_digest_layers();
        let arity_schedule = tree.c61_spill_arity_schedule();
        assert!(!leaves.is_empty(), "C6SPX1 cannot spill an empty matrix batch");
        assert_eq!(
            digest_layers.len().saturating_sub(1),
            arity_schedule.len(),
            "C6SPX1 Merkle schedule drift"
        );

        let header_len = C61_SPILL_FIXED_HEADER_BYTES
            .checked_add(leaves.len() * 32)
            .and_then(|value| value.checked_add(digest_layers.len() * 24))
            .and_then(|value| value.checked_add(arity_schedule.len() * 8))
            .and_then(|value| value.checked_add(commitment.num_roots() * 32))
            .expect("C6SPX1 header length overflow");
        let mut offset = header_len as u64;
        let mut matrices = Vec::with_capacity(leaves.len());
        for matrix in leaves {
            let byte_len = matrix
                .height()
                .checked_mul(matrix.width())
                .and_then(|value| value.checked_mul(8))
                .expect("C6SPX1 matrix length overflow") as u64;
            matrices.push(MatrixDescriptor {
                height: matrix.height() as u64,
                width: matrix.width() as u64,
                offset,
                byte_len,
            });
            offset = offset.checked_add(byte_len).expect("C6SPX1 matrix offset overflow");
        }
        let mut layers = Vec::with_capacity(digest_layers.len());
        for layer in digest_layers {
            let byte_len =
                layer.len().checked_mul(32).expect("C6SPX1 layer length overflow") as u64;
            layers.push(LayerDescriptor { len: layer.len() as u64, offset, byte_len });
            offset = offset.checked_add(byte_len).expect("C6SPX1 layer offset overflow");
        }
        let file_len = offset;

        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
            .expect("C6SPX1 refuses to reuse an existing spill ordinal");
        let mut writer = BufWriter::with_capacity(C61_SPILL_IO_CHUNK_BYTES, file);
        writer.write_all(&vec![0u8; header_len]).expect("C6SPX1 header reservation failed");
        let mut payload_hasher = blake3::Hasher::new();
        let mut chunk = Vec::with_capacity(C61_SPILL_IO_CHUNK_BYTES);
        let mut flush_chunk = |writer: &mut BufWriter<File>, chunk: &mut Vec<u8>| {
            if !chunk.is_empty() {
                payload_hasher.update(chunk);
                writer.write_all(chunk).expect("C6SPX1 payload write failed");
                chunk.clear();
            }
        };
        for matrix in leaves {
            for row in 0..matrix.height() {
                for value in matrix.row(row).expect("C6SPX1 matrix row disappeared") {
                    chunk.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
                    if chunk.len() >= C61_SPILL_IO_CHUNK_BYTES {
                        flush_chunk(&mut writer, &mut chunk);
                    }
                }
            }
        }
        for layer in digest_layers {
            for digest in layer {
                chunk.extend_from_slice(digest);
                if chunk.len() >= C61_SPILL_IO_CHUNK_BYTES {
                    flush_chunk(&mut writer, &mut chunk);
                }
            }
        }
        flush_chunk(&mut writer, &mut chunk);
        drop(flush_chunk);
        writer.flush().expect("C6SPX1 payload flush failed");
        assert_eq!(
            writer.get_ref().metadata().expect("C6SPX1 metadata failed").len(),
            file_len,
            "C6SPX1 payload length drift"
        );
        let payload_digest = *payload_hasher.finalize().as_bytes();
        let mut header = build_header(
            self.session_digest,
            self.lane,
            ordinal,
            &matrices,
            &layers,
            arity_schedule,
            commitment,
            file_len,
            payload_digest,
        );
        assert_eq!(header.len(), header_len, "C6SPX1 header geometry drift");
        let header_digest = blake3::hash(&header);
        let digest_offset = header.len() - 32;
        header[digest_offset..].copy_from_slice(header_digest.as_bytes());
        writer.get_ref().write_all_at(&header, 0).expect("C6SPX1 header seal failed");
        writer.get_ref().sync_all().expect("C6SPX1 fsync failed");
        drop(writer);
        self.metrics.record_file(file_len, header_len as u64);

        C61PersistedProverData {
            path,
            expected_header: Arc::from(header),
            file_len,
            matrices: Arc::from(matrices),
            layers: Arc::from(layers),
            arity_schedule: Arc::from(arity_schedule.to_vec()),
            metrics: Arc::clone(&self.metrics),
            marker: PhantomData,
        }
    }
}

impl Mmcs<Goldilocks> for C61PersistedMmcs {
    type ProverData<M> = C61PersistedProverData<M>;
    type Commitment = C61Commitment;
    type Proof = Vec<[u8; 32]>;
    type MultiProof = C61MultiProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let _commit_guard = self.commit_gate.lock().expect("C6SPX1 commit gate is poisoned");
        let (commitment, resident) = self.inner.commit(inputs);
        let persisted = self.persist(&commitment, &resident);
        drop(resident);
        (commitment, persisted)
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
        let file = prover_data.checked_file();
        BatchOpening::new(prover_data.rows_at(&file, index), prover_data.full_path(&file, index))
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
        &self,
        _prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        panic!("C6SPX1 deliberately exposes no resident matrices")
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        self.inner.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }

    fn open_multi_batch<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let file = prover_data.checked_file();
        let rows = indices.iter().map(|&index| prover_data.rows_at(&file, index)).collect();
        let proof = prover_data.pruned_path(&file, indices);
        (rows, proof)
    }

    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(commitment, dimensions, indices, opened_values, proof)
    }
}

fn build_header(
    session_digest: [u8; 32],
    lane: [u8; 8],
    ordinal: u64,
    matrices: &[MatrixDescriptor],
    layers: &[LayerDescriptor],
    arity_schedule: &[usize],
    commitment: &C61Commitment,
    file_len: u64,
    payload_digest: [u8; 32],
) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&C61_SPILL_MAGIC);
    header.extend_from_slice(&C61_SPILL_VERSION.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&lane);
    header.extend_from_slice(&session_digest);
    header.extend_from_slice(&ordinal.to_le_bytes());
    header.extend_from_slice(&(matrices.len() as u32).to_le_bytes());
    header.extend_from_slice(&(layers.len() as u32).to_le_bytes());
    header.extend_from_slice(&(arity_schedule.len() as u32).to_le_bytes());
    header.extend_from_slice(&(commitment.num_roots() as u32).to_le_bytes());
    let header_len = C61_SPILL_FIXED_HEADER_BYTES
        + matrices.len() * 32
        + layers.len() * 24
        + arity_schedule.len() * 8
        + commitment.num_roots() * 32;
    header.extend_from_slice(&(header_len as u64).to_le_bytes());
    header.extend_from_slice(&file_len.to_le_bytes());
    header.extend_from_slice(&payload_digest);
    for descriptor in matrices {
        header.extend_from_slice(&descriptor.height.to_le_bytes());
        header.extend_from_slice(&descriptor.width.to_le_bytes());
        header.extend_from_slice(&descriptor.offset.to_le_bytes());
        header.extend_from_slice(&descriptor.byte_len.to_le_bytes());
    }
    for descriptor in layers {
        header.extend_from_slice(&descriptor.len.to_le_bytes());
        header.extend_from_slice(&descriptor.offset.to_le_bytes());
        header.extend_from_slice(&descriptor.byte_len.to_le_bytes());
    }
    for &arity in arity_schedule {
        header.extend_from_slice(&(arity as u64).to_le_bytes());
    }
    for root in commitment.as_ref() {
        header.extend_from_slice(root);
    }
    header.extend_from_slice(&[0u8; 32]);
    header
}

fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buffer.is_empty() {
        let read = file.read_at(buffer, offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short C6SPX1 read",
            ));
        }
        offset += read as u64;
        buffer = &mut buffer[read..];
    }
    Ok(())
}

fn log2_ceil(value: usize) -> usize {
    assert!(value > 0, "C6SPX1 height must be nonzero");
    usize::BITS as usize - value.saturating_sub(1).leading_zeros() as usize
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::c61_whir_reference::c61_reference_mmcs;

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "volta-c61-spill-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn persisted_root_rows_and_pruned_frontier_are_byte_identical() {
        let directory = test_directory("identity");
        let reference = c61_reference_mmcs();
        let persisted =
            C61PersistedMmcs::new(c61_reference_mmcs(), &directory, [0x51; 32], *b"response")
                .unwrap();
        let values: Vec<_> = (0..128).map(|value| Goldilocks::from_u64(value * 17 + 3)).collect();
        let matrix = RowMajorMatrix::new(values, 2);
        let (reference_root, reference_data) = reference.commit_matrix(matrix.clone());
        let (persisted_root, persisted_data) = persisted.commit_matrix(matrix);
        assert_eq!(reference_root, persisted_root);

        let indices = [1usize, 2, 7, 18, 18, 31, 63];
        let (reference_rows, reference_proof) =
            reference.open_multi_batch(&indices, &reference_data);
        let (persisted_rows, persisted_proof) =
            persisted.open_multi_batch(&indices, &persisted_data);
        assert_eq!(reference_rows, persisted_rows);
        assert_eq!(reference_proof.sibling_hashes, persisted_proof.sibling_hashes);
        let dimensions = [Dimensions { width: 2, height: 64 }];
        reference
            .verify_multi_batch(
                &persisted_root,
                &dimensions,
                &indices,
                &persisted_rows,
                &persisted_proof,
            )
            .unwrap();
        let metrics = persisted.metrics();
        assert_eq!(metrics.spill_files, 1);
        assert!(metrics.logical_spill_bytes > 0);
        assert!(metrics.host_bytes_read < metrics.logical_spill_bytes);

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn changed_spill_header_fails_closed_before_payload_read() {
        let directory = test_directory("header");
        let persisted =
            C61PersistedMmcs::new(c61_reference_mmcs(), &directory, [0x61; 32], *b"planlane")
                .unwrap();
        let matrix =
            RowMajorMatrix::new((0..64).map(|value| Goldilocks::from_u64(value + 1)).collect(), 2);
        let (_, data) = persisted.commit_matrix(matrix);
        let file = OpenOptions::new().write(true).open(data.path()).unwrap();
        file.write_all_at(&[C61_SPILL_MAGIC[0] ^ 1], 0).unwrap();
        file.sync_all().unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = persisted.open_multi_batch(&[3], &data);
        }))
        .is_err());

        std::fs::remove_dir_all(directory).unwrap();
    }
}

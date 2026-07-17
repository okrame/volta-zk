//! Ligero-style static weight commitment over Goldilocks, with a ZK opening
//! that resolves into a VOLE-authenticated value (design: A′ in
//! docs/private-weights-pcs.md; formal interface: M9 `opening_mac_sound`).
//!
//! Layout: the flat MLE coefficient vector (LSB-first index, low `col_bits`
//! bits = matrix column, the remaining bits = matrix row) is arranged as an
//! explicit rows × cols i16 matrix; each row gets `pad` prover-secret random field
//! elements appended (column-opening ZK: any ≤ pad opened codeword positions
//! are uniform), then is RS-encoded to `2^code_bits` via NTT. One blake3
//! Merkle tree over the encoded columns is the public commitment `C_W`.
//!
//! Opening at r* (after the claims of a response are batch-reduced to one
//! point by `batch::batch_reduce_*`):
//!   W̃(r*) = q_row^T · M · q_col   with q_row/q_col = eq tables of the split
//! point. The prover sends a fresh mask-row commitment (R1, R2), the blinded
//! combinations u_q = q_row^T·Msg + R1 and u_c = c^T·Msg + R2 (c = verifier
//! proximity challenge, drawn after the mask commitment), authenticates
//! s = ⟨R1, q_col⟩ with a full correlation, and opens `n_queries` columns.
//! The evaluation itself is never revealed: with ip = ⟨u_q, q_col⟩ public,
//! the relation v* + s − ip = 0 is closed by Π_ZeroOpen on the authenticated
//! values — the verifier ends holding a MAC key on W̃(r*) bound to C_W.
//!
//! Pre-registered soundness parameters (prototype): rate = msg_len/code_len
//! ≈ 0.516 at full scale, relative distance δ ≈ 0.48; query error bounded by
//! (1 − δ/2)^Q ≈ 2^-81 for Q = 200 under the up-to-d/2 proximity analyses
//! (the conservative d/3 Ligero bound would need Q ≈ 312 — pad = 512 keeps
//! hiding headroom for that). Known limitation, logged in the ledger:
//! repeated openings reveal cumulative columns; pad covers one response's
//! queries (production: larger pad or periodic re-commit — P7 line item).

use crate::batch::BlockClaim;
use crate::merkle::{hash_leaf, verify_path, Hash, MerkleTree};
use crate::ntt::NttPlan;
use rayon::prelude::*;
use std::time::Instant;
use volta_accel::{
    AccelError, Backend, BackendKind, DeviceBuffer, DeviceElement, DeviceMerkleTree, DeviceSlice,
    Fp2Repr, Operation,
};
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_prover,
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::mle::eq_vec;

#[derive(Clone, Copy, Debug)]
pub struct LigeroParams {
    /// Physical matrix rows. This is explicit because production C3 shapes
    /// are not powers of two; the MLE row-variable count is `ceil(log2(rows))`.
    pub rows: usize,
    pub col_bits: u32,
    /// Random field elements appended to each row before encoding.
    pub pad: usize,
    pub code_bits: u32,
    pub n_queries: usize,
}

/// Full-scale parameters for the 2^27-coefficient GPT-2 small weight vector.
pub const GPT2_FULL: LigeroParams =
    LigeroParams { rows: 1 << 13, col_bits: 14, pad: 512, code_bits: 15, n_queries: 200 };

impl LigeroParams {
    pub fn rows(&self) -> usize {
        self.rows
    }
    pub fn row_bits(&self) -> u32 {
        self.rows.next_power_of_two().trailing_zeros()
    }
    pub fn cols(&self) -> usize {
        1 << self.col_bits
    }
    pub fn msg_len(&self) -> usize {
        self.cols() + self.pad
    }
    pub fn code_len(&self) -> usize {
        1 << self.code_bits
    }
    pub fn n_vars(&self) -> usize {
        (self.row_bits() + self.col_bits) as usize
    }
    pub fn validate(&self) {
        assert!(self.rows > 0, "PCS needs at least one matrix row");
        assert!(self.msg_len() <= self.code_len(), "rate > 1");
        assert!(self.n_queries <= self.pad, "column hiding needs n_queries <= pad");
    }
}

pub struct Commitment {
    pub root: Hash,
}

/// Prover-side state kept from commit to opening.
pub struct ProverMatrix {
    pub params: LigeroParams,
    /// rows × pad random message tail, row-major (prover secret).
    pads: Vec<Fp>,
    /// rows × code_len encoded matrix, row-major.
    encoded: Vec<Fp>,
    tree: MerkleTree,
}

/// Checked placement of one compact row-major i16 tensor into the packed
/// coefficient matrix used by a resident commitment. The destination stride
/// supplies per-row zero padding; all remaining target cells stay zero.
///
/// The source is borrowed and never adopted by the PCS. The commitment owns
/// a separate packed target so model weights may outlive it independently.
#[derive(Clone, Copy, Debug)]
pub struct ResidentWeightPlacement<'a> {
    source: volta_accel::DeviceSlice<'a, i16>,
    rows: usize,
    cols: usize,
    destination_offset: usize,
    destination_stride: usize,
    packed_len: usize,
    destination_end: usize,
}

impl<'a> ResidentWeightPlacement<'a> {
    pub fn new(
        source: volta_accel::DeviceSlice<'a, i16>,
        rows: usize,
        cols: usize,
        destination_offset: usize,
        destination_stride: usize,
        packed_len: usize,
    ) -> Result<Self, AccelError> {
        if rows == 0
            || cols == 0
            || destination_stride < cols
            || !destination_stride.is_power_of_two()
        {
            return Err(AccelError::InvalidInput("invalid resident weight placement geometry"));
        }
        let source_len = rows
            .checked_mul(cols)
            .ok_or(AccelError::InvalidInput("resident weight placement overflow"))?;
        if source.len() != source_len {
            return Err(AccelError::InvalidInput(
                "resident weight placement source must be exact and compact",
            ));
        }
        let padded_rows = rows
            .checked_next_power_of_two()
            .ok_or(AccelError::InvalidInput("resident weight placement overflow"))?;
        let destination_span = padded_rows
            .checked_mul(destination_stride)
            .ok_or(AccelError::InvalidInput("resident weight placement overflow"))?;
        if destination_offset % destination_span != 0 {
            return Err(AccelError::InvalidInput("resident weight placement block is not aligned"));
        }
        let destination_end = destination_offset
            .checked_add(destination_span)
            .ok_or(AccelError::InvalidInput("resident weight placement overflow"))?;
        if destination_end > packed_len {
            return Err(AccelError::InvalidInput(
                "resident weight placement exceeds packed target",
            ));
        }
        Ok(Self {
            source,
            rows,
            cols,
            destination_offset,
            destination_stride,
            packed_len,
            destination_end,
        })
    }
}

/// Device-owned commitment state. It is intentionally distinct from
/// [`ProverMatrix`]: no host encoded matrix or host Merkle tree exists, and
/// callers must explicitly return it to the creating backend for cleanup.
#[derive(Debug)]
pub struct ResidentProverMatrix {
    pub params: LigeroParams,
    weights: DeviceBuffer<i16>,
    pads: DeviceBuffer<u64>,
    encoded: DeviceBuffer<u64>,
    tree: DeviceMerkleTree,
}

/// A wrong-backend teardown is rejected before any handle is consumed, so
/// the caller can recover the complete matrix and retry with its owner.
/// `Cleanup` is reserved for an unexpected backend failure after that
/// ownership preflight; in that case cleanup remains exhaustive but may have
/// partially released the matrix.
#[derive(Debug)]
pub enum ResidentMatrixFreeError {
    WrongBackend { error: AccelError, matrix: ResidentProverMatrix },
    Cleanup(AccelError),
}

impl ResidentMatrixFreeError {
    pub fn into_matrix(self) -> Option<ResidentProverMatrix> {
        match self {
            Self::WrongBackend { matrix, .. } => Some(matrix),
            Self::Cleanup(_) => None,
        }
    }
}

/// Run one cleanup action even if an earlier action already failed, retaining
/// the first error for the caller.  Resident handles are deliberately
/// non-Clone, so a failed free consumes that handle; the owning `Backend`
/// remains the final fallback for a CUDA teardown failure.
fn cleanup_step(
    first_error: &mut Option<AccelError>,
    cleanup: impl FnOnce() -> Result<(), AccelError>,
) {
    if let Err(error) = cleanup() {
        if first_error.is_none() {
            *first_error = Some(error);
        }
    }
}

fn cleanup_device_slot<T: DeviceElement>(
    backend: &mut Backend,
    slot: &mut Option<DeviceBuffer<T>>,
    first_error: &mut Option<AccelError>,
) {
    if let Some(buffer) = slot.take() {
        cleanup_step(first_error, || backend.free_device(buffer));
    }
}

fn cleanup_tree_slot(
    backend: &mut Backend,
    slot: &mut Option<DeviceMerkleTree>,
    first_error: &mut Option<AccelError>,
) {
    if let Some(tree) = slot.take() {
        cleanup_step(first_error, || backend.free_device_merkle_tree(tree));
    }
}

/// Transactional owner for the resident allocations made while committing.
/// On the success path the four persistent handles are taken into
/// `ResidentProverMatrix`; every remaining handle is otherwise released by
/// `Drop`, including during early `?` returns.
struct ResidentCommitGuard<'a> {
    backend: &'a mut Backend,
    weights: Option<DeviceBuffer<i16>>,
    pads: Option<DeviceBuffer<u64>>,
    messages: Option<DeviceBuffer<u64>>,
    encoded: Option<DeviceBuffer<u64>>,
    tree: Option<DeviceMerkleTree>,
}

impl<'a> ResidentCommitGuard<'a> {
    fn new(backend: &'a mut Backend) -> Self {
        Self { backend, weights: None, pads: None, messages: None, encoded: None, tree: None }
    }

    fn cleanup(&mut self) -> Result<(), AccelError> {
        let mut first_error = None;
        cleanup_tree_slot(self.backend, &mut self.tree, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.encoded, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.messages, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.pads, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.weights, &mut first_error);
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for ResidentCommitGuard<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Transactional owner for every transient allocation in one resident PCS
/// opening. Handles are cleared as the normal path frees them; an early
/// return releases all handles that are still registered.
struct ResidentOpenGuard<'a> {
    backend: &'a mut Backend,
    mask_messages: Option<DeviceBuffer<Fp2Repr>>,
    mask_compact: Option<DeviceBuffer<Fp2Repr>>,
    mask_encoded: Option<DeviceBuffer<Fp2Repr>>,
    mask_tree: Option<DeviceMerkleTree>,
    c_device: Option<DeviceBuffer<Fp2Repr>>,
    u_c_device: Option<DeviceBuffer<Fp2Repr>>,
    coeff_device: Option<DeviceBuffer<Fp2Repr>>,
    coeff_row: Option<DeviceBuffer<Fp2Repr>>,
    u_g_device: Option<DeviceBuffer<Fp2Repr>>,
    mask_points: Option<DeviceBuffer<Fp2Repr>>,
    mask_eq_rows: Option<DeviceBuffer<Fp2Repr>>,
    mask_dots: Option<DeviceBuffer<Fp2Repr>>,
    indices: Option<DeviceBuffer<u32>>,
    data_columns: Option<DeviceBuffer<u64>>,
    mask_columns: Option<DeviceBuffer<Fp2Repr>>,
    data_paths: Option<DeviceBuffer<u8>>,
    mask_paths: Option<DeviceBuffer<u8>>,
}

impl<'a> ResidentOpenGuard<'a> {
    fn new(backend: &'a mut Backend) -> Self {
        Self {
            backend,
            mask_messages: None,
            mask_compact: None,
            mask_encoded: None,
            mask_tree: None,
            c_device: None,
            u_c_device: None,
            coeff_device: None,
            coeff_row: None,
            u_g_device: None,
            mask_points: None,
            mask_eq_rows: None,
            mask_dots: None,
            indices: None,
            data_columns: None,
            mask_columns: None,
            data_paths: None,
            mask_paths: None,
        }
    }

    fn cleanup(&mut self) -> Result<(), AccelError> {
        let mut first_error = None;
        cleanup_device_slot(self.backend, &mut self.mask_paths, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.data_paths, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_columns, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.data_columns, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.indices, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_dots, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_eq_rows, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_points, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.u_g_device, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.coeff_row, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.coeff_device, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.u_c_device, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.c_device, &mut first_error);
        cleanup_tree_slot(self.backend, &mut self.mask_tree, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_encoded, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_compact, &mut first_error);
        cleanup_device_slot(self.backend, &mut self.mask_messages, &mut first_error);
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for ResidentOpenGuard<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn col_bytes(col: &[Fp]) -> Vec<u8> {
    let mut b = Vec::with_capacity(col.len() * 8);
    for v in col {
        b.extend_from_slice(&v.value().to_le_bytes());
    }
    b
}

/// One-off commit. `w` is the padded coefficient vector (`rows*cols` i16,
/// caller zero-pads); `pad_seed` is prover-secret randomness for the row pads.
pub fn commit(w: &[i16], params: &LigeroParams, pad_seed: [u8; 32]) -> (Commitment, ProverMatrix) {
    commit_impl(w, params, pad_seed, None).expect("CPU PCS commitment is infallible")
}

pub fn commit_with_backend(
    w: &[i16],
    params: &LigeroParams,
    pad_seed: [u8; 32],
    backend: &mut Backend,
) -> Result<(Commitment, ProverMatrix), AccelError> {
    if backend.kind() != BackendKind::CudaHybrid {
        return Err(AccelError::InvalidInput(
            "host ProverMatrix commitment is the CUDA hybrid gate",
        ));
    }
    commit_impl(w, params, pad_seed, Some(backend))
}

/// Host-fed resident commitment checkpoint. This compatibility path uploads
/// the already-packed weight vector, but row pads are generated directly on
/// the device from the prover-secret seed fixed for this registration.
pub fn commit_resident(
    w: &[i16],
    params: &LigeroParams,
    pad_seed: [u8; 32],
    backend: &mut Backend,
) -> Result<(Commitment, ResidentProverMatrix), AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident PCS commitment requires the cuda-resident backend",
        ));
    }
    params.validate();
    let (rows, cols) = (params.rows(), params.cols());
    if w.len() != rows * cols {
        return Err(AccelError::InvalidInput("resident PCS weight geometry mismatch"));
    }
    let mut resident = ResidentCommitGuard::new(backend);
    resident.weights = Some(resident.backend.upload_new_device(w)?);
    finish_resident_commit(resident, params, pad_seed)
}

/// Build a resident commitment from existing context-owned tensor slices.
/// The PCS allocates and zeroes its own packed target, then performs exact
/// row-strided D2D placements; no flattened host weight vector is created or
/// uploaded. `pad_seed` is prover-secret randomness fixed for this weight
/// registration (it need not be response-fresh) and must not be a transcript
/// challenge, shared mock-PCG seed, or verifier secret.
pub fn commit_resident_from_device(
    placements: &[ResidentWeightPlacement<'_>],
    params: &LigeroParams,
    pad_seed: [u8; 32],
    backend: &mut Backend,
) -> Result<(Commitment, ResidentProverMatrix), AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident PCS commitment requires the cuda-resident backend",
        ));
    }
    params.validate();
    let packed_len = params
        .rows()
        .checked_mul(params.cols())
        .ok_or(AccelError::InvalidInput("resident PCS weight geometry overflow"))?;
    if placements.is_empty() {
        return Err(AccelError::InvalidInput("resident PCS needs a weight placement"));
    }
    let mut ranges = Vec::with_capacity(placements.len());
    for placement in placements {
        if placement.packed_len != packed_len {
            return Err(AccelError::InvalidInput(
                "resident weight placement targets the wrong PCS geometry",
            ));
        }
        if !placement.source.buffer().is_owned_by(backend) {
            return Err(AccelError::InvalidInput(
                "resident weight placement belongs to a different CUDA context",
            ));
        }
        ranges.push((placement.destination_offset, placement.destination_end));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(AccelError::InvalidInput("resident weight placements overlap"));
    }

    let mut resident = ResidentCommitGuard::new(backend);
    resident.weights = Some(resident.backend.alloc_device(packed_len)?);
    resident.backend.zero_device(
        resident.weights.as_ref().expect("resident packed weights registered"),
        0,
        packed_len,
    )?;
    for placement in placements {
        resident.backend.copy_device_rows(
            placement.source,
            placement.cols,
            resident.weights.as_ref().expect("resident packed weights registered"),
            placement.destination_offset,
            placement.destination_stride,
            placement.rows,
            placement.cols,
        )?;
    }
    finish_resident_commit(resident, params, pad_seed)
}

fn finish_resident_commit(
    mut resident: ResidentCommitGuard<'_>,
    params: &LigeroParams,
    pad_seed: [u8; 32],
) -> Result<(Commitment, ResidentProverMatrix), AccelError> {
    let (rows, cols, pad, code_len) = (params.rows(), params.cols(), params.pad, params.code_len());
    resident.pads =
        Some(resident.backend.chacha8_prover_secret_fp_rows_device(pad_seed, 0, rows, pad)?);
    resident.messages = Some(resident.backend.pcs_messages_device(
        resident.weights.as_ref().expect("resident weights registered"),
        0,
        resident.pads.as_ref().expect("resident pads registered"),
        0,
        rows,
        cols,
        pad,
        code_len,
    )?);
    resident.encoded = Some(resident.backend.ntt_fp_batch_device(
        resident.messages.as_ref().expect("resident messages registered"),
        0,
        rows,
        code_len,
    )?);
    resident
        .backend
        .free_device(resident.messages.take().expect("resident messages registered"))?;
    resident.tree = Some(resident.backend.hash_fp_tree_device(
        resident.encoded.as_ref().expect("resident encoding registered"),
        rows,
        code_len,
    )?);
    let root = resident
        .backend
        .merkle_root_device(resident.tree.as_ref().expect("resident tree registered"))?;
    let weights = resident.weights.take().expect("resident weights registered");
    let pads = resident.pads.take().expect("resident pads registered");
    let encoded = resident.encoded.take().expect("resident encoding registered");
    let tree = resident.tree.take().expect("resident tree registered");
    Ok((
        Commitment { root },
        ResidentProverMatrix { params: *params, weights, pads, encoded, tree },
    ))
}

/// Release every allocation owned by a resident commitment. All components
/// are attempted even after a failure; the first cleanup error is returned.
pub fn free_resident_matrix(
    pm: ResidentProverMatrix,
    backend: &mut Backend,
) -> Result<(), ResidentMatrixFreeError> {
    let owned = pm.weights.is_owned_by(backend)
        && pm.pads.is_owned_by(backend)
        && pm.encoded.is_owned_by(backend)
        && pm.tree.is_owned_by(backend);
    if !owned {
        return Err(ResidentMatrixFreeError::WrongBackend {
            error: AccelError::InvalidInput(
                "resident prover matrix belongs to a different CUDA context",
            ),
            matrix: pm,
        });
    }
    let ResidentProverMatrix { params: _, weights, pads, encoded, tree } = pm;
    let mut resident = ResidentCommitGuard {
        backend,
        weights: Some(weights),
        pads: Some(pads),
        messages: None,
        encoded: Some(encoded),
        tree: Some(tree),
    };
    resident.cleanup().map_err(ResidentMatrixFreeError::Cleanup)
}

fn commit_impl(
    w: &[i16],
    params: &LigeroParams,
    pad_seed: [u8; 32],
    mut backend: Option<&mut Backend>,
) -> Result<(Commitment, ProverMatrix), AccelError> {
    params.validate();
    let (rows, cols, pad, code_len) = (params.rows(), params.cols(), params.pad, params.code_len());
    assert_eq!(w.len(), rows * cols, "caller pads W to rows*cols");
    let plan = NttPlan::new(code_len);

    // Per-row random pads (prover secret, one stream per row).
    let make_pads = || {
        (0..rows)
            .into_par_iter()
            .flat_map_iter(|r| {
                let mut s = FpStream::domain_separated(pad_seed, r as u64);
                (0..pad).map(move |_| s.next_fp()).collect::<Vec<_>>()
            })
            .collect::<Vec<Fp>>()
    };
    let pads = if let Some(accel) = backend.as_deref_mut() {
        accel.cpu_residual(Operation::PcsRows, make_pads)?
    } else {
        make_pads()
    };

    // Encode every row: (embed(w row) ‖ pads) zero-padded to code_len.
    let encoded = if let Some(accel) = backend.as_deref_mut() {
        let messages = accel.cpu_residual(Operation::PcsRows, || {
            let mut messages = vec![Fp::ZERO; rows * params.msg_len()];
            messages.par_chunks_mut(params.msg_len()).enumerate().for_each(|(r, out)| {
                for j in 0..cols {
                    out[j] = Fp::from_i64(w[r * cols + j] as i64);
                }
                out[cols..cols + pad].copy_from_slice(&pads[r * pad..(r + 1) * pad]);
            });
            messages
        })?;
        accel.ntt_fp_batch(&messages, rows, params.msg_len(), code_len)?
    } else {
        let mut encoded = vec![Fp::ZERO; rows * code_len];
        encoded.par_chunks_mut(code_len).enumerate().for_each(|(r, out)| {
            for j in 0..cols {
                out[j] = Fp::from_i64(w[r * cols + j] as i64);
            }
            out[cols..cols + pad].copy_from_slice(&pads[r * pad..(r + 1) * pad]);
            plan.forward(out);
        });
        encoded
    };

    // Column leaf hashes, tiled so the strided gather stays cache-friendly.
    let tile = 128.min(code_len);
    let leaves: Vec<Hash> = if let Some(accel) = backend.as_deref_mut() {
        accel.hash_fp_columns(&encoded, rows, code_len)?
    } else {
        (0..code_len / tile)
            .into_par_iter()
            .flat_map_iter(|t| {
                let j0 = t * tile;
                let mut buf = vec![Fp::ZERO; rows * tile];
                for i in 0..rows {
                    let row = &encoded[i * code_len + j0..i * code_len + j0 + tile];
                    for (dj, &v) in row.iter().enumerate() {
                        buf[dj * rows + i] = v;
                    }
                }
                (0..tile)
                    .map(|dj| hash_leaf(&col_bytes(&buf[dj * rows..(dj + 1) * rows])))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let tree = if let Some(accel) = backend.as_deref_mut() {
        accel.cpu_residual(Operation::PcsMerkle, || MerkleTree::from_leaves(leaves))?
    } else {
        MerkleTree::from_leaves(leaves)
    };

    Ok((Commitment { root: tree.root() }, ProverMatrix { params: *params, pads, encoded, tree }))
}

pub struct ColumnOpening {
    pub j: u32,
    /// The queried encoded column of C_W (rows values).
    pub col: Vec<Fp>,
    /// (R̂1[j], R̂2[j]) from the per-opening mask commitment.
    pub mask_col: [Fp2; 2],
    pub path: Vec<Hash>,
    pub mask_path: Vec<Hash>,
}

pub struct OpeningProof {
    pub mask_root: Hash,
    /// Blinded eval combination q_row^T·Msg + R1 (message coords).
    pub u_q: Vec<Fp2>,
    /// Blinded proximity combination c^T·Msg + R2.
    pub u_c: Vec<Fp2>,
    /// Correction authenticating s = ⟨R1, q_col⟩.
    pub corr_s: Fp2,
    pub columns: Vec<ColumnOpening>,
    /// Π_ZeroOpen tag for v* + s − ip = 0.
    pub m_z: Fp2,
}

impl OpeningProof {
    pub fn bytes(&self) -> u64 {
        let cols_b: u64 = self
            .columns
            .iter()
            .map(|c| {
                4 + 8 * c.col.len() as u64 + 64 + 32 * (c.path.len() + c.mask_path.len()) as u64
            })
            .sum();
        32 + 16 * (self.u_q.len() + self.u_c.len()) as u64 + 16 + cols_b + 16
    }
}

#[derive(Default, Clone, Copy)]
pub struct OpenTimings {
    /// Mask rows: draw, encode, Merkle.
    pub t_masks_s: f64,
    /// The O(|W|) row-combination passes (u_q and u_c fused).
    pub t_row_combine_s: f64,
    /// s, ip, corrections.
    pub t_ip_s: f64,
    /// Column gather + Merkle paths.
    pub t_columns_s: f64,
}

impl OpenTimings {
    pub fn total_s(&self) -> f64 {
        self.t_masks_s + self.t_row_combine_s + self.t_ip_s + self.t_columns_s
    }
}

/// Fused u_q/u_c row combination over the data block and the pad block.
fn combine_rows(
    w: &[i16],
    pads: &[Fp],
    params: &LigeroParams,
    q_row: &[Fp2],
    c_pows: &[Fp2],
) -> (Vec<Fp2>, Vec<Fp2>) {
    let (rows, cols, pad) = (params.rows(), params.cols(), params.pad);
    let msg_len = params.msg_len();
    let mut u_q = vec![Fp2::ZERO; msg_len];
    let mut u_c = vec![Fp2::ZERO; msg_len];

    // Data block: chunk the column range; each task walks all rows once.
    let n_chunks = rayon::current_num_threads() * 4;
    let chunk = cols.div_ceil(n_chunks);
    u_q[..cols].par_chunks_mut(chunk).zip(u_c[..cols].par_chunks_mut(chunk)).enumerate().for_each(
        |(ci, (uq, uc))| {
            let j0 = ci * chunk;
            for i in 0..rows {
                let (qi, cpi) = (q_row[i], c_pows[i]);
                let row = &w[i * cols + j0..i * cols + j0 + uq.len()];
                for (dj, &v) in row.iter().enumerate() {
                    let x = Fp::from_i64(v as i64);
                    uq[dj] += qi.mul_base(x);
                    uc[dj] += cpi.mul_base(x);
                }
            }
        },
    );
    // Pad block (rows × pad, small).
    for i in 0..rows {
        let (qi, cpi) = (q_row[i], c_pows[i]);
        for p in 0..pad {
            let x = pads[i * pad + p];
            u_q[cols + p] += qi.mul_base(x);
            u_c[cols + p] += cpi.mul_base(x);
        }
    }
    (u_q, u_c)
}

fn encode_fp2(plan: &NttPlan, v: &[Fp2]) -> Vec<Fp2> {
    let c0: Vec<Fp> = v.iter().map(|x| x.c0).collect();
    let c1: Vec<Fp> = v.iter().map(|x| x.c1).collect();
    let e0 = plan.encode(&c0);
    let e1 = plan.encode(&c1);
    e0.into_iter().zip(e1).map(|(a, b)| Fp2::new(a, b)).collect()
}

fn mask_leaf(r1: Fp2, r2: Fp2) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&r1.c0.value().to_le_bytes());
    b[8..16].copy_from_slice(&r1.c1.value().to_le_bytes());
    b[16..24].copy_from_slice(&r2.c0.value().to_le_bytes());
    b[24..].copy_from_slice(&r2.c1.value().to_le_bytes());
    hash_leaf(&b)
}

/// ZK opening of the batched claim `v* = W̃(point)` (authenticated), resolving
/// into the verifier's MAC key — the evaluation never appears in clear.
/// `mask_seed` is fresh prover-secret randomness for R1/R2.
pub fn open_zk(
    w: &[i16],
    pm: &ProverMatrix,
    point: &[Fp2],
    v_star: ProverAuthed,
    stream: &mut CorrelationStream,
    dom_s: u64,
    mask_seed: [u8; 32],
    tx: &mut Transcript,
) -> (OpeningProof, OpenTimings) {
    let params = &pm.params;
    assert_eq!(point.len(), params.n_vars());
    let (rows, cols, msg_len, code_len) =
        (params.rows(), params.cols(), params.msg_len(), params.code_len());
    let plan = NttPlan::new(code_len);
    let mut tm = OpenTimings::default();

    // 1. Fresh mask rows R1, R2 ∈ E^msg_len, committed before any challenge.
    let t0 = Instant::now();
    let mut ms = FpStream::from_seed(mask_seed);
    let r1: Vec<Fp2> = (0..msg_len).map(|_| ms.next_fp2()).collect();
    let r2: Vec<Fp2> = (0..msg_len).map(|_| ms.next_fp2()).collect();
    let r1_enc = encode_fp2(&plan, &r1);
    let r2_enc = encode_fp2(&plan, &r2);
    let mask_tree =
        MerkleTree::from_leaves((0..code_len).map(|j| mask_leaf(r1_enc[j], r2_enc[j])).collect());
    tx.append("pcs_mask_root", 32);
    tm.t_masks_s = t0.elapsed().as_secs_f64();

    // 2. Proximity challenge (after the mask commitment).
    let c = tx.challenge_fp2();
    let mut c_pows = Vec::with_capacity(rows);
    let mut acc = Fp2::ONE;
    for _ in 0..rows {
        acc = acc * c;
        c_pows.push(acc);
    }
    let q_col = eq_vec(&point[..params.col_bits as usize]);
    let q_row = eq_vec(&point[params.col_bits as usize..]);

    // 3. Blinded combinations.
    let t1 = Instant::now();
    let (mut u_q, mut u_c) = combine_rows(w, &pm.pads, params, &q_row, &c_pows);
    for j in 0..msg_len {
        u_q[j] += r1[j];
        u_c[j] += r2[j];
    }
    tx.append("pcs_u_vectors", 2 * 16 * msg_len as u64);
    tm.t_row_combine_s = t1.elapsed().as_secs_f64();

    // 4. Authenticate s = ⟨R1, q_col⟩; ip = ⟨u_q, q_col⟩ is public.
    let t2 = Instant::now();
    let s_val = (0..cols).fold(Fp2::ZERO, |a, j| a + r1[j] * q_col[j]);
    let ip = (0..cols).fold(Fp2::ZERO, |a, j| a + u_q[j] * q_col[j]);
    let fc = stream.draw_fulls(dom_s, 1)[0];
    let corr_s = s_val - fc.x;
    tx.append("pcs_s_correction", 16);
    let s_auth = ProverAuthed { x: s_val, m: fc.m };
    tm.t_ip_s = t2.elapsed().as_secs_f64();

    // 5. Column queries (public coins after all prover messages above).
    let t3 = Instant::now();
    let js: Vec<usize> =
        (0..params.n_queries).map(|_| tx.challenge_fp2().c0.value() as usize % code_len).collect();
    let columns: Vec<ColumnOpening> = js
        .iter()
        .map(|&j| {
            let col: Vec<Fp> = (0..rows).map(|i| pm.encoded[i * code_len + j]).collect();
            ColumnOpening {
                j: j as u32,
                path: pm.tree.open(j),
                mask_path: mask_tree.open(j),
                mask_col: [r1_enc[j], r2_enc[j]],
                col,
            }
        })
        .collect();
    let col_b: u64 = columns
        .iter()
        .map(|c| 4 + 8 * c.col.len() as u64 + 64 + 32 * (c.path.len() + c.mask_path.len()) as u64)
        .sum();
    tx.append("pcs_columns", col_b);
    tm.t_columns_s = t3.elapsed().as_secs_f64();

    // 6. MAC resolution (M9): v* + s − ip = 0, opened via Π_ZeroOpen.
    let z = v_star.add(s_auth).sub(ProverAuthed::from_public(ip));
    let m_z = zero_open_prover(&z, tx);

    (OpeningProof { mask_root: mask_tree.root(), u_q, u_c, corr_s, columns, m_z }, tm)
}

/// Verifier: checks the opening against `C_W` and the authenticated claim key
/// `k_vstar` (from `batch_reduce_verifier`). On acceptance the verifier's
/// `k_vstar` is bound to the committed W̃(point) — no cleartext value seen.
pub fn verify_open(
    root: &Hash,
    params: &LigeroParams,
    point: &[Fp2],
    k_vstar: VerifierKey,
    proof: &OpeningProof,
    ctx: &mut VerifierCtx,
    dom_s: u64,
    tx: &mut Transcript,
) -> bool {
    let (rows, cols, msg_len, code_len) =
        (params.rows(), params.cols(), params.msg_len(), params.code_len());
    if proof.u_q.len() != msg_len
        || proof.u_c.len() != msg_len
        || proof.columns.len() != params.n_queries
        || proof.columns.iter().any(|co| co.col.len() != rows)
    {
        return false;
    }
    let plan = NttPlan::new(code_len);

    // Same challenge order as the prover: c, then the queried columns.
    let c = tx.challenge_fp2();
    let mut c_pows = Vec::with_capacity(rows);
    let mut acc = Fp2::ONE;
    for _ in 0..rows {
        acc = acc * c;
        c_pows.push(acc);
    }
    let q_col = eq_vec(&point[..params.col_bits as usize]);
    let q_row = eq_vec(&point[params.col_bits as usize..]);

    let k_s = VerifierKey { k: ctx.expand_full_keys(dom_s, 1)[0] + ctx.delta * proof.corr_s };
    let ip = (0..cols).fold(Fp2::ZERO, |a, j| a + proof.u_q[j] * q_col[j]);

    let js: Vec<usize> =
        (0..params.n_queries).map(|_| tx.challenge_fp2().c0.value() as usize % code_len).collect();

    let enc_uq = encode_fp2(&plan, &proof.u_q);
    let enc_uc = encode_fp2(&plan, &proof.u_c);
    for (q, co) in proof.columns.iter().enumerate() {
        let j = co.j as usize;
        if j != js[q] {
            return false;
        }
        if !verify_path(root, j, hash_leaf(&col_bytes(&co.col)), &co.path) {
            return false;
        }
        if !verify_path(
            &proof.mask_root,
            j,
            mask_leaf(co.mask_col[0], co.mask_col[1]),
            &co.mask_path,
        ) {
            return false;
        }
        let mut sum_q = Fp2::ZERO;
        let mut sum_c = Fp2::ZERO;
        for i in 0..rows {
            sum_q += q_row[i].mul_base(co.col[i]);
            sum_c += c_pows[i].mul_base(co.col[i]);
        }
        if enc_uq[j] != sum_q + co.mask_col[0] || enc_uc[j] != sum_c + co.mask_col[1] {
            return false;
        }
    }

    // MAC resolution: k(v* + s − ip) must open to zero.
    let k_z = k_vstar.add(k_s).sub(VerifierKey::from_public(ip, ctx.delta));
    zero_open_verify(k_z, proof.m_z)
}

// ---------------------------------------------------------------------------
// Row-local multi-eval opening (P3.5 iteration after the first measurement:
// the generic multi-point → single-point reduction sumcheck costs O(|W|)
// E-field work and dominated everything; block-aligned claims make it
// unnecessary. Each weight tensor's block spans whole matrix rows, so a claim
// on block g needs a masked row combination over ONLY its block's rows. All
// claims share one column-query set and one proximity test, and all resolve
// into MACs through a single Π_ZeroBatch — no reduction sumcheck at all.)
// ---------------------------------------------------------------------------

/// Per-claim geometry on the Ligero matrix.
struct ClaimGeom {
    /// First matrix row of the block.
    row0: usize,
    /// eq table over the block's row variables.
    q_row: Vec<Fp2>,
    /// eq table over the (shared) column variables.
    q_col: Vec<Fp2>,
}

fn claim_geom(params: &LigeroParams, c: &BlockClaim) -> Option<ClaimGeom> {
    let cb = params.col_bits as usize;
    let bv = c.point.len();
    if bv < cb || bv > params.n_vars() {
        return None;
    }
    let block_len = 1usize.checked_shl(bv as u32)?;
    if c.offset % block_len != 0 {
        return None;
    }
    let row_count = 1usize.checked_shl((bv - cb) as u32)?;
    let row0 = c.offset >> cb;
    if row0.checked_add(row_count).is_none_or(|end| end > params.rows()) {
        return None;
    }
    Some(ClaimGeom { row0, q_row: eq_vec(&c.point[cb..]), q_col: eq_vec(&c.point[..cb]) })
}

fn resident_claim_row0(params: &LigeroParams, claim: &BlockClaim) -> Result<usize, AccelError> {
    let col_bits = params.col_bits as usize;
    if claim.point.len() < col_bits {
        return Err(AccelError::InvalidInput("resident PCS block is smaller than a matrix row"));
    }
    let block_len = 1usize
        .checked_shl(claim.point.len() as u32)
        .ok_or(AccelError::InvalidInput("resident PCS claim geometry overflow"))?;
    if claim.offset % block_len != 0 {
        return Err(AccelError::InvalidInput("resident PCS block offset is not aligned"));
    }
    let row_count = 1usize
        .checked_shl((claim.point.len() - col_bits) as u32)
        .ok_or(AccelError::InvalidInput("resident PCS claim geometry overflow"))?;
    let row0 = claim.offset >> col_bits;
    if row0.checked_add(row_count).is_none_or(|end| end > params.rows()) {
        return Err(AccelError::InvalidInput("resident PCS claim rows exceed matrix"));
    }
    Ok(row0)
}

#[derive(Debug, PartialEq, Eq)]
pub struct MultiColumnOpening {
    pub j: u32,
    pub col: Vec<Fp>,
    /// (R̂_c[j], R̂_1[j], …, R̂_G[j]): proximity mask then one mask per claim.
    pub mask_col: Vec<Fp2>,
    pub path: Vec<Hash>,
    pub mask_path: Vec<Hash>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MultiOpenProof {
    pub mask_root: Hash,
    /// Blinded global proximity combination c^T·Msg + R_c.
    pub u_c: Vec<Fp2>,
    /// Per claim: blinded block-local combination q_row^T·Msg|block + R_g.
    pub u_gs: Vec<Vec<Fp2>>,
    /// Per claim: correction authenticating s_g = ⟨R_g, q_col_g⟩.
    pub corr_ss: Vec<Fp2>,
    /// Π_ZeroBatch mask re-centring correction.
    pub mask_corr: Fp2,
    /// Batched zero tag for {v_g + s_g − ip_g}.
    pub m_z: Fp2,
    pub columns: Vec<MultiColumnOpening>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiOpenByteBreakdown {
    pub mask_root: u64,
    pub u_vectors: u64,
    pub corr_ss: u64,
    pub zero_batch: u64,
    pub column_indices: u64,
    pub data_columns: u64,
    pub mask_columns: u64,
    pub commitment_merkle_paths: u64,
    pub mask_merkle_paths: u64,
    pub columns_total: u64,
    pub total: u64,
    /// Conservative marginal byte cut if the verifier already has the static
    /// queried data columns and their commitment Merkle paths cached.
    pub cached_query_cut_bytes: u64,
    pub cached_query_marginal_bytes: u64,
}

/// Exact wire-size projection for the existing unpruned two-Merkle-path
/// multi-opening format. This is also valid before materializing a proof and
/// is therefore used to pin C3 production geometries without allocating the
/// multi-gigabyte encoded matrices.
pub fn projected_multi_open_bytes(
    params: &LigeroParams,
    n_claims: usize,
) -> MultiOpenByteBreakdown {
    params.validate();
    assert!(n_claims > 0, "multi-opening needs at least one claim");
    let queries = params.n_queries as u64;
    let mut b = MultiOpenByteBreakdown {
        mask_root: 32,
        u_vectors: 16 * params.msg_len() as u64 * (n_claims as u64 + 1),
        corr_ss: 16 * n_claims as u64,
        zero_batch: 32,
        column_indices: 4 * queries,
        data_columns: 8 * params.rows() as u64 * queries,
        mask_columns: 16 * (n_claims as u64 + 1) * queries,
        commitment_merkle_paths: 32 * params.code_bits as u64 * queries,
        mask_merkle_paths: 32 * params.code_bits as u64 * queries,
        ..Default::default()
    };
    b.columns_total = b.column_indices
        + b.data_columns
        + b.mask_columns
        + b.commitment_merkle_paths
        + b.mask_merkle_paths;
    b.total = b.mask_root + b.u_vectors + b.corr_ss + b.zero_batch + b.columns_total;
    b.cached_query_cut_bytes = b.data_columns + b.commitment_merkle_paths;
    b.cached_query_marginal_bytes = b.total - b.cached_query_cut_bytes;
    b
}

impl MultiOpenProof {
    pub fn byte_breakdown(&self) -> MultiOpenByteBreakdown {
        let mut b = MultiOpenByteBreakdown {
            mask_root: 32,
            u_vectors: 16
                * (self.u_c.len() + self.u_gs.iter().map(|u| u.len()).sum::<usize>()) as u64,
            corr_ss: 16 * self.corr_ss.len() as u64,
            zero_batch: 32, // mask_corr + m_z
            ..Default::default()
        };
        for c in &self.columns {
            b.column_indices += 4;
            b.data_columns += 8 * c.col.len() as u64;
            b.mask_columns += 16 * c.mask_col.len() as u64;
            b.commitment_merkle_paths += 32 * c.path.len() as u64;
            b.mask_merkle_paths += 32 * c.mask_path.len() as u64;
        }
        b.columns_total = b.column_indices
            + b.data_columns
            + b.mask_columns
            + b.commitment_merkle_paths
            + b.mask_merkle_paths;
        b.total = b.mask_root + b.u_vectors + b.corr_ss + b.zero_batch + b.columns_total;
        b.cached_query_cut_bytes = b.data_columns + b.commitment_merkle_paths;
        b.cached_query_marginal_bytes = b.total - b.cached_query_cut_bytes;
        b
    }

    pub fn bytes(&self) -> u64 {
        self.byte_breakdown().total
    }

    pub fn cached_query_marginal_bytes(&self) -> u64 {
        self.byte_breakdown().cached_query_marginal_bytes
    }
}

#[derive(Default, Clone, Copy)]
pub struct MultiOpenTimings {
    /// Mask rows: draw, encode, Merkle.
    pub t_masks_s: f64,
    /// Global proximity pass (the one O(|W|) cheap pass).
    pub t_global_pass_s: f64,
    /// Per-claim block-local row combinations.
    pub t_block_passes_s: f64,
    /// s_g, ip_g, ZeroBatch.
    pub t_ip_zb_s: f64,
    /// Column gather + Merkle paths.
    pub t_columns_s: f64,
}

impl MultiOpenTimings {
    pub fn total_s(&self) -> f64 {
        self.t_masks_s
            + self.t_global_pass_s
            + self.t_block_passes_s
            + self.t_ip_zb_s
            + self.t_columns_s
    }
}

/// Combine message rows [row0, row0+coeffs.len()) with `coeffs` (no mask).
fn combine_row_range(
    w: &[i16],
    pads: &[Fp],
    params: &LigeroParams,
    row0: usize,
    coeffs: &[Fp2],
) -> Vec<Fp2> {
    let (cols, pad) = (params.cols(), params.pad);
    let mut u = vec![Fp2::ZERO; params.msg_len()];
    for (di, &ci) in coeffs.iter().enumerate() {
        let i = row0 + di;
        let row = &w[i * cols..(i + 1) * cols];
        for (j, &v) in row.iter().enumerate() {
            u[j] += ci.mul_base(Fp::from_i64(v as i64));
        }
        for p in 0..pad {
            u[cols + p] += ci.mul_base(pads[i * pad + p]);
        }
    }
    u
}

fn multi_mask_leaf(vals: &[Fp2]) -> Hash {
    let mut b = Vec::with_capacity(vals.len() * 16);
    for v in vals {
        b.extend_from_slice(&v.c0.value().to_le_bytes());
        b.extend_from_slice(&v.c1.value().to_le_bytes());
    }
    hash_leaf(&b)
}

/// Multi-claim ZK opening: every authenticated claim is bound to C_W directly
/// (block-local row combinations, shared columns, one Π_ZeroBatch).
/// Correlation use: `dom_s` (G full corrs for the s_g), `dom_zb` (ZeroBatch
/// mask). Claim values were authenticated upstream.
pub fn open_multi_zk(
    w: &[i16],
    pm: &ProverMatrix,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    dom_s: u64,
    dom_zb: u64,
    mask_seed: [u8; 32],
    tx: &mut Transcript,
) -> (MultiOpenProof, MultiOpenTimings) {
    open_multi_zk_impl(w, pm, claims, stream, dom_s, dom_zb, mask_seed, tx, None)
        .expect("CPU PCS opening is infallible")
}

#[allow(clippy::too_many_arguments)]
pub fn open_multi_zk_with_backend(
    w: &[i16],
    pm: &ProverMatrix,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    dom_s: u64,
    dom_zb: u64,
    mask_seed: [u8; 32],
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(MultiOpenProof, MultiOpenTimings), AccelError> {
    if backend.kind() != BackendKind::CudaHybrid {
        return Err(AccelError::InvalidInput("host ProverMatrix opening is the CUDA hybrid gate"));
    }
    open_multi_zk_impl(w, pm, claims, stream, dom_s, dom_zb, mask_seed, tx, Some(backend))
}

/// Multi-claim opening over a resident commitment state. All large matrices,
/// NTTs, row combinations, gathers and both Merkle trees stay on the device;
/// D2H consists only of proof fields (roots, u-vectors, queried columns and
/// sibling paths). Transcript/challenge orchestration remains in Rust.
#[allow(clippy::too_many_arguments)]
pub fn open_multi_zk_resident(
    pm: &ResidentProverMatrix,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    dom_s: u64,
    dom_zb: u64,
    mask_seed: [u8; 32],
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(MultiOpenProof, MultiOpenTimings), AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident PCS opening requires the cuda-resident backend",
        ));
    }
    let params = &pm.params;
    let (rows, cols, msg_len, code_len) =
        (params.rows(), params.cols(), params.msg_len(), params.code_len());
    let n_claims = claims.len();
    if n_claims == 0 {
        return Err(AccelError::InvalidInput("resident PCS opening needs a claim"));
    }
    let claim_rows: Vec<usize> = claims
        .iter()
        .map(|(claim, _)| resident_claim_row0(params, claim))
        .collect::<Result<_, _>>()?;
    let mut tm = MultiOpenTimings::default();
    let mut resident = ResidentOpenGuard::new(backend);

    // 1. Fresh prover-secret mask rows are generated directly into padded
    // device storage. A compact D2D copy feeds row additions and s_g dots;
    // neither mask representation ever crosses H2D or D2H.
    let t0 = Instant::now();
    let mask_rows = n_claims + 1;
    resident.mask_messages = Some(resident.backend.chacha8_prover_secret_fp2_rows_padded_device(
        mask_seed, 0, mask_rows, msg_len, code_len,
    )?);
    resident.mask_compact = Some(resident.backend.alloc_device(mask_rows * msg_len)?);
    resident.backend.copy_device_rows(
        DeviceSlice::new(
            resident.mask_messages.as_ref().expect("resident mask messages registered"),
            0,
            mask_rows * code_len,
        )?,
        code_len,
        resident.mask_compact.as_ref().expect("resident compact masks registered"),
        0,
        msg_len,
        mask_rows,
        msg_len,
    )?;
    resident.mask_encoded = Some(resident.backend.ntt_fp2_batch_device(
        resident.mask_messages.as_ref().expect("resident mask messages registered"),
        0,
        mask_rows,
        code_len,
    )?);
    resident
        .backend
        .free_device(resident.mask_messages.take().expect("resident mask messages registered"))?;
    resident.mask_tree = Some(resident.backend.hash_fp2_tree_device(
        resident.mask_encoded.as_ref().expect("resident mask encoding registered"),
        mask_rows,
        code_len,
    )?);
    let mask_root = resident
        .backend
        .merkle_root_device(resident.mask_tree.as_ref().expect("resident mask tree registered"))?;
    tx.append("pcs_mask_root", 32);
    tm.t_masks_s = t0.elapsed().as_secs_f64();

    // 2. Proximity challenge and one resident global row pass.
    let c = tx.challenge_fp2();
    let t1 = Instant::now();
    resident.c_device = Some(resident.backend.fp2_powers_device(c, rows)?);
    resident.u_c_device = Some(resident.backend.pcs_combine_rows_device(
        &pm.weights,
        0,
        &pm.pads,
        0,
        resident.c_device.as_ref().expect("resident c powers registered"),
        0,
        rows,
        cols,
        params.pad,
        1,
    )?);
    resident.backend.fp2_add_inplace_device(
        resident.u_c_device.as_ref().expect("resident u_c registered"),
        0,
        resident.mask_compact.as_ref().expect("resident compact masks registered"),
        0,
        msg_len,
    )?;
    let u_c: Vec<Fp2> = resident
        .backend
        .download_device(
            resident.u_c_device.as_ref().expect("resident u_c registered"),
            0,
            msg_len,
        )?
        .into_iter()
        .map(Into::into)
        .collect();
    resident.backend.free_device(resident.u_c_device.take().expect("resident u_c registered"))?;
    resident
        .backend
        .free_device(resident.c_device.take().expect("resident c powers registered"))?;
    tm.t_global_pass_s = t1.elapsed().as_secs_f64();

    // 3. All block-local claim combinations in one resident pass.
    let t2 = Instant::now();
    resident.coeff_device = Some(resident.backend.alloc_device(n_claims * rows)?);
    resident.backend.zero_device(
        resident.coeff_device.as_ref().expect("resident coefficients registered"),
        0,
        n_claims * rows,
    )?;
    let col_bits = params.col_bits as usize;
    for (g, ((claim, _), &row0)) in claims.iter().zip(&claim_rows).enumerate() {
        resident.coeff_row =
            Some(resident.backend.equality_weights_device(&claim.point[col_bits..])?);
        let coeff_len =
            resident.coeff_row.as_ref().expect("resident coefficient row registered").len();
        if row0.checked_add(coeff_len).is_none_or(|end| end > rows) {
            return Err(AccelError::InvalidInput("resident PCS claim rows exceed matrix"));
        }
        resident.backend.copy_device_rows(
            DeviceSlice::new(
                resident.coeff_row.as_ref().expect("resident coefficient row registered"),
                0,
                coeff_len,
            )?,
            coeff_len,
            resident.coeff_device.as_ref().expect("resident coefficients registered"),
            g * rows + row0,
            coeff_len,
            1,
            coeff_len,
        )?;
        resident
            .backend
            .free_device(resident.coeff_row.take().expect("resident coefficient row registered"))?;
    }
    resident.u_g_device = Some(resident.backend.pcs_combine_rows_device(
        &pm.weights,
        0,
        &pm.pads,
        0,
        resident.coeff_device.as_ref().expect("resident coefficients registered"),
        0,
        rows,
        cols,
        params.pad,
        n_claims,
    )?);
    resident.backend.fp2_add_inplace_device(
        resident.u_g_device.as_ref().expect("resident u_g registered"),
        0,
        resident.mask_compact.as_ref().expect("resident compact masks registered"),
        msg_len,
        n_claims * msg_len,
    )?;
    let u_g_flat: Vec<Fp2> = resident
        .backend
        .download_device(
            resident.u_g_device.as_ref().expect("resident u_g registered"),
            0,
            n_claims * msg_len,
        )?
        .into_iter()
        .map(Into::into)
        .collect();
    let u_gs: Vec<Vec<Fp2>> = u_g_flat.chunks_exact(msg_len).map(|row| row.to_vec()).collect();
    resident.backend.free_device(resident.u_g_device.take().expect("resident u_g registered"))?;
    resident
        .backend
        .free_device(resident.coeff_device.take().expect("resident coefficients registered"))?;
    tx.append("pcs_u_vectors", 16 * (msg_len * (n_claims + 1)) as u64);
    tm.t_block_passes_s = t2.elapsed().as_secs_f64();

    // 4. Compute every s_g on device. Only compact claim points cross H2D;
    // equality rows, row dots, and mask material stay resident. All scalar
    // results return in one protocol-visible D2H batch per commitment.
    let t3 = Instant::now();
    let mask_points_raw: Vec<Fp2Repr> = claims
        .iter()
        .flat_map(|(claim, _)| claim.point[..col_bits].iter().copied().map(Fp2Repr::from))
        .collect();
    resident.mask_points = Some(resident.backend.upload_new_device(&mask_points_raw)?);
    resident.mask_eq_rows = Some(resident.backend.logup_eq_rows_device(
        resident.mask_points.as_ref(),
        n_claims,
        col_bits,
    )?);
    resident.mask_dots = Some(resident.backend.fp2_row_dots_device(
        DeviceSlice::new(
            resident.mask_compact.as_ref().expect("resident compact masks registered"),
            msg_len,
            n_claims * msg_len,
        )?,
        msg_len,
        DeviceSlice::new(
            resident.mask_eq_rows.as_ref().expect("resident mask equality rows registered"),
            0,
            n_claims * cols,
        )?,
        cols,
        n_claims,
        cols,
    )?);
    let s_values: Vec<Fp2> = resident
        .backend
        .download_device(
            resident.mask_dots.as_ref().expect("resident mask dots registered"),
            0,
            n_claims,
        )?
        .into_iter()
        .map(Into::into)
        .collect();
    resident
        .backend
        .free_device(resident.mask_dots.take().expect("resident mask dots registered"))?;
    resident.backend.free_device(
        resident.mask_eq_rows.take().expect("resident mask equality rows registered"),
    )?;
    resident
        .backend
        .free_device(resident.mask_points.take().expect("resident mask points registered"))?;
    resident
        .backend
        .free_device(resident.mask_compact.take().expect("resident compact masks registered"))?;

    let fcs = stream.draw_fulls(dom_s, n_claims);
    let mut corr_ss = Vec::with_capacity(n_claims);
    let mut zs = Vec::with_capacity(n_claims);
    for g in 0..n_claims {
        let q_col = eq_vec(&claims[g].0.point[..col_bits]);
        let s_val = s_values[g];
        corr_ss.push(s_val - fcs[g].x);
        let s_auth = ProverAuthed { x: s_val, m: fcs[g].m };
        let ip = (0..cols).fold(Fp2::ZERO, |sum, j| sum + u_gs[g][j] * q_col[j]);
        zs.push(claims[g].1.add(s_auth).sub(ProverAuthed::from_public(ip)));
    }
    tx.append("pcs_s_corrections", 16 * n_claims as u64);
    let zb_corr = stream.draw_fulls(dom_zb, 1)[0];
    let (zb_mask, mask_corr) = fresh_zero_mask(zb_corr, tx);
    let chi = tx.challenge_fp2();
    let m_z = zero_batch_prover(&zs, &zb_mask, chi, tx);
    tm.t_ip_zb_s = t3.elapsed().as_secs_f64();

    // 5. Shared query columns and Merkle paths. Indices are transcript
    // messages; everything they select remains resident until the final proof
    // payload is downloaded.
    let t4 = Instant::now();
    let js: Vec<usize> =
        (0..params.n_queries).map(|_| tx.challenge_fp2().c0.value() as usize % code_len).collect();
    let indices_raw: Vec<u32> = js.iter().map(|&j| j as u32).collect();
    resident.indices = Some(resident.backend.upload_new_device(&indices_raw)?);
    resident.data_columns = Some(resident.backend.pcs_gather_fp_device(
        &pm.encoded,
        rows,
        code_len,
        resident.indices.as_ref().expect("resident query indices registered"),
        js.len(),
    )?);
    resident.mask_columns = Some(resident.backend.pcs_gather_fp2_device(
        resident.mask_encoded.as_ref().expect("resident mask encoding registered"),
        mask_rows,
        code_len,
        resident.indices.as_ref().expect("resident query indices registered"),
        js.len(),
    )?);
    resident.data_paths = Some(resident.backend.merkle_paths_device(
        &pm.tree,
        resident.indices.as_ref().expect("resident query indices registered"),
        js.len(),
    )?);
    resident.mask_paths = Some(resident.backend.merkle_paths_device(
        resident.mask_tree.as_ref().expect("resident mask tree registered"),
        resident.indices.as_ref().expect("resident query indices registered"),
        js.len(),
    )?);
    let data_columns: Vec<Fp> = resident
        .backend
        .download_device(
            resident.data_columns.as_ref().expect("resident data columns registered"),
            0,
            js.len() * rows,
        )?
        .into_iter()
        .map(Fp::new)
        .collect();
    let mask_columns: Vec<Fp2> = resident
        .backend
        .download_device(
            resident.mask_columns.as_ref().expect("resident mask columns registered"),
            0,
            js.len() * mask_rows,
        )?
        .into_iter()
        .map(Into::into)
        .collect();
    let path_len = params.code_bits as usize;
    let data_path_bytes = resident.backend.download_device(
        resident.data_paths.as_ref().expect("resident data paths registered"),
        0,
        js.len() * path_len * 32,
    )?;
    let mask_path_bytes = resident.backend.download_device(
        resident.mask_paths.as_ref().expect("resident mask paths registered"),
        0,
        js.len() * path_len * 32,
    )?;
    let decode_path = |bytes: &[u8], query: usize| -> Vec<Hash> {
        (0..path_len)
            .map(|level| {
                let offset = (query * path_len + level) * 32;
                bytes[offset..offset + 32].try_into().unwrap()
            })
            .collect()
    };
    let columns: Vec<MultiColumnOpening> = js
        .iter()
        .enumerate()
        .map(|(q, &j)| MultiColumnOpening {
            j: j as u32,
            col: data_columns[q * rows..(q + 1) * rows].to_vec(),
            mask_col: mask_columns[q * mask_rows..(q + 1) * mask_rows].to_vec(),
            path: decode_path(&data_path_bytes, q),
            mask_path: decode_path(&mask_path_bytes, q),
        })
        .collect();
    resident
        .backend
        .free_device(resident.mask_paths.take().expect("resident mask paths registered"))?;
    resident
        .backend
        .free_device(resident.data_paths.take().expect("resident data paths registered"))?;
    resident
        .backend
        .free_device(resident.mask_columns.take().expect("resident mask columns registered"))?;
    resident
        .backend
        .free_device(resident.data_columns.take().expect("resident data columns registered"))?;
    resident
        .backend
        .free_device(resident.indices.take().expect("resident query indices registered"))?;
    resident.backend.free_device_merkle_tree(
        resident.mask_tree.take().expect("resident mask tree registered"),
    )?;
    resident
        .backend
        .free_device(resident.mask_encoded.take().expect("resident mask encoding registered"))?;
    let col_b: u64 = columns
        .iter()
        .map(|column| {
            4 + 8 * column.col.len() as u64
                + 16 * column.mask_col.len() as u64
                + 32 * (column.path.len() + column.mask_path.len()) as u64
        })
        .sum();
    tx.append("pcs_columns", col_b);
    tm.t_columns_s = t4.elapsed().as_secs_f64();

    Ok((MultiOpenProof { mask_root, u_c, u_gs, corr_ss, mask_corr, m_z, columns }, tm))
}

#[allow(clippy::too_many_arguments)]
fn open_multi_zk_impl(
    w: &[i16],
    pm: &ProverMatrix,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    dom_s: u64,
    dom_zb: u64,
    mask_seed: [u8; 32],
    tx: &mut Transcript,
    mut backend: Option<&mut Backend>,
) -> Result<(MultiOpenProof, MultiOpenTimings), AccelError> {
    let params = &pm.params;
    let (rows, cols, msg_len, code_len) =
        (params.rows(), params.cols(), params.msg_len(), params.code_len());
    let n_claims = claims.len();
    assert!(n_claims > 0);
    if w.len() != rows.saturating_mul(cols) {
        return Err(AccelError::InvalidInput("PCS opening weight geometry mismatch"));
    }
    let plan = NttPlan::new(code_len);
    let mut tm = MultiOpenTimings::default();
    let geoms: Vec<ClaimGeom> = claims
        .iter()
        .map(|(claim, _)| {
            claim_geom(params, claim)
                .ok_or(AccelError::InvalidInput("PCS claim exceeds explicit matrix rows"))
        })
        .collect::<Result<_, _>>()?;

    // 1. Fresh mask rows: R_c (proximity) + one per claim, committed first.
    let t0 = Instant::now();
    let make_masks = || {
        (0..=n_claims)
            .into_par_iter()
            .map(|g| {
                let mut ms = FpStream::domain_separated(mask_seed, g as u64);
                (0..msg_len).map(|_| ms.next_fp2()).collect()
            })
            .collect::<Vec<Vec<Fp2>>>()
    };
    let masks = if let Some(accel) = backend.as_deref_mut() {
        accel.cpu_residual(Operation::PcsNtt, make_masks)?
    } else {
        make_masks()
    };
    let masks_enc: Vec<Vec<Fp2>> = if let Some(accel) = backend.as_deref_mut() {
        let mut encoded = Vec::with_capacity(masks.len());
        for mask in &masks {
            encoded.push(accel.ntt_fp2(mask, code_len)?);
        }
        encoded
    } else {
        masks.par_iter().map(|m| encode_fp2(&plan, m)).collect()
    };
    let build_mask_tree = || {
        let mask_leaves: Vec<Hash> = (0..code_len)
            .into_par_iter()
            .map(|j| {
                let vals: Vec<Fp2> = masks_enc.iter().map(|m| m[j]).collect();
                multi_mask_leaf(&vals)
            })
            .collect();
        MerkleTree::from_leaves(mask_leaves)
    };
    let mask_tree = if let Some(accel) = backend.as_deref_mut() {
        accel.cpu_residual(Operation::PcsMerkle, build_mask_tree)?
    } else {
        build_mask_tree()
    };
    tx.append("pcs_mask_root", 32);
    tm.t_masks_s = t0.elapsed().as_secs_f64();

    // 2. Proximity challenge and global pass over all rows.
    let c = tx.challenge_fp2();
    let mut c_pows = Vec::with_capacity(rows);
    let mut acc = Fp2::ONE;
    for _ in 0..rows {
        acc = acc * c;
        c_pows.push(acc);
    }
    let t1 = Instant::now();
    // Chunked CPU pass or one CUDA row-combination pass.
    let mut u_c = if let Some(accel) = backend.as_deref_mut() {
        accel.pcs_combine_rows(w, &pm.pads, &c_pows, rows, cols, params.pad, 1)?.pop().unwrap()
    } else {
        let n_chunks = rayon::current_num_threads() * 4;
        let rows_per = rows.div_ceil(n_chunks);
        (0..n_chunks)
            .into_par_iter()
            .map(|ci| {
                let r0 = ci * rows_per;
                let r1 = rows.min(r0 + rows_per);
                if r0 >= r1 {
                    return vec![Fp2::ZERO; msg_len];
                }
                combine_row_range(w, &pm.pads, params, r0, &c_pows[r0..r1])
            })
            .reduce(
                || vec![Fp2::ZERO; msg_len],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(&b) {
                        *x += *y;
                    }
                    a
                },
            )
    };
    for j in 0..msg_len {
        u_c[j] += masks[0][j];
    }
    tm.t_global_pass_s = t1.elapsed().as_secs_f64();

    // 3. Per-claim block-local combinations.
    let t2 = Instant::now();
    let mut u_gs: Vec<Vec<Fp2>> = if let Some(accel) = backend.as_deref_mut() {
        let mut coeffs = vec![Fp2::ZERO; n_claims * rows];
        for (g, geo) in geoms.iter().enumerate() {
            coeffs[g * rows + geo.row0..g * rows + geo.row0 + geo.q_row.len()]
                .copy_from_slice(&geo.q_row);
        }
        accel.pcs_combine_rows(w, &pm.pads, &coeffs, rows, cols, params.pad, n_claims)?
    } else {
        geoms
            .par_iter()
            .map(|geo| combine_row_range(w, &pm.pads, params, geo.row0, &geo.q_row))
            .collect()
    };
    for (g, u) in u_gs.iter_mut().enumerate() {
        for j in 0..msg_len {
            u[j] += masks[1 + g][j];
        }
    }
    tx.append("pcs_u_vectors", 16 * (msg_len * (n_claims + 1)) as u64);
    tm.t_block_passes_s = t2.elapsed().as_secs_f64();

    // 4. Authenticate the s_g; MAC resolution via one Π_ZeroBatch.
    let t3 = Instant::now();
    let fcs = stream.draw_fulls(dom_s, n_claims);
    let mut corr_ss = Vec::with_capacity(n_claims);
    let mut zs = Vec::with_capacity(n_claims);
    for (g, geo) in geoms.iter().enumerate() {
        let s_val = (0..cols).fold(Fp2::ZERO, |a, j| a + masks[1 + g][j] * geo.q_col[j]);
        corr_ss.push(s_val - fcs[g].x);
        let s_auth = ProverAuthed { x: s_val, m: fcs[g].m };
        let ip = (0..cols).fold(Fp2::ZERO, |a, j| a + u_gs[g][j] * geo.q_col[j]);
        zs.push(claims[g].1.add(s_auth).sub(ProverAuthed::from_public(ip)));
    }
    tx.append("pcs_s_corrections", 16 * n_claims as u64);
    let zb_corr = stream.draw_fulls(dom_zb, 1)[0];
    let (zb_mask, mask_corr) = fresh_zero_mask(zb_corr, tx);
    let chi = tx.challenge_fp2();
    let m_z = zero_batch_prover(&zs, &zb_mask, chi, tx);
    tm.t_ip_zb_s = t3.elapsed().as_secs_f64();

    // 5. Shared column queries.
    let t4 = Instant::now();
    let js: Vec<usize> =
        (0..params.n_queries).map(|_| tx.challenge_fp2().c0.value() as usize % code_len).collect();
    let gathered = if let Some(accel) = backend.as_deref_mut() {
        let indices: Vec<u32> = js.iter().map(|&j| j as u32).collect();
        Some(accel.pcs_gather_columns(&pm.encoded, rows, code_len, &indices)?)
    } else {
        None
    };
    let build_columns = || {
        js.par_iter()
            .enumerate()
            .map(|(q, &j)| MultiColumnOpening {
                j: j as u32,
                col: gathered.as_ref().map_or_else(
                    || (0..rows).map(|i| pm.encoded[i * code_len + j]).collect(),
                    |cols| cols[q].clone(),
                ),
                mask_col: masks_enc.iter().map(|m| m[j]).collect(),
                path: pm.tree.open(j),
                mask_path: mask_tree.open(j),
            })
            .collect::<Vec<_>>()
    };
    let columns = if let Some(accel) = backend.as_deref_mut() {
        accel.cpu_residual(Operation::PcsMerkle, build_columns)?
    } else {
        build_columns()
    };
    let col_b: u64 = columns
        .iter()
        .map(|c| {
            4 + 8 * c.col.len() as u64
                + 16 * c.mask_col.len() as u64
                + 32 * (c.path.len() + c.mask_path.len()) as u64
        })
        .sum();
    tx.append("pcs_columns", col_b);
    tm.t_columns_s = t4.elapsed().as_secs_f64();

    Ok((
        MultiOpenProof { mask_root: mask_tree.root(), u_c, u_gs, corr_ss, mask_corr, m_z, columns },
        tm,
    ))
}

/// Verifier for the multi-claim opening. Accepting binds every claim key to
/// the committed W̃ at its point (M9 interface, batched).
pub fn verify_multi_open(
    root: &Hash,
    params: &LigeroParams,
    claims: &[(BlockClaim, VerifierKey)],
    proof: &MultiOpenProof,
    ctx: &mut VerifierCtx,
    dom_s: u64,
    dom_zb: u64,
    tx: &mut Transcript,
) -> bool {
    let (rows, cols, msg_len, code_len) =
        (params.rows(), params.cols(), params.msg_len(), params.code_len());
    let n_claims = claims.len();
    if n_claims == 0
        || proof.u_c.len() != msg_len
        || proof.u_gs.len() != n_claims
        || proof.u_gs.iter().any(|u| u.len() != msg_len)
        || proof.corr_ss.len() != n_claims
        || proof.columns.len() != params.n_queries
        || proof.columns.iter().any(|co| co.col.len() != rows || co.mask_col.len() != n_claims + 1)
    {
        return false;
    }
    let plan = NttPlan::new(code_len);
    let Some(geoms) =
        claims.iter().map(|(claim, _)| claim_geom(params, claim)).collect::<Option<Vec<_>>>()
    else {
        return false;
    };

    // Same challenge order as the prover: c, χ, then the column queries.
    let c = tx.challenge_fp2();
    let mut c_pows = Vec::with_capacity(rows);
    let mut acc = Fp2::ONE;
    for _ in 0..rows {
        acc = acc * c;
        c_pows.push(acc);
    }

    // MAC resolution first (cheap): batched zero check over v_g + s_g − ip_g.
    let k_fulls = ctx.expand_full_keys(dom_s, n_claims);
    let mut k_zs = Vec::with_capacity(n_claims);
    for (g, geo) in geoms.iter().enumerate() {
        let k_s = VerifierKey { k: k_fulls[g] + ctx.delta * proof.corr_ss[g] };
        let ip = (0..cols).fold(Fp2::ZERO, |a, j| a + proof.u_gs[g][j] * geo.q_col[j]);
        k_zs.push(claims[g].1.add(k_s).sub(VerifierKey::from_public(ip, ctx.delta)));
    }
    let k_zb_full = ctx.expand_full_keys(dom_zb, 1)[0];
    let k_mask = zero_mask_key(ctx, k_zb_full, proof.mask_corr);
    let chi = tx.challenge_fp2();
    if !zero_batch_verify(&k_zs, k_mask, chi, proof.m_z) {
        return false;
    }

    let js: Vec<usize> =
        (0..params.n_queries).map(|_| tx.challenge_fp2().c0.value() as usize % code_len).collect();

    // Encode all blinded combinations (componentwise NTT, parallel).
    let enc_uc = encode_fp2(&plan, &proof.u_c);
    let enc_ugs: Vec<Vec<Fp2>> = proof.u_gs.par_iter().map(|u| encode_fp2(&plan, u)).collect();

    let ok = proof.columns.par_iter().enumerate().all(|(q, co)| {
        let j = co.j as usize;
        if j != js[q]
            || !verify_path(root, j, hash_leaf(&col_bytes(&co.col)), &co.path)
            || !verify_path(&proof.mask_root, j, multi_mask_leaf(&co.mask_col), &co.mask_path)
        {
            return false;
        }
        let mut sum_c = Fp2::ZERO;
        for i in 0..rows {
            sum_c += c_pows[i].mul_base(co.col[i]);
        }
        if enc_uc[j] != sum_c + co.mask_col[0] {
            return false;
        }
        for (g, geo) in geoms.iter().enumerate() {
            let mut sum_g = Fp2::ZERO;
            for (di, &qi) in geo.q_row.iter().enumerate() {
                sum_g += qi.mul_base(co.col[geo.row0 + di]);
            }
            if enc_ugs[g][j] != sum_g + co.mask_col[1 + g] {
                return false;
            }
        }
        true
    });
    ok
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn cleanup_step_runs_every_action_and_retains_first_error() {
        let mut first_error = None;
        let mut ran = Vec::new();
        cleanup_step(&mut first_error, || {
            ran.push(1);
            Err(AccelError::InvalidInput("first cleanup failure"))
        });
        cleanup_step(&mut first_error, || {
            ran.push(2);
            Ok(())
        });
        cleanup_step(&mut first_error, || {
            ran.push(3);
            Err(AccelError::InvalidInput("later cleanup failure"))
        });

        assert_eq!(ran, vec![1, 2, 3]);
        match first_error {
            Some(AccelError::InvalidInput(message)) => {
                assert_eq!(message, "first cleanup failure")
            }
            _ => panic!("cleanup must retain its first error"),
        }
    }
}

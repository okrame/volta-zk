//! Executable C6.4 references for the joint cache/residual sketch.
//!
//! The historical correction-only layout remains as a differential fixture.
//! The selected terminal layout packs the complete private residual owner in
//! the unused cells of the same table and exposes systematic rows only for the
//! cache prefix.

use volta_field::{Fp, Fp2};
use volta_mac::{ProverAuthed, VerifierKey};
use volta_proto::mle::eq_vec;
use volta_proto::{
    C6PairedResidualAuxiliaryWitness, C6PairedResidualClosureWitness,
    C6PairedResidualCorrectionRows, C6PairedResidualLeafWitness, C6ResidualAuxiliaryLane,
    C6ResidualLeafColumn,
};

use crate::c63_authenticated_sketch::C63SparseSketchReference;
use crate::c6_residual_sumcheck::C6ResidualSumcheckFamily;
use crate::c6_residual_sumcheck_blind::{
    C6BlindResidualPendingClaimsProver, C6BlindResidualPendingClaimsVerifier,
};

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use crate::c62_gpu_whir::C62GpuMmcs;
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use std::sync::{Arc, Mutex};
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
use volta_accel::{Backend, DeviceBuffer, Fp2Repr};

pub const C64_JOINT_COLUMNS: usize = 16;
pub const C64_RESIDUAL_PUBLIC_COLUMNS: usize = 4;
pub const C64_RESIDUAL_LEAF_TABLES: usize = 8;
pub const C64_RESIDUAL_AUXILIARY_TABLES: usize = 16;
pub const C64_RESIDUAL_TERMINAL_CLAIMS: usize = 48;
pub const C64_RESIDUAL_FAMILIES: usize = 3;
pub const C64_LEAF_OTHER_FAMILY: usize = 0;
pub const C64_LEAF_CORRECTION_FAMILY: usize = 1;
pub const C64_AUXILIARY_FAMILY: usize = 2;

pub(crate) fn fold_c64_terminal_pending_prover(
    pending: &C6BlindResidualPendingClaimsProver,
    weights: &[Fp2; C64_RESIDUAL_TERMINAL_CLAIMS],
) -> Result<([ProverAuthed; 2], [u8; 32]), String> {
    let entries = pending.link_entries();
    let digest = validate_and_digest_terminal_entries(
        entries.iter().map(|(descriptor, _)| descriptor),
        weights,
    )?;
    let claims = entries.iter().zip(weights).fold(
        [ProverAuthed::ZERO; 2],
        |mut folded, ((_, claims), &weight)| {
            for tape in 0..2 {
                folded[tape] = folded[tape].add(claims[tape].scale(weight));
            }
            folded
        },
    );
    if claims[0].x != claims[1].x {
        return Err("C6.4 folded terminal plaintext differs across tapes".to_owned());
    }
    Ok((claims, digest))
}

pub(crate) fn fold_c64_terminal_pending_verifier(
    pending: &C6BlindResidualPendingClaimsVerifier,
    weights: &[Fp2; C64_RESIDUAL_TERMINAL_CLAIMS],
) -> Result<([VerifierKey; 2], [u8; 32]), String> {
    let entries = pending.link_entries();
    let digest = validate_and_digest_terminal_entries(
        entries.iter().map(|(descriptor, _)| descriptor),
        weights,
    )?;
    let keys = entries.iter().zip(weights).fold(
        [VerifierKey::ZERO; 2],
        |mut folded, ((_, keys), &weight)| {
            for tape in 0..2 {
                folded[tape] = folded[tape].add(keys[tape].scale(weight));
            }
            folded
        },
    );
    Ok((keys, digest))
}

/// Fold the 48 terminal claims into other-leaf, correction-leaf and auxiliary
/// polynomials. Splitting the two correction columns lets the later cache
/// opening bind them without recovering the discarded private table.
pub(crate) fn fold_c64_projected_pending_prover(
    pending: &C6BlindResidualPendingClaimsProver,
    leaf_weights: &[Fp2; C64_RESIDUAL_LEAF_TABLES],
    auxiliary_weights: &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
) -> Result<[[[ProverAuthed; 2]; 2]; C64_RESIDUAL_FAMILIES], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    let mut folded = [[[ProverAuthed::ZERO; 2]; 2]; C64_RESIDUAL_FAMILIES];
    for (index, (_, claims)) in entries.iter().enumerate() {
        let repetition = index / 24;
        let local = index % 24;
        let (family, weight) = if local < C64_RESIDUAL_LEAF_TABLES {
            (
                if matches!(local, 3 | 6) {
                    C64_LEAF_CORRECTION_FAMILY
                } else {
                    C64_LEAF_OTHER_FAMILY
                },
                leaf_weights[local],
            )
        } else {
            (C64_AUXILIARY_FAMILY, auxiliary_weights[local - C64_RESIDUAL_LEAF_TABLES])
        };
        for tape in 0..2 {
            folded[family][repetition][tape] =
                folded[family][repetition][tape].add(claims[tape].scale(weight));
        }
    }
    Ok(folded)
}

pub(crate) fn fold_c64_projected_pending_verifier(
    pending: &C6BlindResidualPendingClaimsVerifier,
    leaf_weights: &[Fp2; C64_RESIDUAL_LEAF_TABLES],
    auxiliary_weights: &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
) -> Result<[[[VerifierKey; 2]; 2]; C64_RESIDUAL_FAMILIES], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    let mut folded = [[[VerifierKey::ZERO; 2]; 2]; C64_RESIDUAL_FAMILIES];
    for (index, (_, keys)) in entries.iter().enumerate() {
        let repetition = index / 24;
        let local = index % 24;
        let (family, weight) = if local < C64_RESIDUAL_LEAF_TABLES {
            (
                if matches!(local, 3 | 6) {
                    C64_LEAF_CORRECTION_FAMILY
                } else {
                    C64_LEAF_OTHER_FAMILY
                },
                leaf_weights[local],
            )
        } else {
            (C64_AUXILIARY_FAMILY, auxiliary_weights[local - C64_RESIDUAL_LEAF_TABLES])
        };
        for tape in 0..2 {
            folded[family][repetition][tape] =
                folded[family][repetition][tape].add(keys[tape].scale(weight));
        }
    }
    Ok(folded)
}

pub(crate) fn c64_correction_pending_prover(
    pending: &C6BlindResidualPendingClaimsProver,
) -> Result<[[[ProverAuthed; 2]; 2]; 2], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    Ok(std::array::from_fn(|repetition| {
        std::array::from_fn(|correction| entries[repetition * 24 + [3, 6][correction]].1)
    }))
}

pub(crate) fn c64_correction_pending_verifier(
    pending: &C6BlindResidualPendingClaimsVerifier,
) -> Result<[[[VerifierKey; 2]; 2]; 2], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    Ok(std::array::from_fn(|repetition| {
        std::array::from_fn(|correction| entries[repetition * 24 + [3, 6][correction]].1)
    }))
}

pub(crate) fn c64_projected_pending_digest(
    pending: &C6BlindResidualPendingClaimsProver,
) -> Result<[u8; 32], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/projected-pending/v1");
    for (descriptor, _) in entries {
        hasher.update(&descriptor.statement_digest());
        hasher.update(&[descriptor.repetition(), descriptor.family() as u8]);
        hasher.update(&descriptor.table().cohort_id.to_le_bytes());
        hasher.update(&descriptor.table().slot.to_le_bytes());
        for value in descriptor.point() {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn c64_projected_pending_digest_verifier(
    pending: &C6BlindResidualPendingClaimsVerifier,
) -> Result<[u8; 32], String> {
    let entries = pending.link_entries();
    validate_projected_terminal_entries(entries.iter().map(|(descriptor, _)| descriptor))?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/projected-pending/v1");
    for (descriptor, _) in entries {
        hasher.update(&descriptor.statement_digest());
        hasher.update(&[descriptor.repetition(), descriptor.family() as u8]);
        hasher.update(&descriptor.table().cohort_id.to_le_bytes());
        hasher.update(&descriptor.table().slot.to_le_bytes());
        for value in descriptor.point() {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn validate_projected_terminal_entries<'a>(
    descriptors: impl IntoIterator<
        Item = &'a crate::c6_residual_sumcheck_blind::C6BlindResidualPendingDescriptor,
    >,
) -> Result<(), String> {
    let descriptors = descriptors.into_iter().collect::<Vec<_>>();
    if descriptors.len() != C64_RESIDUAL_TERMINAL_CLAIMS {
        return Err("C6.4 projected pending-claim census differs".to_owned());
    }
    for (index, descriptor) in descriptors.iter().enumerate() {
        let repetition = index / 24;
        let local = index % 24;
        let (family, slot) = if local < C64_RESIDUAL_LEAF_TABLES {
            (C6ResidualSumcheckFamily::LeafRaw, local)
        } else {
            (C6ResidualSumcheckFamily::Auxiliary, local - C64_RESIDUAL_LEAF_TABLES)
        };
        if usize::from(descriptor.repetition()) != repetition
            || descriptor.family() != family
            || usize::from(descriptor.table().slot) != slot
            || descriptor.statement_digest() == [0; 32]
            || descriptor.point().is_empty()
        {
            return Err(format!("C6.4 projected pending descriptor {index} differs"));
        }
    }
    Ok(())
}

fn validate_and_digest_terminal_entries<'a>(
    descriptors: impl IntoIterator<
        Item = &'a crate::c6_residual_sumcheck_blind::C6BlindResidualPendingDescriptor,
    >,
    weights: &[Fp2; C64_RESIDUAL_TERMINAL_CLAIMS],
) -> Result<[u8; 32], String> {
    let descriptors = descriptors.into_iter().collect::<Vec<_>>();
    if descriptors.len() != C64_RESIDUAL_TERMINAL_CLAIMS {
        return Err("C6.4 terminal pending-claim census differs".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/terminal-pending-fold/v1");
    for (index, (descriptor, &weight)) in descriptors.iter().zip(weights).enumerate() {
        let repetition = index / 24;
        let local = index % 24;
        let (family, table) = if local < C64_RESIDUAL_LEAF_TABLES {
            (C6ResidualSumcheckFamily::LeafRaw, local)
        } else {
            (C6ResidualSumcheckFamily::Auxiliary, local - C64_RESIDUAL_LEAF_TABLES)
        };
        if usize::from(descriptor.repetition()) != repetition
            || descriptor.family() != family
            || usize::from(descriptor.table().slot) != table
            || descriptor.statement_digest() == [0; 32]
            || descriptor.point().is_empty()
        {
            return Err(format!(
                "C6.4 terminal pending descriptor {index} differs: repetition {}, family {:?}, slot {}",
                descriptor.repetition(),
                descriptor.family(),
                descriptor.table().slot
            ));
        }
        hasher.update(&descriptor.statement_digest());
        hasher.update(&[descriptor.repetition(), family as u8]);
        hasher.update(&descriptor.table().cohort_id.to_le_bytes());
        hasher.update(&descriptor.table().slot.to_le_bytes());
        hasher.update(&(descriptor.point().len() as u64).to_le_bytes());
        for value in descriptor.point() {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
        hasher.update(&weight.c0.value().to_le_bytes());
        hasher.update(&weight.c1.value().to_le_bytes());
    }
    for repetition in 0..2 {
        let leaf = descriptors[repetition * 24].point();
        let auxiliary = descriptors[repetition * 24 + C64_RESIDUAL_LEAF_TABLES].point();
        if descriptors[repetition * 24..repetition * 24 + C64_RESIDUAL_LEAF_TABLES]
            .iter()
            .any(|descriptor| descriptor.point() != leaf)
            || descriptors[repetition * 24 + C64_RESIDUAL_LEAF_TABLES..(repetition + 1) * 24]
                .iter()
                .any(|descriptor| descriptor.point() != auxiliary)
            || !leaf.ends_with(auxiliary)
        {
            return Err("C6.4 terminal pending point families differ".to_owned());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C64JointRowKind {
    Cache,
    Residual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64JointCorrectionRow {
    kind: C64JointRowKind,
    columns: [Fp; C64_JOINT_COLUMNS],
}

impl C64JointCorrectionRow {
    pub fn cache(columns: [Fp; C64_JOINT_COLUMNS]) -> Self {
        Self { kind: C64JointRowKind::Cache, columns }
    }

    /// The public residual row contains only `(D_0.c0, D_0.c1, D_1.c0,
    /// D_1.c1)`.  There is no constructor accepting plaintexts, masks or tags.
    pub fn residual(corrections: [Fp2; 2]) -> Self {
        let mut columns = [Fp::ZERO; C64_JOINT_COLUMNS];
        columns[..C64_RESIDUAL_PUBLIC_COLUMNS].copy_from_slice(&[
            corrections[0].c0,
            corrections[0].c1,
            corrections[1].c0,
            corrections[1].c1,
        ]);
        Self { kind: C64JointRowKind::Residual, columns }
    }

    pub fn columns(&self) -> &[Fp; C64_JOINT_COLUMNS] {
        &self.columns
    }

    fn validate(self) -> Result<(), String> {
        if self.kind == C64JointRowKind::Residual
            && self.columns[C64_RESIDUAL_PUBLIC_COLUMNS..].iter().any(|value| *value != Fp::ZERO)
        {
            return Err("C6.4 residual row exposes a non-correction column".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64JointSketchCensus {
    pub input_rows: usize,
    pub cache_rows: usize,
    pub residual_rows: usize,
    pub live_rows: usize,
    pub physical_public_values: usize,
    pub virtual_zero_values: usize,
    pub active_edge_updates: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C64JointCorrectionLayout {
    input_rows: usize,
    cache_rows: Vec<C64JointCorrectionRow>,
    residual_rows: Vec<C64JointCorrectionRow>,
    source_schedule_digest: [u8; 32],
    allocation_binding_digest: [u8; 32],
}

impl C64JointCorrectionLayout {
    /// Scaled/reference constructor. Production callers use
    /// [`Self::from_bound_residual_rows`] so digests cannot be fabricated.
    pub fn reference(
        input_rows: usize,
        cache_rows: Vec<C64JointCorrectionRow>,
        residual_rows: Vec<C64JointCorrectionRow>,
        source_schedule_digest: [u8; 32],
        allocation_binding_digest: [u8; 32],
    ) -> Result<Self, String> {
        let live_rows = cache_rows
            .len()
            .checked_add(residual_rows.len())
            .ok_or_else(|| "C6.4 live row count overflows".to_owned())?;
        if input_rows == 0 || live_rows > input_rows {
            return Err("C6.4 joint rows exceed their input domain".to_owned());
        }
        if source_schedule_digest == [0; 32] || allocation_binding_digest == [0; 32] {
            return Err("C6.4 residual row binding digest is zero".to_owned());
        }
        if cache_rows.iter().any(|row| row.kind != C64JointRowKind::Cache)
            || residual_rows.iter().any(|row| row.kind != C64JointRowKind::Residual)
        {
            return Err("C6.4 joint row segment kind differs".to_owned());
        }
        cache_rows.iter().chain(&residual_rows).try_for_each(|row| row.validate())?;
        Ok(Self {
            input_rows,
            cache_rows,
            residual_rows,
            source_schedule_digest,
            allocation_binding_digest,
        })
    }

    pub fn from_bound_residual_rows(
        input_rows: usize,
        cache_rows: Vec<C64JointCorrectionRow>,
        residual: &C6PairedResidualCorrectionRows,
    ) -> Result<Self, String> {
        let allocation_binding_digest =
            residual.production_allocation_binding_digest().ok_or_else(|| {
                "C6.4 production residual corrections lack allocation binding".to_owned()
            })?;
        let residual_rows =
            residual.rows().iter().copied().map(C64JointCorrectionRow::residual).collect();
        Self::reference(
            input_rows,
            cache_rows,
            residual_rows,
            residual.source_schedule_digest(),
            allocation_binding_digest,
        )
    }

    pub fn census(&self) -> Result<C64JointSketchCensus, String> {
        let live_rows = self
            .cache_rows
            .len()
            .checked_add(self.residual_rows.len())
            .ok_or_else(|| "C6.4 live row count overflows".to_owned())?;
        let physical_public_values = self
            .cache_rows
            .len()
            .checked_mul(C64_JOINT_COLUMNS)
            .and_then(|count| {
                self.residual_rows
                    .len()
                    .checked_mul(C64_RESIDUAL_PUBLIC_COLUMNS)
                    .and_then(|residual| count.checked_add(residual))
            })
            .ok_or_else(|| "C6.4 public value count overflows".to_owned())?;
        let logical_values = self
            .input_rows
            .checked_mul(C64_JOINT_COLUMNS)
            .ok_or_else(|| "C6.4 logical value count overflows".to_owned())?;
        let active_edge_updates = physical_public_values
            .checked_mul(16)
            .ok_or_else(|| "C6.4 active edge count overflows".to_owned())?;
        Ok(C64JointSketchCensus {
            input_rows: self.input_rows,
            cache_rows: self.cache_rows.len(),
            residual_rows: self.residual_rows.len(),
            live_rows,
            physical_public_values,
            virtual_zero_values: logical_values - physical_public_values,
            active_edge_updates,
        })
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/joint-correction-layout/v1");
        hasher.update(&(self.input_rows as u64).to_le_bytes());
        hasher.update(&(self.cache_rows.len() as u64).to_le_bytes());
        hasher.update(&(self.residual_rows.len() as u64).to_le_bytes());
        hasher.update(&self.source_schedule_digest);
        hasher.update(&self.allocation_binding_digest);
        for row in self.cache_rows.iter().chain(&self.residual_rows) {
            hasher.update(&[match row.kind {
                C64JointRowKind::Cache => 1,
                C64JointRowKind::Residual => 2,
            }]);
            for value in row.columns {
                hasher.update(&value.value().to_le_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Apply the existing sparse `H` to the canonical joint table.
    pub fn apply_joint(
        &self,
        sketch: &C63SparseSketchReference,
    ) -> Result<[Vec<Fp2>; C64_JOINT_COLUMNS], String> {
        self.apply_segments(sketch, true, true)
    }

    /// Check that separately streamed cache and residual contributions are
    /// byte-for-byte equal to one application over the canonical joint rows.
    pub fn verify_separate_streaming_identity(
        &self,
        sketch: &C63SparseSketchReference,
    ) -> Result<[Vec<Fp2>; C64_JOINT_COLUMNS], String> {
        let joint = self.apply_joint(sketch)?;
        let cache = self.apply_segments(sketch, true, false)?;
        let residual = self.apply_segments(sketch, false, true)?;
        let combined = std::array::from_fn(|column| {
            cache[column]
                .iter()
                .zip(&residual[column])
                .map(|(left, right)| *left + *right)
                .collect::<Vec<_>>()
        });
        if combined != joint {
            return Err("C6.4 separately streamed sketch differs from the joint table".to_owned());
        }
        Ok(joint)
    }

    fn apply_segments(
        &self,
        sketch: &C63SparseSketchReference,
        include_cache: bool,
        include_residual: bool,
    ) -> Result<[Vec<Fp2>; C64_JOINT_COLUMNS], String> {
        let mut columns: [Vec<Fp2>; C64_JOINT_COLUMNS] =
            std::array::from_fn(|_| vec![Fp2::ZERO; self.input_rows]);
        if include_cache {
            for (row_index, row) in self.cache_rows.iter().enumerate() {
                for (column, value) in row.columns.iter().enumerate() {
                    columns[column][row_index] = Fp2::from_base(*value);
                }
            }
        }
        if include_residual {
            let offset = self.cache_rows.len();
            for (residual_index, row) in self.residual_rows.iter().enumerate() {
                for (column, value) in row.columns.iter().enumerate() {
                    columns[column][offset + residual_index] = Fp2::from_base(*value);
                }
            }
        }
        columns
            .into_iter()
            .map(|column| sketch.apply(&column))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6.4 joint sketch column census differs".to_owned())
    }
}

/// Scaled/reference packing of the complete private residual owner into the
/// unused cells of the same D23 x 16 table.  Only cache rows have a public
/// row-opening API; residual leaf and auxiliary cells remain private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C64JointTerminalLayoutReference {
    input_rows: usize,
    cache_rows: usize,
    leaf_rows: usize,
    closure_rows: usize,
    residual_rows: usize,
    auxiliary_offsets: [usize; C64_RESIDUAL_AUXILIARY_TABLES],
    auxiliary_lengths: [usize; C64_RESIDUAL_AUXILIARY_TABLES],
    cells: Vec<Fp>,
}

impl C64JointTerminalLayoutReference {
    pub fn new(
        input_rows: usize,
        cache_rows: &[[Fp; C64_JOINT_COLUMNS]],
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<Self, String> {
        if input_rows == 0 || !input_rows.is_power_of_two() {
            return Err("C6.4 terminal layout input rows are not a power of two".to_owned());
        }
        let leaf_rows = leaf.source_count() as usize;
        let closure_rows = closure.values().len();
        let residual_rows = leaf_rows.max(closure_rows);
        if auxiliary.closure_witness_digest() != closure.witness_digest() {
            return Err("C6.4 terminal layout owners differ".to_owned());
        }
        let cell_capacity = input_rows
            .checked_mul(C64_JOINT_COLUMNS)
            .ok_or_else(|| "C6.4 terminal layout capacity overflows".to_owned())?;
        if cache_rows.len() > input_rows {
            return Err("C6.4 cache rows exceed D23".to_owned());
        }
        let mut cells = vec![Fp::ZERO; cell_capacity];
        for (row, values) in cache_rows.iter().enumerate() {
            cells[row * C64_JOINT_COLUMNS..(row + 1) * C64_JOINT_COLUMNS].copy_from_slice(values);
        }
        let residual_start = cache_rows.len();
        if residual_start.checked_add(residual_rows).is_none_or(|end| end > input_rows) {
            return Err("C6.4 terminal leaf rows exceed D23".to_owned());
        }
        for (slot, column) in C6ResidualLeafColumn::ALL.into_iter().enumerate() {
            for (row, &value) in leaf.column(column).iter().enumerate() {
                write_fp2_cell(
                    &mut cells,
                    (residual_start + row) * C64_JOINT_COLUMNS + 2 * slot,
                    value,
                )?;
            }
        }
        for (row, &value) in closure.values().iter().enumerate() {
            write_fp2_cell(&mut cells, (residual_start + row) * C64_JOINT_COLUMNS + 14, value)?;
        }

        let mut cursor = residual_start
            .checked_add(residual_rows)
            .and_then(|rows| rows.checked_mul(C64_JOINT_COLUMNS))
            .ok_or_else(|| "C6.4 terminal auxiliary offset overflows".to_owned())?;
        let mut auxiliary_offsets = [0usize; C64_RESIDUAL_AUXILIARY_TABLES];
        let mut auxiliary_lengths = [0usize; C64_RESIDUAL_AUXILIARY_TABLES];
        for lane in C6ResidualAuxiliaryLane::ALL {
            auxiliary_offsets[lane.index()] = cursor;
            auxiliary_lengths[lane.index()] = auxiliary.lane(lane).len();
            for &value in auxiliary.lane(lane) {
                write_fp2_cell(&mut cells, cursor, value)?;
                cursor = cursor
                    .checked_add(2)
                    .ok_or_else(|| "C6.4 terminal auxiliary cursor overflows".to_owned())?;
            }
        }
        if cursor > cell_capacity {
            return Err("C6.4 complete residual owner exceeds the joint D23 table".to_owned());
        }
        Ok(Self {
            input_rows,
            cache_rows: cache_rows.len(),
            leaf_rows,
            closure_rows,
            residual_rows,
            auxiliary_offsets,
            auxiliary_lengths,
            cells,
        })
    }

    pub fn public_cache_row(&self, row: usize) -> Result<[Fp; C64_JOINT_COLUMNS], String> {
        if row >= self.cache_rows {
            return Err("C6.4 systematic opening attempted to expose a private row".to_owned());
        }
        self.cells[row * C64_JOINT_COLUMNS..(row + 1) * C64_JOINT_COLUMNS]
            .try_into()
            .map_err(|_| "C6.4 cache row geometry differs".to_owned())
    }

    pub fn physical_private_fp_values(&self) -> usize {
        self.leaf_rows * 14
            + self.closure_rows * 2
            + 2 * self.auxiliary_lengths.iter().sum::<usize>()
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/joint-terminal-layout/v1");
        hasher.update(&(self.input_rows as u64).to_le_bytes());
        hasher.update(&(self.cache_rows as u64).to_le_bytes());
        hasher.update(&(self.leaf_rows as u64).to_le_bytes());
        hasher.update(&(self.closure_rows as u64).to_le_bytes());
        hasher.update(&(self.residual_rows as u64).to_le_bytes());
        for (&offset, &length) in self.auxiliary_offsets.iter().zip(&self.auxiliary_lengths) {
            hasher.update(&(offset as u64).to_le_bytes());
            hasher.update(&(length as u64).to_le_bytes());
        }
        for value in &self.cells {
            hasher.update(&value.value().to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn private_message_reference(&self) -> Vec<Fp2> {
        self.cells.iter().copied().map(Fp2::from_base).collect()
    }

    pub fn coefficient_digest(coefficients: &[Fp2]) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c64/joint-terminal-coefficients/v1");
        hasher.update(&(coefficients.len() as u64).to_le_bytes());
        for value in coefficients {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Compile the one public coefficient vector whose inner product with
    /// the packed table equals a transcript-weighted fold of all 48 C6RSC3
    /// terminal claims. Production streams these coefficients into the
    /// existing authenticated sumcheck instead of materializing the vector.
    pub fn terminal_coefficients_reference(
        &self,
        leaf_points: [&[Fp2]; 2],
        auxiliary_points: [&[Fp2]; 2],
        claim_weights: &[Fp2; C64_RESIDUAL_TERMINAL_CLAIMS],
    ) -> Result<Vec<Fp2>, String> {
        let mut coefficients = vec![Fp2::ZERO; self.cells.len()];
        for repetition in 0..2 {
            if leaf_points[repetition].len() != self.input_rows.ilog2() as usize
                || auxiliary_points[repetition].len() >= leaf_points[repetition].len()
                || !leaf_points[repetition].ends_with(auxiliary_points[repetition])
            {
                return Err("C6.4 terminal point geometry differs".to_owned());
            }
            let leaf_eq = eq_vec(leaf_points[repetition]);
            let auxiliary_eq = eq_vec(auxiliary_points[repetition]);
            let claim_base =
                repetition * (C64_RESIDUAL_LEAF_TABLES + C64_RESIDUAL_AUXILIARY_TABLES);
            for slot in 0..C64_RESIDUAL_LEAF_TABLES {
                let rows = if slot == 7 { self.closure_rows } else { self.leaf_rows };
                for row in 0..rows {
                    add_fp2_coefficient(
                        &mut coefficients,
                        (self.cache_rows + row) * C64_JOINT_COLUMNS + 2 * slot,
                        claim_weights[claim_base + slot] * leaf_eq[row],
                    )?;
                }
            }
            for lane in 0..C64_RESIDUAL_AUXILIARY_TABLES {
                if self.auxiliary_lengths[lane] > auxiliary_eq.len() {
                    return Err("C6.4 auxiliary live prefix exceeds its terminal point".to_owned());
                }
                for (row, &equality) in
                    auxiliary_eq[..self.auxiliary_lengths[lane]].iter().enumerate()
                {
                    add_fp2_coefficient(
                        &mut coefficients,
                        self.auxiliary_offsets[lane] + 2 * row,
                        claim_weights[claim_base + C64_RESIDUAL_LEAF_TABLES + lane] * equality,
                    )?;
                }
            }
        }
        Ok(coefficients)
    }

    pub fn evaluate_terminal_functional_reference(
        &self,
        coefficients: &[Fp2],
    ) -> Result<Fp2, String> {
        if coefficients.len() != self.cells.len() {
            return Err("C6.4 terminal coefficient census differs".to_owned());
        }
        Ok(coefficients
            .iter()
            .zip(&self.cells)
            .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient.mul_base(value)))
    }
}

/// The corrected C6.4 PCS input. Columns are batched before encoding, so the
/// old padded multi-column wrapper is never materialized. The two raw
/// correction columns are concatenated so an arbitrary cache functional can
/// be linked after commitment; the other two families remain projections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C64ProjectedResidualReference {
    leaf_weights: [Fp2; C64_RESIDUAL_LEAF_TABLES],
    auxiliary_weights: [Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
    leaf_other: Vec<Fp2>,
    leaf_correction: Vec<Fp2>,
    auxiliary: Vec<Fp2>,
}

impl C64ProjectedResidualReference {
    pub fn new(
        leaf_rows: usize,
        auxiliary_rows: usize,
        leaf_column_point: &[Fp2],
        auxiliary_column_point: &[Fp2],
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<Self, String> {
        if !leaf_rows.is_power_of_two()
            || !auxiliary_rows.is_power_of_two()
            || leaf_column_point.len() != 3
            || auxiliary_column_point.len() != 4
            || leaf.source_count() as usize > leaf_rows
            || closure.values().len() > leaf_rows
            || C6ResidualAuxiliaryLane::ALL
                .into_iter()
                .any(|lane| auxiliary.lane(lane).len() > auxiliary_rows)
            || auxiliary.closure_witness_digest() != closure.witness_digest()
        {
            return Err("C6.4 projected residual geometry differs".to_owned());
        }
        let leaf_weights: [Fp2; C64_RESIDUAL_LEAF_TABLES] = eq_vec(leaf_column_point)
            .try_into()
            .map_err(|_| "C6.4 leaf column challenge differs".to_owned())?;
        let auxiliary_weights: [Fp2; C64_RESIDUAL_AUXILIARY_TABLES] =
            eq_vec(auxiliary_column_point)
                .try_into()
                .map_err(|_| "C6.4 auxiliary column challenge differs".to_owned())?;
        let mut leaf_other = vec![Fp2::ZERO; leaf_rows];
        let mut leaf_correction = vec![Fp2::ZERO; 2 * leaf_rows];
        for (slot, column) in C6ResidualLeafColumn::ALL.into_iter().enumerate() {
            if let Some(half) = [3, 6].iter().position(|&correction| correction == slot) {
                let values = leaf.column(column);
                let start = half * leaf_rows;
                leaf_correction[start..start + values.len()].copy_from_slice(values);
            } else {
                for (target, &value) in leaf_other.iter_mut().zip(leaf.column(column)) {
                    *target += leaf_weights[slot] * value;
                }
            }
        }
        for (target, &value) in leaf_other.iter_mut().zip(closure.values()) {
            *target += leaf_weights[7] * value;
        }
        let mut projected_auxiliary = vec![Fp2::ZERO; auxiliary_rows];
        for lane in C6ResidualAuxiliaryLane::ALL {
            for (target, &value) in projected_auxiliary.iter_mut().zip(auxiliary.lane(lane)) {
                *target += auxiliary_weights[lane.index()] * value;
            }
        }
        Ok(Self {
            leaf_weights,
            auxiliary_weights,
            leaf_other,
            leaf_correction,
            auxiliary: projected_auxiliary,
        })
    }

    pub fn leaf_weights(&self) -> &[Fp2; C64_RESIDUAL_LEAF_TABLES] {
        &self.leaf_weights
    }

    pub fn auxiliary_weights(&self) -> &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES] {
        &self.auxiliary_weights
    }

    pub fn leaf_other(&self) -> &[Fp2] {
        &self.leaf_other
    }

    pub fn leaf_correction(&self) -> &[Fp2] {
        &self.leaf_correction
    }

    pub fn auxiliary(&self) -> &[Fp2] {
        &self.auxiliary
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c64/projected-residual/v1");
        hasher.update(&(self.leaf_other.len() as u64).to_le_bytes());
        hasher.update(&(self.leaf_correction.len() as u64).to_le_bytes());
        hasher.update(&(self.auxiliary.len() as u64).to_le_bytes());
        for value in self
            .leaf_weights
            .iter()
            .chain(&self.auxiliary_weights)
            .chain(&self.leaf_other)
            .chain(&self.leaf_correction)
            .chain(&self.auxiliary)
        {
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64ProjectedResidualGpuCensus {
    pub source_fp2_values: u64,
    pub host_to_device_bytes: u64,
    pub projected_fp2_bytes: u64,
    pub base_limb_bytes: u64,
    pub upload_chunks: u64,
    pub scale_add_pairs: u64,
}

/// Six response-local base messages: two limbs for a D23 leaf projection,
/// two for the concatenated D24 corrections and two for the D15 auxiliary
/// projection. Source columns are uploaded in a
/// fixed-size mailbox and immediately folded; no padded multi-column wrapper
/// or joint D23x16 table exists on host or device.
#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
pub struct C64ProjectedResidualGpuOwner {
    backend: Arc<Mutex<Backend>>,
    leaf_other: [Option<DeviceBuffer<u64>>; 2],
    leaf_correction: [Option<DeviceBuffer<u64>>; 2],
    correction_message: Option<DeviceBuffer<Fp2Repr>>,
    auxiliary: [Option<DeviceBuffer<u64>>; 2],
    census: C64ProjectedResidualGpuCensus,
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
impl C64ProjectedResidualGpuOwner {
    pub fn build_production(
        mmcs: &C62GpuMmcs,
        leaf_weights: &[Fp2; C64_RESIDUAL_LEAF_TABLES],
        auxiliary_weights: &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<Self, String> {
        if leaf.production_allocation_binding_digest().is_none()
            || auxiliary.closure_witness_digest() != closure.witness_digest()
        {
            return Err("C6.4 production residual projection owners differ".to_owned());
        }
        Self::build(
            mmcs,
            1 << 23,
            1 << 15,
            leaf_weights,
            auxiliary_weights,
            leaf,
            closure,
            auxiliary,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        mmcs: &C62GpuMmcs,
        leaf_rows: usize,
        auxiliary_rows: usize,
        leaf_weights: &[Fp2; C64_RESIDUAL_LEAF_TABLES],
        auxiliary_weights: &[Fp2; C64_RESIDUAL_AUXILIARY_TABLES],
        leaf: &C6PairedResidualLeafWitness,
        closure: &C6PairedResidualClosureWitness,
        auxiliary: &C6PairedResidualAuxiliaryWitness,
    ) -> Result<Self, String> {
        if !leaf_rows.is_power_of_two()
            || !auxiliary_rows.is_power_of_two()
            || leaf.source_count() as usize > leaf_rows
            || closure.values().len() > leaf_rows
            || C6ResidualAuxiliaryLane::ALL
                .into_iter()
                .any(|lane| auxiliary.lane(lane).len() > auxiliary_rows)
            || auxiliary.closure_witness_digest() != closure.witness_digest()
        {
            return Err("C6.4 GPU residual projection geometry differs".to_owned());
        }
        let backend = mmcs.backend();
        let leaf_sources = C6ResidualLeafColumn::ALL
            .into_iter()
            .enumerate()
            .map(|(slot, column)| (slot, leaf.column(column), leaf_weights[slot]))
            .collect::<Vec<_>>();
        let leaf_other_sources = leaf_sources
            .iter()
            .filter(|(slot, _, _)| !matches!(slot, 3 | 6))
            .map(|(_, values, weight)| (*values, *weight))
            .chain(std::iter::once((closure.values(), leaf_weights[7])))
            .collect::<Vec<_>>();
        let leaf_correction_sources = leaf_sources
            .iter()
            .filter(|(slot, _, _)| matches!(slot, 3 | 6))
            .map(|(_, values, _)| *values)
            .collect::<Vec<_>>();
        let auxiliary_sources = C6ResidualAuxiliaryLane::ALL
            .into_iter()
            .map(|lane| (auxiliary.lane(lane), auxiliary_weights[lane.index()]))
            .collect::<Vec<_>>();
        let (leaf_other_limbs, leaf_other_census) =
            project_c64_family(&backend, leaf_rows, &leaf_other_sources)?;
        let (leaf_correction_limbs, correction_message, leaf_correction_census) =
            match concatenate_c64_family(&backend, leaf_rows, &leaf_correction_sources) {
                Ok(value) => value,
                Err(error) => {
                    free_c64_limbs(&backend, leaf_other_limbs);
                    return Err(error);
                }
            };
        let (auxiliary_limbs, auxiliary_census) =
            match project_c64_family(&backend, auxiliary_rows, &auxiliary_sources) {
                Ok(value) => value,
                Err(error) => {
                    free_c64_limbs(&backend, leaf_other_limbs);
                    free_c64_limbs(&backend, leaf_correction_limbs);
                    free_c64_message(&backend, correction_message);
                    return Err(error);
                }
            };
        let census = C64ProjectedResidualGpuCensus {
            source_fp2_values: leaf_other_census.0 + leaf_correction_census.0 + auxiliary_census.0,
            host_to_device_bytes: (leaf_other_census.0
                + leaf_correction_census.0
                + auxiliary_census.0)
                * 16,
            projected_fp2_bytes: ((3 * leaf_rows + auxiliary_rows) * 16) as u64,
            base_limb_bytes: ((3 * leaf_rows + auxiliary_rows) * 16) as u64,
            upload_chunks: leaf_other_census.1 + leaf_correction_census.1 + auxiliary_census.1,
            scale_add_pairs: (leaf_other_sources.len() + auxiliary_sources.len()) as u64,
        };
        Ok(Self {
            backend,
            leaf_other: leaf_other_limbs.map(Some),
            leaf_correction: leaf_correction_limbs.map(Some),
            correction_message: Some(correction_message),
            auxiliary: auxiliary_limbs.map(Some),
            census,
        })
    }

    pub fn take_leaf_other_limb(&mut self, limb: usize) -> Result<DeviceBuffer<u64>, String> {
        self.leaf_other
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| "C6.4 projected other-leaf limb is absent".to_owned())
    }

    pub fn take_leaf_correction_limb(&mut self, limb: usize) -> Result<DeviceBuffer<u64>, String> {
        self.leaf_correction
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| "C6.4 projected correction-leaf limb is absent".to_owned())
    }

    pub fn take_correction_message(&mut self) -> Result<DeviceBuffer<Fp2Repr>, String> {
        self.correction_message.take().ok_or_else(|| "C6.4 correction message is absent".to_owned())
    }

    pub fn take_auxiliary_limb(&mut self, limb: usize) -> Result<DeviceBuffer<u64>, String> {
        self.auxiliary
            .get_mut(limb)
            .and_then(Option::take)
            .ok_or_else(|| "C6.4 projected auxiliary limb is absent".to_owned())
    }

    pub fn census(&self) -> C64ProjectedResidualGpuCensus {
        self.census
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
impl Drop for C64ProjectedResidualGpuOwner {
    fn drop(&mut self) {
        if let Ok(mut backend) = self.backend.lock() {
            for limb in self
                .leaf_other
                .iter_mut()
                .chain(&mut self.leaf_correction)
                .chain(&mut self.auxiliary)
                .filter_map(Option::take)
            {
                let _ = backend.free_device(limb);
            }
            if let Some(message) = self.correction_message.take() {
                let _ = backend.free_device(message);
            }
        }
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn project_c64_family(
    backend: &Arc<Mutex<Backend>>,
    rows: usize,
    sources: &[(&[Fp2], Fp2)],
) -> Result<([DeviceBuffer<u64>; 2], (u64, u64)), String> {
    const CHUNK: usize = 1 << 20;
    let max_live = sources.iter().map(|(values, _)| values.len()).max().unwrap_or(0);
    if max_live == 0 || max_live > rows {
        return Err("C6.4 projected family source geometry differs".to_owned());
    }
    let mut locked = backend.lock().map_err(|_| "CUDA lock".to_owned())?;
    let output = locked.alloc_device::<Fp2Repr>(rows).map_err(|error| error.to_string())?;
    if let Err(error) = locked.zero_device(&output, 0, rows) {
        let _ = locked.free_device(output);
        return Err(error.to_string());
    }
    let mailbox = match locked.alloc_device::<Fp2Repr>(max_live.min(CHUNK)) {
        Ok(value) => value,
        Err(error) => {
            let _ = locked.free_device(output);
            return Err(error.to_string());
        }
    };
    let mut source_values = 0u64;
    let mut chunks = 0u64;
    let operation = (|| {
        for &(values, weight) in sources {
            source_values += values.len() as u64;
            for (chunk, values) in values.chunks(CHUNK).enumerate() {
                let encoded = values.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
                locked.upload_device(&mailbox, 0, &encoded)?;
                locked.fp2_scale_inplace_device(&mailbox, 0, encoded.len(), weight)?;
                locked.fp2_add_inplace_device(
                    &output,
                    chunk * CHUNK,
                    &mailbox,
                    0,
                    encoded.len(),
                )?;
                chunks += 1;
            }
        }
        locked.fp2_to_base_limbs_device(&output)
    })();
    let mailbox_cleanup = locked.free_device(mailbox);
    let output_cleanup = locked.free_device(output);
    match (operation, mailbox_cleanup, output_cleanup) {
        (Ok(limbs), Ok(()), Ok(())) => Ok((limbs, (source_values, chunks))),
        (Ok(limbs), mailbox, output) => {
            for limb in limbs {
                let _ = locked.free_device(limb);
            }
            mailbox.and(output).map_err(|error| error.to_string())?;
            Err("C6.4 projected family cleanup failed".to_owned())
        }
        (Err(error), _, _) => Err(error.to_string()),
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn concatenate_c64_family(
    backend: &Arc<Mutex<Backend>>,
    rows: usize,
    sources: &[&[Fp2]],
) -> Result<([DeviceBuffer<u64>; 2], DeviceBuffer<Fp2Repr>, (u64, u64)), String> {
    const CHUNK: usize = 1 << 20;
    if sources.len() != 2 || sources.iter().any(|values| values.len() > rows) {
        return Err("C6.4 correction concatenation geometry differs".to_owned());
    }
    let max_live = sources.iter().map(|values| values.len()).max().unwrap_or(0);
    if max_live == 0 {
        return Err("C6.4 correction concatenation is empty".to_owned());
    }
    let mut locked = backend.lock().map_err(|_| "CUDA lock".to_owned())?;
    let output = locked.alloc_device::<Fp2Repr>(2 * rows).map_err(|error| error.to_string())?;
    if let Err(error) = locked.zero_device(&output, 0, 2 * rows) {
        let _ = locked.free_device(output);
        return Err(error.to_string());
    }
    let mailbox = match locked.alloc_device::<Fp2Repr>(max_live.min(CHUNK)) {
        Ok(value) => value,
        Err(error) => {
            let _ = locked.free_device(output);
            return Err(error.to_string());
        }
    };
    let mut chunks = 0u64;
    let operation = (|| {
        for (half, values) in sources.iter().enumerate() {
            for (chunk, values) in values.chunks(CHUNK).enumerate() {
                let encoded = values.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
                locked.upload_device(&mailbox, 0, &encoded)?;
                locked.fp2_add_inplace_device(
                    &output,
                    half * rows + chunk * CHUNK,
                    &mailbox,
                    0,
                    encoded.len(),
                )?;
                chunks += 1;
            }
        }
        locked.fp2_to_base_limbs_device(&output)
    })();
    let mailbox_cleanup = locked.free_device(mailbox);
    match (operation, mailbox_cleanup) {
        (Ok(limbs), Ok(())) => {
            Ok((limbs, output, (sources.iter().map(|values| values.len() as u64).sum(), chunks)))
        }
        (Ok(limbs), Err(error)) => {
            for limb in limbs {
                let _ = locked.free_device(limb);
            }
            let _ = locked.free_device(output);
            Err(error.to_string())
        }
        (Err(error), _) => {
            let _ = locked.free_device(output);
            Err(error.to_string())
        }
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn free_c64_limbs(backend: &Arc<Mutex<Backend>>, limbs: [DeviceBuffer<u64>; 2]) {
    if let Ok(mut backend) = backend.lock() {
        for limb in limbs {
            let _ = backend.free_device(limb);
        }
    }
}

#[cfg(all(feature = "cuda", feature = "c61-p3-authenticated-reference"))]
fn free_c64_message(backend: &Arc<Mutex<Backend>>, message: DeviceBuffer<Fp2Repr>) {
    if let Ok(mut backend) = backend.lock() {
        let _ = backend.free_device(message);
    }
}

fn write_fp2_cell(cells: &mut [Fp], offset: usize, value: Fp2) -> Result<(), String> {
    let target = cells
        .get_mut(offset..offset + 2)
        .ok_or_else(|| "C6.4 packed Fp2 exceeds the joint table".to_owned())?;
    target.copy_from_slice(&[value.c0, value.c1]);
    Ok(())
}

fn add_fp2_coefficient(
    coefficients: &mut [Fp2],
    offset: usize,
    coefficient: Fp2,
) -> Result<(), String> {
    let target = coefficients
        .get_mut(offset..offset + 2)
        .ok_or_else(|| "C6.4 packed coefficient exceeds the joint table".to_owned())?;
    target[0] += coefficient;
    target[1] += coefficient * Fp2::new(Fp::ZERO, Fp::ONE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c63_authenticated_sketch::C63SparseSketchEdge;

    fn fp(value: u64) -> Fp {
        Fp::new(value)
    }

    fn fixture_sketch() -> C63SparseSketchReference {
        let edges = (0..8u32)
            .flat_map(|input| {
                (0..2u8).map(move |socket_ordinal| C63SparseSketchEdge {
                    input,
                    socket_ordinal,
                    output: (input + u32::from(socket_ordinal)) % 4,
                    coefficient: fp(3 + u64::from(input) + u64::from(socket_ordinal)),
                })
            })
            .collect();
        C63SparseSketchReference::new(8, 4, edges).unwrap()
    }

    fn fixture_layout() -> C64JointCorrectionLayout {
        let cache = vec![
            C64JointCorrectionRow::cache(std::array::from_fn(|column| fp(column as u64 + 1))),
            C64JointCorrectionRow::cache(std::array::from_fn(|column| fp(column as u64 + 21))),
        ];
        let residual = vec![
            C64JointCorrectionRow::residual([Fp2::new(fp(41), fp(42)), Fp2::new(fp(43), fp(44))]),
            C64JointCorrectionRow::residual([Fp2::new(fp(51), fp(52)), Fp2::new(fp(53), fp(54))]),
        ];
        C64JointCorrectionLayout::reference(8, cache, residual, [0x64; 32], [0xa4; 32]).unwrap()
    }

    #[test]
    fn joint_and_separately_streamed_sketches_match() {
        let layout = fixture_layout();
        let sketch = fixture_sketch();
        assert_eq!(
            layout.apply_joint(&sketch).unwrap(),
            layout.verify_separate_streaming_identity(&sketch).unwrap()
        );
        assert_eq!(
            layout.census().unwrap(),
            C64JointSketchCensus {
                input_rows: 8,
                cache_rows: 2,
                residual_rows: 2,
                live_rows: 4,
                physical_public_values: 40,
                virtual_zero_values: 88,
                active_edge_updates: 640,
            }
        );
    }

    #[test]
    fn row_order_binding_and_private_columns_fail_closed() {
        let original = fixture_layout();
        let original_digest = original.binding_digest();

        let mut reordered_residual = original.residual_rows.clone();
        reordered_residual.swap(0, 1);
        let reordered = C64JointCorrectionLayout::reference(
            8,
            original.cache_rows.clone(),
            reordered_residual,
            original.source_schedule_digest,
            original.allocation_binding_digest,
        )
        .unwrap();
        assert_ne!(reordered.binding_digest(), original_digest);
        assert_ne!(
            reordered.apply_joint(&fixture_sketch()).unwrap(),
            original.apply_joint(&fixture_sketch()).unwrap()
        );

        let mut leaking = C64JointCorrectionRow::residual([Fp2::ONE, Fp2::ONE]);
        leaking.columns[C64_RESIDUAL_PUBLIC_COLUMNS] = Fp::ONE;
        assert!(C64JointCorrectionLayout::reference(
            8,
            original.cache_rows,
            vec![leaking],
            [0x64; 32],
            [0xa4; 32],
        )
        .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn projected_residual_matches_all_twenty_four_column_openings() {
        use volta_proto::{build_c6_residual_direct_fused_scaled_fixture, mle::eval_mle};

        let fixture = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let leaf_rows = 1usize << fixture.manifest().leaf_log2();
        let auxiliary_rows = 1usize << fixture.manifest().auxiliary_log2();
        let leaf_column_point =
            [Fp2::new(fp(101), fp(103)), Fp2::new(fp(107), fp(109)), Fp2::new(fp(113), fp(127))];
        let auxiliary_column_point = [
            Fp2::new(fp(131), fp(137)),
            Fp2::new(fp(139), fp(149)),
            Fp2::new(fp(151), fp(157)),
            Fp2::new(fp(163), fp(167)),
        ];
        let projected = C64ProjectedResidualReference::new(
            leaf_rows,
            auxiliary_rows,
            &leaf_column_point,
            &auxiliary_column_point,
            fixture.leaf_witness(),
            fixture.closure_witness(),
            fixture.auxiliary_witness(),
        )
        .unwrap();
        assert_ne!(projected.binding_digest(), [0; 32]);

        for repetition in 0..2u64 {
            let leaf_point = (0..fixture.manifest().leaf_log2())
                .map(|index| {
                    Fp2::new(fp(211 + repetition * 31 + index as u64), fp(307 + index as u64))
                })
                .collect::<Vec<_>>();
            let auxiliary_point = leaf_point
                [leaf_point.len() - fixture.manifest().auxiliary_log2() as usize..]
                .to_vec();
            let mut expected_leaf = Fp2::ZERO;
            for (slot, column) in C6ResidualLeafColumn::ALL.into_iter().enumerate() {
                expected_leaf += projected.leaf_weights()[slot]
                    * eval_mle(fixture.leaf_witness().column(column), &leaf_point);
            }
            expected_leaf += projected.leaf_weights()[7]
                * eval_mle(fixture.closure_witness().values(), &leaf_point);
            let expected_auxiliary =
                C6ResidualAuxiliaryLane::ALL.into_iter().fold(Fp2::ZERO, |sum, lane| {
                    sum + projected.auxiliary_weights()[lane.index()]
                        * eval_mle(fixture.auxiliary_witness().lane(lane), &auxiliary_point)
                });
            assert_eq!(
                eval_mle(projected.leaf_other(), &leaf_point)
                    + {
                        let mut correction_point = leaf_point.clone();
                        correction_point.push(Fp2::ZERO);
                        projected.leaf_weights()[3]
                            * eval_mle(projected.leaf_correction(), &correction_point)
                    }
                    + {
                        let mut correction_point = leaf_point.clone();
                        correction_point.push(Fp2::ONE);
                        projected.leaf_weights()[6]
                            * eval_mle(projected.leaf_correction(), &correction_point)
                    },
                expected_leaf
            );
            assert_eq!(eval_mle(projected.auxiliary(), &auxiliary_point), expected_auxiliary);
        }

        let mut changed = projected.clone();
        changed.leaf_other[0] += Fp2::ONE;
        assert_ne!(changed.binding_digest(), projected.binding_digest());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn complete_terminal_functional_matches_packed_joint_table() {
        use crate::c63_sparse_h_closure::{
            prove_c64_terminal_link_reference, verify_c64_terminal_link_reference,
            C63SparseHClosureProof, C64TerminalLinkStatement,
            C64_TERMINAL_LINK_PRODUCTION_FRAMED_BYTES,
            C64_TERMINAL_LINK_PRODUCTION_FULL_CORRELATIONS_PER_TAPE,
            C64_TERMINAL_LINK_PRODUCTION_ROUNDS,
        };
        use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
        use volta_proto::{build_c6_residual_direct_fused_scaled_fixture, mle::eval_mle};

        let fixture = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        assert_eq!(C64_TERMINAL_LINK_PRODUCTION_ROUNDS, 27);
        assert_eq!(56 + 27 * 64 + 32, C64_TERMINAL_LINK_PRODUCTION_FRAMED_BYTES);
        assert_eq!(
            2 * C64_TERMINAL_LINK_PRODUCTION_ROUNDS,
            C64_TERMINAL_LINK_PRODUCTION_FULL_CORRELATIONS_PER_TAPE
        );
        let cache = vec![[Fp::new(101); C64_JOINT_COLUMNS], [Fp::new(103); C64_JOINT_COLUMNS]];
        let layout = C64JointTerminalLayoutReference::new(
            128,
            &cache,
            fixture.leaf_witness(),
            fixture.closure_witness(),
            fixture.auxiliary_witness(),
        )
        .unwrap();
        let leaf_points: [Vec<Fp2>; 2] = std::array::from_fn(|repetition| {
            (0..7)
                .map(|index| Fp2::new(fp(211 + 17 * repetition as u64 + index), fp(307 + index)))
                .collect()
        });
        let auxiliary_points: [Vec<Fp2>; 2] =
            std::array::from_fn(|repetition| leaf_points[repetition][5..].to_vec());
        let weights = std::array::from_fn(|index| {
            Fp2::new(fp(401 + index as u64), fp(701 + 3 * index as u64))
        });
        let coefficients = layout
            .terminal_coefficients_reference(
                [&leaf_points[0], &leaf_points[1]],
                [&auxiliary_points[0], &auxiliary_points[1]],
                &weights,
            )
            .unwrap();
        let mut expected = Fp2::ZERO;
        for repetition in 0..2 {
            let base = repetition * 24;
            for (slot, column) in C6ResidualLeafColumn::ALL.into_iter().enumerate() {
                expected += weights[base + slot]
                    * eval_mle(fixture.leaf_witness().column(column), &leaf_points[repetition]);
            }
            expected += weights[base + 7]
                * eval_mle(fixture.closure_witness().values(), &leaf_points[repetition]);
            for lane in C6ResidualAuxiliaryLane::ALL {
                expected += weights[base + 8 + lane.index()]
                    * eval_mle(
                        fixture.auxiliary_witness().lane(lane),
                        &auxiliary_points[repetition],
                    );
            }
        }
        assert_eq!(layout.evaluate_terminal_functional_reference(&coefficients).unwrap(), expected);
        assert_eq!(layout.public_cache_row(0).unwrap(), cache[0]);
        assert!(layout.public_cache_row(cache.len()).is_err());

        let mut changed = layout.clone();
        changed.cells[cache.len() * C64_JOINT_COLUMNS] += Fp::ONE;
        assert_ne!(
            changed.evaluate_terminal_functional_reference(&coefficients).unwrap(),
            expected
        );
        assert_ne!(changed.binding_digest(), layout.binding_digest());

        let message = layout.private_message_reference();
        let claim = layout.evaluate_terminal_functional_reference(&coefficients).unwrap();
        let statement = C64TerminalLinkStatement::new(
            layout.binding_digest(),
            C64JointTerminalLayoutReference::coefficient_digest(&coefficients),
            [0x48; 32],
            message.len().ilog2() as u8,
        )
        .unwrap();
        let deltas = [Fp2::new(fp(811), fp(821)), Fp2::new(fp(823), fp(827))];
        let initial_tags = [Fp2::new(fp(829), fp(839)), Fp2::new(fp(853), fp(857))];
        let initial_claims =
            std::array::from_fn(|tape| ProverAuthed::new(claim, initial_tags[tape]));
        let initial_keys =
            std::array::from_fn(|tape| VerifierKey::new(initial_tags[tape] + deltas[tape] * claim));
        let seeds = [[0x64; 32], [0x65; 32]];
        let mut streams = std::array::from_fn(|tape| CorrelationStream::new(seeds[tape]));
        let mut prover_transcript = Transcript::new([0x66; 32]);
        let (proof, opening_point, opening_claims) = prove_c64_terminal_link_reference(
            &coefficients,
            &message,
            initial_claims,
            &statement,
            &mut streams,
            &mut prover_transcript,
        )
        .unwrap();
        assert_eq!(opening_claims[0].x, eval_mle(&message, &opening_point));
        assert_eq!(proof.round_count(), 11);
        assert_eq!(proof.encoded_len().unwrap(), 792);
        assert!(streams
            .iter()
            .all(|stream| stream.counters.full_corrs == 2 * proof.round_count() as u64));
        let encoded = proof.encode().unwrap();
        let decoded = C63SparseHClosureProof::decode(&encoded).unwrap();
        let mut contexts = std::array::from_fn(|tape| VerifierCtx::new(seeds[tape], deltas[tape]));
        let mut verifier_transcript = Transcript::new([0x66; 32]);
        let audit = verify_c64_terminal_link_reference(
            &coefficients,
            initial_keys,
            &statement,
            &decoded,
            &mut contexts,
            &mut verifier_transcript,
        )
        .unwrap();
        for tape in 0..2 {
            assert_eq!(
                audit.terminal_m_keys[tape].k,
                opening_claims[tape].m + deltas[tape] * opening_claims[tape].x
            );
        }
        assert_eq!(audit.transcript_bytes, 792);
        assert_eq!(prover_transcript.ledger(), verifier_transcript.ledger());

        let mut wrong_keys = initial_keys;
        wrong_keys[0] = wrong_keys[0].add(VerifierKey::new(Fp2::ONE));
        let mut wrong_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(seeds[tape], deltas[tape]));
        let mut wrong_transcript = Transcript::new([0x66; 32]);
        let wrong_audit = verify_c64_terminal_link_reference(
            &coefficients,
            wrong_keys,
            &statement,
            &decoded,
            &mut wrong_contexts,
            &mut wrong_transcript,
        )
        .unwrap();
        assert_ne!(wrong_audit.terminal_m_keys[0], audit.terminal_m_keys[0]);
    }
}

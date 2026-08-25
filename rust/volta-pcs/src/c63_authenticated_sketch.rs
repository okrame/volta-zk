//! Compact cache-transition and authenticated-sketch references for C6.3.
//!
//! This module implements only the executable K/V layout, append semantics,
//! Bolt row permutation, candidate typed correction root, a scaled setup
//! sampler, and the linear identities needed by the future authenticated WHIR
//! bridge. It is not a proof, production setup generator, proof codec, or GPU
//! path.

use volta_field::{Fp, Fp2};
use volta_mac::{CorrScheduleAudit, CorrScheduleKind, CorrScheduleRole};
#[cfg(test)]
use volta_mac::{ProverAuthed, VerifierKey};
#[cfg(feature = "c6-trace")]
use volta_proto::c6_cache_fold::{C6CacheFoldAppendSourcePlan, C6CacheFoldKind};
use volta_proto::mle::eq_vec;
#[cfg(feature = "c6-trace")]
use volta_proto::{C6PairedSourceWitness, C6ProductionPairedSourceWitness};

use crate::c6_persistent_cache::{
    expected_c6_cache_append_cells, C6CacheCell, C6CacheSlotKind, C6CacheSourceValue,
    C6PersistentCacheLayout, C6_PERSISTENT_CACHE_LIVE_SLOTS, C6_PERSISTENT_CACHE_SLOTS,
};
use crate::merkle::{hash_pair, multi_root, Hash, MerkleTree};

pub const C63_BOLT_ROW_LOG2: u8 = 22;
pub const C63_BOLT_COLUMN_LOG2: u8 = 4;
pub const C63_BOLT_ROWS: usize = 1 << C63_BOLT_ROW_LOG2;
pub const C63_BOLT_COLUMNS: usize = 1 << C63_BOLT_COLUMN_LOG2;
pub const C63_BOLT_ROWS_PER_POSITION: usize = 1 << 12;
pub const C63_BOLT_LIVE_ROWS_PER_POSITION: usize = 6 << 9;
pub const C63_BOLT_SKETCH_ROW_LOG2: u8 = 19;
pub const C63_BOLT_SKETCH_ROWS: usize = 1 << C63_BOLT_SKETCH_ROW_LOG2;
pub const C63_BOLT_LDPC_COLUMN_DEGREE: u8 = 16;
pub const C63_BOLT_LDPC_CHECK_DEGREE: u16 = 128;
pub const C63_SYSTEMATIC_SPOT_QUERIES: usize = 4_420;
pub const C63_SPARSE_SETUP_DESCRIPTOR_BYTES: usize = 80;
pub const C63_CORRECTION_ROW_FRAME_WORDS: usize = 27;
/// Public one-shot production setup seed fixed before the first C6.3 pod run.
pub const C63_PRODUCTION_SETUP_SEED: Hash = [
    0xde, 0xda, 0x54, 0xf4, 0x05, 0x26, 0x5c, 0xd5, 0xf5, 0x7b, 0x0b, 0xae, 0xc7, 0x9f, 0xbc, 0x6f,
    0xcd, 0x1e, 0x51, 0x49, 0xf6, 0x89, 0x37, 0xe2, 0x8b, 0xb0, 0x73, 0x73, 0x38, 0xc5, 0xbd, 0xea,
];

const C63_CORRECTION_TREE_MAGIC: [u8; 8] = *b"C63CR3\0\0";
const C63_VIRTUAL_ROW_MAGIC: [u8; 8] = *b"C63VZ3\0\0";
const C63_CORRECTION_TREE_VERSION: u16 = 3;
const C63_STATE_ROOT_HASH_CONTEXT: &str = "volta-zk/c63/correction-state-root/v2";
const C63_CORRECTION_OPENING_MAGIC: [u8; 8] = *b"C63CRM2\0";
const C63_CORRECTION_OPENING_VERSION: u16 = 2;
const C63_SPARSE_SETUP_MAGIC: [u8; 8] = *b"C63HSM1\0";
const C63_SPARSE_SETUP_VERSION: u16 = 1;
const C63_SPARSE_SETUP_FIELD_ID_GOLDILOCKS: u16 = 1;
const C63_SPARSE_SETUP_MAX_REJECTION_DRAWS: usize = 4;
const C63_SPARSE_SETUP_PERMUTATION_CONTEXT: &str = "volta-zk/c63/sparse-H/permutation/v1";
const C63_SPARSE_SETUP_COEFFICIENT_CONTEXT: &str = "volta-zk/c63/sparse-H/coefficient/v1";
const C63_SPARSE_SETUP_DIGEST_CONTEXT: &str = "volta-zk/c63/sparse-H/expanded-digest/v1";

/// Compact setup descriptor. The expanded edge table is derived, never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63SparseSetupDescriptor {
    input_log2: u8,
    column_degree: u8,
    check_degree: u16,
    seed: Hash,
    expanded_h_digest: Hash,
}

impl C63SparseSetupDescriptor {
    fn new(
        input_len: usize,
        output_len: usize,
        column_degree: u8,
        check_degree: u16,
        seed: Hash,
        expanded_h_digest: Hash,
    ) -> Result<Self, String> {
        if expanded_h_digest == [0; 32] {
            return Err("C6.3 sparse setup digest is zero".to_owned());
        }
        if !input_len.is_power_of_two() {
            return Err("C6.3 sparse setup descriptor input is not a power of two".to_owned());
        }
        let descriptor = Self {
            input_log2: u8::try_from(input_len.ilog2())
                .map_err(|_| "C6.3 sparse setup descriptor input log exceeds u8".to_owned())?,
            column_degree,
            check_degree,
            seed,
            expanded_h_digest,
        };
        let (decoded_input, decoded_output, _, _) = descriptor.geometry()?;
        if (decoded_input, decoded_output) != (input_len, output_len) {
            return Err("C6.3 sparse setup descriptor geometry differs".to_owned());
        }
        Ok(descriptor)
    }

    pub fn seed(&self) -> Hash {
        self.seed
    }

    pub fn expanded_h_digest(&self) -> Hash {
        self.expanded_h_digest
    }

    pub fn encode(&self) -> Result<[u8; C63_SPARSE_SETUP_DESCRIPTOR_BYTES], String> {
        self.geometry()?;
        if self.expanded_h_digest == [0; 32] {
            return Err("C6.3 sparse setup digest is zero".to_owned());
        }
        let mut bytes = [0u8; C63_SPARSE_SETUP_DESCRIPTOR_BYTES];
        bytes[..8].copy_from_slice(&C63_SPARSE_SETUP_MAGIC);
        bytes[8..10].copy_from_slice(&C63_SPARSE_SETUP_VERSION.to_le_bytes());
        bytes[10] = self.input_log2;
        bytes[11] = self.column_degree;
        bytes[12..14].copy_from_slice(&self.check_degree.to_le_bytes());
        bytes[14..16].copy_from_slice(&C63_SPARSE_SETUP_FIELD_ID_GOLDILOCKS.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.seed);
        bytes[48..80].copy_from_slice(&self.expanded_h_digest);
        Ok(bytes)
    }

    /// Parse canonical framing only; call
    /// [`C63SparseSetupReference::verify_production_descriptor`] for binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != C63_SPARSE_SETUP_DESCRIPTOR_BYTES
            || bytes[..8] != C63_SPARSE_SETUP_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed C63HSM1 version"))
                != C63_SPARSE_SETUP_VERSION
            || u16::from_le_bytes(bytes[14..16].try_into().expect("fixed C63HSM1 field"))
                != C63_SPARSE_SETUP_FIELD_ID_GOLDILOCKS
        {
            return Err("C6.3 sparse setup descriptor is noncanonical".to_owned());
        }
        Self::new(
            1usize
                .checked_shl(u32::from(bytes[10]))
                .ok_or_else(|| "C6.3 sparse setup descriptor input log is invalid".to_owned())?,
            1usize
                .checked_shl(u32::from(bytes[10]))
                .and_then(|input_len| input_len.checked_mul(usize::from(bytes[11])))
                .and_then(|socket_count| {
                    let check_degree = usize::from(u16::from_le_bytes(
                        bytes[12..14].try_into().expect("fixed C63HSM1 degree"),
                    ));
                    (check_degree != 0 && socket_count % check_degree == 0)
                        .then_some(socket_count / check_degree)
                })
                .ok_or_else(|| "C6.3 sparse setup descriptor geometry is invalid".to_owned())?,
            bytes[11],
            u16::from_le_bytes(bytes[12..14].try_into().expect("fixed C63HSM1 degree")),
            bytes[16..48].try_into().expect("fixed C63HSM1 seed"),
            bytes[48..80].try_into().expect("fixed C63HSM1 digest"),
        )
    }

    fn geometry(&self) -> Result<(usize, usize, u8, u16), String> {
        let input_len = 1usize
            .checked_shl(u32::from(self.input_log2))
            .ok_or_else(|| "C6.3 sparse setup descriptor input log is invalid".to_owned())?;
        let socket_count = input_len
            .checked_mul(usize::from(self.column_degree))
            .ok_or_else(|| "C6.3 sparse setup descriptor socket count overflows".to_owned())?;
        let check_degree = usize::from(self.check_degree);
        if self.column_degree == 0
            || self.column_degree > C63_BOLT_LDPC_COLUMN_DEGREE
            || check_degree == 0
            || socket_count % check_degree != 0
        {
            return Err("C6.3 sparse setup descriptor geometry is invalid".to_owned());
        }
        Ok((input_len, socket_count / check_degree, self.column_degree, self.check_degree))
    }
}

/// Scaled executable form of the exact YHC socket-bijection sampler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseSetupReference {
    seed: Hash,
    input_len: usize,
    output_len: usize,
    column_degree: u8,
    check_degree: u16,
    permutation: Vec<u32>,
    coefficients: Vec<Fp>,
    expanded_h_digest: Hash,
}

impl C63SparseSetupReference {
    pub fn sample(
        seed: Hash,
        input_len: usize,
        output_len: usize,
        column_degree: u8,
        check_degree: u16,
    ) -> Result<Self, String> {
        let socket_count = input_len
            .checked_mul(usize::from(column_degree))
            .ok_or_else(|| "C6.3 sparse setup socket count overflows".to_owned())?;
        if input_len == 0
            || output_len == 0
            || column_degree == 0
            || column_degree > C63_BOLT_LDPC_COLUMN_DEGREE
            || check_degree == 0
            || output_len.checked_mul(usize::from(check_degree)) != Some(socket_count)
            || socket_count > u32::MAX as usize
        {
            return Err("C6.3 sparse setup geometry is invalid".to_owned());
        }
        let geometry =
            c63_sparse_setup_geometry(input_len, output_len, column_degree, check_degree)?;
        let mut permutation_reader =
            c63_sparse_setup_reader(C63_SPARSE_SETUP_PERMUTATION_CONTEXT, seed, &geometry);
        let mut permutation = (0..socket_count as u32).collect::<Vec<_>>();
        for upper in (1..socket_count).rev() {
            let selected = c63_sparse_setup_bounded(&mut permutation_reader, upper as u64 + 1)?;
            permutation.swap(upper, selected as usize);
        }

        let mut coefficient_reader =
            c63_sparse_setup_reader(C63_SPARSE_SETUP_COEFFICIENT_CONTEXT, seed, &geometry);
        let coefficients = (0..socket_count)
            .map(|_| c63_sparse_setup_nonzero_coefficient(&mut coefficient_reader))
            .collect::<Result<Vec<_>, _>>()?;
        let expanded_h_digest =
            c63_sparse_setup_expanded_digest(&geometry, &permutation, &coefficients);
        C63SparseSetupDescriptor::new(
            input_len,
            output_len,
            column_degree,
            check_degree,
            seed,
            expanded_h_digest,
        )?;
        Ok(Self {
            seed,
            input_len,
            output_len,
            column_degree,
            check_degree,
            permutation,
            coefficients,
            expanded_h_digest,
        })
    }

    pub fn expanded_h_digest(&self) -> Hash {
        self.expanded_h_digest
    }

    pub fn descriptor(&self) -> C63SparseSetupDescriptor {
        C63SparseSetupDescriptor::new(
            self.input_len,
            self.output_len,
            self.column_degree,
            self.check_degree,
            self.seed,
            self.expanded_h_digest,
        )
        .expect("sampled C6.3 setup has a canonical descriptor")
    }

    /// Regenerate the sampled matrix and reject any seed/digest substitution.
    fn verify_descriptor(descriptor: C63SparseSetupDescriptor) -> Result<Self, String> {
        let (input_len, output_len, column_degree, check_degree) = descriptor.geometry()?;
        let setup =
            Self::sample(descriptor.seed, input_len, output_len, column_degree, check_degree)?;
        if setup.expanded_h_digest != descriptor.expanded_h_digest {
            return Err("C6.3 sparse setup descriptor digest differs".to_owned());
        }
        Ok(setup)
    }

    pub fn verify_production_descriptor(
        descriptor: C63SparseSetupDescriptor,
    ) -> Result<Self, String> {
        if descriptor.geometry()?
            != (
                C63_BOLT_ROWS,
                C63_BOLT_SKETCH_ROWS,
                C63_BOLT_LDPC_COLUMN_DEGREE,
                C63_BOLT_LDPC_CHECK_DEGREE,
            )
        {
            return Err("C6.3 sparse setup descriptor is not the production profile".to_owned());
        }
        Self::verify_descriptor(descriptor)
    }

    pub fn permutation(&self) -> &[u32] {
        &self.permutation
    }

    pub fn coefficients(&self) -> &[Fp] {
        &self.coefficients
    }

    pub fn sketch_edges(&self) -> Vec<C63SparseSketchEdge> {
        self.permutation
            .iter()
            .zip(&self.coefficients)
            .enumerate()
            .map(|(source_socket, (&destination_socket, &coefficient))| C63SparseSketchEdge {
                input: (source_socket / usize::from(self.column_degree)) as u32,
                socket_ordinal: (source_socket % usize::from(self.column_degree)) as u8,
                output: destination_socket / u32::from(self.check_degree),
                coefficient,
            })
            .collect()
    }

    pub fn dimensions(&self) -> (usize, usize) {
        (self.input_len, self.output_len)
    }
}

fn c63_sparse_setup_geometry(
    input_len: usize,
    output_len: usize,
    column_degree: u8,
    check_degree: u16,
) -> Result<[u8; 21], String> {
    let mut geometry = [0u8; 21];
    geometry[..8].copy_from_slice(&C63_SPARSE_SETUP_MAGIC);
    geometry[8..10].copy_from_slice(&C63_SPARSE_SETUP_VERSION.to_le_bytes());
    geometry[10..14].copy_from_slice(
        &u32::try_from(input_len)
            .map_err(|_| "C6.3 sparse setup input length exceeds u32".to_owned())?
            .to_le_bytes(),
    );
    geometry[14..18].copy_from_slice(
        &u32::try_from(output_len)
            .map_err(|_| "C6.3 sparse setup output length exceeds u32".to_owned())?
            .to_le_bytes(),
    );
    geometry[18] = column_degree;
    geometry[19..21].copy_from_slice(&check_degree.to_le_bytes());
    Ok(geometry)
}

fn c63_sparse_setup_reader(
    context: &'static str,
    seed: Hash,
    geometry: &[u8],
) -> blake3::OutputReader {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(geometry);
    hasher.update(&seed);
    hasher.finalize_xof()
}

fn c63_sparse_setup_u64(reader: &mut blake3::OutputReader) -> u64 {
    let mut bytes = [0u8; 8];
    reader.fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

fn c63_sparse_setup_bounded(reader: &mut blake3::OutputReader, bound: u64) -> Result<u64, String> {
    let range = 1u128 << 64;
    let limit = range - range % u128::from(bound);
    for _ in 0..C63_SPARSE_SETUP_MAX_REJECTION_DRAWS {
        let candidate = c63_sparse_setup_u64(reader);
        if u128::from(candidate) < limit {
            return Ok(candidate % bound);
        }
    }
    Err("C6.3 sparse setup permutation rejection exhausted".to_owned())
}

fn c63_sparse_setup_nonzero_coefficient(reader: &mut blake3::OutputReader) -> Result<Fp, String> {
    for _ in 0..C63_SPARSE_SETUP_MAX_REJECTION_DRAWS {
        let candidate = c63_sparse_setup_u64(reader);
        if candidate != 0 && candidate < volta_field::P {
            return Ok(Fp::new(candidate));
        }
    }
    Err("C6.3 sparse setup coefficient rejection exhausted".to_owned())
}

fn c63_sparse_setup_expanded_digest(
    geometry: &[u8],
    permutation: &[u32],
    coefficients: &[Fp],
) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(C63_SPARSE_SETUP_DIGEST_CONTEXT);
    hasher.update(geometry);
    for (&destination_socket, &coefficient) in permutation.iter().zip(coefficients) {
        hasher.update(&destination_socket.to_le_bytes());
        hasher.update(&coefficient.value().to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The append-aligned Bolt coordinate for one padded K/V correction and tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63BoltCorrectionIndex {
    pub row: u32,
    pub column: u8,
}

/// Permute the existing D24 cache coordinate plus K/V and tape into D22 x 16.
pub fn c63_bolt_correction_index(
    cell: C6CacheCell,
    tape: u8,
) -> Result<C63BoltCorrectionIndex, String> {
    let layout = C6PersistentCacheLayout::production();
    if tape >= 2
        || cell.layer >= layout.padded_layers
        || cell.position >= layout.capacity_tokens
        || cell.channel >= layout.padded_width
    {
        return Err("C6.3 Bolt correction coordinate is outside its geometry".to_owned());
    }
    let kv = match cell.kind {
        C6CacheSlotKind::Key => 0u8,
        C6CacheSlotKind::Value => 1u8,
    };
    let row = (u32::from(cell.position) << 12)
        | (u32::from(cell.layer >> 1) << 9)
        | u32::from(cell.channel & 0x01ff);
    let column = tape
        | (kv << 1)
        | (u8::try_from(cell.layer & 1).map_err(|_| "C6.3 layer conversion failed")? << 2)
        | (u8::try_from(cell.channel >> 9).map_err(|_| "C6.3 channel conversion failed")? << 3);
    Ok(C63BoltCorrectionIndex { row, column })
}

/// Invert [`c63_bolt_correction_index`] over the complete padded geometry.
pub fn c63_bolt_correction_cell(
    index: C63BoltCorrectionIndex,
) -> Result<(C6CacheCell, u8), String> {
    if index.row as usize >= C63_BOLT_ROWS || index.column as usize >= C63_BOLT_COLUMNS {
        return Err("C6.3 Bolt correction index is outside its geometry".to_owned());
    }
    let tape = index.column & 1;
    let kind =
        if (index.column >> 1) & 1 == 0 { C6CacheSlotKind::Key } else { C6CacheSlotKind::Value };
    let layer =
        u16::try_from((index.row >> 9) & 0x07).map_err(|_| "C6.3 row layer conversion failed")? * 2
            + u16::from((index.column >> 2) & 1);
    let channel = u16::from((index.column >> 3) & 1) << 9
        | u16::try_from(index.row & 0x01ff).map_err(|_| "C6.3 row conversion failed")?;
    let position = u16::try_from(index.row >> 12).map_err(|_| "C6.3 position conversion failed")?;
    Ok((C6CacheCell { kind, layer, position, channel }, tape))
}

/// Pull Bolt's single post-commit row challenge back to one correction cell.
pub fn c63_bolt_interleaved_coefficient_reference(
    index: C63BoltCorrectionIndex,
    row_weight: Fp2,
    rho: &[Fp2; C63_BOLT_COLUMNS],
) -> Result<Fp2, String> {
    c63_bolt_correction_cell(index)?;
    Ok(row_weight * rho[usize::from(index.column)])
}

/// Compile the two tape-separated correction functionals directly in the
/// residual source order. Unrelated Transformer sources retain zero weight.
#[cfg(feature = "c6-trace")]
pub fn c63_compile_residual_source_functionals(
    old_len: u16,
    new_len: u16,
    source_count: u32,
    source_schedule_digest: Hash,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    row_point: &[Fp2],
) -> Result<[Vec<Fp2>; 2], String> {
    let layout = C6PersistentCacheLayout::production();
    layout.validate().map_err(|error| error.to_string())?;
    if old_len >= new_len
        || new_len > layout.capacity_tokens
        || !schedule.is_canonical()
        || schedule.digest != source_schedule_digest
        || plan.layers().len() != usize::from(layout.layers)
    {
        return Err("C6.3 residual source-functional binding differs".to_owned());
    }
    let source_count = usize::try_from(source_count)
        .map_err(|_| "C6.3 residual source count exceeds usize".to_owned())?;
    let domains = c63_direct_source_domain_offsets(source_count, schedule)?;
    let factors = C63RowEqualityFactors::new(row_point)?;
    let width = usize::from(layout.width);
    let mut coefficients = std::array::from_fn(|_| vec![Fp2::ZERO; source_count]);
    let mut mapped = 0usize;
    for (layer_index, layer) in plan.layers().iter().enumerate() {
        if usize::from(layer.model_layer()) != layer_index
            || layer.first_row() != usize::from(old_len)
            || layer.row_count().map_err(|error| error.to_string())?
                != usize::from(new_len - old_len)
        {
            return Err("C6.3 source plan does not cover the exact append".to_owned());
        }
        for (kind, slot_kind) in [
            (C6CacheFoldKind::KeyRows, C6CacheSlotKind::Key),
            (C6CacheFoldKind::ValueColumns, C6CacheSlotKind::Value),
        ] {
            for position in usize::from(old_len)..usize::from(new_len) {
                let domain =
                    layer.source_domain(kind, position).map_err(|error| error.to_string())?;
                let &(start, _, count) = domains.get(&domain).ok_or_else(|| {
                    "C6.3 cache source domain is absent from the residual".to_owned()
                })?;
                if count != width || start.checked_add(width).is_none_or(|end| end > source_count) {
                    return Err("C6.3 cache source draw has the wrong width".to_owned());
                }
                for channel in 0..width {
                    let cell = C6CacheCell {
                        kind: slot_kind,
                        layer: layer.model_layer(),
                        position: position as u16,
                        channel: channel as u16,
                    };
                    for tape in 0..2 {
                        let index = c63_bolt_correction_index(cell, tape as u8)?;
                        let coefficient = c63_bolt_interleaved_coefficient_reference(
                            index,
                            factors.weight(index.row)?,
                            rho,
                        )?;
                        let target = &mut coefficients[tape][start + channel];
                        if *target != Fp2::ZERO {
                            return Err("C6.3 cache source maps to more than one cell".to_owned());
                        }
                        *target = coefficient;
                    }
                    mapped += 1;
                }
            }
        }
    }
    let expected = C6_PERSISTENT_CACHE_LIVE_SLOTS
        .checked_mul(usize::from(layout.layers))
        .and_then(|count| count.checked_mul(usize::from(new_len - old_len)))
        .and_then(|count| count.checked_mul(width))
        .ok_or_else(|| "C6.3 cache source census overflows".to_owned())?;
    if mapped != expected {
        return Err("C6.3 cache source functional is incomplete".to_owned());
    }
    Ok(coefficients)
}

/// Locate direct subfield sources in the flattened residual leaf order.
/// Shared by the coefficient compiler and the live append owner so they
/// cannot disagree about schedule offsets.
pub(crate) fn c63_direct_source_domain_offsets(
    source_count: usize,
    schedule: &CorrScheduleAudit,
) -> Result<std::collections::BTreeMap<u64, (usize, usize, usize)>, String> {
    if !schedule.is_canonical() {
        return Err("C6.3 residual source schedule is not canonical".to_owned());
    }
    let mut domains = std::collections::BTreeMap::new();
    let mut flat_offset = 0usize;
    for draw in &schedule.draws {
        let count = usize::try_from(draw.count)
            .map_err(|_| "C6.3 correlation draw count exceeds usize".to_owned())?;
        if draw.kind == CorrScheduleKind::Subfield
            && draw.role == CorrScheduleRole::DirectCorrection
            && domains
                .insert(
                    draw.domain,
                    (
                        flat_offset,
                        usize::try_from(draw.global_offset)
                            .map_err(|_| "C6.3 subfield source offset exceeds usize".to_owned())?,
                        count,
                    ),
                )
                .is_some()
        {
            return Err("C6.3 residual source domain is repeated".to_owned());
        }
        flat_offset = flat_offset
            .checked_add(count)
            .ok_or_else(|| "C6.3 residual source count overflows".to_owned())?;
    }
    if flat_offset != source_count {
        return Err("C6.3 residual source census differs from its schedule".to_owned());
    }
    Ok(domains)
}

/// Evaluate the two response-local correction openings from the paired source
/// witness already produced by inference. This is the production `D=X-R`
/// seam: it reads only the append's subfield audit and allocates no dense cache.
#[cfg(feature = "c6-trace")]
pub fn c63_evaluate_residual_source_functionals(
    old_len: u16,
    new_len: u16,
    source_schedule_digest: Hash,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    source: &C6ProductionPairedSourceWitness,
    coefficients: [&[Fp2]; 2],
) -> Result<[Fp2; 2], String> {
    if source.allocation_binding_digest() == [0; 32] {
        return Err("C6.3 resident correction allocation binding is empty".to_owned());
    }
    c63_evaluate_paired_source_functionals(
        old_len,
        new_len,
        source_schedule_digest,
        plan,
        schedule,
        source.source(),
        coefficients,
    )
}

#[cfg(feature = "c6-trace")]
fn c63_evaluate_paired_source_functionals(
    old_len: u16,
    new_len: u16,
    source_schedule_digest: Hash,
    plan: &C6CacheFoldAppendSourcePlan,
    schedule: &CorrScheduleAudit,
    paired: &C6PairedSourceWitness,
    coefficients: [&[Fp2]; 2],
) -> Result<[Fp2; 2], String> {
    let layout = C6PersistentCacheLayout::production();
    let source_count = coefficients[0].len();
    if old_len >= new_len
        || new_len > layout.capacity_tokens
        || coefficients[1].len() != source_count
        || plan.layers().len() != usize::from(layout.layers)
        || paired.schedule_digest() != schedule.digest
        || paired.source_schedule_digest() != source_schedule_digest
    {
        return Err("C6.3 resident correction-functional binding differs".to_owned());
    }
    let domains = c63_direct_source_domain_offsets(source_count, schedule)?;
    let width = usize::from(layout.width);
    let coordinates = paired.coordinates();
    let mut values = [Fp2::ZERO; 2];
    let mut mapped = 0usize;
    for (layer_ordinal, layer) in plan.layers().iter().enumerate() {
        if usize::from(layer.model_layer()) != layer_ordinal
            || layer.first_row() != usize::from(old_len)
            || layer.row_count().map_err(|error| error.to_string())?
                != usize::from(new_len - old_len)
        {
            return Err("C6.3 resident correction-functional plan differs".to_owned());
        }
        for kind in [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns] {
            for position in usize::from(old_len)..usize::from(new_len) {
                let domain =
                    layer.source_domain(kind, position).map_err(|error| error.to_string())?;
                let &(flat_start, subfield_start, count) =
                    domains.get(&domain).ok_or_else(|| {
                        "C6.3 resident correction source is absent from the schedule".to_owned()
                    })?;
                if count != width
                    || flat_start.checked_add(width).is_none_or(|end| end > source_count)
                {
                    return Err("C6.3 resident correction source width differs".to_owned());
                }
                for channel in 0..width {
                    let source_index = subfield_start + channel;
                    for tape in 0..2 {
                        let audit = coordinates[tape].subfield();
                        let mask = *audit.masks().get(source_index).ok_or_else(|| {
                            "C6.3 resident correction mask is truncated".to_owned()
                        })?;
                        let correction = *audit
                            .corrections()
                            .get(source_index)
                            .ok_or_else(|| "C6.3 resident correction is truncated".to_owned())?;
                        if audit.plaintext(source_index) != Some(mask + correction) {
                            return Err("C6.3 resident correction differs from X-R".to_owned());
                        }
                        values[tape] +=
                            Fp2::from_base(correction) * coefficients[tape][flat_start + channel];
                    }
                    mapped += 1;
                }
            }
        }
    }
    let expected = C6_PERSISTENT_CACHE_LIVE_SLOTS
        .checked_mul(usize::from(layout.layers))
        .and_then(|count| count.checked_mul(usize::from(new_len - old_len)))
        .and_then(|count| count.checked_mul(width))
        .ok_or_else(|| "C6.3 resident correction census overflows".to_owned())?;
    if mapped != expected {
        return Err("C6.3 resident correction functional is incomplete".to_owned());
    }
    Ok(values)
}

/// One live correction cell as held by the provider. `source` authenticates
/// the Transformer K/V value and `mask` is the replayed correlation for the
/// same source coordinate. Their difference must be the correction committed
/// by the C6.3 state.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C63AuthenticatedCorrectionProverCell {
    pub cell: C6CacheCell,
    pub correction: [Fp; 2],
    pub source: [ProverAuthed; 2],
    pub mask: [ProverAuthed; 2],
}

/// Verifier mirror of [`C63AuthenticatedCorrectionProverCell`]. The source
/// keys come from the verified Transformer output and the mask keys from a
/// counter-neutral replay of the same two connection-scoped correlations.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C63AuthenticatedCorrectionVerifierCell {
    pub cell: C6CacheCell,
    pub source_keys: [VerifierKey; 2],
    pub mask_keys: [VerifierKey; 2],
}

/// Compile the exact post-`rho` correction opening from the already
/// authenticated Transformer sources. This reference streams the canonical
/// live-cell order and never allocates a D22 coefficient vector.
#[cfg(test)]
pub(crate) fn c63_authenticated_correction_functional_prover_reference(
    old_len: u16,
    new_len: u16,
    cells: &[C63AuthenticatedCorrectionProverCell],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    row_point: &[Fp2],
) -> Result<[[ProverAuthed; 2]; 2], String> {
    validate_authenticated_correction_geometry(
        old_len,
        new_len,
        cells.iter().map(|entry| entry.cell),
        row_point,
    )?;
    let row_weights = C63RowEqualityFactors::new(row_point)?;
    let mut result = [[ProverAuthed::ZERO; 2]; 2];
    for entry in cells {
        for tape in 0..2 {
            let source = entry.source[tape];
            let mask = entry.mask[tape];
            let difference = source.sub(mask);
            if source.x.c1 != Fp::ZERO
                || mask.x.c1 != Fp::ZERO
                || source.m != mask.m
                || difference.x != Fp2::from_base(entry.correction[tape])
            {
                return Err(
                    "C6.3 provider correction differs from its authenticated K/V source".to_owned()
                );
            }
            let index = c63_bolt_correction_index(entry.cell, tape as u8)?;
            let row_weight = row_weights.weight(index.row)?;
            for (limb, scalar) in
                [rho[usize::from(index.column)].c0, rho[usize::from(index.column)].c1]
                    .into_iter()
                    .enumerate()
            {
                result[tape][limb] =
                    result[tape][limb].add(difference.scale(row_weight * Fp2::from_base(scalar)));
            }
        }
    }
    Ok(result)
}

/// Witness-free mirror of
/// [`c63_authenticated_correction_functional_prover_reference`]. It derives
/// each hidden correction key by subtracting the replayed mask key from the
/// already verified Transformer source key. It deliberately does not receive
/// all correction plaintexts; the systematic openings bind the resulting
/// functional to the committed correction root.
#[cfg(test)]
pub(crate) fn c63_authenticated_correction_functional_verifier_reference(
    old_len: u16,
    new_len: u16,
    cells: &[C63AuthenticatedCorrectionVerifierCell],
    deltas: [Fp2; 2],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    row_point: &[Fp2],
) -> Result<[[VerifierKey; 2]; 2], String> {
    if deltas[0] == deltas[1] {
        return Err("C6.3 output-link MAC tapes are not independent".to_owned());
    }
    validate_authenticated_correction_geometry(
        old_len,
        new_len,
        cells.iter().map(|entry| entry.cell),
        row_point,
    )?;
    let row_weights = C63RowEqualityFactors::new(row_point)?;
    let mut result = [[VerifierKey::ZERO; 2]; 2];
    for entry in cells {
        for tape in 0..2 {
            let difference = entry.source_keys[tape].sub(entry.mask_keys[tape]);
            let index = c63_bolt_correction_index(entry.cell, tape as u8)?;
            let row_weight = row_weights.weight(index.row)?;
            for (limb, scalar) in
                [rho[usize::from(index.column)].c0, rho[usize::from(index.column)].c1]
                    .into_iter()
                    .enumerate()
            {
                result[tape][limb] =
                    result[tape][limb].add(difference.scale(row_weight * Fp2::from_base(scalar)));
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
fn validate_authenticated_correction_geometry(
    old_len: u16,
    new_len: u16,
    cells: impl Iterator<Item = C6CacheCell>,
    row_point: &[Fp2],
) -> Result<(), String> {
    let layout = C6PersistentCacheLayout::production();
    layout.validate().map_err(|error| error.to_string())?;
    if old_len >= new_len || new_len > layout.capacity_tokens || row_point.is_empty() {
        return Err("C6.3 authenticated correction geometry is invalid".to_owned());
    }
    let expected_count = C6_PERSISTENT_CACHE_LIVE_SLOTS
        .checked_mul(usize::from(layout.layers))
        .and_then(|count| count.checked_mul(usize::from(new_len - old_len)))
        .and_then(|count| count.checked_mul(usize::from(layout.width)))
        .ok_or_else(|| "C6.3 authenticated correction census overflows".to_owned())?;
    let mut seen = 0usize;
    for (ordinal, cell) in cells.enumerate() {
        if ordinal >= expected_count
            || cell != canonical_live_cell(layout, old_len, new_len, ordinal)?
        {
            return Err("C6.3 authenticated correction cells are not canonical".to_owned());
        }
        let index = c63_bolt_correction_index(cell, 0)?;
        if usize::try_from(index.row).ok().is_none_or(|row| {
            1usize.checked_shl(row_point.len() as u32).is_none_or(|rows| row >= rows)
        }) {
            return Err("C6.3 correction row is outside its opening point".to_owned());
        }
        seen += 1;
    }
    if seen != expected_count {
        return Err("C6.3 authenticated correction cell census differs".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn canonical_live_cell(
    layout: C6PersistentCacheLayout,
    old_len: u16,
    new_len: u16,
    ordinal: usize,
) -> Result<C6CacheCell, String> {
    let width = usize::from(layout.width);
    let positions = usize::from(new_len - old_len);
    let per_layer = positions
        .checked_mul(width)
        .ok_or_else(|| "C6.3 canonical correction layer overflows".to_owned())?;
    let per_kind = usize::from(layout.layers)
        .checked_mul(per_layer)
        .ok_or_else(|| "C6.3 canonical correction kind overflows".to_owned())?;
    let kind = if ordinal / per_kind == 0 { C6CacheSlotKind::Key } else { C6CacheSlotKind::Value };
    let within_kind = ordinal % per_kind;
    let layer = within_kind / per_layer;
    let within_layer = within_kind % per_layer;
    let position = usize::from(old_len) + within_layer / width;
    let channel = within_layer % width;
    Ok(C6CacheCell {
        kind,
        layer: u16::try_from(layer)
            .map_err(|_| "C6.3 canonical correction layer exceeds u16".to_owned())?,
        position: u16::try_from(position)
            .map_err(|_| "C6.3 canonical correction position exceeds u16".to_owned())?,
        channel: u16::try_from(channel)
            .map_err(|_| "C6.3 canonical correction channel exceeds u16".to_owned())?,
    })
}

struct C63RowEqualityFactors {
    channel: Vec<Fp2>,
    layer_high: Vec<Fp2>,
    position: Vec<Fp2>,
}

impl C63RowEqualityFactors {
    fn new(point: &[Fp2]) -> Result<Self, String> {
        if !(12..=C63_BOLT_ROW_LOG2 as usize).contains(&point.len()) {
            return Err("C6.3 correction opening point has the wrong dimension".to_owned());
        }
        Ok(Self {
            channel: eq_vec(&point[..9]),
            layer_high: eq_vec(&point[9..12]),
            position: eq_vec(&point[12..]),
        })
    }

    fn weight(&self, row: u32) -> Result<Fp2, String> {
        let channel = row as usize & 0x01ff;
        let layer_high = row as usize >> 9 & 0x07;
        let position = row as usize >> 12;
        let position_weight = self
            .position
            .get(position)
            .ok_or_else(|| "C6.3 correction row is outside its opening point".to_owned())?;
        Ok(self.channel[channel] * self.layer_high[layer_high] * *position_weight)
    }
}

/// One typed systematic row. Padded columns must remain canonical zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CorrectionRowReference {
    pub position: u16,
    pub layer_high: u8,
    pub channel_low: u16,
    pub birth_epoch: u64,
    pub allocation_binding_digest: Hash,
    pub source_schedule_digest: Hash,
    pub corrections: [Fp; C63_BOLT_COLUMNS],
}

impl C63CorrectionRowReference {
    pub fn validate(&self) -> Result<(), String> {
        let layout = C6PersistentCacheLayout::production();
        if self.position >= layout.capacity_tokens
            || self.layer_high >= 6
            || self.channel_low >= 512
            || self.birth_epoch == 0
            || self.allocation_binding_digest == [0; 32]
            || self.source_schedule_digest == [0; 32]
        {
            return Err("C6.3 correction row metadata is invalid".to_owned());
        }
        let row = (u32::from(self.position) << 12)
            | (u32::from(self.layer_high) << 9)
            | u32::from(self.channel_low);
        for (column, correction) in self.corrections.iter().enumerate() {
            let (cell, _) = c63_bolt_correction_cell(C63BoltCorrectionIndex {
                row,
                column: u8::try_from(column)
                    .map_err(|_| "C6.3 correction column conversion failed")?,
            })?;
            if (cell.layer >= layout.layers || cell.channel >= layout.width)
                && *correction != Fp::ZERO
            {
                return Err("C6.3 padded correction column is nonzero".to_owned());
            }
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(crate::merkle::hash_leaf(&c63_correction_live_row_frame(self)))
    }
}

fn c63_correction_live_row_frame(
    row: &C63CorrectionRowReference,
) -> [u8; C63_CORRECTION_ROW_FRAME_WORDS * 8] {
    let mut bytes = [0u8; C63_CORRECTION_ROW_FRAME_WORDS * 8];
    bytes[..8].copy_from_slice(&C63_CORRECTION_TREE_MAGIC);
    bytes[8..10].copy_from_slice(&C63_CORRECTION_TREE_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&row.position.to_le_bytes());
    bytes[12] = row.layer_high;
    bytes[13..15].copy_from_slice(&row.channel_low.to_le_bytes());
    bytes[16..24].copy_from_slice(&row.birth_epoch.to_le_bytes());
    bytes[24..56].copy_from_slice(&row.allocation_binding_digest);
    bytes[56..88].copy_from_slice(&row.source_schedule_digest);
    for (index, correction) in row.corrections.iter().enumerate() {
        let offset = 88 + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&correction.value().to_le_bytes());
    }
    bytes
}

fn c63_virtual_correction_row_frame() -> [u8; C63_CORRECTION_ROW_FRAME_WORDS * 8] {
    let mut bytes = [0u8; C63_CORRECTION_ROW_FRAME_WORDS * 8];
    bytes[..8].copy_from_slice(&C63_VIRTUAL_ROW_MAGIC);
    bytes[8..10].copy_from_slice(&C63_CORRECTION_TREE_VERSION.to_le_bytes());
    bytes
}

/// Small verifier-owned frontier for the accepted contiguous tile prefix.
/// It authenticates an exact append without retaining corrections or all
/// historical tile roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CorrectionAppendFrontier {
    accepted_len: u16,
    peaks: [Option<Hash>; 11],
}

impl C63CorrectionAppendFrontier {
    pub fn zero() -> Self {
        Self { accepted_len: 0, peaks: [None; 11] }
    }

    pub fn from_tile_roots(tile_roots: &[Hash]) -> Result<Self, String> {
        let mut frontier = Self::zero();
        frontier.append(tile_roots)?;
        Ok(frontier)
    }

    pub fn accepted_len(&self) -> u16 {
        self.accepted_len
    }

    pub fn append(&mut self, tile_roots: &[Hash]) -> Result<(), String> {
        if tile_roots.is_empty()
            || tile_roots.contains(&[0; 32])
            || usize::from(self.accepted_len)
                .checked_add(tile_roots.len())
                .is_none_or(|length| length > 1 << 10)
        {
            return Err("C6.3 correction append frontier geometry differs".to_owned());
        }
        for &root in tile_roots {
            self.append_one(root)?;
        }
        self.accepted_len = self
            .accepted_len
            .checked_add(
                u16::try_from(tile_roots.len())
                    .map_err(|_| "C6.3 correction append length exceeds u16".to_owned())?,
            )
            .ok_or_else(|| "C6.3 correction append length overflows".to_owned())?;
        Ok(())
    }

    pub fn state_root(&self, profile_digest: Hash, epoch: u64) -> Result<Hash, String> {
        if (epoch == 0) != (self.accepted_len == 0) {
            return Err("C6.3 correction frontier epoch differs".to_owned());
        }
        c63_correction_state_root_from_inner_reference(
            profile_digest,
            epoch,
            self.accepted_len,
            self.padded_inner_root()?,
        )
    }

    fn append_one(&mut self, mut node: Hash) -> Result<(), String> {
        for peak in &mut self.peaks {
            match peak.take() {
                None => {
                    *peak = Some(node);
                    return Ok(());
                }
                Some(left) => node = hash_pair(&left, &node),
            }
        }
        Err("C6.3 correction append frontier is full".to_owned())
    }

    fn padded_inner_root(&self) -> Result<Hash, String> {
        let mut padded = self.clone();
        let virtual_tile_root = c63_virtual_correction_tile_root();
        for _ in usize::from(self.accepted_len)..(1 << 10) {
            padded.append_one(virtual_tile_root)?;
        }
        if padded.peaks[..10].iter().any(Option::is_some) {
            return Err("C6.3 correction append frontier is noncanonical".to_owned());
        }
        padded.peaks[10].ok_or_else(|| "C6.3 correction append frontier root is missing".to_owned())
    }
}

impl Default for C63CorrectionAppendFrontier {
    fn default() -> Self {
        Self::zero()
    }
}

/// Deduplicated openings inside one accepted D12 position tile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CorrectionTileOpeningReference {
    metadata: Option<C63CorrectionTileMetadataReference>,
    corrections: Vec<[Fp; C63_BOLT_COLUMNS]>,
    frontier: Vec<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C63CorrectionTileMetadataReference {
    birth_epoch: u64,
    allocation_binding_digest: Hash,
    source_schedule_digest: Hash,
}

/// Two-level D12-inside-D10 multiproof. Virtual rows and tiles carry no payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CorrectionRowsOpeningReference {
    appended_tile_roots: Vec<Hash>,
    tiles: Vec<C63CorrectionTileOpeningReference>,
}

impl C63CorrectionRowsOpeningReference {
    /// Encode only non-derivable data. Query coordinates and virtual zeros are external.
    pub fn encode(
        &self,
        old_len: u16,
        new_len: u16,
        queried_rows: &[u32],
    ) -> Result<Vec<u8>, String> {
        validate_c63_correction_queries(queried_rows)?;
        validate_c63_append_lengths(old_len, new_len)?;
        if self.appended_tile_roots.len() != usize::from(new_len - old_len)
            || self.appended_tile_roots.contains(&[0; 32])
        {
            return Err("C6.3 correction append tile-root census differs".to_owned());
        }
        let positions = c63_correction_query_positions(queried_rows);
        let mut tiles = self.tiles.iter();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&C63_CORRECTION_OPENING_MAGIC);
        bytes.extend_from_slice(&C63_CORRECTION_OPENING_VERSION.to_le_bytes());
        for root in &self.appended_tile_roots {
            bytes.extend_from_slice(root);
        }
        for position in positions
            .into_iter()
            .filter(|&position| position >= usize::from(old_len) && position < usize::from(new_len))
        {
            let tile =
                tiles.next().ok_or_else(|| "C6.3 correction tile opening is missing".to_owned())?;
            let live_count = c63_correction_live_query_count(queried_rows, position);
            match (live_count, tile.metadata) {
                (0, None) => {}
                (0, Some(_)) => {
                    return Err("C6.3 correction tile has unnecessary metadata".to_owned())
                }
                (_, None) => return Err("C6.3 correction tile metadata is missing".to_owned()),
                (_, Some(metadata)) => {
                    validate_c63_correction_metadata(metadata)?;
                    bytes.extend_from_slice(&metadata.birth_epoch.to_le_bytes());
                    bytes.extend_from_slice(&metadata.allocation_binding_digest);
                    bytes.extend_from_slice(&metadata.source_schedule_digest);
                }
            }
            if tile.corrections.len() != live_count {
                return Err("C6.3 correction row payload count differs".to_owned());
            }
            for row in &tile.corrections {
                for value in row {
                    bytes.extend_from_slice(&value.value().to_le_bytes());
                }
            }
            encode_c63_frontier(&mut bytes, &tile.frontier, C63_BOLT_ROWS_PER_POSITION)?;
        }
        if tiles.next().is_some() {
            return Err("C6.3 correction proof has trailing tile openings".to_owned());
        }
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        old_len: u16,
        new_len: u16,
        queried_rows: &[u32],
    ) -> Result<Self, String> {
        validate_c63_correction_queries(queried_rows)?;
        validate_c63_append_lengths(old_len, new_len)?;
        let mut cursor = C63CorrectionOpeningCursor::new(bytes);
        if cursor.take(8)? != C63_CORRECTION_OPENING_MAGIC
            || cursor.u16()? != C63_CORRECTION_OPENING_VERSION
        {
            return Err("C6.3 correction opening header differs".to_owned());
        }
        let appended_tile_roots =
            (old_len..new_len).map(|_| cursor.hash()).collect::<Result<Vec<_>, _>>()?;
        if appended_tile_roots.contains(&[0; 32]) {
            return Err("C6.3 correction append contains an empty tile root".to_owned());
        }
        let mut tiles = Vec::new();
        for position in c63_correction_query_positions(queried_rows)
            .into_iter()
            .filter(|&position| position >= usize::from(old_len) && position < usize::from(new_len))
        {
            let live_count = c63_correction_live_query_count(queried_rows, position);
            let metadata = if live_count == 0 {
                None
            } else {
                let metadata = C63CorrectionTileMetadataReference {
                    birth_epoch: cursor.u64()?,
                    allocation_binding_digest: cursor.hash()?,
                    source_schedule_digest: cursor.hash()?,
                };
                validate_c63_correction_metadata(metadata)?;
                Some(metadata)
            };
            let mut corrections = Vec::with_capacity(live_count);
            for _ in 0..live_count {
                let mut row = [Fp::ZERO; C63_BOLT_COLUMNS];
                for value in &mut row {
                    *value = cursor.fp()?;
                }
                corrections.push(row);
            }
            let frontier = cursor.frontier(C63_BOLT_ROWS_PER_POSITION)?;
            tiles.push(C63CorrectionTileOpeningReference { metadata, corrections, frontier });
        }
        cursor.finish()?;
        Ok(Self { appended_tile_roots, tiles })
    }
}

/// Assemble the canonical two-level proof from resident tile openings. The
/// caller supplies only accepted-tile payloads; virtual tiles remain derived
/// from the public geometry.
pub(crate) fn c63_correction_rows_opening_from_resident_parts(
    old_len: u16,
    accepted_len: u16,
    tile_roots: &[Hash],
    queried_rows: &[u32],
    tiles: Vec<(Option<(u64, Hash, Hash)>, Vec<[Fp; C63_BOLT_COLUMNS]>, Vec<Hash>)>,
) -> Result<C63CorrectionRowsOpeningReference, String> {
    validate_c63_correction_queries(queried_rows)?;
    validate_c63_append_lengths(old_len, accepted_len)?;
    if tile_roots.len() != usize::from(accepted_len) || tile_roots.contains(&[0; 32]) {
        return Err("C6.3 resident correction tile roots differ".to_owned());
    }
    let positions = c63_correction_query_positions(queried_rows);
    if tiles.len()
        != positions
            .iter()
            .filter(|&&position| {
                position >= usize::from(old_len) && position < usize::from(accepted_len)
            })
            .count()
    {
        return Err("C6.3 resident correction tile opening count differs".to_owned());
    }
    let tiles = tiles
        .into_iter()
        .map(|(metadata, corrections, frontier)| C63CorrectionTileOpeningReference {
            metadata: metadata.map(
                |(birth_epoch, allocation_binding_digest, source_schedule_digest)| {
                    C63CorrectionTileMetadataReference {
                        birth_epoch,
                        allocation_binding_digest,
                        source_schedule_digest,
                    }
                },
            ),
            corrections,
            frontier,
        })
        .collect::<Vec<_>>();
    let opening = C63CorrectionRowsOpeningReference {
        appended_tile_roots: tile_roots[usize::from(old_len)..].to_vec(),
        tiles,
    };
    opening.encode(old_len, accepted_len, queried_rows)?;
    Ok(opening)
}

/// Reference prover for the exact production-depth correction tree.
pub fn c63_open_correction_rows_reference(
    profile_digest: Hash,
    epoch: u64,
    old_len: u16,
    accepted_tiles: &[Vec<C63CorrectionRowReference>],
    queried_rows: &[u32],
) -> Result<(Hash, C63CorrectionRowsOpeningReference), String> {
    validate_c63_correction_queries(queried_rows)?;
    let new_len = u16::try_from(accepted_tiles.len())
        .map_err(|_| "C6.3 accepted correction length exceeds u16".to_owned())?;
    validate_c63_append_lengths(old_len, new_len)?;
    let tile_roots = accepted_tiles
        .iter()
        .enumerate()
        .map(|(position, rows)| {
            if rows.first().map(|row| usize::from(row.position)) != Some(position) {
                return Err("C6.3 accepted correction tile position differs".to_owned());
            }
            c63_correction_tile_root_reference(rows)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state_root = c63_correction_state_root_reference(profile_digest, epoch, &tile_roots)?;
    let positions = queried_rows.iter().map(|row| (*row as usize) >> 12).collect::<Vec<_>>();
    let mut unique_positions = positions.clone();
    unique_positions.dedup();

    let mut tiles = Vec::new();
    for position in unique_positions
        .iter()
        .copied()
        .filter(|&position| position >= usize::from(old_len) && position < tile_roots.len())
    {
        let rows = &accepted_tiles[position];
        let mut leaves =
            rows.iter().map(C63CorrectionRowReference::hash).collect::<Result<Vec<_>, _>>()?;
        leaves.resize(C63_BOLT_ROWS_PER_POSITION, c63_virtual_correction_row_hash());
        let tree = MerkleTree::from_leaves(leaves);
        let locals = queried_rows
            .iter()
            .copied()
            .filter(|row| (*row as usize) >> 12 == position)
            .map(|row| (row as usize) & (C63_BOLT_ROWS_PER_POSITION - 1))
            .collect::<Vec<_>>();
        let corrections = locals
            .iter()
            .copied()
            .filter(|&local| local < C63_BOLT_LIVE_ROWS_PER_POSITION)
            .map(|local| rows[local].corrections)
            .collect::<Vec<_>>();
        let metadata = (!corrections.is_empty()).then_some(C63CorrectionTileMetadataReference {
            birth_epoch: rows[0].birth_epoch,
            allocation_binding_digest: rows[0].allocation_binding_digest,
            source_schedule_digest: rows[0].source_schedule_digest,
        });
        let frontier = tree
            .open_multi(&locals)
            .ok_or_else(|| "C6.3 correction tile query set is invalid".to_owned())?;
        tiles.push(C63CorrectionTileOpeningReference { metadata, corrections, frontier });
    }
    Ok((
        state_root,
        C63CorrectionRowsOpeningReference {
            appended_tile_roots: tile_roots[usize::from(old_len)..].to_vec(),
            tiles,
        },
    ))
}

/// Verify queried correction rows and return the authenticated `m=D'*rho` spots.
pub fn c63_verify_correction_rows_reference(
    predecessor_root: Hash,
    successor_root: Hash,
    predecessor_frontier: &C63CorrectionAppendFrontier,
    profile_digest: Hash,
    epoch: u64,
    old_len: u16,
    new_len: u16,
    queried_rows: &[u32],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    proof: &C63CorrectionRowsOpeningReference,
) -> Result<(Vec<(u32, Fp2)>, C63CorrectionAppendFrontier), String> {
    let (spots, frontier) = c63_verify_correction_rows_by_tape_reference(
        predecessor_root,
        successor_root,
        predecessor_frontier,
        profile_digest,
        epoch,
        old_len,
        new_len,
        queried_rows,
        rho,
        proof,
    )?;
    Ok((spots.into_iter().map(|(row, values)| (row, values[0] + values[1])).collect(), frontier))
}

/// Verify the same opening while preserving the two authentication tapes.
pub fn c63_verify_correction_rows_by_tape_reference(
    predecessor_root: Hash,
    successor_root: Hash,
    predecessor_frontier: &C63CorrectionAppendFrontier,
    profile_digest: Hash,
    epoch: u64,
    old_len: u16,
    new_len: u16,
    queried_rows: &[u32],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    proof: &C63CorrectionRowsOpeningReference,
) -> Result<(Vec<(u32, [Fp2; 2])>, C63CorrectionAppendFrontier), String> {
    validate_c63_correction_queries(queried_rows)?;
    validate_c63_append_lengths(old_len, new_len)?;
    let predecessor_epoch =
        epoch.checked_sub(1).ok_or_else(|| "C6.3 correction append epoch is zero".to_owned())?;
    if predecessor_frontier.accepted_len() != old_len
        || predecessor_frontier.state_root(profile_digest, predecessor_epoch)? != predecessor_root
        || proof.appended_tile_roots.len() != usize::from(new_len - old_len)
    {
        return Err("C6.3 correction predecessor state differs".to_owned());
    }
    let mut successor_frontier = predecessor_frontier.clone();
    successor_frontier.append(&proof.appended_tile_roots)?;
    if successor_frontier.state_root(profile_digest, epoch)? != successor_root {
        return Err("C6.3 correction successor state differs".to_owned());
    }

    let unique_positions = c63_correction_query_positions(queried_rows);
    let mut tile_openings = proof.tiles.iter();
    let mut spots = Vec::with_capacity(queried_rows.len());
    for &position in &unique_positions {
        let rows = queried_rows
            .iter()
            .copied()
            .filter(|row| (*row as usize) >> 12 == position)
            .collect::<Vec<_>>();
        if position < usize::from(old_len) || position >= usize::from(new_len) {
            spots.extend(rows.into_iter().map(|row| (row, [Fp2::ZERO; 2])));
            continue;
        }

        let opening = tile_openings
            .next()
            .ok_or_else(|| "C6.3 accepted correction tile opening is missing".to_owned())?;
        let locals = rows
            .iter()
            .map(|row| (*row as usize) & (C63_BOLT_ROWS_PER_POSITION - 1))
            .collect::<Vec<_>>();
        let live_count =
            locals.iter().filter(|&&local| local < C63_BOLT_LIVE_ROWS_PER_POSITION).count();
        if opening.corrections.len() != live_count
            || (live_count == 0) != opening.metadata.is_none()
        {
            return Err("C6.3 correction row payload shape differs".to_owned());
        }
        let mut corrections = opening.corrections.iter();
        let mut leaf_hashes = Vec::with_capacity(locals.len());
        for (&row_index, &local) in rows.iter().zip(&locals) {
            if local >= C63_BOLT_LIVE_ROWS_PER_POSITION {
                leaf_hashes.push(c63_virtual_correction_row_hash());
                spots.push((row_index, [Fp2::ZERO; 2]));
                continue;
            }
            let correction = corrections
                .next()
                .ok_or_else(|| "C6.3 live correction row opening is missing".to_owned())?;
            let metadata = opening.metadata.expect("checked live C6.3 metadata");
            if metadata.birth_epoch != epoch {
                return Err("C6.3 correction append birth epoch differs".to_owned());
            }
            let row = C63CorrectionRowReference {
                position: position as u16,
                layer_high: (local >> 9) as u8,
                channel_low: (local & 0x01ff) as u16,
                birth_epoch: metadata.birth_epoch,
                allocation_binding_digest: metadata.allocation_binding_digest,
                source_schedule_digest: metadata.source_schedule_digest,
                corrections: *correction,
            };
            leaf_hashes.push(row.hash()?);
            let mut values = [Fp2::ZERO; 2];
            for (column, (&correction, &weight)) in correction.iter().zip(rho).enumerate() {
                values[column & 1] += weight.mul_base(correction);
            }
            spots.push((row_index, values));
        }
        if corrections.next().is_some() {
            return Err("C6.3 live correction row opening has trailing payload".to_owned());
        }
        let tile_root = multi_root(&locals, &leaf_hashes, &opening.frontier, 12)
            .ok_or_else(|| "C6.3 correction tile multiproof is invalid".to_owned())?;
        if proof.appended_tile_roots[position - usize::from(old_len)] != tile_root {
            return Err("C6.3 correction append tile root differs".to_owned());
        }
    }
    if tile_openings.next().is_some() {
        return Err("C6.3 correction proof has trailing tile openings".to_owned());
    }
    Ok((spots, successor_frontier))
}

fn validate_c63_correction_queries(queried_rows: &[u32]) -> Result<(), String> {
    if queried_rows.is_empty()
        || queried_rows.windows(2).any(|pair| pair[0] >= pair[1])
        || queried_rows.last().is_some_and(|&row| row as usize >= C63_BOLT_ROWS)
    {
        return Err("C6.3 correction query rows are noncanonical".to_owned());
    }
    Ok(())
}

fn validate_c63_accepted_len(accepted_len: u16) -> Result<(), String> {
    if accepted_len > C6PersistentCacheLayout::production().capacity_tokens {
        return Err("C6.3 accepted correction length is invalid".to_owned());
    }
    Ok(())
}

fn validate_c63_append_lengths(old_len: u16, new_len: u16) -> Result<(), String> {
    validate_c63_accepted_len(new_len)?;
    if old_len >= new_len {
        return Err("C6.3 correction append lengths differ".to_owned());
    }
    Ok(())
}

fn c63_correction_query_positions(queried_rows: &[u32]) -> Vec<usize> {
    let mut positions = queried_rows.iter().map(|row| (*row as usize) >> 12).collect::<Vec<_>>();
    positions.dedup();
    positions
}

fn c63_correction_live_query_count(queried_rows: &[u32], position: usize) -> usize {
    queried_rows
        .iter()
        .filter(|&&row| {
            (row as usize) >> 12 == position
                && (row as usize) & (C63_BOLT_ROWS_PER_POSITION - 1)
                    < C63_BOLT_LIVE_ROWS_PER_POSITION
        })
        .count()
}

fn validate_c63_correction_metadata(
    metadata: C63CorrectionTileMetadataReference,
) -> Result<(), String> {
    if metadata.birth_epoch == 0
        || metadata.allocation_binding_digest == [0; 32]
        || metadata.source_schedule_digest == [0; 32]
    {
        return Err("C6.3 correction tile metadata is invalid".to_owned());
    }
    Ok(())
}

fn encode_c63_frontier(
    bytes: &mut Vec<u8>,
    frontier: &[Hash],
    maximum: usize,
) -> Result<(), String> {
    if frontier.len() > maximum {
        return Err("C6.3 correction multiproof frontier is too large".to_owned());
    }
    bytes.extend_from_slice(
        &u32::try_from(frontier.len())
            .map_err(|_| "C6.3 correction frontier count overflows".to_owned())?
            .to_le_bytes(),
    );
    for hash in frontier {
        bytes.extend_from_slice(hash);
    }
    Ok(())
}

struct C63CorrectionOpeningCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> C63CorrectionOpeningCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| "C6.3 correction opening cursor overflows".to_owned())?;
        if end > self.bytes.len() {
            return Err("C6.3 correction opening is truncated".to_owned());
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed u32")) as usize)
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn fp(&mut self) -> Result<Fp, String> {
        let value = self.u64()?;
        if value >= volta_field::P {
            return Err("C6.3 correction opening field element is noncanonical".to_owned());
        }
        Ok(Fp::new(value))
    }

    fn hash(&mut self) -> Result<Hash, String> {
        Ok(self.take(32)?.try_into().expect("fixed hash"))
    }

    fn frontier(&mut self, maximum: usize) -> Result<Vec<Hash>, String> {
        let count = self.u32()?;
        if count > maximum
            || count.checked_mul(32).is_none_or(|bytes| bytes > self.bytes.len() - self.offset)
        {
            return Err("C6.3 correction multiproof frontier is invalid".to_owned());
        }
        (0..count).map(|_| self.hash()).collect()
    }

    fn finish(self) -> Result<(), String> {
        if self.offset != self.bytes.len() {
            return Err("C6.3 correction opening has trailing bytes".to_owned());
        }
        Ok(())
    }
}

/// Hash one accepted-position tile. Rows must be canonical layer-high/channel-low order.
pub fn c63_correction_tile_root_reference(
    rows: &[C63CorrectionRowReference],
) -> Result<Hash, String> {
    if rows.len() != C63_BOLT_LIVE_ROWS_PER_POSITION {
        return Err("C6.3 correction tile row count differs".to_owned());
    }
    let position = rows[0].position;
    let birth_epoch = rows[0].birth_epoch;
    let allocation_binding_digest = rows[0].allocation_binding_digest;
    let source_schedule_digest = rows[0].source_schedule_digest;
    let mut leaves = rows
        .iter()
        .enumerate()
        .map(|(offset, row)| {
            let layer_high = (offset >> 9) as u8;
            let channel_low = (offset & 0x01ff) as u16;
            if row.position != position
                || row.layer_high != layer_high
                || row.channel_low != channel_low
                || row.birth_epoch != birth_epoch
                || row.allocation_binding_digest != allocation_binding_digest
                || row.source_schedule_digest != source_schedule_digest
            {
                return Err("C6.3 correction tile row order differs".to_owned());
            }
            row.hash()
        })
        .collect::<Result<Vec<_>, _>>()?;
    leaves.resize(C63_BOLT_ROWS_PER_POSITION, c63_virtual_correction_row_hash());
    Ok(MerkleTree::from_leaves(leaves).root())
}

/// Root accepted position tiles over the setup-owned virtual tail.
pub fn c63_correction_state_root_reference(
    profile_digest: Hash,
    epoch: u64,
    accepted_tile_roots: &[Hash],
) -> Result<Hash, String> {
    if profile_digest == [0; 32]
        || accepted_tile_roots.len()
            > usize::from(C6PersistentCacheLayout::production().capacity_tokens)
        || accepted_tile_roots.contains(&[0; 32])
        || (epoch == 0) != accepted_tile_roots.is_empty()
    {
        return Err("C6.3 correction state metadata is invalid".to_owned());
    }
    let virtual_root = c63_virtual_correction_tile_root();
    let mut tiles = vec![virtual_root; 1 << 10];
    tiles[..accepted_tile_roots.len()].copy_from_slice(accepted_tile_roots);
    let inner_root = MerkleTree::from_leaves(tiles).root();
    c63_correction_state_root_from_inner_reference(
        profile_digest,
        epoch,
        accepted_tile_roots.len() as u16,
        inner_root,
    )
}

fn c63_correction_state_root_from_inner_reference(
    profile_digest: Hash,
    epoch: u64,
    accepted_len: u16,
    inner_root: Hash,
) -> Result<Hash, String> {
    if profile_digest == [0; 32]
        || accepted_len > C6PersistentCacheLayout::production().capacity_tokens
        || inner_root == [0; 32]
        || (epoch == 0) != (accepted_len == 0)
    {
        return Err("C6.3 correction state metadata is invalid".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key(C63_STATE_ROOT_HASH_CONTEXT);
    hasher.update(&C63_CORRECTION_TREE_MAGIC);
    hasher.update(&C63_CORRECTION_TREE_VERSION.to_le_bytes());
    hasher.update(&profile_digest);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&accepted_len.to_le_bytes());
    hasher.update(&inner_root);
    Ok(*hasher.finalize().as_bytes())
}

fn c63_virtual_correction_tile_root() -> Hash {
    MerkleTree::from_leaves(vec![c63_virtual_correction_row_hash(); C63_BOLT_ROWS_PER_POSITION])
        .root()
}

fn c63_virtual_correction_row_hash() -> Hash {
    crate::merkle::hash_leaf(&c63_virtual_correction_row_frame())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63CompactCacheReferenceCensus {
    pub cache_len: u16,
    pub cells_per_token: u64,
    pub stored_cells: u64,
    pub live_capacity_cells: u64,
    pub virtual_tail_cells: u64,
    pub virtual_padding_cells: u64,
    pub virtual_inactive_slot_cells: u64,
    pub conceptual_padded_cells: u64,
}

/// One socket edge of the setup-fixed sparse Bolt precode.
///
/// Distinct socket ordinals may connect the same input and output. They must
/// remain separate because the finite-distance ensemble permits parallel edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63SparseSketchEdge {
    pub input: u32,
    pub socket_ordinal: u8,
    pub output: u32,
    pub coefficient: Fp,
}

/// Explicit small-instance reference for `S = H * X`.
///
/// Production C6.3 will derive `H` from setup and execute it on the GPU. This
/// owner exists only to test the two identities the protocol must preserve:
/// incremental updates and the transposed authenticated opening functional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63SparseSketchReference {
    input_len: usize,
    output_len: usize,
    edges: Vec<C63SparseSketchEdge>,
}

impl C63SparseSketchReference {
    pub fn new(
        input_len: usize,
        output_len: usize,
        edges: Vec<C63SparseSketchEdge>,
    ) -> Result<Self, String> {
        if input_len == 0 || output_len == 0 || edges.is_empty() {
            return Err("C6.3 sparse sketch geometry is empty".to_owned());
        }
        for (index, edge) in edges.iter().enumerate() {
            if edge.input as usize >= input_len
                || edge.socket_ordinal >= C63_BOLT_LDPC_COLUMN_DEGREE
                || edge.output as usize >= output_len
                || edge.coefficient == Fp::ZERO
            {
                return Err("C6.3 sparse sketch edge is invalid".to_owned());
            }
            if index == 0 {
                if edge.socket_ordinal != 0 {
                    return Err("C6.3 sparse sketch socket order is not canonical".to_owned());
                }
            } else {
                let previous = edges[index - 1];
                let expected_socket = if edge.input == previous.input {
                    previous.socket_ordinal.checked_add(1)
                } else if edge.input > previous.input {
                    Some(0)
                } else {
                    None
                };
                if Some(edge.socket_ordinal) != expected_socket {
                    return Err("C6.3 sparse sketch socket order is not canonical".to_owned());
                }
            }
        }
        Ok(Self { input_len, output_len, edges })
    }

    /// Compute the short message `H * X` without constructing a dense matrix.
    pub fn apply(&self, input: &[Fp2]) -> Result<Vec<Fp2>, String> {
        if input.len() != self.input_len {
            return Err("C6.3 sparse sketch input length differs".to_owned());
        }
        let mut output = vec![Fp2::ZERO; self.output_len];
        for edge in &self.edges {
            output[edge.output as usize] += input[edge.input as usize].mul_base(edge.coefficient);
        }
        Ok(output)
    }

    /// Compute `H^T * q`, the public weights used to authenticate `<q, H*X>`.
    pub fn transpose_weights(&self, output_weights: &[Fp2]) -> Result<Vec<Fp2>, String> {
        if output_weights.len() != self.output_len {
            return Err("C6.3 sparse sketch output-weight length differs".to_owned());
        }
        let mut input_weights = vec![Fp2::ZERO; self.input_len];
        for edge in &self.edges {
            input_weights[edge.input as usize] +=
                output_weights[edge.output as usize].mul_base(edge.coefficient);
        }
        Ok(input_weights)
    }
}

/// Reference-only owner for the two live cache tables.
///
/// Values are stored position-major so an accepted state is an exact prefix
/// of its successor. Tail, padded coordinates, and slots 2--7 are virtual
/// zeros and consume no storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CompactCacheReference {
    layout: C6PersistentCacheLayout,
    cache_len: u16,
    tables: [Vec<Fp2>; C6_PERSISTENT_CACHE_LIVE_SLOTS],
}

impl C63CompactCacheReference {
    pub fn zero(layout: C6PersistentCacheLayout) -> Result<Self, String> {
        layout.validate().map_err(|error| error.to_string())?;
        Ok(Self { layout, cache_len: 0, tables: std::array::from_fn(|_| Vec::new()) })
    }

    pub fn layout(&self) -> C6PersistentCacheLayout {
        self.layout
    }

    pub fn cache_len(&self) -> u16 {
        self.cache_len
    }

    pub fn stored_cells(&self) -> usize {
        self.tables.iter().map(Vec::len).sum()
    }

    pub fn census(&self) -> Result<C63CompactCacheReferenceCensus, String> {
        c63_compact_cache_reference_census(self.layout, self.cache_len)
    }

    /// Return a K/V value, virtualizing every non-live padded coordinate.
    pub fn value(&self, cell: C6CacheCell) -> Result<Fp2, String> {
        self.value_at(
            match cell.kind {
                C6CacheSlotKind::Key => 0,
                C6CacheSlotKind::Value => 1,
            },
            cell.layer,
            cell.position,
            cell.channel,
        )
    }

    /// Return any conceptual eight-slot value without materializing zeros.
    pub fn value_at(
        &self,
        slot: usize,
        layer: u16,
        position: u16,
        channel: u16,
    ) -> Result<Fp2, String> {
        if slot >= C6_PERSISTENT_CACHE_SLOTS
            || layer >= self.layout.padded_layers
            || position >= self.layout.capacity_tokens
            || channel >= self.layout.padded_width
        {
            return Err("C6.3 compact cache coordinate is outside padded geometry".to_owned());
        }
        if slot >= C6_PERSISTENT_CACHE_LIVE_SLOTS
            || layer >= self.layout.layers
            || position >= self.cache_len
            || channel >= self.layout.width
        {
            return Ok(Fp2::ZERO);
        }
        let index = compact_index(self.layout, layer, position, channel)?;
        self.tables[slot]
            .get(index)
            .copied()
            .ok_or_else(|| "C6.3 compact cache table is truncated".to_owned())
    }

    /// Build a staged successor from the exact canonical append-source order.
    pub fn apply_append(
        &self,
        new_len: u16,
        append_sources: &[C6CacheSourceValue],
    ) -> Result<Self, String> {
        self.validate_shape()?;
        let expected = expected_c6_cache_append_cells(self.layout, self.cache_len, new_len)
            .map_err(|error| error.to_string())?;
        validate_append_sources(&expected, append_sources)?;

        let table_len = compact_table_len(self.layout, new_len)?;
        let mut successor = self.clone();
        successor.cache_len = new_len;
        for table in &mut successor.tables {
            table.resize(table_len, Fp2::ZERO);
        }
        for source in append_sources {
            let slot = match source.cell.kind {
                C6CacheSlotKind::Key => 0,
                C6CacheSlotKind::Value => 1,
            };
            let index = compact_index(
                self.layout,
                source.cell.layer,
                source.cell.position,
                source.cell.channel,
            )?;
            successor.tables[slot][index] = source.value;
        }
        successor.validate_transition_from(self, append_sources)?;
        Ok(successor)
    }

    /// Check prefix preservation and the exact append values/order/count.
    pub fn validate_transition_from(
        &self,
        predecessor: &Self,
        append_sources: &[C6CacheSourceValue],
    ) -> Result<(), String> {
        predecessor.validate_shape()?;
        self.validate_shape()?;
        if self.layout != predecessor.layout || self.cache_len < predecessor.cache_len {
            return Err("C6.3 compact cache transition geometry differs".to_owned());
        }
        let expected =
            expected_c6_cache_append_cells(self.layout, predecessor.cache_len, self.cache_len)
                .map_err(|error| error.to_string())?;
        validate_append_sources(&expected, append_sources)?;

        for slot in 0..C6_PERSISTENT_CACHE_LIVE_SLOTS {
            if !self.tables[slot].starts_with(&predecessor.tables[slot]) {
                return Err(
                    "C6.3 compact cache successor changed its predecessor prefix".to_owned()
                );
            }
        }
        for source in append_sources {
            if self.value(source.cell)? != source.value {
                return Err("C6.3 compact cache append value differs from its source".to_owned());
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), String> {
        self.layout.validate().map_err(|error| error.to_string())?;
        if self.cache_len > self.layout.capacity_tokens {
            return Err("C6.3 compact cache length exceeds capacity".to_owned());
        }
        let expected = compact_table_len(self.layout, self.cache_len)?;
        if self.tables.iter().any(|table| table.len() != expected) {
            return Err("C6.3 compact cache table length differs".to_owned());
        }
        Ok(())
    }
}

pub fn c63_production_compact_cache_reference_census(
    cache_len: u16,
) -> Result<C63CompactCacheReferenceCensus, String> {
    c63_compact_cache_reference_census(C6PersistentCacheLayout::production(), cache_len)
}

fn c63_compact_cache_reference_census(
    layout: C6PersistentCacheLayout,
    cache_len: u16,
) -> Result<C63CompactCacheReferenceCensus, String> {
    layout.validate().map_err(|error| error.to_string())?;
    if cache_len > layout.capacity_tokens {
        return Err("C6.3 compact cache census length exceeds capacity".to_owned());
    }
    let cells_per_token = u64::try_from(C6_PERSISTENT_CACHE_LIVE_SLOTS)
        .ok()
        .and_then(|slots| slots.checked_mul(u64::from(layout.layers)))
        .and_then(|cells| cells.checked_mul(u64::from(layout.width)))
        .ok_or_else(|| "C6.3 compact cache token census overflows".to_owned())?;
    let stored_cells = cells_per_token
        .checked_mul(u64::from(cache_len))
        .ok_or_else(|| "C6.3 compact cache stored census overflows".to_owned())?;
    let live_capacity_cells = cells_per_token
        .checked_mul(u64::from(layout.capacity_tokens))
        .ok_or_else(|| "C6.3 compact cache capacity census overflows".to_owned())?;
    let padded_entries = layout.padded_entries_u64().map_err(|error| error.to_string())?;
    let live_entries = layout.live_entries_u64().map_err(|error| error.to_string())?;
    let live_slots = u64::try_from(C6_PERSISTENT_CACHE_LIVE_SLOTS)
        .map_err(|_| "C6.3 compact cache live-slot census overflows".to_owned())?;
    let inactive_slots = u64::try_from(C6_PERSISTENT_CACHE_SLOTS - C6_PERSISTENT_CACHE_LIVE_SLOTS)
        .map_err(|_| "C6.3 compact cache inactive-slot census overflows".to_owned())?;
    let virtual_tail_cells = live_capacity_cells - stored_cells;
    let virtual_padding_cells = padded_entries
        .checked_sub(live_entries)
        .and_then(|cells| cells.checked_mul(live_slots))
        .ok_or_else(|| "C6.3 compact cache padding census overflows".to_owned())?;
    let virtual_inactive_slot_cells = padded_entries
        .checked_mul(inactive_slots)
        .ok_or_else(|| "C6.3 compact cache inactive census overflows".to_owned())?;
    let conceptual_padded_cells = padded_entries
        .checked_mul(
            u64::try_from(C6_PERSISTENT_CACHE_SLOTS)
                .map_err(|_| "C6.3 compact cache slot census overflows".to_owned())?,
        )
        .ok_or_else(|| "C6.3 compact cache padded census overflows".to_owned())?;
    if stored_cells
        .checked_add(virtual_tail_cells)
        .and_then(|cells| cells.checked_add(virtual_padding_cells))
        .and_then(|cells| cells.checked_add(virtual_inactive_slot_cells))
        != Some(conceptual_padded_cells)
    {
        return Err("C6.3 compact cache census does not partition padded geometry".to_owned());
    }
    Ok(C63CompactCacheReferenceCensus {
        cache_len,
        cells_per_token,
        stored_cells,
        live_capacity_cells,
        virtual_tail_cells,
        virtual_padding_cells,
        virtual_inactive_slot_cells,
        conceptual_padded_cells,
    })
}

fn compact_table_len(layout: C6PersistentCacheLayout, cache_len: u16) -> Result<usize, String> {
    usize::from(cache_len)
        .checked_mul(usize::from(layout.layers))
        .and_then(|cells| cells.checked_mul(usize::from(layout.width)))
        .ok_or_else(|| "C6.3 compact cache table length overflows".to_owned())
}

fn compact_index(
    layout: C6PersistentCacheLayout,
    layer: u16,
    position: u16,
    channel: u16,
) -> Result<usize, String> {
    usize::from(position)
        .checked_mul(usize::from(layout.layers))
        .and_then(|cells| cells.checked_add(usize::from(layer)))
        .and_then(|cells| cells.checked_mul(usize::from(layout.width)))
        .and_then(|cells| cells.checked_add(usize::from(channel)))
        .ok_or_else(|| "C6.3 compact cache index overflows".to_owned())
}

fn validate_append_sources(
    expected: &[C6CacheCell],
    append_sources: &[C6CacheSourceValue],
) -> Result<(), String> {
    if append_sources.len() != expected.len() {
        return Err("C6.3 compact cache append source count differs".to_owned());
    }
    if expected.iter().zip(append_sources).any(|(cell, source)| *cell != source.cell) {
        return Err("C6.3 compact cache append source order differs".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, Fp2};
    use volta_mac::CorrelationStream;
    #[cfg(feature = "c6-trace")]
    use volta_proto::c6_cache_fold::{
        C6CacheFoldAppendSourceLayer, C6CacheFoldDirectSourceSegment,
    };
    #[cfg(feature = "c6-trace")]
    use volta_proto::C6SourceCoordinate;

    use crate::c6_persistent_cache::C6PersistentCacheStateWitness;

    fn layout() -> C6PersistentCacheLayout {
        C6PersistentCacheLayout {
            layers: 2,
            capacity_tokens: 4,
            width: 3,
            padded_layers: 2,
            padded_width: 4,
        }
    }

    fn sources(
        layout: C6PersistentCacheLayout,
        old_len: u16,
        new_len: u16,
        offset: u64,
    ) -> Vec<C6CacheSourceValue> {
        expected_c6_cache_append_cells(layout, old_len, new_len)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, cell)| C6CacheSourceValue {
                cell,
                value: Fp2::from_base(Fp::new(offset + index as u64)),
            })
            .collect()
    }

    fn correction_rows(
        position: u16,
        birth_epoch: u64,
        allocation_binding_digest: Hash,
        source_schedule_digest: Hash,
    ) -> Vec<C63CorrectionRowReference> {
        let layout = C6PersistentCacheLayout::production();
        (0..C63_BOLT_LIVE_ROWS_PER_POSITION)
            .map(|offset| {
                let layer_high = (offset >> 9) as u8;
                let channel_low = (offset & 0x01ff) as u16;
                let row = (u32::from(position) << 12)
                    | (u32::from(layer_high) << 9)
                    | u32::from(channel_low);
                let corrections = std::array::from_fn(|column| {
                    let (cell, tape) = c63_bolt_correction_cell(C63BoltCorrectionIndex {
                        row,
                        column: column as u8,
                    })
                    .unwrap();
                    if cell.layer < layout.layers && cell.channel < layout.width {
                        Fp::new(
                            1 + u64::from(cell.layer)
                                + 17 * u64::from(cell.channel)
                                + 1_009 * u64::from(position)
                                + 1_000_003
                                    * u64::from(match cell.kind {
                                        C6CacheSlotKind::Key => 0u8,
                                        C6CacheSlotKind::Value => 1u8,
                                    })
                                + 2_000_003 * u64::from(tape),
                        )
                    } else {
                        Fp::ZERO
                    }
                });
                C63CorrectionRowReference {
                    position,
                    layer_high,
                    channel_low,
                    birth_epoch,
                    allocation_binding_digest,
                    source_schedule_digest,
                    corrections,
                }
            })
            .collect()
    }

    #[test]
    fn compact_reference_applies_exact_append_and_virtualizes_zeros() {
        let layout = layout();
        let zero = C63CompactCacheReference::zero(layout).unwrap();
        let first_sources = sources(layout, 0, 2, 10);
        let first = zero.apply_append(2, &first_sources).unwrap();
        let second_sources = sources(layout, 2, 3, 100);
        let second = first.apply_append(3, &second_sources).unwrap();

        let mut dense = C6PersistentCacheStateWitness::zero(layout).unwrap();
        for source in first_sources.iter().chain(&second_sources) {
            dense.set(layout, source.cell, source.value).unwrap();
        }

        assert_eq!(first.stored_cells(), 2 * 2 * 2 * 3);
        assert_eq!(second.stored_cells(), 2 * 2 * 3 * 3);
        assert_eq!(second.value(first_sources[5].cell).unwrap(), first_sources[5].value);
        assert_eq!(second.value(second_sources[7].cell).unwrap(), second_sources[7].value);
        assert_eq!(
            second
                .value(C6CacheCell {
                    kind: C6CacheSlotKind::Key,
                    layer: 0,
                    position: 3,
                    channel: 0,
                })
                .unwrap(),
            Fp2::ZERO
        );
        assert_eq!(second.value_at(0, 0, 0, 3).unwrap(), Fp2::ZERO);
        assert_eq!(second.value_at(7, 0, 0, 0).unwrap(), Fp2::ZERO);
        for slot in 0..C6_PERSISTENT_CACHE_SLOTS {
            for layer in 0..layout.padded_layers {
                for position in 0..layout.capacity_tokens {
                    for channel in 0..layout.padded_width {
                        let kind =
                            if slot == 1 { C6CacheSlotKind::Value } else { C6CacheSlotKind::Key };
                        let dense_index = layout
                            .flat_index(C6CacheCell { kind, layer, position, channel })
                            .unwrap();
                        assert_eq!(
                            second.value_at(slot, layer, position, channel).unwrap(),
                            dense.slots[slot][dense_index]
                        );
                    }
                }
            }
        }

        let mut mutated = second.clone();
        mutated.tables[0][0] = Fp2::from_base(Fp::new(999));
        assert!(mutated.validate_transition_from(&first, &second_sources).is_err());

        let mut reordered = second_sources.clone();
        reordered.swap(0, 1);
        assert!(first.apply_append(3, &reordered).is_err());
        assert!(first.apply_append(3, &second_sources[..second_sources.len() - 1]).is_err());

        let census = c63_production_compact_cache_reference_census(150).unwrap();
        assert_eq!(census.cells_per_token, 18_432);
        assert_eq!(census.stored_cells, 2_764_800);
        assert_eq!(census.live_capacity_cells, 18_874_368);
        assert_eq!(census.virtual_tail_cells, 16_109_568);
        assert_eq!(census.virtual_padding_cells, 14_680_064);
        assert_eq!(census.virtual_inactive_slot_cells, 100_663_296);
        assert_eq!(census.conceptual_padded_cells, 134_217_728);
        assert_eq!(census.cells_per_token * 50, 921_600);
    }

    #[test]
    fn bolt_interleave_and_typed_position_roots_are_canonical() {
        for position in [0u16, 149, 511, 512, 1_023] {
            for layer_high in [0u8, 5, 6, 7] {
                for channel_low in [0u16, 255, 256, 511] {
                    for column in 0..C63_BOLT_COLUMNS {
                        let index = C63BoltCorrectionIndex {
                            row: (u32::from(position) << 12)
                                | (u32::from(layer_high) << 9)
                                | u32::from(channel_low),
                            column: column as u8,
                        };
                        let (cell, tape) = c63_bolt_correction_cell(index).unwrap();
                        assert_eq!(c63_bolt_correction_index(cell, tape).unwrap(), index);
                        assert_eq!(index.row >> 12, u32::from(position));
                        assert_eq!((index.row >> 9) & 0x07, u32::from(layer_high));
                    }
                }
            }
        }
        assert!(c63_bolt_correction_index(
            C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 0, channel: 0 },
            2,
        )
        .is_err());

        let profile = [7; 32];
        let allocation_1 = [11; 32];
        let allocation_2 = [13; 32];
        let schedule = [17; 32];
        let rows_0 = correction_rows(0, 1, allocation_1, schedule);
        let rows_1 = correction_rows(1, 2, allocation_2, schedule);
        let frame = c63_correction_live_row_frame(&rows_1[513]);
        assert_eq!(&frame[..8], b"C63CR3\0\0");
        assert_eq!(u16::from_le_bytes(frame[8..10].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(frame[10..12].try_into().unwrap()), 1);
        assert_eq!(frame[12], 1);
        assert_eq!(u16::from_le_bytes(frame[13..15].try_into().unwrap()), 1);
        assert_eq!(frame[15], 0);
        assert_eq!(u64::from_le_bytes(frame[16..24].try_into().unwrap()), 2);
        assert_eq!(&frame[24..56], &allocation_2);
        assert_eq!(&frame[56..88], &schedule);
        assert_eq!(
            u64::from_le_bytes(frame[88..96].try_into().unwrap()),
            rows_1[513].corrections[0].value()
        );
        let virtual_frame = c63_virtual_correction_row_frame();
        assert_eq!(&virtual_frame[..8], b"C63VZ3\0\0");
        assert!(virtual_frame[10..].iter().all(|&byte| byte == 0));
        let tile_0 = c63_correction_tile_root_reference(&rows_0).unwrap();
        let tile_1 = c63_correction_tile_root_reference(&rows_1).unwrap();
        let zero = c63_correction_state_root_reference(profile, 0, &[]).unwrap();
        let first = c63_correction_state_root_reference(profile, 1, &[tile_0]).unwrap();
        let second = c63_correction_state_root_reference(profile, 2, &[tile_0, tile_1]).unwrap();
        assert_ne!(zero, first);
        assert_ne!(first, second);
        assert_eq!(first, c63_correction_state_root_reference(profile, 1, &[tile_0]).unwrap());

        let mut changed_value = rows_0.clone();
        changed_value[0].corrections[0] += Fp::ONE;
        assert_ne!(tile_0, c63_correction_tile_root_reference(&changed_value).unwrap());
        let mut changed_scope = rows_0.clone();
        for row in &mut changed_scope {
            row.allocation_binding_digest = allocation_2;
        }
        assert_ne!(tile_0, c63_correction_tile_root_reference(&changed_scope).unwrap());
        let mut changed_epoch = rows_0.clone();
        for row in &mut changed_epoch {
            row.birth_epoch = 2;
        }
        assert_ne!(tile_0, c63_correction_tile_root_reference(&changed_epoch).unwrap());

        let mut reordered = rows_0.clone();
        reordered.swap(0, 1);
        assert!(c63_correction_tile_root_reference(&reordered).is_err());
        let mut mixed_scope = rows_0.clone();
        mixed_scope[1].allocation_binding_digest = allocation_2;
        assert!(c63_correction_tile_root_reference(&mixed_scope).is_err());
        let mut nonzero_padding = rows_0;
        nonzero_padding[256].corrections[8] = Fp::ONE;
        assert!(c63_correction_tile_root_reference(&nonzero_padding).is_err());
        assert!(c63_correction_state_root_reference(profile, 0, &[tile_0]).is_err());
    }

    #[test]
    fn correction_frontier_matches_full_roots_for_genesis_and_150_to_200() {
        let profile = [0x63; 32];
        let tile_roots = (0..200u16)
            .map(|position| crate::merkle::hash_leaf(&position.to_le_bytes()))
            .collect::<Vec<_>>();
        let mut frontier = C63CorrectionAppendFrontier::zero();
        assert_eq!(
            frontier.state_root(profile, 0).unwrap(),
            c63_correction_state_root_reference(profile, 0, &[]).unwrap(),
        );
        frontier.append(&tile_roots[..150]).unwrap();
        assert_eq!(
            frontier.state_root(profile, 1).unwrap(),
            c63_correction_state_root_reference(profile, 1, &tile_roots[..150]).unwrap(),
        );
        let accepted = frontier.clone();
        frontier.append(&tile_roots[150..]).unwrap();
        assert_eq!(frontier.accepted_len(), 200);
        assert_eq!(
            frontier.state_root(profile, 2).unwrap(),
            c63_correction_state_root_reference(profile, 2, &tile_roots).unwrap(),
        );
        let mut changed = tile_roots[150..].to_vec();
        changed[0][0] ^= 1;
        let mut rejected = accepted;
        rejected.append(&changed).unwrap();
        assert_ne!(
            rejected.state_root(profile, 2).unwrap(),
            frontier.state_root(profile, 2).unwrap()
        );
    }

    #[test]
    fn correction_multiproof_authenticates_spots_and_virtual_zeros() {
        let profile = [7; 32];
        let rows = correction_rows(0, 1, [11; 32], [17; 32]);
        let queried = [0, 7, 3_071, 3_072, 4_095, 4_096 + 19];
        let rho: [Fp2; C63_BOLT_COLUMNS] = std::array::from_fn(|column| {
            Fp2::new(Fp::new(31 + column as u64), Fp::new(71 + 3 * column as u64))
        });
        let predecessor_frontier = C63CorrectionAppendFrontier::zero();
        let predecessor_root = predecessor_frontier.state_root(profile, 0).unwrap();
        let (root, proof) =
            c63_open_correction_rows_reference(profile, 1, 0, &[rows.clone()], &queried).unwrap();
        let (spots, successor_frontier) = c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &queried,
            &rho,
            &proof,
        )
        .unwrap();
        let (tape_spots, replayed_frontier) = c63_verify_correction_rows_by_tape_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &queried,
            &rho,
            &proof,
        )
        .unwrap();
        let encoded = proof.encode(0, 1, &queried).unwrap();
        let decoded = C63CorrectionRowsOpeningReference::decode(&encoded, 0, 1, &queried).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(successor_frontier, replayed_frontier);
        assert_eq!(spots.len(), queried.len());
        for (offset, &row_index) in queried.iter().enumerate() {
            let expected = if row_index < C63_BOLT_LIVE_ROWS_PER_POSITION as u32 {
                rows[row_index as usize]
                    .corrections
                    .iter()
                    .zip(&rho)
                    .fold(Fp2::ZERO, |sum, (&correction, &weight)| {
                        sum + weight.mul_base(correction)
                    })
            } else {
                Fp2::ZERO
            };
            assert_eq!(spots[offset], (row_index, expected));
            assert_eq!(tape_spots[offset].0, row_index);
            assert_eq!(tape_spots[offset].1[0] + tape_spots[offset].1[1], expected);
        }

        let mut bad_row = proof.clone();
        bad_row.tiles[0].corrections[0][0] += Fp::ONE;
        assert!(c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &queried,
            &rho,
            &bad_row
        )
        .is_err());
        let mut bad_frontier = proof.clone();
        bad_frontier.tiles[0].frontier[0][0] ^= 1;
        assert!(c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &queried,
            &rho,
            &bad_frontier
        )
        .is_err());
        let mut trailing = proof.clone();
        trailing.tiles.push(trailing.tiles[0].clone());
        assert!(c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &queried,
            &rho,
            &trailing
        )
        .is_err());
        assert!(c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            1,
            &[0, 0],
            &rho,
            &proof
        )
        .is_err());
        assert!(c63_verify_correction_rows_reference(
            predecessor_root,
            root,
            &predecessor_frontier,
            profile,
            1,
            0,
            2,
            &queried,
            &rho,
            &proof
        )
        .is_err());

        let mut noncanonical = encoded.clone();
        noncanonical[114..122].copy_from_slice(&volta_field::P.to_le_bytes());
        assert!(C63CorrectionRowsOpeningReference::decode(&noncanonical, 0, 1, &queried).is_err());
        let mut trailing_bytes = encoded.clone();
        trailing_bytes.push(0);
        assert!(C63CorrectionRowsOpeningReference::decode(&trailing_bytes, 0, 1, &queried).is_err());
        assert!(C63CorrectionRowsOpeningReference::decode(
            &encoded[..encoded.len() - 1],
            0,
            1,
            &queried,
        )
        .is_err());
    }

    #[test]
    fn bolt_single_row_challenge_pulls_back_to_both_mac_tapes() {
        let cells = [
            C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 149, channel: 0 },
            C6CacheCell { kind: C6CacheSlotKind::Value, layer: 1, position: 149, channel: 511 },
            C6CacheCell { kind: C6CacheSlotKind::Key, layer: 10, position: 149, channel: 512 },
            C6CacheCell { kind: C6CacheSlotKind::Value, layer: 11, position: 149, channel: 767 },
        ];
        let corrections = [
            [Fp::new(3), Fp::new(5)],
            [Fp::new(7), Fp::new(11)],
            [Fp::new(13), Fp::new(17)],
            [Fp::new(19), Fp::new(23)],
        ];
        let rho: [Fp2; C63_BOLT_COLUMNS] = std::array::from_fn(|column| {
            Fp2::new(Fp::new(29 + 17 * column as u64), Fp::new(43 + 19 * column as u64))
        });
        let row_weight =
            |row: u32| Fp2::new(Fp::new(59 + u64::from(row)), Fp::new(61 + u64::from(row)));

        let per_tape: [Fp2; 2] = std::array::from_fn(|tape| {
            cells.iter().zip(&corrections).fold(Fp2::ZERO, |sum, (cell, correction)| {
                let index = c63_bolt_correction_index(*cell, tape as u8).unwrap();
                let coefficient =
                    c63_bolt_interleaved_coefficient_reference(index, row_weight(index.row), &rho)
                        .unwrap();
                sum + coefficient.mul_base(correction[tape])
            })
        });
        let combined = cells.iter().zip(&corrections).fold(Fp2::ZERO, |sum, (cell, correction)| {
            (0..2u8).fold(sum, |sum, tape| {
                let index = c63_bolt_correction_index(*cell, tape).unwrap();
                let coefficient =
                    c63_bolt_interleaved_coefficient_reference(index, row_weight(index.row), &rho)
                        .unwrap();
                sum + coefficient.mul_base(correction[usize::from(tape)])
            })
        });
        assert_eq!(combined, per_tape[0] + per_tape[1]);
        assert!(c63_bolt_interleaved_coefficient_reference(
            C63BoltCorrectionIndex { row: C63_BOLT_ROWS as u32, column: 0 },
            Fp2::ONE,
            &rho,
        )
        .is_err());
    }

    #[test]
    fn authenticated_correction_functional_reuses_transformer_sources_and_rejects_drift() {
        let layout = C6PersistentCacheLayout::production();
        let live_len = 1;
        let point = (0..12)
            .map(|index| Fp2::new(Fp::new(31 + index), Fp::new(47 + index)))
            .collect::<Vec<_>>();
        let rho: [Fp2; C63_BOLT_COLUMNS] = std::array::from_fn(|column| {
            Fp2::new(Fp::new(71 + column as u64), Fp::new(97 + column as u64))
        });
        let deltas = [Fp2::new(Fp::new(101), Fp::new(103)), Fp2::new(Fp::new(107), Fp::new(109))];
        let cells = expected_c6_cache_append_cells(layout, 0, live_len).unwrap();
        let row_weights = C63RowEqualityFactors::new(&point).unwrap();
        let mut prover = Vec::with_capacity(cells.len());
        let mut verifier = Vec::with_capacity(cells.len());
        let mut expected = [Fp2::ZERO; 2];
        let mut expected_limbs = [[Fp2::ZERO; 2]; 2];
        for (ordinal, cell) in cells.into_iter().enumerate() {
            let correction =
                std::array::from_fn(|tape| Fp::new(3 + ordinal as u64 * 5 + tape as u64 * 7));
            let masks: [Fp; 2] =
                std::array::from_fn(|tape| Fp::new(11 + ordinal as u64 * 13 + tape as u64 * 17));
            let tags: [Fp2; 2] = std::array::from_fn(|tape| {
                Fp2::new(
                    Fp::new(19 + ordinal as u64 * 23 + tape as u64),
                    Fp::new(29 + ordinal as u64 * 31 + tape as u64),
                )
            });
            let source = std::array::from_fn(|tape| {
                ProverAuthed::new(Fp2::from_base(masks[tape] + correction[tape]), tags[tape])
            });
            let mask = std::array::from_fn(|tape| {
                ProverAuthed::new(Fp2::from_base(masks[tape]), tags[tape])
            });
            let source_keys = std::array::from_fn(|tape| {
                VerifierKey::new(tags[tape] + deltas[tape] * source[tape].x)
            });
            let mask_keys = std::array::from_fn(|tape| {
                VerifierKey::new(tags[tape] + deltas[tape] * mask[tape].x)
            });
            for tape in 0..2 {
                let index = c63_bolt_correction_index(cell, tape as u8).unwrap();
                let coefficient = c63_bolt_interleaved_coefficient_reference(
                    index,
                    row_weights.weight(index.row).unwrap(),
                    &rho,
                )
                .unwrap();
                expected[tape] += coefficient.mul_base(correction[tape]);
                let row_weight = row_weights.weight(index.row).unwrap();
                for limb in 0..2 {
                    let scalar = if limb == 0 {
                        rho[usize::from(index.column)].c0
                    } else {
                        rho[usize::from(index.column)].c1
                    };
                    expected_limbs[tape][limb] +=
                        row_weight * Fp2::from_base(correction[tape] * scalar);
                }
            }
            prover.push(C63AuthenticatedCorrectionProverCell { cell, correction, source, mask });
            verifier.push(C63AuthenticatedCorrectionVerifierCell { cell, source_keys, mask_keys });
        }

        let prover_open = c63_authenticated_correction_functional_prover_reference(
            0, live_len, &prover, &rho, &point,
        )
        .unwrap();
        let verifier_open = c63_authenticated_correction_functional_verifier_reference(
            0, live_len, &verifier, deltas, &rho, &point,
        )
        .unwrap();
        let basis = Fp2::new(Fp::ZERO, Fp::ONE);
        for tape in 0..2 {
            assert_eq!(
                prover_open[tape][0].add(prover_open[tape][1].scale(basis)).x,
                expected[tape],
            );
            for limb in 0..2 {
                let expected_limb = expected_limbs[tape][limb];
                assert_eq!(prover_open[tape][limb].x, expected_limb);
                assert_eq!(prover_open[tape][limb].m, Fp2::ZERO);
                assert_eq!(verifier_open[tape][limb].k, deltas[tape] * expected_limb);
            }
        }

        let mut changed = prover.clone();
        changed[0].correction[0] += Fp::ONE;
        assert!(c63_authenticated_correction_functional_prover_reference(
            0, live_len, &changed, &rho, &point,
        )
        .is_err());
        let mut changed = verifier.clone();
        changed[0].source_keys[0] =
            changed[0].source_keys[0].add(VerifierKey::from_public(Fp2::ONE, deltas[0]));
        assert_ne!(
            c63_authenticated_correction_functional_verifier_reference(
                0, live_len, &changed, deltas, &rho, &point,
            )
            .unwrap(),
            verifier_open,
        );
        prover.swap(0, 1);
        assert!(c63_authenticated_correction_functional_prover_reference(
            0, live_len, &prover, &rho, &point,
        )
        .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn residual_source_functional_compiler_maps_cache_domains_without_key_log() {
        let layers = (0..12u16)
            .map(|layer| {
                C6CacheFoldAppendSourceLayer::new(
                    layer,
                    vec![C6CacheFoldDirectSourceSegment {
                        base_domain: 0x0100_0000 + u64::from(layer) * 0x100,
                        rows: 2,
                    }],
                    vec![C6CacheFoldDirectSourceSegment {
                        base_domain: 0x0200_0000 + u64::from(layer) * 0x100,
                        rows: 2,
                    }],
                )
                .and_then(|layer| layer.suffix_from(1))
                .unwrap()
            })
            .collect::<Vec<_>>();
        let plan = C6CacheFoldAppendSourcePlan::new(layers).unwrap();
        let mut streams = [CorrelationStream::new([0x31; 32]), CorrelationStream::new([0x32; 32])];
        for stream in &mut streams {
            stream.enable_c6_source_witness_collection().unwrap();
            let _ = stream.draw_fulls(0x0300_0000, 2);
            stream
                .record_c6_fullfield_plaintexts(
                    0x0300_0000,
                    &[Fp2::from_base(Fp::new(5)), Fp2::from_base(Fp::new(7))],
                )
                .unwrap();
        }
        let mut sub_offset = 0u64;
        for layer in plan.layers() {
            for kind in [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns] {
                let domain = layer.source_domain(kind, 1).unwrap();
                let plaintexts =
                    (0..768).map(|channel| Fp::new(101 + sub_offset + channel)).collect::<Vec<_>>();
                for stream in &mut streams {
                    let correlations = stream.draw_subs(domain, plaintexts.len());
                    let corrections = correlations
                        .iter()
                        .zip(&plaintexts)
                        .map(|(source, plaintext)| (*plaintext - source.r).value())
                        .collect::<Vec<_>>();
                    stream.record_c6_subfield_corrections(domain, &corrections).unwrap();
                }
                sub_offset += 768;
            }
        }
        let schedule = streams[0].schedule_audit().unwrap();
        assert_eq!(streams[1].schedule_audit(), Some(schedule.clone()));
        let digest = schedule.digest;
        let [mut first, mut second] = streams;
        let coordinates = [
            C6SourceCoordinate::new(
                first.finish_c6_subfield_witness_collection().unwrap(),
                first.finish_c6_fullfield_witness_collection().unwrap(),
                &schedule,
            )
            .unwrap(),
            C6SourceCoordinate::new(
                second.finish_c6_subfield_witness_collection().unwrap(),
                second.finish_c6_fullfield_witness_collection().unwrap(),
                &schedule,
            )
            .unwrap(),
        ];
        let paired =
            C6PairedSourceWitness::new([[0x41; 32], [0x42; 32]], coordinates, &schedule, digest)
                .unwrap();
        let point = (0..C63_BOLT_ROW_LOG2)
            .map(|index| Fp2::new(Fp::new(401 + u64::from(index)), Fp::new(701 + u64::from(index))))
            .collect::<Vec<_>>();
        let rho = std::array::from_fn(|column| {
            Fp2::new(Fp::new(1_001 + column as u64), Fp::new(2_003 + column as u64))
        });
        let source_count = u32::try_from(2 + sub_offset).unwrap();
        let coefficients = c63_compile_residual_source_functionals(
            1,
            2,
            source_count,
            digest,
            &plan,
            &schedule,
            &rho,
            &point,
        )
        .unwrap();
        assert_eq!(coefficients[0].len(), source_count as usize);
        assert_eq!(coefficients[0][..2], [Fp2::ZERO; 2]);
        let cell = C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 1, channel: 0 };
        let index = c63_bolt_correction_index(cell, 0).unwrap();
        let factors = C63RowEqualityFactors::new(&point).unwrap();
        assert_eq!(
            coefficients[0][2],
            c63_bolt_interleaved_coefficient_reference(
                index,
                factors.weight(index.row).unwrap(),
                &rho,
            )
            .unwrap()
        );
        assert_ne!(coefficients[0][2], coefficients[1][2]);
        let values = c63_evaluate_paired_source_functionals(
            1,
            2,
            digest,
            &plan,
            &schedule,
            &paired,
            [&coefficients[0], &coefficients[1]],
        )
        .unwrap();
        let expected = std::array::from_fn(|tape| {
            paired.coordinates()[tape]
                .subfield()
                .corrections()
                .iter()
                .zip(&coefficients[tape][2..])
                .fold(Fp2::ZERO, |sum, (&correction, &coefficient)| {
                    sum + Fp2::from_base(correction) * coefficient
                })
        });
        assert_eq!(values, expected);
        assert!(c63_compile_residual_source_functionals(
            1,
            2,
            source_count,
            [0x55; 32],
            &plan,
            &schedule,
            &rho,
            &point,
        )
        .is_err());
    }

    #[test]
    fn sparse_sketch_update_and_authenticated_transpose_are_exact() {
        let sketch = C63SparseSketchReference::new(
            4,
            2,
            vec![
                C63SparseSketchEdge {
                    input: 0,
                    socket_ordinal: 0,
                    output: 0,
                    coefficient: Fp::new(2),
                },
                C63SparseSketchEdge {
                    input: 0,
                    socket_ordinal: 1,
                    output: 0,
                    coefficient: Fp::new(3),
                },
                C63SparseSketchEdge {
                    input: 1,
                    socket_ordinal: 0,
                    output: 0,
                    coefficient: Fp::new(5),
                },
                C63SparseSketchEdge {
                    input: 2,
                    socket_ordinal: 0,
                    output: 1,
                    coefficient: Fp::new(7),
                },
                C63SparseSketchEdge {
                    input: 3,
                    socket_ordinal: 0,
                    output: 0,
                    coefficient: Fp::new(11),
                },
            ],
        )
        .unwrap();
        let predecessor = [1, 2, 0, 0].map(|value| Fp2::from_base(Fp::new(value)));
        let delta = [0, 0, 3, 4].map(|value| Fp2::from_base(Fp::new(value)));
        let successor: [Fp2; 4] = std::array::from_fn(|index| predecessor[index] + delta[index]);
        let old_sketch = sketch.apply(&predecessor).unwrap();
        let delta_sketch = sketch.apply(&delta).unwrap();
        let new_sketch = sketch.apply(&successor).unwrap();
        assert_eq!(
            new_sketch,
            old_sketch
                .iter()
                .zip(&delta_sketch)
                .map(|(&old, &change)| old + change)
                .collect::<Vec<_>>()
        );

        let challenge = [Fp2::new(Fp::new(13), Fp::new(17)), Fp2::new(Fp::new(19), Fp::new(23))];
        let input_weights = sketch.transpose_weights(&challenge).unwrap();
        let opened_sketch = challenge
            .iter()
            .zip(&new_sketch)
            .fold(Fp2::ZERO, |sum, (&weight, &value)| sum + weight * value);
        let opened_input = input_weights
            .iter()
            .zip(&successor)
            .fold(Fp2::ZERO, |sum, (&weight, &value)| sum + weight * value);
        assert_eq!(opened_sketch, opened_input);

        for mac_delta in [Fp2::new(Fp::new(29), Fp::new(31)), Fp2::new(Fp::new(37), Fp::new(41))] {
            let tags = [43, 47, 53, 59].map(|value| Fp2::from_base(Fp::new(value)));
            let prover_open = input_weights.iter().zip(successor.iter().zip(&tags)).fold(
                volta_mac::ProverAuthed::ZERO,
                |sum, (&weight, (&value, &tag))| {
                    sum.add(volta_mac::ProverAuthed::new(value, tag).scale(weight))
                },
            );
            let verifier_open = input_weights.iter().zip(successor.iter().zip(&tags)).fold(
                volta_mac::VerifierKey::ZERO,
                |sum, (&weight, (&value, &tag))| {
                    sum.add(volta_mac::VerifierKey::new(tag + mac_delta * value).scale(weight))
                },
            );
            assert_eq!(prover_open.x, opened_sketch);
            assert_eq!(verifier_open.k, prover_open.m + mac_delta * prover_open.x);
        }

        assert!(C63SparseSketchReference::new(
            2,
            1,
            vec![
                C63SparseSketchEdge {
                    input: 1,
                    socket_ordinal: 0,
                    output: 0,
                    coefficient: Fp::ONE,
                },
                C63SparseSketchEdge {
                    input: 0,
                    socket_ordinal: 0,
                    output: 0,
                    coefficient: Fp::ONE,
                },
            ],
        )
        .is_err());
    }

    #[test]
    fn sparse_setup_sampler_is_canonical_unbiased_and_keeps_parallel_edges() {
        let seed = [0x5au8; 32];
        let setup = C63SparseSetupReference::sample(seed, 4, 2, 4, 8).unwrap();
        assert_eq!(setup.dimensions(), (4, 2));
        let mut destinations = setup.permutation().to_vec();
        destinations.sort_unstable();
        assert_eq!(destinations, (0..16u32).collect::<Vec<_>>());
        assert!(setup.coefficients().iter().all(|&coefficient| coefficient != Fp::ZERO));

        let edges = setup.sketch_edges();
        assert!((0..4u32).any(|input| {
            let mut outputs = edges
                .iter()
                .filter(|edge| edge.input == input)
                .map(|edge| edge.output)
                .collect::<Vec<_>>();
            outputs.sort_unstable();
            outputs.windows(2).any(|pair| pair[0] == pair[1])
        }));
        C63SparseSketchReference::new(4, 2, edges).unwrap();
        assert_eq!(setup, C63SparseSetupReference::sample(seed, 4, 2, 4, 8).unwrap());
        assert_ne!(
            setup.expanded_h_digest(),
            C63SparseSetupReference::sample([0x5bu8; 32], 4, 2, 4, 8).unwrap().expanded_h_digest()
        );

        let descriptor = setup.descriptor();
        let encoded = descriptor.encode().unwrap();
        assert_eq!(encoded.len(), C63_SPARSE_SETUP_DESCRIPTOR_BYTES);
        let decoded = C63SparseSetupDescriptor::decode(&encoded).unwrap();
        assert_eq!(decoded, descriptor);
        assert_eq!(decoded.seed(), seed);
        assert_eq!(decoded.expanded_h_digest(), setup.expanded_h_digest());
        assert_eq!(C63SparseSetupReference::verify_descriptor(decoded).unwrap(), setup);
        assert!(C63SparseSetupReference::verify_production_descriptor(decoded).is_err());

        let mut wrong_seed = encoded;
        wrong_seed[16] ^= 1;
        let wrong_seed = C63SparseSetupDescriptor::decode(&wrong_seed).unwrap();
        assert!(C63SparseSetupReference::verify_descriptor(wrong_seed).is_err());

        let mut wrong_digest = encoded;
        wrong_digest[48] ^= 1;
        let wrong_digest = C63SparseSetupDescriptor::decode(&wrong_digest).unwrap();
        assert!(C63SparseSetupReference::verify_descriptor(wrong_digest).is_err());

        let mut wrong_geometry = encoded;
        wrong_geometry[10] += 1;
        let wrong_geometry = C63SparseSetupDescriptor::decode(&wrong_geometry).unwrap();
        assert!(C63SparseSetupReference::verify_descriptor(wrong_geometry).is_err());

        let mut wrong_field = encoded;
        wrong_field[14] ^= 1;
        assert!(C63SparseSetupDescriptor::decode(&wrong_field).is_err());
    }
}

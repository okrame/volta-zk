//! Small executable C6.4 reference for the joint cache/residual correction sketch.
//!
//! This module proves only the linear row-layout identity.  It intentionally
//! has no prover, codec, production geometry allocation, GPU path or claim of
//! residual/source binding.

use volta_field::{Fp, Fp2};
use volta_proto::C6PairedResidualCorrectionRows;

use crate::c63_authenticated_sketch::C63SparseSketchReference;

pub const C64_JOINT_COLUMNS: usize = 16;
pub const C64_RESIDUAL_PUBLIC_COLUMNS: usize = 4;

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
}

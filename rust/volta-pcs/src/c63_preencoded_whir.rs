//! CPU reference for C6.3's pre-encoded initial WHIR oracle.
//!
//! This freezes the deterministic `A * rho` layout and a CPU-only, opt-in
//! first-round link against the existing C6.2 cached-base seam. It is not a
//! production adapter, a privacy proof, the systematic `D' -> m` link, or
//! evidence for paired queries.

use std::sync::Arc;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeError;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_whir_c61::pcs::proof::QueryOpenings;
use p3_whir_c61::pcs::zk::ZkWhirInitialOracleLink;
use volta_field::Fp2;

use crate::c61_whir_reference::{
    c61_reference_mmcs, c61_volta_fp2_from_p3, C61Commitment, C61Mmcs, C61MultiProof, C61P3Fp2,
};
use crate::c63_authenticated_sketch::C63_BOLT_COLUMNS;

pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2: usize = 19;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROWS: usize = 1 << C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2;
pub const C63_ENCODED_SKETCH_FOLDED_POSITIONS: usize = 2;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH: usize =
    C63_BOLT_COLUMNS * C63_ENCODED_SKETCH_FOLDED_POSITIONS;
pub const C63_ENCODED_SKETCH_INDEPENDENT_A_QUERIES: usize = 486;

type C63InnerProof = <C61Mmcs as Mmcs<Goldilocks>>::Proof;
type C63AProverData = <C61Mmcs as Mmcs<Goldilocks>>::ProverData<DenseMatrix<Goldilocks>>;

/// Prover data for the ordinary C6.1 MMCS plus, only on the first randomized
/// `y` oracle, the separately rooted D19-by-32 tensor `A`.
pub(crate) struct C63ProjectedProverData<M> {
    inner: <C61Mmcs as Mmcs<Goldilocks>>::ProverData<M>,
    encoded_sketch_a: Option<Arc<C63AProverData>>,
}

/// The extra tuple member is present only for the opt-in `A -> y` opening.
/// Keeping the ordinary proof first lets no-link commits and openings delegate
/// without changing their values or transcript observations.
type C63ProjectedProof = (C63InnerProof, Option<(Vec<Vec<Goldilocks>>, C63InnerProof)>);
type C63ProjectedMultiProof = (C61MultiProof, Option<(Vec<Vec<Goldilocks>>, C61MultiProof)>);

/// Verifier-known context for one base-field limb of `y=A*rho`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct C63EncodedSketchAtoYContext {
    accepted_d: C61Commitment,
    accepted_a: C61Commitment,
    dimensions: Dimensions,
    coefficients: [Goldilocks; C63_BOLT_COLUMNS],
    limb: usize,
}

impl C63EncodedSketchAtoYContext {
    /// Bind both deterministic roots, then draw one verifier-owned
    /// `rho in Fp2^16` and build the two limb contexts from that same draw.
    pub(crate) fn sample_pair_after_roots<Challenger>(
        accepted_d: C61Commitment,
        accepted_a: C61Commitment,
        rows: usize,
        challenger: &mut Challenger,
    ) -> Result<([Fp2; C63_BOLT_COLUMNS], [Self; 2]), String>
    where
        Challenger: FieldChallenger<Goldilocks> + CanObserve<C61Commitment>,
    {
        if rows == 0 || !rows.is_power_of_two() {
            return Err("C6.3 A-to-y context geometry differs".to_owned());
        }
        challenger.observe(accepted_d.clone());
        challenger.observe(accepted_a.clone());
        let rho = std::array::from_fn(|_| {
            let value: C61P3Fp2 = challenger.sample_algebra_element();
            c61_volta_fp2_from_p3(value)
        });
        let contexts = std::array::from_fn(|limb| Self {
            accepted_d: accepted_d.clone(),
            accepted_a: accepted_a.clone(),
            dimensions: Dimensions { width: C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH, height: rows },
            coefficients: rho.map(|value| {
                Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() })
            }),
            limb,
        });
        Ok((rho, contexts))
    }
}

/// CPU MMCS seam which opens the fresh randomized `y` row and the accepted
/// `A` row at the same verifier-derived first-round WHIR positions.
///
/// Later WHIR commitments and the default/no-link path delegate to C6.1.
#[derive(Clone)]
pub(crate) struct C63ProjectedMmcs {
    inner: C61Mmcs,
    context: Arc<C63EncodedSketchAtoYContext>,
}

impl C63ProjectedMmcs {
    pub(crate) fn new(context: C63EncodedSketchAtoYContext) -> Self {
        Self { inner: c61_reference_mmcs(), context: Arc::new(context) }
    }

    pub(crate) fn link(&self) -> C63EncodedSketchAtoYLink {
        C63EncodedSketchAtoYLink { context: Arc::clone(&self.context) }
    }

    /// Marks exactly one already-committed WHIR oracle as the projected
    /// `A -> y` initial oracle. The accepted root is checked before attaching
    /// its prover data.
    pub(crate) fn attach_encoded_sketch_a<M>(
        &self,
        prover_data: &mut C63ProjectedProverData<M>,
        commitment: &C61Commitment,
        a_data: C63AProverData,
    ) -> Result<(), String> {
        if commitment != &self.context.accepted_a {
            return Err("C6.3 attached A root differs from accepted root".to_owned());
        }
        if prover_data.encoded_sketch_a.is_some() {
            return Err("C6.3 A prover data already attached".to_owned());
        }
        prover_data.encoded_sketch_a = Some(Arc::new(a_data));
        Ok(())
    }
}

impl Mmcs<Goldilocks> for C63ProjectedMmcs {
    type ProverData<M> = C63ProjectedProverData<M>;
    type Commitment = C61Commitment;
    type Proof = C63ProjectedProof;
    type MultiProof = C63ProjectedMultiProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, inner) = self.inner.commit(inputs);
        (commitment, C63ProjectedProverData { inner, encoded_sketch_a: None })
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
        let ordinary = self.inner.open_batch(index, &prover_data.inner);
        let linked = prover_data.encoded_sketch_a.as_ref().map(|a_data| {
            let opening = self.inner.open_batch(index, a_data);
            let (rows, proof) = opening.unpack();
            (rows, proof)
        });
        BatchOpening::new(ordinary.opened_values, (ordinary.opening_proof, linked))
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner.get_matrices(&prover_data.inner)
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        let (ordinary_proof, linked) = batch_opening.opening_proof;
        self.inner.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::new(batch_opening.opened_values, ordinary_proof),
        )?;
        if let Some((a_rows, a_proof)) = linked {
            self.inner.verify_batch(
                &self.context.accepted_a,
                std::slice::from_ref(&self.context.dimensions),
                index,
                BatchOpeningRef::new(a_rows, a_proof),
            )?;
        }
        Ok(())
    }

    fn open_multi_batch<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let (ordinary_rows, ordinary_proof) =
            self.inner.open_multi_batch(indices, &prover_data.inner);
        let linked = prover_data.encoded_sketch_a.as_ref().map(|a_data| {
            let (rows, proof) = self.inner.open_multi_batch(indices, a_data);
            let rows = rows
                .into_iter()
                .map(|mut per_matrix| {
                    assert_eq!(per_matrix.len(), 1, "C6.3 A root holds one matrix");
                    per_matrix.swap_remove(0)
                })
                .collect();
            (rows, proof)
        });
        (ordinary_rows, (ordinary_proof, linked))
    }

    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(commit, dimensions, indices, opened_values, &proof.0)?;
        if let Some((a_rows, a_proof)) = &proof.1 {
            let opened_a = a_rows.iter().map(|row| vec![row.as_slice()]).collect::<Vec<_>>();
            self.inner.verify_multi_batch(
                &self.context.accepted_a,
                std::slice::from_ref(&self.context.dimensions),
                indices,
                &opened_a,
                a_proof,
            )?;
        }
        Ok(())
    }
}

/// Extracts `randomized_y - project(A,rho,limb)` from the authenticated rows.
/// WHIR's opt-in first-round equation constrains these values to
/// `Enc(0,zeta)`; this type does not claim the separate Bolt `D' -> m` link.
#[derive(Clone)]
pub(crate) struct C63EncodedSketchAtoYLink {
    context: Arc<C63EncodedSketchAtoYContext>,
}

impl<EF> ZkWhirInitialOracleLink<Goldilocks, EF, C63ProjectedMmcs> for C63EncodedSketchAtoYLink
where
    EF: p3_field::ExtensionField<Goldilocks>,
{
    fn required(&self) -> bool {
        true
    }

    fn folded_mask_values(
        &self,
        opening: &QueryOpenings<Goldilocks, EF, C63ProjectedMultiProof>,
        indices: &[usize],
        randomness: &Point<EF>,
    ) -> Option<Vec<EF>> {
        let QueryOpenings::Base(opening) = opening else {
            return None;
        };
        let (_, Some((a_rows, _))) = &opening.proof else {
            return None;
        };
        if opening.rows.len() != indices.len()
            || a_rows.len() != indices.len()
            || opening.rows.iter().any(|row| row.len() != C63_ENCODED_SKETCH_FOLDED_POSITIONS)
            || a_rows.iter().any(|row| row.len() != C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH)
        {
            return None;
        }

        opening
            .rows
            .iter()
            .zip(a_rows)
            .map(|(randomized, a_row)| {
                let mut difference = randomized.clone();
                for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
                    let projected = (0..C63_BOLT_COLUMNS)
                        .map(|column| {
                            a_row[column * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position]
                                * self.context.coefficients[column]
                        })
                        .sum::<Goldilocks>();
                    difference[folded_position] -= projected;
                }
                Some(Poly::new(difference).eval_base(randomness))
            })
            .collect()
    }
}

/// Pack the sixteen deterministic scalar codewords into WHIR's first-fold
/// leaf order. Each physical row is
/// `[column_0/fold_0, column_0/fold_1, ..., column_15/fold_1]`.
pub fn c63_pack_encoded_sketch_rows_reference(
    encoded_columns: &[DenseMatrix<Goldilocks>],
) -> Result<DenseMatrix<Goldilocks>, String> {
    if encoded_columns.len() != C63_BOLT_COLUMNS {
        return Err("C6.3 encoded sketch needs sixteen tensor columns".to_owned());
    }
    let values_per_column = encoded_columns[0].values.len();
    if encoded_columns[0].width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
        || values_per_column == 0
        || !values_per_column
            .checked_div(C63_ENCODED_SKETCH_FOLDED_POSITIONS)
            .is_some_and(usize::is_power_of_two)
        || encoded_columns.iter().any(|column| {
            column.width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
                || column.values.len() != values_per_column
        })
    {
        return Err("C6.3 encoded sketch column geometry differs".to_owned());
    }

    let rows = values_per_column / C63_ENCODED_SKETCH_FOLDED_POSITIONS;
    let mut packed = Vec::with_capacity(rows * C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH);
    for row in 0..rows {
        for column in encoded_columns {
            let start = row * C63_ENCODED_SKETCH_FOLDED_POSITIONS;
            packed.extend_from_slice(
                &column.values[start..start + C63_ENCODED_SKETCH_FOLDED_POSITIONS],
            );
        }
    }
    Ok(DenseMatrix::new(packed, C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH))
}

/// Project a paired `A` row by one base-field limb of `rho in Fp2^16`.
/// The result has exactly the width-two layout consumed by
/// `commit_c62_cached_fixed_base`.
pub fn c63_project_encoded_sketch_limb_reference(
    paired_rows: &DenseMatrix<Goldilocks>,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    limb: usize,
) -> Result<DenseMatrix<Goldilocks>, String> {
    if limb >= 2
        || paired_rows.width != C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH
        || paired_rows.values.is_empty()
        || paired_rows.values.len() % C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH != 0
        || !(paired_rows.values.len() / C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH).is_power_of_two()
    {
        return Err("C6.3 encoded sketch projection geometry differs".to_owned());
    }
    let coefficients = rho
        .map(|value| Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() }));
    let mut projected = Vec::with_capacity(paired_rows.values.len() / C63_BOLT_COLUMNS);
    for row in paired_rows.values.chunks_exact(C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH) {
        for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
            let mut value = Goldilocks::ZERO;
            for column in 0..C63_BOLT_COLUMNS {
                value += row[column * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position]
                    * coefficients[column];
            }
            projected.push(value);
        }
    }
    Ok(DenseMatrix::new(projected, C63_ENCODED_SKETCH_FOLDED_POSITIONS))
}

/// Project the decoded D19 tensor message by the same limb and column order.
pub fn c63_project_decoded_sketch_limb_reference(
    columns: &[Poly<Goldilocks>],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    limb: usize,
) -> Result<Poly<Goldilocks>, String> {
    if columns.len() != C63_BOLT_COLUMNS || limb >= 2 {
        return Err("C6.3 decoded sketch projection geometry differs".to_owned());
    }
    let len = columns[0].as_slice().len();
    if len == 0
        || !len.is_power_of_two()
        || columns.iter().any(|column| column.as_slice().len() != len)
    {
        return Err("C6.3 decoded sketch column geometry differs".to_owned());
    }
    let coefficients = rho
        .map(|value| Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() }));
    let mut projected = Goldilocks::zero_vec(len);
    for (column, coefficient) in columns.iter().zip(coefficients) {
        for (target, &value) in projected.iter_mut().zip(column.as_slice()) {
            *target += value * coefficient;
        }
    }
    Ok(Poly::new(projected))
}

/// Reference-only equality check for the decoded-message/pre-encoded-oracle
/// link. A production prover must establish this relation without re-encoding.
pub fn c63_check_preencoded_link_reference(
    projected: &DenseMatrix<Goldilocks>,
    ordinary_encoding: &DenseMatrix<Goldilocks>,
) -> Result<(), String> {
    if projected == ordinary_encoding {
        Ok(())
    } else {
        Err("C6.3 pre-encoded initial oracle is not the decoded message encoding".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use p3_blake3::Blake3;
    use p3_challenger::{CanObserve, FieldChallenger, HashChallenger, SerializingChallenger64};
    use p3_commit::Mmcs;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::Dimensions;
    use p3_multilinear_util::point::Point;
    use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    use p3_whir_c61::pcs::zk::{HidingWhirProver, HidingWhirVerifier, ZkParameters, ZkWhirConfig};
    use rand_010::rngs::StdRng;
    use rand_010::SeedableRng;
    use volta_field::{Fp, Fp2};
    use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

    use super::*;
    use crate::c61_authenticated_whir::{
        finish_c61_authenticated_whir_base, prepare_c61_authenticated_whir_mask,
        verify_c61_authenticated_whir_base, C61AuthenticatedWhirAffineClaim,
        C61AuthenticatedWhirMaskRange, C61AuthenticatedWhirProverFinishInput,
        C61AuthenticatedWhirVerifierInput,
    };
    use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};
    use crate::c61_whir_reference::{
        c61_p3_fp2_from_volta, c61_reference_mmcs, c61_volta_fp2_from_p3, C61P3Fp2,
        C61SizingChallenger,
    };

    const TEST_NUM_VARIABLES: usize = 12;

    fn config<Challenger>() -> ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>
    where
        Challenger: p3_challenger::FieldChallenger<Goldilocks>
            + p3_challenger::GrindingChallenger<Witness = Goldilocks>,
    {
        ZkWhirConfig::new(
            TEST_NUM_VARIABLES,
            ProtocolParameters {
                security_level: 32,
                pow_bits: 0,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::ConstantFromSecondRound(1, 2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            ZkParameters { ell_zk: 4, mask_log_inv_rate: 1 },
        )
        .unwrap()
    }

    fn challenger(seed: [u8; 32]) -> C61SizingChallenger {
        SerializingChallenger64::new(HashChallenger::<u8, Blake3, 32>::new(
            seed.to_vec(),
            Blake3 {},
        ))
    }

    fn verify_claimless(
        commitment: &crate::c61_whir_reference::C61Commitment,
        proof: &p3_whir_c61::pcs::zk::ZkWhirProof<
            Goldilocks,
            BinomialExtensionField<Goldilocks, 2>,
            crate::c61_whir_reference::C61Mmcs,
        >,
        point: &Point<C61P3Fp2>,
        verifier_seed: [u8; 32],
    ) -> bool {
        let mut challenger = challenger(verifier_seed);
        let config = config::<C61SizingChallenger>();
        let mmcs = c61_reference_mmcs();
        challenger.observe(commitment.clone());
        challenger.observe_algebra_slice(point.as_slice());
        let verifier = HidingWhirVerifier::new(&config, &mmcs);
        catch_unwind(AssertUnwindSafe(|| {
            verifier.verify_claimless(
                proof,
                commitment,
                std::slice::from_ref(point),
                &mut challenger,
            )
        }))
        .is_ok_and(|result| result.is_ok())
    }

    fn replay_projected_claimless(
        mmcs: &C63ProjectedMmcs,
        link: Option<&C63EncodedSketchAtoYLink>,
        commitment: &crate::c61_whir_reference::C61Commitment,
        proof: &p3_whir_c61::pcs::zk::ZkWhirProof<
            Goldilocks,
            BinomialExtensionField<Goldilocks, 2>,
            C63ProjectedMmcs,
        >,
        point: &Point<C61P3Fp2>,
        verifier_seed: [u8; 32],
    ) -> Option<p3_whir_c61::pcs::zk::ClaimlessWhirVerifierClosure<C61P3Fp2>> {
        let mut challenger = challenger(verifier_seed);
        let config = config::<C61SizingChallenger>();
        let (_, contexts) = C63EncodedSketchAtoYContext::sample_pair_after_roots(
            mmcs.context.accepted_d.clone(),
            mmcs.context.accepted_a.clone(),
            mmcs.context.dimensions.height,
            &mut challenger,
        )
        .ok()?;
        if &contexts[mmcs.context.limb] != mmcs.context.as_ref() {
            return None;
        }
        challenger.observe(commitment.clone());
        challenger.observe_algebra_slice(point.as_slice());
        let verifier = HidingWhirVerifier::new(&config, mmcs);
        catch_unwind(AssertUnwindSafe(|| match link {
            Some(link) => verifier.verify_claimless_with_initial_link(
                proof,
                commitment,
                std::slice::from_ref(point),
                link,
                &mut challenger,
            ),
            None => verifier.verify_claimless(
                proof,
                commitment,
                std::slice::from_ref(point),
                &mut challenger,
            ),
        }))
        .ok()?
        .ok()
    }

    /// Malicious-prover fixture: it uses the honest cached fixed base in the
    /// extra equation while still sending authenticated rows from a different
    /// accepted `A`. This preserves the linked proof shape and challenge
    /// schedule, so rejection cannot come from switching no-link/link modes.
    struct ForgedFixedBaseLink<'a> {
        fixed_base: &'a DenseMatrix<Goldilocks>,
    }

    impl ZkWhirInitialOracleLink<Goldilocks, C61P3Fp2, C63ProjectedMmcs> for ForgedFixedBaseLink<'_> {
        fn required(&self) -> bool {
            true
        }

        fn folded_mask_values(
            &self,
            opening: &QueryOpenings<Goldilocks, C61P3Fp2, C63ProjectedMultiProof>,
            indices: &[usize],
            randomness: &Point<C61P3Fp2>,
        ) -> Option<Vec<C61P3Fp2>> {
            let QueryOpenings::Base(opening) = opening else {
                return None;
            };
            if opening.proof.1.is_none()
                || opening.rows.len() != indices.len()
                || self.fixed_base.width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
            {
                return None;
            }
            opening
                .rows
                .iter()
                .zip(indices)
                .map(|(randomized, &index)| {
                    let start = index.checked_mul(self.fixed_base.width)?;
                    let fixed = self.fixed_base.values.get(start..start + self.fixed_base.width)?;
                    if randomized.len() != fixed.len() {
                        return None;
                    }
                    let difference: Vec<Goldilocks> =
                        randomized.iter().zip(fixed).map(|(&y, &a)| y - a).collect();
                    Some(Poly::new(difference).eval_base(randomness))
                })
                .collect()
        }
    }

    #[test]
    fn preencoded_tensor_matches_normal_encode_and_keeps_fresh_masks() {
        assert_eq!(C63_ENCODED_SKETCH_PHYSICAL_ROWS, 1 << 19);
        assert_eq!(C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH, 32);
        assert_eq!(C63_ENCODED_SKETCH_INDEPENDENT_A_QUERIES, 486);

        let dft = Radix2DFTSmallBatch::default();
        let mmcs = c61_reference_mmcs();
        let config = config::<C61SizingChallenger>();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);

        let columns = (0..C63_BOLT_COLUMNS)
            .map(|column| {
                Poly::new(
                    (0..1usize << TEST_NUM_VARIABLES)
                        .map(|row| {
                            Goldilocks::from_u64((row as u64 + 3) * (column as u64 * 2 + 5) + 11)
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let encoded_columns =
            columns.iter().map(|column| prover.c62_fixed_base_encoding(column)).collect::<Vec<_>>();
        let paired = c63_pack_encoded_sketch_rows_reference(&encoded_columns).unwrap();
        for row in 0..paired.values.len() / paired.width {
            for column in 0..C63_BOLT_COLUMNS {
                for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
                    assert_eq!(
                        paired.values[row * paired.width
                            + column * C63_ENCODED_SKETCH_FOLDED_POSITIONS
                            + folded_position],
                        encoded_columns[column].values
                            [row * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position],
                    );
                }
            }
        }

        let rho = std::array::from_fn(|column| {
            Fp2::new(Fp::new(column as u64 * 7 + 2), Fp::new(column as u64 * 11 + 3))
        });
        let mut projected_messages = Vec::new();
        let mut projected_encodings = Vec::new();
        for limb in 0..2 {
            let message = c63_project_decoded_sketch_limb_reference(&columns, &rho, limb).unwrap();
            let projected = c63_project_encoded_sketch_limb_reference(&paired, &rho, limb).unwrap();
            let ordinary = prover.c62_fixed_base_encoding(&message);
            c63_check_preencoded_link_reference(&projected, &ordinary).unwrap();
            projected_messages.push(message);
            projected_encodings.push(projected);
        }

        let (a_root, a_data) = mmcs.commit_matrix(paired.clone());
        let authenticated_row = 17usize;
        let (opened, frontier) = mmcs.open_multi_batch(&[authenticated_row], &a_data);
        let dimensions = [Dimensions {
            width: C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
            height: 1 << TEST_NUM_VARIABLES,
        }];
        mmcs.verify_multi_batch(&a_root, &dimensions, &[authenticated_row], &opened, &frontier)
            .unwrap();
        let mut changed_opening = opened;
        changed_opening[0][0][9] += Goldilocks::ONE;
        assert!(mmcs
            .verify_multi_batch(
                &a_root,
                &dimensions,
                &[authenticated_row],
                &changed_opening,
                &frontier,
            )
            .is_err());

        let mut changed_paired = paired.clone();
        changed_paired.values[authenticated_row * changed_paired.width + 9] += Goldilocks::ONE;
        let changed_projection =
            c63_project_encoded_sketch_limb_reference(&changed_paired, &rho, 0).unwrap();
        assert!(c63_check_preencoded_link_reference(&changed_projection, &projected_encodings[0],)
            .is_err());

        let point = Point::new(
            (0..TEST_NUM_VARIABLES)
                .map(|index| C61P3Fp2::from_u64(index as u64 * 13 + 5))
                .collect(),
        );
        let evaluation = projected_messages[0].eval_base(&point);
        let verifier_seed = [0xA3; 32];
        let mut roots_and_proofs = Vec::new();
        for rng_seed in [0xC6_3001, 0xC6_3002] {
            let mut challenger = challenger(verifier_seed);
            let mut rng = StdRng::seed_from_u64(rng_seed);
            let (commitment, data) = prover.commit_c62_cached_fixed_base(
                projected_messages[0].clone(),
                &projected_encodings[0],
                &mut challenger,
                &mut rng,
            );
            challenger.observe_algebra_slice(point.as_slice());
            let output = prover.prove_claimless(
                data,
                &[(point.clone(), evaluation)],
                C61P3Fp2::ZERO,
                &mut challenger,
                &mut rng,
            );
            roots_and_proofs.push((commitment, output.proof));
        }
        assert_ne!(roots_and_proofs[0].0, roots_and_proofs[1].0);
        for (commitment, proof) in &roots_and_proofs {
            assert!(verify_claimless(commitment, proof, &point, verifier_seed));
        }
    }

    #[test]
    fn encoded_sketch_a_to_y_link_rejects_substituted_fixed_base() {
        let dft = Radix2DFTSmallBatch::default();
        let base_mmcs = c61_reference_mmcs();
        let config = config::<C61SizingChallenger>();
        let base_prover = HidingWhirProver::new(&config, &dft, &base_mmcs);
        let columns = (0..C63_BOLT_COLUMNS)
            .map(|column| {
                Poly::new(
                    (0..1usize << TEST_NUM_VARIABLES)
                        .map(|row| {
                            Goldilocks::from_u64((row as u64 + 7) * (column as u64 * 3 + 2) + 19)
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let mut systematic_values =
            Vec::with_capacity((1 << TEST_NUM_VARIABLES) * C63_BOLT_COLUMNS);
        for row in 0..1 << TEST_NUM_VARIABLES {
            for column in &columns {
                systematic_values.push(column.as_slice()[row]);
            }
        }
        let (accepted_d_root, _) =
            base_mmcs.commit_matrix(DenseMatrix::new(systematic_values, C63_BOLT_COLUMNS));

        let encoded_columns = columns
            .iter()
            .map(|column| base_prover.c62_fixed_base_encoding(column))
            .collect::<Vec<_>>();
        let honest_a = c63_pack_encoded_sketch_rows_reference(&encoded_columns).unwrap();
        let (honest_a_root, honest_a_data) = base_mmcs.commit_matrix(honest_a.clone());
        let verifier_seed = [0x63; 32];
        let mut prover_challenger = challenger(verifier_seed);
        let (honest_rho, [honest_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                accepted_d_root.clone(),
                honest_a_root.clone(),
                honest_a.values.len() / honest_a.width,
                &mut prover_challenger,
            )
            .unwrap();
        let honest_message =
            c63_project_decoded_sketch_limb_reference(&columns, &honest_rho, 0).unwrap();
        let honest_fixed_base = base_prover.c62_fixed_base_encoding(&honest_message);
        let projected_mmcs = C63ProjectedMmcs::new(honest_context);
        let link = projected_mmcs.link();
        let projected_prover = HidingWhirProver::new(&config, &dft, &projected_mmcs);
        let point = Point::new(
            (0..TEST_NUM_VARIABLES)
                .map(|index| C61P3Fp2::from_u64(index as u64 * 17 + 4))
                .collect(),
        );
        let honest_evaluation = honest_message.eval_base(&point);

        // Honest opt-in execution: the opened row difference is the encoding
        // of exactly the fresh initial-oracle randomness.
        let mut rng = StdRng::seed_from_u64(0xA63_0001);
        let (honest_root, mut honest_data) = projected_prover.commit_c62_cached_fixed_base(
            honest_message,
            &honest_fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        projected_mmcs
            .attach_encoded_sketch_a(&mut honest_data.merkle, &honest_a_root, honest_a_data)
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());
        let honest = projected_prover.prove_claimless_with_initial_link(
            honest_data,
            &[(point.clone(), honest_evaluation)],
            C61P3Fp2::ZERO,
            &link,
            &mut prover_challenger,
            &mut rng,
        );
        let honest_closure = replay_projected_claimless(
            &projected_mmcs,
            Some(&link),
            &honest_root,
            &honest.proof,
            &point,
            verifier_seed,
        )
        .unwrap();
        assert_eq!(honest_closure.claim_weights, honest.claim_weights);
        assert_eq!(honest_closure.target, honest.target);
        assert_eq!(honest_closure.base_case, honest.base_case);

        // Attack fixture: the accepted A root encodes a different tensor,
        // while the cached fixed base remains C(u) for the accepted D root.
        let mut substituted_columns = columns.clone();
        substituted_columns[0].as_mut_slice()[0] += Goldilocks::ONE;
        substituted_columns[0].as_mut_slice()[1 << (TEST_NUM_VARIABLES - 1)] += Goldilocks::ONE;
        let substituted_encoded = substituted_columns
            .iter()
            .map(|column| base_prover.c62_fixed_base_encoding(column))
            .collect::<Vec<_>>();
        let substituted_a = c63_pack_encoded_sketch_rows_reference(&substituted_encoded).unwrap();
        let (substituted_a_root, substituted_a_data) =
            base_mmcs.commit_matrix(substituted_a.clone());
        let mut prover_challenger = challenger(verifier_seed);
        let (attack_rho, [attack_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                accepted_d_root,
                substituted_a_root.clone(),
                substituted_a.values.len() / substituted_a.width,
                &mut prover_challenger,
            )
            .unwrap();
        let attack_message =
            c63_project_decoded_sketch_limb_reference(&columns, &attack_rho, 0).unwrap();
        let fixed_base = base_prover.c62_fixed_base_encoding(&attack_message);
        let substituted_projection =
            c63_project_encoded_sketch_limb_reference(&substituted_a, &attack_rho, 0).unwrap();
        assert!(substituted_projection
            .values
            .iter()
            .zip(&fixed_base.values)
            .all(|(substituted, honest)| substituted != honest));
        let attack_mmcs = C63ProjectedMmcs::new(attack_context);
        let attack_link = attack_mmcs.link();
        let attack_prover = HidingWhirProver::new(&config, &dft, &attack_mmcs);
        let attack_evaluation = attack_message.eval_base(&point);

        let mut rng = StdRng::seed_from_u64(0xA63_0002);
        let (attack_root, mut attack_data) = attack_prover.commit_c62_cached_fixed_base(
            attack_message.clone(),
            &fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        attack_mmcs
            .attach_encoded_sketch_a(
                &mut attack_data.merkle,
                &substituted_a_root,
                substituted_a_data,
            )
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());
        let attack = attack_prover.prove_claimless(
            attack_data,
            &[(point.clone(), attack_evaluation)],
            C61P3Fp2::ZERO,
            &mut prover_challenger,
            &mut rng,
        );

        // The historical/plain seam authenticates both supplied roots but has
        // no equation between them, so the substituted base is accepted.
        let plain_closure = replay_projected_claimless(
            &attack_mmcs,
            None,
            &attack_root,
            &attack.proof,
            &point,
            verifier_seed,
        )
        .unwrap();
        assert_eq!(plain_closure.claim_weights, attack.claim_weights);
        assert_eq!(plain_closure.target, attack.target);
        assert_eq!(plain_closure.base_case, attack.base_case);

        // Build a malicious proof with the linked coefficient count and exact
        // challenge schedule. Its prover-side link pretends the accepted A row
        // was the honest fixed base; the proof still carries and authenticates
        // the substituted A rows.
        let (linked_a_root, linked_a_data) = base_mmcs.commit_matrix(substituted_a);
        assert_eq!(linked_a_root, substituted_a_root);
        let mut prover_challenger = challenger(verifier_seed);
        let (replayed_rho, [replayed_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                attack_mmcs.context.accepted_d.clone(),
                linked_a_root.clone(),
                attack_mmcs.context.dimensions.height,
                &mut prover_challenger,
            )
            .unwrap();
        assert_eq!(replayed_rho, attack_rho);
        assert!(replayed_context == *attack_mmcs.context);
        let mut rng = StdRng::seed_from_u64(0xA63_0003);
        let (linked_root, mut linked_data) = attack_prover.commit_c62_cached_fixed_base(
            attack_message,
            &fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        attack_mmcs
            .attach_encoded_sketch_a(&mut linked_data.merkle, &linked_a_root, linked_a_data)
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());

        let pcg_seed = [0xA6; 32];
        let delta = Fp2::new(Fp::new(101), Fp::new(103));
        let target_tag = Fp2::new(Fp::new(107), Fp::new(109));
        let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
        let mask_range = C61AuthenticatedWhirMaskRange { stage: 63, slot: 0, range_start: 0 };
        let mut correlations = CorrelationStream::new(pcg_seed);
        let prepared =
            prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations).unwrap();
        let forged_link = ForgedFixedBaseLink { fixed_base: &fixed_base };
        let linked_attack = attack_prover.prove_claimless_with_initial_link(
            linked_data,
            &[(point.clone(), attack_evaluation)],
            c61_p3_fp2_from_volta(prepared.value()),
            &forged_link,
            &mut prover_challenger,
            &mut rng,
        );

        // The linked WHIR proof remains structurally valid, but the verifier
        // projects the authenticated substituted A rows. The existing
        // designated ZeroOpen must therefore reject the forged terminal tag.
        let linked_closure = replay_projected_claimless(
            &attack_mmcs,
            Some(&attack_link),
            &linked_root,
            &linked_attack.proof,
            &point,
            verifier_seed,
        )
        .expect("forged linked shape should reach the designated closure");
        let target_value = c61_volta_fp2_from_p3(attack_evaluation);
        let target = ProverAuthed::new(target_value, target_tag);
        let aggregate_target = target.scale(c61_volta_fp2_from_p3(linked_attack.claim_weights[0]));
        let provider_affine = C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(linked_attack.target.coefficient),
            constant: c61_volta_fp2_from_p3(linked_attack.target.constant),
        };
        let mut prover_terminal_transcript = Transcript::new_fiat_shamir([0xB6; 32]).unwrap();
        let provider_closure = finish_c61_authenticated_whir_base(
            prepared,
            C61AuthenticatedWhirProverFinishInput {
                combined: c61_volta_fp2_from_p3(linked_attack.base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(
                    linked_attack.base_case.shifted_masked_claim,
                ),
                gamma: c61_volta_fp2_from_p3(linked_attack.base_case.gamma),
                target: provider_affine.authenticate_prover(aggregate_target),
            },
            &mut prover_terminal_transcript,
        )
        .unwrap();

        let target_key = VerifierKey::new(target_tag + delta * target_value);
        let aggregate_key =
            target_key.scale(c61_volta_fp2_from_p3(linked_closure.claim_weights[0]));
        let verifier_affine = C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(linked_closure.target.coefficient),
            constant: c61_volta_fp2_from_p3(linked_closure.target.constant),
        };
        let mut verifier_context = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_terminal_transcript = Transcript::new_fiat_shamir([0xB6; 32]).unwrap();
        let terminal_error = verify_c61_authenticated_whir_base(
            C61AuthenticatedWhirVerifierInput {
                id,
                mask_range,
                combined: c61_volta_fp2_from_p3(linked_closure.base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(
                    linked_closure.base_case.shifted_masked_claim,
                ),
                gamma: c61_volta_fp2_from_p3(linked_closure.base_case.gamma),
                target: verifier_affine.derive_verifier_key(aggregate_key, delta),
            },
            provider_closure.proof,
            &mut verifier_context,
            &mut verifier_terminal_transcript,
        )
        .unwrap_err();
        assert_eq!(terminal_error.to_string(), "C6AWH1 authenticated target ZeroOpen failed");
    }
}

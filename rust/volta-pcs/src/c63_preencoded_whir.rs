//! CPU reference for C6.3's pre-encoded initial WHIR oracle.
//!
//! This freezes only the deterministic `A * rho` layout and checks it against
//! the existing C6.2 cached-base seam. It is not a production adapter, a
//! privacy proof, or evidence for paired queries.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_multilinear_util::poly::Poly;
use volta_field::Fp2;

use crate::c63_authenticated_sketch::C63_BOLT_COLUMNS;

pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2: usize = 19;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROWS: usize = 1 << C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2;
pub const C63_ENCODED_SKETCH_FOLDED_POSITIONS: usize = 2;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH: usize =
    C63_BOLT_COLUMNS * C63_ENCODED_SKETCH_FOLDED_POSITIONS;
pub const C63_ENCODED_SKETCH_INDEPENDENT_A_QUERIES: usize = 486;

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

    use super::*;
    use crate::c61_whir_reference::{c61_reference_mmcs, C61P3Fp2, C61SizingChallenger};

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
}

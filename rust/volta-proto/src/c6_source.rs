//! C6 paired source-witness replay.
//!
//! Coordinate zero is extracted while the unchanged T1 prover runs.  This
//! module reconstructs coordinate one from the exact public correlation
//! schedule and the direct-source plaintexts already present in coordinate
//! zero.  Model inference and the historical proof are not rerun.
//!
//! ProductClosure masks are deliberately different: they are uncorrected
//! secret sources, not two authentications of a shared direct plaintext.
//! This module is a prover-only witness-construction seam, not yet the
//! committed residual DAG or the final succinct wrapper.

use std::fmt;
use volta_mac::{
    C6FullfieldWitnessAudit, C6SubfieldWitnessAudit, CorrScheduleAudit, CorrScheduleKind,
    CorrScheduleRole, CorrelationStream,
};

pub type C6SourceDigest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SourceError(String);

impl C6SourceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6SourceError {}

/// All source leaves extracted from one independently backed MAC tape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SourceCoordinate {
    subfield: C6SubfieldWitnessAudit,
    fullfield: C6FullfieldWitnessAudit,
}

impl C6SourceCoordinate {
    pub fn new(
        subfield: C6SubfieldWitnessAudit,
        fullfield: C6FullfieldWitnessAudit,
        schedule: &CorrScheduleAudit,
    ) -> Result<Self, C6SourceError> {
        subfield.validate_against(schedule).map_err(C6SourceError::new)?;
        fullfield.validate_against(schedule).map_err(C6SourceError::new)?;
        Ok(Self { subfield, fullfield })
    }

    pub fn subfield(&self) -> &C6SubfieldWitnessAudit {
        &self.subfield
    }

    pub fn fullfield(&self) -> &C6FullfieldWitnessAudit {
        &self.fullfield
    }
}

/// Two independent source witnesses for the same direct T1 plaintexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedSourceWitness {
    tape_ids: [C6SourceDigest; 2],
    coordinates: [C6SourceCoordinate; 2],
    schedule_digest: C6SourceDigest,
    direct_fullfield_plaintext_digest: C6SourceDigest,
    pair_digest: C6SourceDigest,
}

impl C6PairedSourceWitness {
    pub fn new(
        tape_ids: [C6SourceDigest; 2],
        coordinates: [C6SourceCoordinate; 2],
        schedule: &CorrScheduleAudit,
    ) -> Result<Self, C6SourceError> {
        if tape_ids[0] == [0; 32] || tape_ids[1] == [0; 32] || tape_ids[0] == tape_ids[1] {
            return Err(C6SourceError::new(
                "C6 paired source witness requires two distinct nonzero tape identities",
            ));
        }
        for coordinate in &coordinates {
            coordinate.subfield.validate_against(schedule).map_err(C6SourceError::new)?;
            coordinate.fullfield.validate_against(schedule).map_err(C6SourceError::new)?;
        }
        if coordinates[0].subfield.is_empty() || coordinates[0].fullfield.is_empty() {
            return Err(C6SourceError::new("C6 paired source witness cannot be empty"));
        }
        if coordinates[0].subfield.len() != coordinates[1].subfield.len()
            || coordinates[0].fullfield.len() != coordinates[1].fullfield.len()
        {
            return Err(C6SourceError::new(
                "C6 paired source coordinates have different leaf counts",
            ));
        }
        if coordinates[0].subfield.witness_digest == coordinates[1].subfield.witness_digest
            || coordinates[0].fullfield.witness_digest == coordinates[1].fullfield.witness_digest
        {
            return Err(C6SourceError::new("C6 paired source coordinates reuse a secret witness"));
        }
        for index in 0..coordinates[0].subfield.len() {
            if coordinates[0].subfield.plaintext(index) != coordinates[1].subfield.plaintext(index)
            {
                return Err(C6SourceError::new(format!(
                    "C6 paired subfield plaintext differs at leaf {index}"
                )));
            }
        }
        if coordinates[0].subfield.plaintext_digest != coordinates[1].subfield.plaintext_digest {
            return Err(C6SourceError::new("C6 paired subfield plaintext digests differ"));
        }

        for draw in coordinates[0].fullfield.draws() {
            if draw.role != CorrScheduleRole::DirectCorrection {
                continue;
            }
            let first = usize::try_from(draw.witness_offset)
                .map_err(|_| C6SourceError::new("C6 full-field offset exceeds usize"))?;
            let count = usize::try_from(draw.count)
                .map_err(|_| C6SourceError::new("C6 full-field count exceeds usize"))?;
            let end = first
                .checked_add(count)
                .ok_or_else(|| C6SourceError::new("C6 full-field range overflows"))?;
            for index in first..end {
                if coordinates[0].fullfield.plaintext(index)
                    != coordinates[1].fullfield.plaintext(index)
                {
                    return Err(C6SourceError::new(format!(
                        "C6 paired direct full-field plaintext differs at leaf {index}"
                    )));
                }
            }
        }
        let direct_digests = [
            direct_fullfield_plaintext_digest(&coordinates[0].fullfield)?,
            direct_fullfield_plaintext_digest(&coordinates[1].fullfield)?,
        ];
        if direct_digests[0] != direct_digests[1] {
            return Err(C6SourceError::new("C6 paired direct full-field plaintext digests differ"));
        }

        let mut hasher = blake3::Hasher::new_derive_key("volta/proto/c6/paired-source-witness/v1");
        hasher.update(&schedule.digest);
        hasher.update(&direct_digests[0]);
        for coordinate in 0..2 {
            hasher.update(&tape_ids[coordinate]);
            hasher.update(&coordinates[coordinate].subfield.witness_digest);
            hasher.update(&coordinates[coordinate].subfield.correction_digest);
            hasher.update(&coordinates[coordinate].subfield.plaintext_digest);
            hasher.update(&coordinates[coordinate].fullfield.witness_digest);
            hasher.update(&coordinates[coordinate].fullfield.correction_digest);
            hasher.update(&coordinates[coordinate].fullfield.plaintext_digest);
        }
        let pair_digest = *hasher.finalize().as_bytes();
        Ok(Self {
            tape_ids,
            coordinates,
            schedule_digest: schedule.digest,
            direct_fullfield_plaintext_digest: direct_digests[0],
            pair_digest,
        })
    }

    pub fn tape_ids(&self) -> [C6SourceDigest; 2] {
        self.tape_ids
    }

    pub fn coordinates(&self) -> &[C6SourceCoordinate; 2] {
        &self.coordinates
    }

    pub fn subfield_leaf_count(&self) -> usize {
        self.coordinates[0].subfield.len()
    }

    pub fn fullfield_leaf_count(&self) -> usize {
        self.coordinates[0].fullfield.len()
    }

    pub fn direct_fullfield_leaf_count(&self) -> usize {
        self.coordinates[0]
            .fullfield
            .draws()
            .iter()
            .filter(|draw| draw.role == CorrScheduleRole::DirectCorrection)
            .map(|draw| draw.count as usize)
            .sum()
    }

    pub fn product_mask_leaf_count(&self) -> usize {
        self.coordinates[0]
            .fullfield
            .draws()
            .iter()
            .filter(|draw| draw.role == CorrScheduleRole::ProductMask)
            .map(|draw| draw.count as usize)
            .sum()
    }

    pub fn schedule_digest(&self) -> C6SourceDigest {
        self.schedule_digest
    }

    pub fn direct_fullfield_plaintext_digest(&self) -> C6SourceDigest {
        self.direct_fullfield_plaintext_digest
    }

    pub fn pair_digest(&self) -> C6SourceDigest {
        self.pair_digest
    }
}

fn direct_fullfield_plaintext_digest(
    witness: &C6FullfieldWitnessAudit,
) -> Result<C6SourceDigest, C6SourceError> {
    let mut hasher = blake3::Hasher::new_derive_key("volta/proto/c6/direct-fullfield-plaintext/v1");
    for draw in witness.draws() {
        if draw.role != CorrScheduleRole::DirectCorrection {
            continue;
        }
        hasher.update(&draw.domain.to_le_bytes());
        hasher.update(&draw.global_offset.to_le_bytes());
        hasher.update(&draw.count.to_le_bytes());
        hasher.update(&draw.witness_offset.to_le_bytes());
        let first = usize::try_from(draw.witness_offset)
            .map_err(|_| C6SourceError::new("C6 direct full-field offset exceeds usize"))?;
        let count = usize::try_from(draw.count)
            .map_err(|_| C6SourceError::new("C6 direct full-field count exceeds usize"))?;
        let end = first
            .checked_add(count)
            .ok_or_else(|| C6SourceError::new("C6 direct full-field range overflows"))?;
        for index in first..end {
            let value = witness
                .plaintext(index)
                .ok_or_else(|| C6SourceError::new("C6 direct full-field plaintext is missing"))?;
            hasher.update(&value.c0.value().to_le_bytes());
            hasher.update(&value.c1.value().to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Replay a fresh independent source coordinate without rerunning the model.
pub fn replay_c6_source_coordinate(
    primary: &C6SourceCoordinate,
    schedule: &CorrScheduleAudit,
    secondary: &mut CorrelationStream,
) -> Result<C6SourceCoordinate, C6SourceError> {
    primary.subfield.validate_against(schedule).map_err(C6SourceError::new)?;
    primary.fullfield.validate_against(schedule).map_err(C6SourceError::new)?;
    secondary.enable_c6_source_witness_collection().map_err(C6SourceError::new)?;

    for draw in &schedule.draws {
        let count = usize::try_from(draw.count)
            .map_err(|_| C6SourceError::new("C6 source replay draw count exceeds usize"))?;
        let first = usize::try_from(draw.global_offset)
            .map_err(|_| C6SourceError::new("C6 source replay offset exceeds usize"))?;
        let end = first
            .checked_add(count)
            .ok_or_else(|| C6SourceError::new("C6 source replay range overflows"))?;
        match (draw.kind, draw.role) {
            (CorrScheduleKind::Subfield, CorrScheduleRole::DirectCorrection) => {
                if end > primary.subfield.len() {
                    return Err(C6SourceError::new(
                        "C6 source replay subfield range exceeds the primary witness",
                    ));
                }
                let correlations = secondary.draw_subs(draw.domain, count);
                let corrections = correlations
                    .iter()
                    .enumerate()
                    .map(|(offset, correlation)| {
                        primary
                            .subfield
                            .plaintext(first + offset)
                            .expect("validated C6 primary subfield range")
                            .sub(correlation.r)
                            .value()
                    })
                    .collect::<Vec<_>>();
                secondary
                    .record_c6_subfield_corrections(draw.domain, &corrections)
                    .map_err(C6SourceError::new)?;
            }
            (CorrScheduleKind::FullField, CorrScheduleRole::DirectCorrection) => {
                if end > primary.fullfield.len() {
                    return Err(C6SourceError::new(
                        "C6 source replay full-field range exceeds the primary witness",
                    ));
                }
                let _ = secondary.draw_fulls(draw.domain, count);
                secondary
                    .record_c6_fullfield_plaintexts_iter(
                        draw.domain,
                        (first..end).map(|index| {
                            primary
                                .fullfield
                                .plaintext(index)
                                .expect("validated C6 primary full-field range")
                        }),
                    )
                    .map_err(C6SourceError::new)?;
            }
            (CorrScheduleKind::FullField, CorrScheduleRole::ProductMask) => {
                if count != 1 {
                    return Err(C6SourceError::new(
                        "C6 source replay ProductClosure mask count is not one",
                    ));
                }
                let triples = usize::try_from(draw.product_triples).map_err(|_| {
                    C6SourceError::new("C6 source replay triple count exceeds usize")
                })?;
                let _ = secondary.draw_product_mask(draw.domain, triples);
            }
            (CorrScheduleKind::Subfield, CorrScheduleRole::ProductMask) => {
                return Err(C6SourceError::new(
                    "C6 source replay encountered a subfield ProductClosure mask",
                ));
            }
        }
    }

    let replayed_schedule = secondary
        .schedule_audit()
        .ok_or_else(|| C6SourceError::new("C6 source replay lacks its schedule audit"))?;
    if replayed_schedule != *schedule {
        return Err(C6SourceError::new(
            "C6 source replay allocation schedule differs from coordinate zero",
        ));
    }
    let subfield = secondary.finish_c6_subfield_witness_collection().map_err(C6SourceError::new)?;
    let fullfield =
        secondary.finish_c6_fullfield_witness_collection().map_err(C6SourceError::new)?;
    C6SourceCoordinate::new(subfield, fullfield, schedule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, Fp2};

    fn coordinate(
        seed: u8,
        sub_plaintexts: &[u64],
        full_plaintexts: &[Fp2],
    ) -> (CorrScheduleAudit, C6SourceCoordinate) {
        let mut stream = CorrelationStream::new([seed; 32]);
        stream.enable_c6_source_witness_collection().unwrap();

        let subs = stream.draw_subs(10, sub_plaintexts.len());
        let sub_corrections = subs
            .iter()
            .zip(sub_plaintexts)
            .map(|(source, &value)| (Fp::new(value) - source.r).value())
            .collect::<Vec<_>>();
        stream.record_c6_subfield_corrections(10, &sub_corrections).unwrap();
        let _ = stream.draw_fulls(11, full_plaintexts.len());
        stream.record_c6_fullfield_plaintexts(11, full_plaintexts).unwrap();
        let _ = stream.draw_product_mask(12, 7);

        let schedule = stream.schedule_audit().unwrap();
        let subfield = stream.finish_c6_subfield_witness_collection().unwrap();
        let fullfield = stream.finish_c6_fullfield_witness_collection().unwrap();
        let coordinate = C6SourceCoordinate::new(subfield, fullfield, &schedule).unwrap();
        (schedule, coordinate)
    }

    #[test]
    fn paired_source_replay_preserves_direct_plaintexts_and_refreshes_product_mask() {
        let full_plaintexts = [Fp2::new(Fp::new(5), Fp::new(6)), Fp2::new(Fp::new(7), Fp::new(8))];
        let (schedule, primary) = coordinate(0x81, &[1, 2, 3], &full_plaintexts);
        let mut secondary_stream = CorrelationStream::new([0x82; 32]);
        let secondary =
            replay_c6_source_coordinate(&primary, &schedule, &mut secondary_stream).unwrap();
        let pair =
            C6PairedSourceWitness::new([[0x91; 32], [0x92; 32]], [primary, secondary], &schedule)
                .unwrap();

        assert_eq!(pair.subfield_leaf_count(), 3);
        assert_eq!(pair.direct_fullfield_leaf_count(), 2);
        assert_eq!(pair.product_mask_leaf_count(), 1);
        assert_eq!(pair.schedule_digest(), schedule.digest);
        for index in 0..3 {
            assert_eq!(
                pair.coordinates()[0].subfield().plaintext(index),
                pair.coordinates()[1].subfield().plaintext(index)
            );
        }
        for index in 0..2 {
            assert_eq!(
                pair.coordinates()[0].fullfield().plaintext(index),
                pair.coordinates()[1].fullfield().plaintext(index)
            );
        }
        assert_ne!(
            pair.coordinates()[0].fullfield().plaintext(2),
            pair.coordinates()[1].fullfield().plaintext(2)
        );
        assert_ne!(pair.pair_digest(), [0; 32]);
    }

    #[test]
    fn paired_source_rejects_tape_reuse_and_changed_direct_plaintext() {
        let first_values = [Fp2::new(Fp::new(5), Fp::new(6))];
        let changed_values = [Fp2::new(Fp::new(5), Fp::new(7))];
        let (schedule, first) = coordinate(0xA1, &[1], &first_values);
        let (_, changed) = coordinate(0xA2, &[1], &changed_values);
        assert!(C6PairedSourceWitness::new(
            [[0xB1; 32], [0xB2; 32]],
            [first.clone(), changed],
            &schedule,
        )
        .is_err());

        let mut secondary_stream = CorrelationStream::new([0xA3; 32]);
        let second = replay_c6_source_coordinate(&first, &schedule, &mut secondary_stream).unwrap();
        assert!(C6PairedSourceWitness::new([[0xB1; 32], [0xB1; 32]], [first, second], &schedule,)
            .is_err());
    }
}

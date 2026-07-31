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
    CorrScheduleRole, CorrelationStream, VerifierCtx,
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

/// Incremental provider-side mirror of the response-global T1 allocation
/// schedule on the independent C6 MAC tape.
///
/// The primary proof is the schedule oracle: only its already-consumed,
/// canonical public prefix may be mirrored.  This lets an inline cache fold
/// replay secondary K/V masks before the response has reached its final
/// ProductClosure, without predicting a length-dependent schedule or
/// advancing the secondary tape in K/V-only order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct C6SourceScheduleProverFollower {
    next_draw: usize,
    poisoned: bool,
}

impl C6SourceScheduleProverFollower {
    pub fn start(secondary: &mut CorrelationStream) -> Result<Self, C6SourceError> {
        secondary.enable_c6_source_witness_collection().map_err(C6SourceError::new)?;
        Ok(Self::default())
    }

    pub fn next_draw(&self) -> usize {
        self.next_draw
    }

    pub fn sync_primary(
        &mut self,
        primary: &CorrelationStream,
        secondary: &mut CorrelationStream,
    ) -> Result<(), C6SourceError> {
        let schedule = primary.schedule_audit().ok_or_else(|| {
            C6SourceError::new("C6 primary provider stream lacks its schedule audit")
        })?;
        self.sync_audit(&schedule, secondary)
    }

    pub fn sync_audit(
        &mut self,
        schedule: &CorrScheduleAudit,
        secondary: &mut CorrelationStream,
    ) -> Result<(), C6SourceError> {
        if self.poisoned {
            return Err(C6SourceError::new("C6 provider schedule follower is poisoned"));
        }
        if let Err(error) =
            validate_follower_prefix(self.next_draw, schedule, secondary.schedule_audit())
        {
            self.poisoned = true;
            return Err(error);
        }
        for draw in &schedule.draws[self.next_draw..] {
            let count = usize::try_from(draw.count).map_err(|_| {
                self.poisoned = true;
                C6SourceError::new("C6 provider follower draw count exceeds usize")
            })?;
            match (draw.kind, draw.role) {
                (CorrScheduleKind::Subfield, CorrScheduleRole::DirectCorrection) => {
                    let _ = secondary.draw_sub_masks(draw.domain, count);
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::DirectCorrection) => {
                    let _ = secondary.draw_fulls(draw.domain, count);
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::ProductMask) => {
                    if count != 1 {
                        self.poisoned = true;
                        return Err(C6SourceError::new(
                            "C6 provider follower ProductClosure mask count is not one",
                        ));
                    }
                    let triples = usize::try_from(draw.product_triples).map_err(|_| {
                        self.poisoned = true;
                        C6SourceError::new("C6 provider follower triple count exceeds usize")
                    })?;
                    let _ = secondary.draw_product_mask(draw.domain, triples);
                }
                (CorrScheduleKind::Subfield, CorrScheduleRole::ProductMask) => {
                    self.poisoned = true;
                    return Err(C6SourceError::new(
                        "C6 provider follower encountered a subfield ProductClosure mask",
                    ));
                }
            }
        }
        let mirrored = secondary.schedule_audit().ok_or_else(|| {
            self.poisoned = true;
            C6SourceError::new("C6 secondary provider stream lacks its schedule audit")
        })?;
        if mirrored != *schedule {
            self.poisoned = true;
            return Err(C6SourceError::new(
                "C6 secondary provider allocation schedule differs from the primary prefix",
            ));
        }
        self.next_draw = schedule.draws.len();
        Ok(())
    }

    /// Attach the direct plaintexts after the primary witness closes, then
    /// close the already-consumed independent coordinate.  Product masks stay
    /// uncorrected by construction.
    pub fn finish_coordinate(
        mut self,
        primary: &C6SourceCoordinate,
        schedule: &CorrScheduleAudit,
        secondary: &mut CorrelationStream,
    ) -> Result<C6SourceCoordinate, C6SourceError> {
        self.sync_audit(schedule, secondary)?;
        primary.subfield.validate_against(schedule).map_err(C6SourceError::new)?;
        primary.fullfield.validate_against(schedule).map_err(C6SourceError::new)?;

        for draw in &schedule.draws {
            let count = usize::try_from(draw.count)
                .map_err(|_| C6SourceError::new("C6 follower final draw count exceeds usize"))?;
            let first = usize::try_from(draw.global_offset)
                .map_err(|_| C6SourceError::new("C6 follower final offset exceeds usize"))?;
            let end = first
                .checked_add(count)
                .ok_or_else(|| C6SourceError::new("C6 follower final range overflows"))?;
            match (draw.kind, draw.role) {
                (CorrScheduleKind::Subfield, CorrScheduleRole::DirectCorrection) => {
                    let masks = secondary.replay_consumed_sub_masks(draw.domain, count);
                    let corrections = masks
                        .into_iter()
                        .enumerate()
                        .map(|(offset, mask)| {
                            primary
                                .subfield
                                .plaintext(first + offset)
                                .expect("validated primary C6 subfield range")
                                .sub(mask)
                                .value()
                        })
                        .collect::<Vec<_>>();
                    secondary
                        .record_c6_subfield_corrections(draw.domain, &corrections)
                        .map_err(C6SourceError::new)?;
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::DirectCorrection) => {
                    secondary
                        .record_c6_fullfield_plaintexts_iter(
                            draw.domain,
                            (first..end).map(|index| {
                                primary
                                    .fullfield
                                    .plaintext(index)
                                    .expect("validated primary C6 full-field range")
                            }),
                        )
                        .map_err(C6SourceError::new)?;
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::ProductMask) => {}
                (CorrScheduleKind::Subfield, CorrScheduleRole::ProductMask) => {
                    return Err(C6SourceError::new(
                        "C6 follower finalization encountered a subfield ProductClosure mask",
                    ));
                }
            }
        }

        let subfield =
            secondary.finish_c6_subfield_witness_collection().map_err(C6SourceError::new)?;
        let fullfield =
            secondary.finish_c6_fullfield_witness_collection().map_err(C6SourceError::new)?;
        C6SourceCoordinate::new(subfield, fullfield, schedule)
    }
}

/// Verifier mirror of [`C6SourceScheduleProverFollower`].  It consumes the
/// same accepted primary schedule prefix and leaves all reserved base keys
/// available for counter-neutral source replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct C6SourceScheduleVerifierFollower {
    next_draw: usize,
    poisoned: bool,
}

impl C6SourceScheduleVerifierFollower {
    pub fn start(secondary: &mut VerifierCtx) -> Result<Self, C6SourceError> {
        secondary.enable_schedule_audit().map_err(C6SourceError::new)?;
        Ok(Self::default())
    }

    pub fn next_draw(&self) -> usize {
        self.next_draw
    }

    pub fn sync_primary(
        &mut self,
        primary: &VerifierCtx,
        secondary: &mut VerifierCtx,
    ) -> Result<(), C6SourceError> {
        let schedule = primary.schedule_audit().ok_or_else(|| {
            C6SourceError::new("C6 primary verifier stream lacks its schedule audit")
        })?;
        self.sync_audit(&schedule, secondary)
    }

    pub fn sync_audit(
        &mut self,
        schedule: &CorrScheduleAudit,
        secondary: &mut VerifierCtx,
    ) -> Result<(), C6SourceError> {
        if self.poisoned {
            return Err(C6SourceError::new("C6 verifier schedule follower is poisoned"));
        }
        if let Err(error) =
            validate_follower_prefix(self.next_draw, schedule, secondary.schedule_audit())
        {
            self.poisoned = true;
            return Err(error);
        }
        for draw in &schedule.draws[self.next_draw..] {
            let count = usize::try_from(draw.count).map_err(|_| {
                self.poisoned = true;
                C6SourceError::new("C6 verifier follower draw count exceeds usize")
            })?;
            match (draw.kind, draw.role) {
                (CorrScheduleKind::Subfield, CorrScheduleRole::DirectCorrection) => {
                    secondary.reserve_sub_key_rows(draw.domain, 1, count);
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::DirectCorrection) => {
                    let _ = secondary.expand_full_keys(draw.domain, count);
                }
                (CorrScheduleKind::FullField, CorrScheduleRole::ProductMask) => {
                    if count != 1 {
                        self.poisoned = true;
                        return Err(C6SourceError::new(
                            "C6 verifier follower ProductClosure mask count is not one",
                        ));
                    }
                    let triples = usize::try_from(draw.product_triples).map_err(|_| {
                        self.poisoned = true;
                        C6SourceError::new("C6 verifier follower triple count exceeds usize")
                    })?;
                    let _ = secondary.expand_product_mask_key(draw.domain, triples);
                }
                (CorrScheduleKind::Subfield, CorrScheduleRole::ProductMask) => {
                    self.poisoned = true;
                    return Err(C6SourceError::new(
                        "C6 verifier follower encountered a subfield ProductClosure mask",
                    ));
                }
            }
        }
        let mirrored = secondary.schedule_audit().ok_or_else(|| {
            self.poisoned = true;
            C6SourceError::new("C6 secondary verifier stream lacks its schedule audit")
        })?;
        if mirrored != *schedule {
            self.poisoned = true;
            return Err(C6SourceError::new(
                "C6 secondary verifier allocation schedule differs from the primary prefix",
            ));
        }
        self.next_draw = schedule.draws.len();
        Ok(())
    }
}

fn validate_follower_prefix(
    next_draw: usize,
    schedule: &CorrScheduleAudit,
    mirrored: Option<CorrScheduleAudit>,
) -> Result<(), C6SourceError> {
    if !schedule.is_canonical() || schedule.draws.len() < next_draw {
        return Err(C6SourceError::new(
            "C6 schedule follower received a noncanonical or rolled-back primary prefix",
        ));
    }
    let mirrored =
        mirrored.ok_or_else(|| C6SourceError::new("C6 schedule follower was not initialized"))?;
    if !mirrored.is_canonical()
        || mirrored.draws.len() != next_draw
        || mirrored.draws != schedule.draws[..next_draw]
    {
        return Err(C6SourceError::new(
            "C6 schedule follower prefix differs from the primary allocation history",
        ));
    }
    Ok(())
}

/// Two independent source witnesses for the same direct T1 plaintexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6PairedSourceWitness {
    tape_ids: [C6SourceDigest; 2],
    coordinates: [C6SourceCoordinate; 2],
    schedule_digest: C6SourceDigest,
    source_schedule_digest: C6SourceDigest,
    direct_fullfield_plaintext_digest: C6SourceDigest,
    pair_digest: C6SourceDigest,
}

impl C6PairedSourceWitness {
    pub fn new(
        tape_ids: [C6SourceDigest; 2],
        coordinates: [C6SourceCoordinate; 2],
        schedule: &CorrScheduleAudit,
        source_schedule_digest: C6SourceDigest,
    ) -> Result<Self, C6SourceError> {
        if tape_ids[0] == [0; 32] || tape_ids[1] == [0; 32] || tape_ids[0] == tape_ids[1] {
            return Err(C6SourceError::new(
                "C6 paired source witness requires two distinct nonzero tape identities",
            ));
        }
        if source_schedule_digest == [0; 32] {
            return Err(C6SourceError::new(
                "C6 paired source witness requires a nonzero source-schedule digest",
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
        hasher.update(&source_schedule_digest);
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
            source_schedule_digest,
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

    pub fn source_schedule_digest(&self) -> C6SourceDigest {
        self.source_schedule_digest
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
    let mut follower = C6SourceScheduleProverFollower::start(secondary)?;
    follower.sync_audit(schedule, secondary)?;
    follower.finish_coordinate(primary, schedule, secondary)
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
        let pair = C6PairedSourceWitness::new(
            [[0x91; 32], [0x92; 32]],
            [primary, secondary],
            &schedule,
            [0x93; 32],
        )
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
            [0xB3; 32],
        )
        .is_err());

        let mut secondary_stream = CorrelationStream::new([0xA3; 32]);
        let second = replay_c6_source_coordinate(&first, &schedule, &mut secondary_stream).unwrap();
        assert!(C6PairedSourceWitness::new(
            [[0xB1; 32], [0xB1; 32]],
            [first, second],
            &schedule,
            [0xB3; 32],
        )
        .is_err());
    }

    #[test]
    fn incremental_provider_follower_mirrors_every_public_prefix_before_inline_replay() {
        let mut primary_stream = CorrelationStream::new([0xC1; 32]);
        primary_stream.enable_c6_source_witness_collection().unwrap();
        let mut secondary_stream = CorrelationStream::new([0xC2; 32]);
        let mut follower = C6SourceScheduleProverFollower::start(&mut secondary_stream).unwrap();

        let first_plaintexts = [Fp::new(11), Fp::new(12), Fp::new(13)];
        let first = primary_stream.draw_subs(0xC100, first_plaintexts.len());
        let corrections = first
            .iter()
            .zip(first_plaintexts)
            .map(|(source, value)| value.sub(source.r).value())
            .collect::<Vec<_>>();
        primary_stream.record_c6_subfield_corrections(0xC100, &corrections).unwrap();
        follower.sync_primary(&primary_stream, &mut secondary_stream).unwrap();
        assert_eq!(follower.next_draw(), 1);
        let counters = secondary_stream.counters;
        let allocation = secondary_stream.allocation_digest_hex();
        assert_eq!(secondary_stream.replay_consumed_sub_masks(0xC100, 3).len(), 3);
        let _ = secondary_stream.draw_sub_tags(0xC100, 3);
        assert_eq!(secondary_stream.counters, counters);
        assert_eq!(secondary_stream.allocation_digest_hex(), allocation);

        let full_plaintexts = [Fp2::new(Fp::new(21), Fp::new(22))];
        let _ = primary_stream.draw_fulls(0xC101, 1);
        primary_stream.record_c6_fullfield_plaintexts(0xC101, &full_plaintexts).unwrap();
        let _ = primary_stream.draw_product_mask(0xC102, 17);
        follower.sync_primary(&primary_stream, &mut secondary_stream).unwrap();
        assert_eq!(follower.next_draw(), 3);

        let last_plaintexts = [Fp::new(31), Fp::new(32)];
        let last = primary_stream.draw_subs(0xC103, last_plaintexts.len());
        let corrections = last
            .iter()
            .zip(last_plaintexts)
            .map(|(source, value)| value.sub(source.r).value())
            .collect::<Vec<_>>();
        primary_stream.record_c6_subfield_corrections(0xC103, &corrections).unwrap();
        follower.sync_primary(&primary_stream, &mut secondary_stream).unwrap();

        let schedule = primary_stream.schedule_audit().unwrap();
        assert_eq!(secondary_stream.schedule_audit(), Some(schedule.clone()));
        let primary = C6SourceCoordinate::new(
            primary_stream.finish_c6_subfield_witness_collection().unwrap(),
            primary_stream.finish_c6_fullfield_witness_collection().unwrap(),
            &schedule,
        )
        .unwrap();
        let secondary =
            follower.finish_coordinate(&primary, &schedule, &mut secondary_stream).unwrap();
        let pair = C6PairedSourceWitness::new(
            [[0xC3; 32], [0xC4; 32]],
            [primary, secondary],
            &schedule,
            [0xC5; 32],
        )
        .unwrap();
        assert_eq!(pair.subfield_leaf_count(), 5);
        assert_eq!(pair.direct_fullfield_leaf_count(), 1);
        assert_eq!(pair.product_mask_leaf_count(), 1);
    }

    #[test]
    fn incremental_verifier_follower_is_exact_and_rejects_schedule_rollback() {
        let primary_delta = Fp2::new(Fp::new(0xD1), Fp::new(0xD2));
        let secondary_delta = Fp2::new(Fp::new(0xD3), Fp::new(0xD4));
        let mut primary = VerifierCtx::new([0xD5; 32], primary_delta);
        primary.enable_schedule_audit().unwrap();
        let mut secondary = VerifierCtx::new([0xD6; 32], secondary_delta);
        let mut follower = C6SourceScheduleVerifierFollower::start(&mut secondary).unwrap();

        primary.reserve_sub_key_rows(0xD100, 2, 3);
        follower.sync_primary(&primary, &mut secondary).unwrap();
        let first_prefix = primary.schedule_audit().unwrap();
        assert_eq!(secondary.schedule_audit(), Some(first_prefix.clone()));
        let counters = secondary.counters;
        let allocation = secondary.allocation_digest_hex();
        assert_eq!(secondary.replay_consumed_sub_keys(0xD101, 3).len(), 3);
        assert_eq!(secondary.counters, counters);
        assert_eq!(secondary.allocation_digest_hex(), allocation);

        let _ = primary.expand_full_keys(0xD102, 2);
        let _ = primary.expand_product_mask_key(0xD103, 19);
        primary.reserve_sub_key_rows(0xD104, 1, 4);
        follower.sync_primary(&primary, &mut secondary).unwrap();
        assert_eq!(secondary.schedule_audit(), primary.schedule_audit());
        assert_eq!(follower.next_draw(), 5);

        assert!(follower.sync_audit(&first_prefix, &mut secondary).is_err());
        assert!(follower.sync_primary(&primary, &mut secondary).is_err());
    }

    #[test]
    fn incremental_followers_preserve_real_pool_order_and_mac_relations() {
        let deltas =
            [Fp2::new(Fp::new(0xE1), Fp::new(0xE2)), Fp2::new(Fp::new(0xE3), Fp::new(0xE4))];
        let params = volta_pcg::PhaseAParams::tiny_for_test(12);
        let pools = [
            volta_pcg::expand_phase_a([0xE5; 32], deltas[0], 6, 3, params.clone()),
            volta_pcg::expand_phase_a([0xE6; 32], deltas[1], 6, 3, params),
        ];
        let [primary_pool, secondary_pool] = pools;
        let mut primary = CorrelationStream::from_pcg_pool(primary_pool.prover);
        primary.enable_schedule_audit().unwrap();
        let mut primary_verifier = VerifierCtx::from_pcg_pool(deltas[0], primary_pool.verifier);
        primary_verifier.enable_schedule_audit().unwrap();
        let mut secondary = CorrelationStream::from_pcg_pool(secondary_pool.prover);
        let mut secondary_verifier = VerifierCtx::from_pcg_pool(deltas[1], secondary_pool.verifier);
        let mut prover_follower = C6SourceScheduleProverFollower::start(&mut secondary).unwrap();
        let mut verifier_follower =
            C6SourceScheduleVerifierFollower::start(&mut secondary_verifier).unwrap();

        let _ = primary.reserve_sub_mask_rows(0xE100, 2, 3);
        primary_verifier.reserve_sub_key_rows(0xE100, 2, 3);
        let _ = primary.draw_fulls(0xE102, 2);
        let _ = primary_verifier.expand_full_keys(0xE102, 2);
        let _ = primary.draw_product_mask(0xE103, 23);
        let _ = primary_verifier.expand_product_mask_key(0xE103, 23);
        assert_eq!(primary.schedule_audit(), primary_verifier.schedule_audit());
        assert_eq!(primary.allocation_digest_hex(), primary_verifier.allocation_digest_hex());

        prover_follower.sync_primary(&primary, &mut secondary).unwrap();
        verifier_follower.sync_primary(&primary_verifier, &mut secondary_verifier).unwrap();
        assert_eq!(secondary.schedule_audit(), secondary_verifier.schedule_audit());
        assert_eq!(secondary.allocation_digest_hex(), secondary_verifier.allocation_digest_hex());

        for domain in [0xE100, 0xE101] {
            let masks = secondary.replay_consumed_sub_masks(domain, 3);
            let tags = secondary.draw_sub_tags(domain, 3);
            let keys = secondary_verifier.replay_consumed_sub_keys(domain, 3);
            for ((mask, tag), key) in masks.into_iter().zip(tags).zip(keys) {
                assert_eq!(key, tag + deltas[1].mul_base(mask));
            }
        }
        assert_eq!(secondary.counters, secondary_verifier.counters);
        assert_eq!(secondary.allocation_digest_hex(), secondary_verifier.allocation_digest_hex());
    }
}

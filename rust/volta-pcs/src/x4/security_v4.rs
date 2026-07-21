//! Closed schema-4 counter inventory from the Amendment-5 LinkBad audit.
//!
//! Every protocol rejection, accepting statistical owner, privacy/lifecycle
//! invariant and permanent diagnostic has one stable family name.  Adding a
//! family is a preregistration change, not an implementation convenience.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum X4V4CounterFamily {
    FrameReject,
    PackedScheduleReject,
    PackedReconstructionReject,
    CohortBindingReject,
    SlotIdentityReject,
    EarlyQueryReject,
    AcceptedUnsealedChain,
    FoldQueryBad,
    ClaimReduceBad,
    AuthLinkBad,
    ResponseZeroBatchBad,
    PendingEscapeReject,
    TargetEvalLeakReject,
    CorrelationViewReject,
    EpochReuseReject,
    DeltaShiftAttempt,
    BetaCollisionWitness,
}

impl X4V4CounterFamily {
    pub const ALL: [Self; 17] = [
        Self::FrameReject,
        Self::PackedScheduleReject,
        Self::PackedReconstructionReject,
        Self::CohortBindingReject,
        Self::SlotIdentityReject,
        Self::EarlyQueryReject,
        Self::AcceptedUnsealedChain,
        Self::FoldQueryBad,
        Self::ClaimReduceBad,
        Self::AuthLinkBad,
        Self::ResponseZeroBatchBad,
        Self::PendingEscapeReject,
        Self::TargetEvalLeakReject,
        Self::CorrelationViewReject,
        Self::EpochReuseReject,
        Self::DeltaShiftAttempt,
        Self::BetaCollisionWitness,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::FrameReject => "frame_reject",
            Self::PackedScheduleReject => "packed_schedule_reject",
            Self::PackedReconstructionReject => "packed_reconstruction_reject",
            Self::CohortBindingReject => "cohort_binding_reject",
            Self::SlotIdentityReject => "slot_identity_reject",
            Self::EarlyQueryReject => "early_query_reject",
            Self::AcceptedUnsealedChain => "accepted_unsealed_chain",
            Self::FoldQueryBad => "fold_query_bad",
            Self::ClaimReduceBad => "claim_reduce_bad",
            Self::AuthLinkBad => "auth_link_bad",
            Self::ResponseZeroBatchBad => "response_zero_batch_bad",
            Self::PendingEscapeReject => "pending_escape_reject",
            Self::TargetEvalLeakReject => "target_eval_leak_reject",
            Self::CorrelationViewReject => "correlation_view_reject",
            Self::EpochReuseReject => "epoch_reuse_reject",
            Self::DeltaShiftAttempt => "delta_shift_attempt",
            Self::BetaCollisionWitness => "beta_collision_witness",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X4V4SecurityCounters {
    pub frame_reject: u64,
    pub packed_schedule_reject: u64,
    pub packed_reconstruction_reject: u64,
    pub cohort_binding_reject: u64,
    pub slot_identity_reject: u64,
    pub early_query_reject: u64,
    pub accepted_unsealed_chain: u64,
    pub fold_query_bad: u64,
    pub claim_reduce_bad: u64,
    pub auth_link_bad: u64,
    pub response_zero_batch_bad: u64,
    pub pending_escape_reject: u64,
    pub target_eval_leak_reject: u64,
    pub correlation_view_reject: u64,
    pub epoch_reuse_reject: u64,
    pub delta_shift_attempt: u64,
    pub beta_collision_witness: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4V4CounterOverflow;

impl X4V4SecurityCounters {
    pub fn increment(&mut self, family: X4V4CounterFamily) -> Result<(), X4V4CounterOverflow> {
        let counter = match family {
            X4V4CounterFamily::FrameReject => &mut self.frame_reject,
            X4V4CounterFamily::PackedScheduleReject => &mut self.packed_schedule_reject,
            X4V4CounterFamily::PackedReconstructionReject => &mut self.packed_reconstruction_reject,
            X4V4CounterFamily::CohortBindingReject => &mut self.cohort_binding_reject,
            X4V4CounterFamily::SlotIdentityReject => &mut self.slot_identity_reject,
            X4V4CounterFamily::EarlyQueryReject => &mut self.early_query_reject,
            X4V4CounterFamily::AcceptedUnsealedChain => &mut self.accepted_unsealed_chain,
            X4V4CounterFamily::FoldQueryBad => &mut self.fold_query_bad,
            X4V4CounterFamily::ClaimReduceBad => &mut self.claim_reduce_bad,
            X4V4CounterFamily::AuthLinkBad => &mut self.auth_link_bad,
            X4V4CounterFamily::ResponseZeroBatchBad => &mut self.response_zero_batch_bad,
            X4V4CounterFamily::PendingEscapeReject => &mut self.pending_escape_reject,
            X4V4CounterFamily::TargetEvalLeakReject => &mut self.target_eval_leak_reject,
            X4V4CounterFamily::CorrelationViewReject => &mut self.correlation_view_reject,
            X4V4CounterFamily::EpochReuseReject => &mut self.epoch_reuse_reject,
            X4V4CounterFamily::DeltaShiftAttempt => &mut self.delta_shift_attempt,
            X4V4CounterFamily::BetaCollisionWitness => &mut self.beta_collision_witness,
        };
        *counter = counter.checked_add(1).ok_or(X4V4CounterOverflow)?;
        Ok(())
    }

    pub fn get(&self, family: X4V4CounterFamily) -> u64 {
        match family {
            X4V4CounterFamily::FrameReject => self.frame_reject,
            X4V4CounterFamily::PackedScheduleReject => self.packed_schedule_reject,
            X4V4CounterFamily::PackedReconstructionReject => self.packed_reconstruction_reject,
            X4V4CounterFamily::CohortBindingReject => self.cohort_binding_reject,
            X4V4CounterFamily::SlotIdentityReject => self.slot_identity_reject,
            X4V4CounterFamily::EarlyQueryReject => self.early_query_reject,
            X4V4CounterFamily::AcceptedUnsealedChain => self.accepted_unsealed_chain,
            X4V4CounterFamily::FoldQueryBad => self.fold_query_bad,
            X4V4CounterFamily::ClaimReduceBad => self.claim_reduce_bad,
            X4V4CounterFamily::AuthLinkBad => self.auth_link_bad,
            X4V4CounterFamily::ResponseZeroBatchBad => self.response_zero_batch_bad,
            X4V4CounterFamily::PendingEscapeReject => self.pending_escape_reject,
            X4V4CounterFamily::TargetEvalLeakReject => self.target_eval_leak_reject,
            X4V4CounterFamily::CorrelationViewReject => self.correlation_view_reject,
            X4V4CounterFamily::EpochReuseReject => self.epoch_reuse_reject,
            X4V4CounterFamily::DeltaShiftAttempt => self.delta_shift_attempt,
            X4V4CounterFamily::BetaCollisionWitness => self.beta_collision_witness,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn counter_inventory_is_closed_unique_and_uses_the_frozen_names() {
        let names =
            X4V4CounterFamily::ALL.iter().map(|family| family.name()).collect::<BTreeSet<_>>();
        assert_eq!(names.len(), X4V4CounterFamily::ALL.len());
        assert!(names.contains("auth_link_bad"));
        assert!(names.contains("delta_shift_attempt"));
        assert!(names.contains("beta_collision_witness"));
        assert!(names.contains("pending_escape_reject"));

        let mut counters = X4V4SecurityCounters::default();
        for family in X4V4CounterFamily::ALL {
            counters.increment(family).unwrap();
            assert_eq!(counters.get(family), 1);
        }
        assert_eq!(counters.accepted_unsealed_chain, 1);
    }
}

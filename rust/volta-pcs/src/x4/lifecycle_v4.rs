//! Observer seam for X4c's legacy X4b lifecycle instrumentation.
//!
//! The protocol library reports only implementation-owned phase boundaries
//! and logical ownership.  Process, allocator, NUMA and CUDA snapshots belong
//! to the recorder implementing [`X4LifecycleObserverV4`]; keeping those
//! collectors out of this crate avoids changing the proof path or transcript.

use volta_accel::{Backend, CudaStreamState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4LifecycleTrackV4 {
    LegacySeal,
    LegacyOpening,
}

impl X4LifecycleTrackV4 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacySeal => "legacy_seal",
            Self::LegacyOpening => "legacy_opening",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4LifecyclePhaseV4 {
    CoefficientCloneAllocation,
    ENtt,
    CoefficientOracleWrite,
    FlushSyncData,
    OracleRereadN4Inner,
    N4OuterLevels,
    FullOracleComparison,
    CpuCodewordCacheCloneBack,
    FileCleanup,
    DirectoryCleanup,
    BackendFinishSynchronizationBoundary,
    DrawValidationSchedule,
    InitialGroupOpening,
    FoldRoundOpening,
    InnerHashingPathAssembly,
    ScheduleDigestStructuralValidation,
    CanonicalEncodeSerialization,
    DestroyCodewords,
    DestroyOuterCacheLevels,
    DestroyRemainingSealedState,
}

impl X4LifecyclePhaseV4 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoefficientCloneAllocation => "coefficient_clone_allocation",
            Self::ENtt => "e_ntt",
            Self::CoefficientOracleWrite => "coefficient_oracle_write",
            Self::FlushSyncData => "flush_sync_data",
            Self::OracleRereadN4Inner => "oracle_reread_n4_inner",
            Self::N4OuterLevels => "n4_outer_levels",
            Self::FullOracleComparison => "full_oracle_comparison",
            Self::CpuCodewordCacheCloneBack => "cpu_codeword_cache_clone_back",
            Self::FileCleanup => "file_cleanup",
            Self::DirectoryCleanup => "directory_cleanup",
            Self::BackendFinishSynchronizationBoundary => "backend_finish_synchronization_boundary",
            Self::DrawValidationSchedule => "draw_validation_schedule",
            Self::InitialGroupOpening => "initial_group_opening",
            Self::FoldRoundOpening => "fold_round_opening",
            Self::InnerHashingPathAssembly => "inner_hashing_path_assembly",
            Self::ScheduleDigestStructuralValidation => "schedule_digest_structural_validation",
            Self::CanonicalEncodeSerialization => "canonical_encode_serialization",
            Self::DestroyCodewords => "destroy_codewords",
            Self::DestroyOuterCacheLevels => "destroy_outer_cache_levels",
            Self::DestroyRemainingSealedState => "destroy_remaining_sealed_state",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4LifecycleTransitionV4 {
    SpanStart,
    SpanEnd,
    Boundary,
}

impl X4LifecycleTransitionV4 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpanStart => "span_start",
            Self::SpanEnd => "span_end",
            Self::Boundary => "boundary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4LifecycleNestingV4 {
    TopLevel,
    Nested,
}

impl X4LifecycleNestingV4 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TopLevel => "top_level",
            Self::Nested => "nested",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4LifecycleContextV4 {
    pub cohort_id: Option<u32>,
    pub fold_round: Option<u8>,
    pub slot_index: Option<u16>,
    pub initial_group_index: Option<u32>,
    pub outer_level: Option<u8>,
    /// Disambiguates repeated, non-overlapping segments of one named phase.
    pub segment_index: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4AcceleratorControlSnapshotV4 {
    pub available: bool,
    pub device_workspace_bytes: u64,
    pub device_resident_bytes: u64,
    pub device_cached_bytes: u64,
    pub device_live_bytes: u64,
    pub pinned_host_bytes: u64,
    pub outstanding_operations: u64,
    pub measurement_active: bool,
    pub synchronized: bool,
}

impl X4AcceleratorControlSnapshotV4 {
    /// Capture allocator ownership plus one non-blocking `cudaStreamQuery`.
    /// An unavailable component remains explicit zero, never an inferred
    /// candidate cause.
    pub fn capture(backend: &Backend) -> Self {
        let Ok(control) = backend.x4c_control_state() else {
            return Self::default();
        };
        let Ok(device) = backend.device_memory_breakdown() else {
            return Self::default();
        };
        let Ok(pinned) = backend.pinned_memory_stats() else {
            return Self::default();
        };
        let Some(device_live_bytes) = device
            .workspace_bytes
            .checked_add(device.resident_bytes)
            .and_then(|bytes| bytes.checked_add(device.cached_resident_bytes))
        else {
            return Self::default();
        };
        let Some(pinned_host_bytes) = pinned.active_bytes.checked_add(pinned.cached_bytes) else {
            return Self::default();
        };
        if control.workspace_device_bytes != device.workspace_bytes
            || control.active_device_bytes != device.resident_bytes
            || control.cached_device_bytes != device.cached_resident_bytes
            || control.active_pinned_bytes != pinned.active_bytes
            || control.cached_pinned_bytes != pinned.cached_bytes
        {
            return Self::default();
        }
        Self {
            available: true,
            device_workspace_bytes: device.workspace_bytes,
            device_resident_bytes: device.resident_bytes,
            device_cached_bytes: device.cached_resident_bytes,
            device_live_bytes,
            pinned_host_bytes,
            outstanding_operations: control.outstanding_cuda_operations,
            measurement_active: control.measurement_active,
            synchronized: control.stream_state == CudaStreamState::Idle
                && control.outstanding_cuda_operations == 0,
        }
    }

    pub fn is_consistent(self) -> bool {
        if !self.available {
            return self.device_workspace_bytes == 0
                && self.device_resident_bytes == 0
                && self.device_cached_bytes == 0
                && self.device_live_bytes == 0
                && self.pinned_host_bytes == 0
                && self.outstanding_operations == 0
                && !self.measurement_active
                && !self.synchronized;
        }
        match self
            .device_workspace_bytes
            .checked_add(self.device_resident_bytes)
            .and_then(|bytes| bytes.checked_add(self.device_cached_bytes))
        {
            Some(total) => {
                total == self.device_live_bytes
                    && (!self.synchronized || self.outstanding_operations == 0)
            }
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4LegacySealedOwnershipV4 {
    pub fold_codeword_bytes: u64,
    pub fold_outer_cache_bytes: u64,
    /// Accounted ordinary-host fold payload. Allocator-wide ownership is
    /// deliberately sampled by the recorder, not inferred here.
    pub accounted_ordinary_host_bytes: u64,
    pub pinned_host_bytes: u64,
    pub device_bytes: u64,
    pub file_backed_bytes: u64,
    pub owned_files: u64,
    pub owned_mappings: u64,
    /// Backend-wide state copied at the boundary. It is not ownership
    /// attributed to the sealed CPU state.
    pub accelerator_control: X4AcceleratorControlSnapshotV4,
}

impl X4LegacySealedOwnershipV4 {
    pub fn from_fold_payload(
        fold_codeword_bytes: u64,
        fold_outer_cache_bytes: u64,
    ) -> Option<Self> {
        Some(Self {
            fold_codeword_bytes,
            fold_outer_cache_bytes,
            accounted_ordinary_host_bytes: fold_codeword_bytes
                .checked_add(fold_outer_cache_bytes)?,
            ..Self::default()
        })
    }

    pub fn is_consistent_legacy(self) -> bool {
        match self.fold_codeword_bytes.checked_add(self.fold_outer_cache_bytes) {
            Some(total) => {
                self.accounted_ordinary_host_bytes == total
                    && self.pinned_host_bytes == 0
                    && self.device_bytes == 0
                    && self.file_backed_bytes == 0
                    && self.owned_files == 0
                    && self.owned_mappings == 0
                    && self.accelerator_control.is_consistent()
            }
            None => false,
        }
    }

    pub const fn with_accelerator_control(
        mut self,
        accelerator_control: X4AcceleratorControlSnapshotV4,
    ) -> Self {
        self.accelerator_control = accelerator_control;
        self
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4TemporaryFileStateV4 {
    pub live_files: u64,
    pub live_file_bytes: u64,
    pub live_directories: u64,
    pub files_created: u64,
    pub files_deleted: u64,
    pub directories_created: u64,
    pub directories_deleted: u64,
}

impl X4TemporaryFileStateV4 {
    pub const fn is_consistent(self) -> bool {
        self.files_created >= self.files_deleted
            && self.files_created - self.files_deleted == self.live_files
            && self.directories_created >= self.directories_deleted
            && self.directories_created - self.directories_deleted == self.live_directories
    }

    pub(crate) fn record_file_created(&mut self) -> Option<()> {
        self.live_files = self.live_files.checked_add(1)?;
        self.files_created = self.files_created.checked_add(1)?;
        Some(())
    }

    pub(crate) fn record_file_bytes_written(&mut self, bytes: u64) -> Option<()> {
        self.live_file_bytes = self.live_file_bytes.checked_add(bytes)?;
        Some(())
    }

    pub(crate) fn record_file_deleted(&mut self, bytes: u64) -> Option<()> {
        self.live_files = self.live_files.checked_sub(1)?;
        self.live_file_bytes = self.live_file_bytes.checked_sub(bytes)?;
        self.files_deleted = self.files_deleted.checked_add(1)?;
        Some(())
    }

    pub(crate) fn record_directory_created(&mut self) -> Option<()> {
        self.live_directories = self.live_directories.checked_add(1)?;
        self.directories_created = self.directories_created.checked_add(1)?;
        Some(())
    }

    pub fn record_directory_deleted(&mut self) -> Option<()> {
        self.live_directories = self.live_directories.checked_sub(1)?;
        self.directories_deleted = self.directories_deleted.checked_add(1)?;
        Some(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4LifecycleEventV4 {
    pub track: X4LifecycleTrackV4,
    pub phase: X4LifecyclePhaseV4,
    pub transition: X4LifecycleTransitionV4,
    pub nesting: X4LifecycleNestingV4,
    pub context: X4LifecycleContextV4,
    pub sealed_ownership: X4LegacySealedOwnershipV4,
    pub temporary_files: X4TemporaryFileStateV4,
}

impl X4LifecycleEventV4 {
    pub const fn span_start(
        track: X4LifecycleTrackV4,
        phase: X4LifecyclePhaseV4,
        nesting: X4LifecycleNestingV4,
        context: X4LifecycleContextV4,
        sealed_ownership: X4LegacySealedOwnershipV4,
        temporary_files: X4TemporaryFileStateV4,
    ) -> Self {
        Self {
            track,
            phase,
            transition: X4LifecycleTransitionV4::SpanStart,
            nesting,
            context,
            sealed_ownership,
            temporary_files,
        }
    }

    pub const fn span_end(
        track: X4LifecycleTrackV4,
        phase: X4LifecyclePhaseV4,
        nesting: X4LifecycleNestingV4,
        context: X4LifecycleContextV4,
        sealed_ownership: X4LegacySealedOwnershipV4,
        temporary_files: X4TemporaryFileStateV4,
    ) -> Self {
        Self {
            track,
            phase,
            transition: X4LifecycleTransitionV4::SpanEnd,
            nesting,
            context,
            sealed_ownership,
            temporary_files,
        }
    }

    pub const fn boundary(
        track: X4LifecycleTrackV4,
        phase: X4LifecyclePhaseV4,
        nesting: X4LifecycleNestingV4,
        context: X4LifecycleContextV4,
        sealed_ownership: X4LegacySealedOwnershipV4,
        temporary_files: X4TemporaryFileStateV4,
    ) -> Self {
        Self {
            track,
            phase,
            transition: X4LifecycleTransitionV4::Boundary,
            nesting,
            context,
            sealed_ownership,
            temporary_files,
        }
    }

    pub const fn with_accelerator_control(
        mut self,
        accelerator_control: X4AcceleratorControlSnapshotV4,
    ) -> Self {
        self.sealed_ownership.accelerator_control = accelerator_control;
        self
    }
}

pub trait X4LifecycleObserverV4 {
    fn observe(&mut self, event: &X4LifecycleEventV4);
}

#[derive(Debug, Default)]
pub struct NoopX4LifecycleObserverV4;

impl X4LifecycleObserverV4 for NoopX4LifecycleObserverV4 {
    fn observe(&mut self, _event: &X4LifecycleEventV4) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_ownership_rejects_every_non_host_candidate_cause() {
        let ownership = X4LegacySealedOwnershipV4::from_fold_payload(16, 32).unwrap();
        assert!(ownership.is_consistent_legacy());
        for bad in [
            X4LegacySealedOwnershipV4 { pinned_host_bytes: 1, ..ownership },
            X4LegacySealedOwnershipV4 { device_bytes: 1, ..ownership },
            X4LegacySealedOwnershipV4 { file_backed_bytes: 1, ..ownership },
            X4LegacySealedOwnershipV4 { owned_files: 1, ..ownership },
            X4LegacySealedOwnershipV4 { owned_mappings: 1, ..ownership },
            X4LegacySealedOwnershipV4 { accounted_ordinary_host_bytes: 47, ..ownership },
        ] {
            assert!(!bad.is_consistent_legacy());
        }
    }

    #[test]
    fn runner_owned_control_phase_names_are_exact() {
        assert_eq!(X4LifecyclePhaseV4::DirectoryCleanup.as_str(), "directory_cleanup");
        assert_eq!(
            X4LifecyclePhaseV4::BackendFinishSynchronizationBoundary.as_str(),
            "backend_finish_synchronization_boundary"
        );
    }

    #[test]
    fn unavailable_accelerator_control_is_explicit_zero() {
        let snapshot = X4AcceleratorControlSnapshotV4::default();
        assert!(!snapshot.available);
        assert!(snapshot.is_consistent());
        let mut inconsistent = snapshot;
        inconsistent.device_live_bytes = 1;
        assert!(!inconsistent.is_consistent());
    }

    #[test]
    fn temporary_file_ledger_reconciles_create_write_delete() {
        let mut files = X4TemporaryFileStateV4::default();
        files.record_directory_created().unwrap();
        files.record_file_created().unwrap();
        files.record_file_bytes_written(64).unwrap();
        assert!(files.is_consistent());
        files.record_file_deleted(64).unwrap();
        files.record_directory_deleted().unwrap();
        assert!(files.is_consistent());
        assert_eq!(files.live_files, 0);
        assert_eq!(files.live_file_bytes, 0);
        assert_eq!(files.live_directories, 0);
    }
}

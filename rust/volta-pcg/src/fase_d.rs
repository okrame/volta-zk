//! Fase-D production parameters and refill accounting.
//!
//! This module deliberately separates the logical allocation schedule from
//! the GGM implementation.  A PRG choice may change serialized setup bytes,
//! but it cannot change which correlation is generated, reserved as a child
//! base, allocated to a response, or burned.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The only production profile accepted by the fase-D capability preflight.
pub const FASE_D_PROFILE: &str = "fase-d-realpcg-v1";
pub const TEST_ONLY_INSECURE_PREFIX: &str = "TEST_ONLY_INSECURE_";

pub const STAGE3_K: usize = 6_520_000;
pub const STAGE3_N: usize = 117_440_512;
pub const STAGE3_T: usize = 1_792;
pub const STAGE3_BLOCK_SIZE: usize = 65_536;
pub const STAGE3_DEPTH: u32 = 16;
pub const STAGE3_BASE_CONSUMPTION: usize = STAGE3_K + STAGE3_T + 2;
pub const STAGE3_USABLE_OUTPUT: usize = STAGE3_N - STAGE3_BASE_CONSUMPTION;

pub const MAIN_K: usize = 589_760;
pub const MAIN_N: usize = 10_805_248;
pub const MAIN_T: usize = 1_319;
pub const MAIN_BASE_CONSUMPTION: usize = MAIN_K + MAIN_T + 2;
pub const MAIN_USABLE_OUTPUT: usize = MAIN_N - MAIN_BASE_CONSUMPTION;

pub const SETUP_K: usize = 25_000;
pub const SETUP_N: usize = 642_048;
pub const SETUP_T: usize = 2_508;

pub const MAX_STAGE3_INSTANCES: usize = 6;
pub const STAGE3_BATCH_BLOCKS: usize = 896;
pub const STAGE3_BATCH_COUNT: usize = 2;
pub const PROVER_BUFFER_CAP_BYTES: u64 = 4_000_000_000;
pub const RAW_SUB_CORRELATION_BYTES: u64 = 24;
pub const GGM_NODE_BYTES_AES128: u64 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegularNoiseTuple {
    pub k: usize,
    pub n: usize,
    pub t: usize,
    pub block_size: usize,
    pub depth: u32,
}

impl RegularNoiseTuple {
    pub const fn base_consumption(self) -> usize {
        self.k + self.t + 2
    }

    pub const fn usable_output(self) -> usize {
        self.n - self.base_consumption()
    }

    pub fn validate(self) -> Result<(), FaseDError> {
        if self.k == 0 || self.t == 0 || self.n <= self.base_consumption() {
            return Err(FaseDError::InvalidTuple("empty or undersized LPN tuple"));
        }
        if self.t.checked_mul(self.block_size) != Some(self.n) {
            return Err(FaseDError::InvalidTuple(
                "regular-noise blocks do not partition n exactly",
            ));
        }
        if self.block_size != 1usize.checked_shl(self.depth).unwrap_or(0) {
            return Err(FaseDError::InvalidTuple(
                "GGM depth does not match the regular-noise block size",
            ));
        }
        Ok(())
    }
}

pub const SETUP_TUPLE: RegularNoiseTuple =
    RegularNoiseTuple { k: SETUP_K, n: SETUP_N, t: SETUP_T, block_size: 256, depth: 8 };

pub const MAIN_TUPLE: RegularNoiseTuple =
    RegularNoiseTuple { k: MAIN_K, n: MAIN_N, t: MAIN_T, block_size: 8_192, depth: 13 };

pub const STAGE3_TUPLE: RegularNoiseTuple = RegularNoiseTuple {
    k: STAGE3_K,
    n: STAGE3_N,
    t: STAGE3_T,
    block_size: STAGE3_BLOCK_SIZE,
    depth: STAGE3_DEPTH,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaseDStagePlan {
    TerminalOne,
    ChainSix,
}

impl FaseDStagePlan {
    pub const fn activated_stage3_instances(self) -> usize {
        match self {
            Self::TerminalOne => 1,
            Self::ChainSix => MAX_STAGE3_INSTANCES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaseDParams {
    pub profile: String,
    pub setup: RegularNoiseTuple,
    pub main: RegularNoiseTuple,
    pub stage3: RegularNoiseTuple,
    pub preprovisioned_stage3_instances: usize,
    pub plan: FaseDStagePlan,
    pub batch_blocks: usize,
    pub prover_buffer_cap_bytes: u64,
}

impl FaseDParams {
    pub fn production(plan: FaseDStagePlan) -> Self {
        Self {
            profile: FASE_D_PROFILE.into(),
            setup: SETUP_TUPLE,
            main: MAIN_TUPLE,
            stage3: STAGE3_TUPLE,
            // All six path-OT slices are included in the single connection
            // base phase even when terminal-one activates only the first.
            preprovisioned_stage3_instances: MAX_STAGE3_INSTANCES,
            plan,
            batch_blocks: STAGE3_BATCH_BLOCKS,
            prover_buffer_cap_bytes: PROVER_BUFFER_CAP_BYTES,
        }
    }

    pub fn test_only_insecure(plan: FaseDStagePlan) -> Self {
        Self {
            profile: format!("{TEST_ONLY_INSECURE_PREFIX}fase-d-toy"),
            setup: RegularNoiseTuple { k: 16, n: 128, t: 4, block_size: 32, depth: 5 },
            main: RegularNoiseTuple { k: 64, n: 256, t: 8, block_size: 32, depth: 5 },
            stage3: RegularNoiseTuple { k: 32, n: 256, t: 8, block_size: 32, depth: 5 },
            preprovisioned_stage3_instances: MAX_STAGE3_INSTANCES,
            plan,
            batch_blocks: 4,
            prover_buffer_cap_bytes: 1 << 20,
        }
    }

    /// Fail-closed production capability check.  Tests may exercise toy
    /// tuples, but record-producing paths accept only the preregistered tuple
    /// and schedule byte-for-byte.
    pub fn production_preflight(&self) -> Result<(), FaseDError> {
        self.setup.validate()?;
        self.main.validate()?;
        self.stage3.validate()?;
        if self.profile.starts_with(TEST_ONLY_INSECURE_PREFIX) {
            return Err(FaseDError::ProductionPreflight(
                "TEST_ONLY_INSECURE profile is forbidden in production",
            ));
        }
        if self.profile != FASE_D_PROFILE
            || self.setup != SETUP_TUPLE
            || self.main != MAIN_TUPLE
            || self.stage3 != STAGE3_TUPLE
            || self.preprovisioned_stage3_instances != MAX_STAGE3_INSTANCES
            || self.batch_blocks != STAGE3_BATCH_BLOCKS
            || self.prover_buffer_cap_bytes != PROVER_BUFFER_CAP_BYTES
        {
            return Err(FaseDError::ProductionPreflight(
                "parameters differ from the preregistered fase-D profile",
            ));
        }
        if self.stage3.base_consumption() > self.main.usable_output() {
            return Err(FaseDError::ProductionPreflight(
                "stage-3 base consumption exceeds main usable output",
            ));
        }
        if self.stage3.usable_output() < 110_000_000 {
            return Err(FaseDError::ProductionPreflight(
                "stage-3 usable output is below the G2 floor",
            ));
        }
        Ok(())
    }

    pub fn batches(&self) -> Result<Vec<Stage3Batch>, FaseDError> {
        if !self.stage3.t.is_multiple_of(self.batch_blocks) {
            return Err(FaseDError::InvalidTuple(
                "stage-3 noise blocks are not divisible by the batch size",
            ));
        }
        let count = self.stage3.t / self.batch_blocks;
        let mut batches = Vec::with_capacity(count);
        for index in 0..count {
            let block_start = index * self.batch_blocks;
            batches.push(Stage3Batch {
                index,
                block_start,
                block_count: self.batch_blocks,
                row_start: block_start * self.stage3.block_size,
                row_count: self.batch_blocks * self.stage3.block_size,
            });
        }
        Ok(batches)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage3Batch {
    pub index: usize,
    pub block_start: usize,
    pub block_count: usize,
    pub row_start: usize,
    pub row_count: usize,
}

/// Tracks only memory that is simultaneously live on the prover.  Callers
/// must account actual Vec capacities, not logical lengths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBufferAccount {
    pub cap_bytes: u64,
    pub current_bytes: u64,
    pub high_water_bytes: u64,
}

impl ProverBufferAccount {
    pub fn new(cap_bytes: u64) -> Self {
        Self { cap_bytes, current_bytes: 0, high_water_bytes: 0 }
    }

    pub fn acquire(&mut self, bytes: u64) -> Result<(), FaseDError> {
        let next = self
            .current_bytes
            .checked_add(bytes)
            .ok_or(FaseDError::ArithmeticOverflow("live prover buffer"))?;
        if next > self.cap_bytes {
            return Err(FaseDError::BufferCapExceeded { requested: next, cap: self.cap_bytes });
        }
        self.current_bytes = next;
        self.high_water_bytes = self.high_water_bytes.max(next);
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) -> Result<(), FaseDError> {
        self.current_bytes = self
            .current_bytes
            .checked_sub(bytes)
            .ok_or(FaseDError::CounterUnderflow("prover buffer release"))?;
        Ok(())
    }
}

/// Enforces canonical `(stage_ordinal,row)` batch lifting and requires each
/// batch's scratch storage to be released before the next batch begins.
#[derive(Clone, Debug)]
pub struct CanonicalBatchLift {
    stage_ordinal: usize,
    expected_batch: usize,
    expected_row: usize,
    active_scratch_bytes: u64,
    rows_lifted: usize,
    digest: blake3::Hasher,
    memory: ProverBufferAccount,
}

impl CanonicalBatchLift {
    pub fn new(stage_ordinal: usize, cap_bytes: u64) -> Self {
        let mut digest = blake3::Hasher::new_derive_key("volta/fase-d/canonical-allocation/v1");
        digest.update(&(stage_ordinal as u64).to_le_bytes());
        Self {
            stage_ordinal,
            expected_batch: 0,
            expected_row: 0,
            active_scratch_bytes: 0,
            rows_lifted: 0,
            digest,
            memory: ProverBufferAccount::new(cap_bytes),
        }
    }

    pub fn acquire_persistent(&mut self, bytes: u64) -> Result<(), FaseDError> {
        self.memory.acquire(bytes)
    }

    pub fn begin_batch(
        &mut self,
        batch: Stage3Batch,
        actual_scratch_capacity_bytes: u64,
    ) -> Result<(), FaseDError> {
        if self.active_scratch_bytes != 0 {
            return Err(FaseDError::BatchOrder("previous batch storage is still live"));
        }
        if batch.index != self.expected_batch || batch.row_start != self.expected_row {
            return Err(FaseDError::BatchOrder("non-canonical batch or row order"));
        }
        self.memory.acquire(actual_scratch_capacity_bytes)?;
        self.active_scratch_bytes = actual_scratch_capacity_bytes;
        Ok(())
    }

    /// Commit a fully checked batch to logical allocation order.  The digest
    /// is over canonical metadata; cryptographic correlation values remain in
    /// the caller's transcript/allocation digest.
    pub fn lift_checked_batch(&mut self, batch: Stage3Batch) -> Result<(), FaseDError> {
        if self.active_scratch_bytes == 0 {
            return Err(FaseDError::BatchOrder("batch storage was not acquired"));
        }
        if batch.index != self.expected_batch || batch.row_start != self.expected_row {
            return Err(FaseDError::BatchOrder("checked batch is out of canonical order"));
        }
        self.digest.update(&(self.stage_ordinal as u64).to_le_bytes());
        self.digest.update(&(batch.index as u64).to_le_bytes());
        self.digest.update(&(batch.row_start as u64).to_le_bytes());
        self.digest.update(&(batch.row_count as u64).to_le_bytes());
        self.rows_lifted = self
            .rows_lifted
            .checked_add(batch.row_count)
            .ok_or(FaseDError::ArithmeticOverflow("canonical row count"))?;
        self.expected_row += batch.row_count;
        self.expected_batch += 1;
        Ok(())
    }

    pub fn release_batch(&mut self) -> Result<(), FaseDError> {
        if self.active_scratch_bytes == 0 {
            return Err(FaseDError::BatchOrder("no active batch storage"));
        }
        let bytes = self.active_scratch_bytes;
        self.active_scratch_bytes = 0;
        self.memory.release(bytes)
    }

    pub fn finish(
        self,
        expected_batches: usize,
        expected_rows: usize,
    ) -> Result<BatchLiftReport, FaseDError> {
        if self.active_scratch_bytes != 0 {
            return Err(FaseDError::BatchOrder("final batch storage was not released"));
        }
        if self.expected_batch != expected_batches || self.rows_lifted != expected_rows {
            return Err(FaseDError::BatchOrder("incomplete canonical batch lift"));
        }
        Ok(BatchLiftReport {
            stage_ordinal: self.stage_ordinal,
            batches_lifted: self.expected_batch,
            rows_lifted: self.rows_lifted,
            allocation_order_digest: self.digest.finalize().to_hex().to_string(),
            prover_buffer_high_water_bytes: self.memory.high_water_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchLiftReport {
    pub stage_ordinal: usize,
    pub batches_lifted: usize,
    pub rows_lifted: usize,
    pub allocation_order_digest: String,
    pub prover_buffer_high_water_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageId {
    Setup,
    Main,
    Stage3(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageCounters {
    pub stage: StageId,
    pub generated: u64,
    pub consumed: u64,
    pub reserved_as_base: u64,
    pub burned: u64,
    pub available: u64,
}

impl StageCounters {
    pub fn new(stage: StageId, generated: usize) -> Self {
        Self {
            stage,
            generated: generated as u64,
            consumed: 0,
            reserved_as_base: 0,
            burned: 0,
            available: generated as u64,
        }
    }

    pub fn reserve_as_base(&mut self, count: usize) -> Result<(), FaseDError> {
        self.move_from_available(count as u64, CounterClass::ReservedAsBase)
    }

    pub fn consume(&mut self, count: usize) -> Result<(), FaseDError> {
        self.move_from_available(count as u64, CounterClass::Consumed)
    }

    pub fn burn(&mut self, count: usize) -> Result<(), FaseDError> {
        self.move_from_available(count as u64, CounterClass::Burned)
    }

    pub fn burn_residual(&mut self) {
        self.burned += self.available;
        self.available = 0;
    }

    pub fn reconciles(&self) -> bool {
        self.generated == self.consumed + self.reserved_as_base + self.burned + self.available
    }

    fn move_from_available(&mut self, count: u64, class: CounterClass) -> Result<(), FaseDError> {
        if count > self.available {
            return Err(FaseDError::CounterUnderflow(match class {
                CounterClass::Consumed => "response consumption",
                CounterClass::ReservedAsBase => "reserved-as-base consumption",
                CounterClass::Burned => "burn consumption",
            }));
        }
        self.available -= count;
        match class {
            CounterClass::Consumed => self.consumed += count,
            CounterClass::ReservedAsBase => self.reserved_as_base += count,
            CounterClass::Burned => self.burned += count,
        }
        debug_assert!(self.reconciles());
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CounterClass {
    Consumed,
    ReservedAsBase,
    Burned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefillLedger {
    pub plan: FaseDStagePlan,
    pub stages: Vec<StageCounters>,
}

impl RefillLedger {
    pub fn new(params: &FaseDParams) -> Result<Self, FaseDError> {
        params.setup.validate()?;
        params.main.validate()?;
        params.stage3.validate()?;
        let active = params.plan.activated_stage3_instances();
        if active == 0 || active > params.preprovisioned_stage3_instances {
            return Err(FaseDError::StageOrder("invalid stage-3 activation count"));
        }

        // The recursive setup emits exactly the main base slice, not its
        // maximum theoretical usable tuple capacity.
        let mut setup = StageCounters::new(StageId::Setup, params.main.base_consumption());
        setup.reserve_as_base(params.main.base_consumption())?;

        let mut main = StageCounters::new(StageId::Main, params.main.usable_output());
        main.reserve_as_base(params.stage3.base_consumption())?;

        let mut stages = vec![setup, main];
        for ordinal in 0..active {
            let mut stage = StageCounters::new(
                StageId::Stage3((ordinal + 1) as u8),
                params.stage3.usable_output(),
            );
            if ordinal + 1 < active {
                stage.reserve_as_base(params.stage3.base_consumption())?;
            }
            stages.push(stage);
        }
        let ledger = Self { plan: params.plan, stages };
        ledger.check()?;
        Ok(ledger)
    }

    pub fn stage_mut(&mut self, id: StageId) -> Result<&mut StageCounters, FaseDError> {
        self.stages
            .iter_mut()
            .find(|stage| stage.stage == id)
            .ok_or(FaseDError::StageOrder("unknown stage counter"))
    }

    pub fn allocatable(&self) -> u64 {
        self.stages.iter().map(|stage| stage.available).sum()
    }

    /// Allocate in the only permitted global order: remaining main outputs,
    /// then stage-3 ordinals in ascending order.  Reserved child bases were
    /// removed before this function can see them.
    pub fn consume_canonical(&mut self, mut count: usize) -> Result<(), FaseDError> {
        if count as u64 > self.allocatable() {
            return Err(FaseDError::CounterUnderflow("canonical response allocation"));
        }
        for stage in &mut self.stages {
            if count == 0 {
                break;
            }
            let take = count.min(stage.available as usize);
            stage.consume(take)?;
            count -= take;
        }
        self.check()
    }

    /// Terminal connection close/TTL/abort accounting.  The caller records
    /// the durable connection marker before making this in-memory transition.
    pub fn burn_all_residual(&mut self) -> Result<(), FaseDError> {
        for stage in &mut self.stages {
            stage.burn_residual();
        }
        self.check()
    }

    pub fn check(&self) -> Result<(), FaseDError> {
        if self.stages.iter().any(|stage| !stage.reconciles()) {
            return Err(FaseDError::StageOrder("stage counters do not reconcile"));
        }
        for (position, stage) in self.stages.iter().enumerate() {
            let expected = match position {
                0 => StageId::Setup,
                1 => StageId::Main,
                ordinal => StageId::Stage3((ordinal - 1) as u8),
            };
            if stage.stage != expected {
                return Err(FaseDError::StageOrder("stage counters are not canonical"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaseDCapacityReport {
    pub main_residual: usize,
    pub gross_stage3: usize,
    pub reserved_stage3_as_base: usize,
    pub allocatable_stage3: usize,
    pub total_allocatable: usize,
}

impl FaseDCapacityReport {
    pub fn for_params(params: &FaseDParams) -> Result<Self, FaseDError> {
        let active = params.plan.activated_stage3_instances();
        let main_residual = params
            .main
            .usable_output()
            .checked_sub(params.stage3.base_consumption())
            .ok_or(FaseDError::CounterUnderflow("main-to-stage3 reservation"))?;
        let gross_stage3 = active
            .checked_mul(params.stage3.usable_output())
            .ok_or(FaseDError::ArithmeticOverflow("gross stage-3 output"))?;
        let reserved_stage3_as_base = active
            .saturating_sub(1)
            .checked_mul(params.stage3.base_consumption())
            .ok_or(FaseDError::ArithmeticOverflow("stage-3 child reservations"))?;
        let allocatable_stage3 = gross_stage3 - reserved_stage3_as_base;
        Ok(Self {
            main_residual,
            gross_stage3,
            reserved_stage3_as_base,
            allocatable_stage3,
            total_allocatable: main_residual + allocatable_stage3,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaseDError {
    InvalidTuple(&'static str),
    ProductionPreflight(&'static str),
    BufferCapExceeded { requested: u64, cap: u64 },
    BatchOrder(&'static str),
    CounterUnderflow(&'static str),
    ArithmeticOverflow(&'static str),
    StageOrder(&'static str),
}

impl fmt::Display for FaseDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTuple(message) => write!(f, "invalid fase-D tuple: {message}"),
            Self::ProductionPreflight(message) => {
                write!(f, "fase-D production preflight rejected: {message}")
            }
            Self::BufferCapExceeded { requested, cap } => {
                write!(f, "prover buffer cap exceeded: requested {requested} B, cap {cap} B")
            }
            Self::BatchOrder(message) => write!(f, "invalid stage-3 batch order: {message}"),
            Self::CounterUnderflow(message) => write!(f, "fase-D counter underflow: {message}"),
            Self::ArithmeticOverflow(message) => write!(f, "fase-D arithmetic overflow: {message}"),
            Self::StageOrder(message) => write!(f, "invalid fase-D stage order: {message}"),
        }
    }
}

impl std::error::Error for FaseDError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_tuple_and_capacity_are_exact() {
        let terminal = FaseDParams::production(FaseDStagePlan::TerminalOne);
        terminal.production_preflight().unwrap();
        assert_eq!(terminal.stage3.base_consumption(), 6_521_794);
        assert_eq!(terminal.stage3.usable_output(), 110_918_718);
        assert!(terminal.stage3.usable_output() >= 110_000_000);
        assert!(terminal.stage3.base_consumption() <= terminal.main.usable_output());

        let chain = FaseDParams::production(FaseDStagePlan::ChainSix);
        let report = FaseDCapacityReport::for_params(&chain).unwrap();
        assert_eq!(report.main_residual, 3_692_373);
        assert_eq!(report.gross_stage3, 665_512_308);
        assert_eq!(report.reserved_stage3_as_base, 32_608_970);
        assert_eq!(report.allocatable_stage3, 632_903_338);
        assert_eq!(report.total_allocatable, 636_595_711);
    }

    #[test]
    fn production_preflight_rejects_all_toy_profiles_and_tuple_changes() {
        let toy = FaseDParams::test_only_insecure(FaseDStagePlan::TerminalOne);
        assert!(matches!(toy.production_preflight(), Err(FaseDError::ProductionPreflight(_))));

        let mut changed = FaseDParams::production(FaseDStagePlan::TerminalOne);
        changed.stage3.k -= 1;
        assert!(matches!(changed.production_preflight(), Err(FaseDError::ProductionPreflight(_))));
    }

    #[test]
    fn production_batches_are_exact_and_canonical() {
        let params = FaseDParams::production(FaseDStagePlan::TerminalOne);
        let batches = params.batches().unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].row_count, 58_720_256);
        assert_eq!(batches[1].row_start, 58_720_256);
        assert_eq!(batches[1].row_start + batches[1].row_count, STAGE3_N);

        let mut lift = CanonicalBatchLift::new(1, PROVER_BUFFER_CAP_BYTES);
        let base = STAGE3_BASE_CONSUMPTION as u64 * RAW_SUB_CORRELATION_BYTES;
        let output = STAGE3_USABLE_OUTPUT as u64 * RAW_SUB_CORRELATION_BYTES;
        let scratch = batches[0].row_count as u64 * GGM_NODE_BYTES_AES128;
        lift.acquire_persistent(base + output).unwrap();
        for batch in &batches {
            lift.begin_batch(*batch, scratch).unwrap();
            lift.lift_checked_batch(*batch).unwrap();
            lift.release_batch().unwrap();
        }
        let report = lift.finish(2, STAGE3_N).unwrap();
        assert_eq!(report.prover_buffer_high_water_bytes, 3_758_096_384);
        assert!(report.prover_buffer_high_water_bytes <= PROVER_BUFFER_CAP_BYTES);
    }

    #[test]
    fn buffer_cap_fails_before_allocation_and_requires_release() {
        let params = FaseDParams::test_only_insecure(FaseDStagePlan::TerminalOne);
        let batch = params.batches().unwrap()[0];
        let mut lift = CanonicalBatchLift::new(1, 100);
        assert!(matches!(lift.begin_batch(batch, 101), Err(FaseDError::BufferCapExceeded { .. })));

        let mut lift = CanonicalBatchLift::new(1, 1_000);
        lift.begin_batch(batch, 100).unwrap();
        assert!(matches!(lift.begin_batch(batch, 100), Err(FaseDError::BatchOrder(_))));
    }

    #[test]
    fn reserved_as_base_is_never_allocatable() {
        let params = FaseDParams::production(FaseDStagePlan::ChainSix);
        let mut ledger = RefillLedger::new(&params).unwrap();
        let report = FaseDCapacityReport::for_params(&params).unwrap();
        assert_eq!(ledger.allocatable(), report.total_allocatable as u64);
        assert_eq!(ledger.stages[1].reserved_as_base, STAGE3_BASE_CONSUMPTION as u64);
        for stage in ledger.stages.iter().skip(2).take(5) {
            assert_eq!(stage.reserved_as_base, STAGE3_BASE_CONSUMPTION as u64);
        }

        ledger.consume_canonical(report.total_allocatable).unwrap();
        assert_eq!(ledger.allocatable(), 0);
        assert!(ledger
            .stages
            .iter()
            .all(|stage| stage.generated == stage.consumed + stage.reserved_as_base));
        assert!(ledger.consume_canonical(1).is_err());
    }

    #[test]
    fn abort_or_close_burns_every_allocatable_residual() {
        let params = FaseDParams::test_only_insecure(FaseDStagePlan::ChainSix);
        let mut ledger = RefillLedger::new(&params).unwrap();
        ledger.consume_canonical(17).unwrap();
        ledger.burn_all_residual().unwrap();
        assert_eq!(ledger.allocatable(), 0);
        assert!(ledger.stages.iter().all(|stage| stage.available == 0 && stage.reconciles()));
    }

    #[test]
    fn canonical_batch_digest_is_schedule_deterministic() {
        fn run() -> BatchLiftReport {
            let params = FaseDParams::test_only_insecure(FaseDStagePlan::TerminalOne);
            let batches = params.batches().unwrap();
            let mut lift = CanonicalBatchLift::new(1, params.prover_buffer_cap_bytes);
            for batch in &batches {
                lift.begin_batch(*batch, 64).unwrap();
                lift.lift_checked_batch(*batch).unwrap();
                lift.release_batch().unwrap();
            }
            lift.finish(batches.len(), params.stage3.n).unwrap()
        }
        assert_eq!(run().allocation_order_digest, run().allocation_order_digest);
    }
}

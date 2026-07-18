//! Production provisioning, connection lifecycle, and response authorization.
//!
//! Role entropy is read independently for each role from [`rand::rngs::OsRng`].
//! On Linux, `rand` 0.8 obtains this randomness through the operating-system
//! `getrandom` interface. The application supplies an authenticated session
//! identity, authenticated channel identity, and verifier-issued single-use
//! response authorization nonce in [`SessionBinding`].
//!
//! [`ResponseAuthorizationStore`] implements burn-before-use: a durable,
//! append-only marker keyed only by the authorization nonce is created and
//! synced before any role entropy is sampled or any correlation is generated.
//! Markers are never deleted on success or failure. Consequently a process
//! kill, protocol abort, reconnect, retry, or resume cannot authorize a second
//! PCG session for the same response.
//!
//! [`ConnectionStore`] is the fase-D connection-level companion.  A connection
//! identity gets one append-only journal, created atomically and synced before
//! setup.  A journal can never be resumed after a process restart: reopening a
//! live journal first appends a durable terminal burn marker and then rejects
//! the caller.  Successful responses leave the connection active; every abort,
//! malformed frame, EOF, close, TTL expiry, or dropped handle burns all
//! remaining pools and reservations.

use crate::phase_b::{bind_role_entropy, expand_phase_b_bound_with_ggm_prg, GgmPrg};
use crate::{
    expand_fase_d_connection, FaseDConnectionBinding, FaseDConnectionExpansion, FaseDParams,
    FullVole, PhaseAParams, PhaseBError, PhaseBExpansion, ProverPcgPool, SessionBinding, SubVole,
    VerifierPcgPool, GAMMA,
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use volta_field::{Fp, Fp2};

const BURN_RECORD_MAGIC: &[u8] = b"VOLTA-PCG-AUTH-BURN-v1\n";
const CONNECTION_RECORD_MAGIC: &[u8] = b"VOLTA-PCG-CONNECTION-v1\n";
const CORRELATION_SPOOL_ENTRY_BYTES: usize = 5 * std::mem::size_of::<u64>();
const CORRELATION_SPOOL_CHUNK_ENTRIES: usize = 1 << 16;
static CORRELATION_SPOOL_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct ResponseAuthorizationStore {
    root: PathBuf,
}

/// Evidence that the response authorization was durably burned before setup.
#[derive(Clone, Debug)]
pub struct AuthorizationBurn {
    marker_path: PathBuf,
    pub record_digest: String,
}

impl AuthorizationBurn {
    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }
}

/// Connection-lifecycle name for the preregistered fase-D expansion plan.
pub type ConnectionStagePlan = crate::fase_d::FaseDStagePlan;

fn connection_stage_plan_record(plan: ConnectionStagePlan) -> &'static str {
    match plan {
        ConnectionStagePlan::TerminalOne => "terminal-one",
        ConnectionStagePlan::ChainSix => "chain-six",
    }
}

/// Public identities fixed when a connection is opened.  The authenticated
/// channel identity is a transport exporter or equivalent authenticated
/// binding, never a peer-selected display name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionBinding {
    pub connection_id: [u8; 32],
    pub authenticated_channel_id: [u8; 32],
    pub stage_plan: ConnectionStagePlan,
}

impl ConnectionBinding {
    pub fn new(
        connection_id: [u8; 32],
        authenticated_channel_id: [u8; 32],
        stage_plan: ConnectionStagePlan,
    ) -> Result<Self, PhaseBError> {
        if connection_id == [0; 32] || authenticated_channel_id == [0; 32] {
            return Err(PhaseBError::new(
                "connection and authenticated-channel identities must be nonzero",
            ));
        }
        Ok(Self { connection_id, authenticated_channel_id, stage_plan })
    }

    /// Construct the existing response binding without changing its
    /// burn-before-use semantics.
    pub fn response_binding(
        &self,
        response_authorization_nonce: [u8; 32],
    ) -> Result<SessionBinding, PhaseBError> {
        SessionBinding::new(
            self.connection_id,
            self.authenticated_channel_id,
            response_authorization_nonce,
        )
    }

    pub fn digest_hex(&self) -> String {
        hex32(self.digest())
    }

    fn digest(&self) -> [u8; 32] {
        digest_parts(
            b"volta-pcg/connection-binding/v1",
            &[
                &self.connection_id,
                &self.authenticated_channel_id,
                connection_stage_plan_record(self.stage_plan).as_bytes(),
            ],
        )
    }
}

/// Terminal causes are deliberately explicit in the durable journal.  All
/// variants have the same state-machine effect: the entire connection and
/// every remaining or reserved correlation become permanently unusable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionAbortReason {
    MaliciousCheckFailure,
    MalformedFrame,
    UnexpectedEof,
    ProcessKillOrRestart,
    ExplicitAbort,
    ProtocolError,
    AuthorizationFailure,
    DurableStoreFailure,
    ExplicitClose,
    TtlExpired,
}

impl ConnectionAbortReason {
    fn as_record(self) -> &'static str {
        match self {
            Self::MaliciousCheckFailure => "malicious-check-failure",
            Self::MalformedFrame => "malformed-frame",
            Self::UnexpectedEof => "unexpected-eof",
            Self::ProcessKillOrRestart => "process-kill-or-restart",
            Self::ExplicitAbort => "explicit-abort",
            Self::ProtocolError => "protocol-error",
            Self::AuthorizationFailure => "authorization-failure",
            Self::DurableStoreFailure => "durable-store-failure",
            Self::ExplicitClose => "explicit-close",
            Self::TtlExpired => "ttl-expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ConnectionState {
    Open,
    Active,
    Terminal { reason: ConnectionAbortReason },
}

/// Mutually exclusive accounting classes for one expansion stage.
///
/// `generated = consumed + reserved_as_base + burned + available` is checked
/// after every transition.  `base_inputs_consumed` belongs to the child stage
/// and records how many outputs of its predecessor were dedicated to creating
/// it.  Reserved values never return to `available` and are therefore never
/// response-allocatable; at terminal state they remain in the reserved class
/// for provenance but are semantically burned with the connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StageCorrelationCounters {
    pub generated: u64,
    pub consumed: u64,
    pub reserved_as_base: u64,
    pub burned: u64,
    pub available: u64,
    pub base_inputs_consumed: u64,
}

impl StageCorrelationCounters {
    pub fn reconciled(&self) -> bool {
        self.consumed
            .checked_add(self.reserved_as_base)
            .and_then(|value| value.checked_add(self.burned))
            .and_then(|value| value.checked_add(self.available))
            == Some(self.generated)
    }

    pub fn terminally_unusable(&self) -> u64 {
        self.burned.saturating_add(self.reserved_as_base)
    }
}

/// Full logical allocation domain.  Logical allocation and its digest are
/// independent of the configured GGM PRG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CorrelationDomain {
    pub connection_id: [u8; 32],
    pub response_nonce: [u8; 32],
    pub layer: u32,
    pub head: u32,
    pub position: u64,
    pub tensor_tag: [u8; 32],
}

impl CorrelationDomain {
    pub fn new(
        connection_id: [u8; 32],
        response_nonce: [u8; 32],
        layer: u32,
        head: u32,
        position: u64,
        tensor_tag: [u8; 32],
    ) -> Result<Self, PhaseBError> {
        if connection_id == [0; 32] || response_nonce == [0; 32] || tensor_tag == [0; 32] {
            return Err(PhaseBError::new(
                "connection, response, and tensor-tag domain components must be nonzero",
            ));
        }
        Ok(Self { connection_id, response_nonce, layer, head, position, tensor_tag })
    }

    pub fn digest_hex(&self) -> String {
        hex32(self.digest())
    }

    fn digest(&self) -> [u8; 32] {
        digest_parts(
            b"volta-pcg/connection-correlation-domain/v1",
            &[
                &self.connection_id,
                &self.response_nonce,
                &self.layer.to_le_bytes(),
                &self.head.to_le_bytes(),
                &self.position.to_le_bytes(),
                &self.tensor_tag,
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionChannelDirection {
    ProverToVerifier,
    VerifierToProver,
}

impl ConnectionChannelDirection {
    fn as_byte(self) -> u8 {
        match self {
            Self::ProverToVerifier => 0,
            Self::VerifierToProver => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CorrelationAllocation {
    pub stage: u32,
    pub start: u64,
    pub count: u64,
    pub domain_digest: String,
    pub connection_allocation_digest: String,
    pub response_allocation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BaseCorrelationReservation {
    pub stage: u32,
    pub start: u64,
    pub count: u64,
    pub connection_allocation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionResponseAudit {
    pub response_nonce_digest: String,
    pub allocation_digest: String,
    pub channel_ledger_digest: String,
    pub correlations_consumed: u64,
    pub channel_frames: u64,
}

#[derive(Clone, Debug)]
struct ActiveConnectionResponse {
    nonce: [u8; 32],
    nonce_digest: [u8; 32],
    allocation_digest: [u8; 32],
    channel_digest: [u8; 32],
    correlations_consumed: u64,
    channel_frames: u64,
}

/// Directory containing one immutable-name, append-only journal per
/// connection identity.
#[derive(Clone, Debug)]
pub struct ConnectionStore {
    root: PathBuf,
}

/// Live connection state.  It cannot be reconstructed from a journal: a
/// restart is terminal by design and must use a fresh connection identity.
#[derive(Debug)]
pub struct ConnectionHandle {
    root: PathBuf,
    journal_path: PathBuf,
    journal: File,
    binding: ConnectionBinding,
    state: ConnectionState,
    expires_at: Option<SystemTime>,
    active_response: Option<ActiveConnectionResponse>,
    completed_responses: u64,
    stages: BTreeMap<u32, StageCorrelationCounters>,
    activated_base_inputs: BTreeMap<u32, u64>,
    allocated_domains: HashSet<[u8; 32]>,
    allocation_digest: [u8; 32],
    channel_digest: [u8; 32],
    terminal_active_nonce_digest: Option<[u8; 32]>,
    terminal_record_synced: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductionSetupAudit {
    pub entropy_source: String,
    pub independent_role_entropy_samples: bool,
    pub prover_role_seed_commitment: String,
    pub verifier_role_seed_commitment: String,
    pub role_seed_commitments_distinct: bool,
    pub session_channel_identity_bound: bool,
    pub session_binding_digest: String,
    pub response_authorization_burned_before_setup: bool,
    pub response_authorization_burn_record_digest: String,
    pub burn_on_success_or_abort: bool,
    pub reconnect_retry_resume_allowed: bool,
}

#[derive(Debug)]
pub struct ProductionPhaseBExpansion {
    pub expansion: PhaseBExpansion,
    pub production: ProductionSetupAudit,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductionConnectionSetupAudit {
    pub entropy_source: String,
    pub independent_role_entropy_samples: bool,
    pub prover_role_seed_commitment: String,
    pub verifier_role_seed_commitment: String,
    pub role_seed_commitments_distinct: bool,
    pub connection_identity_bound: bool,
    pub authenticated_channel_identity_bound: bool,
    pub durable_connection_open_before_entropy: bool,
    pub one_base_ot_copee_iknp_phase: bool,
    pub ggm_prg: GgmPrg,
    pub pcg_production_ready: bool,
}

/// Live production object: dropping it terminally burns the journal through
/// `ConnectionHandle::drop`.  Successful responses mutate only `connection`;
/// `expansion` owns the one connection-scoped Delta and correlation pools.
#[derive(Debug)]
pub struct ProductionFaseDConnection {
    pub connection: ConnectionHandle,
    pub expansion: FaseDConnectionExpansion,
    pub production: ProductionConnectionSetupAudit,
    correlation_spool: Option<ConnectionCorrelationSpool>,
    pub correlation_spool_audit: Option<CorrelationSpoolAudit>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CorrelationSpoolAudit {
    pub storage: String,
    pub entries: u64,
    pub bytes: u64,
    pub chunk_entries: usize,
    pub resident_raw_entries_after_spool: u64,
    pub write_wall_s: f64,
    pub digest: String,
}

#[derive(Debug)]
struct ConnectionCorrelationSpool {
    file: File,
    entries: usize,
}

#[cfg(target_os = "linux")]
fn discard_spool_page_cache(file: &File, offset: u64, len: u64) -> Result<(), PhaseBError> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    }
    const POSIX_FADV_DONTNEED: i32 = 4;
    let offset = i64::try_from(offset)
        .map_err(|_| PhaseBError::new("PCG spool cache-discard offset exceeds i64"))?;
    let len = i64::try_from(len)
        .map_err(|_| PhaseBError::new("PCG spool cache-discard length exceeds i64"))?;
    // SAFETY: the descriptor remains owned by `file`; this call only provides
    // a reclaim hint for the specified valid byte range and does not alter it.
    let status = unsafe { posix_fadvise(file.as_raw_fd(), offset, len, POSIX_FADV_DONTNEED) };
    if status == 0 {
        Ok(())
    } else {
        Err(PhaseBError::new(format!("cannot discard PCG spool page cache: OS error {status}")))
    }
}

#[cfg(not(target_os = "linux"))]
fn discard_spool_page_cache(_file: &File, _offset: u64, _len: u64) -> Result<(), PhaseBError> {
    Ok(())
}

pub struct AllocatedSubCorrelationBatch<'a> {
    pub allocation: CorrelationAllocation,
    pub prover: &'a [SubVole],
    pub verifier_keys: &'a [volta_field::Fp2],
    pub verifier_delta: volta_field::Fp2,
}

#[derive(Debug)]
pub struct AllocatedPcgPools {
    pub allocation: CorrelationAllocation,
    pub prover: ProverPcgPool,
    pub verifier: VerifierPcgPool,
    pub verifier_delta: volta_field::Fp2,
}

impl ConnectionCorrelationSpool {
    fn create(
        prover: &[SubVole],
        verifier_keys: &[Fp2],
    ) -> Result<(Self, CorrelationSpoolAudit), PhaseBError> {
        if prover.len() != verifier_keys.len() || prover.is_empty() {
            return Err(PhaseBError::new("invalid connection correlation spool geometry"));
        }
        let started = Instant::now();
        let directory = std::env::var_os("VOLTA_PCG_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&directory).map_err(|error| {
            PhaseBError::new(format!(
                "cannot create PCG spool directory {}: {error}",
                directory.display()
            ))
        })?;
        let nonce = CORRELATION_SPOOL_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".volta-pcg-{}-{nonce}.spool", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|error| {
            PhaseBError::new(format!("cannot create anonymous PCG spool: {error}"))
        })?;
        if let Err(error) = std::fs::remove_file(&path) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(PhaseBError::new(format!(
                "cannot unlink anonymous PCG spool {}: {error}",
                path.display()
            )));
        }
        let bytes = prover
            .len()
            .checked_mul(CORRELATION_SPOOL_ENTRY_BYTES)
            .ok_or_else(|| PhaseBError::new("PCG spool size overflow"))?;
        file.set_len(
            u64::try_from(bytes).map_err(|_| PhaseBError::new("PCG spool size exceeds u64"))?,
        )
        .map_err(|error| PhaseBError::new(format!("cannot size PCG spool: {error}")))?;
        let mut digest = blake3::Hasher::new_derive_key("volta/pcg/connection-spool/v1");
        let mut encoded =
            Vec::with_capacity(CORRELATION_SPOOL_CHUNK_ENTRIES * CORRELATION_SPOOL_ENTRY_BYTES);
        for start in (0..prover.len()).step_by(CORRELATION_SPOOL_CHUNK_ENTRIES) {
            let end = (start + CORRELATION_SPOOL_CHUNK_ENTRIES).min(prover.len());
            encoded.clear();
            for (value, key) in prover[start..end].iter().zip(&verifier_keys[start..end]) {
                for limb in [
                    value.r.value(),
                    value.m.c0.value(),
                    value.m.c1.value(),
                    key.c0.value(),
                    key.c1.value(),
                ] {
                    encoded.extend_from_slice(&limb.to_le_bytes());
                }
            }
            digest.update(&encoded);
            file.write_all(&encoded)
                .map_err(|error| PhaseBError::new(format!("cannot write PCG spool: {error}")))?;
        }
        file.sync_data()
            .map_err(|error| PhaseBError::new(format!("cannot sync PCG spool: {error}")))?;
        let bytes_u64 =
            u64::try_from(bytes).map_err(|_| PhaseBError::new("PCG spool size exceeds u64"))?;
        discard_spool_page_cache(&file, 0, bytes_u64)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| PhaseBError::new(format!("cannot rewind PCG spool: {error}")))?;
        let audit = CorrelationSpoolAudit {
            storage: "unlinked-0600-file; connection-scoped; range-read only; page-cache discarded"
                .into(),
            entries: u64::try_from(prover.len())
                .map_err(|_| PhaseBError::new("PCG spool entries exceed u64"))?,
            bytes: bytes_u64,
            chunk_entries: CORRELATION_SPOOL_CHUNK_ENTRIES,
            resident_raw_entries_after_spool: 0,
            write_wall_s: started.elapsed().as_secs_f64(),
            digest: digest.finalize().to_hex().to_string(),
        };
        Ok((Self { file, entries: prover.len() }, audit))
    }

    fn allocate(
        &mut self,
        start: usize,
        sub_corrs: usize,
        full_corrs: usize,
    ) -> Result<(ProverPcgPool, VerifierPcgPool), PhaseBError> {
        let raw_count = sub_corrs
            .checked_add(
                full_corrs
                    .checked_mul(2)
                    .ok_or_else(|| PhaseBError::new("full-correlation raw count overflow"))?,
            )
            .ok_or_else(|| PhaseBError::new("response raw-correlation count overflow"))?;
        let end = start
            .checked_add(raw_count)
            .ok_or_else(|| PhaseBError::new("PCG spool range overflow"))?;
        if end > self.entries {
            return Err(PhaseBError::new("PCG spool allocation exceeds retained capacity"));
        }
        let byte_start = start
            .checked_mul(CORRELATION_SPOOL_ENTRY_BYTES)
            .ok_or_else(|| PhaseBError::new("PCG spool byte offset overflow"))?;
        self.file
            .seek(SeekFrom::Start(
                u64::try_from(byte_start)
                    .map_err(|_| PhaseBError::new("PCG spool byte offset exceeds u64"))?,
            ))
            .map_err(|error| PhaseBError::new(format!("cannot seek PCG spool: {error}")))?;

        let mut prover = ProverPcgPool {
            subs: Vec::with_capacity(sub_corrs),
            fulls: Vec::with_capacity(full_corrs),
        };
        let mut verifier = VerifierPcgPool {
            sub_keys: Vec::with_capacity(sub_corrs),
            full_keys: Vec::with_capacity(full_corrs),
        };
        let mut pending_full: Option<(SubVole, Fp2)> = None;
        let mut consumed = 0usize;
        let mut encoded = Vec::new();
        while consumed < raw_count {
            let entries = (raw_count - consumed).min(CORRELATION_SPOOL_CHUNK_ENTRIES);
            encoded.resize(entries * CORRELATION_SPOOL_ENTRY_BYTES, 0);
            self.file
                .read_exact(&mut encoded)
                .map_err(|error| PhaseBError::new(format!("cannot read PCG spool: {error}")))?;
            for record in encoded.chunks_exact(CORRELATION_SPOOL_ENTRY_BYTES) {
                let word = |index: usize| {
                    let offset = index * 8;
                    u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap())
                };
                let raw = SubVole {
                    r: Fp::new(word(0)),
                    m: Fp2::new(Fp::new(word(1)), Fp::new(word(2))),
                };
                let key = Fp2::new(Fp::new(word(3)), Fp::new(word(4)));
                let index = consumed;
                consumed += 1;
                if index < sub_corrs {
                    prover.subs.push(raw);
                    verifier.sub_keys.push(key);
                } else if let Some((lo, key_lo)) = pending_full.take() {
                    prover.fulls.push(FullVole {
                        x: Fp2::from_base(lo.r) + GAMMA.mul_base(raw.r),
                        m: lo.m + GAMMA * raw.m,
                    });
                    verifier.full_keys.push(key_lo + GAMMA * key);
                } else {
                    pending_full = Some((raw, key));
                }
            }
        }
        if pending_full.is_some()
            || prover.subs.len() != sub_corrs
            || prover.fulls.len() != full_corrs
            || verifier.sub_keys.len() != sub_corrs
            || verifier.full_keys.len() != full_corrs
        {
            return Err(PhaseBError::new("PCG spool allocation shape mismatch"));
        }
        let range_bytes = raw_count
            .checked_mul(CORRELATION_SPOOL_ENTRY_BYTES)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| PhaseBError::new("PCG spool range byte length overflow"))?;
        discard_spool_page_cache(
            &self.file,
            u64::try_from(byte_start)
                .map_err(|_| PhaseBError::new("PCG spool byte offset exceeds u64"))?,
            range_bytes,
        )?;
        Ok((prover, verifier))
    }
}

impl ProductionFaseDConnection {
    /// Move the terminal-one raw pool out of heap memory before PCS scratch
    /// exists. The backing file is mode 0600 and unlinked immediately, so it
    /// is connection-scoped and cannot be reopened by name. Logical stage
    /// allocation, domains, Delta and lifecycle accounting are unchanged.
    pub fn spool_terminal_one_correlations(
        &mut self,
    ) -> Result<CorrelationSpoolAudit, PhaseBError> {
        if let Some(audit) = &self.correlation_spool_audit {
            return Ok(audit.clone());
        }
        if self.expansion.params.plan != crate::FaseDStagePlan::TerminalOne
            || !self.expansion.prover.fulls.is_empty()
            || !self.expansion.verifier.full_keys.is_empty()
            || self.expansion.prover.subs.len() != self.expansion.capacity.total_allocatable
            || self.expansion.verifier.sub_keys.len() != self.expansion.capacity.total_allocatable
        {
            self.connection.abort(ConnectionAbortReason::ProtocolError)?;
            return Err(PhaseBError::new("only a complete terminal-one raw pool can be spooled"));
        }
        let prover = std::mem::take(&mut self.expansion.prover.subs);
        let verifier = std::mem::take(&mut self.expansion.verifier.sub_keys);
        let created = ConnectionCorrelationSpool::create(&prover, &verifier);
        drop(prover);
        drop(verifier);
        let (spool, audit) = match created {
            Ok(value) => value,
            Err(error) => {
                let _ = self.connection.abort(ConnectionAbortReason::DurableStoreFailure);
                return Err(error);
            }
        };
        self.correlation_spool = Some(spool);
        self.correlation_spool_audit = Some(audit.clone());
        Ok(audit)
    }

    /// Allocate canonical raw stage output and convert the requested tail
    /// pairs into full `F_p²` correlations without changing logical order.
    pub fn allocate_pcg_pools(
        &mut self,
        stage: u32,
        sub_corrs: usize,
        full_corrs: usize,
        domain: CorrelationDomain,
    ) -> Result<AllocatedPcgPools, PhaseBError> {
        let raw_count = sub_corrs
            .checked_add(
                full_corrs
                    .checked_mul(2)
                    .ok_or_else(|| PhaseBError::new("full-correlation raw count overflow"))?,
            )
            .ok_or_else(|| PhaseBError::new("response raw-correlation count overflow"))?;
        let raw_count_u64 = u64::try_from(raw_count)
            .map_err(|_| PhaseBError::new("response raw-correlation count exceeds u64"))?;
        if self.correlation_spool.is_some() {
            let allocation = self.connection.allocate(stage, raw_count_u64, domain)?;
            let stage_offset = match stage {
                0 => 0usize,
                1 => self.expansion.capacity.main_residual,
                _ => {
                    self.connection.abort(ConnectionAbortReason::ProtocolError)?;
                    return Err(PhaseBError::new(
                        "terminal-one connection has only main and stage-1 pools",
                    ));
                }
            };
            let local = usize::try_from(allocation.start)
                .map_err(|_| PhaseBError::new("allocation start exceeds usize"))?;
            let start = stage_offset
                .checked_add(local)
                .ok_or_else(|| PhaseBError::new("connection spool offset overflow"))?;
            let loaded = self
                .correlation_spool
                .as_mut()
                .expect("spool presence checked")
                .allocate(start, sub_corrs, full_corrs);
            let (prover, verifier) = match loaded {
                Ok(value) => value,
                Err(error) => {
                    let _ = self.connection.abort(ConnectionAbortReason::ProtocolError);
                    return Err(error);
                }
            };
            return Ok(AllocatedPcgPools {
                allocation,
                prover,
                verifier,
                verifier_delta: self.expansion.verifier_delta,
            });
        }
        let batch = self.allocate_sub_correlations(stage, raw_count_u64, domain)?;
        let mut prover = ProverPcgPool {
            subs: batch.prover[..sub_corrs].to_vec(),
            fulls: Vec::with_capacity(full_corrs),
        };
        let mut verifier = VerifierPcgPool {
            sub_keys: batch.verifier_keys[..sub_corrs].to_vec(),
            full_keys: Vec::with_capacity(full_corrs),
        };
        for index in 0..full_corrs {
            let lo = sub_corrs + 2 * index;
            let hi = lo + 1;
            prover.fulls.push(FullVole {
                x: volta_field::Fp2::from_base(batch.prover[lo].r)
                    + GAMMA.mul_base(batch.prover[hi].r),
                m: batch.prover[lo].m + GAMMA * batch.prover[hi].m,
            });
            verifier.full_keys.push(batch.verifier_keys[lo] + GAMMA * batch.verifier_keys[hi]);
        }
        Ok(AllocatedPcgPools {
            allocation: batch.allocation,
            prover,
            verifier,
            verifier_delta: batch.verifier_delta,
        })
    }

    /// Allocate a terminal-one raw sub-correlation range and bind it to the
    /// active response domain.  The returned slices borrow the connection, so
    /// callers cannot finish/abort the response while using them.
    pub fn allocate_sub_correlations<'a>(
        &'a mut self,
        stage: u32,
        count: u64,
        domain: CorrelationDomain,
    ) -> Result<AllocatedSubCorrelationBatch<'a>, PhaseBError> {
        if self.expansion.params.plan != crate::FaseDStagePlan::TerminalOne {
            self.connection.abort(ConnectionAbortReason::ProtocolError)?;
            return Err(PhaseBError::new(
                "digest-and-release chain-six connection has no response-allocatable flat pool",
            ));
        }
        let allocation = self.connection.allocate(stage, count, domain)?;
        let stage_offset = match stage {
            0 => 0usize,
            1 => self.expansion.capacity.main_residual,
            _ => {
                self.connection.abort(ConnectionAbortReason::ProtocolError)?;
                return Err(PhaseBError::new(
                    "terminal-one connection has only main and stage-1 pools",
                ));
            }
        };
        let local = usize::try_from(allocation.start)
            .map_err(|_| PhaseBError::new("allocation start exceeds usize"))?;
        let count = usize::try_from(allocation.count)
            .map_err(|_| PhaseBError::new("allocation count exceeds usize"))?;
        let start = stage_offset
            .checked_add(local)
            .ok_or_else(|| PhaseBError::new("connection pool offset overflow"))?;
        let end = start
            .checked_add(count)
            .ok_or_else(|| PhaseBError::new("connection pool range overflow"))?;
        if end > self.expansion.prover.subs.len() || end > self.expansion.verifier.sub_keys.len() {
            self.connection.abort(ConnectionAbortReason::ProtocolError)?;
            return Err(PhaseBError::new("connection allocation exceeds retained crypto pool"));
        }
        Ok(AllocatedSubCorrelationBatch {
            allocation,
            prover: &self.expansion.prover.subs[start..end],
            verifier_keys: &self.expansion.verifier.sub_keys[start..end],
            verifier_delta: self.expansion.verifier_delta,
        })
    }
}

impl ResponseAuthorizationStore {
    /// Open or create the append-only burn directory. Production deployments
    /// must place it on storage whose durability matches the authorization
    /// service; an unavailable or read-only store fails capability preflight.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PhaseBError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| {
            PhaseBError::new(format!(
                "cannot create response-authorization burn store {}: {error}",
                root.display()
            ))
        })?;
        if !root.is_dir() {
            return Err(PhaseBError::new(format!(
                "response-authorization burn store is not a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Permanently reserve-and-burn an authorization nonce. The marker name is
    /// a nonce-only digest, so reuse is rejected even if a reconnect changes
    /// the claimed session or channel identity. `create_new` is the atomic
    /// concurrency boundary; the file and containing directory are synced
    /// before setup may proceed.
    pub fn reserve(&self, binding: &SessionBinding) -> Result<AuthorizationBurn, PhaseBError> {
        let nonce_digest = digest_parts(
            b"volta-pcg/authorization-nonce/v1",
            &[&binding.response_authorization_nonce],
        );
        let marker_path = self.root.join(format!("{}.burned", hex32(nonce_digest)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&marker_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PhaseBError::new("response-authorization nonce already burned; retry rejected")
            } else {
                PhaseBError::new(format!(
                    "cannot burn response authorization in {}: {error}",
                    marker_path.display()
                ))
            }
        })?;

        let binding_digest = binding.digest_hex();
        let mut record = Vec::with_capacity(BURN_RECORD_MAGIC.len() + binding_digest.len() + 1);
        record.extend_from_slice(BURN_RECORD_MAGIC);
        record.extend_from_slice(binding_digest.as_bytes());
        record.push(b'\n');
        // Once create_new succeeds the nonce is already fail-closed burned.
        // Any later I/O error is returned, but the marker is intentionally not
        // removed and a retry remains forbidden.
        file.write_all(&record).map_err(|error| {
            PhaseBError::new(format!("cannot persist response-authorization burn record: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            PhaseBError::new(format!("cannot sync response-authorization burn record: {error}"))
        })?;
        File::open(&self.root).and_then(|directory| directory.sync_all()).map_err(|error| {
            PhaseBError::new(format!("cannot sync response-authorization burn directory: {error}"))
        })?;

        Ok(AuthorizationBurn {
            marker_path,
            record_digest: hex32(digest_parts(
                b"volta-pcg/authorization-burn-record/v1",
                &[&record],
            )),
        })
    }
}

impl ConnectionStore {
    /// Open or create the durable connection-journal directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PhaseBError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| {
            PhaseBError::new(format!("cannot create connection store {}: {error}", root.display()))
        })?;
        if !root.is_dir() {
            return Err(PhaseBError::new(format!(
                "connection store is not a directory: {}",
                root.display()
            )));
        }
        sync_directory(&root, "connection store")?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Atomically create a fresh connection journal.  An existing journal is
    /// never resumed.  If it lacks a terminal record (the previous process
    /// died), this call durably appends the process-kill burn before returning
    /// an error.  The caller must reconnect with a new `connection_id`.
    pub fn create(
        &self,
        binding: ConnectionBinding,
        ttl: Option<Duration>,
    ) -> Result<ConnectionHandle, PhaseBError> {
        let expires_at = match ttl {
            Some(ttl) => Some(
                SystemTime::now()
                    .checked_add(ttl)
                    .ok_or_else(|| PhaseBError::new("connection TTL overflows system time"))?,
            ),
            None => None,
        };
        let id_digest =
            digest_parts(b"volta-pcg/connection-journal-name/v1", &[&binding.connection_id]);
        let journal_path = self.root.join(format!("{}.connection", hex32(id_digest)));
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut journal = match options.open(&journal_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let was_terminal = journal_contains_terminal(&journal_path).unwrap_or(false);
                if !was_terminal {
                    burn_existing_journal(
                        &self.root,
                        &journal_path,
                        ConnectionAbortReason::ProcessKillOrRestart,
                    )?;
                }
                return Err(PhaseBError::new(if was_terminal {
                    "connection identity is terminally burned; resume rejected"
                } else {
                    "connection restart burned the prior connection; resume rejected"
                }));
            }
            Err(error) => {
                return Err(PhaseBError::new(format!(
                    "cannot create connection journal {}: {error}",
                    journal_path.display()
                )))
            }
        };

        let expires_ms = expires_at
            .and_then(|deadline| deadline.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().to_string())
            .unwrap_or_else(|| "none".into());
        let binding_digest = binding.digest();
        let allocation_digest =
            digest_parts(b"volta-pcg/connection-allocation-ledger/v1", &[&binding_digest]);
        let channel_digest =
            digest_parts(b"volta-pcg/connection-channel-ledger/v1", &[&binding_digest]);
        let open_record = format!(
            "OPEN|{}|{}|{}|{}|{}|{}|{}\n",
            hex32(binding.connection_id),
            hex32(binding.authenticated_channel_id),
            hex32(binding_digest),
            connection_stage_plan_record(binding.stage_plan),
            expires_ms,
            hex32(allocation_digest),
            hex32(channel_digest)
        );
        let mut bytes = Vec::with_capacity(CONNECTION_RECORD_MAGIC.len() + open_record.len());
        bytes.extend_from_slice(CONNECTION_RECORD_MAGIC);
        bytes.extend_from_slice(open_record.as_bytes());
        // Once create_new succeeds the identity is permanently reserved.  A
        // partial write is not removed; the next create attempt crash-burns it.
        journal.write_all(&bytes).map_err(|error| {
            PhaseBError::new(format!("cannot persist connection-open record: {error}"))
        })?;
        journal.sync_all().map_err(|error| {
            PhaseBError::new(format!("cannot sync connection-open record: {error}"))
        })?;
        sync_directory(&self.root, "connection store")?;

        Ok(ConnectionHandle {
            root: self.root.clone(),
            journal_path,
            journal,
            binding,
            state: ConnectionState::Open,
            expires_at,
            active_response: None,
            completed_responses: 0,
            stages: BTreeMap::new(),
            activated_base_inputs: BTreeMap::new(),
            allocated_domains: HashSet::new(),
            allocation_digest,
            channel_digest,
            terminal_active_nonce_digest: None,
            terminal_record_synced: false,
        })
    }
}

impl ConnectionHandle {
    pub fn binding(&self) -> ConnectionBinding {
        self.binding
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn completed_responses(&self) -> u64 {
        self.completed_responses
    }

    pub fn stage_counters(&self) -> &BTreeMap<u32, StageCorrelationCounters> {
        &self.stages
    }

    pub fn allocation_digest_hex(&self) -> String {
        hex32(self.allocation_digest)
    }

    pub fn channel_ledger_digest_hex(&self) -> String {
        hex32(self.channel_digest)
    }

    /// Mark completion of the one connection-scoped base OT + COPEe phase.
    /// The caller supplies a public transcript digest, never `Delta`, a
    /// Delta-equivalent, or either role seed.  A second activation is fatal.
    pub fn activate(&mut self, base_phase_digest: [u8; 32]) -> Result<(), PhaseBError> {
        self.ensure_live()?;
        if self.state != ConnectionState::Open || base_phase_digest == [0; 32] {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "connection base phase may be activated exactly once with a nonzero digest",
            );
        }
        let record = format!("ACTIVE|{}\n", hex32(base_phase_digest));
        self.append_or_burn(&record)?;
        self.state = ConnectionState::Active;
        Ok(())
    }

    /// Register the initial checked stage output.  Later stages must use
    /// [`Self::register_refill_stage`] so one reserved range cannot seed two
    /// expansions.
    pub fn register_stage_output(
        &mut self,
        stage: u32,
        generated: u64,
        base_inputs_consumed: u64,
    ) -> Result<(), PhaseBError> {
        self.ensure_active()?;
        if stage != 0 && base_inputs_consumed != 0 {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "non-initial stage base inputs must come from a tracked reservation",
            );
        }
        self.register_stage_output_inner(stage, generated, base_inputs_consumed)
    }

    /// Consume a previously reserved range exactly once and register the
    /// checked child-stage output.  `reserved_as_base` remains a provenance
    /// class on the source stage and can never become response-available.
    pub fn register_refill_stage(
        &mut self,
        source_stage: u32,
        stage: u32,
        generated: u64,
        base_inputs_consumed: u64,
    ) -> Result<(), PhaseBError> {
        self.ensure_active()?;
        if base_inputs_consumed == 0 || source_stage == stage {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "refill stages require nonzero base inputs from a distinct source stage",
            );
        }
        let source = match self.stages.get(&source_stage).copied() {
            Some(counters) => counters,
            None => {
                return self
                    .fail(ConnectionAbortReason::ProtocolError, "refill source stage is unknown")
            }
        };
        let already_activated = self.activated_base_inputs.get(&source_stage).copied().unwrap_or(0);
        let activated_after = already_activated
            .checked_add(base_inputs_consumed)
            .ok_or_else(|| PhaseBError::new("activated base-input counter overflow"))?;
        if activated_after > source.reserved_as_base {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "refill would reuse or exceed reserved base correlations",
            );
        }
        self.register_stage_output_inner(stage, generated, base_inputs_consumed)?;
        self.activated_base_inputs.insert(source_stage, activated_after);
        self.allocation_digest = digest_parts(
            b"volta-pcg/connection-allocation-chain/base-input-consumed/v1",
            &[
                &self.allocation_digest,
                &source_stage.to_le_bytes(),
                &stage.to_le_bytes(),
                &base_inputs_consumed.to_le_bytes(),
                &activated_after.to_le_bytes(),
            ],
        );
        let record = format!(
            "BASE_INPUTS_CONSUMED|{}|{}|{}|{}|{}\n",
            source_stage,
            stage,
            base_inputs_consumed,
            activated_after,
            hex32(self.allocation_digest)
        );
        self.append_or_burn(&record)
    }

    fn register_stage_output_inner(
        &mut self,
        stage: u32,
        generated: u64,
        base_inputs_consumed: u64,
    ) -> Result<(), PhaseBError> {
        if self.active_response.is_some() || generated == 0 || self.stages.contains_key(&stage) {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "stage output must be nonzero, uniquely numbered, and registered between responses",
            );
        }
        let counters = StageCorrelationCounters {
            generated,
            available: generated,
            base_inputs_consumed,
            ..StageCorrelationCounters::default()
        };
        debug_assert!(counters.reconciled());
        self.stages.insert(stage, counters);
        self.allocation_digest = digest_parts(
            b"volta-pcg/connection-allocation-chain/stage/v1",
            &[
                &self.allocation_digest,
                &stage.to_le_bytes(),
                &generated.to_le_bytes(),
                &base_inputs_consumed.to_le_bytes(),
            ],
        );
        let record = format!(
            "STAGE|{}|{}|{}|{}\n",
            stage,
            generated,
            base_inputs_consumed,
            hex32(self.allocation_digest)
        );
        self.append_or_burn(&record)
    }

    /// Permanently take a high-end canonical range out of the response pool
    /// for a later stage.  The receipt cannot be passed to `allocate`.
    pub fn reserve_as_base(
        &mut self,
        stage: u32,
        count: u64,
    ) -> Result<BaseCorrelationReservation, PhaseBError> {
        self.ensure_active()?;
        if self.active_response.is_some() || count == 0 {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "base reservations must be nonzero and occur between responses",
            );
        }
        let current = match self.stages.get(&stage).copied() {
            Some(counters) => counters,
            None => {
                return self.fail(
                    ConnectionAbortReason::ProtocolError,
                    "cannot reserve from an unknown stage",
                )
            }
        };
        if count > current.available {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "base reservation exceeds available stage correlations",
            );
        }
        let reserved_after = current
            .reserved_as_base
            .checked_add(count)
            .ok_or_else(|| PhaseBError::new("reserved-as-base counter overflow"))?;
        let start = current
            .generated
            .checked_sub(reserved_after)
            .ok_or_else(|| PhaseBError::new("reserved-as-base range underflow"))?;
        if start < current.consumed {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "base reservation overlaps an allocated response range",
            );
        }
        let mut updated = current;
        updated.reserved_as_base = reserved_after;
        updated.available -= count;
        debug_assert!(updated.reconciled());
        self.stages.insert(stage, updated);
        self.allocation_digest = digest_parts(
            b"volta-pcg/connection-allocation-chain/reserved-as-base/v1",
            &[
                &self.allocation_digest,
                &stage.to_le_bytes(),
                &start.to_le_bytes(),
                &count.to_le_bytes(),
            ],
        );
        let record = format!(
            "RESERVED_AS_BASE|{}|{}|{}|{}\n",
            stage,
            start,
            count,
            hex32(self.allocation_digest)
        );
        self.append_or_burn(&record)?;
        Ok(BaseCorrelationReservation {
            stage,
            start,
            count,
            connection_allocation_digest: hex32(self.allocation_digest),
        })
    }

    /// Permanently discard checked stage output that was intentionally not
    /// retained (the chain-six digest-and-release path).  Discarded values
    /// enter the `burned` counter class and can never be allocated later.
    pub fn burn_stage_output(&mut self, stage: u32, count: u64) -> Result<(), PhaseBError> {
        self.ensure_active()?;
        if self.active_response.is_some() || count == 0 {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "stage-output burns must be nonzero and occur between responses",
            );
        }
        let current = match self.stages.get(&stage).copied() {
            Some(counters) => counters,
            None => {
                return self.fail(
                    ConnectionAbortReason::ProtocolError,
                    "cannot burn output from an unknown stage",
                )
            }
        };
        if count > current.available {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "stage-output burn exceeds available correlations",
            );
        }
        let mut updated = current;
        updated.burned = updated
            .burned
            .checked_add(count)
            .ok_or_else(|| PhaseBError::new("burned stage-output counter overflow"))?;
        updated.available -= count;
        debug_assert!(updated.reconciled());
        self.stages.insert(stage, updated);
        self.allocation_digest = digest_parts(
            b"volta-pcg/connection-allocation-chain/stage-output-burn/v1",
            &[
                &self.allocation_digest,
                &stage.to_le_bytes(),
                &count.to_le_bytes(),
                &updated.burned.to_le_bytes(),
            ],
        );
        let record = format!(
            "STAGE_OUTPUT_BURN|{}|{}|{}|{}\n",
            stage,
            count,
            updated.burned,
            hex32(self.allocation_digest)
        );
        self.append_or_burn(&record)
    }

    /// Burn the response nonce before exposing any correlation allocation.
    pub fn begin_response(
        &mut self,
        authorizations: &ResponseAuthorizationStore,
        binding: SessionBinding,
    ) -> Result<AuthorizationBurn, PhaseBError> {
        self.ensure_active()?;
        if self.active_response.is_some() {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "a connection may have only one active response",
            );
        }
        if binding.session_id != self.binding.connection_id
            || binding.channel_id != self.binding.authenticated_channel_id
        {
            return self.fail(
                ConnectionAbortReason::AuthorizationFailure,
                "response binding does not match connection/channel identity",
            );
        }
        let burn = match authorizations.reserve(&binding) {
            Ok(burn) => burn,
            Err(error) => {
                let message = format!("response authorization failed: {error}");
                return self.fail(ConnectionAbortReason::AuthorizationFailure, &message);
            }
        };
        let nonce_digest = digest_parts(
            b"volta-pcg/connection-response-nonce/v1",
            &[&binding.response_authorization_nonce],
        );
        let response_allocation_digest = digest_parts(
            b"volta-pcg/response-allocation-ledger/v1",
            &[&self.allocation_digest, &nonce_digest],
        );
        let response_channel_digest = digest_parts(
            b"volta-pcg/response-channel-ledger/v1",
            &[&self.channel_digest, &nonce_digest],
        );
        self.active_response = Some(ActiveConnectionResponse {
            nonce: binding.response_authorization_nonce,
            nonce_digest,
            allocation_digest: response_allocation_digest,
            channel_digest: response_channel_digest,
            correlations_consumed: 0,
            channel_frames: 0,
        });
        let record = format!(
            "RESPONSE_BEGIN|{}|{}|{}\n",
            hex32(nonce_digest),
            hex32(response_allocation_digest),
            burn.record_digest
        );
        self.append_or_burn(&record)?;
        Ok(burn)
    }

    /// Allocate the next low-end canonical stage range to the active response.
    /// Reserved high-end ranges have already left `available`, so they cannot
    /// be returned by this method.
    pub fn allocate(
        &mut self,
        stage: u32,
        count: u64,
        domain: CorrelationDomain,
    ) -> Result<CorrelationAllocation, PhaseBError> {
        self.ensure_active()?;
        let response_nonce = match self.active_response.as_ref() {
            Some(response) => response.nonce,
            None => {
                return self.fail(
                    ConnectionAbortReason::ProtocolError,
                    "correlations require an active, durably authorized response",
                )
            }
        };
        if count == 0
            || domain.connection_id != self.binding.connection_id
            || domain.response_nonce != response_nonce
        {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "allocation domain does not match the active connection/response",
            );
        }
        let domain_digest = domain.digest();
        if self.allocated_domains.contains(&domain_digest) {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "correlation allocation domain was already consumed",
            );
        }
        let current = match self.stages.get(&stage).copied() {
            Some(counters) => counters,
            None => {
                return self.fail(
                    ConnectionAbortReason::ProtocolError,
                    "cannot allocate from an unknown stage",
                )
            }
        };
        if count > current.available {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "correlation allocation exceeds the available non-reserved pool",
            );
        }
        let start = current.consumed;
        let mut updated = current;
        updated.consumed = updated
            .consumed
            .checked_add(count)
            .ok_or_else(|| PhaseBError::new("consumed counter overflow"))?;
        updated.available -= count;
        debug_assert!(updated.reconciled());
        self.stages.insert(stage, updated);
        self.allocated_domains.insert(domain_digest);

        self.allocation_digest = digest_parts(
            b"volta-pcg/connection-allocation-chain/response/v1",
            &[
                &self.allocation_digest,
                &stage.to_le_bytes(),
                &start.to_le_bytes(),
                &count.to_le_bytes(),
                &domain_digest,
            ],
        );
        let response = self.active_response.as_mut().expect("checked above");
        response.allocation_digest = digest_parts(
            b"volta-pcg/response-allocation-chain/v1",
            &[
                &response.allocation_digest,
                &stage.to_le_bytes(),
                &start.to_le_bytes(),
                &count.to_le_bytes(),
                &domain_digest,
            ],
        );
        response.correlations_consumed = response
            .correlations_consumed
            .checked_add(count)
            .ok_or_else(|| PhaseBError::new("response correlation counter overflow"))?;
        let response_digest = response.allocation_digest;
        let record = format!(
            "ALLOCATE|{}|{}|{}|{}|{}|{}\n",
            stage,
            start,
            count,
            hex32(domain_digest),
            hex32(self.allocation_digest),
            hex32(response_digest)
        );
        self.append_or_burn(&record)?;
        Ok(CorrelationAllocation {
            stage,
            start,
            count,
            domain_digest: hex32(domain_digest),
            connection_allocation_digest: hex32(self.allocation_digest),
            response_allocation_digest: hex32(response_digest),
        })
    }

    /// Record a canonical `kind:u8 || length:u64_le || payload` frame.
    pub fn record_channel_frame(
        &mut self,
        direction: ConnectionChannelDirection,
        kind: u8,
        payload: &[u8],
    ) -> Result<(), PhaseBError> {
        self.ensure_active()?;
        if kind == 0 {
            return self.fail(ConnectionAbortReason::MalformedFrame, "zero channel-frame kind");
        }
        let length = u64::try_from(payload.len())
            .map_err(|_| PhaseBError::new("connection channel payload length does not fit u64"))?;
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(kind);
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(payload);
        self.record_canonical_frame(direction, &frame)
    }

    /// Validate and record a serialized frame received from the transport.
    /// Any malformed encoding terminally burns the connection.
    pub fn ingest_serialized_frame(
        &mut self,
        direction: ConnectionChannelDirection,
        frame: &[u8],
    ) -> Result<(), PhaseBError> {
        self.ensure_active()?;
        if frame.len() < 9 || frame[0] == 0 {
            return self.fail(
                ConnectionAbortReason::MalformedFrame,
                "malformed connection channel frame header",
            );
        }
        let declared = u64::from_le_bytes(frame[1..9].try_into().expect("fixed slice"));
        let actual = match u64::try_from(frame.len() - 9) {
            Ok(actual) => actual,
            Err(_) => {
                return self.fail(
                    ConnectionAbortReason::MalformedFrame,
                    "connection channel frame length exceeds u64",
                )
            }
        };
        if declared != actual {
            return self.fail(
                ConnectionAbortReason::MalformedFrame,
                "non-canonical connection channel frame length",
            );
        }
        self.record_canonical_frame(direction, frame)
    }

    pub fn finish_response_success(&mut self) -> Result<ConnectionResponseAudit, PhaseBError> {
        self.ensure_active()?;
        let response = match self.active_response.as_ref().cloned() {
            Some(response) => response,
            None => {
                return self
                    .fail(ConnectionAbortReason::ProtocolError, "no active response to complete")
            }
        };
        let record = format!(
            "RESPONSE_SUCCESS|{}|{}|{}|{}|{}\n",
            hex32(response.nonce_digest),
            hex32(response.allocation_digest),
            hex32(response.channel_digest),
            response.correlations_consumed,
            response.channel_frames
        );
        self.append_or_burn(&record)?;
        self.active_response = None;
        self.completed_responses = self
            .completed_responses
            .checked_add(1)
            .ok_or_else(|| PhaseBError::new("completed-response counter overflow"))?;
        Ok(ConnectionResponseAudit {
            response_nonce_digest: hex32(response.nonce_digest),
            allocation_digest: hex32(response.allocation_digest),
            channel_ledger_digest: hex32(response.channel_digest),
            correlations_consumed: response.correlations_consumed,
            channel_frames: response.channel_frames,
        })
    }

    pub fn abort(&mut self, reason: ConnectionAbortReason) -> Result<(), PhaseBError> {
        self.terminal_burn(reason)
    }

    pub fn malicious_check_failed(&mut self) -> Result<(), PhaseBError> {
        self.terminal_burn(ConnectionAbortReason::MaliciousCheckFailure)
    }

    pub fn unexpected_eof(&mut self) -> Result<(), PhaseBError> {
        self.terminal_burn(ConnectionAbortReason::UnexpectedEof)
    }

    pub fn close(&mut self) -> Result<(), PhaseBError> {
        self.terminal_burn(ConnectionAbortReason::ExplicitClose)
    }

    /// Enforce the preregistered TTL at a protocol boundary.  Expiry burns all
    /// residual pools and prevents any further response.
    pub fn enforce_ttl(&mut self) -> Result<(), PhaseBError> {
        self.ensure_live()
    }

    fn record_canonical_frame(
        &mut self,
        direction: ConnectionChannelDirection,
        frame: &[u8],
    ) -> Result<(), PhaseBError> {
        if self.active_response.is_none() {
            return self.fail(
                ConnectionAbortReason::ProtocolError,
                "connection frames require an active response",
            );
        }
        let direction_byte = [direction.as_byte()];
        self.channel_digest = digest_parts(
            b"volta-pcg/connection-channel-chain/v1",
            &[&self.channel_digest, &direction_byte, frame],
        );
        let response = self.active_response.as_mut().expect("checked above");
        response.channel_digest = digest_parts(
            b"volta-pcg/response-channel-chain/v1",
            &[&response.channel_digest, &direction_byte, frame],
        );
        response.channel_frames = response
            .channel_frames
            .checked_add(1)
            .ok_or_else(|| PhaseBError::new("response channel-frame counter overflow"))?;
        let record = format!(
            "CHANNEL|{}|{}|{}|{}|{}\n",
            direction.as_byte(),
            frame[0],
            frame.len() - 9,
            hex32(self.channel_digest),
            hex32(response.channel_digest)
        );
        self.append_or_burn(&record)
    }

    fn ensure_active(&mut self) -> Result<(), PhaseBError> {
        self.ensure_live()?;
        if self.state != ConnectionState::Active {
            return self
                .fail(ConnectionAbortReason::ProtocolError, "connection base phase is not active");
        }
        Ok(())
    }

    fn ensure_live(&mut self) -> Result<(), PhaseBError> {
        if let ConnectionState::Terminal { reason } = self.state {
            return Err(PhaseBError::new(format!(
                "connection is terminally burned: {}",
                reason.as_record()
            )));
        }
        match journal_contains_terminal(&self.journal_path) {
            Ok(true) => {
                self.burn_in_memory(ConnectionAbortReason::ProcessKillOrRestart);
                self.terminal_record_synced = true;
                return Err(PhaseBError::new("connection was terminally burned by another opener"));
            }
            Ok(false) => {}
            Err(error) => {
                let message = format!("cannot inspect durable connection journal: {error}");
                return self.fail(ConnectionAbortReason::DurableStoreFailure, &message);
            }
        }
        if self.expires_at.is_some_and(|deadline| SystemTime::now() >= deadline) {
            self.terminal_burn(ConnectionAbortReason::TtlExpired)?;
            return Err(PhaseBError::new("connection TTL expired; connection burned"));
        }
        Ok(())
    }

    fn append_or_burn(&mut self, record: &str) -> Result<(), PhaseBError> {
        if let Err(error) = self.append_record(record) {
            self.burn_in_memory(ConnectionAbortReason::DurableStoreFailure);
            return Err(error);
        }
        Ok(())
    }

    fn append_record(&mut self, record: &str) -> Result<(), PhaseBError> {
        self.journal.write_all(record.as_bytes()).map_err(|error| {
            PhaseBError::new(format!("cannot append connection journal: {error}"))
        })?;
        self.journal
            .sync_all()
            .map_err(|error| PhaseBError::new(format!("cannot sync connection journal: {error}")))
    }

    fn fail<T>(&mut self, reason: ConnectionAbortReason, message: &str) -> Result<T, PhaseBError> {
        match self.terminal_burn(reason) {
            Ok(()) => Err(PhaseBError::new(format!("{message}; entire connection burned"))),
            Err(burn_error) => Err(PhaseBError::new(format!(
                "{message}; connection fail-closed but durable burn failed: {burn_error}"
            ))),
        }
    }

    fn terminal_burn(&mut self, reason: ConnectionAbortReason) -> Result<(), PhaseBError> {
        if self.terminal_record_synced {
            return Ok(());
        }
        let durable_reason = match self.state {
            ConnectionState::Terminal { reason } => reason,
            ConnectionState::Open | ConnectionState::Active => {
                self.burn_in_memory(reason);
                reason
            }
        };
        let active_nonce =
            self.terminal_active_nonce_digest.map(hex32).unwrap_or_else(|| "none".into());
        let counters_digest = stage_counters_digest(&self.stages);
        let record = format!(
            "TERMINAL|{}|{}|{}|{}|{}\n",
            durable_reason.as_record(),
            active_nonce,
            hex32(self.allocation_digest),
            hex32(self.channel_digest),
            hex32(counters_digest)
        );
        self.append_record(&record)?;
        sync_directory(&self.root, "connection store")?;
        self.terminal_record_synced = true;
        Ok(())
    }

    fn burn_in_memory(&mut self, reason: ConnectionAbortReason) {
        self.terminal_active_nonce_digest =
            self.active_response.as_ref().map(|response| response.nonce_digest);
        for (stage, counters) in &mut self.stages {
            let residual = counters.available;
            counters.burned = counters
                .burned
                .checked_add(residual)
                .expect("reconciled stage counters cannot overflow while burning residual");
            counters.available = 0;
            debug_assert!(counters.reconciled());
            self.allocation_digest = digest_parts(
                b"volta-pcg/connection-allocation-chain/burn/v1",
                &[
                    &self.allocation_digest,
                    &stage.to_le_bytes(),
                    &residual.to_le_bytes(),
                    &counters.reserved_as_base.to_le_bytes(),
                ],
            );
        }
        self.active_response = None;
        self.state = ConnectionState::Terminal { reason };
    }
}

impl Drop for ConnectionHandle {
    fn drop(&mut self) {
        if !self.terminal_record_synced {
            let _ = self.terminal_burn(ConnectionAbortReason::ProcessKillOrRestart);
        }
    }
}

fn stage_counters_digest(stages: &BTreeMap<u32, StageCorrelationCounters>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta-pcg/connection-stage-counters/v1");
    for (stage, counters) in stages {
        hasher.update(&stage.to_le_bytes());
        hasher.update(&counters.generated.to_le_bytes());
        hasher.update(&counters.consumed.to_le_bytes());
        hasher.update(&counters.reserved_as_base.to_le_bytes());
        hasher.update(&counters.burned.to_le_bytes());
        hasher.update(&counters.available.to_le_bytes());
        hasher.update(&counters.base_inputs_consumed.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn journal_contains_terminal(path: &Path) -> Result<bool, PhaseBError> {
    let bytes = std::fs::read(path).map_err(|error| {
        PhaseBError::new(format!("cannot read connection journal {}: {error}", path.display()))
    })?;
    if !bytes.starts_with(CONNECTION_RECORD_MAGIC) {
        // A partial or malformed create is an unfinished connection, not a
        // resumable record; the duplicate opener will append a terminal burn.
        return Ok(false);
    }
    Ok(bytes.windows(b"\nTERMINAL|".len()).any(|window| window == b"\nTERMINAL|"))
}

fn burn_existing_journal(
    root: &Path,
    journal_path: &Path,
    reason: ConnectionAbortReason,
) -> Result<(), PhaseBError> {
    let mut file = OpenOptions::new().append(true).open(journal_path).map_err(|error| {
        PhaseBError::new(format!(
            "cannot open crashed connection journal {} for terminal burn: {error}",
            journal_path.display()
        ))
    })?;
    // Prefix with a newline so even a torn final record becomes unambiguously
    // followed by a complete terminal marker.
    let record = format!("\nTERMINAL|{}|unknown|unknown|unknown|unknown\n", reason.as_record());
    file.write_all(record.as_bytes()).map_err(|error| {
        PhaseBError::new(format!("cannot append crashed-connection burn: {error}"))
    })?;
    file.sync_all().map_err(|error| {
        PhaseBError::new(format!("cannot sync crashed-connection burn: {error}"))
    })?;
    sync_directory(root, "connection store")
}

fn sync_directory(path: &Path, label: &str) -> Result<(), PhaseBError> {
    File::open(path).and_then(|directory| directory.sync_all()).map_err(|error| {
        PhaseBError::new(format!("cannot sync {label} directory {}: {error}", path.display()))
    })
}

/// Burn the single-use response authorization, independently sample both role
/// seeds from the OS CSPRNG, bind them to the authenticated identities, and
/// execute phase B. Every error after `reserve` leaves the nonce burned.
pub fn expand_phase_b_production(
    store: &ResponseAuthorizationStore,
    binding: SessionBinding,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> Result<ProductionPhaseBExpansion, PhaseBError> {
    expand_phase_b_production_with_ggm_prg(
        store,
        binding,
        sub_corrs,
        full_corrs,
        params,
        GgmPrg::Aes128Mmo,
    )
}

/// Explicit production selector retained for diagnostics and parity records.
/// The ordinary entry point above always chooses AES-128-MMO; BLAKE3 can only
/// be selected by calling this API explicitly.
pub fn expand_phase_b_production_with_ggm_prg(
    store: &ResponseAuthorizationStore,
    binding: SessionBinding,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
    ggm_prg: GgmPrg,
) -> Result<ProductionPhaseBExpansion, PhaseBError> {
    let burn = store.reserve(&binding)?;

    let mut prover_entropy = [0u8; 32];
    let mut verifier_entropy = [0u8; 32];
    OsRng.try_fill_bytes(&mut prover_entropy).map_err(|error| {
        PhaseBError::new(format!("OS entropy unavailable for prover role: {error}"))
    })?;
    OsRng.try_fill_bytes(&mut verifier_entropy).map_err(|error| {
        PhaseBError::new(format!("OS entropy unavailable for verifier role: {error}"))
    })?;
    if prover_entropy == verifier_entropy {
        return Err(PhaseBError::new(
            "OS entropy returned identical prover/verifier role samples; authorization burned",
        ));
    }
    let prover_seed = bind_role_entropy(prover_entropy, &binding, b"prover");
    let verifier_seed = bind_role_entropy(verifier_entropy, &binding, b"verifier");
    prover_entropy.fill(0);
    verifier_entropy.fill(0);

    let prover_commitment = seed_commitment(prover_seed, b"prover");
    let verifier_commitment = seed_commitment(verifier_seed, b"verifier");
    if prover_commitment == verifier_commitment {
        return Err(PhaseBError::new("role-seed commitments collided; authorization burned"));
    }
    let mut expansion = expand_phase_b_bound_with_ggm_prg(
        prover_seed,
        verifier_seed,
        binding,
        sub_corrs,
        full_corrs,
        params,
        ggm_prg,
    )?;
    expansion.setup.params.production_ready = true;
    let production = ProductionSetupAudit {
        entropy_source:
            "rand 0.8 OsRng; Linux OS CSPRNG via getrandom; independent 256-bit role reads".into(),
        independent_role_entropy_samples: true,
        prover_role_seed_commitment: hex32(prover_commitment),
        verifier_role_seed_commitment: hex32(verifier_commitment),
        role_seed_commitments_distinct: true,
        session_channel_identity_bound: true,
        session_binding_digest: binding.digest_hex(),
        response_authorization_burned_before_setup: true,
        response_authorization_burn_record_digest: burn.record_digest,
        burn_on_success_or_abort: true,
        reconnect_retry_resume_allowed: false,
    };
    Ok(ProductionPhaseBExpansion { expansion, production })
}

/// Open and fully provision a fase-D connection with the default AES-128-MMO
/// GGM.  The durable OPEN record precedes entropy sampling and cryptographic
/// setup, so a process kill at any later point is burned on reopen.
pub fn open_fase_d_connection(
    store: &ConnectionStore,
    binding: ConnectionBinding,
    ttl: Option<Duration>,
    params: FaseDParams,
) -> Result<ProductionFaseDConnection, PhaseBError> {
    open_fase_d_connection_with_ggm_prg(store, binding, ttl, params, GgmPrg::Aes128Mmo)
}

/// Explicit diagnostic selector.  Record-producing callers use
/// [`open_fase_d_connection`]; selecting BLAKE3 requires naming it here.
pub fn open_fase_d_connection_with_ggm_prg(
    store: &ConnectionStore,
    binding: ConnectionBinding,
    ttl: Option<Duration>,
    params: FaseDParams,
    ggm_prg: GgmPrg,
) -> Result<ProductionFaseDConnection, PhaseBError> {
    params.production_preflight().map_err(|error| PhaseBError::new(error.to_string()))?;
    if binding.stage_plan != params.plan {
        return Err(PhaseBError::new(
            "connection stage plan does not match fase-D expansion parameters",
        ));
    }
    let mut connection = store.create(binding, ttl)?;
    let mut prover_entropy = [0u8; 32];
    let mut verifier_entropy = [0u8; 32];
    if let Err(error) = OsRng.try_fill_bytes(&mut prover_entropy) {
        let _ = connection.abort(ConnectionAbortReason::DurableStoreFailure);
        return Err(PhaseBError::new(format!(
            "OS entropy unavailable for connection prover role: {error}"
        )));
    }
    if let Err(error) = OsRng.try_fill_bytes(&mut verifier_entropy) {
        prover_entropy.fill(0);
        let _ = connection.abort(ConnectionAbortReason::DurableStoreFailure);
        return Err(PhaseBError::new(format!(
            "OS entropy unavailable for connection verifier role: {error}"
        )));
    }
    if prover_entropy == verifier_entropy {
        prover_entropy.fill(0);
        verifier_entropy.fill(0);
        let _ = connection.abort(ConnectionAbortReason::ProtocolError);
        return Err(PhaseBError::new(
            "OS entropy returned identical connection role samples; connection burned",
        ));
    }
    let binding_digest = binding.digest();
    let mut prover_seed = digest_parts(
        b"volta-pcg/fase-d/connection-role-entropy/v1",
        &[&binding_digest, b"prover", &prover_entropy],
    );
    let mut verifier_seed = digest_parts(
        b"volta-pcg/fase-d/connection-role-entropy/v1",
        &[&binding_digest, b"verifier", &verifier_entropy],
    );
    prover_entropy.fill(0);
    verifier_entropy.fill(0);
    let prover_commitment = seed_commitment(prover_seed, b"fase-d-prover");
    let verifier_commitment = seed_commitment(verifier_seed, b"fase-d-verifier");
    if prover_commitment == verifier_commitment {
        let _ = connection.abort(ConnectionAbortReason::ProtocolError);
        return Err(PhaseBError::new("connection role-seed commitments collided"));
    }
    let phase_binding =
        FaseDConnectionBinding::new(binding.connection_id, binding.authenticated_channel_id)?;
    let expansion_result = expand_fase_d_connection(
        prover_seed,
        verifier_seed,
        phase_binding,
        params.clone(),
        ggm_prg,
    );
    prover_seed.fill(0);
    verifier_seed.fill(0);
    let expansion = match expansion_result {
        Ok(expansion) => expansion,
        Err(error) => {
            let reason = if error.to_string().contains("rejected") {
                ConnectionAbortReason::MaliciousCheckFailure
            } else {
                ConnectionAbortReason::ProtocolError
            };
            let _ = connection.abort(reason);
            return Err(error);
        }
    };
    let base_phase_digest = digest_parts(
        b"volta-pcg/fase-d/base-phase-closure/v1",
        &[
            expansion.base_ot_transcript_digest.as_bytes(),
            expansion.ot_extension_digest.as_bytes(),
            expansion.connection_binding_digest.as_bytes(),
        ],
    );
    connection.activate(base_phase_digest)?;
    connection.register_stage_output(0, params.main.usable_output() as u64, 0)?;
    connection.reserve_as_base(0, params.stage3.base_consumption() as u64)?;
    if params.plan == crate::FaseDStagePlan::ChainSix {
        connection.burn_stage_output(0, expansion.capacity.main_residual as u64)?;
    }
    for stage in &expansion.stages {
        let source = (stage.ordinal - 1) as u32;
        let ordinal = stage.ordinal as u32;
        connection.register_refill_stage(
            source,
            ordinal,
            stage.generated,
            params.stage3.base_consumption() as u64,
        )?;
        if stage.reserved_as_base != 0 {
            connection.reserve_as_base(ordinal, stage.reserved_as_base)?;
        }
        if stage.released != 0 {
            connection.burn_stage_output(ordinal, stage.released)?;
        }
    }
    let production = ProductionConnectionSetupAudit {
        entropy_source:
            "rand 0.8 OsRng; Linux OS CSPRNG via getrandom; independent 256-bit connection-role reads"
                .into(),
        independent_role_entropy_samples: true,
        prover_role_seed_commitment: hex32(prover_commitment),
        verifier_role_seed_commitment: hex32(verifier_commitment),
        role_seed_commitments_distinct: true,
        connection_identity_bound: true,
        authenticated_channel_identity_bound: true,
        durable_connection_open_before_entropy: true,
        one_base_ot_copee_iknp_phase: expansion.one_base_phase,
        ggm_prg,
        pcg_production_ready: true,
    };
    Ok(ProductionFaseDConnection {
        connection,
        expansion,
        production,
        correlation_spool: None,
        correlation_spool_audit: None,
    })
}

fn seed_commitment(seed: [u8; 32], role: &[u8]) -> [u8; 32] {
    digest_parts(b"volta-pcg/phase-b/role-seed-commitment/v1", &[role, &seed])
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_store(label: &str) -> (PathBuf, ResponseAuthorizationStore) {
        let serial = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("volta-pcg-{label}-{}-{serial}", std::process::id()));
        let store = ResponseAuthorizationStore::new(&root).unwrap();
        (root, store)
    }

    fn binding(tag: u8) -> SessionBinding {
        SessionBinding::new([tag; 32], [tag.wrapping_add(1); 32], [tag.wrapping_add(2); 32])
            .unwrap()
    }

    fn lifecycle_stores(label: &str) -> (PathBuf, ConnectionStore, ResponseAuthorizationStore) {
        let serial = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .join(format!("volta-pcg-connection-{label}-{}-{serial}", std::process::id()));
        let connections = ConnectionStore::new(root.join("connections")).unwrap();
        let authorizations = ResponseAuthorizationStore::new(root.join("authorizations")).unwrap();
        (root, connections, authorizations)
    }

    fn connection_binding(tag: u8, plan: ConnectionStagePlan) -> ConnectionBinding {
        ConnectionBinding::new([tag; 32], [tag.wrapping_add(1); 32], plan).unwrap()
    }

    fn domain(binding: ConnectionBinding, nonce: [u8; 32], tag: u8) -> CorrelationDomain {
        CorrelationDomain::new(
            binding.connection_id,
            nonce,
            u32::from(tag),
            u32::from(tag.wrapping_add(1)),
            u64::from(tag) * 17,
            [tag.wrapping_add(2); 32],
        )
        .unwrap()
    }

    #[test]
    fn anonymous_connection_spool_range_loads_exact_pools() {
        let delta = Fp2::new(Fp::new(17), Fp::new(29));
        let prover: Vec<_> = (0..12u64)
            .map(|index| SubVole {
                r: Fp::new(index + 1),
                m: Fp2::new(Fp::new(100 + index), Fp::new(200 + index)),
            })
            .collect();
        let keys: Vec<_> = prover.iter().map(|value| value.m + delta.mul_base(value.r)).collect();
        let (mut spool, audit) = ConnectionCorrelationSpool::create(&prover, &keys).unwrap();
        assert_eq!(audit.entries, 12);
        assert_eq!(audit.bytes, 12 * CORRELATION_SPOOL_ENTRY_BYTES as u64);
        assert_eq!(audit.resident_raw_entries_after_spool, 0);

        let (loaded_p, loaded_v) = spool.allocate(2, 3, 2).unwrap();
        for (actual, expected) in loaded_p.subs.iter().zip(&prover[2..5]) {
            assert_eq!(actual.r, expected.r);
            assert_eq!(actual.m, expected.m);
        }
        assert_eq!(loaded_v.sub_keys, keys[2..5]);
        for full in 0..2 {
            let lo = 5 + 2 * full;
            let hi = lo + 1;
            assert_eq!(
                loaded_p.fulls[full].x,
                Fp2::from_base(prover[lo].r) + GAMMA.mul_base(prover[hi].r)
            );
            assert_eq!(loaded_p.fulls[full].m, prover[lo].m + GAMMA * prover[hi].m);
            assert_eq!(loaded_v.full_keys[full], keys[lo] + GAMMA * keys[hi]);
        }
    }

    #[test]
    fn reconnect_retry_and_nonce_reuse_are_rejected_after_restart() {
        let (root, store) = test_store("restart");
        let first = binding(0x21);
        let burn = store.reserve(&first).unwrap();
        assert!(burn.marker_path().exists());
        drop(store); // Simulate a killed role process after durable reservation.

        let restarted = ResponseAuthorizationStore::new(&root).unwrap();
        let retry = restarted.reserve(&first).unwrap_err();
        assert!(retry.to_string().contains("already burned"));

        let reused_nonce =
            SessionBinding::new([0x41; 32], [0x42; 32], first.response_authorization_nonce)
                .unwrap();
        let reconnect = restarted.reserve(&reused_nonce).unwrap_err();
        assert!(reconnect.to_string().contains("already burned"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abort_burns_nonce_and_fresh_restart_correlations_do_not_repeat() {
        let (root, store) = test_store("abort-non-reuse");
        let aborted = binding(0x31);
        let bad_params = PhaseAParams::tiny_for_test(58);
        let error = expand_phase_b_production(&store, aborted, 47, 5, bad_params).unwrap_err();
        assert!(error.to_string().contains("params/count mismatch"));
        assert!(store.reserve(&aborted).unwrap_err().to_string().contains("already burned"));

        let params = PhaseAParams::tiny_for_test(58);
        let first =
            expand_phase_b_production(&store, binding(0x51), 48, 5, params.clone()).unwrap();
        drop(store);
        let restarted = ResponseAuthorizationStore::new(&root).unwrap();
        let second = expand_phase_b_production_with_ggm_prg(
            &restarted,
            binding(0x61),
            48,
            5,
            params,
            GgmPrg::Blake3,
        )
        .unwrap();
        assert_eq!(first.expansion.setup.params.ggm_prg, GgmPrg::Aes128Mmo);
        assert_eq!(second.expansion.setup.params.ggm_prg, GgmPrg::Blake3);
        assert_ne!(
            first.production.prover_role_seed_commitment,
            second.production.prover_role_seed_commitment
        );
        assert_ne!(
            first.production.verifier_role_seed_commitment,
            second.production.verifier_role_seed_commitment
        );
        assert_ne!(first.expansion.prover.subs[0].r, second.expansion.prover.subs[0].r);
        assert!(first.production.response_authorization_burned_before_setup);
        assert!(second.production.response_authorization_burned_before_setup);
        assert!(!first.production.reconnect_retry_resume_allowed);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn three_successful_responses_share_connection_without_reuse() {
        let (root, connections, authorizations) = lifecycle_stores("three-success");
        let binding = connection_binding(0x70, ConnectionStagePlan::TerminalOne);
        let mut connection = connections.create(binding, None).unwrap();
        connection.activate([0x71; 32]).unwrap();
        connection.register_stage_output(0, 100, 0).unwrap();

        let initial_allocation_digest = connection.allocation_digest_hex();
        let mut previous_end = 0;
        let mut response_digests = HashSet::new();
        for response_index in 0..3u8 {
            let nonce = [0x80 + response_index; 32];
            let response_binding = binding.response_binding(nonce).unwrap();
            let burn = connection.begin_response(&authorizations, response_binding).unwrap();
            assert!(burn.marker_path().exists());
            let allocation =
                connection.allocate(0, 10, domain(binding, nonce, 0x10 + response_index)).unwrap();
            assert_eq!(allocation.start, previous_end);
            previous_end = allocation.start + allocation.count;
            connection
                .record_channel_frame(
                    ConnectionChannelDirection::ProverToVerifier,
                    1 + response_index,
                    &[response_index; 7],
                )
                .unwrap();
            let audit = connection.finish_response_success().unwrap();
            assert_eq!(audit.correlations_consumed, 10);
            assert_eq!(audit.channel_frames, 1);
            assert!(response_digests.insert(audit.allocation_digest));
            assert_eq!(connection.state(), ConnectionState::Active);
        }
        assert_eq!(connection.completed_responses(), 3);
        assert_ne!(connection.allocation_digest_hex(), initial_allocation_digest);
        let counters = connection.stage_counters().get(&0).unwrap();
        assert_eq!(counters.consumed, 30);
        assert_eq!(counters.available, 70);
        assert!(counters.reconciled());

        // Success leaves the connection alive, while each successful nonce is
        // still permanently burned by the unchanged authorization store.
        let reused = binding.response_binding([0x80; 32]).unwrap();
        assert!(authorizations
            .reserve(&reused)
            .unwrap_err()
            .to_string()
            .contains("already burned"));
        connection.close().unwrap();
        assert_eq!(
            connection.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::ExplicitClose }
        );
        assert_eq!(connection.stage_counters().get(&0).unwrap().burned, 70);
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn response_two_abort_burns_connection_and_reopen_cannot_resume() {
        let (root, connections, authorizations) = lifecycle_stores("response-two-abort");
        let binding = connection_binding(0x91, ConnectionStagePlan::TerminalOne);
        let mut connection = connections.create(binding, None).unwrap();
        let journal_path = connection.journal_path().to_path_buf();
        connection.activate([0x92; 32]).unwrap();
        connection.register_stage_output(0, 80, 0).unwrap();

        let nonce_one = [0x93; 32];
        connection
            .begin_response(&authorizations, binding.response_binding(nonce_one).unwrap())
            .unwrap();
        connection.allocate(0, 10, domain(binding, nonce_one, 1)).unwrap();
        connection.finish_response_success().unwrap();

        let nonce_two = [0x94; 32];
        connection
            .begin_response(&authorizations, binding.response_binding(nonce_two).unwrap())
            .unwrap();
        connection.allocate(0, 10, domain(binding, nonce_two, 2)).unwrap();
        connection.malicious_check_failed().unwrap();
        assert_eq!(
            connection.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::MaliciousCheckFailure }
        );
        let counters = connection.stage_counters().get(&0).unwrap();
        assert_eq!((counters.consumed, counters.burned, counters.available), (20, 60, 0));
        assert!(counters.reconciled());
        assert!(connection
            .begin_response(&authorizations, binding.response_binding([0x95; 32]).unwrap())
            .unwrap_err()
            .to_string()
            .contains("terminally burned"));
        assert!(connections
            .create(binding, None)
            .unwrap_err()
            .to_string()
            .contains("resume rejected"));
        let journal = std::fs::read_to_string(journal_path).unwrap();
        assert!(journal.contains("TERMINAL|malicious-check-failure"));
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn killed_connection_is_durably_burned_on_reopen() {
        let (root, connections, _authorizations) = lifecycle_stores("kill-restart");
        let binding = connection_binding(0xa1, ConnectionStagePlan::ChainSix);
        let mut killed = connections.create(binding, None).unwrap();
        let journal_path = killed.journal_path().to_path_buf();
        killed.activate([0xa2; 32]).unwrap();
        killed.register_stage_output(0, 64, 0).unwrap();
        // `forget` is the unit-test analogue of SIGKILL: Drop cannot append a
        // terminal record.  The duplicate opener must do so before rejecting.
        std::mem::forget(killed);

        let error = connections.create(binding, None).unwrap_err();
        assert!(error.to_string().contains("restart burned"));
        let journal = std::fs::read_to_string(journal_path).unwrap();
        assert!(journal.contains("TERMINAL|process-kill-or-restart"));
        assert!(connections
            .create(binding, None)
            .unwrap_err()
            .to_string()
            .contains("terminally burned"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reserved_base_range_is_never_response_allocatable_and_counters_reconcile() {
        let (root, connections, authorizations) = lifecycle_stores("reserved-exclusion");
        let binding = connection_binding(0xb1, ConnectionStagePlan::ChainSix);
        let mut connection = connections.create(binding, None).unwrap();
        connection.activate([0xb2; 32]).unwrap();
        connection.register_stage_output(0, 100, 0).unwrap();
        let reservation = connection.reserve_as_base(0, 30).unwrap();
        assert_eq!((reservation.start, reservation.count), (70, 30));
        connection.register_refill_stage(0, 1, 200, 30).unwrap();
        assert_eq!(connection.stage_counters().get(&1).unwrap().base_inputs_consumed, 30);
        connection.burn_stage_output(1, 200).unwrap();
        assert_eq!(
            (
                connection.stage_counters().get(&1).unwrap().burned,
                connection.stage_counters().get(&1).unwrap().available
            ),
            (200, 0)
        );

        let nonce_one = [0xb3; 32];
        connection
            .begin_response(&authorizations, binding.response_binding(nonce_one).unwrap())
            .unwrap();
        let allocation = connection.allocate(0, 60, domain(binding, nonce_one, 3)).unwrap();
        assert!(allocation.start + allocation.count <= reservation.start);
        connection.finish_response_success().unwrap();

        let nonce_two = [0xb4; 32];
        connection
            .begin_response(&authorizations, binding.response_binding(nonce_two).unwrap())
            .unwrap();
        let error = connection.allocate(0, 11, domain(binding, nonce_two, 4)).unwrap_err();
        assert!(error.to_string().contains("non-reserved pool"));
        assert_eq!(
            connection.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::ProtocolError }
        );
        let counters = connection.stage_counters().get(&0).unwrap();
        assert_eq!(
            (counters.generated, counters.consumed, counters.reserved_as_base, counters.burned),
            (100, 60, 30, 10)
        );
        assert_eq!(counters.available, 0);
        assert_eq!(counters.terminally_unusable(), 40);
        assert!(counters.reconciled());
        let child = connection.stage_counters().get(&1).unwrap();
        assert_eq!((child.generated, child.base_inputs_consumed, child.burned), (200, 30, 200));
        assert!(child.reconciled());
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ttl_close_malformed_frame_and_eof_are_terminal() {
        let (root, connections, authorizations) = lifecycle_stores("terminal-causes");

        let ttl_binding = connection_binding(0xc1, ConnectionStagePlan::TerminalOne);
        let mut ttl_connection = connections.create(ttl_binding, Some(Duration::ZERO)).unwrap();
        assert!(ttl_connection.enforce_ttl().unwrap_err().to_string().contains("TTL expired"));
        assert_eq!(
            ttl_connection.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::TtlExpired }
        );
        drop(ttl_connection);

        let close_binding = connection_binding(0xc2, ConnectionStagePlan::TerminalOne);
        let mut close_connection = connections.create(close_binding, None).unwrap();
        close_connection.activate([0xc3; 32]).unwrap();
        close_connection.register_stage_output(0, 50, 0).unwrap();
        close_connection.reserve_as_base(0, 10).unwrap();
        close_connection.close().unwrap();
        let counters = close_connection.stage_counters().get(&0).unwrap();
        assert_eq!((counters.reserved_as_base, counters.burned), (10, 40));
        drop(close_connection);

        let malformed_binding = connection_binding(0xc4, ConnectionStagePlan::TerminalOne);
        let mut malformed = connections.create(malformed_binding, None).unwrap();
        malformed.activate([0xc5; 32]).unwrap();
        malformed.register_stage_output(0, 10, 0).unwrap();
        malformed
            .begin_response(
                &authorizations,
                malformed_binding.response_binding([0xc6; 32]).unwrap(),
            )
            .unwrap();
        assert!(malformed
            .ingest_serialized_frame(ConnectionChannelDirection::VerifierToProver, &[1, 2, 3])
            .unwrap_err()
            .to_string()
            .contains("malformed"));
        assert_eq!(
            malformed.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::MalformedFrame }
        );
        drop(malformed);

        let eof_binding = connection_binding(0xc7, ConnectionStagePlan::TerminalOne);
        let mut eof = connections.create(eof_binding, None).unwrap();
        eof.activate([0xc8; 32]).unwrap();
        eof.unexpected_eof().unwrap();
        assert_eq!(
            eof.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::UnexpectedEof }
        );
        drop(eof);

        let abort_binding = connection_binding(0xc9, ConnectionStagePlan::TerminalOne);
        let mut explicit_abort = connections.create(abort_binding, None).unwrap();
        explicit_abort.activate([0xca; 32]).unwrap();
        explicit_abort.abort(ConnectionAbortReason::ExplicitAbort).unwrap();
        assert_eq!(
            explicit_abort.state(),
            ConnectionState::Terminal { reason: ConnectionAbortReason::ExplicitAbort }
        );
        drop(explicit_abort);
        std::fs::remove_dir_all(root).unwrap();
    }
}

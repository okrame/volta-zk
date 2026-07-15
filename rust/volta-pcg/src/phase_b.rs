//! Real two-party malicious Goldilocks sVOLE setup.
//!
//! The two roles below never share an RNG seed or an in-memory correlation
//! object. Every value that moves between them is encoded as a length-delimited
//! frame by [`SerializedChannel`]. `Delta` is sampled inside [`VerifierSetup`]
//! and is deliberately absent from every message type.
//!
//! Protocol references are Weng--Yang--Katz--Wang (WYKW), *Wolverine*, IEEE
//! S&P 2021 / ePrint 2020/925. The bootstrap follows the base-sVOLE protocol
//! in Section 5, Figure 5, with COPEe from Appendix B.1, Figure 15. Sparse
//! errors use Section 5.1, Figure 7. In particular, [`wykw_consistency_check`]
//! is the **batched single-point-sVOLE consistency check** from Figure 7,
//! steps 4--6 and Section 5.1 optimization 3 (pp. 15--16 of the ePrint).
//! The LPN extension is Section 5.2, Figure 8. [`PhaseAParams`] pins the
//! published Section 6.1 Table-2 main tuple and the preregistered hardened
//! setup tuple; its serialized metadata records the exact estimator commits
//! and margins.

use super::{
    ConsistencyReport, FullVole, PhaseAParams, ProverPcgPool, SubVole, VerifierPcgPool, GAMMA,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};
use volta_field::{Fp, Fp2, FpStream};

const BASE_OT_COUNT: usize = 128;
const CHECK_LIMBS: usize = 2;
const FRAME_HEADER_BYTES: usize = 9;
const IKNP_CHECK_REPS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseBError(String);

impl PhaseBError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PhaseBError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PhaseBError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseBSetupParams {
    pub profile: String,
    pub base_ot_count: usize,
    pub extended_ot_count: usize,
    pub setup_ggm_path_depth: u32,
    pub ggm_path_depth: u32,
    pub setup_security_bits: u32,
    pub malicious_check: String,
    pub malicious_check_paper_section: String,
    pub lpn_parameter_source: String,
    pub parity_candidate: bool,
    pub production_ready: bool,
}

/// Public identity material bound into every phase-B KDF and both role
/// transcripts without becoming a setup message field. `channel_id` is the
/// caller's authenticated transport identity (for example, a channel-exporter
/// digest), not a peer-selected display name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub response_authorization_nonce: [u8; 32],
}

impl SessionBinding {
    pub fn new(
        session_id: [u8; 32],
        channel_id: [u8; 32],
        response_authorization_nonce: [u8; 32],
    ) -> Result<Self, PhaseBError> {
        if session_id == [0; 32] || channel_id == [0; 32] || response_authorization_nonce == [0; 32]
        {
            return Err(PhaseBError::new(
                "session, channel, and response-authorization identities must be nonzero",
            ));
        }
        Ok(Self { session_id, channel_id, response_authorization_nonce })
    }

    fn deterministic(prover_seed: [u8; 32], verifier_seed: [u8; 32]) -> Self {
        fn component(prover_seed: [u8; 32], verifier_seed: [u8; 32], label: &[u8]) -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            h.update(b"volta-pcg/phase-b/deterministic-binding/v1");
            h.update(label);
            h.update(&prover_seed);
            h.update(&verifier_seed);
            *h.finalize().as_bytes()
        }
        Self {
            session_id: component(prover_seed, verifier_seed, b"session"),
            channel_id: component(prover_seed, verifier_seed, b"channel"),
            response_authorization_nonce: component(prover_seed, verifier_seed, b"authorization"),
        }
    }

    pub fn digest_hex(&self) -> String {
        hex32(binding_digest(self))
    }
}

impl PhaseBSetupParams {
    fn for_phase_a(params: &PhaseAParams) -> Self {
        Self {
            profile: "p7-phase-b-wykw-two-party-v2".into(),
            base_ot_count: BASE_OT_COUNT,
            extended_ot_count: params.setup_lpn_noise_weight * params.setup_ggm_depth as usize
                + params.lpn_noise_weight * params.ggm_depth as usize,
            setup_ggm_path_depth: params.setup_ggm_depth,
            ggm_path_depth: params.ggm_depth,
            setup_security_bits: 128,
            malicious_check: "WYKW batched single-point-sVOLE consistency check".into(),
            malicious_check_paper_section:
                "Wolverine ePrint 2020/925 Section 5.1, Figure 7 steps 4-6, optimization 3".into(),
            lpn_parameter_source: params.parameter_source.clone(),
            parity_candidate: true,
            // The cryptographic hardening can be a parity candidate without
            // making the separate product decision to flip the default.
            production_ready: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PhaseBTimings {
    pub t_base_ot_s: f64,
    /// IKNP expansion, COPEe PRF/corrections, and encrypted GGM-OT delivery.
    pub t_ot_extension_s: f64,
    /// Diagnostic subset of `t_ot_extension_s`: COPEe base-sVOLE bootstrap.
    pub t_base_vole_from_setup_s: f64,
    pub t_ggm_pprf_s: f64,
    pub t_lpn_expand_s: f64,
    /// Included in the LPN setup line; retained for historical schema readers.
    pub t_full_combine_s: f64,
    pub t_consistency_check_s: f64,
    pub t_total_setup_and_expansion_s: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SetupCommBreakdown {
    pub base_ot_bytes: u64,
    pub ot_extension_bytes: u64,
    pub ggm_bytes: u64,
    pub consistency_bytes: u64,
    pub prover_to_verifier_bytes: u64,
    pub verifier_to_prover_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ChannelAudit {
    pub base_ot_prover_to_verifier_bytes: u64,
    pub base_ot_verifier_to_prover_bytes: u64,
    pub ot_extension_prover_to_verifier_bytes: u64,
    pub ot_extension_verifier_to_prover_bytes: u64,
    pub ggm_prover_to_verifier_bytes: u64,
    pub ggm_verifier_to_prover_bytes: u64,
    pub check_prover_to_verifier_bytes: u64,
    pub check_verifier_to_prover_bytes: u64,
    pub prover_to_verifier_bytes: u64,
    pub verifier_to_prover_bytes: u64,
    pub total_bytes: u64,
    pub serialized_delta_found: bool,
    pub transcript_digest: String,
    #[serde(skip)]
    pub serialized_bytes: Vec<u8>,
}

impl ChannelAudit {
    fn comm(&self) -> SetupCommBreakdown {
        SetupCommBreakdown {
            base_ot_bytes: self.base_ot_prover_to_verifier_bytes
                + self.base_ot_verifier_to_prover_bytes,
            ot_extension_bytes: self.ot_extension_prover_to_verifier_bytes
                + self.ot_extension_verifier_to_prover_bytes,
            ggm_bytes: self.ggm_prover_to_verifier_bytes + self.ggm_verifier_to_prover_bytes,
            consistency_bytes: self.check_prover_to_verifier_bytes
                + self.check_verifier_to_prover_bytes,
            prover_to_verifier_bytes: self.prover_to_verifier_bytes,
            verifier_to_prover_bytes: self.verifier_to_prover_bytes,
            total_bytes: self.total_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseBSetupReport {
    pub params: PhaseBSetupParams,
    pub comm: SetupCommBreakdown,
    pub channel: ChannelAudit,
    pub base_ot_transcript_digest: String,
    pub ot_extension_digest: String,
    pub setup_binding_digest: String,
    pub consistency_challenge_source: String,
    pub role_seeds_shared: bool,
    pub delta_serialized: bool,
}

#[derive(Clone, Debug)]
pub struct PhaseBExpansion {
    pub params: PhaseAParams,
    pub setup: PhaseBSetupReport,
    pub prover: ProverPcgPool,
    pub verifier: VerifierPcgPool,
    /// Verifier-owned output needed only to construct `VerifierCtx` at the
    /// existing backend seam. It is never placed on the setup channel.
    pub verifier_delta: Fp2,
    pub timings: PhaseBTimings,
    pub consistency: ConsistencyReport,
    pub ggm_checksum: u64,
}

#[derive(Clone)]
struct RoleTranscript {
    hasher: blake3::Hasher,
}

impl RoleTranscript {
    fn new(binding: &SessionBinding) -> Self {
        Self { hasher: bound_channel_hasher(binding) }
    }

    fn observe(&mut self, direction: Direction, frame: &[u8]) {
        self.hasher.update(&[direction as u8]);
        self.hasher.update(frame);
    }

    fn digest(&self) -> [u8; 32] {
        *self.hasher.clone().finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Direction {
    ProverToVerifier = 0,
    VerifierToProver = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommPhase {
    BaseOt,
    OtExtension,
    Ggm,
    Check,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MessageKind {
    BaseOtA = 1,
    BaseOtB = 2,
    BaseOtCiphertexts = 3,
    CopeCorrections = 4,
    BaseCheckChallenge = 5,
    BaseCheckResponse = 6,
    BaseCheckAck = 7,
    IknpRows = 8,
    IknpCheckChallenge = 9,
    IknpCheckResponse = 10,
    IknpCheckAck = 11,
    GgmOtCiphertexts = 12,
    SetupBetaCorrections = 13,
    SetupGgmCorrections = 14,
    SetupWykwChallenge = 15,
    SetupWykwMask = 16,
    SetupEqCommit = 17,
    SetupEqResponse = 18,
    SetupEqOpen = 19,
    MainBetaCorrections = 20,
    MainGgmCorrections = 21,
    MainWykwChallenge = 22,
    MainWykwMask = 23,
    MainEqCommit = 24,
    MainEqResponse = 25,
    MainEqOpen = 26,
}

struct SerializedChannel {
    prover_to_verifier: VecDeque<Vec<u8>>,
    verifier_to_prover: VecDeque<Vec<u8>>,
    audit: ChannelAudit,
    audit_hasher: blake3::Hasher,
    capture: bool,
}

impl SerializedChannel {
    fn new(capture: bool, binding: &SessionBinding) -> Self {
        let audit_hasher = bound_channel_hasher(binding);
        Self {
            prover_to_verifier: VecDeque::new(),
            verifier_to_prover: VecDeque::new(),
            audit: ChannelAudit::default(),
            audit_hasher,
            capture,
        }
    }

    fn send(
        &mut self,
        direction: Direction,
        phase: CommPhase,
        kind: MessageKind,
        payload: Vec<u8>,
        transcript: &mut RoleTranscript,
    ) -> Result<(), PhaseBError> {
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| PhaseBError::new("serialized payload exceeds u64"))?;
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        frame.push(kind as u8);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&payload);
        let bytes = u64::try_from(frame.len())
            .map_err(|_| PhaseBError::new("serialized frame exceeds u64"))?;

        self.record(direction, phase, bytes);
        self.audit_hasher.update(&[direction as u8]);
        self.audit_hasher.update(&frame);
        if self.capture {
            self.audit.serialized_bytes.push(direction as u8);
            self.audit.serialized_bytes.extend_from_slice(&frame);
        }
        transcript.observe(direction, &frame);
        match direction {
            Direction::ProverToVerifier => self.prover_to_verifier.push_back(frame),
            Direction::VerifierToProver => self.verifier_to_prover.push_back(frame),
        }
        Ok(())
    }

    fn receive(
        &mut self,
        direction: Direction,
        expected: MessageKind,
        transcript: &mut RoleTranscript,
    ) -> Result<Vec<u8>, PhaseBError> {
        let frame = match direction {
            Direction::ProverToVerifier => self.prover_to_verifier.pop_front(),
            Direction::VerifierToProver => self.verifier_to_prover.pop_front(),
        }
        .ok_or_else(|| PhaseBError::new(format!("missing {:?} frame", expected)))?;
        if frame.len() < FRAME_HEADER_BYTES || frame[0] != expected as u8 {
            return Err(PhaseBError::new(format!("unexpected frame; wanted {:?}", expected)));
        }
        let declared = u64::from_le_bytes(frame[1..9].try_into().unwrap());
        let declared = usize::try_from(declared)
            .map_err(|_| PhaseBError::new("frame length exceeds usize"))?;
        if declared != frame.len() - FRAME_HEADER_BYTES {
            return Err(PhaseBError::new("non-canonical serialized frame length"));
        }
        transcript.observe(direction, &frame);
        Ok(frame[FRAME_HEADER_BYTES..].to_vec())
    }

    fn record(&mut self, direction: Direction, phase: CommPhase, bytes: u64) {
        match (phase, direction) {
            (CommPhase::BaseOt, Direction::ProverToVerifier) => {
                self.audit.base_ot_prover_to_verifier_bytes += bytes
            }
            (CommPhase::BaseOt, Direction::VerifierToProver) => {
                self.audit.base_ot_verifier_to_prover_bytes += bytes
            }
            (CommPhase::OtExtension, Direction::ProverToVerifier) => {
                self.audit.ot_extension_prover_to_verifier_bytes += bytes
            }
            (CommPhase::OtExtension, Direction::VerifierToProver) => {
                self.audit.ot_extension_verifier_to_prover_bytes += bytes
            }
            (CommPhase::Ggm, Direction::ProverToVerifier) => {
                self.audit.ggm_prover_to_verifier_bytes += bytes
            }
            (CommPhase::Ggm, Direction::VerifierToProver) => {
                self.audit.ggm_verifier_to_prover_bytes += bytes
            }
            (CommPhase::Check, Direction::ProverToVerifier) => {
                self.audit.check_prover_to_verifier_bytes += bytes
            }
            (CommPhase::Check, Direction::VerifierToProver) => {
                self.audit.check_verifier_to_prover_bytes += bytes
            }
        }
        match direction {
            Direction::ProverToVerifier => self.audit.prover_to_verifier_bytes += bytes,
            Direction::VerifierToProver => self.audit.verifier_to_prover_bytes += bytes,
        }
        self.audit.total_bytes += bytes;
    }

    fn finish(mut self) -> Result<ChannelAudit, PhaseBError> {
        if !self.prover_to_verifier.is_empty() || !self.verifier_to_prover.is_empty() {
            return Err(PhaseBError::new("unconsumed setup channel frames"));
        }
        self.audit.transcript_digest = hex32(*self.audit_hasher.finalize().as_bytes());
        Ok(self.audit)
    }
}

#[derive(Clone, Copy)]
struct SeedPair {
    zero: [u8; 32],
    one: [u8; 32],
}

/// Prover-side phase-B state. There is intentionally no `Delta` field.
pub struct ProverSetup {
    private_seed: [u8; 32],
    transcript: RoleTranscript,
    base_ot_pairs: Vec<SeedPair>,
}

impl ProverSetup {
    pub fn new(private_seed: [u8; 32], binding: &SessionBinding) -> Self {
        Self { private_seed, transcript: RoleTranscript::new(binding), base_ot_pairs: Vec::new() }
    }
}

/// Verifier-side phase-B state. `Delta` and its bit decomposition never leave
/// this object except as the final verifier-owned backend value.
pub struct VerifierSetup {
    private_seed: [u8; 32],
    delta: Fp2,
    delta_bits: [bool; BASE_OT_COUNT],
    transcript: RoleTranscript,
    base_ot_selected: Vec<[u8; 32]>,
}

impl VerifierSetup {
    pub fn new(private_seed: [u8; 32], binding: &SessionBinding) -> Self {
        let mut stream = FpStream::from_seed(derive_seed(private_seed, b"verifier-delta", 0));
        let mut delta = stream.next_fp2();
        if delta == Fp2::ZERO {
            delta = Fp2::ONE;
        }
        // The paper's (w, v) shares map to VOLTA's (m, k), so this module
        // uses w = v - Delta*u, equivalently k = m + Delta*u.
        let delta_bits = fp2_bits(delta);
        Self {
            private_seed,
            delta,
            delta_bits,
            transcript: RoleTranscript::new(binding),
            base_ot_selected: Vec::new(),
        }
    }

    pub fn delta(&self) -> Fp2 {
        self.delta
    }
}

#[derive(Default)]
struct TimingAccumulator {
    base_ot: Duration,
    ot_extension: Duration,
    base_vole: Duration,
    ggm: Duration,
    lpn: Duration,
    full_combine: Duration,
    check: Duration,
}

impl TimingAccumulator {
    fn finish(self, total: Duration) -> PhaseBTimings {
        PhaseBTimings {
            t_base_ot_s: self.base_ot.as_secs_f64(),
            t_ot_extension_s: self.ot_extension.as_secs_f64(),
            t_base_vole_from_setup_s: self.base_vole.as_secs_f64(),
            t_ggm_pprf_s: self.ggm.as_secs_f64(),
            t_lpn_expand_s: self.lpn.as_secs_f64(),
            t_full_combine_s: self.full_combine.as_secs_f64(),
            t_consistency_check_s: self.check.as_secs_f64(),
            t_total_setup_and_expansion_s: total.as_secs_f64(),
        }
    }
}

#[derive(Clone, Debug)]
struct ProverBase {
    r: Vec<Fp>,
    m: Vec<Fp2>,
}

#[derive(Clone, Debug)]
struct VerifierBase {
    k: Vec<Fp2>,
}

#[derive(Clone, Debug)]
struct SparseSecrets {
    alpha: Vec<usize>,
    beta: Vec<Fp>,
    block_size: usize,
}

#[derive(Clone, Debug)]
struct ProverNoise {
    tags: Vec<Fp2>,
}

#[derive(Clone, Debug)]
struct VerifierNoise {
    keys: Vec<Fp2>,
}

#[derive(Clone)]
struct IknpReceiverOutput {
    choices: Vec<u8>,
    keys: Vec<[u8; 32]>,
}

#[derive(Clone)]
struct IknpSenderOutput {
    keys: Vec<SeedPair>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Faults {
    tamper_ggm_leaf: bool,
    corrupt_ggm_correction: bool,
    cheat_consistency_response: bool,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PhaseBError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| PhaseBError::new("serialized offset overflow"))?;
        if end > self.bytes.len() {
            return Err(PhaseBError::new("truncated serialized setup message"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u64(&mut self) -> Result<u64, PhaseBError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn fp(&mut self) -> Result<Fp, PhaseBError> {
        let raw = self.u64()?;
        if raw >= volta_field::P {
            return Err(PhaseBError::new("non-canonical Goldilocks element"));
        }
        Ok(Fp::new(raw))
    }

    fn fp2(&mut self) -> Result<Fp2, PhaseBError> {
        Ok(Fp2::new(self.fp()?, self.fp()?))
    }

    fn array32(&mut self) -> Result<[u8; 32], PhaseBError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn finish(self) -> Result<(), PhaseBError> {
        if self.offset != self.bytes.len() {
            return Err(PhaseBError::new("trailing bytes in serialized setup message"));
        }
        Ok(())
    }
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_usize(out: &mut Vec<u8>, value: usize) -> Result<(), PhaseBError> {
    put_u64(
        out,
        u64::try_from(value).map_err(|_| PhaseBError::new("usize exceeds serialized u64"))?,
    );
    Ok(())
}

fn put_fp(out: &mut Vec<u8>, value: Fp) {
    put_u64(out, value.value());
}

fn put_fp2(out: &mut Vec<u8>, value: Fp2) {
    put_fp(out, value.c0);
    put_fp(out, value.c1);
}

fn fp2_bytes(value: Fp2) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&value.c0.value().to_le_bytes());
    out[8..].copy_from_slice(&value.c1.value().to_le_bytes());
    out
}

fn fp2_bits(value: Fp2) -> [bool; BASE_OT_COUNT] {
    let mut out = [false; BASE_OT_COUNT];
    for (component, raw) in [value.c0.value(), value.c1.value()].into_iter().enumerate() {
        for bit in 0..64 {
            out[component * 64 + bit] = (raw >> bit) & 1 == 1;
        }
    }
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn binding_digest(binding: &SessionBinding) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/session-binding/v1");
    h.update(&binding.session_id);
    h.update(&binding.channel_id);
    h.update(&binding.response_authorization_nonce);
    *h.finalize().as_bytes()
}

fn bound_channel_hasher(binding: &SessionBinding) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta-pcg/phase-b/channel/v2");
    hasher.update(&binding_digest(binding));
    hasher
}

pub(crate) fn bind_role_entropy(
    raw_entropy: [u8; 32],
    binding: &SessionBinding,
    role: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/role-entropy/v1");
    h.update(&binding_digest(binding));
    h.update(&(role.len() as u64).to_le_bytes());
    h.update(role);
    h.update(&raw_entropy);
    *h.finalize().as_bytes()
}

fn derive_seed(seed: [u8; 32], label: &[u8], ctr: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/kdf/v1");
    h.update(&seed);
    h.update(&(label.len() as u64).to_le_bytes());
    h.update(label);
    h.update(&ctr.to_le_bytes());
    *h.finalize().as_bytes()
}

fn bind_seed(binding: [u8; 32], nonce: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/transcript-challenge/v1");
    h.update(&binding);
    h.update(&nonce);
    h.update(&(label.len() as u64).to_le_bytes());
    h.update(label);
    *h.finalize().as_bytes()
}

fn scalar_from_seed(seed: [u8; 32], label: &[u8], ctr: u64) -> Scalar {
    let lo = derive_seed(seed, label, ctr);
    let hi = derive_seed(seed, label, ctr ^ 0xFFFF_FFFF_0000_0000);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&lo);
    wide[32..].copy_from_slice(&hi);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    if scalar == Scalar::ZERO {
        Scalar::ONE
    } else {
        scalar
    }
}

fn point_key(point: RistrettoPoint, index: usize, branch: bool) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/base-ot-key/v1");
    h.update(point.compress().as_bytes());
    h.update(&(index as u64).to_le_bytes());
    h.update(&[branch as u8]);
    *h.finalize().as_bytes()
}

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn xor32_in_place(out: &mut [u8; 32], rhs: &[u8; 32]) {
    for i in 0..32 {
        out[i] ^= rhs[i];
    }
}

fn hex32(x: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in x {
        use fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn xof(seed: [u8; 32], label: &[u8], len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/xof/v1");
    h.update(&seed);
    h.update(&(label.len() as u64).to_le_bytes());
    h.update(label);
    let mut reader = h.finalize_xof();
    let mut out = vec![0u8; len];
    reader.fill(&mut out);
    out
}

fn basis_mul(bit: usize, value: Fp) -> Fp2 {
    let weight = Fp::new(2).pow((bit % 64) as u64);
    if bit < 64 {
        Fp2::from_base(weight * value)
    } else {
        GAMMA.mul_base(weight * value)
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn seed_word(seed: [u8; 32]) -> u64 {
    u64::from_le_bytes(seed[..8].try_into().unwrap())
}

fn validate_params(
    params: &PhaseAParams,
    sub_corrs: usize,
    full_corrs: usize,
) -> Result<(), PhaseBError> {
    let expected = sub_corrs
        .checked_add(
            full_corrs
                .checked_mul(2)
                .ok_or_else(|| PhaseBError::new("full-correlation count overflow"))?,
        )
        .ok_or_else(|| PhaseBError::new("sub-equivalent count overflow"))?;
    if params.output_sub_equiv != expected {
        return Err(PhaseBError::new("phase-B params/count mismatch"));
    }
    if params.lpn_n != params.lpn_noise_weight * params.ggm_block_size
        || params.setup_lpn_n != params.setup_lpn_noise_weight * params.setup_ggm_block_size
        || params.ggm_block_size != 1usize << params.ggm_depth
        || params.setup_ggm_block_size != 1usize << params.setup_ggm_depth
    {
        return Err(PhaseBError::new(
            "regular-LPN dimensions must be exact power-of-two GGM blocks",
        ));
    }
    if params.base_vole_len != params.lpn_k + params.lpn_noise_weight + CHECK_LIMBS {
        return Err(PhaseBError::new("phase-B base-sVOLE reservation mismatch"));
    }
    let capacity = params
        .lpn_n
        .checked_sub(params.lpn_k + params.lpn_noise_weight + CHECK_LIMBS)
        .ok_or_else(|| PhaseBError::new("invalid extend LPN dimensions"))?;
    if expected > capacity {
        return Err(PhaseBError::new("WYKW regular-LPN extend capacity exceeded"));
    }
    let setup_capacity = params
        .setup_lpn_n
        .checked_sub(params.setup_lpn_k + params.setup_lpn_noise_weight + CHECK_LIMBS)
        .ok_or_else(|| PhaseBError::new("invalid setup LPN dimensions"))?;
    if params.base_vole_len > setup_capacity {
        return Err(PhaseBError::new("WYKW regular-LPN setup capacity exceeded"));
    }
    Ok(())
}

fn field_xof(seed: [u8; 32], label: &[u8], n: usize) -> Vec<Fp> {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/field-xof/v1");
    h.update(&seed);
    h.update(&(label.len() as u64).to_le_bytes());
    h.update(label);
    let mut reader = h.finalize_xof();
    let mut out = Vec::with_capacity(n);
    let mut raw = [0u8; 8];
    while out.len() < n {
        reader.fill(&mut raw);
        let value = u64::from_le_bytes(raw);
        if value < volta_field::P {
            out.push(Fp::new(value));
        }
    }
    out
}

fn seed_fp2(seed: [u8; 32], label: &[u8]) -> Fp2 {
    let mut stream = FpStream::from_seed(derive_seed(seed, label, 0));
    stream.next_fp2()
}

fn decode_point(bytes: &[u8]) -> Result<RistrettoPoint, PhaseBError> {
    let raw: [u8; 32] =
        bytes.try_into().map_err(|_| PhaseBError::new("invalid compressed Ristretto length"))?;
    CompressedRistretto(raw)
        .decompress()
        .ok_or_else(|| PhaseBError::new("invalid compressed Ristretto point"))
}

/// Execute 128 Simplest-OT instances over Ristretto. The prover is the OT
/// sender and the verifier's receiver choices are the verifier-owned bit
/// decomposition of `Delta`; the encrypted random seeds are the COPE/IKNP
/// bootstrap. Both roles validate every received group element.
fn run_base_ot(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
) -> Result<[u8; 32], PhaseBError> {
    let mut scalars = Vec::with_capacity(BASE_OT_COUNT);
    let mut a_payload = Vec::with_capacity(BASE_OT_COUNT * 32);
    for i in 0..BASE_OT_COUNT {
        let a = scalar_from_seed(prover.private_seed, b"base-ot/a", i as u64);
        let point = a * RISTRETTO_BASEPOINT_POINT;
        scalars.push(a);
        a_payload.extend_from_slice(point.compress().as_bytes());
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::BaseOt,
        MessageKind::BaseOtA,
        a_payload,
        &mut prover.transcript,
    )?;
    let a_payload = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::BaseOtA,
        &mut verifier.transcript,
    )?;

    let mut receiver_scalars = Vec::with_capacity(BASE_OT_COUNT);
    let mut a_points = Vec::with_capacity(BASE_OT_COUNT);
    let mut b_payload = Vec::with_capacity(BASE_OT_COUNT * 32);
    for i in 0..BASE_OT_COUNT {
        let a_point = decode_point(&a_payload[i * 32..(i + 1) * 32])?;
        let b = scalar_from_seed(verifier.private_seed, b"base-ot/b", i as u64);
        let mut b_point = b * RISTRETTO_BASEPOINT_POINT;
        if verifier.delta_bits[i] {
            b_point += a_point;
        }
        receiver_scalars.push(b);
        a_points.push(a_point);
        b_payload.extend_from_slice(b_point.compress().as_bytes());
    }
    channel.send(
        Direction::VerifierToProver,
        CommPhase::BaseOt,
        MessageKind::BaseOtB,
        b_payload,
        &mut verifier.transcript,
    )?;
    let b_payload = channel.receive(
        Direction::VerifierToProver,
        MessageKind::BaseOtB,
        &mut prover.transcript,
    )?;

    let mut ciphertexts = Vec::with_capacity(BASE_OT_COUNT * 64);
    for i in 0..BASE_OT_COUNT {
        let b_point = decode_point(&b_payload[i * 32..(i + 1) * 32])?;
        let a_point = scalars[i] * RISTRETTO_BASEPOINT_POINT;
        let pair = SeedPair {
            zero: derive_seed(prover.private_seed, b"base-ot/m0", i as u64),
            one: derive_seed(prover.private_seed, b"base-ot/m1", i as u64),
        };
        let key0 = point_key(scalars[i] * b_point, i, false);
        let key1 = point_key(scalars[i] * (b_point - a_point), i, true);
        ciphertexts.extend_from_slice(&xor32(pair.zero, key0));
        ciphertexts.extend_from_slice(&xor32(pair.one, key1));
        prover.base_ot_pairs.push(pair);
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::BaseOt,
        MessageKind::BaseOtCiphertexts,
        ciphertexts,
        &mut prover.transcript,
    )?;
    let ciphertexts = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::BaseOtCiphertexts,
        &mut verifier.transcript,
    )?;
    for i in 0..BASE_OT_COUNT {
        let start = i * 64 + usize::from(verifier.delta_bits[i]) * 32;
        let ciphertext: [u8; 32] = ciphertexts[start..start + 32].try_into().unwrap();
        let key = point_key(receiver_scalars[i] * a_points[i], i, verifier.delta_bits[i]);
        verifier.base_ot_selected.push(xor32(ciphertext, key));
    }
    if prover.transcript.digest() != verifier.transcript.digest() {
        return Err(PhaseBError::new("base-OT transcript divergence"));
    }
    Ok(prover.transcript.digest())
}

fn cope_stream(seed: [u8; 32], branch: bool, n: usize) -> Vec<Fp> {
    field_xof(seed, if branch { b"cope/one" } else { b"cope/zero" }, n)
}

/// COPEe plus the WYKW Figure-5 base-sVOLE sacrifice check. `wanted`
/// correlations are returned; one additional COPE correlation is generated
/// and consumed by the check, so it can never enter either output pool.
fn run_cope_base_svole(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    wanted: usize,
    timings: &mut TimingAccumulator,
) -> Result<(ProverBase, VerifierBase), PhaseBError> {
    let extension_start = Instant::now();
    let n = wanted.checked_add(1).ok_or_else(|| PhaseBError::new("base-sVOLE length overflow"))?;
    let mut prover_m = vec![Fp2::ZERO; n];
    let mut verifier_k = vec![Fp2::ZERO; n];
    let mut corrections = Vec::with_capacity(BASE_OT_COUNT * n * 8);

    for bit in 0..BASE_OT_COUNT {
        let q0 = cope_stream(prover.base_ot_pairs[bit].zero, false, n);
        let q1 = cope_stream(prover.base_ot_pairs[bit].one, true, n);
        for j in 0..n {
            prover_m[j] += basis_mul(bit, q0[j]);
            // If Delta_bit=1, the verifier adds tau and obtains q0+u;
            // otherwise its selected q0 is already the desired summand.
            put_fp(&mut corrections, q0[j] - q1[j]);
        }
    }

    let mut r_stream = FpStream::from_seed(derive_seed(prover.private_seed, b"cope/u", 0));
    let mut prover_r = Vec::with_capacity(n);
    for _ in 0..n {
        prover_r.push(r_stream.next_fp());
    }
    // Add u to every bit correction. COPE's bit-weighted sum contributes
    // exactly Delta*u in F_p^2.
    for bit in 0..BASE_OT_COUNT {
        for j in 0..n {
            let offset = (bit * n + j) * 8;
            let old =
                Fp::new(u64::from_le_bytes(corrections[offset..offset + 8].try_into().unwrap()));
            corrections[offset..offset + 8]
                .copy_from_slice(&(old + prover_r[j]).value().to_le_bytes());
        }
    }

    channel.send(
        Direction::ProverToVerifier,
        CommPhase::OtExtension,
        MessageKind::CopeCorrections,
        corrections,
        &mut prover.transcript,
    )?;
    let corrections = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::CopeCorrections,
        &mut verifier.transcript,
    )?;
    let mut reader = Reader::new(&corrections);
    for bit in 0..BASE_OT_COUNT {
        let selected = cope_stream(verifier.base_ot_selected[bit], verifier.delta_bits[bit], n);
        for j in 0..n {
            let tau = reader.fp()?;
            let q = if verifier.delta_bits[bit] { selected[j] + tau } else { selected[j] };
            verifier_k[j] += basis_mul(bit, q);
        }
    }
    reader.finish()?;
    let extension_elapsed = extension_start.elapsed();
    timings.ot_extension += extension_elapsed;
    timings.base_vole += extension_elapsed;

    // Figure 5, steps 3-4: verifier challenge, then the prover's two linear
    // responses. The verifier checks K = M + Delta*R.
    let check_start = Instant::now();
    let verifier_binding = verifier.transcript.digest();
    let prover_binding = prover.transcript.digest();
    let nonce = derive_seed(verifier.private_seed, b"base-check/nonce", 0);
    let verifier_challenge_seed = bind_seed(verifier_binding, nonce, b"base-svole-check");
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        MessageKind::BaseCheckChallenge,
        nonce.to_vec(),
        &mut verifier.transcript,
    )?;
    let nonce_msg = channel.receive(
        Direction::VerifierToProver,
        MessageKind::BaseCheckChallenge,
        &mut prover.transcript,
    )?;
    let prover_nonce: [u8; 32] =
        nonce_msg.try_into().map_err(|_| PhaseBError::new("invalid base-sVOLE challenge nonce"))?;
    let prover_challenge_seed = bind_seed(prover_binding, prover_nonce, b"base-svole-check");
    let prover_chi = field_xof(prover_challenge_seed, b"chi", wanted);
    let mut response_r = prover_r[wanted];
    let mut response_m = prover_m[wanted];
    for i in 0..wanted {
        response_r += prover_chi[i] * prover_r[i];
        response_m += prover_m[i].mul_base(prover_chi[i]);
    }
    let mut response = Vec::with_capacity(24);
    put_fp(&mut response, response_r);
    put_fp2(&mut response, response_m);
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::Check,
        MessageKind::BaseCheckResponse,
        response,
        &mut prover.transcript,
    )?;
    let response = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::BaseCheckResponse,
        &mut verifier.transcript,
    )?;
    let mut response_reader = Reader::new(&response);
    let response_r = response_reader.fp()?;
    let response_m = response_reader.fp2()?;
    response_reader.finish()?;
    let verifier_chi = field_xof(verifier_challenge_seed, b"chi", wanted);
    let mut expected_k = verifier_k[wanted];
    for i in 0..wanted {
        expected_k += verifier_k[i].mul_base(verifier_chi[i]);
    }
    if expected_k != response_m + verifier.delta.mul_base(response_r) {
        return Err(PhaseBError::new("WYKW base-sVOLE sacrifice check rejected"));
    }
    let verifier_ack_binding = verifier.transcript.digest();
    let prover_ack_binding = prover.transcript.digest();
    let ack = derive_seed(verifier_ack_binding, b"base-check/ack", 0);
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        MessageKind::BaseCheckAck,
        ack.to_vec(),
        &mut verifier.transcript,
    )?;
    let got_ack = channel.receive(
        Direction::VerifierToProver,
        MessageKind::BaseCheckAck,
        &mut prover.transcript,
    )?;
    let expected_ack = derive_seed(prover_ack_binding, b"base-check/ack", 0);
    if got_ack.as_slice() != expected_ack {
        return Err(PhaseBError::new("base-sVOLE acknowledgement mismatch"));
    }
    timings.check += check_start.elapsed();

    prover_r.truncate(wanted);
    prover_m.truncate(wanted);
    verifier_k.truncate(wanted);
    Ok((ProverBase { r: prover_r, m: prover_m }, VerifierBase { k: verifier_k }))
}

fn get_bit(bytes: &[u8], index: usize) -> bool {
    (bytes[index / 8] >> (index % 8)) & 1 == 1
}

fn set_bit(bytes: &mut [u8], index: usize, value: bool) {
    let mask = 1u8 << (index % 8);
    if value {
        bytes[index / 8] |= mask;
    } else {
        bytes[index / 8] &= !mask;
    }
}

fn parity_and(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).fold(0u32, |acc, (x, y)| acc ^ (x & y).count_ones()) & 1 == 1
}

fn delta_bytes(bits: &[bool; BASE_OT_COUNT]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, bit) in bits.iter().copied().enumerate() {
        set_bit(&mut out, i, bit);
    }
    out
}

fn ot_column_key(column: [u8; 16], index: usize, branch: bool) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/iknp-column/v1");
    h.update(&(index as u64).to_le_bytes());
    h.update(&[branch as u8]);
    h.update(&column);
    *h.finalize().as_bytes()
}

fn column(rows: &[Vec<u8>], index: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for row in 0..BASE_OT_COUNT {
        set_bit(&mut out, row, get_bit(&rows[row], index));
    }
    out
}

fn sample_sparse(seed: [u8; 32], label: &[u8], blocks: usize, block_size: usize) -> SparseSecrets {
    let mut alpha = Vec::with_capacity(blocks);
    let mut beta = Vec::with_capacity(blocks);
    let mut beta_stream = FpStream::from_seed(derive_seed(seed, label, 1));
    let alpha_seed = seed_word(derive_seed(seed, label, 0));
    for block in 0..blocks {
        // All production block sizes are powers of two, so this masking is an
        // exact uniform sample, not a modulo-biased shortcut.
        alpha.push(
            (splitmix64(alpha_seed ^ (block as u64).wrapping_mul(0xD1B5_4A32_D192_ED03)) as usize)
                & (block_size - 1),
        );
        let mut value = beta_stream.next_fp();
        if value == Fp::ZERO {
            value = Fp::ONE;
        }
        beta.push(value);
    }
    SparseSecrets { alpha, beta, block_size }
}

fn ggm_choice_bits(secrets: &SparseSecrets, depth: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(secrets.alpha.len() * depth as usize);
    for alpha in &secrets.alpha {
        for level in 0..depth as usize {
            let bit = (alpha >> (depth as usize - 1 - level)) & 1 == 1;
            // WYKW GGM reconstruction receives the aggregate for the branch
            // opposite the punctured path.
            out.push(u8::from(!bit));
        }
    }
    out
}

/// IKNP extension with a transcript-bound 128-fold row-correlation check.
/// Each check parity is one-time-padded by a fresh dummy receiver-choice
/// column, so the verifier learns no linear predicate of the GGM punctures.
fn run_iknp_extension(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    target_choices: Vec<u8>,
    timings: &mut TimingAccumulator,
) -> Result<(IknpReceiverOutput, IknpSenderOutput, [u8; 32]), PhaseBError> {
    let extension_start = Instant::now();
    let target_len = target_choices.len();
    let total_cols = target_len
        .checked_add(IKNP_CHECK_REPS)
        .ok_or_else(|| PhaseBError::new("IKNP column count overflow"))?;
    let row_bytes = (total_cols + 7) / 8;
    let mut choices = target_choices;
    let dummy = xof(
        derive_seed(prover.private_seed, b"iknp/dummy-choices", 0),
        b"bits",
        (IKNP_CHECK_REPS + 7) / 8,
    );
    for i in 0..IKNP_CHECK_REPS {
        choices.push(u8::from(get_bit(&dummy, i)));
    }
    let mut choice_bytes = vec![0u8; row_bytes];
    for (i, choice) in choices.iter().copied().enumerate() {
        set_bit(&mut choice_bytes, i, choice != 0);
    }

    let mut t_rows = Vec::with_capacity(BASE_OT_COUNT);
    let mut rows_payload = Vec::with_capacity(8 + BASE_OT_COUNT * row_bytes);
    put_usize(&mut rows_payload, total_cols)?;
    for i in 0..BASE_OT_COUNT {
        let t0 = xof(prover.base_ot_pairs[i].zero, b"iknp/row-zero", row_bytes);
        let t1 = xof(prover.base_ot_pairs[i].one, b"iknp/row-one", row_bytes);
        let mut u = vec![0u8; row_bytes];
        for j in 0..row_bytes {
            u[j] = t0[j] ^ t1[j] ^ choice_bytes[j];
        }
        // Unused high bits are canonical zeroes in every row and choice.
        if total_cols % 8 != 0 {
            let mask = (1u8 << (total_cols % 8)) - 1;
            u[row_bytes - 1] &= mask;
        }
        rows_payload.extend_from_slice(&u);
        t_rows.push(t0);
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::OtExtension,
        MessageKind::IknpRows,
        rows_payload,
        &mut prover.transcript,
    )?;
    let rows_payload = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::IknpRows,
        &mut verifier.transcript,
    )?;
    let mut rows_reader = Reader::new(&rows_payload);
    let received_cols = usize::try_from(rows_reader.u64()?)
        .map_err(|_| PhaseBError::new("IKNP column count exceeds usize"))?;
    if received_cols != total_cols {
        return Err(PhaseBError::new("IKNP column count mismatch"));
    }
    let mut q_rows = Vec::with_capacity(BASE_OT_COUNT);
    for i in 0..BASE_OT_COUNT {
        let u = rows_reader.take(row_bytes)?;
        let mut q = xof(
            verifier.base_ot_selected[i],
            if verifier.delta_bits[i] { b"iknp/row-one" } else { b"iknp/row-zero" },
            row_bytes,
        );
        if verifier.delta_bits[i] {
            for j in 0..row_bytes {
                q[j] ^= u[j];
            }
        }
        q_rows.push(q);
    }
    rows_reader.finish()?;
    timings.ot_extension += extension_start.elapsed();

    let check_start = Instant::now();
    let verifier_binding = verifier.transcript.digest();
    let prover_binding = prover.transcript.digest();
    let nonce = derive_seed(verifier.private_seed, b"iknp/check-nonce", 0);
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        MessageKind::IknpCheckChallenge,
        nonce.to_vec(),
        &mut verifier.transcript,
    )?;
    let nonce_msg = channel.receive(
        Direction::VerifierToProver,
        MessageKind::IknpCheckChallenge,
        &mut prover.transcript,
    )?;
    let prover_nonce: [u8; 32] =
        nonce_msg.try_into().map_err(|_| PhaseBError::new("invalid IKNP check nonce"))?;
    let verifier_check_seed = bind_seed(verifier_binding, nonce, b"iknp-row-correlation");
    let prover_check_seed = bind_seed(prover_binding, prover_nonce, b"iknp-row-correlation");
    let mut response = Vec::with_capacity(IKNP_CHECK_REPS * 17);
    for rep in 0..IKNP_CHECK_REPS {
        let mut chi = xof(
            derive_seed(prover_check_seed, b"iknp/check-vector", rep as u64),
            b"target",
            row_bytes,
        );
        // The unique dummy coefficient masks the disclosed parity.
        for dummy_index in target_len..total_cols {
            set_bit(&mut chi, dummy_index, dummy_index == target_len + rep);
        }
        if total_cols % 8 != 0 {
            let mask = (1u8 << (total_cols % 8)) - 1;
            chi[row_bytes - 1] &= mask;
        }
        response.push(u8::from(parity_and(&choice_bytes, &chi)));
        let mut packed_t = [0u8; 16];
        for row in 0..BASE_OT_COUNT {
            set_bit(&mut packed_t, row, parity_and(&t_rows[row], &chi));
        }
        response.extend_from_slice(&packed_t);
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::Check,
        MessageKind::IknpCheckResponse,
        response,
        &mut prover.transcript,
    )?;
    let response = channel.receive(
        Direction::ProverToVerifier,
        MessageKind::IknpCheckResponse,
        &mut verifier.transcript,
    )?;
    let mut response_reader = Reader::new(&response);
    for rep in 0..IKNP_CHECK_REPS {
        let x = response_reader.take(1)?[0];
        if x > 1 {
            return Err(PhaseBError::new("non-canonical IKNP parity response"));
        }
        let packed_t = response_reader.take(16)?;
        let mut chi = xof(
            derive_seed(verifier_check_seed, b"iknp/check-vector", rep as u64),
            b"target",
            row_bytes,
        );
        for dummy_index in target_len..total_cols {
            set_bit(&mut chi, dummy_index, dummy_index == target_len + rep);
        }
        if total_cols % 8 != 0 {
            let mask = (1u8 << (total_cols % 8)) - 1;
            chi[row_bytes - 1] &= mask;
        }
        for row in 0..BASE_OT_COUNT {
            let q_parity = parity_and(&q_rows[row], &chi);
            let t_parity = get_bit(packed_t, row);
            let expected = t_parity ^ (verifier.delta_bits[row] && x == 1);
            if q_parity != expected {
                return Err(PhaseBError::new("malicious IKNP correlation check rejected"));
            }
        }
    }
    response_reader.finish()?;
    let verifier_ack_binding = verifier.transcript.digest();
    let prover_ack_binding = prover.transcript.digest();
    let ack = derive_seed(verifier_ack_binding, b"iknp/check-ack", 0);
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        MessageKind::IknpCheckAck,
        ack.to_vec(),
        &mut verifier.transcript,
    )?;
    let got_ack = channel.receive(
        Direction::VerifierToProver,
        MessageKind::IknpCheckAck,
        &mut prover.transcript,
    )?;
    let expected_ack = derive_seed(prover_ack_binding, b"iknp/check-ack", 0);
    if got_ack.as_slice() != expected_ack {
        return Err(PhaseBError::new("IKNP check acknowledgement mismatch"));
    }
    timings.check += check_start.elapsed();

    let hash_start = Instant::now();
    let delta_column = delta_bytes(&verifier.delta_bits);
    let mut receiver_keys = Vec::with_capacity(target_len);
    let mut sender_keys = Vec::with_capacity(target_len);
    for i in 0..target_len {
        let t_column = column(&t_rows, i);
        let q_column = column(&q_rows, i);
        let mut q_xor_delta = q_column;
        for j in 0..16 {
            q_xor_delta[j] ^= delta_column[j];
        }
        receiver_keys.push(ot_column_key(t_column, i, choices[i] != 0));
        sender_keys.push(SeedPair {
            zero: ot_column_key(q_column, i, false),
            one: ot_column_key(q_xor_delta, i, true),
        });
    }
    let digest = prover.transcript.digest();
    if digest != verifier.transcript.digest() {
        return Err(PhaseBError::new("IKNP transcript divergence"));
    }
    timings.ot_extension += hash_start.elapsed();
    Ok((
        IknpReceiverOutput { choices: choices[..target_len].to_vec(), keys: receiver_keys },
        IknpSenderOutput { keys: sender_keys },
        digest,
    ))
}

fn apply_beta_corrections(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    prover_beta: &mut ProverBase,
    verifier_beta: &mut VerifierBase,
    secrets: &SparseSecrets,
    kind: MessageKind,
) -> Result<(), PhaseBError> {
    if prover_beta.r.len() != secrets.beta.len()
        || prover_beta.m.len() != secrets.beta.len()
        || verifier_beta.k.len() != secrets.beta.len()
    {
        return Err(PhaseBError::new("beta-correction input length mismatch"));
    }
    let mut payload = Vec::with_capacity(secrets.beta.len() * 8);
    for i in 0..secrets.beta.len() {
        let correction = secrets.beta[i] - prover_beta.r[i];
        put_fp(&mut payload, correction);
        prover_beta.r[i] = secrets.beta[i];
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::Ggm,
        kind,
        payload,
        &mut prover.transcript,
    )?;
    let payload = channel.receive(Direction::ProverToVerifier, kind, &mut verifier.transcript)?;
    let mut reader = Reader::new(&payload);
    for key in &mut verifier_beta.k {
        *key += verifier.delta.mul_base(reader.fp()?);
    }
    reader.finish()
}

fn ggm_children(seed: [u8; 32], level: usize) -> ([u8; 32], [u8; 32]) {
    (derive_seed(seed, b"ggm/left", level as u64), derive_seed(seed, b"ggm/right", level as u64))
}

/// Generate one WYKW GGM tree and the two XOR aggregates at every level.
/// The final leaves remain verifier-side; only encrypted aggregates cross the
/// channel through the IKNP OTs.
fn ggm_sender_tree(root: [u8; 32], depth: u32) -> (Vec<SeedPair>, Vec<[u8; 32]>) {
    let mut level = vec![root];
    let mut messages = Vec::with_capacity(depth as usize);
    for d in 0..depth as usize {
        let mut next = Vec::with_capacity(level.len() * 2);
        let mut zero = [0u8; 32];
        let mut one = [0u8; 32];
        for node in level {
            let (left, right) = ggm_children(node, d);
            xor32_in_place(&mut zero, &left);
            xor32_in_place(&mut one, &right);
            next.push(left);
            next.push(right);
        }
        messages.push(SeedPair { zero, one });
        level = next;
    }
    (messages, level)
}

fn prepare_ggm_sender(
    verifier_seed: [u8; 32],
    label: &[u8],
    blocks: usize,
    depth: u32,
) -> (Vec<SeedPair>, VerifierNoise, u64) {
    let block_size = 1usize << depth;
    // Blocks are independent PPRF instances. `IndexedParallelIterator::collect`
    // preserves block order, after which the historical sequential checksum is
    // replayed exactly. Thus only wall time moves: OT message order, leaf order,
    // payload bytes, and channel schedule remain byte-for-byte canonical.
    let prepared: Vec<(Vec<SeedPair>, Vec<Fp2>)> = (0..blocks)
        .into_par_iter()
        .map(|block| {
            let root = derive_seed(verifier_seed, label, block as u64);
            let (block_messages, leaves) = ggm_sender_tree(root, depth);
            let keys = leaves.into_iter().map(|leaf| seed_fp2(leaf, b"ggm/leaf-field")).collect();
            (block_messages, keys)
        })
        .collect();
    let mut messages = Vec::with_capacity(blocks * depth as usize);
    let mut keys = Vec::with_capacity(blocks * block_size);
    let mut checksum = 0xD6E8_FD50_4A5B_7C11u64;
    for (block, (block_messages, block_keys)) in prepared.into_iter().enumerate() {
        messages.extend(block_messages);
        for key in block_keys {
            checksum ^= key.c0.value().rotate_left((block & 63) as u32);
            checksum = checksum.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            checksum ^= key.c1.value();
            keys.push(key);
        }
    }
    (messages, VerifierNoise { keys }, checksum)
}

fn deliver_ggm_ots(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    receiver: &IknpReceiverOutput,
    sender: &IknpSenderOutput,
    messages: &[SeedPair],
) -> Result<Vec<[u8; 32]>, PhaseBError> {
    if messages.len() != receiver.keys.len()
        || messages.len() != sender.keys.len()
        || messages.len() != receiver.choices.len()
    {
        return Err(PhaseBError::new("GGM OT/message count mismatch"));
    }
    let mut payload = Vec::with_capacity(8 + messages.len() * 64);
    put_usize(&mut payload, messages.len())?;
    for (message, keys) in messages.iter().zip(&sender.keys) {
        payload.extend_from_slice(&xor32(message.zero, keys.zero));
        payload.extend_from_slice(&xor32(message.one, keys.one));
    }
    channel.send(
        Direction::VerifierToProver,
        CommPhase::OtExtension,
        MessageKind::GgmOtCiphertexts,
        payload,
        &mut verifier.transcript,
    )?;
    let payload = channel.receive(
        Direction::VerifierToProver,
        MessageKind::GgmOtCiphertexts,
        &mut prover.transcript,
    )?;
    let mut reader = Reader::new(&payload);
    let count = usize::try_from(reader.u64()?)
        .map_err(|_| PhaseBError::new("GGM OT count exceeds usize"))?;
    if count != messages.len() {
        return Err(PhaseBError::new("serialized GGM OT count mismatch"));
    }
    let mut selected = Vec::with_capacity(count);
    for i in 0..count {
        let zero: [u8; 32] = reader.take(32)?.try_into().unwrap();
        let one: [u8; 32] = reader.take(32)?.try_into().unwrap();
        let ciphertext = if receiver.choices[i] == 0 { zero } else { one };
        selected.push(xor32(ciphertext, receiver.keys[i]));
    }
    reader.finish()?;
    Ok(selected)
}

fn reconstruct_punctured_tree(
    aggregates: &[[u8; 32]],
    choice_bits: &[u8],
    depth: u32,
) -> Result<Vec<Option<[u8; 32]>>, PhaseBError> {
    if aggregates.len() != depth as usize || choice_bits.len() != depth as usize {
        return Err(PhaseBError::new("punctured GGM path length mismatch"));
    }
    let mut level: Vec<Option<[u8; 32]>> = vec![None];
    for d in 0..depth as usize {
        let mut next = Vec::with_capacity(level.len() * 2);
        for node in level {
            if let Some(seed) = node {
                let (left, right) = ggm_children(seed, d);
                next.push(Some(left));
                next.push(Some(right));
            } else {
                next.push(None);
                next.push(None);
            }
        }
        let parity = usize::from(choice_bits[d]);
        let missing: Vec<_> =
            (parity..next.len()).step_by(2).filter(|index| next[*index].is_none()).collect();
        if missing.len() != 1 {
            return Err(PhaseBError::new("GGM reconstruction lost puncture invariant"));
        }
        let mut recovered = aggregates[d];
        for index in (parity..next.len()).step_by(2) {
            if let Some(seed) = next[index] {
                xor32_in_place(&mut recovered, &seed);
            }
        }
        next[missing[0]] = Some(recovered);
        level = next;
    }
    if level.iter().filter(|leaf| leaf.is_none()).count() != 1 {
        return Err(PhaseBError::new("GGM reconstruction did not leave one puncture"));
    }
    Ok(level)
}

fn finish_ggm_phase(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    secrets: &SparseSecrets,
    depth: u32,
    selected_aggregates: &[[u8; 32]],
    beta_prover: &ProverBase,
    beta_verifier: &VerifierBase,
    verifier_noise: VerifierNoise,
    correction_kind: MessageKind,
    corrupt_correction: bool,
) -> Result<(ProverNoise, VerifierNoise), PhaseBError> {
    let blocks = secrets.alpha.len();
    let block_size = 1usize << depth;
    if block_size != secrets.block_size
        || selected_aggregates.len() != blocks * depth as usize
        || verifier_noise.keys.len() != blocks * block_size
        || beta_prover.m.len() != blocks
        || beta_verifier.k.len() != blocks
    {
        return Err(PhaseBError::new("GGM phase dimensions mismatch"));
    }
    let choices = ggm_choice_bits(secrets, depth);
    let block_tags: Result<Vec<Vec<Fp2>>, PhaseBError> = (0..blocks)
        .into_par_iter()
        .map(|block| {
            let start = block * depth as usize;
            let leaves = reconstruct_punctured_tree(
                &selected_aggregates[start..start + depth as usize],
                &choices[start..start + depth as usize],
                depth,
            )?;
            let missing = leaves.iter().position(Option::is_none).unwrap();
            if missing != secrets.alpha[block] {
                return Err(PhaseBError::new("GGM puncture/alpha mismatch"));
            }
            Ok(leaves
                .into_iter()
                .map(|leaf| leaf.map(|seed| seed_fp2(seed, b"ggm/leaf-field")).unwrap_or(Fp2::ZERO))
                .collect())
        })
        .collect();
    let mut prover_tags: Vec<Fp2> =
        block_tags?.into_iter().flat_map(|block| block.into_iter()).collect();

    let mut corrections = Vec::with_capacity(blocks * 16);
    let block_corrections: Vec<Fp2> = verifier_noise
        .keys
        .par_chunks(block_size)
        .enumerate()
        .map(|(block, keys)| {
            let sum = keys.iter().fold(Fp2::ZERO, |acc, key| acc + *key);
            let mut correction = beta_verifier.k[block] - sum;
            if corrupt_correction && block == 0 {
                correction += Fp2::ONE;
            }
            correction
        })
        .collect();
    for correction in block_corrections {
        put_fp2(&mut corrections, correction);
    }
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Ggm,
        correction_kind,
        corrections,
        &mut verifier.transcript,
    )?;
    let corrections =
        channel.receive(Direction::VerifierToProver, correction_kind, &mut prover.transcript)?;
    let mut reader = Reader::new(&corrections);
    let mut decoded_corrections = Vec::with_capacity(blocks);
    for _ in 0..blocks {
        decoded_corrections.push(reader.fp2()?);
    }
    reader.finish()?;
    prover_tags.par_chunks_mut(block_size).enumerate().for_each(|(block, tags)| {
        let sum_off = tags.iter().fold(Fp2::ZERO, |acc, tag| acc + *tag);
        tags[secrets.alpha[block]] = beta_prover.m[block] - decoded_corrections[block] - sum_off;
    });
    Ok((ProverNoise { tags: prover_tags }, verifier_noise))
}

fn wykw_chi(seed: [u8; 32], rep: usize, block: usize, block_size: usize) -> Vec<Fp> {
    field_xof(
        derive_seed(seed, b"wykw/chi-block", ((rep as u64) << 32) ^ block as u64),
        b"coefficients",
        block_size,
    )
}

fn wykw_commit(binding: [u8; 32], values: &[Fp2], blind: [u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/wykw-feq/v1");
    h.update(&binding);
    for value in values {
        h.update(&fp2_bytes(*value));
    }
    h.update(&blind);
    *h.finalize().as_bytes()
}

/// WYKW/Wolverine Section 5.1, Figure 7 steps 4--6, batched according to
/// optimization 3. For each repetition this proves
///
/// `sum_i chi_i*w_i - m_check = sum_i chi_i*v_i - (k_check - Delta*x*)`
///
/// where `x* = r_check - sum_j beta_j*chi_{j,alpha_j}`. The challenge is
/// derived from the complete serialized setup transcript immediately before
/// the check; the final equality uses a commit/response/open realization of
/// the paper's `F_eq` functionality.
fn wykw_consistency_check(
    prover: &mut ProverSetup,
    verifier: &mut VerifierSetup,
    channel: &mut SerializedChannel,
    secrets: &SparseSecrets,
    prover_noise: &mut ProverNoise,
    verifier_noise: &VerifierNoise,
    check_prover: &ProverBase,
    check_verifier: &VerifierBase,
    kinds: [MessageKind; 5],
    faults: Faults,
) -> Result<ConsistencyReport, PhaseBError> {
    if check_prover.r.len() != CHECK_LIMBS
        || check_prover.m.len() != CHECK_LIMBS
        || check_verifier.k.len() != CHECK_LIMBS
        || prover_noise.tags.len() != verifier_noise.keys.len()
        || prover_noise.tags.len() != secrets.alpha.len() * secrets.block_size
    {
        return Err(PhaseBError::new("WYKW check dimensions mismatch"));
    }
    if faults.tamper_ggm_leaf {
        let mut index = 0usize;
        if secrets.alpha[0] == 0 {
            index = 1;
        }
        prover_noise.tags[index] += Fp2::ONE;
    }

    let verifier_pre_challenge_binding = verifier.transcript.digest();
    let prover_pre_challenge_binding = prover.transcript.digest();
    let nonce = derive_seed(
        verifier.private_seed,
        b"wykw/challenge-nonce",
        verifier_noise.keys.len() as u64,
    );
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        kinds[0],
        nonce.to_vec(),
        &mut verifier.transcript,
    )?;
    let nonce_msg =
        channel.receive(Direction::VerifierToProver, kinds[0], &mut prover.transcript)?;
    let prover_nonce: [u8; 32] =
        nonce_msg.try_into().map_err(|_| PhaseBError::new("invalid WYKW challenge nonce"))?;
    let verifier_challenge_seed =
        bind_seed(verifier_pre_challenge_binding, nonce, b"wykw-spsvole-check");
    let prover_challenge_seed =
        bind_seed(prover_pre_challenge_binding, prover_nonce, b"wykw-spsvole-check");

    let blocks = secrets.alpha.len();
    let weighted_betas: Vec<Fp> = (0..CHECK_LIMBS * blocks)
        .into_par_iter()
        .map(|item| {
            let rep = item / blocks;
            let block = item % blocks;
            let chi = wykw_chi(prover_challenge_seed, rep, block, secrets.block_size);
            secrets.beta[block] * chi[secrets.alpha[block]]
        })
        .collect();
    let x_stars: Vec<Fp> = weighted_betas
        .chunks(blocks)
        .enumerate()
        .map(|(rep, contributions)| {
            let weighted_beta =
                contributions.iter().copied().fold(Fp::ZERO, |acc, value| acc + value);
            check_prover.r[rep] - weighted_beta
        })
        .collect();
    let mut mask_payload = Vec::with_capacity(CHECK_LIMBS * 8);
    for x in &x_stars {
        put_fp(&mut mask_payload, *x);
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::Check,
        kinds[1],
        mask_payload,
        &mut prover.transcript,
    )?;
    let mask_payload =
        channel.receive(Direction::ProverToVerifier, kinds[1], &mut verifier.transcript)?;
    let mut mask_reader = Reader::new(&mask_payload);
    let mut received_x = Vec::with_capacity(CHECK_LIMBS);
    for _ in 0..CHECK_LIMBS {
        received_x.push(mask_reader.fp()?);
    }
    mask_reader.finish()?;

    let verifier_block_values: Vec<Fp2> = (0..CHECK_LIMBS * blocks)
        .into_par_iter()
        .map(|item| {
            let rep = item / blocks;
            let block = item % blocks;
            let chi = wykw_chi(verifier_challenge_seed, rep, block, secrets.block_size);
            let start = block * secrets.block_size;
            chi.iter()
                .zip(&verifier_noise.keys[start..start + secrets.block_size])
                .fold(Fp2::ZERO, |acc, (coefficient, key)| acc + key.mul_base(*coefficient))
        })
        .collect();
    let verifier_values: Vec<Fp2> = verifier_block_values
        .chunks(blocks)
        .enumerate()
        .map(|(rep, contributions)| {
            let acc = contributions.iter().copied().fold(Fp2::ZERO, |acc, value| acc + value);
            let y_star = check_verifier.k[rep] - verifier.delta.mul_base(received_x[rep]);
            acc - y_star
        })
        .collect();
    let verifier_equality_binding = verifier.transcript.digest();
    let prover_equality_binding = prover.transcript.digest();
    let blind =
        derive_seed(verifier.private_seed, b"wykw/feq-blind", verifier_noise.keys.len() as u64);
    let commitment = wykw_commit(verifier_equality_binding, &verifier_values, blind);
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        kinds[2],
        commitment.to_vec(),
        &mut verifier.transcript,
    )?;
    let commitment_msg =
        channel.receive(Direction::VerifierToProver, kinds[2], &mut prover.transcript)?;
    if commitment_msg.len() != 32 {
        return Err(PhaseBError::new("invalid WYKW equality commitment"));
    }

    let prover_block_values: Vec<Fp2> = (0..CHECK_LIMBS * blocks)
        .into_par_iter()
        .map(|item| {
            let rep = item / blocks;
            let block = item % blocks;
            let chi = wykw_chi(prover_challenge_seed, rep, block, secrets.block_size);
            let start = block * secrets.block_size;
            chi.iter()
                .zip(&prover_noise.tags[start..start + secrets.block_size])
                .fold(Fp2::ZERO, |acc, (coefficient, tag)| acc + tag.mul_base(*coefficient))
        })
        .collect();
    let prover_values: Vec<Fp2> = prover_block_values
        .chunks(blocks)
        .enumerate()
        .map(|(rep, contributions)| {
            let acc = contributions.iter().copied().fold(Fp2::ZERO, |acc, value| acc + value);
            let mut value = acc - check_prover.m[rep];
            if faults.cheat_consistency_response && rep == 0 {
                value += Fp2::ONE;
            }
            value
        })
        .collect();
    let mut response_payload = Vec::with_capacity(CHECK_LIMBS * 16);
    for value in &prover_values {
        put_fp2(&mut response_payload, *value);
    }
    channel.send(
        Direction::ProverToVerifier,
        CommPhase::Check,
        kinds[3],
        response_payload,
        &mut prover.transcript,
    )?;
    let response_payload =
        channel.receive(Direction::ProverToVerifier, kinds[3], &mut verifier.transcript)?;
    let mut response_reader = Reader::new(&response_payload);
    let mut received_values = Vec::with_capacity(CHECK_LIMBS);
    for _ in 0..CHECK_LIMBS {
        received_values.push(response_reader.fp2()?);
    }
    response_reader.finish()?;
    if received_values != verifier_values {
        return Err(PhaseBError::new("WYKW batched single-point consistency check rejected"));
    }

    let mut open_payload = Vec::with_capacity(CHECK_LIMBS * 16 + 32);
    for value in &verifier_values {
        put_fp2(&mut open_payload, *value);
    }
    open_payload.extend_from_slice(&blind);
    channel.send(
        Direction::VerifierToProver,
        CommPhase::Check,
        kinds[4],
        open_payload,
        &mut verifier.transcript,
    )?;
    let open_payload =
        channel.receive(Direction::VerifierToProver, kinds[4], &mut prover.transcript)?;
    let mut open_reader = Reader::new(&open_payload);
    let mut opened_values = Vec::with_capacity(CHECK_LIMBS);
    for _ in 0..CHECK_LIMBS {
        opened_values.push(open_reader.fp2()?);
    }
    let opened_blind = open_reader.array32()?;
    open_reader.finish()?;
    if wykw_commit(prover_equality_binding, &opened_values, opened_blind)
        != commitment_msg.as_slice()
        || opened_values != prover_values
    {
        return Err(PhaseBError::new("WYKW equality opening rejected"));
    }
    let mut checksum = 0x5759_4B57_4348_4543u64;
    for value in prover_values {
        checksum ^= value.c0.value();
        checksum = checksum.rotate_left(17) ^ value.c1.value();
    }
    Ok(ConsistencyReport { ok: true, checksum })
}

fn split_base(
    mut prover: ProverBase,
    mut verifier: VerifierBase,
    k: usize,
    t: usize,
) -> Result<
    (ProverBase, VerifierBase, ProverBase, VerifierBase, ProverBase, VerifierBase),
    PhaseBError,
> {
    let total = k
        .checked_add(t)
        .and_then(|x| x.checked_add(CHECK_LIMBS))
        .ok_or_else(|| PhaseBError::new("base split length overflow"))?;
    if prover.r.len() != total || prover.m.len() != total || verifier.k.len() != total {
        return Err(PhaseBError::new("base split length mismatch"));
    }
    let check_r = prover.r.split_off(k + t);
    let check_m = prover.m.split_off(k + t);
    let check_k = verifier.k.split_off(k + t);
    let beta_r = prover.r.split_off(k);
    let beta_m = prover.m.split_off(k);
    let beta_k = verifier.k.split_off(k);
    Ok((
        prover,
        verifier,
        ProverBase { r: beta_r, m: beta_m },
        VerifierBase { k: beta_k },
        ProverBase { r: check_r, m: check_m },
        VerifierBase { k: check_k },
    ))
}

fn public_lpn_seed(params: &PhaseAParams, label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"volta-pcg/phase-b/public-lpn-code/v1");
    h.update(params.profile.as_bytes());
    h.update(label);
    h.update(&(params.code_fanout as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

fn lpn_row_indices(seed: [u8; 32], row: usize, k: usize, fanout: usize) -> Vec<usize> {
    let mut state = seed_word(seed) ^ (row as u64).wrapping_mul(0xA24B_AED4_963E_E407);
    let mut indices = Vec::with_capacity(fanout);
    for limb in 0..fanout {
        state = splitmix64(state ^ (limb as u64).wrapping_mul(0x9FB2_1C65_1E98_DF25));
        indices.push((state as usize) % k);
    }
    indices
}

fn lpn_expand_prover(
    code_seed: [u8; 32],
    base: &ProverBase,
    noise: &ProverNoise,
    secrets: &SparseSecrets,
    output: usize,
    fanout: usize,
) -> Result<ProverBase, PhaseBError> {
    if base.r.is_empty()
        || base.r.len() != base.m.len()
        || noise.tags.len() != secrets.alpha.len() * secrets.block_size
        || output > noise.tags.len()
    {
        return Err(PhaseBError::new("prover LPN dimensions mismatch"));
    }
    let mut r_out = Vec::with_capacity(output);
    let mut m_out = Vec::with_capacity(output);
    for row in 0..output {
        let mut r = Fp::ZERO;
        let mut m = noise.tags[row];
        for index in lpn_row_indices(code_seed, row, base.r.len(), fanout) {
            r += base.r[index];
            m += base.m[index];
        }
        let block = row / secrets.block_size;
        if row % secrets.block_size == secrets.alpha[block] {
            r += secrets.beta[block];
        }
        r_out.push(r);
        m_out.push(m);
    }
    Ok(ProverBase { r: r_out, m: m_out })
}

fn lpn_expand_verifier(
    code_seed: [u8; 32],
    base: &VerifierBase,
    noise: &VerifierNoise,
    output: usize,
    fanout: usize,
) -> Result<VerifierBase, PhaseBError> {
    if base.k.is_empty() || output > noise.keys.len() {
        return Err(PhaseBError::new("verifier LPN dimensions mismatch"));
    }
    let mut k_out = Vec::with_capacity(output);
    for row in 0..output {
        let mut k = noise.keys[row];
        for index in lpn_row_indices(code_seed, row, base.k.len(), fanout) {
            k += base.k[index];
        }
        k_out.push(k);
    }
    Ok(VerifierBase { k: k_out })
}

fn bases_to_pools(
    prover: ProverBase,
    verifier: VerifierBase,
    sub_corrs: usize,
    full_corrs: usize,
) -> Result<(ProverPcgPool, VerifierPcgPool), PhaseBError> {
    let expected = sub_corrs + 2 * full_corrs;
    if prover.r.len() != expected || prover.m.len() != expected || verifier.k.len() != expected {
        return Err(PhaseBError::new("expanded pool length mismatch"));
    }
    let mut prover_pool = ProverPcgPool {
        subs: Vec::with_capacity(sub_corrs),
        fulls: Vec::with_capacity(full_corrs),
    };
    let mut verifier_pool = VerifierPcgPool {
        sub_keys: Vec::with_capacity(sub_corrs),
        full_keys: Vec::with_capacity(full_corrs),
    };
    for i in 0..sub_corrs {
        prover_pool.subs.push(SubVole { r: prover.r[i], m: prover.m[i] });
        verifier_pool.sub_keys.push(verifier.k[i]);
    }
    for i in 0..full_corrs {
        let lo = sub_corrs + 2 * i;
        let hi = lo + 1;
        prover_pool.fulls.push(FullVole {
            x: Fp2::from_base(prover.r[lo]) + GAMMA.mul_base(prover.r[hi]),
            m: prover.m[lo] + GAMMA * prover.m[hi],
        });
        verifier_pool.full_keys.push(verifier.k[lo] + GAMMA * verifier.k[hi]);
    }
    Ok((prover_pool, verifier_pool))
}

fn phase_message_kinds(setup: bool) -> [MessageKind; 5] {
    if setup {
        [
            MessageKind::SetupWykwChallenge,
            MessageKind::SetupWykwMask,
            MessageKind::SetupEqCommit,
            MessageKind::SetupEqResponse,
            MessageKind::SetupEqOpen,
        ]
    } else {
        [
            MessageKind::MainWykwChallenge,
            MessageKind::MainWykwMask,
            MessageKind::MainEqCommit,
            MessageKind::MainEqResponse,
            MessageKind::MainEqOpen,
        ]
    }
}

fn expand_phase_b_internal(
    prover_seed: [u8; 32],
    verifier_seed: [u8; 32],
    prover_binding: SessionBinding,
    verifier_binding: SessionBinding,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
    capture_channel: bool,
    faults: Faults,
) -> Result<PhaseBExpansion, PhaseBError> {
    validate_params(&params, sub_corrs, full_corrs)?;
    if prover_seed == verifier_seed {
        return Err(PhaseBError::new("phase-B role seeds must be independently provisioned"));
    }
    if prover_binding.session_id != verifier_binding.session_id {
        return Err(PhaseBError::new("authenticated session identity mismatch"));
    }
    if prover_binding.channel_id != verifier_binding.channel_id {
        return Err(PhaseBError::new("authenticated channel identity mismatch"));
    }
    if prover_binding.response_authorization_nonce != verifier_binding.response_authorization_nonce
    {
        return Err(PhaseBError::new("response-authorization nonce mismatch"));
    }
    let setup_params = PhaseBSetupParams::for_phase_a(&params);
    let total_start = Instant::now();
    let mut timings = TimingAccumulator::default();
    let mut prover = ProverSetup::new(prover_seed, &prover_binding);
    let mut verifier = VerifierSetup::new(verifier_seed, &verifier_binding);
    let delta = verifier.delta();
    let mut channel = SerializedChannel::new(capture_channel, &prover_binding);

    let base_ot_start = Instant::now();
    let base_ot_digest = run_base_ot(&mut prover, &mut verifier, &mut channel)?;
    timings.base_ot += base_ot_start.elapsed();

    let direct_len = params.setup_lpn_k + params.setup_lpn_noise_weight + CHECK_LIMBS;
    let (direct_prover, direct_verifier) =
        run_cope_base_svole(&mut prover, &mut verifier, &mut channel, direct_len, &mut timings)?;
    let (
        setup_lpn_prover,
        setup_lpn_verifier,
        mut setup_beta_prover,
        mut setup_beta_verifier,
        setup_check_prover,
        setup_check_verifier,
    ) = split_base(
        direct_prover,
        direct_verifier,
        params.setup_lpn_k,
        params.setup_lpn_noise_weight,
    )?;

    let setup_secrets = sample_sparse(
        prover.private_seed,
        b"setup/sparse",
        params.setup_lpn_noise_weight,
        params.setup_ggm_block_size,
    );
    let main_secrets = sample_sparse(
        prover.private_seed,
        b"main/sparse",
        params.lpn_noise_weight,
        params.ggm_block_size,
    );
    let mut all_choices = ggm_choice_bits(&setup_secrets, params.setup_ggm_depth);
    all_choices.extend(ggm_choice_bits(&main_secrets, params.ggm_depth));
    let (iknp_receiver, iknp_sender, ot_extension_digest) =
        run_iknp_extension(&mut prover, &mut verifier, &mut channel, all_choices, &mut timings)?;

    apply_beta_corrections(
        &mut prover,
        &mut verifier,
        &mut channel,
        &mut setup_beta_prover,
        &mut setup_beta_verifier,
        &setup_secrets,
        MessageKind::SetupBetaCorrections,
    )?;

    let ggm_prepare_start = Instant::now();
    let (setup_messages, setup_verifier_noise, setup_checksum) = prepare_ggm_sender(
        verifier.private_seed,
        b"setup/ggm-root",
        params.setup_lpn_noise_weight,
        params.setup_ggm_depth,
    );
    let (main_messages, main_verifier_noise, main_checksum) = prepare_ggm_sender(
        verifier.private_seed,
        b"main/ggm-root",
        params.lpn_noise_weight,
        params.ggm_depth,
    );
    timings.ggm += ggm_prepare_start.elapsed();
    let setup_message_count = setup_messages.len();
    let mut all_messages = setup_messages;
    all_messages.extend(main_messages);
    let delivery_start = Instant::now();
    let selected_aggregates = deliver_ggm_ots(
        &mut prover,
        &mut verifier,
        &mut channel,
        &iknp_receiver,
        &iknp_sender,
        &all_messages,
    )?;
    timings.ot_extension += delivery_start.elapsed();
    let (setup_selected, main_selected) = selected_aggregates.split_at(setup_message_count);

    let setup_ggm_start = Instant::now();
    let (mut setup_prover_noise, setup_verifier_noise) = finish_ggm_phase(
        &mut prover,
        &mut verifier,
        &mut channel,
        &setup_secrets,
        params.setup_ggm_depth,
        setup_selected,
        &setup_beta_prover,
        &setup_beta_verifier,
        setup_verifier_noise,
        MessageKind::SetupGgmCorrections,
        faults.corrupt_ggm_correction,
    )?;
    timings.ggm += setup_ggm_start.elapsed();
    let setup_check_start = Instant::now();
    let setup_consistency = wykw_consistency_check(
        &mut prover,
        &mut verifier,
        &mut channel,
        &setup_secrets,
        &mut setup_prover_noise,
        &setup_verifier_noise,
        &setup_check_prover,
        &setup_check_verifier,
        phase_message_kinds(true),
        faults,
    )?;
    timings.check += setup_check_start.elapsed();

    let setup_lpn_start = Instant::now();
    let setup_code_seed = public_lpn_seed(&params, b"setup-to-extend");
    let main_base_prover = lpn_expand_prover(
        setup_code_seed,
        &setup_lpn_prover,
        &setup_prover_noise,
        &setup_secrets,
        params.base_vole_len,
        params.code_fanout,
    )?;
    let main_base_verifier = lpn_expand_verifier(
        setup_code_seed,
        &setup_lpn_verifier,
        &setup_verifier_noise,
        params.base_vole_len,
        params.code_fanout,
    )?;
    timings.lpn += setup_lpn_start.elapsed();
    let (
        main_lpn_prover,
        main_lpn_verifier,
        mut main_beta_prover,
        mut main_beta_verifier,
        main_check_prover,
        main_check_verifier,
    ) = split_base(main_base_prover, main_base_verifier, params.lpn_k, params.lpn_noise_weight)?;
    apply_beta_corrections(
        &mut prover,
        &mut verifier,
        &mut channel,
        &mut main_beta_prover,
        &mut main_beta_verifier,
        &main_secrets,
        MessageKind::MainBetaCorrections,
    )?;

    let main_ggm_start = Instant::now();
    let (mut main_prover_noise, main_verifier_noise) = finish_ggm_phase(
        &mut prover,
        &mut verifier,
        &mut channel,
        &main_secrets,
        params.ggm_depth,
        main_selected,
        &main_beta_prover,
        &main_beta_verifier,
        main_verifier_noise,
        MessageKind::MainGgmCorrections,
        false,
    )?;
    timings.ggm += main_ggm_start.elapsed();
    let main_check_start = Instant::now();
    let main_consistency = wykw_consistency_check(
        &mut prover,
        &mut verifier,
        &mut channel,
        &main_secrets,
        &mut main_prover_noise,
        &main_verifier_noise,
        &main_check_prover,
        &main_check_verifier,
        phase_message_kinds(false),
        Faults {
            tamper_ggm_leaf: false,
            corrupt_ggm_correction: false,
            cheat_consistency_response: faults.cheat_consistency_response,
        },
    )?;
    timings.check += main_check_start.elapsed();

    let main_lpn_start = Instant::now();
    let main_code_seed = public_lpn_seed(&params, b"extend-to-output");
    let expanded_prover = lpn_expand_prover(
        main_code_seed,
        &main_lpn_prover,
        &main_prover_noise,
        &main_secrets,
        params.output_sub_equiv,
        params.code_fanout,
    )?;
    let expanded_verifier = lpn_expand_verifier(
        main_code_seed,
        &main_lpn_verifier,
        &main_verifier_noise,
        params.output_sub_equiv,
        params.code_fanout,
    )?;
    timings.lpn += main_lpn_start.elapsed();
    let combine_start = Instant::now();
    let (prover_pool, verifier_pool) =
        bases_to_pools(expanded_prover, expanded_verifier, sub_corrs, full_corrs)?;
    let combine_elapsed = combine_start.elapsed();
    timings.full_combine += combine_elapsed;
    timings.lpn += combine_elapsed;

    if prover.transcript.digest() != verifier.transcript.digest() {
        return Err(PhaseBError::new("final setup transcript divergence"));
    }
    let setup_binding_digest = prover.transcript.digest();
    let mut audit = channel.finish()?;
    // The channel itself is deliberately secret-agnostic. Tests may request
    // a byte capture and let the verifier-side harness compare that public
    // transcript with its local Delta after the protocol has finished.
    audit.serialized_delta_found =
        capture_channel && contains_subslice(&audit.serialized_bytes, &fp2_bytes(delta));
    if audit.serialized_delta_found {
        return Err(PhaseBError::new("verifier Delta appeared in serialized channel bytes"));
    }
    let comm = audit.comm();
    let setup = PhaseBSetupReport {
        params: setup_params,
        comm,
        channel: audit,
        base_ot_transcript_digest: hex32(base_ot_digest),
        ot_extension_digest: hex32(ot_extension_digest),
        setup_binding_digest: hex32(setup_binding_digest),
        consistency_challenge_source:
            "BLAKE3(serialized role transcript || verifier nonce), sampled after GGM corrections"
                .into(),
        role_seeds_shared: false,
        delta_serialized: false,
    };
    let consistency = ConsistencyReport {
        ok: setup_consistency.ok && main_consistency.ok,
        checksum: setup_consistency.checksum ^ main_consistency.checksum.rotate_left(23),
    };
    let timings = timings.finish(total_start.elapsed());
    Ok(PhaseBExpansion {
        params,
        setup,
        prover: prover_pool,
        verifier: verifier_pool,
        verifier_delta: delta,
        timings,
        consistency,
        ggm_checksum: setup_checksum ^ main_checksum.rotate_left(31),
    })
}

/// Run the real two-party phase-B setup. `prover_seed` and `verifier_seed`
/// provision independent local RNGs; neither seed is sent or shared, and the
/// verifier samples `Delta` internally.
pub fn expand_phase_b(
    prover_seed: [u8; 32],
    verifier_seed: [u8; 32],
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> Result<PhaseBExpansion, PhaseBError> {
    if prover_seed == verifier_seed {
        return Err(PhaseBError::new("phase-B role seeds must be independently provisioned"));
    }
    let binding = SessionBinding::deterministic(prover_seed, verifier_seed);
    expand_phase_b_bound(prover_seed, verifier_seed, binding, sub_corrs, full_corrs, params)
}

pub(crate) fn expand_phase_b_bound(
    prover_seed: [u8; 32],
    verifier_seed: [u8; 32],
    binding: SessionBinding,
    sub_corrs: usize,
    full_corrs: usize,
    params: PhaseAParams,
) -> Result<PhaseBExpansion, PhaseBError> {
    expand_phase_b_internal(
        prover_seed,
        verifier_seed,
        binding,
        binding,
        sub_corrs,
        full_corrs,
        params,
        false,
        Faults::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROVER_SEED: [u8; 32] = [0x31; 32];
    const VERIFIER_SEED: [u8; 32] = [0xA6; 32];

    fn params() -> PhaseAParams {
        PhaseAParams::tiny_for_test(48 + 2 * 5)
    }

    fn run_with(faults: Faults, capture: bool) -> Result<PhaseBExpansion, PhaseBError> {
        let binding = SessionBinding::deterministic(PROVER_SEED, VERIFIER_SEED);
        expand_phase_b_internal(
            PROVER_SEED,
            VERIFIER_SEED,
            binding,
            binding,
            48,
            5,
            params(),
            capture,
            faults,
        )
    }

    #[test]
    fn honest_two_party_channel_has_matching_counts_and_mac_relations() {
        let out = run_with(Faults::default(), false).unwrap();
        assert!(out.consistency.ok);
        assert_eq!(out.prover.subs.len(), 48);
        assert_eq!(out.prover.fulls.len(), 5);
        assert_eq!(out.verifier.sub_keys.len(), 48);
        assert_eq!(out.verifier.full_keys.len(), 5);
        for (value, key) in out.prover.subs.iter().zip(&out.verifier.sub_keys) {
            assert_eq!(*key, value.m + out.verifier_delta.mul_base(value.r));
        }
        for (value, key) in out.prover.fulls.iter().zip(&out.verifier.full_keys) {
            assert_eq!(*key, value.m + out.verifier_delta * value.x);
        }
        let comm = &out.setup.comm;
        let audit = &out.setup.channel;
        assert_eq!(comm.prover_to_verifier_bytes, audit.prover_to_verifier_bytes);
        assert_eq!(comm.verifier_to_prover_bytes, audit.verifier_to_prover_bytes);
        assert_eq!(comm.total_bytes, comm.prover_to_verifier_bytes + comm.verifier_to_prover_bytes);
        assert_eq!(comm.total_bytes, audit.total_bytes);
        assert_eq!(out.setup.setup_binding_digest, audit.transcript_digest);
        assert!(!out.setup.role_seeds_shared);
        assert!(!out.setup.delta_serialized);
    }

    #[test]
    fn channel_transcript_excludes_delta_and_verifier_private_state() {
        let out = run_with(Faults::default(), true).unwrap();
        let bytes = &out.setup.channel.serialized_bytes;
        assert!(!bytes.is_empty());
        assert!(!contains_subslice(bytes, &fp2_bytes(out.verifier_delta)));
        assert!(!contains_subslice(bytes, &PROVER_SEED));
        assert!(!contains_subslice(bytes, &VERIFIER_SEED));
        assert!(!out.setup.channel.serialized_delta_found);

        // Reparse the captured wire image rather than trusting the channel's
        // counters: each record is direction || kind || u64(len) || payload.
        let mut offset = 0usize;
        let mut prover_to_verifier = 0u64;
        let mut verifier_to_prover = 0u64;
        while offset < bytes.len() {
            let direction = bytes[offset];
            offset += 1;
            assert!(offset + FRAME_HEADER_BYTES <= bytes.len());
            let payload_len =
                u64::from_le_bytes(bytes[offset + 1..offset + 9].try_into().unwrap()) as usize;
            let frame_len = FRAME_HEADER_BYTES + payload_len;
            assert!(offset + frame_len <= bytes.len());
            match direction {
                x if x == Direction::ProverToVerifier as u8 => {
                    prover_to_verifier += frame_len as u64
                }
                x if x == Direction::VerifierToProver as u8 => {
                    verifier_to_prover += frame_len as u64
                }
                _ => panic!("non-canonical captured channel direction"),
            }
            offset += frame_len;
        }
        assert_eq!(offset, bytes.len());
        assert_eq!(prover_to_verifier, out.setup.comm.prover_to_verifier_bytes);
        assert_eq!(verifier_to_prover, out.setup.comm.verifier_to_prover_bytes);
    }

    #[test]
    fn tampered_ggm_leaf_is_rejected() {
        let error =
            run_with(Faults { tamper_ggm_leaf: true, ..Faults::default() }, false).unwrap_err();
        assert!(error.to_string().contains("single-point consistency check rejected"));
    }

    #[test]
    fn corrupted_ggm_correction_is_rejected() {
        let error = run_with(Faults { corrupt_ggm_correction: true, ..Faults::default() }, false)
            .unwrap_err();
        assert!(error.to_string().contains("single-point consistency check rejected"));
    }

    #[test]
    fn cheating_consistency_response_is_rejected() {
        let error =
            run_with(Faults { cheat_consistency_response: true, ..Faults::default() }, false)
                .unwrap_err();
        assert!(error.to_string().contains("single-point consistency check rejected"));
    }

    #[test]
    fn shared_role_seed_is_rejected() {
        let error = expand_phase_b(PROVER_SEED, PROVER_SEED, 48, 5, params()).unwrap_err();
        assert!(error.to_string().contains("independently provisioned"));
    }

    #[test]
    fn mismatched_session_or_channel_identity_is_rejected_before_setup() {
        let binding = SessionBinding::deterministic(PROVER_SEED, VERIFIER_SEED);
        let mut other = binding;
        other.channel_id[0] ^= 1;
        let error = expand_phase_b_internal(
            PROVER_SEED,
            VERIFIER_SEED,
            binding,
            other,
            48,
            5,
            params(),
            false,
            Faults::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("channel identity mismatch"));

        other = binding;
        other.session_id[0] ^= 1;
        let error = expand_phase_b_internal(
            PROVER_SEED,
            VERIFIER_SEED,
            binding,
            other,
            48,
            5,
            params(),
            false,
            Faults::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("session identity mismatch"));
    }
}

//! C6AWH1 authenticated-target seam for the C6.1 native WHIR candidate.
//!
//! This module implements only the VOLE-MAC base closure registered in
//! Section 0.12 of `docs/c6-delta-residual-inline-design.md`.  It does not
//! modify or wrap the pinned Plonky3 prover/verifier and deliberately does not
//! implement `C61NativeBackendVerifier`.  A production backend must replace
//! WHIR's clear evaluation with the shifted base claim returned here and
//! prove claim privacy for that modified protocol.

use std::fmt;

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_prover, zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey, RESERVED_DOMAIN_BITS,
};

use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};

/// One model, embedding and compiler mask on each of two MAC tapes.
pub const C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE: usize = 3;
pub const C61_AUTHENTICATED_WHIR_TAPES: usize = 2;
pub const C61_AUTHENTICATED_WHIR_CHAINS: usize =
    C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE * C61_AUTHENTICATED_WHIR_TAPES;
pub const C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE: usize = 4;
pub const C64_AUTHENTICATED_WHIR_MASKS_PER_TAPE: usize = 6;

/// The clear Fp2 evaluation removed from upstream and the replacement
/// designated ZeroOpen tag have the same strict width.
pub const C61_AUTHENTICATED_WHIR_REMOVED_EVALUATION_BYTES: usize = 16;
pub const C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES: usize = 16;
pub const C61_AUTHENTICATED_WHIR_NET_PROVIDER_BYTES: isize =
    C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as isize
        - C61_AUTHENTICATED_WHIR_REMOVED_EVALUATION_BYTES as isize;
pub const C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES: usize = 32;

/// Two fixed high domain bits below the three MAC-reserved bits.  The
/// remaining fields are injectively packed as
/// `stage:8 || slot:16 || range_start:32 || component:2 || repetition:1`.
const C61_AUTHENTICATED_WHIR_DOMAIN_PREFIX: u64 = 0b01 << 59;
const C63_AUTHENTICATED_WHIR_DOMAIN_PREFIX: u64 = 0b10 << 59;
const C64_AUTHENTICATED_WHIR_DOMAIN_PREFIX: u64 = 0b11 << 59;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirError(String);

impl C61AuthenticatedWhirError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61AuthenticatedWhirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61AuthenticatedWhirError {}

type Result<T> = std::result::Result<T, C61AuthenticatedWhirError>;

/// Exact three-mask subrange reserved for one MAC tape in one attempted
/// certificate.  The enclosing durable allocator owns burn/retry semantics;
/// this type makes it impossible for a chain to select an arbitrary offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirMaskRange {
    pub stage: u8,
    pub slot: u16,
    pub range_start: u32,
}

impl C61AuthenticatedWhirMaskRange {
    pub fn end(self) -> Result<u32> {
        self.range_start
            .checked_add(C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32)
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 mask range overflows u32"))
    }

    pub fn mask_ordinal(self, id: C61NativeChainId) -> Result<u32> {
        self.validate_id(id)?;
        self.range_start
            .checked_add(component_ordinal(id.component)?)
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 mask ordinal overflows u32"))
    }

    /// Correlation domain injectively binds stage, slot, complete range start,
    /// component and repetition.  Range count is the fixed constant three.
    pub fn correlation_domain(self, id: C61NativeChainId) -> Result<u64> {
        self.end()?;
        self.validate_id(id)?;
        let component = u64::from(component_ordinal(id.component)?);
        let domain = C61_AUTHENTICATED_WHIR_DOMAIN_PREFIX
            | (u64::from(self.stage) << 51)
            | (u64::from(self.slot) << 35)
            | (u64::from(self.range_start) << 3)
            | (component << 1)
            | u64::from(id.repetition);
        if domain & RESERVED_DOMAIN_BITS != 0 {
            return Err(C61AuthenticatedWhirError::new(
                "C6AWH1 correlation domain overlaps reserved MAC bits",
            ));
        }
        Ok(domain)
    }

    fn validate_id(self, id: C61NativeChainId) -> Result<()> {
        if usize::from(id.repetition) >= C61_AUTHENTICATED_WHIR_TAPES {
            return Err(C61AuthenticatedWhirError::new(
                "C6AWH1 repetition is not one of the two MAC tapes",
            ));
        }
        component_ordinal(id.component)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum C63AuthenticatedWhirLane {
    Systematic = 0,
    Sketch = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum C64ProjectedResidualFamily {
    LeafOther = 0,
    LeafCorrection = 1,
    Auxiliary = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64AuthenticatedWhirMaskRange {
    pub stage: u8,
    pub slot: u16,
    pub range_start: u32,
}

impl C64AuthenticatedWhirMaskRange {
    pub fn end(self) -> Result<u32> {
        self.range_start
            .checked_add(C64_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32)
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.4 WHIR mask range overflows u32"))
    }

    pub fn mask_ordinal_limb(self, family: C64ProjectedResidualFamily, limb: u8) -> Result<u32> {
        self.end()?;
        if limb >= 2 {
            return Err(C61AuthenticatedWhirError::new("C6.4 WHIR limb is out of range"));
        }
        self.range_start
            .checked_add(u32::from(family as u8) * 2 + u32::from(limb))
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.4 WHIR mask ordinal overflows u32"))
    }

    pub fn correlation_domain_limb(
        self,
        family: C64ProjectedResidualFamily,
        limb: u8,
    ) -> Result<u64> {
        self.end()?;
        if limb >= 2 {
            return Err(C61AuthenticatedWhirError::new("C6.4 WHIR limb is out of range"));
        }
        let component = u64::from(family as u8) * 2 + u64::from(limb);
        let domain = C64_AUTHENTICATED_WHIR_DOMAIN_PREFIX
            | (u64::from(self.stage) << 51)
            | (u64::from(self.slot) << 35)
            | (u64::from(self.range_start) << 3)
            | component;
        if domain & RESERVED_DOMAIN_BITS != 0 {
            return Err(C61AuthenticatedWhirError::new(
                "C6.4 WHIR correlation domain overlaps reserved MAC bits",
            ));
        }
        Ok(domain)
    }
}

/// Four response-local terminal masks on one real-PCG tape: two arithmetic
/// limbs for each of the systematic and sketch objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63AuthenticatedWhirMaskRange {
    pub stage: u8,
    pub slot: u16,
    pub range_start: u32,
}

impl C63AuthenticatedWhirMaskRange {
    pub fn end(self) -> Result<u32> {
        self.range_start
            .checked_add(C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32)
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR mask range overflows u32"))
    }

    pub fn mask_ordinal(self, lane: C63AuthenticatedWhirLane) -> Result<u32> {
        self.mask_ordinal_limb(lane, 0)
    }

    pub fn mask_ordinal_limb(self, lane: C63AuthenticatedWhirLane, limb: u8) -> Result<u32> {
        self.end()?;
        if limb >= 2 {
            return Err(C61AuthenticatedWhirError::new("C6.3 WHIR limb is out of range"));
        }
        self.range_start
            .checked_add(u32::from(lane as u8) * 2 + u32::from(limb))
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR mask ordinal overflows u32"))
    }

    pub fn correlation_domain(self, lane: C63AuthenticatedWhirLane) -> Result<u64> {
        self.correlation_domain_limb(lane, 0)
    }

    pub fn correlation_domain_limb(self, lane: C63AuthenticatedWhirLane, limb: u8) -> Result<u64> {
        self.end()?;
        if limb >= 2 {
            return Err(C61AuthenticatedWhirError::new("C6.3 WHIR limb is out of range"));
        }
        let component = u64::from(lane as u8) * 2 + u64::from(limb);
        let domain = C63_AUTHENTICATED_WHIR_DOMAIN_PREFIX
            | (u64::from(self.stage) << 51)
            | (u64::from(self.slot) << 35)
            | (u64::from(self.range_start) << 2)
            | component;
        if domain & RESERVED_DOMAIN_BITS != 0 {
            return Err(C61AuthenticatedWhirError::new(
                "C6.3 WHIR correlation domain overlaps reserved MAC bits",
            ));
        }
        Ok(domain)
    }
}

/// Strict replacement for the removed clear Fp2 evaluation.  Chain kind,
/// repetition, statement, slot and range are already fixed by the outer
/// C6PA1/backend typestate and therefore add no duplicate provider wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirBaseProof {
    zero_open_tag: Fp2,
}

impl C61AuthenticatedWhirBaseProof {
    pub fn encode(self) -> [u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES] {
        let mut bytes = [0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES];
        bytes[..8].copy_from_slice(&self.zero_open_tag.c0.value().to_le_bytes());
        bytes[8..].copy_from_slice(&self.zero_open_tag.c1.value().to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES {
            return Err(C61AuthenticatedWhirError::new(
                "C6AWH1 ZeroOpen tag has noncanonical length",
            ));
        }
        let mut c0 = [0u8; 8];
        let mut c1 = [0u8; 8];
        c0.copy_from_slice(&bytes[..8]);
        c1.copy_from_slice(&bytes[8..]);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C61AuthenticatedWhirError::new(
                "C6AWH1 ZeroOpen tag contains a noncanonical field element",
            ));
        }
        Ok(Self { zero_open_tag: Fp2::new(Fp::new(c0), Fp::new(c1)) })
    }

    pub fn tag(self) -> Fp2 {
        self.zero_open_tag
    }
}

/// Wire-neutral replacement for two secondary 16-byte tails. The correction
/// is one canonical Fp2 encoded as two 8-byte Fp limbs; the final Fp2 is the
/// single joint ZeroOpen tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61JointNativeBridgeFrame {
    correction: Fp2,
    zero_open_tag: Fp2,
}

impl C61JointNativeBridgeFrame {
    pub fn encode(self) -> [u8; C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES] {
        let mut bytes = [0u8; C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES];
        bytes[..8].copy_from_slice(&self.correction.c0.value().to_le_bytes());
        bytes[8..16].copy_from_slice(&self.correction.c1.value().to_le_bytes());
        bytes[16..24].copy_from_slice(&self.zero_open_tag.c0.value().to_le_bytes());
        bytes[24..].copy_from_slice(&self.zero_open_tag.c1.value().to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES {
            return Err(C61AuthenticatedWhirError::new(
                "C6NBR1 joint bridge frame has noncanonical length",
            ));
        }
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let mut encoded = [0u8; 8];
            encoded.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
            *limb = u64::from_le_bytes(encoded);
            if *limb >= P {
                return Err(C61AuthenticatedWhirError::new(
                    "C6NBR1 joint bridge frame contains a noncanonical field element",
                ));
            }
        }
        Ok(Self {
            correction: Fp2::new(Fp::new(limbs[0]), Fp::new(limbs[1])),
            zero_open_tag: Fp2::new(Fp::new(limbs[2]), Fp::new(limbs[3])),
        })
    }

    pub fn correction(self) -> Fp2 {
        self.correction
    }

    pub fn tag(self) -> Fp2 {
        self.zero_open_tag
    }
}

pub struct C61JointNativeProverTerm {
    pub prepared: C61AuthenticatedWhirPreparedMask,
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub affine: C61AuthenticatedWhirAffineClaim,
    pub cohort_weight: Fp2,
}

/// Native bridge state after the public correction is fixed but before the
/// joint ZeroOpen tag is emitted. Kept crate-private so only the strict C6PA2
/// orchestration can pair it with a completed C6NBR2 link receipt.
pub(crate) struct C61JointNativeProverBridgePending {
    correction: Fp2,
    residual: ProverAuthed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61JointNativeVerifierTerm {
    pub mask_key: VerifierKey,
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub affine: C61AuthenticatedWhirAffineClaim,
    pub cohort_weight: Fp2,
}

pub struct C62SecondaryResponseProverTerm {
    pub native: C61JointNativeProverTerm,
    pub response_target: ProverAuthed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C62SecondaryResponseVerifierTerm {
    pub native: C61JointNativeVerifierTerm,
    pub response_target: VerifierKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C62ResponseCompilerBinding {
    pub schedule_digest: [u8; 32],
    pub response_binding_digest: [u8; 32],
    pub functional_digest: [u8; 32],
    pub nbr2_statement_digest: [u8; 32],
    pub root_binding_digest: [u8; 32],
    pub compiler_correction: Fp2,
}

impl C62ResponseCompilerBinding {
    pub fn validate(self) -> Result<()> {
        if [
            self.schedule_digest,
            self.response_binding_digest,
            self.functional_digest,
            self.nbr2_statement_digest,
            self.root_binding_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(C61AuthenticatedWhirError::new("C62JVR1 contains an empty public binding"));
        }
        Ok(())
    }

    pub fn encode(self) -> [u8; 176] {
        let mut encoded = [0u8; 176];
        for (index, digest) in [
            self.schedule_digest,
            self.response_binding_digest,
            self.functional_digest,
            self.nbr2_statement_digest,
            self.root_binding_digest,
        ]
        .into_iter()
        .enumerate()
        {
            encoded[index * 32..(index + 1) * 32].copy_from_slice(&digest);
        }
        encoded[160..168].copy_from_slice(&self.compiler_correction.c0.value().to_le_bytes());
        encoded[168..].copy_from_slice(&self.compiler_correction.c1.value().to_le_bytes());
        encoded
    }

    pub fn draw_eta(self, transcript: &mut Transcript) -> Result<Fp2> {
        self.validate()?;
        transcript.absorb_public_message("c62_response_compiler_binding", &self.encode());
        Ok(transcript.challenge_fp2())
    }
}

pub struct C62ResponseCompilerProverPending {
    correction: Fp2,
    eta: Fp2,
    residual: ProverAuthed,
}

pub struct C62ResponseCompilerVerifierPending {
    eta: Fp2,
    residual: VerifierKey,
    zero_open_tag: Fp2,
}

impl C62ResponseCompilerProverPending {
    pub fn eta(&self) -> Fp2 {
        self.eta
    }

    pub fn finish(self, transcript: &mut Transcript) -> Result<C61JointNativeBridgeFrame> {
        transcript.append_fp2s("zero_open_tag", &[self.residual.m]);
        transcript.canonical_binding_digest().map_err(C61AuthenticatedWhirError::new)?;
        Ok(C61JointNativeBridgeFrame {
            correction: self.correction,
            zero_open_tag: self.residual.m,
        })
    }
}

impl C62ResponseCompilerVerifierPending {
    pub fn eta(&self) -> Fp2 {
        self.eta
    }

    pub fn finish(self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_fp2s("zero_open_tag", &[self.zero_open_tag]);
        transcript.canonical_binding_digest().map_err(C61AuthenticatedWhirError::new)?;
        if !zero_open_verify(self.residual, self.zero_open_tag) {
            return Err(C61AuthenticatedWhirError::new(
                "C62JVR1 response/compiler ZeroOpen failed",
            ));
        }
        Ok(())
    }
}

pub fn prepare_c62_response_compiler_relation_prover(
    terms: Vec<C62SecondaryResponseProverTerm>,
    compiler_base_fold: ProverAuthed,
    binding: C62ResponseCompilerBinding,
    transcript: &mut Transcript,
) -> Result<C62ResponseCompilerProverPending> {
    if terms.len() < 2 || !transcript.is_fiat_shamir() {
        return Err(C61AuthenticatedWhirError::new(
            "C62JVR1 prover requires two Fiat--Shamir-bound secondary cohorts",
        ));
    }
    let mut native_fold = ProverAuthed::ZERO;
    let mut response_fold = ProverAuthed::ZERO;
    for term in terms {
        let (public, inverse) = c61_joint_native_normalization(
            term.native.combined,
            term.native.shifted_masked_claim,
            term.native.gamma,
            term.native.affine,
        )?;
        let normalized = ProverAuthed::from_public(public)
            .add(term.native.prepared.authenticated.scale(inverse))
            .scale(term.native.cohort_weight);
        native_fold = native_fold.add(normalized);
        response_fold = response_fold.add(term.response_target.scale(term.native.cohort_weight));
    }
    let eta = binding.draw_eta(transcript)?;
    let compiler_fold =
        compiler_base_fold.add(ProverAuthed::from_public(binding.compiler_correction));
    let residual = native_fold.sub(response_fold).add(native_fold.sub(compiler_fold).scale(eta));
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new(
            "C62JVR1 honest response/compiler residual is nonzero",
        ));
    }
    Ok(C62ResponseCompilerProverPending { correction: binding.compiler_correction, eta, residual })
}

pub fn prepare_c62_response_compiler_relation_verifier(
    terms: &[C62SecondaryResponseVerifierTerm],
    compiler_base_fold: VerifierKey,
    expected_binding: C62ResponseCompilerBinding,
    delta: Fp2,
    frame: C61JointNativeBridgeFrame,
    transcript: &mut Transcript,
) -> Result<C62ResponseCompilerVerifierPending> {
    if terms.len() < 2 || !transcript.is_fiat_shamir() {
        return Err(C61AuthenticatedWhirError::new(
            "C62JVR1 verifier requires two Fiat--Shamir-bound secondary cohorts",
        ));
    }
    if frame.correction != expected_binding.compiler_correction {
        return Err(C61AuthenticatedWhirError::new(
            "C62JVR1 compiler correction differs from its typed binding",
        ));
    }
    let mut native_fold = VerifierKey::ZERO;
    let mut response_fold = VerifierKey::ZERO;
    for term in terms {
        let (public, inverse) = c61_joint_native_normalization(
            term.native.combined,
            term.native.shifted_masked_claim,
            term.native.gamma,
            term.native.affine,
        )?;
        let normalized = VerifierKey::from_public(public, delta)
            .add(term.native.mask_key.scale(inverse))
            .scale(term.native.cohort_weight);
        native_fold = native_fold.add(normalized);
        response_fold = response_fold.add(term.response_target.scale(term.native.cohort_weight));
    }
    let eta = expected_binding.draw_eta(transcript)?;
    let compiler_fold = compiler_base_fold
        .add(VerifierKey::from_public(expected_binding.compiler_correction, delta));
    let residual = native_fold.sub(response_fold).add(native_fold.sub(compiler_fold).scale(eta));
    Ok(C62ResponseCompilerVerifierPending { eta, residual, zero_open_tag: frame.zero_open_tag })
}

pub(crate) struct C61JointNativeVerifierBridgePending {
    residual: VerifierKey,
    zero_open_tag: Fp2,
}

fn c61_joint_native_normalization(
    combined: Fp2,
    shifted_masked_claim: Fp2,
    gamma: Fp2,
    affine: C61AuthenticatedWhirAffineClaim,
) -> Result<(Fp2, Fp2)> {
    let target_coefficient = gamma * affine.coefficient;
    if target_coefficient == Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new("C6NBR1 native target coefficient is zero"));
    }
    let inverse = target_coefficient.inv();
    let public = (combined - shifted_masked_claim - gamma * affine.constant) * inverse;
    Ok((public, inverse))
}

/// Consume every fixed secondary body and close their zeta-weighted,
/// normalized base relation against the compiler-derived tape-1 source fold.
/// No fresh correlation is drawn: the already consumed native masks provide
/// the joint tag entropy.
pub fn finish_c61_joint_native_bridge(
    terms: Vec<C61JointNativeProverTerm>,
    compiler_base_fold: ProverAuthed,
    compiler_correction: Fp2,
    transcript: &mut Transcript,
) -> Result<C61JointNativeBridgeFrame> {
    prepare_c61_joint_native_bridge_prover(
        terms,
        compiler_base_fold,
        compiler_correction,
        transcript,
    )?
    .finish(transcript)
}

pub(crate) fn prepare_c61_joint_native_bridge_prover(
    terms: Vec<C61JointNativeProverTerm>,
    compiler_base_fold: ProverAuthed,
    compiler_correction: Fp2,
    transcript: &mut Transcript,
) -> Result<C61JointNativeProverBridgePending> {
    if terms.len() < 2 {
        return Err(C61AuthenticatedWhirError::new(
            "C6NBR1 joint bridge requires at least two native bodies",
        ));
    }
    let mut native_fold = ProverAuthed::ZERO;
    for term in terms {
        let (public, inverse) = c61_joint_native_normalization(
            term.combined,
            term.shifted_masked_claim,
            term.gamma,
            term.affine,
        )?;
        let normalized = ProverAuthed::from_public(public)
            .add(term.prepared.authenticated.scale(inverse))
            .scale(term.cohort_weight);
        native_fold = native_fold.add(normalized);
    }
    transcript.append("c6_joint_native_corrections", 16);
    let residual =
        native_fold.sub(compiler_base_fold).sub(ProverAuthed::from_public(compiler_correction));
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new("C6NBR1 corrected joint residual is nonzero"));
    }
    Ok(C61JointNativeProverBridgePending { correction: compiler_correction, residual })
}

impl C61JointNativeProverBridgePending {
    pub(crate) fn finish(self, transcript: &mut Transcript) -> Result<C61JointNativeBridgeFrame> {
        Ok(C61JointNativeBridgeFrame {
            correction: self.correction,
            zero_open_tag: zero_open_prover(&self.residual, transcript),
        })
    }
}

pub fn verify_c61_joint_native_bridge(
    terms: &[C61JointNativeVerifierTerm],
    compiler_base_fold: VerifierKey,
    expected_compiler_correction: Fp2,
    delta: Fp2,
    frame: C61JointNativeBridgeFrame,
    transcript: &mut Transcript,
) -> Result<()> {
    prepare_c61_joint_native_bridge_verifier(
        terms,
        compiler_base_fold,
        expected_compiler_correction,
        delta,
        frame,
        transcript,
    )?
    .finish(transcript)
}

pub(crate) fn prepare_c61_joint_native_bridge_verifier(
    terms: &[C61JointNativeVerifierTerm],
    compiler_base_fold: VerifierKey,
    expected_compiler_correction: Fp2,
    delta: Fp2,
    frame: C61JointNativeBridgeFrame,
    transcript: &mut Transcript,
) -> Result<C61JointNativeVerifierBridgePending> {
    if terms.len() < 2 {
        return Err(C61AuthenticatedWhirError::new(
            "C6NBR1 joint verifier requires at least two native bodies",
        ));
    }
    if frame.correction != expected_compiler_correction {
        return Err(C61AuthenticatedWhirError::new(
            "C6NBR1 compiler correction differs from its independently derived source fold",
        ));
    }
    let mut native_fold = VerifierKey::ZERO;
    for term in terms {
        let (public, inverse) = c61_joint_native_normalization(
            term.combined,
            term.shifted_masked_claim,
            term.gamma,
            term.affine,
        )?;
        let normalized = VerifierKey::from_public(public, delta)
            .add(term.mask_key.scale(inverse))
            .scale(term.cohort_weight);
        native_fold = native_fold.add(normalized);
    }
    transcript.append("c6_joint_native_corrections", 16);
    let residual =
        native_fold.sub(compiler_base_fold).sub(VerifierKey::from_public(frame.correction, delta));
    Ok(C61JointNativeVerifierBridgePending { residual, zero_open_tag: frame.zero_open_tag })
}

impl C61JointNativeVerifierBridgePending {
    pub(crate) fn finish(self, transcript: &mut Transcript) -> Result<()> {
        transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
        if !zero_open_verify(self.residual, self.zero_open_tag) {
            return Err(C61AuthenticatedWhirError::new("C6NBR1 joint native ZeroOpen failed"));
        }
        Ok(())
    }
}

/// Provider output for the patched WHIR base case.  Only
/// `shifted_masked_claim` enters the native PCS payload; `proof` replaces the
/// old clear evaluation.  The domain/ordinal fields are role-local audit
/// metadata and are not serialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirProverClosure {
    pub shifted_masked_claim: Fp2,
    pub proof: C61AuthenticatedWhirBaseProof,
    pub mask_domain: u64,
    pub mask_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63AuthenticatedWhirLimbPairClosure {
    pub proof: C61AuthenticatedWhirBaseProof,
    pub mask_domains: [u64; 2],
    pub mask_ordinals: [u32; 2],
}

/// One pair of WHIR hiding masks authenticated on both independent tapes.
/// Tape zero supplies the private values; tape one receives canonical field
/// corrections, so the expensive WHIR body is shared without sharing a VOLE
/// correlation.
#[derive(Debug)]
pub struct C64SharedAuthenticatedWhirLimbPair {
    values: [Fp2; 2],
    tapes: [[Option<C61AuthenticatedWhirPreparedMask>; 2]; 2],
    corrections: [[Fp2; 2]; 2],
}

impl C64SharedAuthenticatedWhirLimbPair {
    pub fn values(&self) -> [Fp2; 2] {
        self.values
    }

    pub fn corrections(&self) -> [[Fp2; 2]; 2] {
        self.corrections
    }
}

/// One consumed provider mask waiting for the WHIR base case.  It is neither
/// cloneable nor serializable; finishing the closure consumes it exactly once.
#[derive(Debug)]
pub struct C61AuthenticatedWhirPreparedMask {
    value: Fp2,
    authenticated: ProverAuthed,
    mask_domain: u64,
    mask_ordinal: u32,
}

impl C61AuthenticatedWhirPreparedMask {
    pub fn shifted_masked_claim(&self, masked_claim: Fp2) -> Fp2 {
        masked_claim + self.value
    }

    pub fn value(&self) -> Fp2 {
        self.value
    }
}

/// Typed inputs owned by the provider role.  Keeping the six algebraic and
/// allocation fields together prevents positional swaps at the WHIR adapter
/// boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirProverInput {
    pub id: C61NativeChainId,
    pub mask_range: C61AuthenticatedWhirMaskRange,
    pub combined: Fp2,
    pub masked_claim: Fp2,
    pub gamma: Fp2,
    pub target: ProverAuthed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirProverFinishInput {
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub target: ProverAuthed,
}

/// Typed inputs owned by the designated-verifier role.  In particular, the
/// target is a MAC key and never a plaintext field element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirVerifierInput {
    pub id: C61NativeChainId,
    pub mask_range: C61AuthenticatedWhirMaskRange,
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub target: VerifierKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63AuthenticatedWhirVerifierInput {
    pub lane: C63AuthenticatedWhirLane,
    pub mask_range: C63AuthenticatedWhirMaskRange,
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub target: VerifierKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C63AuthenticatedWhirNormalizedLimb {
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub affine: C61AuthenticatedWhirAffineClaim,
    pub claim_weight: Fp2,
}

#[derive(Debug)]
pub struct C63AuthenticatedWhirPreparedLimbPair {
    limbs: [C61AuthenticatedWhirPreparedMask; 2],
}

impl C63AuthenticatedWhirPreparedLimbPair {
    pub fn values(&self) -> [Fp2; 2] {
        self.limbs.each_ref().map(|limb| limb.value())
    }

    pub fn shifted_masked_claims(&self, masked_claims: [Fp2; 2]) -> [Fp2; 2] {
        [
            self.limbs[0].shifted_masked_claim(masked_claims[0]),
            self.limbs[1].shifted_masked_claim(masked_claims[1]),
        ]
    }
}

/// Public affine coordinates for a claim-hidden WHIR replay.  The verifier
/// carries `coefficient * opening_target + constant` without learning the
/// opening target itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedWhirAffineClaim {
    pub coefficient: Fp2,
    pub constant: Fp2,
}

impl C61AuthenticatedWhirAffineClaim {
    pub const fn identity() -> Self {
        Self { coefficient: Fp2::ONE, constant: Fp2::ZERO }
    }

    pub fn evaluate(self, opening_target: Fp2) -> Fp2 {
        self.coefficient * opening_target + self.constant
    }

    /// Apply the private-claim ZK-sumcheck prelude
    /// `target <- epsilon * target + mu_tilde`.
    pub fn prelude(self, epsilon: Fp2, mu_tilde: Fp2) -> Self {
        Self {
            coefficient: epsilon * self.coefficient,
            constant: epsilon * self.constant + mu_tilde,
        }
    }

    /// Replay one dropped-linear-coefficient sumcheck round.  `tail_at_one`
    /// is `sum_{i>=2} c_i`; `tail_at_gamma` is
    /// `sum_{i>=2} c_i * gamma^i`.
    pub fn round(self, c0: Fp2, tail_at_one: Fp2, tail_at_gamma: Fp2, gamma: Fp2) -> Self {
        Self {
            coefficient: gamma * self.coefficient,
            constant: c0 + gamma * (self.constant - c0 - c0 - tail_at_one) + tail_at_gamma,
        }
    }

    /// Code-switch and query contributions are public affine offsets.
    pub fn add_public(self, value: Fp2) -> Self {
        Self { coefficient: self.coefficient, constant: self.constant + value }
    }

    pub fn authenticate_prover(self, opening_target: ProverAuthed) -> ProverAuthed {
        opening_target.scale(self.coefficient).add(ProverAuthed::from_public(self.constant))
    }

    pub fn derive_verifier_key(self, opening_target: VerifierKey, delta: Fp2) -> VerifierKey {
        opening_target.scale(self.coefficient).add(VerifierKey::from_public(self.constant, delta))
    }
}

/// Consume one uncorrected full VOLE correlation, shift WHIR's base claim and
/// open only the resulting authenticated zero residual.
pub fn prepare_c61_authenticated_whir_mask(
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    correlations: &mut CorrelationStream,
) -> Result<C61AuthenticatedWhirPreparedMask> {
    let mask_domain = mask_range.correlation_domain(id)?;
    let mask_ordinal = mask_range.mask_ordinal(id)?;
    let correlation = correlations
        .draw_fulls(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 missing full correlation"))?;
    let mask_value = correlation.x;
    let mask = correlation.authenticate(mask_value);
    Ok(C61AuthenticatedWhirPreparedMask {
        value: mask_value,
        authenticated: mask,
        mask_domain,
        mask_ordinal,
    })
}

pub fn prepare_c63_authenticated_whir_mask(
    lane: C63AuthenticatedWhirLane,
    mask_range: C63AuthenticatedWhirMaskRange,
    correlations: &mut CorrelationStream,
) -> Result<C61AuthenticatedWhirPreparedMask> {
    let mask_domain = mask_range.correlation_domain(lane)?;
    let mask_ordinal = mask_range.mask_ordinal(lane)?;
    let correlation = correlations
        .draw_fulls(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR missing full correlation"))?;
    let mask_value = correlation.x;
    Ok(C61AuthenticatedWhirPreparedMask {
        value: mask_value,
        authenticated: correlation.authenticate(mask_value),
        mask_domain,
        mask_ordinal,
    })
}

pub fn prepare_c63_authenticated_whir_limb_pair(
    lane: C63AuthenticatedWhirLane,
    mask_range: C63AuthenticatedWhirMaskRange,
    correlations: &mut CorrelationStream,
) -> Result<C63AuthenticatedWhirPreparedLimbPair> {
    let mut prepare = |limb: u8| {
        let mask_domain = mask_range.correlation_domain_limb(lane, limb)?;
        let mask_ordinal = mask_range.mask_ordinal_limb(lane, limb)?;
        let correlation = correlations
            .draw_fulls(mask_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR missing limb mask"))?;
        Ok(C61AuthenticatedWhirPreparedMask {
            value: correlation.x,
            authenticated: correlation.authenticate(correlation.x),
            mask_domain,
            mask_ordinal,
        })
    };
    Ok(C63AuthenticatedWhirPreparedLimbPair { limbs: [prepare(0)?, prepare(1)?] })
}

pub fn prepare_c64_shared_authenticated_whir_limb_pair(
    family: C64ProjectedResidualFamily,
    mask_range: C64AuthenticatedWhirMaskRange,
    streams: &mut [CorrelationStream; 2],
) -> Result<C64SharedAuthenticatedWhirLimbPair> {
    let mut values = [Fp2::ZERO; 2];
    let mut tapes: [[Option<C61AuthenticatedWhirPreparedMask>; 2]; 2] =
        std::array::from_fn(|_| std::array::from_fn(|_| None));
    let mut corrections = [[Fp2::ZERO; 2]; 2];
    for limb in 0..2u8 {
        let domain = mask_range.correlation_domain_limb(family, limb)?;
        let ordinal = mask_range.mask_ordinal_limb(family, limb)?;
        let mut correlations = Vec::with_capacity(2);
        for stream in streams.iter_mut() {
            correlations.push(stream.draw_fulls(domain, 1).into_iter().next().ok_or_else(
                || C61AuthenticatedWhirError::new("C6.4 WHIR missing full correlation"),
            )?);
        }
        let [left, right]: [_; 2] = correlations
            .try_into()
            .map_err(|_| C61AuthenticatedWhirError::new("C6.4 WHIR tape census differs"))?;
        let common = left.x;
        values[usize::from(limb)] = common;
        for (tape, correlation) in [left, right].into_iter().enumerate() {
            let correction = common - correlation.x;
            corrections[tape][usize::from(limb)] = correction;
            tapes[tape][usize::from(limb)] = Some(C61AuthenticatedWhirPreparedMask {
                value: common,
                authenticated: correlation
                    .authenticate(correlation.x)
                    .add(ProverAuthed::from_public(correction)),
                mask_domain: domain,
                mask_ordinal: ordinal,
            });
        }
    }
    Ok(C64SharedAuthenticatedWhirLimbPair { values, tapes, corrections })
}

pub fn finish_c64_shared_authenticated_whir_limb_pair(
    mut prepared: C64SharedAuthenticatedWhirLimbPair,
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
    expected_targets: [ProverAuthed; 2],
    transcripts: &mut [Transcript; 2],
) -> Result<[C63AuthenticatedWhirLimbPairClosure; 2]> {
    let mut closures = Vec::with_capacity(2);
    for tape in 0..2 {
        let limbs = [
            prepared.tapes[tape][0]
                .take()
                .ok_or_else(|| C61AuthenticatedWhirError::new("C6.4 shared WHIR mask is absent"))?,
            prepared.tapes[tape][1]
                .take()
                .ok_or_else(|| C61AuthenticatedWhirError::new("C6.4 shared WHIR mask is absent"))?,
        ];
        transcripts[tape]
            .append_fp2s("c64_shared_whir_mask_corrections", &prepared.corrections[tape]);
        closures.push(finish_c63_authenticated_whir_limb_pair(
            C63AuthenticatedWhirPreparedLimbPair { limbs },
            inputs,
            expected_targets[tape],
            &mut transcripts[tape],
        )?);
    }
    closures.try_into().map_err(|_| C61AuthenticatedWhirError::new("C6.4 WHIR tape census differs"))
}

pub fn finish_c63_authenticated_whir_limb_pair(
    prepared: C63AuthenticatedWhirPreparedLimbPair,
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
    expected_target: ProverAuthed,
    transcript: &mut Transcript,
) -> Result<C63AuthenticatedWhirLimbPairClosure> {
    let derived = c63_normalized_limb_pair_prover_target(&prepared, inputs)?;
    let residual = derived.sub(expected_target);
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new(
            "C6.3 WHIR normalized limb-pair target differs",
        ));
    }
    let proof = C61AuthenticatedWhirBaseProof {
        zero_open_tag: append_authenticated_whir_zero_open_prover(&residual, transcript),
    };
    Ok(C63AuthenticatedWhirLimbPairClosure {
        proof,
        mask_domains: prepared.limbs.each_ref().map(|limb| limb.mask_domain),
        mask_ordinals: prepared.limbs.each_ref().map(|limb| limb.mask_ordinal),
    })
}

fn c63_normalized_limb_pair_prover_target(
    prepared: &C63AuthenticatedWhirPreparedLimbPair,
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
) -> Result<ProverAuthed> {
    let mut targets = [ProverAuthed::ZERO; 2];
    for limb in 0..2 {
        let coefficient =
            inputs[limb].gamma * inputs[limb].affine.coefficient * inputs[limb].claim_weight;
        if coefficient == Fp2::ZERO {
            return Err(C61AuthenticatedWhirError::new(
                "C6.3 WHIR normalized limb coefficient is zero",
            ));
        }
        let public = inputs[limb].combined
            - inputs[limb].shifted_masked_claim
            - inputs[limb].gamma * inputs[limb].affine.constant;
        targets[limb] = ProverAuthed::from_public(public)
            .add(prepared.limbs[limb].authenticated)
            .scale(coefficient.inv());
    }
    Ok(targets[0].add(targets[1].scale(Fp2::new(Fp::ZERO, Fp::ONE))))
}

pub fn finish_c61_authenticated_whir_base(
    prepared: C61AuthenticatedWhirPreparedMask,
    input: C61AuthenticatedWhirProverFinishInput,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirProverClosure> {
    let residual = c61_authenticated_whir_prover_residual(&prepared, input);
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new(
            "C6AWH1 honest WHIR base identity does not close",
        ));
    }
    let zero_open_tag = append_authenticated_whir_zero_open_prover(&residual, transcript);
    let proof = C61AuthenticatedWhirBaseProof { zero_open_tag };
    Ok(C61AuthenticatedWhirProverClosure {
        shifted_masked_claim: input.shifted_masked_claim,
        proof,
        mask_domain: prepared.mask_domain,
        mask_ordinal: prepared.mask_ordinal,
    })
}

/// Fold already-authenticated arithmetic zero rows into the compiler chain's
/// existing C6AWH1 closure.  The fresh RLC challenge is drawn only after the
/// WHIR residual and every additional row are fixed.  The prepared WHIR mask
/// supplies the one-time random tag, so this emits the same single 16-byte
/// ZeroOpen and consumes no second mask correlation.
pub fn finish_c61_authenticated_whir_base_with_zero_rows(
    prepared: C61AuthenticatedWhirPreparedMask,
    input: C61AuthenticatedWhirProverFinishInput,
    zero_rows: &[ProverAuthed],
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirProverClosure> {
    if zero_rows.is_empty() {
        return Err(C61AuthenticatedWhirError::new(
            "C6AWH1 folded arithmetic closure requires at least one zero row",
        ));
    }
    let mut residual = c61_authenticated_whir_prover_residual(&prepared, input);
    if residual.x != Fp2::ZERO || zero_rows.iter().any(|row| row.x != Fp2::ZERO) {
        return Err(C61AuthenticatedWhirError::new(
            "C6AWH1 honest folded arithmetic residual is nonzero",
        ));
    }
    let challenge = transcript.challenge_fp2();
    let mut weight = Fp2::ONE;
    for row in zero_rows {
        weight = weight * challenge;
        residual = residual.add(row.scale(weight));
    }
    let zero_open_tag = append_authenticated_whir_zero_open_prover(&residual, transcript);
    let proof = C61AuthenticatedWhirBaseProof { zero_open_tag };
    Ok(C61AuthenticatedWhirProverClosure {
        shifted_masked_claim: input.shifted_masked_claim,
        proof,
        mask_domain: prepared.mask_domain,
        mask_ordinal: prepared.mask_ordinal,
    })
}

fn c61_authenticated_whir_prover_residual(
    prepared: &C61AuthenticatedWhirPreparedMask,
    input: C61AuthenticatedWhirProverFinishInput,
) -> ProverAuthed {
    ProverAuthed::from_public(input.combined - input.shifted_masked_claim)
        .sub(input.target.scale(input.gamma))
        .add(prepared.authenticated)
}

pub fn prove_c61_authenticated_whir_base(
    input: C61AuthenticatedWhirProverInput,
    correlations: &mut CorrelationStream,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirProverClosure> {
    let prepared = prepare_c61_authenticated_whir_mask(input.id, input.mask_range, correlations)?;
    let shifted_masked_claim = prepared.shifted_masked_claim(input.masked_claim);
    finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: input.combined,
            shifted_masked_claim,
            gamma: input.gamma,
            target: input.target,
        },
        transcript,
    )
}

/// Verifier half of the same linear residual.  It never receives the target
/// plaintext or mask plaintext; both remain represented by MAC keys.
pub fn verify_c61_authenticated_whir_base(
    input: C61AuthenticatedWhirVerifierInput,
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<()> {
    let mask_domain = input.mask_range.correlation_domain(input.id)?;
    let mask_key = context
        .expand_full_verifier_keys(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 missing verifier mask key"))?;
    let residual = c61_authenticated_whir_verifier_residual(input, mask_key, context.delta);
    append_authenticated_whir_zero_open_verifier(proof.zero_open_tag, transcript);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new("C6AWH1 authenticated target ZeroOpen failed"));
    }
    Ok(())
}

pub fn verify_c63_authenticated_whir_base(
    input: C63AuthenticatedWhirVerifierInput,
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<()> {
    let mask_domain = input.mask_range.correlation_domain(input.lane)?;
    let mask_key = context
        .expand_full_verifier_keys(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR missing verifier mask key"))?;
    let residual =
        VerifierKey::from_public(input.combined - input.shifted_masked_claim, context.delta)
            .sub(input.target.scale(input.gamma))
            .add(mask_key);
    append_authenticated_whir_zero_open_verifier(proof.zero_open_tag, transcript);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new(
            "C6.3 WHIR authenticated target ZeroOpen failed",
        ));
    }
    Ok(())
}

pub fn verify_c63_authenticated_whir_limb_pair(
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
    expected_target: VerifierKey,
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    lane: C63AuthenticatedWhirLane,
    mask_range: C63AuthenticatedWhirMaskRange,
    transcript: &mut Transcript,
) -> Result<()> {
    let mut targets = [VerifierKey::ZERO; 2];
    for limb in 0..2 {
        let input = inputs[limb];
        let coefficient = input.gamma * input.affine.coefficient * input.claim_weight;
        if coefficient == Fp2::ZERO {
            return Err(C61AuthenticatedWhirError::new(
                "C6.3 WHIR normalized limb coefficient is zero",
            ));
        }
        let mask_domain = mask_range.correlation_domain_limb(lane, limb as u8)?;
        let mask_key = context
            .expand_full_verifier_keys(mask_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR missing limb key"))?;
        let public =
            input.combined - input.shifted_masked_claim - input.gamma * input.affine.constant;
        targets[limb] =
            VerifierKey::from_public(public, context.delta).add(mask_key).scale(coefficient.inv());
    }
    let derived = targets[0].add(targets[1].scale(Fp2::new(Fp::ZERO, Fp::ONE)));
    let residual = derived.sub(expected_target);
    append_authenticated_whir_zero_open_verifier(proof.zero_open_tag, transcript);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new(
            "C6.3 WHIR normalized limb-pair ZeroOpen failed",
        ));
    }
    Ok(())
}

pub fn verify_c64_shared_authenticated_whir_limb_pair(
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
    expected_target: VerifierKey,
    proof: C61AuthenticatedWhirBaseProof,
    corrections: [Fp2; 2],
    context: &mut VerifierCtx,
    family: C64ProjectedResidualFamily,
    mask_range: C64AuthenticatedWhirMaskRange,
    transcript: &mut Transcript,
) -> Result<()> {
    transcript.append_fp2s("c64_shared_whir_mask_corrections", &corrections);
    let mut targets = [VerifierKey::ZERO; 2];
    for limb in 0..2 {
        let input = inputs[limb];
        let coefficient = input.gamma * input.affine.coefficient * input.claim_weight;
        if coefficient == Fp2::ZERO {
            return Err(C61AuthenticatedWhirError::new(
                "C6.4 WHIR normalized limb coefficient is zero",
            ));
        }
        let mask_domain = mask_range.correlation_domain_limb(family, limb as u8)?;
        let raw_mask_key = context
            .expand_full_verifier_keys(mask_domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.4 WHIR missing limb key"))?;
        let mask_key = raw_mask_key.add(VerifierKey::from_public(corrections[limb], context.delta));
        let public =
            input.combined - input.shifted_masked_claim - input.gamma * input.affine.constant;
        targets[limb] =
            VerifierKey::from_public(public, context.delta).add(mask_key).scale(coefficient.inv());
    }
    let residual =
        targets[0].add(targets[1].scale(Fp2::new(Fp::ZERO, Fp::ONE))).sub(expected_target);
    append_authenticated_whir_zero_open_verifier(proof.zero_open_tag, transcript);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new(
            "C6.4 WHIR normalized limb-pair ZeroOpen failed",
        ));
    }
    Ok(())
}

/// Verifier mirror of
/// [`finish_c61_authenticated_whir_base_with_zero_rows`].
pub fn verify_c61_authenticated_whir_base_with_zero_rows(
    input: C61AuthenticatedWhirVerifierInput,
    zero_rows: &[VerifierKey],
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<()> {
    verify_c61_authenticated_whir_base_with_zero_rows_residual(
        input, zero_rows, proof, context, transcript,
    )
    .map(|_| ())
}

/// Internal verifier seam that also returns the exact folded residual key.
/// This lets integration diagnostics test a mutated terminal tag against the
/// same challenge and correlation cursor as the accepted execution, without
/// replaying it under unrelated verifier state.
pub(crate) fn verify_c61_authenticated_whir_base_with_zero_rows_residual(
    input: C61AuthenticatedWhirVerifierInput,
    zero_rows: &[VerifierKey],
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<VerifierKey> {
    if zero_rows.is_empty() {
        return Err(C61AuthenticatedWhirError::new(
            "C6AWH1 folded arithmetic closure requires at least one zero row",
        ));
    }
    let mask_domain = input.mask_range.correlation_domain(input.id)?;
    let mask_key = context
        .expand_full_verifier_keys(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 missing verifier mask key"))?;
    let mut residual = c61_authenticated_whir_verifier_residual(input, mask_key, context.delta);
    let challenge = transcript.challenge_fp2();
    let mut weight = Fp2::ONE;
    for row in zero_rows {
        weight = weight * challenge;
        residual = residual.add(row.scale(weight));
    }
    append_authenticated_whir_zero_open_verifier(proof.zero_open_tag, transcript);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new("C6AWH1 folded arithmetic ZeroOpen failed"));
    }
    Ok(residual)
}

fn c61_authenticated_whir_verifier_residual(
    input: C61AuthenticatedWhirVerifierInput,
    mask_key: VerifierKey,
    delta: Fp2,
) -> VerifierKey {
    VerifierKey::from_public(input.combined - input.shifted_masked_claim, delta)
        .sub(input.target.scale(input.gamma))
        .add(mask_key)
}

/// Designated-verifier view simulator for the feature-only C6.1 reference.
///
/// The simulator reads only verifier-owned state and public transcript
/// derivatives.  It deliberately does not receive the opening plaintext,
/// its provider MAC tag, or the one-time mask plaintext/tag.  A designated
/// verifier can set the final tag to its locally derived residual key; an
/// honest execution emits exactly the same value because the residual has
/// plaintext zero.  This is a privacy diagnostic, never a prover API.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub(crate) fn simulate_c61_authenticated_whir_base_view(
    input: C61AuthenticatedWhirVerifierInput,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirBaseProof> {
    let mask_domain = input.mask_range.correlation_domain(input.id)?;
    let mask_key = context
        .expand_full_verifier_keys(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 missing simulator mask key"))?;
    let residual = c61_authenticated_whir_verifier_residual(input, mask_key, context.delta);
    append_authenticated_whir_zero_open_verifier(residual.k, transcript);
    Ok(C61AuthenticatedWhirBaseProof { zero_open_tag: residual.k })
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub(crate) fn simulate_c63_authenticated_whir_base_view(
    input: C63AuthenticatedWhirVerifierInput,
    context: &mut VerifierCtx,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirBaseProof> {
    let mask_domain = input.mask_range.correlation_domain(input.lane)?;
    let mask_key =
        context.expand_full_verifier_keys(mask_domain, 1).into_iter().next().ok_or_else(|| {
            C61AuthenticatedWhirError::new("C6.3 WHIR missing simulator mask key")
        })?;
    let residual =
        VerifierKey::from_public(input.combined - input.shifted_masked_claim, context.delta)
            .sub(input.target.scale(input.gamma))
            .add(mask_key);
    append_authenticated_whir_zero_open_verifier(residual.k, transcript);
    Ok(C61AuthenticatedWhirBaseProof { zero_open_tag: residual.k })
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub(crate) fn simulate_c63_authenticated_whir_limb_pair_view(
    inputs: [C63AuthenticatedWhirNormalizedLimb; 2],
    expected_target: VerifierKey,
    context: &mut VerifierCtx,
    lane: C63AuthenticatedWhirLane,
    mask_range: C63AuthenticatedWhirMaskRange,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirBaseProof> {
    let mut targets = [VerifierKey::ZERO; 2];
    for limb in 0..2 {
        let input = inputs[limb];
        let coefficient = input.gamma * input.affine.coefficient * input.claim_weight;
        if coefficient == Fp2::ZERO {
            return Err(C61AuthenticatedWhirError::new(
                "C6.3 WHIR normalized limb coefficient is zero",
            ));
        }
        let domain = mask_range.correlation_domain_limb(lane, limb as u8)?;
        let mask_key = context
            .expand_full_verifier_keys(domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C61AuthenticatedWhirError::new("C6.3 WHIR missing simulator key"))?;
        let public =
            input.combined - input.shifted_masked_claim - input.gamma * input.affine.constant;
        targets[limb] =
            VerifierKey::from_public(public, context.delta).add(mask_key).scale(coefficient.inv());
    }
    let derived =
        targets[0].add(targets[1].scale(Fp2::new(Fp::ZERO, Fp::ONE))).sub(expected_target);
    append_authenticated_whir_zero_open_verifier(derived.k, transcript);
    Ok(C61AuthenticatedWhirBaseProof { zero_open_tag: derived.k })
}

fn append_authenticated_whir_zero_open_prover(
    residual: &ProverAuthed,
    transcript: &mut Transcript,
) -> Fp2 {
    if transcript.is_fiat_shamir() {
        debug_assert_eq!(residual.x, Fp2::ZERO, "ZeroOpen on a nonzero claim");
        transcript.append_fp2s("zero_open_tag", &[residual.m]);
        residual.m
    } else {
        zero_open_prover(residual, transcript)
    }
}

fn append_authenticated_whir_zero_open_verifier(tag: Fp2, transcript: &mut Transcript) {
    if transcript.is_fiat_shamir() {
        transcript.append_fp2s("zero_open_tag", &[tag]);
    } else {
        transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
    }
}

fn component_ordinal(component: C61NativeComponent) -> Result<u32> {
    match component {
        C61NativeComponent::Model => Ok(0),
        C61NativeComponent::Embedding => Ok(1),
        C61NativeComponent::Compiler => Ok(2),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, panic::AssertUnwindSafe};

    use volta_mac::CorrCounters;

    use super::*;

    const PCG_SEEDS: [[u8; 32]; 2] = [[0xA1; 32], [0xB2; 32]];

    fn f(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(11).wrapping_add(7)))
    }

    fn target(value: Fp2, tag: Fp2, delta: Fp2) -> (ProverAuthed, VerifierKey) {
        (ProverAuthed::new(value, tag), VerifierKey::new(tag + delta * value))
    }

    fn range(tape: usize) -> C61AuthenticatedWhirMaskRange {
        C61AuthenticatedWhirMaskRange {
            stage: 0x61,
            slot: 17,
            range_start: 1_000 + tape as u32 * 100,
        }
    }

    #[test]
    fn c63_real_pcg_terminal_range_consumes_four_distinct_limb_masks_per_tape() {
        let seed = [0xC3; 32];
        let delta = f(1_201);
        let range = C63AuthenticatedWhirMaskRange { stage: 0x63, slot: 17, range_start: 2_000 };
        let mut prover = CorrelationStream::new(seed);
        let mut verifier = VerifierCtx::new(seed, delta);
        #[cfg(feature = "c61-p3-authenticated-reference")]
        let mut simulator = VerifierCtx::new(seed, delta);
        let transcript_seed = [0xD3; 32];
        let mut prover_transcript = Transcript::new(transcript_seed);
        let mut verifier_transcript = Transcript::new(transcript_seed);
        #[cfg(feature = "c61-p3-authenticated-reference")]
        let mut simulator_transcript = Transcript::new(transcript_seed);
        let mut domains = HashSet::new();

        for (lane_index, lane) in
            [C63AuthenticatedWhirLane::Systematic, C63AuthenticatedWhirLane::Sketch]
                .into_iter()
                .enumerate()
        {
            let prepared =
                prepare_c63_authenticated_whir_limb_pair(lane, range, &mut prover).unwrap();
            let target_values = [f(1_211 + lane_index as u64), f(1_213 + lane_index as u64)];
            let target_pairs = [
                target(target_values[0], f(1_221 + lane_index as u64), delta),
                target(target_values[1], f(1_223 + lane_index as u64), delta),
            ];
            let expected_target =
                target_pairs[0].0.add(target_pairs[1].0.scale(Fp2::new(Fp::ZERO, Fp::ONE)));
            let expected_target_key =
                target_pairs[0].1.add(target_pairs[1].1.scale(Fp2::new(Fp::ZERO, Fp::ONE)));
            let gammas = [f(1_231 + lane_index as u64), f(1_233 + lane_index as u64)];
            let masked_claims = [f(1_241 + lane_index as u64), f(1_243 + lane_index as u64)];
            let shifted = prepared.shifted_masked_claims(masked_claims);
            let inputs = std::array::from_fn(|limb| C63AuthenticatedWhirNormalizedLimb {
                combined: masked_claims[limb] + gammas[limb] * target_values[limb],
                shifted_masked_claim: shifted[limb],
                gamma: gammas[limb],
                affine: C61AuthenticatedWhirAffineClaim::identity(),
                claim_weight: Fp2::ONE,
            });
            let closure = finish_c63_authenticated_whir_limb_pair(
                prepared,
                inputs,
                expected_target,
                &mut prover_transcript,
            )
            .unwrap();
            for limb in 0..2 {
                assert!(domains.insert(closure.mask_domains[limb]));
                assert_eq!(
                    closure.mask_ordinals[limb],
                    range.range_start + (lane_index * 2 + limb) as u32
                );
            }
            #[cfg(feature = "c61-p3-authenticated-reference")]
            assert_eq!(
                simulate_c63_authenticated_whir_limb_pair_view(
                    inputs,
                    expected_target_key,
                    &mut simulator,
                    lane,
                    range,
                    &mut simulator_transcript,
                )
                .unwrap(),
                closure.proof,
            );
            verify_c63_authenticated_whir_limb_pair(
                inputs,
                expected_target_key,
                closure.proof,
                &mut verifier,
                lane,
                range,
                &mut verifier_transcript,
            )
            .unwrap();
        }
        assert_eq!(prover.counters.full_corrs, 4);
        assert_eq!(verifier.counters.full_corrs, 4);
        #[cfg(feature = "c61-p3-authenticated-reference")]
        assert_eq!(simulator.counters.full_corrs, 4);
    }

    #[test]
    fn c64_shared_masks_keep_one_whir_value_and_two_independent_mac_tapes() {
        let delta = f(1_251);
        let range = C64AuthenticatedWhirMaskRange { stage: 0x64, slot: 19, range_start: 2_100 };
        let mut streams =
            [CorrelationStream::new(PCG_SEEDS[0]), CorrelationStream::new(PCG_SEEDS[1])];
        let prepared = prepare_c64_shared_authenticated_whir_limb_pair(
            C64ProjectedResidualFamily::LeafOther,
            range,
            &mut streams,
        )
        .unwrap();
        let corrections = prepared.corrections();
        assert_eq!(corrections[0], [Fp2::ZERO; 2]);
        assert_ne!(corrections[1], [Fp2::ZERO; 2]);

        let target_values = [f(1_253), f(1_257)];
        let expected_value = target_values[0] + target_values[1] * Fp2::new(Fp::ZERO, Fp::ONE);
        let expected =
            [target(expected_value, f(1_263), delta), target(expected_value, f(1_269), delta)];
        let masked_claims = [f(1_271), f(1_277)];
        let shifted =
            [masked_claims[0] + prepared.values()[0], masked_claims[1] + prepared.values()[1]];
        let inputs = std::array::from_fn(|limb| C63AuthenticatedWhirNormalizedLimb {
            combined: masked_claims[limb] + f(1_281 + limb as u64) * target_values[limb],
            shifted_masked_claim: shifted[limb],
            gamma: f(1_281 + limb as u64),
            affine: C61AuthenticatedWhirAffineClaim::identity(),
            claim_weight: Fp2::ONE,
        });
        let mut prover_transcripts = [Transcript::new([0xE1; 32]), Transcript::new([0xE2; 32])];
        let closures = finish_c64_shared_authenticated_whir_limb_pair(
            prepared,
            inputs,
            [expected[0].0, expected[1].0],
            &mut prover_transcripts,
        )
        .unwrap();

        for tape in 0..2 {
            let mut context = VerifierCtx::new(PCG_SEEDS[tape], delta);
            let mut transcript = Transcript::new([0xE1 + tape as u8; 32]);
            verify_c64_shared_authenticated_whir_limb_pair(
                inputs,
                expected[tape].1,
                closures[tape].proof,
                corrections[tape],
                &mut context,
                C64ProjectedResidualFamily::LeafOther,
                range,
                &mut transcript,
            )
            .unwrap();
            assert_eq!(context.counters.full_corrs, 2);
            assert_eq!(prover_transcripts[tape].ledger(), transcript.ledger());
            assert_eq!(transcript.ledger()["c64_shared_whir_mask_corrections"], 32);
        }

        let mut changed = corrections[1];
        changed[0] = changed[0] + Fp2::ONE;
        assert!(verify_c64_shared_authenticated_whir_limb_pair(
            inputs,
            expected[1].1,
            closures[1].proof,
            changed,
            &mut VerifierCtx::new(PCG_SEEDS[1], delta),
            C64ProjectedResidualFamily::LeafOther,
            range,
            &mut Transcript::new([0xE2; 32]),
        )
        .is_err());
    }

    #[test]
    fn joint_native_bridge_closes_generic_weighted_functionals_in_32_bytes() {
        let delta = f(1_101);
        let gamma = [f(1_103), f(1_109)];
        let affine = [
            C61AuthenticatedWhirAffineClaim { coefficient: f(1_113), constant: f(1_117) },
            C61AuthenticatedWhirAffineClaim { coefficient: f(1_121), constant: f(1_123) },
        ];
        let weights = [Fp2::ONE, f(1_127)];
        let ids = [
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
        ];
        let ranges = [range(0), range(1)];
        let mut prover_correlations = CorrelationStream::new(PCG_SEEDS[1]);
        let mut prepared = Vec::new();
        let mut target_auth = Vec::new();
        let mut target_keys = Vec::new();
        let mut combined = [Fp2::ZERO; 2];
        let mut shifted = [Fp2::ZERO; 2];

        for index in 0..2 {
            let mask = prepare_c61_authenticated_whir_mask(
                ids[index],
                ranges[index],
                &mut prover_correlations,
            )
            .unwrap();
            let (authenticated, key) =
                target(f(1_201 + index as u64), f(1_301 + index as u64), delta);
            let masked_claim = f(1_401 + index as u64);
            shifted[index] = mask.shifted_masked_claim(masked_claim);
            combined[index] = shifted[index]
                + gamma[index] * affine[index].evaluate(authenticated.x)
                - mask.value();
            prepared.push(mask);
            target_auth.push(authenticated);
            target_keys.push(key);
        }

        let compiler_fold = target_auth[0].scale(weights[0]).add(target_auth[1].scale(weights[1]));
        let compiler_key = target_keys[0].scale(weights[0]).add(target_keys[1].scale(weights[1]));
        let compiler_correction = f(1_399);
        let compiler_base_fold = compiler_fold.sub(ProverAuthed::from_public(compiler_correction));
        let compiler_base_key =
            compiler_key.sub(VerifierKey::from_public(compiler_correction, delta));
        let prover_terms: Vec<_> = prepared
            .into_iter()
            .enumerate()
            .map(|(index, prepared)| C61JointNativeProverTerm {
                prepared,
                combined: combined[index],
                shifted_masked_claim: shifted[index],
                gamma: gamma[index],
                affine: affine[index],
                cohort_weight: weights[index],
            })
            .collect();
        let mut verifier_context = VerifierCtx::new(PCG_SEEDS[1], delta);
        let verifier_terms: Vec<_> = (0..2)
            .map(|index| {
                let domain = ranges[index].correlation_domain(ids[index]).unwrap();
                let mask_key = verifier_context.expand_full_verifier_keys(domain, 1)[0];
                C61JointNativeVerifierTerm {
                    mask_key,
                    combined: combined[index],
                    shifted_masked_claim: shifted[index],
                    gamma: gamma[index],
                    affine: affine[index],
                    cohort_weight: weights[index],
                }
            })
            .collect();
        let mut prover_transcript = Transcript::new([0xD1; 32]);
        let frame = finish_c61_joint_native_bridge(
            prover_terms,
            compiler_base_fold,
            compiler_correction,
            &mut prover_transcript,
        )
        .unwrap();
        let encoded = frame.encode();
        assert_eq!(encoded.len(), C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES);
        let decoded = C61JointNativeBridgeFrame::decode(&encoded).unwrap();
        let mut verifier_transcript = Transcript::new([0xD1; 32]);
        verify_c61_joint_native_bridge(
            &verifier_terms,
            compiler_base_key,
            compiler_correction,
            delta,
            decoded,
            &mut verifier_transcript,
        )
        .unwrap();
        assert_eq!(prover_transcript.ledger(), verifier_transcript.ledger());

        let mut changed_correction = decoded;
        changed_correction.correction = changed_correction.correction + Fp2::ONE;
        assert!(verify_c61_joint_native_bridge(
            &verifier_terms,
            compiler_base_key,
            compiler_correction,
            delta,
            changed_correction,
            &mut Transcript::new([0xD1; 32]),
        )
        .is_err());
        let mut changed_tag = decoded;
        changed_tag.zero_open_tag = changed_tag.zero_open_tag + Fp2::ONE;
        assert!(verify_c61_joint_native_bridge(
            &verifier_terms,
            compiler_base_key,
            compiler_correction,
            delta,
            changed_tag,
            &mut Transcript::new([0xD1; 32]),
        )
        .is_err());

        let mut wrong_order = verifier_terms.clone();
        wrong_order.swap(0, 1);
        wrong_order[0].cohort_weight = weights[0];
        wrong_order[1].cohort_weight = weights[1];
        assert!(verify_c61_joint_native_bridge(
            &wrong_order,
            compiler_base_key,
            compiler_correction,
            delta,
            decoded,
            &mut Transcript::new([0xD1; 32]),
        )
        .is_err());

        let mut noncanonical = encoded;
        noncanonical[..8].copy_from_slice(&P.to_le_bytes());
        assert!(C61JointNativeBridgeFrame::decode(&noncanonical).is_err());
    }

    #[test]
    fn joint_native_bridge_rejects_degenerate_shapes() {
        assert!(verify_c61_joint_native_bridge(
            &[],
            VerifierKey::ZERO,
            Fp2::ZERO,
            f(1_501),
            C61JointNativeBridgeFrame { correction: Fp2::ZERO, zero_open_tag: Fp2::ZERO },
            &mut Transcript::new([0xD2; 32]),
        )
        .is_err());
        let term = C61JointNativeVerifierTerm {
            mask_key: VerifierKey::ZERO,
            combined: Fp2::ZERO,
            shifted_masked_claim: Fp2::ZERO,
            gamma: Fp2::ZERO,
            affine: C61AuthenticatedWhirAffineClaim::identity(),
            cohort_weight: Fp2::ONE,
        };
        assert!(verify_c61_joint_native_bridge(
            &[term, term],
            VerifierKey::ZERO,
            Fp2::ZERO,
            f(1_503),
            C61JointNativeBridgeFrame { correction: Fp2::ZERO, zero_open_tag: Fp2::ZERO },
            &mut Transcript::new([0xD3; 32]),
        )
        .is_err());
    }

    #[test]
    fn c62_relation_binds_distinct_secondary_response_and_compiler_values() {
        let delta = f(1_601);
        let gamma = [f(1_603), f(1_607)];
        let affine = [
            C61AuthenticatedWhirAffineClaim { coefficient: f(1_609), constant: f(1_613) },
            C61AuthenticatedWhirAffineClaim { coefficient: f(1_617), constant: f(1_619) },
        ];
        let weights = [Fp2::ONE, f(1_621)];
        let ids = [
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 },
        ];
        let ranges = [range(0), range(1)];
        let mut prover_correlations = CorrelationStream::new(PCG_SEEDS[1]);
        let mut prepared = Vec::new();
        let mut response_targets = Vec::new();
        let mut response_keys = Vec::new();
        let mut combined = [Fp2::ZERO; 2];
        let mut shifted = [Fp2::ZERO; 2];
        for index in 0..2 {
            let mask = prepare_c61_authenticated_whir_mask(
                ids[index],
                ranges[index],
                &mut prover_correlations,
            )
            .unwrap();
            let (response_target, response_key) =
                target(f(1_701 + index as u64), f(1_801 + index as u64), delta);
            let masked_claim = f(1_901 + index as u64);
            shifted[index] = mask.shifted_masked_claim(masked_claim);
            combined[index] = shifted[index]
                + gamma[index] * affine[index].evaluate(response_target.x)
                - mask.value();
            prepared.push(mask);
            response_targets.push(response_target);
            response_keys.push(response_key);
        }
        let compiler_fold =
            response_targets[0].scale(weights[0]).add(response_targets[1].scale(weights[1]));
        let compiler_key =
            response_keys[0].scale(weights[0]).add(response_keys[1].scale(weights[1]));
        let correction = f(1_999);
        let compiler_base = compiler_fold.sub(ProverAuthed::from_public(correction));
        let compiler_base_key = compiler_key.sub(VerifierKey::from_public(correction, delta));
        let prover_terms = prepared
            .into_iter()
            .enumerate()
            .map(|(index, prepared)| C62SecondaryResponseProverTerm {
                native: C61JointNativeProverTerm {
                    prepared,
                    combined: combined[index],
                    shifted_masked_claim: shifted[index],
                    gamma: gamma[index],
                    affine: affine[index],
                    cohort_weight: weights[index],
                },
                response_target: response_targets[index],
            })
            .collect();
        let mut verifier_context = VerifierCtx::new(PCG_SEEDS[1], delta);
        let verifier_terms: Vec<_> = (0..2)
            .map(|index| {
                let domain = ranges[index].correlation_domain(ids[index]).unwrap();
                C62SecondaryResponseVerifierTerm {
                    native: C61JointNativeVerifierTerm {
                        mask_key: verifier_context.expand_full_verifier_keys(domain, 1)[0],
                        combined: combined[index],
                        shifted_masked_claim: shifted[index],
                        gamma: gamma[index],
                        affine: affine[index],
                        cohort_weight: weights[index],
                    },
                    response_target: response_keys[index],
                }
            })
            .collect();
        let binding = C62ResponseCompilerBinding {
            schedule_digest: [0xE1; 32],
            response_binding_digest: [0xE2; 32],
            functional_digest: [0xE3; 32],
            nbr2_statement_digest: [0xE4; 32],
            root_binding_digest: [0xE5; 32],
            compiler_correction: correction,
        };
        let mut prover_transcript = Transcript::new_fiat_shamir([0xE6; 32]).unwrap();
        let prover_pending = prepare_c62_response_compiler_relation_prover(
            prover_terms,
            compiler_base,
            binding,
            &mut prover_transcript,
        )
        .unwrap();
        let prover_eta = prover_pending.eta();
        let frame = prover_pending.finish(&mut prover_transcript).unwrap();
        let mut verifier_transcript = Transcript::new_fiat_shamir([0xE6; 32]).unwrap();
        let verifier_pending = prepare_c62_response_compiler_relation_verifier(
            &verifier_terms,
            compiler_base_key,
            binding,
            delta,
            frame,
            &mut verifier_transcript,
        )
        .unwrap();
        assert_eq!(prover_eta, verifier_pending.eta());
        verifier_pending.finish(&mut verifier_transcript).unwrap();
        assert_eq!(
            prover_transcript.canonical_binding_digest().unwrap(),
            verifier_transcript.canonical_binding_digest().unwrap(),
        );

        let mut divergent = verifier_terms.clone();
        divergent[0].response_target =
            divergent[0].response_target.add(VerifierKey::from_public(Fp2::ONE, delta));
        let mut divergent_transcript = Transcript::new_fiat_shamir([0xE6; 32]).unwrap();
        assert!(prepare_c62_response_compiler_relation_verifier(
            &divergent,
            compiler_base_key,
            binding,
            delta,
            frame,
            &mut divergent_transcript,
        )
        .unwrap()
        .finish(&mut divergent_transcript)
        .is_err());
    }

    #[test]
    fn honest_base_closure_is_16_bytes_and_consumes_one_mask() {
        let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
        let delta = f(91);
        let gamma = f(17);
        let masked_claim = f(23);
        let (target, key) = target(f(29), f(31), delta);
        let combined = masked_claim + gamma * target.x;
        let mut prover_correlations = CorrelationStream::new(PCG_SEEDS[0]);
        let mut verifier_context = VerifierCtx::new(PCG_SEEDS[0], delta);
        let mut prover_transcript = Transcript::new_fiat_shamir([0xC3; 32]).unwrap();
        let mut verifier_transcript = Transcript::new_fiat_shamir([0xC3; 32]).unwrap();

        let closure = prove_c61_authenticated_whir_base(
            C61AuthenticatedWhirProverInput {
                id,
                mask_range: range(0),
                combined,
                masked_claim,
                gamma,
                target,
            },
            &mut prover_correlations,
            &mut prover_transcript,
        )
        .unwrap();
        let encoded = closure.proof.encode();
        assert_eq!(encoded.len(), C61_AUTHENTICATED_WHIR_REMOVED_EVALUATION_BYTES);
        assert_eq!(C61_AUTHENTICATED_WHIR_NET_PROVIDER_BYTES, 0);
        let decoded = C61AuthenticatedWhirBaseProof::decode(&encoded).unwrap();
        verify_c61_authenticated_whir_base(
            C61AuthenticatedWhirVerifierInput {
                id,
                mask_range: range(0),
                combined,
                shifted_masked_claim: closure.shifted_masked_claim,
                gamma,
                target: key,
            },
            decoded,
            &mut verifier_context,
            &mut verifier_transcript,
        )
        .unwrap();
        let expected = CorrCounters { sub_corrs: 0, full_corrs: 1, domains: 1 };
        assert_eq!(prover_correlations.counters, expected);
        assert_eq!(verifier_context.counters, expected);
        assert_eq!(prover_transcript.total_bytes(), 16);
        assert_eq!(prover_transcript.ledger(), verifier_transcript.ledger());
        assert_eq!(
            prover_transcript.canonical_binding_digest().unwrap(),
            verifier_transcript.canonical_binding_digest().unwrap(),
        );
    }

    #[test]
    fn arithmetic_zero_rows_share_the_existing_whir_mask_and_tag() {
        let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
        let delta = f(701);
        let gamma = f(709);
        let masked_claim = f(719);
        let (target, target_key) = target(f(727), f(733), delta);
        let combined = masked_claim + gamma * target.x;
        let zero_rows: Vec<_> =
            (0..7).map(|index| ProverAuthed::new(Fp2::ZERO, f(739 + index))).collect();
        let zero_keys: Vec<_> = zero_rows.iter().map(|row| VerifierKey::new(row.m)).collect();
        let mut prover_correlations = CorrelationStream::new(PCG_SEEDS[0]);
        let prepared =
            prepare_c61_authenticated_whir_mask(id, range(0), &mut prover_correlations).unwrap();
        let shifted_masked_claim = prepared.shifted_masked_claim(masked_claim);
        let mut prover_transcript = Transcript::new([0xA7; 32]);
        let closure = finish_c61_authenticated_whir_base_with_zero_rows(
            prepared,
            C61AuthenticatedWhirProverFinishInput { combined, shifted_masked_claim, gamma, target },
            &zero_rows,
            &mut prover_transcript,
        )
        .unwrap();
        let verifier_input = C61AuthenticatedWhirVerifierInput {
            id,
            mask_range: range(0),
            combined,
            shifted_masked_claim,
            gamma,
            target: target_key,
        };
        let mut verifier_context = VerifierCtx::new(PCG_SEEDS[0], delta);
        let mut verifier_transcript = Transcript::new([0xA7; 32]);
        verify_c61_authenticated_whir_base_with_zero_rows(
            verifier_input,
            &zero_keys,
            closure.proof,
            &mut verifier_context,
            &mut verifier_transcript,
        )
        .unwrap();
        assert_eq!(closure.proof.encode().len(), C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES);
        assert_eq!(
            prover_correlations.counters,
            CorrCounters { sub_corrs: 0, full_corrs: 1, domains: 1 }
        );
        assert_eq!(prover_correlations.counters, verifier_context.counters);
        assert_eq!(prover_transcript.total_bytes(), 16);
        assert_eq!(prover_transcript.ledger(), verifier_transcript.ledger());

        let verify_changed = |rows: &[VerifierKey]| {
            let mut context = VerifierCtx::new(PCG_SEEDS[0], delta);
            let mut transcript = Transcript::new([0xA7; 32]);
            verify_c61_authenticated_whir_base_with_zero_rows(
                verifier_input,
                rows,
                closure.proof,
                &mut context,
                &mut transcript,
            )
        };
        assert!(verify_changed(&zero_keys[..zero_keys.len() - 1]).is_err());
        let mut changed_keys = zero_keys.clone();
        changed_keys[3] = changed_keys[3].add(VerifierKey::new(Fp2::ONE));
        assert!(verify_changed(&changed_keys).is_err());
        assert!(verify_changed(&[]).is_err());

        let mut changed_rows = zero_rows;
        changed_rows[2].x = Fp2::ONE;
        let mut changed_correlations = CorrelationStream::new(PCG_SEEDS[0]);
        let changed_prepared =
            prepare_c61_authenticated_whir_mask(id, range(0), &mut changed_correlations).unwrap();
        let mut changed_transcript = Transcript::new([0xA7; 32]);
        assert!(finish_c61_authenticated_whir_base_with_zero_rows(
            changed_prepared,
            C61AuthenticatedWhirProverFinishInput { combined, shifted_masked_claim, gamma, target },
            &changed_rows,
            &mut changed_transcript,
        )
        .is_err());
    }

    #[test]
    fn affine_replay_matches_plain_target_and_preserves_mac() {
        let delta = f(131);
        let opening_value = f(137);
        let (opening_target, opening_key) = target(opening_value, f(139), delta);
        let mut affine = C61AuthenticatedWhirAffineClaim::identity();
        let mut plain = opening_value;

        let epsilon = f(149);
        let mu_tilde = f(151);
        affine = affine.prelude(epsilon, mu_tilde);
        plain = epsilon * plain + mu_tilde;
        assert_eq!(affine.evaluate(opening_value), plain);

        for index in 0..4u64 {
            let c0 = f(157 + index);
            let c2 = f(163 + index);
            let c3 = f(167 + index);
            let gamma = f(173 + index);
            let tail_at_one = c2 + c3;
            let tail_at_gamma = c2 * gamma * gamma + c3 * gamma * gamma * gamma;
            let c1 = plain - c0 - c0 - tail_at_one;
            plain = c0 + c1 * gamma + tail_at_gamma;
            affine = affine.round(c0, tail_at_one, tail_at_gamma, gamma);
            assert_eq!(affine.evaluate(opening_value), plain);
        }

        let public_switch = f(181);
        affine = affine.add_public(public_switch);
        plain += public_switch;
        assert_eq!(affine.evaluate(opening_value), plain);

        let final_target = affine.authenticate_prover(opening_target);
        let final_key = affine.derive_verifier_key(opening_key, delta);
        assert_eq!(final_target.x, plain);
        assert_eq!(final_key.k, final_target.m + delta * final_target.x);
    }

    #[test]
    fn six_chains_use_three_distinct_masks_per_tape() {
        let delta = f(101);
        let mut prover_streams = PCG_SEEDS.map(CorrelationStream::new);
        let mut verifier_contexts = PCG_SEEDS.map(|seed| VerifierCtx::new(seed, delta));
        for tape in 0..2 {
            prover_streams[tape].enable_schedule_audit().unwrap();
            verifier_contexts[tape].enable_schedule_audit().unwrap();
        }
        let mut prover_transcript = Transcript::new([0xD4; 32]);
        let mut verifier_transcript = Transcript::new([0xD4; 32]);
        let mut domains = HashSet::new();
        for (index, id) in C61NativeChainId::ordered().into_iter().enumerate() {
            let tape = usize::from(id.repetition);
            let gamma = f(200 + index as u64);
            let masked_claim = f(300 + index as u64);
            let (target, key) = target(f(400 + index as u64), f(500 + index as u64), delta);
            let combined = masked_claim + gamma * target.x;
            let closure = prove_c61_authenticated_whir_base(
                C61AuthenticatedWhirProverInput {
                    id,
                    mask_range: range(tape),
                    combined,
                    masked_claim,
                    gamma,
                    target,
                },
                &mut prover_streams[tape],
                &mut prover_transcript,
            )
            .unwrap();
            assert!(domains.insert(closure.mask_domain));
            assert_eq!(closure.mask_ordinal, range(tape).range_start + (index / 2) as u32);
            verify_c61_authenticated_whir_base(
                C61AuthenticatedWhirVerifierInput {
                    id,
                    mask_range: range(tape),
                    combined,
                    shifted_masked_claim: closure.shifted_masked_claim,
                    gamma,
                    target: key,
                },
                closure.proof,
                &mut verifier_contexts[tape],
                &mut verifier_transcript,
            )
            .unwrap();
        }
        assert_eq!(domains.len(), C61_AUTHENTICATED_WHIR_CHAINS);
        let expected = CorrCounters { sub_corrs: 0, full_corrs: 3, domains: 3 };
        for tape in 0..2 {
            assert_eq!(prover_streams[tape].counters, expected);
            assert_eq!(verifier_contexts[tape].counters, expected);
            assert_eq!(
                prover_streams[tape].schedule_audit().unwrap(),
                verifier_contexts[tape].schedule_audit().unwrap()
            );
        }
        assert_eq!(prover_transcript.total_bytes(), 6 * 16);
        assert_eq!(prover_transcript.ledger(), verifier_transcript.ledger());
    }

    #[test]
    fn codec_and_every_authenticated_seam_mutation_reject() {
        let id = C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 };
        let delta = f(601);
        let gamma = f(607);
        let masked_claim = f(613);
        let (target, key) = target(f(617), f(619), delta);
        let combined = masked_claim + gamma * target.x;
        let mut prover = CorrelationStream::new(PCG_SEEDS[1]);
        let mut prover_transcript = Transcript::new([0xE5; 32]);
        let closure = prove_c61_authenticated_whir_base(
            C61AuthenticatedWhirProverInput {
                id,
                mask_range: range(1),
                combined,
                masked_claim,
                gamma,
                target,
            },
            &mut prover,
            &mut prover_transcript,
        )
        .unwrap();

        let verify = |candidate_id: C61NativeChainId,
                      candidate_range: C61AuthenticatedWhirMaskRange,
                      candidate_combined: Fp2,
                      candidate_shifted: Fp2,
                      candidate_gamma: Fp2,
                      candidate_key: VerifierKey,
                      candidate_proof: C61AuthenticatedWhirBaseProof| {
            let mut context = VerifierCtx::new(PCG_SEEDS[1], delta);
            let mut transcript = Transcript::new([0xE5; 32]);
            verify_c61_authenticated_whir_base(
                C61AuthenticatedWhirVerifierInput {
                    id: candidate_id,
                    mask_range: candidate_range,
                    combined: candidate_combined,
                    shifted_masked_claim: candidate_shifted,
                    gamma: candidate_gamma,
                    target: candidate_key,
                },
                candidate_proof,
                &mut context,
                &mut transcript,
            )
        };

        assert!(verify(
            id,
            range(1),
            combined + Fp2::ONE,
            closure.shifted_masked_claim,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        assert!(verify(
            id,
            range(1),
            combined,
            closure.shifted_masked_claim + Fp2::ONE,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        assert!(verify(
            id,
            range(1),
            combined,
            closure.shifted_masked_claim,
            gamma + Fp2::ONE,
            key,
            closure.proof,
        )
        .is_err());
        assert!(verify(
            id,
            range(1),
            combined,
            closure.shifted_masked_claim,
            gamma,
            key.add(VerifierKey::new(Fp2::ONE)),
            closure.proof,
        )
        .is_err());
        assert!(verify(
            C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 },
            range(1),
            combined,
            closure.shifted_masked_claim,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        let mut wrong_range = range(1);
        wrong_range.slot += 1;
        assert!(verify(
            id,
            wrong_range,
            combined,
            closure.shifted_masked_claim,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        let mut wrong_range = range(1);
        wrong_range.stage += 1;
        assert!(verify(
            id,
            wrong_range,
            combined,
            closure.shifted_masked_claim,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        let mut wrong_range = range(1);
        wrong_range.range_start += C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32;
        assert!(verify(
            id,
            wrong_range,
            combined,
            closure.shifted_masked_claim,
            gamma,
            key,
            closure.proof,
        )
        .is_err());
        let forged =
            C61AuthenticatedWhirBaseProof { zero_open_tag: closure.proof.tag() + Fp2::ONE };
        assert!(verify(id, range(1), combined, closure.shifted_masked_claim, gamma, key, forged,)
            .is_err());

        let encoded = closure.proof.encode();
        assert!(C61AuthenticatedWhirBaseProof::decode(&encoded[..15]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(C61AuthenticatedWhirBaseProof::decode(&trailing).is_err());
        let mut noncanonical = encoded;
        noncanonical[..8].copy_from_slice(&P.to_le_bytes());
        assert!(C61AuthenticatedWhirBaseProof::decode(&noncanonical).is_err());
    }

    #[test]
    fn failed_attempt_burns_mask_and_retry_needs_new_range() {
        let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
        let delta = f(701);
        let gamma = f(709);
        let masked_claim = f(719);
        let (target, _) = target(f(727), f(733), delta);
        let mut correlations = CorrelationStream::new(PCG_SEEDS[0]);
        let mut transcript = Transcript::new([0xF6; 32]);
        let bad = prove_c61_authenticated_whir_base(
            C61AuthenticatedWhirProverInput {
                id,
                mask_range: range(0),
                combined: masked_claim + gamma * target.x + Fp2::ONE,
                masked_claim,
                gamma,
                target,
            },
            &mut correlations,
            &mut transcript,
        );
        assert!(bad.is_err());
        assert_eq!(correlations.counters.full_corrs, 1);
        assert_eq!(transcript.total_bytes(), 0);

        let replay = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = prove_c61_authenticated_whir_base(
                C61AuthenticatedWhirProverInput {
                    id,
                    mask_range: range(0),
                    combined: masked_claim + gamma * target.x,
                    masked_claim,
                    gamma,
                    target,
                },
                &mut correlations,
                &mut transcript,
            );
        }));
        assert!(replay.is_err());

        let mut retry_range = range(0);
        retry_range.slot += 1;
        retry_range.range_start += C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32;
        assert!(prove_c61_authenticated_whir_base(
            C61AuthenticatedWhirProverInput {
                id,
                mask_range: retry_range,
                combined: masked_claim + gamma * target.x,
                masked_claim,
                gamma,
                target,
            },
            &mut correlations,
            &mut transcript,
        )
        .is_ok());
        assert_eq!(correlations.counters.full_corrs, 2);
    }

    #[test]
    fn range_and_repetition_validation_are_fail_closed() {
        let overflowing =
            C61AuthenticatedWhirMaskRange { stage: 1, slot: 1, range_start: u32::MAX - 1 };
        let model = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
        assert!(overflowing.correlation_domain(model).is_err());
        let bad_repetition =
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 2 };
        assert!(range(0).correlation_domain(bad_repetition).is_err());
        for id in C61NativeChainId::ordered() {
            assert_eq!(
                range(usize::from(id.repetition)).correlation_domain(id).unwrap()
                    & RESERVED_DOMAIN_BITS,
                0
            );
        }
    }
}

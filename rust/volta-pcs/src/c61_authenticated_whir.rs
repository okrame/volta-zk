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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61JointNativeVerifierTerm {
    pub mask_key: VerifierKey,
    pub combined: Fp2,
    pub shifted_masked_claim: Fp2,
    pub gamma: Fp2,
    pub affine: C61AuthenticatedWhirAffineClaim,
    pub cohort_weight: Fp2,
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
    compiler_fold: ProverAuthed,
    transcript: &mut Transcript,
) -> Result<C61JointNativeBridgeFrame> {
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
    let correction = compiler_fold.x - native_fold.x;
    transcript.append("c6_joint_native_corrections", 16);
    let residual = native_fold.add(ProverAuthed::from_public(correction)).sub(compiler_fold);
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new("C6NBR1 corrected joint residual is nonzero"));
    }
    Ok(C61JointNativeBridgeFrame {
        correction,
        zero_open_tag: zero_open_prover(&residual, transcript),
    })
}

pub fn verify_c61_joint_native_bridge(
    terms: &[C61JointNativeVerifierTerm],
    compiler_fold: VerifierKey,
    delta: Fp2,
    frame: C61JointNativeBridgeFrame,
    transcript: &mut Transcript,
) -> Result<()> {
    if terms.len() < 2 {
        return Err(C61AuthenticatedWhirError::new(
            "C6NBR1 joint verifier requires at least two native bodies",
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
        native_fold.add(VerifierKey::from_public(frame.correction, delta)).sub(compiler_fold);
    transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
    if !zero_open_verify(residual, frame.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new("C6NBR1 joint native ZeroOpen failed"));
    }
    Ok(())
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
    let proof =
        C61AuthenticatedWhirBaseProof { zero_open_tag: zero_open_prover(&residual, transcript) };
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
    let proof =
        C61AuthenticatedWhirBaseProof { zero_open_tag: zero_open_prover(&residual, transcript) };
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
    transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new("C6AWH1 authenticated target ZeroOpen failed"));
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
    transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
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
    transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
    Ok(C61AuthenticatedWhirBaseProof { zero_open_tag: residual.k })
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
        let frame =
            finish_c61_joint_native_bridge(prover_terms, compiler_fold, &mut prover_transcript)
                .unwrap();
        let encoded = frame.encode();
        assert_eq!(encoded.len(), C61_JOINT_NATIVE_BRIDGE_FRAME_BYTES);
        let decoded = C61JointNativeBridgeFrame::decode(&encoded).unwrap();
        let mut verifier_transcript = Transcript::new([0xD1; 32]);
        verify_c61_joint_native_bridge(
            &verifier_terms,
            compiler_key,
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
            compiler_key,
            delta,
            changed_correction,
            &mut Transcript::new([0xD1; 32]),
        )
        .is_err());
        let mut changed_tag = decoded;
        changed_tag.zero_open_tag = changed_tag.zero_open_tag + Fp2::ONE;
        assert!(verify_c61_joint_native_bridge(
            &verifier_terms,
            compiler_key,
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
            compiler_key,
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
            f(1_503),
            C61JointNativeBridgeFrame { correction: Fp2::ZERO, zero_open_tag: Fp2::ZERO },
            &mut Transcript::new([0xD3; 32]),
        )
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
        let mut prover_transcript = Transcript::new([0xC3; 32]);
        let mut verifier_transcript = Transcript::new([0xC3; 32]);

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

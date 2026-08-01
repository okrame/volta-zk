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

/// Consume one uncorrected full VOLE correlation, shift WHIR's base claim and
/// open only the resulting authenticated zero residual.
pub fn prove_c61_authenticated_whir_base(
    input: C61AuthenticatedWhirProverInput,
    correlations: &mut CorrelationStream,
    transcript: &mut Transcript,
) -> Result<C61AuthenticatedWhirProverClosure> {
    let mask_domain = input.mask_range.correlation_domain(input.id)?;
    let mask_ordinal = input.mask_range.mask_ordinal(input.id)?;
    let correlation = correlations
        .draw_fulls(mask_domain, 1)
        .into_iter()
        .next()
        .ok_or_else(|| C61AuthenticatedWhirError::new("C6AWH1 missing full correlation"))?;
    let mask_value = correlation.x;
    let mask = correlation.authenticate(mask_value);
    let shifted_masked_claim = input.masked_claim + mask_value;
    let residual = ProverAuthed::from_public(input.combined - shifted_masked_claim)
        .sub(input.target.scale(input.gamma))
        .add(mask);
    if residual.x != Fp2::ZERO {
        return Err(C61AuthenticatedWhirError::new(
            "C6AWH1 honest WHIR base identity does not close",
        ));
    }
    let proof =
        C61AuthenticatedWhirBaseProof { zero_open_tag: zero_open_prover(&residual, transcript) };
    Ok(C61AuthenticatedWhirProverClosure { shifted_masked_claim, proof, mask_domain, mask_ordinal })
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
    let residual =
        VerifierKey::from_public(input.combined - input.shifted_masked_claim, context.delta)
            .sub(input.target.scale(input.gamma))
            .add(mask_key);
    transcript.append("zero_open_tag", C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES as u64);
    if !zero_open_verify(residual, proof.zero_open_tag) {
        return Err(C61AuthenticatedWhirError::new("C6AWH1 authenticated target ZeroOpen failed"));
    }
    Ok(())
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

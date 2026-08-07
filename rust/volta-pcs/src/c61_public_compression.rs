//! C6.1 scaled public-compression seam.
//!
//! This module implements the strict outer codec, interactive typestate,
//! direct MLE equality challenges and a scaled sparse-adjoint compiler.  It
//! deliberately does not provide a production native PCS implementation.
//! Verification requires an explicit [`C61NativeBackendVerifier`]; there is
//! no default, mock or CPU fallback in production code.

use std::{array, fmt};

use volta_field::{Fp, Fp2, P};
use volta_mac::Transcript;
use volta_proto::{
    C6ResidualDirectAlphaPoints, C6ResidualDirectPostClaimPoints,
    C6ResidualRelationManifest,
};

pub const C61_PUBLIC_ARGUMENT_MAGIC: [u8; 8] = *b"C6PA1\0\0\0";
pub const C61_PUBLIC_ARGUMENT_VERSION: u16 = 1;
pub const C61_JOINT_PUBLIC_ARGUMENT_MAGIC: [u8; 8] = *b"C6PA2\0\0\0";
pub const C61_JOINT_PUBLIC_ARGUMENT_VERSION: u16 = 2;
pub const C61_PUBLIC_ARGUMENT_COMPONENTS: usize = 7;
pub const C61_NATIVE_COMPONENTS: usize = 3;
pub const C61_NATIVE_CHAINS_PER_COMPONENT: usize = 2;
pub const C61_NATIVE_CHAIN_COUNT: usize = C61_NATIVE_COMPONENTS * C61_NATIVE_CHAINS_PER_COMPONENT;
pub const C61_NATIVE_CHAIN_MAX_BYTES: usize = 1_500_000;
pub const C61_PUBLIC_ARGUMENT_MAX_BYTES: usize = 9_500_000;
pub const C61_ARITHMETIC_AND_OUTER_FRAMING_MAX_BYTES: usize = 500_000;

pub const C61_ALPHA_STREAMS: usize = 2;
pub const C61_ALPHA_POINT_DIMENSION: usize = 23;
pub const C61_TERMINAL_STREAMS: usize = 8;
pub const C61_TERMINAL_POINT_DIMENSION: usize = 17;
pub const C61_ATOMIC_STREAMS: usize = 2;
pub const C61_ATOMIC_POINT_DIMENSION: usize = 26;
pub const C61_EQUALITY_CHALLENGE_ELEMENTS: usize = C61_ALPHA_STREAMS * C61_ALPHA_POINT_DIMENSION
    + C61_TERMINAL_STREAMS * C61_TERMINAL_POINT_DIMENSION
    + C61_ATOMIC_STREAMS * C61_ATOMIC_POINT_DIMENSION;
pub const C61_TERMINAL_CLAIMS: usize = 64;
pub const C61_RUNTIME_FINGERPRINTS: usize = 2;
pub const C61_RUNTIME_POINT_DIMENSION: usize = 24;
pub const C61_MAC_COORDINATES: usize = 2;

const OUTER_HEADER_BYTES: usize = 8 + 2 + 2 + 32;
const COMPONENT_HEADER_BYTES: usize = 2 + 1 + 1 + 4 + 32;
const OUTER_DIGEST_BYTES: usize = 32;
pub const C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES: usize = OUTER_HEADER_BYTES
    + C61_PUBLIC_ARGUMENT_COMPONENTS * COMPONENT_HEADER_BYTES
    + OUTER_DIGEST_BYTES;
pub const C61_ARITHMETIC_PAYLOAD_MAX_BYTES: usize =
    C61_ARITHMETIC_AND_OUTER_FRAMING_MAX_BYTES - C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES;

pub const C61_ARITHMETIC_MAGIC: [u8; 8] = *b"C6RSC4\0\0";
pub const C61_ARITHMETIC_VERSION: u16 = 4;
pub const C61_ARITHMETIC_FRAME_BYTES: usize =
    8 + 2 + 2 + 3 * 32 + C61_TERMINAL_CLAIMS * 16 + C61_RUNTIME_FINGERPRINTS * 16 + 16 + 32;
pub const C61_PUBLIC_ARGUMENT_V1_STRICT_MAX_BYTES: usize = C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
    + C61_NATIVE_CHAIN_COUNT * C61_NATIVE_CHAIN_MAX_BYTES
    + C61_ARITHMETIC_FRAME_BYTES;

const STATEMENT_DIGEST_TRANSCRIPT_BYTES: u64 = 32;
const TERMINAL_TRANSCRIPT_BYTES: u64 = (C61_TERMINAL_CLAIMS * 16) as u64;
const ADJOINT_ROOT_TRANSCRIPT_BYTES: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicCompressionError(String);

impl C61PublicCompressionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61PublicCompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61PublicCompressionError {}

type Result<T> = std::result::Result<T, C61PublicCompressionError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum C61NativeComponent {
    Model = 1,
    Embedding = 2,
    Compiler = 3,
}

impl C61NativeComponent {
    const ORDERED: [Self; C61_NATIVE_COMPONENTS] = [Self::Model, Self::Embedding, Self::Compiler];

    fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61NativeChainId {
    pub component: C61NativeComponent,
    pub repetition: u8,
}

impl C61NativeChainId {
    pub fn ordered() -> [Self; C61_NATIVE_CHAIN_COUNT] {
        let mut index = 0usize;
        array::from_fn(|_| {
            let component = C61NativeComponent::ORDERED[index / 2];
            let repetition = (index % 2) as u8;
            index += 1;
            Self { component, repetition }
        })
    }

    fn kind_code(self) -> u16 {
        self.component.code()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61CorrelationRangeBinding {
    pub stage: u32,
    pub start: u64,
    pub count: u64,
}

impl C61CorrelationRangeBinding {
    fn validate(self) -> Result<()> {
        if self.count == 0 {
            return Err(C61PublicCompressionError::new(
                "C6.1 statement has an empty correlation range",
            ));
        }
        self.start
            .checked_add(self.count)
            .ok_or_else(|| C61PublicCompressionError::new("C6.1 correlation range overflows"))?;
        Ok(())
    }
}

/// Provider-global and response-local bindings required in every C6.1
/// public argument.  No designated-verifier secret has a representable
/// field in this structure.  Digests already carried by the retained C6
/// certificate are re-bound here but are not counted as duplicate wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61StatementBinding {
    pub protocol_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub quantization_digest: [u8; 32],
    pub plan_digest: [u8; 32],
    pub parameter_digest: [u8; 32],
    pub setup_manifest_digest: [u8; 32],
    pub connection_id: [u8; 32],
    pub workload_digest: [u8; 32],
    pub public_io_digest: [u8; 32],
    pub retained_transcript_digest: [u8; 32],
    pub retained_wrapper_digest: [u8; 32],
    pub model_root: [u8; 32],
    pub embedding_root: [u8; 32],
    pub compiler_source_root: [u8; 32],
    pub runtime_root: [u8; 32],
    pub predecessor_certificate: [u8; 32],
    pub old_head: [u8; 32],
    pub new_head: [u8; 32],
    pub nonce: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub correlation_ranges: [C61CorrelationRangeBinding; C61_MAC_COORDINATES],
}

impl C61StatementBinding {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"volta/c6.1/statement/v1");
        for digest in [
            self.protocol_digest,
            self.model_digest,
            self.quantization_digest,
            self.plan_digest,
            self.parameter_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.workload_digest,
            self.public_io_digest,
            self.retained_transcript_digest,
            self.retained_wrapper_digest,
            self.model_root,
            self.embedding_root,
            self.compiler_source_root,
            self.runtime_root,
            self.predecessor_certificate,
            self.old_head,
            self.new_head,
            self.nonce,
        ] {
            hasher.update(&digest);
        }
        for value in [self.epoch, self.slot] {
            hasher.update(&value.to_le_bytes());
        }
        for range in self.correlation_ranges {
            hasher.update(&range.stage.to_le_bytes());
            hasher.update(&range.start.to_le_bytes());
            hasher.update(&range.count.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn validate(&self) -> Result<()> {
        let required_nonzero = [
            self.protocol_digest,
            self.model_digest,
            self.quantization_digest,
            self.plan_digest,
            self.parameter_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.workload_digest,
            self.public_io_digest,
            self.retained_transcript_digest,
            self.retained_wrapper_digest,
            self.model_root,
            self.embedding_root,
            self.compiler_source_root,
            self.runtime_root,
            self.old_head,
            self.new_head,
            self.nonce,
        ];
        if required_nonzero.contains(&[0; 32]) {
            return Err(C61PublicCompressionError::new(
                "C6.1 statement contains a zero binding digest",
            ));
        }
        if self.epoch == 0 || (self.predecessor_certificate == [0; 32] && self.epoch != 1) {
            return Err(C61PublicCompressionError::new(
                "C6.1 predecessor/epoch binding is invalid",
            ));
        }
        if self.old_head == self.new_head {
            return Err(C61PublicCompressionError::new(
                "C6.1 statement does not advance its cache head",
            ));
        }
        for range in self.correlation_ranges {
            range.validate()?;
        }
        if self.correlation_ranges[0].count != self.correlation_ranges[1].count {
            return Err(C61PublicCompressionError::new(
                "C6.1 paired correlation ranges have unequal counts",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61EqualityChallenges {
    pub alpha: [[Fp2; C61_ALPHA_POINT_DIMENSION]; C61_ALPHA_STREAMS],
    pub terminal: [[Fp2; C61_TERMINAL_POINT_DIMENSION]; C61_TERMINAL_STREAMS],
    pub atomic: [[Fp2; C61_ATOMIC_POINT_DIMENSION]; C61_ATOMIC_STREAMS],
}

impl C61EqualityChallenges {
    fn draw(transcript: &mut Transcript) -> Self {
        Self {
            alpha: array::from_fn(|_| array::from_fn(|_| transcript.challenge_fp2())),
            terminal: array::from_fn(|_| array::from_fn(|_| transcript.challenge_fp2())),
            atomic: array::from_fn(|_| array::from_fn(|_| transcript.challenge_fp2())),
        }
    }

    pub fn element_count(&self) -> usize {
        C61_EQUALITY_CHALLENGE_ELEMENTS
    }

    fn update_digest(&self, hasher: &mut blake3::Hasher) {
        update_challenge_family(hasher, b"alpha", &self.alpha);
        update_challenge_family(hasher, b"terminal", &self.terminal);
        update_challenge_family(hasher, b"atomic", &self.atomic);
    }
}

/// Reuse the single C6PA2 equality challenge family as the exact C6RSC3-v4
/// residual schedule. This is the zero-wire bridge: no second challenge set
/// or independently supplied point can enter the production relation.
pub fn c61_residual_direct_points(
    manifest: &C6ResidualRelationManifest,
    equality: &C61EqualityChallenges,
) -> Result<(C6ResidualDirectAlphaPoints, C6ResidualDirectPostClaimPoints)> {
    let alpha = std::array::from_fn(|stream| equality.alpha[stream].to_vec());
    let terminal = std::array::from_fn(|stream| equality.terminal[stream].to_vec());
    let atomic = std::array::from_fn(|stream| equality.atomic[stream].to_vec());
    Ok((
        C6ResidualDirectAlphaPoints::new(manifest, alpha)
            .map_err(|error| C61PublicCompressionError::new(error.to_string()))?,
        C6ResidualDirectPostClaimPoints::new(manifest, terminal, atomic)
            .map_err(|error| C61PublicCompressionError::new(error.to_string()))?,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ReadyChallenges {
    pub equality: C61EqualityChallenges,
    pub output_beta: Fp2,
    pub runtime_points: [[Fp2; C61_RUNTIME_POINT_DIMENSION]; C61_RUNTIME_FINGERPRINTS],
}

impl C61ReadyChallenges {
    pub fn digest(&self, statement_digest: [u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"volta/c6.1/challenges/v1");
        hasher.update(&statement_digest);
        self.equality.update_digest(&mut hasher);
        hasher.update(b"output-beta");
        update_fp2(&mut hasher, self.output_beta);
        update_challenge_family(&mut hasher, b"runtime", &self.runtime_points);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct C61RootsFixed {
    binding: C61StatementBinding,
}

impl C61RootsFixed {
    pub fn new(binding: C61StatementBinding) -> Result<Self> {
        binding.validate()?;
        Ok(Self { binding })
    }

    pub fn draw_equality_challenges(self, transcript: &mut Transcript) -> C61EqualityDrawn {
        transcript.append("c61.statement_digest_fixed", STATEMENT_DIGEST_TRANSCRIPT_BYTES);
        C61EqualityDrawn {
            binding: self.binding,
            equality: C61EqualityChallenges::draw(transcript),
        }
    }
}

#[derive(Clone, Debug)]
pub struct C61EqualityDrawn {
    binding: C61StatementBinding,
    equality: C61EqualityChallenges,
}

impl C61EqualityDrawn {
    pub fn equality(&self) -> &C61EqualityChallenges {
        &self.equality
    }

    pub fn fix_terminal_claims(
        self,
        terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
        transcript: &mut Transcript,
    ) -> C61TerminalClaimsFixed {
        transcript.append("c61.terminal_claims", TERMINAL_TRANSCRIPT_BYTES);
        C61TerminalClaimsFixed { binding: self.binding, equality: self.equality, terminal_claims }
    }
}

#[derive(Clone, Debug)]
pub struct C61TerminalClaimsFixed {
    binding: C61StatementBinding,
    equality: C61EqualityChallenges,
    terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
}

impl C61TerminalClaimsFixed {
    pub fn draw_output_challenge(self, transcript: &mut Transcript) -> C61OutputChallengeDrawn {
        C61OutputChallengeDrawn {
            binding: self.binding,
            equality: self.equality,
            terminal_claims: self.terminal_claims,
            output_beta: transcript.challenge_fp2(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct C61OutputChallengeDrawn {
    binding: C61StatementBinding,
    equality: C61EqualityChallenges,
    terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    output_beta: Fp2,
}

impl C61OutputChallengeDrawn {
    pub fn output_beta(&self) -> Fp2 {
        self.output_beta
    }

    pub fn terminal_claims(&self) -> &[Fp2; C61_TERMINAL_CLAIMS] {
        &self.terminal_claims
    }

    pub fn fix_adjoint_root(
        self,
        adjoint_root: [u8; 32],
        transcript: &mut Transcript,
    ) -> Result<C61AdjointFixed> {
        if adjoint_root == [0; 32] {
            return Err(C61PublicCompressionError::new("zero C6.1 adjoint root"));
        }
        transcript.append("c61.adjoint_root", ADJOINT_ROOT_TRANSCRIPT_BYTES);
        Ok(C61AdjointFixed {
            binding: self.binding,
            equality: self.equality,
            terminal_claims: self.terminal_claims,
            output_beta: self.output_beta,
            adjoint_root,
        })
    }
}

#[derive(Clone, Debug)]
pub struct C61AdjointFixed {
    binding: C61StatementBinding,
    equality: C61EqualityChallenges,
    terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    output_beta: Fp2,
    adjoint_root: [u8; 32],
}

impl C61AdjointFixed {
    pub fn draw_runtime_challenges(self, transcript: &mut Transcript) -> C61ReadyPublicProof {
        let challenges = C61ReadyChallenges {
            equality: self.equality,
            output_beta: self.output_beta,
            runtime_points: array::from_fn(|_| array::from_fn(|_| transcript.challenge_fp2())),
        };
        C61ReadyPublicProof {
            binding: self.binding,
            terminal_claims: self.terminal_claims,
            adjoint_root: self.adjoint_root,
            challenges,
        }
    }
}

#[derive(Clone, Debug)]
pub struct C61ReadyPublicProof {
    binding: C61StatementBinding,
    terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    adjoint_root: [u8; 32],
    challenges: C61ReadyChallenges,
}

impl C61ReadyPublicProof {
    pub fn binding(&self) -> &C61StatementBinding {
        &self.binding
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.binding.digest()
    }

    pub fn terminal_claims(&self) -> &[Fp2; C61_TERMINAL_CLAIMS] {
        &self.terminal_claims
    }

    pub fn adjoint_root(&self) -> [u8; 32] {
        self.adjoint_root
    }

    pub fn challenges(&self) -> &C61ReadyChallenges {
        &self.challenges
    }
}

/// `eq(point, bits(index))`, with coordinate zero as the least-significant
/// index bit.  The caller supplies canonical zero padding above its live
/// prefix.
pub fn c61_eq_weight(point: &[Fp2], index: usize) -> Result<Fp2> {
    if point.len() >= usize::BITS as usize || index >= (1usize << point.len()) {
        return Err(C61PublicCompressionError::new("C6.1 MLE index lies outside its point domain"));
    }
    Ok(point.iter().enumerate().fold(Fp2::ONE, |weight, (bit, challenge)| {
        let factor = if (index >> bit) & 1 == 0 { Fp2::ONE - *challenge } else { *challenge };
        weight * factor
    }))
}

/// Streaming MLE of a live prefix; all omitted cells in the registered
/// power-of-two domain are canonical zero.
pub fn c61_mle_eval_prefix(values: &[Fp2], point: &[Fp2]) -> Result<Fp2> {
    if point.len() >= usize::BITS as usize || values.len() > (1usize << point.len()) {
        return Err(C61PublicCompressionError::new("C6.1 MLE live prefix exceeds its domain"));
    }
    values
        .iter()
        .enumerate()
        .try_fold(Fp2::ZERO, |sum, (index, value)| Ok(sum + c61_eq_weight(point, index)? * *value))
}

/// Independent fold reference used by scaled differentials.
pub fn c61_mle_eval_fold_reference(values: &[Fp2], point: &[Fp2]) -> Result<Fp2> {
    if point.len() >= usize::BITS as usize || values.len() > (1usize << point.len()) {
        return Err(C61PublicCompressionError::new("C6.1 MLE fold reference exceeds its domain"));
    }
    let mut layer = vec![Fp2::ZERO; 1usize << point.len()];
    layer[..values.len()].copy_from_slice(values);
    for challenge in point {
        for index in 0..layer.len() / 2 {
            let low = layer[2 * index];
            let high = layer[2 * index + 1];
            layer[index] = low + (high - low) * *challenge;
        }
        layer.truncate(layer.len() / 2);
    }
    Ok(layer[0])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C61LinearOp {
    Source {
        ordinal: u32,
    },
    /// Response-local public input selected from the canonical runtime
    /// stream.  Its value is never embedded in the provider-global plan.
    PublicInput {
        runtime: u32,
    },
    Zero,
    Add {
        left: u32,
        right: u32,
    },
    Sub {
        left: u32,
        right: u32,
    },
    Scale {
        input: u32,
        runtime: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparsePlan {
    operations: Vec<C61LinearOp>,
    terminals: [u32; C61_TERMINAL_CLAIMS],
}

impl C61SparsePlan {
    pub fn new(
        operations: Vec<C61LinearOp>,
        terminals: [u32; C61_TERMINAL_CLAIMS],
        source_len: usize,
        runtime_len: usize,
    ) -> Result<Self> {
        if operations.is_empty() {
            return Err(C61PublicCompressionError::new("empty C6.1 sparse plan"));
        }
        for (index, operation) in operations.iter().enumerate() {
            let prior = |operand: u32| -> Result<()> {
                if usize::try_from(operand).ok().is_none_or(|value| value >= index) {
                    Err(C61PublicCompressionError::new(
                        "C6.1 sparse plan is not strictly topological",
                    ))
                } else {
                    Ok(())
                }
            };
            match operation {
                C61LinearOp::Source { ordinal } => {
                    if usize::try_from(*ordinal).ok().is_none_or(|value| value >= source_len) {
                        return Err(C61PublicCompressionError::new(
                            "C6.1 sparse plan source ordinal is out of range",
                        ));
                    }
                }
                C61LinearOp::PublicInput { runtime } => {
                    if usize::try_from(*runtime).ok().is_none_or(|value| value >= runtime_len) {
                        return Err(C61PublicCompressionError::new(
                            "C6.1 sparse plan public-input runtime index is out of range",
                        ));
                    }
                }
                C61LinearOp::Zero => {}
                C61LinearOp::Add { left, right } | C61LinearOp::Sub { left, right } => {
                    prior(*left)?;
                    prior(*right)?;
                }
                C61LinearOp::Scale { input, runtime } => {
                    prior(*input)?;
                    if usize::try_from(*runtime).ok().is_none_or(|value| value >= runtime_len) {
                        return Err(C61PublicCompressionError::new(
                            "C6.1 sparse plan runtime index is out of range",
                        ));
                    }
                }
            }
        }
        if terminals.iter().any(|terminal| {
            usize::try_from(*terminal).ok().is_none_or(|value| value >= operations.len())
        }) {
            return Err(C61PublicCompressionError::new(
                "C6.1 sparse plan terminal is out of range",
            ));
        }
        Ok(Self { operations, terminals })
    }

    pub fn operations(&self) -> &[C61LinearOp] {
        &self.operations
    }

    pub fn terminals(&self) -> &[u32; C61_TERMINAL_CLAIMS] {
        &self.terminals
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"volta/c6.1/sparse-plan/v1");
        hasher.update(&(self.operations.len() as u64).to_le_bytes());
        for operation in &self.operations {
            match operation {
                C61LinearOp::Source { ordinal } => {
                    hasher.update(&[0]);
                    hasher.update(&ordinal.to_le_bytes());
                }
                C61LinearOp::PublicInput { runtime } => {
                    hasher.update(&[1]);
                    hasher.update(&runtime.to_le_bytes());
                }
                C61LinearOp::Zero => {
                    hasher.update(&[2]);
                }
                C61LinearOp::Add { left, right } => {
                    hasher.update(&[3]);
                    hasher.update(&left.to_le_bytes());
                    hasher.update(&right.to_le_bytes());
                }
                C61LinearOp::Sub { left, right } => {
                    hasher.update(&[4]);
                    hasher.update(&left.to_le_bytes());
                    hasher.update(&right.to_le_bytes());
                }
                C61LinearOp::Scale { input, runtime } => {
                    hasher.update(&[5]);
                    hasher.update(&input.to_le_bytes());
                    hasher.update(&runtime.to_le_bytes());
                }
            }
        }
        for terminal in self.terminals {
            hasher.update(&terminal.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn evaluate(&self, sources: &[Fp2], runtime: &[Fp2]) -> Result<Vec<Fp2>> {
        let mut values = Vec::with_capacity(self.operations.len());
        for operation in &self.operations {
            let value = match *operation {
                C61LinearOp::Source { ordinal } => {
                    *sources.get(index(ordinal)?).ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 source witness is shorter than its fixed sparse plan",
                        )
                    })?
                }
                C61LinearOp::PublicInput { runtime: runtime_index } => {
                    *runtime.get(index(runtime_index)?).ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 runtime is shorter than its public-input plan",
                        )
                    })?
                }
                C61LinearOp::Zero => Fp2::ZERO,
                C61LinearOp::Add { left, right } => values[index(left)?] + values[index(right)?],
                C61LinearOp::Sub { left, right } => values[index(left)?] - values[index(right)?],
                C61LinearOp::Scale { input, runtime: runtime_index } => {
                    let scalar = *runtime.get(index(runtime_index)?).ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 runtime shorter than its fixed sparse plan",
                        )
                    })?;
                    values[index(input)?] * scalar
                }
            };
            values.push(value);
        }
        Ok(values)
    }

    pub fn terminal_claims(&self, values: &[Fp2]) -> Result<[Fp2; C61_TERMINAL_CLAIMS]> {
        if values.len() != self.operations.len() {
            return Err(C61PublicCompressionError::new(
                "C6.1 value vector differs from its sparse plan",
            ));
        }
        Ok(array::from_fn(|claim| {
            values[index(self.terminals[claim]).expect("validated terminal index")]
        }))
    }

    pub fn output_injection(&self, beta: Fp2) -> Vec<Fp2> {
        let mut output = vec![Fp2::ZERO; self.operations.len()];
        let mut power = Fp2::ONE;
        for terminal in self.terminals {
            output[index(terminal).expect("validated terminal index")] += power;
            power = power * beta;
        }
        output
    }

    pub fn reverse_adjoint(&self, runtime: &[Fp2], output: &[Fp2]) -> Result<Vec<Fp2>> {
        if output.len() != self.operations.len() {
            return Err(C61PublicCompressionError::new(
                "C6.1 output injection differs from its sparse plan",
            ));
        }
        let mut adjoint = output.to_vec();
        for node in (0..self.operations.len()).rev() {
            let weight = adjoint[node];
            match self.operations[node] {
                C61LinearOp::Source { .. }
                | C61LinearOp::PublicInput { .. }
                | C61LinearOp::Zero => {}
                C61LinearOp::Add { left, right } => {
                    adjoint[index(left)?] += weight;
                    adjoint[index(right)?] += weight;
                }
                C61LinearOp::Sub { left, right } => {
                    adjoint[index(left)?] += weight;
                    adjoint[index(right)?] += Fp2::ZERO - weight;
                }
                C61LinearOp::Scale { input, runtime: runtime_index } => {
                    let scalar = *runtime.get(index(runtime_index)?).ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 runtime shorter than its fixed sparse plan",
                        )
                    })?;
                    adjoint[index(input)?] += weight * scalar;
                }
            }
        }
        Ok(adjoint)
    }

    pub fn source_boundary(
        &self,
        sources: &[Fp2],
        runtime: &[Fp2],
        adjoint: &[Fp2],
    ) -> Result<Fp2> {
        if adjoint.len() != self.operations.len() {
            return Err(C61PublicCompressionError::new(
                "C6.1 adjoint differs from its sparse plan",
            ));
        }
        self.operations.iter().zip(adjoint).try_fold(Fp2::ZERO, |sum, (operation, weight)| {
            match operation {
                C61LinearOp::Source { ordinal } => sources
                    .get(index(*ordinal)?)
                    .copied()
                    .map(|value| sum + *weight * value)
                    .ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 source witness is shorter than its fixed sparse plan",
                        )
                    }),
                C61LinearOp::PublicInput { runtime: runtime_index } => runtime
                    .get(index(*runtime_index)?)
                    .copied()
                    .map(|value| sum + *weight * value)
                    .ok_or_else(|| {
                        C61PublicCompressionError::new(
                            "C6.1 runtime is shorter than its public-input boundary",
                        )
                    }),
                _ => Ok(sum),
            }
        })
    }

    pub fn verify_adjoint_recurrence(
        &self,
        runtime: &[Fp2],
        output: &[Fp2],
        adjoint: &[Fp2],
    ) -> Result<()> {
        let expected = self.reverse_adjoint(runtime, output)?;
        if expected != adjoint {
            return Err(C61PublicCompressionError::new("C6.1 sparse adjoint recurrence failed"));
        }
        Ok(())
    }
}

pub fn c61_fp2_vector_root(domain: &[u8], values: &[Fp2]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta/c6.1/fp2-vector/v1");
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(&(values.len() as u64).to_le_bytes());
    for value in values {
        update_fp2(&mut hasher, *value);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61ArithmeticFrame {
    pub statement_digest: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub adjoint_root: [u8; 32],
    pub terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    pub runtime_evaluations: [Fp2; C61_RUNTIME_FINGERPRINTS],
    pub source_boundary: Fp2,
}

impl C61ArithmeticFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(C61_ARITHMETIC_FRAME_BYTES);
        bytes.extend_from_slice(&C61_ARITHMETIC_MAGIC);
        bytes.extend_from_slice(&C61_ARITHMETIC_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        bytes.extend_from_slice(&self.challenge_digest);
        bytes.extend_from_slice(&self.adjoint_root);
        for claim in self.terminal_claims {
            encode_fp2(&mut bytes, claim);
        }
        for evaluation in self.runtime_evaluations {
            encode_fp2(&mut bytes, evaluation);
        }
        encode_fp2(&mut bytes, self.source_boundary);
        bytes.extend_from_slice(&domain_digest(b"volta/c6.1/arithmetic-frame/v4", &bytes));
        debug_assert_eq!(bytes.len(), C61_ARITHMETIC_FRAME_BYTES);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C61_ARITHMETIC_FRAME_BYTES {
            return Err(C61PublicCompressionError::new(
                "C6RSC4 strict arithmetic frame length mismatch",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C61_ARITHMETIC_MAGIC
            || cursor.u16()? != C61_ARITHMETIC_VERSION
            || cursor.u16()? != 0
        {
            return Err(C61PublicCompressionError::new("C6RSC4 arithmetic frame header mismatch"));
        }
        let statement_digest = cursor.digest()?;
        let challenge_digest = cursor.digest()?;
        let adjoint_root = cursor.digest()?;
        let terminal_claims = try_array_from_fn(|_| cursor.fp2())?;
        let runtime_evaluations = try_array_from_fn(|_| cursor.fp2())?;
        let source_boundary = cursor.fp2()?;
        let digest_offset = cursor.position();
        let digest = cursor.digest()?;
        cursor.finish()?;
        if digest != domain_digest(b"volta/c6.1/arithmetic-frame/v4", &bytes[..digest_offset]) {
            return Err(C61PublicCompressionError::new("C6RSC4 arithmetic frame digest mismatch"));
        }
        let frame = Self {
            statement_digest,
            challenge_digest,
            adjoint_root,
            terminal_claims,
            runtime_evaluations,
            source_boundary,
        };
        if frame.encode() != bytes {
            return Err(C61PublicCompressionError::new("noncanonical C6RSC4 arithmetic frame"));
        }
        Ok(frame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicArgument {
    statement_digest: [u8; 32],
    native_chains: [Vec<u8>; C61_NATIVE_CHAIN_COUNT],
    arithmetic: Vec<u8>,
}

impl C61PublicArgument {
    pub fn new(
        statement_digest: [u8; 32],
        native_chains: [Vec<u8>; C61_NATIVE_CHAIN_COUNT],
        arithmetic: Vec<u8>,
    ) -> Result<Self> {
        let argument = Self { statement_digest, native_chains, arithmetic };
        argument.validate()?;
        Ok(argument)
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn native_chains(&self) -> &[Vec<u8>; C61_NATIVE_CHAIN_COUNT] {
        &self.native_chains
    }

    pub fn arithmetic(&self) -> &[u8] {
        &self.arithmetic
    }

    pub fn encoded_len(&self) -> Result<usize> {
        self.validate()?;
        C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
            .checked_add(self.native_chains.iter().map(Vec::len).sum::<usize>())
            .and_then(|value| value.checked_add(self.arithmetic.len()))
            .ok_or_else(|| C61PublicCompressionError::new("C6PA1 length overflows"))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let encoded_len = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&C61_PUBLIC_ARGUMENT_MAGIC);
        bytes.extend_from_slice(&C61_PUBLIC_ARGUMENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C61_PUBLIC_ARGUMENT_COMPONENTS as u16).to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for (id, payload) in C61NativeChainId::ordered().into_iter().zip(&self.native_chains) {
            encode_component_header(&mut bytes, id.kind_code(), id.repetition, payload)?;
            bytes.extend_from_slice(payload);
        }
        encode_component_header(&mut bytes, 4, 0, &self.arithmetic)?;
        bytes.extend_from_slice(&self.arithmetic);
        bytes.extend_from_slice(&domain_digest(b"volta/c6.1/public-argument/v1", &bytes));
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > C61_PUBLIC_ARGUMENT_V1_STRICT_MAX_BYTES {
            return Err(C61PublicCompressionError::new("C6PA1 public argument exceeds its cap"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C61_PUBLIC_ARGUMENT_MAGIC
            || cursor.u16()? != C61_PUBLIC_ARGUMENT_VERSION
            || usize::from(cursor.u16()?) != C61_PUBLIC_ARGUMENT_COMPONENTS
        {
            return Err(C61PublicCompressionError::new(
                "C6PA1 header/version/component census mismatch",
            ));
        }
        let statement_digest = cursor.digest()?;
        let mut native_chains: [Vec<u8>; C61_NATIVE_CHAIN_COUNT] = array::from_fn(|_| Vec::new());
        for (index, expected) in C61NativeChainId::ordered().into_iter().enumerate() {
            let (kind, repetition, payload_len, digest) = decode_component_header(&mut cursor)?;
            if kind != expected.kind_code() || repetition != expected.repetition {
                return Err(C61PublicCompressionError::new(
                    "C6PA1 native chain kind/order mismatch",
                ));
            }
            if payload_len > C61_NATIVE_CHAIN_MAX_BYTES {
                return Err(C61PublicCompressionError::new("C6PA1 native chain exceeds its cap"));
            }
            let payload = cursor.take(payload_len)?;
            if digest != component_digest(kind, repetition, payload) {
                return Err(C61PublicCompressionError::new("C6PA1 native chain digest mismatch"));
            }
            native_chains[index] = payload.to_vec();
        }
        let (kind, repetition, arithmetic_len, arithmetic_digest) =
            decode_component_header(&mut cursor)?;
        if kind != 4 || repetition != 0 || arithmetic_len != C61_ARITHMETIC_FRAME_BYTES {
            return Err(C61PublicCompressionError::new(
                "C6PA1 arithmetic component header/length mismatch",
            ));
        }
        let arithmetic = cursor.take(arithmetic_len)?.to_vec();
        if arithmetic_digest != component_digest(kind, repetition, &arithmetic) {
            return Err(C61PublicCompressionError::new(
                "C6PA1 arithmetic component digest mismatch",
            ));
        }
        let digest_offset = cursor.position();
        let digest = cursor.digest()?;
        cursor.finish()?;
        if digest != domain_digest(b"volta/c6.1/public-argument/v1", &bytes[..digest_offset]) {
            return Err(C61PublicCompressionError::new("C6PA1 outer digest mismatch"));
        }
        let argument = Self::new(statement_digest, native_chains, arithmetic)?;
        if argument.encode()?.as_slice() != bytes {
            return Err(C61PublicCompressionError::new("noncanonical C6PA1 public argument"));
        }
        Ok(argument)
    }

    fn validate(&self) -> Result<()> {
        if self.statement_digest == [0; 32] {
            return Err(C61PublicCompressionError::new("C6PA1 has a zero statement digest"));
        }
        if self.native_chains.iter().any(Vec::is_empty) {
            return Err(C61PublicCompressionError::new("C6PA1 has an empty native chain"));
        }
        if self.native_chains.iter().any(|chain| chain.len() > C61_NATIVE_CHAIN_MAX_BYTES) {
            return Err(C61PublicCompressionError::new("C6PA1 native chain exceeds its cap"));
        }
        if self.arithmetic.len() != C61_ARITHMETIC_FRAME_BYTES {
            return Err(C61PublicCompressionError::new("C6PA1 arithmetic payload length mismatch"));
        }
        C61ArithmeticFrame::decode(&self.arithmetic)?;
        let encoded = C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES
            .checked_add(self.native_chains.iter().map(Vec::len).sum::<usize>())
            .and_then(|value| value.checked_add(self.arithmetic.len()))
            .ok_or_else(|| C61PublicCompressionError::new("C6PA1 length overflows"))?;
        if encoded > C61_PUBLIC_ARGUMENT_V1_STRICT_MAX_BYTES {
            return Err(C61PublicCompressionError::new("C6PA1 public argument exceeds its cap"));
        }
        Ok(())
    }
}

/// Wire-neutral outer semantic version for the generic joint native bridge.
/// All component headers and payloads retain their exact widths; only the
/// outer magic/version and domain-separated trailer differ from C6PA1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61JointPublicArgument {
    inner: C61PublicArgument,
}

impl C61JointPublicArgument {
    pub fn new(
        statement_digest: [u8; 32],
        native_chains: [Vec<u8>; C61_NATIVE_CHAIN_COUNT],
        arithmetic: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self { inner: C61PublicArgument::new(statement_digest, native_chains, arithmetic)? })
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.inner.statement_digest()
    }

    pub fn native_chains(&self) -> &[Vec<u8>; C61_NATIVE_CHAIN_COUNT] {
        self.inner.native_chains()
    }

    pub fn arithmetic(&self) -> &[u8] {
        self.inner.arithmetic()
    }

    pub fn encoded_len(&self) -> Result<usize> {
        self.inner.encoded_len()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.inner.encode()?;
        let digest_offset = bytes.len() - OUTER_DIGEST_BYTES;
        bytes[..8].copy_from_slice(&C61_JOINT_PUBLIC_ARGUMENT_MAGIC);
        bytes[8..10].copy_from_slice(&C61_JOINT_PUBLIC_ARGUMENT_VERSION.to_le_bytes());
        let digest = domain_digest(b"volta/c6.1/public-argument/v2-joint", &bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < OUTER_HEADER_BYTES + OUTER_DIGEST_BYTES
            || bytes[..8] != C61_JOINT_PUBLIC_ARGUMENT_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed C6PA2 version"))
                != C61_JOINT_PUBLIC_ARGUMENT_VERSION
        {
            return Err(C61PublicCompressionError::new("C6PA2 header/version mismatch"));
        }
        let digest_offset = bytes.len() - OUTER_DIGEST_BYTES;
        if bytes[digest_offset..]
            != domain_digest(b"volta/c6.1/public-argument/v2-joint", &bytes[..digest_offset])
        {
            return Err(C61PublicCompressionError::new("C6PA2 outer digest mismatch"));
        }
        let mut ordinary = bytes.to_vec();
        ordinary[..8].copy_from_slice(&C61_PUBLIC_ARGUMENT_MAGIC);
        ordinary[8..10].copy_from_slice(&C61_PUBLIC_ARGUMENT_VERSION.to_le_bytes());
        let digest = domain_digest(b"volta/c6.1/public-argument/v1", &ordinary[..digest_offset]);
        ordinary[digest_offset..].copy_from_slice(&digest);
        let argument = Self { inner: C61PublicArgument::decode(&ordinary)? };
        if argument.encode()?.as_slice() != bytes {
            return Err(C61PublicCompressionError::new("noncanonical C6PA2 public argument"));
        }
        Ok(argument)
    }
}

pub fn c61_joint_public_statement_digest(
    base_statement_digest: [u8; 32],
    native_target_profile_digest: [u8; 32],
    body_schedule_digest: [u8; 32],
    compiler_functional_digest: [u8; 32],
) -> Result<[u8; 32]> {
    if [
        base_statement_digest,
        native_target_profile_digest,
        body_schedule_digest,
        compiler_functional_digest,
    ]
    .contains(&[0; 32])
    {
        return Err(C61PublicCompressionError::new("C6PA2 joint statement contains a zero digest"));
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/joint-public-statement/v2");
    hasher.update(&base_statement_digest);
    hasher.update(&native_target_profile_digest);
    hasher.update(&body_schedule_digest);
    hasher.update(&compiler_functional_digest);
    Ok(*hasher.finalize().as_bytes())
}

/// Explicit backend boundary.  A production implementation must verify the
/// native HVZK proof represented by `payload`; the outer codec never treats a
/// digest or successful parse as proof acceptance.  The mutable verifier
/// transcript is load-bearing: an interactive backend must append each
/// prover message before drawing the challenge for that round.
pub trait C61NativeBackendVerifier {
    fn verify_chain(
        &self,
        id: C61NativeChainId,
        statement_digest: [u8; 32],
        arithmetic_digest: [u8; 32],
        payload: &[u8],
        transcript: &mut Transcript,
    ) -> Result<()>;
}

pub fn verify_c61_scaled_public_argument<B: C61NativeBackendVerifier>(
    ready: &C61ReadyPublicProof,
    plan: &C61SparsePlan,
    sources: &[Fp2],
    runtime: &[Fp2],
    argument: &C61PublicArgument,
    backend: &B,
    transcript: &mut Transcript,
) -> Result<C61ArithmeticFrame> {
    let statement_digest = ready.statement_digest();
    if argument.statement_digest != statement_digest {
        return Err(C61PublicCompressionError::new(
            "C6PA1 statement digest differs from interactive typestate",
        ));
    }
    if plan.digest() != ready.binding.plan_digest {
        return Err(C61PublicCompressionError::new(
            "C6PA1 sparse plan digest differs from statement",
        ));
    }
    let source_root = c61_fp2_vector_root(b"compiler-source", sources);
    if source_root != ready.binding.compiler_source_root {
        return Err(C61PublicCompressionError::new(
            "C6PA1 compiler source root differs from statement",
        ));
    }
    let runtime_root = c61_fp2_vector_root(b"runtime", runtime);
    if runtime_root != ready.binding.runtime_root {
        return Err(C61PublicCompressionError::new("C6PA1 runtime root differs from statement"));
    }
    let frame = C61ArithmeticFrame::decode(&argument.arithmetic)?;
    let arithmetic_digest = component_digest(4, 0, &argument.arithmetic);
    if frame.statement_digest != statement_digest
        || frame.challenge_digest != ready.challenges.digest(statement_digest)
        || frame.adjoint_root != ready.adjoint_root
        || frame.terminal_claims != ready.terminal_claims
    {
        return Err(C61PublicCompressionError::new(
            "C6RSC4 arithmetic frame differs from interactive typestate",
        ));
    }
    let values = plan.evaluate(sources, runtime)?;
    if plan.terminal_claims(&values)? != frame.terminal_claims {
        return Err(C61PublicCompressionError::new(
            "C6RSC4 terminal claims differ from sparse compiler",
        ));
    }
    let runtime_evaluations = try_array_from_fn(|index| {
        c61_mle_eval_prefix(runtime, &ready.challenges.runtime_points[index])
    })?;
    if runtime_evaluations != frame.runtime_evaluations {
        return Err(C61PublicCompressionError::new("C6RSC4 runtime fingerprints differ"));
    }
    let output = plan.output_injection(ready.challenges.output_beta);
    let adjoint = plan.reverse_adjoint(runtime, &output)?;
    plan.verify_adjoint_recurrence(runtime, &output, &adjoint)?;
    let adjoint_root = c61_fp2_vector_root(b"adjoint", &adjoint);
    if adjoint_root != frame.adjoint_root {
        return Err(C61PublicCompressionError::new("C6RSC4 adjoint root differs"));
    }
    let source_boundary = plan.source_boundary(sources, runtime, &adjoint)?;
    let terminal_boundary = frame
        .terminal_claims
        .iter()
        .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
            (sum + power * *claim, power * ready.challenges.output_beta)
        })
        .0;
    if source_boundary != frame.source_boundary || terminal_boundary != source_boundary {
        return Err(C61PublicCompressionError::new(
            "C6RSC4 sparse-adjoint source/terminal boundary mismatch",
        ));
    }
    for (id, payload) in C61NativeChainId::ordered().into_iter().zip(&argument.native_chains) {
        backend.verify_chain(id, statement_digest, arithmetic_digest, payload, transcript)?;
    }
    Ok(frame)
}

pub fn build_c61_scaled_arithmetic_frame(
    ready: &C61ReadyPublicProof,
    plan: &C61SparsePlan,
    sources: &[Fp2],
    runtime: &[Fp2],
) -> Result<C61ArithmeticFrame> {
    if plan.digest() != ready.binding.plan_digest
        || c61_fp2_vector_root(b"compiler-source", sources) != ready.binding.compiler_source_root
        || c61_fp2_vector_root(b"runtime", runtime) != ready.binding.runtime_root
    {
        return Err(C61PublicCompressionError::new("C6RSC4 prover plan/runtime binding mismatch"));
    }
    let values = plan.evaluate(sources, runtime)?;
    let terminal_claims = plan.terminal_claims(&values)?;
    if terminal_claims != ready.terminal_claims {
        return Err(C61PublicCompressionError::new(
            "C6RSC4 prover terminal claims changed after output challenge",
        ));
    }
    let output = plan.output_injection(ready.challenges.output_beta);
    let adjoint = plan.reverse_adjoint(runtime, &output)?;
    let adjoint_root = c61_fp2_vector_root(b"adjoint", &adjoint);
    if adjoint_root != ready.adjoint_root {
        return Err(C61PublicCompressionError::new(
            "C6RSC4 prover adjoint root differs from fixed root",
        ));
    }
    Ok(C61ArithmeticFrame {
        statement_digest: ready.statement_digest(),
        challenge_digest: ready.challenges.digest(ready.statement_digest()),
        adjoint_root,
        terminal_claims,
        runtime_evaluations: try_array_from_fn(|index| {
            c61_mle_eval_prefix(runtime, &ready.challenges.runtime_points[index])
        })?,
        source_boundary: plan.source_boundary(sources, runtime, &adjoint)?,
    })
}

/// Build the wire-neutral C6RSC4-v5 frame from the exact production
/// challenge typestate. The legacy field names retain the fixed codec width:
/// `adjoint_root` is the C6TFR1 terminal relation root and
/// `source_boundary` is its post-beta functional fold.
pub fn build_c61_production_arithmetic_frame(
    ready: &C61ReadyPublicProof,
    outer_statement_digest: [u8; 32],
    canonical_runtime: &[Fp2],
    functional_fold: Fp2,
) -> Result<C61ArithmeticFrame> {
    if outer_statement_digest == [0; 32] {
        return Err(C61PublicCompressionError::new(
            "C6RSC4-v5 outer statement digest is zero",
        ));
    }
    let expected_fold = ready
        .terminal_claims
        .iter()
        .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
            (sum + power * *claim, power * ready.challenges.output_beta)
        })
        .0;
    if expected_fold != functional_fold {
        return Err(C61PublicCompressionError::new(
            "C6RSC4-v5 functional fold differs from the fixed terminal claims",
        ));
    }
    Ok(C61ArithmeticFrame {
        statement_digest: outer_statement_digest,
        challenge_digest: ready.challenges.digest(ready.statement_digest()),
        adjoint_root: ready.adjoint_root,
        terminal_claims: ready.terminal_claims,
        runtime_evaluations: try_array_from_fn(|index| {
            c61_mle_eval_prefix(canonical_runtime, &ready.challenges.runtime_points[index])
        })?,
        source_boundary: functional_fold,
    })
}

/// Reconstruct every public C6RSC4-v5 field before invoking the native and
/// compiler verifiers. This is a semantic check, not merely a strict-codec
/// round trip.
pub fn verify_c61_production_arithmetic_frame(
    ready: &C61ReadyPublicProof,
    outer_statement_digest: [u8; 32],
    canonical_runtime: &[Fp2],
    frame: &C61ArithmeticFrame,
) -> Result<()> {
    let expected = build_c61_production_arithmetic_frame(
        ready,
        outer_statement_digest,
        canonical_runtime,
        frame.source_boundary,
    )?;
    if &expected != frame {
        return Err(C61PublicCompressionError::new(
            "C6RSC4-v5 differs from the reconstructed production typestate",
        ));
    }
    Ok(())
}

fn index(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| C61PublicCompressionError::new("C6.1 index exceeds usize"))
}

fn try_array_from_fn<T, const N: usize>(
    mut function: impl FnMut(usize) -> Result<T>,
) -> Result<[T; N]> {
    let mut values = Vec::with_capacity(N);
    for index in 0..N {
        values.push(function(index)?);
    }
    values
        .try_into()
        .map_err(|_| C61PublicCompressionError::new("C6.1 internal array length mismatch"))
}

fn update_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

fn update_challenge_family<const STREAMS: usize, const DIMENSION: usize>(
    hasher: &mut blake3::Hasher,
    domain: &[u8],
    points: &[[Fp2; DIMENSION]; STREAMS],
) {
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(&(STREAMS as u64).to_le_bytes());
    hasher.update(&(DIMENSION as u64).to_le_bytes());
    for (stream, point) in points.iter().enumerate() {
        hasher.update(&(stream as u64).to_le_bytes());
        for value in point {
            update_fp2(hasher, *value);
        }
    }
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn component_digest(kind: u16, repetition: u8, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"volta/c6.1/component/v1");
    hasher.update(&kind.to_le_bytes());
    hasher.update(&[repetition]);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn encode_component_header(
    bytes: &mut Vec<u8>,
    kind: u16,
    repetition: u8,
    payload: &[u8],
) -> Result<()> {
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.push(repetition);
    bytes.push(0);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| C61PublicCompressionError::new("C6PA1 component exceeds u32"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&component_digest(kind, repetition, payload));
    Ok(())
}

fn decode_component_header(cursor: &mut Cursor<'_>) -> Result<(u16, u8, usize, [u8; 32])> {
    let kind = cursor.u16()?;
    let repetition = cursor.u8()?;
    if cursor.u8()? != 0 {
        return Err(C61PublicCompressionError::new("C6PA1 component reserved byte is nonzero"));
    }
    let len = usize::try_from(cursor.u32()?)
        .map_err(|_| C61PublicCompressionError::new("C6PA1 component exceeds usize"))?;
    let digest = cursor.digest()?;
    Ok((kind, repetition, len, digest))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C61PublicCompressionError::new("C6PA1 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C61PublicCompressionError::new("truncated C6PA1 encoding"))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C61PublicCompressionError::new("trailing C6PA1 bytes"));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32> {
        let mut raw = [0; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let mut c0 = [0; 8];
        let mut c1 = [0; 8];
        c0.copy_from_slice(self.take(8)?);
        c1.copy_from_slice(self.take(8)?);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C61PublicCompressionError::new("noncanonical C6PA1 field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct DiagnosticDigestBackend;

    impl DiagnosticDigestBackend {
        fn first_message(
            id: C61NativeChainId,
            statement_digest: [u8; 32],
            arithmetic_digest: [u8; 32],
        ) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"diagnostic-only/c6.1/native-chain/first-message");
            hasher.update(&id.kind_code().to_le_bytes());
            hasher.update(&[id.repetition]);
            hasher.update(&statement_digest);
            hasher.update(&arithmetic_digest);
            *hasher.finalize().as_bytes()
        }

        fn prove(
            id: C61NativeChainId,
            statement_digest: [u8; 32],
            arithmetic_digest: [u8; 32],
            transcript: &mut Transcript,
        ) -> Vec<u8> {
            let first_message = Self::first_message(id, statement_digest, arithmetic_digest);
            transcript.append("c61.diagnostic_native.first_message", 32);
            let challenge = transcript.challenge_fp2();
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"diagnostic-only/c6.1/native-chain/response");
            hasher.update(&id.kind_code().to_le_bytes());
            hasher.update(&[id.repetition]);
            hasher.update(&statement_digest);
            hasher.update(&arithmetic_digest);
            hasher.update(&first_message);
            update_fp2(&mut hasher, challenge);
            let mut payload = first_message.to_vec();
            payload.extend_from_slice(hasher.finalize().as_bytes());
            payload
        }
    }

    impl C61NativeBackendVerifier for DiagnosticDigestBackend {
        fn verify_chain(
            &self,
            id: C61NativeChainId,
            statement_digest: [u8; 32],
            arithmetic_digest: [u8; 32],
            payload: &[u8],
            transcript: &mut Transcript,
        ) -> Result<()> {
            if payload.len() != 64
                || payload[..32] != Self::first_message(id, statement_digest, arithmetic_digest)
            {
                return Err(C61PublicCompressionError::new(
                    "diagnostic native-chain first message mismatch",
                ));
            }
            transcript.append("c61.diagnostic_native.first_message", 32);
            let challenge = transcript.challenge_fp2();
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"diagnostic-only/c6.1/native-chain/response");
            hasher.update(&id.kind_code().to_le_bytes());
            hasher.update(&[id.repetition]);
            hasher.update(&statement_digest);
            hasher.update(&arithmetic_digest);
            hasher.update(&payload[..32]);
            update_fp2(&mut hasher, challenge);
            if payload[32..] != *hasher.finalize().as_bytes() {
                return Err(C61PublicCompressionError::new(
                    "diagnostic native-chain response mismatch",
                ));
            }
            Ok(())
        }
    }

    fn f(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(7).wrapping_add(3)))
    }

    fn scaled_fixture() -> (C61SparsePlan, Vec<Fp2>, Vec<Fp2>) {
        let sources = vec![f(13), f(17)];
        let runtime = vec![f(19), f(3), f(5), f(7), f(11)];
        let operations = vec![
            C61LinearOp::Source { ordinal: 0 },
            C61LinearOp::Source { ordinal: 1 },
            C61LinearOp::PublicInput { runtime: 0 },
            C61LinearOp::Zero,
            C61LinearOp::Add { left: 0, right: 1 },
            C61LinearOp::Scale { input: 4, runtime: 1 },
            C61LinearOp::Sub { left: 5, right: 2 },
            C61LinearOp::Add { left: 6, right: 3 },
            C61LinearOp::Scale { input: 7, runtime: 2 },
            C61LinearOp::Add { left: 8, right: 0 },
            C61LinearOp::Scale { input: 9, runtime: 3 },
            C61LinearOp::Sub { left: 10, right: 1 },
        ];
        let terminals = array::from_fn(|index| 4 + (index % 8) as u32);
        (
            C61SparsePlan::new(operations, terminals, sources.len(), runtime.len()).unwrap(),
            sources,
            runtime,
        )
    }

    fn binding(plan: &C61SparsePlan, sources: &[Fp2], runtime: &[Fp2]) -> C61StatementBinding {
        C61StatementBinding {
            protocol_digest: [1; 32],
            model_digest: [2; 32],
            quantization_digest: [3; 32],
            plan_digest: plan.digest(),
            parameter_digest: [5; 32],
            setup_manifest_digest: [6; 32],
            connection_id: [7; 32],
            workload_digest: [8; 32],
            public_io_digest: [9; 32],
            retained_transcript_digest: [10; 32],
            retained_wrapper_digest: [11; 32],
            model_root: [12; 32],
            embedding_root: [13; 32],
            compiler_source_root: c61_fp2_vector_root(b"compiler-source", sources),
            runtime_root: c61_fp2_vector_root(b"runtime", runtime),
            predecessor_certificate: [14; 32],
            old_head: [15; 32],
            new_head: [16; 32],
            nonce: [17; 32],
            epoch: 4,
            slot: 2,
            correlation_ranges: [
                C61CorrelationRangeBinding { stage: 41, start: 100, count: 50 },
                C61CorrelationRangeBinding { stage: 42, start: 200, count: 50 },
            ],
        }
    }

    fn ready_from_binding(
        challenge_seed: [u8; 32],
        plan: &C61SparsePlan,
        sources: &[Fp2],
        runtime: &[Fp2],
        binding: C61StatementBinding,
    ) -> (C61ReadyPublicProof, Transcript) {
        let values = plan.evaluate(sources, runtime).unwrap();
        let terminal_claims = plan.terminal_claims(&values).unwrap();
        let mut transcript = Transcript::new(challenge_seed);
        let equality =
            C61RootsFixed::new(binding).unwrap().draw_equality_challenges(&mut transcript);
        assert_eq!(equality.equality().element_count(), 234);
        let output = equality
            .fix_terminal_claims(terminal_claims, &mut transcript)
            .draw_output_challenge(&mut transcript);
        let injection = plan.output_injection(output.output_beta());
        let adjoint = plan.reverse_adjoint(&runtime, &injection).unwrap();
        let adjoint_root = c61_fp2_vector_root(b"adjoint", &adjoint);
        let ready = output
            .fix_adjoint_root(adjoint_root, &mut transcript)
            .unwrap()
            .draw_runtime_challenges(&mut transcript);
        (ready, transcript)
    }

    fn ready_fixture(
        challenge_seed: [u8; 32],
    ) -> (C61ReadyPublicProof, C61SparsePlan, Vec<Fp2>, Vec<Fp2>, Transcript) {
        let (plan, sources, runtime) = scaled_fixture();
        let (ready, transcript) = ready_from_binding(
            challenge_seed,
            &plan,
            &sources,
            &runtime,
            binding(&plan, &sources, &runtime),
        );
        (ready, plan, sources, runtime, transcript)
    }

    fn honest_argument(
        ready: &C61ReadyPublicProof,
        plan: &C61SparsePlan,
        sources: &[Fp2],
        runtime: &[Fp2],
        transcript: &mut Transcript,
    ) -> C61PublicArgument {
        let arithmetic =
            build_c61_scaled_arithmetic_frame(ready, plan, sources, runtime).unwrap().encode();
        let arithmetic_digest = component_digest(4, 0, &arithmetic);
        let native_chains = array::from_fn(|index| {
            DiagnosticDigestBackend::prove(
                C61NativeChainId::ordered()[index],
                ready.statement_digest(),
                arithmetic_digest,
                transcript,
            )
        });
        C61PublicArgument::new(ready.statement_digest(), native_chains, arithmetic).unwrap()
    }

    fn honest_fixture(
        challenge_seed: [u8; 32],
    ) -> (C61ReadyPublicProof, C61SparsePlan, Vec<Fp2>, Vec<Fp2>, C61PublicArgument, Transcript)
    {
        let (prover_ready, plan, sources, runtime, mut prover_transcript) =
            ready_fixture(challenge_seed);
        let argument =
            honest_argument(&prover_ready, &plan, &sources, &runtime, &mut prover_transcript);
        let (ready, verifier_plan, verifier_sources, verifier_runtime, verifier_transcript) =
            ready_fixture(challenge_seed);
        assert_eq!(ready.statement_digest(), prover_ready.statement_digest());
        assert_eq!(ready.challenges(), prover_ready.challenges());
        assert_eq!(verifier_plan, plan);
        assert_eq!(verifier_sources, sources);
        assert_eq!(verifier_runtime, runtime);
        (ready, plan, sources, runtime, argument, verifier_transcript)
    }

    #[test]
    fn direct_mle_matches_independent_fold_with_zero_padding() {
        let values: Vec<_> = (0..37).map(f).collect();
        let point: Vec<_> = (0..6).map(|index| f(index as u64 + 101)).collect();
        assert_eq!(
            c61_mle_eval_prefix(&values, &point).unwrap(),
            c61_mle_eval_fold_reference(&values, &point).unwrap()
        );
        assert!(c61_mle_eval_prefix(&vec![Fp2::ZERO; 65], &point).is_err());
        assert!(c61_eq_weight(&point, 64).is_err());
    }

    #[test]
    fn sparse_adjoint_matches_terminal_batch_and_detects_mutation() {
        let (ready, plan, sources, runtime, _) = ready_fixture([41; 32]);
        let values = plan.evaluate(&sources, &runtime).unwrap();
        let claims = plan.terminal_claims(&values).unwrap();
        let output = plan.output_injection(ready.challenges.output_beta);
        let mut adjoint = plan.reverse_adjoint(&runtime, &output).unwrap();
        let source = plan.source_boundary(&sources, &runtime, &adjoint).unwrap();
        let terminal = claims
            .iter()
            .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
                (sum + power * *claim, power * ready.challenges.output_beta)
            })
            .0;
        assert_eq!(source, terminal);
        plan.verify_adjoint_recurrence(&runtime, &output, &adjoint).unwrap();
        adjoint[0] += Fp2::ONE;
        assert!(plan.verify_adjoint_recurrence(&runtime, &output, &adjoint).is_err());
    }

    #[test]
    fn production_v5_frame_reconstructs_every_public_field() {
        let (ready, _, _, runtime, _) = ready_fixture([0x9A; 32]);
        let functional_fold = ready
            .terminal_claims()
            .iter()
            .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
                (sum + power * *claim, power * ready.challenges().output_beta)
            })
            .0;
        let outer_statement_digest = [0x9B; 32];
        let frame = build_c61_production_arithmetic_frame(
            &ready,
            outer_statement_digest,
            &runtime,
            functional_fold,
        )
        .unwrap();
        verify_c61_production_arithmetic_frame(
            &ready,
            outer_statement_digest,
            &runtime,
            &frame,
        )
        .unwrap();
        assert_eq!(frame.encode().len(), C61_ARITHMETIC_FRAME_BYTES);

        let mut changed = frame.clone();
        changed.runtime_evaluations[0] += Fp2::ONE;
        assert!(verify_c61_production_arithmetic_frame(
            &ready,
            outer_statement_digest,
            &runtime,
            &changed,
        )
        .is_err());
        assert!(build_c61_production_arithmetic_frame(
            &ready,
            outer_statement_digest,
            &runtime,
            functional_fold + Fp2::ONE,
        )
        .is_err());
    }

    #[test]
    fn strict_codec_roundtrip_and_scaled_verification() {
        let (ready, plan, sources, runtime, argument, mut transcript) = honest_fixture([42; 32]);
        let encoded = argument.encode().unwrap();
        assert_eq!(C61_PUBLIC_ARGUMENT_OUTER_FRAMING_BYTES, 356);
        assert_eq!(C61_ARITHMETIC_FRAME_BYTES, 1_212);
        assert_eq!(C61_PUBLIC_ARGUMENT_V1_STRICT_MAX_BYTES, 9_001_568);
        assert_eq!(encoded.len(), 1_952);
        assert!(C61_PUBLIC_ARGUMENT_V1_STRICT_MAX_BYTES < C61_PUBLIC_ARGUMENT_MAX_BYTES);
        assert_eq!(argument.encoded_len().unwrap(), encoded.len());
        let decoded = C61PublicArgument::decode(&encoded).unwrap();
        assert_eq!(decoded, argument);
        let frame = verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &runtime,
            &decoded,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .unwrap();
        assert_eq!(frame.terminal_claims, *ready.terminal_claims());
    }

    #[test]
    fn joint_pa2_codec_is_wire_neutral_and_domain_separated() {
        let (_, _, _, _, ordinary, _) = honest_fixture([0xB4; 32]);
        let joint_digest = c61_joint_public_statement_digest(
            ordinary.statement_digest(),
            [0xB5; 32],
            [0xB6; 32],
            [0xB7; 32],
        )
        .unwrap();
        let joint = C61JointPublicArgument::new(
            joint_digest,
            ordinary.native_chains().clone(),
            ordinary.arithmetic().to_vec(),
        )
        .unwrap();
        let encoded = joint.encode().unwrap();
        assert_eq!(encoded.len(), ordinary.encoded_len().unwrap());
        assert_eq!(C61JointPublicArgument::decode(&encoded).unwrap(), joint);
        assert!(C61PublicArgument::decode(&encoded).is_err());

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = encoded.clone();
        bad_version[8] ^= 1;
        let mut bad_digest = encoded;
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 1;
        for mutation in [bad_magic, bad_version, bad_digest] {
            assert!(C61JointPublicArgument::decode(&mutation).is_err());
        }
        assert!(c61_joint_public_statement_digest([0; 32], [1; 32], [2; 32], [3; 32]).is_err());
        assert_ne!(
            joint_digest,
            c61_joint_public_statement_digest(
                ordinary.statement_digest(),
                [0xB6; 32],
                [0xB5; 32],
                [0xB7; 32],
            )
            .unwrap(),
        );
    }

    #[test]
    fn codec_and_seam_mutations_fail_closed() {
        let (ready, plan, sources, runtime, argument, _) = honest_fixture([43; 32]);
        let encoded = argument.encode().unwrap();

        let mut cases = Vec::new();
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        cases.push(bad_magic);
        let mut bad_version = encoded.clone();
        bad_version[8] ^= 1;
        cases.push(bad_version);
        let mut bad_order = encoded.clone();
        bad_order[OUTER_HEADER_BYTES] ^= 1;
        cases.push(bad_order);
        let mut bad_reserved = encoded.clone();
        bad_reserved[OUTER_HEADER_BYTES + 3] = 1;
        cases.push(bad_reserved);
        let mut bad_payload = encoded.clone();
        bad_payload[OUTER_HEADER_BYTES + COMPONENT_HEADER_BYTES] ^= 1;
        cases.push(bad_payload);
        let mut trailing = encoded.clone();
        trailing.push(0);
        cases.push(trailing);
        for bytes in cases {
            assert!(C61PublicArgument::decode(&bytes).is_err());
        }

        let mut bad_statement = argument.clone();
        bad_statement.statement_digest[0] ^= 1;
        let (_, _, _, _, _, mut transcript) = honest_fixture([43; 32]);
        assert!(verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &runtime,
            &bad_statement,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .is_err());

        let mut bad_chain = argument.clone();
        bad_chain.native_chains[2][0] ^= 1;
        let (_, _, _, _, _, mut transcript) = honest_fixture([43; 32]);
        assert!(verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &runtime,
            &bad_chain,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .is_err());

        let mut bad_runtime = runtime.clone();
        bad_runtime[0] += Fp2::ONE;
        let (_, _, _, _, _, mut transcript) = honest_fixture([43; 32]);
        assert!(verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &bad_runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .is_err());

        let mut bad_sources = sources.clone();
        bad_sources[0] += Fp2::ONE;
        let (_, _, _, _, _, mut transcript) = honest_fixture([43; 32]);
        assert!(verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &bad_sources,
            &runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .is_err());
    }

    #[test]
    fn sparse_plan_binds_indices_but_not_response_values() {
        let (plan, mut sources, mut runtime) = scaled_fixture();
        let digest = plan.digest();
        let baseline = plan.evaluate(&sources, &runtime).unwrap();
        sources[0] += Fp2::ONE;
        assert_eq!(plan.digest(), digest);
        let source_mutated = plan.evaluate(&sources, &runtime).unwrap();
        assert_ne!(source_mutated, baseline);
        runtime[0] += Fp2::ONE;
        assert_eq!(plan.digest(), digest);
        assert_ne!(plan.evaluate(&sources, &runtime).unwrap(), source_mutated);

        let bad_source = vec![C61LinearOp::Source { ordinal: 2 }];
        assert!(C61SparsePlan::new(bad_source, [0; C61_TERMINAL_CLAIMS], 2, 0).is_err());
        let bad_public = vec![C61LinearOp::PublicInput { runtime: 1 }];
        assert!(C61SparsePlan::new(bad_public, [0; C61_TERMINAL_CLAIMS], 0, 1).is_err());
        let bad_topology = vec![C61LinearOp::Add { left: 0, right: 0 }];
        assert!(C61SparsePlan::new(bad_topology, [0; C61_TERMINAL_CLAIMS], 0, 0).is_err());
    }

    #[test]
    fn changed_challenge_tape_rejects_same_artifact() {
        let (_, plan, sources, runtime, argument, _) = honest_fixture([44; 32]);
        let (other_ready, other_plan, other_sources, other_runtime, mut other_transcript) =
            ready_fixture([45; 32]);
        assert_eq!(plan, other_plan);
        assert_eq!(sources, other_sources);
        assert_eq!(runtime, other_runtime);
        assert!(verify_c61_scaled_public_argument(
            &other_ready,
            &other_plan,
            &other_sources,
            &other_runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut other_transcript,
        )
        .is_err());
    }

    #[test]
    fn native_round_challenge_must_follow_its_first_message() {
        let (ready, plan, sources, runtime, argument, mut transcript) = honest_fixture([48; 32]);
        let _premature_challenge = transcript.challenge_fp2();
        assert!(verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut transcript,
        )
        .is_err());

        let (_, _, _, _, _, mut transcript) = honest_fixture([48; 32]);
        let mut wrong_arithmetic_digest = component_digest(4, 0, argument.arithmetic());
        wrong_arithmetic_digest[0] ^= 1;
        assert!(DiagnosticDigestBackend
            .verify_chain(
                C61NativeChainId::ordered()[0],
                ready.statement_digest(),
                wrong_arithmetic_digest,
                &argument.native_chains()[0],
                &mut transcript,
            )
            .is_err());
    }

    #[test]
    fn retry_bindings_reject_replay_but_exact_retransmission_is_idempotent() {
        let seed = [49; 32];
        let (ready, plan, sources, runtime, argument, mut first_transcript) = honest_fixture(seed);
        verify_c61_scaled_public_argument(
            &ready,
            &plan,
            &sources,
            &runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut first_transcript,
        )
        .unwrap();

        let (same_ready, same_plan, same_sources, same_runtime, mut retransmit_transcript) =
            ready_fixture(seed);
        verify_c61_scaled_public_argument(
            &same_ready,
            &same_plan,
            &same_sources,
            &same_runtime,
            &argument,
            &DiagnosticDigestBackend,
            &mut retransmit_transcript,
        )
        .unwrap();

        let base = binding(&plan, &sources, &runtime);
        let mut mutations = Vec::new();
        let mut changed = base.clone();
        changed.nonce = [21; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.slot += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.correlation_ranges[0].start += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.correlation_ranges[0].count += 1;
        changed.correlation_ranges[1].count += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.old_head = [22; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.new_head = [23; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.predecessor_certificate = [24; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.workload_digest = [25; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.public_io_digest = [26; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.retained_transcript_digest = [27; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.retained_wrapper_digest = [28; 32];
        mutations.push(changed);
        let mut changed = base.clone();
        changed.connection_id = [29; 32];
        mutations.push(changed);
        let mut changed = base;
        changed.epoch += 1;
        mutations.push(changed);

        for changed_binding in mutations {
            let (changed_ready, mut changed_transcript) =
                ready_from_binding(seed, &plan, &sources, &runtime, changed_binding);
            assert!(verify_c61_scaled_public_argument(
                &changed_ready,
                &plan,
                &sources,
                &runtime,
                &argument,
                &DiagnosticDigestBackend,
                &mut changed_transcript,
            )
            .is_err());
        }
    }

    #[test]
    fn genesis_predecessor_exception_is_narrow() {
        let (plan, sources, runtime) = scaled_fixture();
        let mut first = binding(&plan, &sources, &runtime);
        first.epoch = 1;
        first.predecessor_certificate = [0; 32];
        assert!(C61RootsFixed::new(first.clone()).is_ok());
        first.epoch = 2;
        assert!(C61RootsFixed::new(first).is_err());
    }

    #[test]
    fn strict_caps_are_checked_before_payload_copy() {
        let (_, _, _, _, argument, _) = honest_fixture([46; 32]);
        let mut encoded = argument.encode().unwrap();
        let length_offset = OUTER_HEADER_BYTES + 4;
        encoded[length_offset..length_offset + 4]
            .copy_from_slice(&u32::try_from(C61_NATIVE_CHAIN_MAX_BYTES + 1).unwrap().to_le_bytes());
        let error = C61PublicArgument::decode(&encoded).unwrap_err().to_string();
        assert!(error.contains("exceeds its cap"));
    }

    #[test]
    fn noncanonical_arithmetic_field_rejects() {
        let (ready, plan, sources, runtime, _) = ready_fixture([47; 32]);
        let frame = build_c61_scaled_arithmetic_frame(&ready, &plan, &sources, &runtime).unwrap();
        let mut bytes = frame.encode();
        let first_claim_offset = 8 + 2 + 2 + 3 * 32;
        bytes[first_claim_offset..first_claim_offset + 8].copy_from_slice(&P.to_le_bytes());
        assert!(C61ArithmeticFrame::decode(&bytes).is_err());
    }
}

//! Typed C6.1 native-chain statements for the exact C6TFR1 relation.
//!
//! These types deliberately stop before a native backend implementation.
//! Public commitments, ordered points and compiler bindings are hashed into
//! one role-independent statement digest.  Authenticated target shares stay
//! in the provider statement and target keys stay in the verifier statement;
//! neither role-local vector is serialized into, or hashed by, the public
//! statement.

use std::fmt;

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    C6InstalledOperationPlan, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::prod_check::ProdProof;

use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent, C61_TERMINAL_CLAIMS};
use crate::c6_residual_sumcheck::{C6_RESIDUAL_AUXILIARY_ROUNDS, C6_RESIDUAL_LEAF_ROUNDS};

pub const C61_MODEL_OPENING_TARGETS: usize = 96;
pub const C61_EMBEDDING_OPENING_TARGETS: usize = 6;
pub const C61_COMPILER_TERMINAL_TARGETS: usize = C61_TERMINAL_CLAIMS;
pub const C61_TERMINAL_FUNCTIONAL_RELATION_LOG2: u8 = 28;
pub const C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS: usize = 2;
pub const C61_SPARSE_RATIONAL_INPUT_LOG2: u8 = 25;
pub const C61_SPARSE_RATIONAL_RESPONSE_PACKED_LOG2: u8 = 28;
pub const C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2: u8 = 27;
pub const C61_SPARSE_RATIONAL_SEMANTIC_RESPONSE_OPENINGS: usize = 6;
pub const C61_SPARSE_RATIONAL_RESPONSE_OPENINGS: usize =
    2 * C61_SPARSE_RATIONAL_SEMANTIC_RESPONSE_OPENINGS;
pub const C61_SPARSE_RATIONAL_PLAN_OPENINGS: usize = 3;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAGIC: [u8; 8] = *b"C6SBA1\0\0";
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_VERSION: u16 = 1;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_SUBCHECKS: usize = 7;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_HEADER_BYTES: u64 = 60;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_DIGEST_BYTES: u64 = 32;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES: u64 =
    C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_HEADER_BYTES
        + C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_DIGEST_BYTES;
pub const C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAX_BYTES: u64 = 500_000;
pub const C61_SPARSE_RATIONAL_BLIND_PRODUCTION_DEPTHS: [u8;
    C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_SUBCHECKS] = [25, 25, 25, 25, 24, 23, 25];
pub const C61_SPARSE_RATIONAL_BLIND_PRODUCTION_GKR_BYTES: u64 = 84_528;
pub const C61_SPARSE_RATIONAL_BLIND_PRODUCTION_JOINT_BYTES: u64 = 3_248;
pub const C61_SPARSE_RATIONAL_BLIND_TERMINAL_BYTES: u64 = 16;
pub const C61_SPARSE_RATIONAL_BLIND_PRODUCT_BYTES: u64 = 32;
pub const C61_SPARSE_RATIONAL_BLIND_PRODUCTION_ARITHMETIC_BYTES: u64 = 87_916;

const PUBLIC_STATEMENT_DOMAIN: &str = "volta-zk/c6.1/typed-native-chain-statement/v1";
const COMMITTED_OPENINGS_DOMAIN: &str = "volta-zk/c6.1/typed-committed-openings/v1";
const COMPILER_RELATION_DOMAIN: &str = "volta-zk/c6.1/typed-terminal-functional-compiler/v1";
const TERMINAL_CLAIMS_DOMAIN: &str = "volta-zk/c6.1/ordered-terminal-claims/v1";
const SPARSE_RESPONSE_LAYOUT_DOMAIN: &str = "volta-zk/c6.1/sparse-response-layout/v1";
const SPARSE_PLAN_LAYOUT_DOMAIN: &str = "volta-zk/c6.1/sparse-plan-layout/v1";
const SPARSE_ORACLES_DOMAIN: &str = "volta-zk/c6.1/sparse-compiler-oracles/v1";
const SPARSE_OPENING_STATEMENT_DOMAIN: &str = "volta-zk/c6.1/sparse-compiler-opening-statement/v1";
const SPARSE_BLIND_ARITHMETIC_PROOF_DOMAIN: &str = "volta-zk/c6.1/sparse-blind-arithmetic-proof/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalStatementError(String);

impl C61TerminalFunctionalStatementError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61TerminalFunctionalStatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61TerminalFunctionalStatementError {}

type Result<T> = std::result::Result<T, C61TerminalFunctionalStatementError>;

fn encode_sparse_blind_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

fn sparse_blind_arithmetic_proof_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SPARSE_BLIND_ARITHMETIC_PROOF_DOMAIN);
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    *hasher.finalize().as_bytes()
}

struct SparseBlindArithmeticReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SparseBlindArithmeticReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C61TerminalFunctionalStatementError::new("C6SBA1 cursor overflows"))?;
        if end > self.bytes.len() {
            return Err(C61TerminalFunctionalStatementError::new("truncated C6SBA1 proof"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed C6SBA1 u16 slice")))
    }

    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed C6SBA1 u32 slice")) as usize)
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let c0 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed C6SBA1 Fp slice"));
        let c1 = u64::from_le_bytes(self.take(8)?.try_into().expect("fixed C6SBA1 Fp slice"));
        if c0 >= P || c1 >= P {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 contains a noncanonical base-field limb",
            ));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("fixed C6SBA1 digest slice"))
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C61TerminalFunctionalStatementError::new("trailing C6SBA1 proof bytes"));
        }
        Ok(())
    }
}

/// Strict provider artifact for the blind seven-tree reduction, joint
/// degree-eight sumcheck, terminal product correction and the single global
/// QuickSilver product proof.  The compiler chain's designated ZeroOpen tag
/// remains in C6SMO1 and is deliberately not duplicated here.
#[derive(Debug, PartialEq, Eq)]
pub struct C61SparseRationalBlindArithmeticProof {
    gkr: volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof,
    joint: volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof,
    terminal: volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof,
    product: ProdProof,
}

impl C61SparseRationalBlindArithmeticProof {
    pub fn new(
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: [u8; 32],
        gkr: volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof,
        joint: volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof,
        terminal: volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof,
        product: ProdProof,
    ) -> Result<Self> {
        let proof = Self { gkr, joint, terminal, product };
        proof.validate(operation_plan, relation_digest)?;
        Ok(proof)
    }

    pub fn encoded_len(
        &self,
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: [u8; 32],
    ) -> Result<u64> {
        self.validate(operation_plan, relation_digest)?;
        let base_domain_log2 =
            volta_proto::c6_residual::c6_sparse_rational_base_domain_log2(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let gkr_bytes =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof::correction_bytes(
                operation_plan,
            )
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let joint_bytes =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof::correction_bytes(
                base_domain_log2,
            )
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES
            .checked_add(gkr_bytes)
            .and_then(|bytes| bytes.checked_add(joint_bytes))
            .and_then(|bytes| bytes.checked_add(C61_SPARSE_RATIONAL_BLIND_TERMINAL_BYTES))
            .and_then(|bytes| bytes.checked_add(C61_SPARSE_RATIONAL_BLIND_PRODUCT_BYTES))
            .ok_or_else(|| {
                C61TerminalFunctionalStatementError::new("C6SBA1 encoded length overflows")
            })
    }

    pub fn encode(
        &self,
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: [u8; 32],
    ) -> Result<Vec<u8>> {
        self.validate(operation_plan, relation_digest)?;
        let base_domain_log2 =
            volta_proto::c6_residual::c6_sparse_rational_base_domain_log2(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let depths =
            volta_proto::c6_residual::c6_sparse_rational_subcheck_depths(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let gkr = self
            .gkr
            .encode_corrections(operation_plan)
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let joint = self
            .joint
            .encode_corrections(base_domain_log2)
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let expected_len = self.encoded_len(operation_plan, relation_digest)?;
        if expected_len > C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAX_BYTES {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 exceeds the arithmetic/MAC/link cap",
            ));
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected_len)
                .map_err(|_| C61TerminalFunctionalStatementError::new("C6SBA1 exceeds usize"))?,
        );
        bytes.extend_from_slice(&C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAGIC);
        bytes.extend_from_slice(&C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_VERSION.to_le_bytes());
        bytes.push(base_domain_log2);
        bytes.push(C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_SUBCHECKS as u8);
        for depth in depths {
            bytes.push(u8::try_from(depth).map_err(|_| {
                C61TerminalFunctionalStatementError::new("C6SBA1 fraction depth exceeds u8")
            })?);
        }
        bytes.push(0);
        bytes.extend_from_slice(&relation_digest);
        bytes.extend_from_slice(
            &u32::try_from(gkr.len())
                .map_err(|_| {
                    C61TerminalFunctionalStatementError::new("C6SBA1 GKR body exceeds u32")
                })?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(joint.len())
                .map_err(|_| {
                    C61TerminalFunctionalStatementError::new("C6SBA1 joint body exceeds u32")
                })?
                .to_le_bytes(),
        );
        debug_assert_eq!(bytes.len() as u64, C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_HEADER_BYTES);
        bytes.extend_from_slice(&gkr);
        bytes.extend_from_slice(&joint);
        encode_sparse_blind_fp2(&mut bytes, self.terminal.product_correction());
        encode_sparse_blind_fp2(&mut bytes, self.product.m0);
        encode_sparse_blind_fp2(&mut bytes, self.product.m1);
        bytes.extend_from_slice(&sparse_blind_arithmetic_proof_digest(&bytes));
        if bytes.len() as u64 != expected_len {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 encoder length disagrees with the exact census",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self> {
        if bytes.len() as u64 > C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAX_BYTES {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 exceeds the arithmetic/MAC/link cap",
            ));
        }
        let expected_base =
            volta_proto::c6_residual::c6_sparse_rational_base_domain_log2(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let expected_depths =
            volta_proto::c6_residual::c6_sparse_rational_subcheck_depths(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let expected_gkr =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof::correction_bytes(
                operation_plan,
            )
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let expected_joint =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof::correction_bytes(
                expected_base,
            )
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let expected_len = C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES
            .checked_add(expected_gkr)
            .and_then(|value| value.checked_add(expected_joint))
            .and_then(|value| value.checked_add(C61_SPARSE_RATIONAL_BLIND_TERMINAL_BYTES))
            .and_then(|value| value.checked_add(C61_SPARSE_RATIONAL_BLIND_PRODUCT_BYTES))
            .ok_or_else(|| C61TerminalFunctionalStatementError::new("C6SBA1 length overflows"))?;
        if bytes.len() as u64 != expected_len {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 strict proof length mismatch",
            ));
        }
        let mut reader = SparseBlindArithmeticReader::new(bytes);
        if reader.take(8)? != C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAGIC {
            return Err(C61TerminalFunctionalStatementError::new("bad C6SBA1 magic"));
        }
        if reader.u16()? != C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_VERSION {
            return Err(C61TerminalFunctionalStatementError::new("unknown C6SBA1 version"));
        }
        if reader.u8()? != expected_base
            || reader.u8()? as usize != C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_SUBCHECKS
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 base dimension or subcheck census mismatch",
            ));
        }
        for expected in expected_depths {
            if reader.u8()? as usize != expected {
                return Err(C61TerminalFunctionalStatementError::new(
                    "C6SBA1 fraction depth mismatch",
                ));
            }
        }
        if reader.u8()? != 0 || reader.digest()? != relation_digest {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 reserved byte or relation digest mismatch",
            ));
        }
        let gkr_len = reader.u32()?;
        let joint_len = reader.u32()?;
        if gkr_len as u64 != expected_gkr || joint_len as u64 != expected_joint {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 nested body length mismatch",
            ));
        }
        let gkr =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof::decode_corrections(
                operation_plan,
                relation_digest,
                reader.take(gkr_len)?,
            )
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let joint = volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof::decode_corrections(
            relation_digest,
            expected_base,
            reader.take(joint_len)?,
        )
        .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        let terminal =
            volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof::from_product_correction(
                reader.fp2()?,
            );
        let product = ProdProof { m0: reader.fp2()?, m1: reader.fp2()? };
        let digest_offset = reader.position();
        let encoded_digest = reader.digest()?;
        reader.finish()?;
        if encoded_digest != sparse_blind_arithmetic_proof_digest(&bytes[..digest_offset]) {
            return Err(C61TerminalFunctionalStatementError::new(
                "corrupt or noncanonical C6SBA1 proof",
            ));
        }
        Self::new(operation_plan, relation_digest, gkr, joint, terminal, product)
    }

    pub fn into_parts(
        self,
    ) -> (
        volta_proto::c6_residual::C6ResidualSparseRationalBlindGkrProof,
        volta_proto::c6_residual::C6ResidualSparseRationalBlindJointRoundsProof,
        volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof,
        ProdProof,
    ) {
        (self.gkr, self.joint, self.terminal, self.product)
    }

    fn validate(
        &self,
        operation_plan: &C6InstalledOperationPlan,
        relation_digest: [u8; 32],
    ) -> Result<()> {
        if self.gkr.relation_digest() != relation_digest
            || self.joint.relation_digest() != relation_digest
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SBA1 nested proof relation digest mismatch",
            ));
        }
        let base_domain_log2 =
            volta_proto::c6_residual::c6_sparse_rational_base_domain_log2(operation_plan)
                .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        self.gkr
            .encode_corrections(operation_plan)
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        self.joint
            .encode_corrections(base_domain_log2)
            .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61NativeCommitmentDescriptor {
    pub parameter_digest: [u8; 32],
    pub commitment_root: [u8; 32],
    pub polynomial_domain_log2: u8,
}

impl C61NativeCommitmentDescriptor {
    fn validate(self) -> Result<()> {
        if self.parameter_digest == [0; 32] || self.commitment_root == [0; 32] {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native commitment contains a zero digest",
            ));
        }
        if self.polynomial_domain_log2 == 0 || self.polynomial_domain_log2 > 63 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native commitment dimension is out of range",
            ));
        }
        Ok(())
    }
}

fn sparse_layout_digest(domain: &'static str, physical_log2: u8, blocks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&[C61_SPARSE_RATIONAL_INPUT_LOG2, physical_log2]);
    hasher.update(&(blocks.len() as u64).to_le_bytes());
    for (ordinal, block) in blocks.iter().enumerate() {
        hasher.update(&(ordinal as u64).to_le_bytes());
        hasher.update(&(block.len() as u64).to_le_bytes());
        hasher.update(block);
    }
    *hasher.finalize().as_bytes()
}

pub fn c61_sparse_response_layout_digest() -> [u8; 32] {
    sparse_layout_digest(
        SPARSE_RESPONSE_LAYOUT_DOMAIN,
        C61_SPARSE_RATIONAL_RESPONSE_PACKED_LOG2,
        &[
            b"c0(lambda_0_D25|lambda_1_D25|scale_runtime_D24_g0_D23_g1_D23|mu_D25)",
            b"c1(lambda_0_D25|lambda_1_D25|scale_runtime_D24_g0_D23_g1_D23|mu_D25)",
        ],
    )
}

pub fn c61_sparse_plan_layout_digest() -> [u8; 32] {
    sparse_layout_digest(
        SPARSE_PLAN_LAYOUT_DOMAIN,
        C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2,
        &[b"opcode_D25_structural_zero_pad", b"lhs_D25", b"rhs_D25", b"zero_D25"],
    )
}

/// The two commitment roots fixed before C6SPR2's lane/rational challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOracles {
    pub response: C61NativeCommitmentDescriptor,
    pub plan: C61NativeCommitmentDescriptor,
    pub response_layout_digest: [u8; 32],
    pub plan_layout_digest: [u8; 32],
}

impl C61SparseRationalCompilerOracles {
    pub fn new(
        response: C61NativeCommitmentDescriptor,
        plan: C61NativeCommitmentDescriptor,
    ) -> Result<Self> {
        let oracles = Self {
            response,
            plan,
            response_layout_digest: c61_sparse_response_layout_digest(),
            plan_layout_digest: c61_sparse_plan_layout_digest(),
        };
        oracles.validate()?;
        Ok(oracles)
    }

    pub fn validate(&self) -> Result<()> {
        self.response.validate()?;
        self.plan.validate()?;
        if self.response.polynomial_domain_log2 != C61_SPARSE_RATIONAL_RESPONSE_PACKED_LOG2
            || self.plan.polynomial_domain_log2 != C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR3 response/plan commitments must use physical D28/D27",
            ));
        }
        if self.response_layout_digest != c61_sparse_response_layout_digest()
            || self.plan_layout_digest != c61_sparse_plan_layout_digest()
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 compiler oracle layout digest is noncanonical",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(SPARSE_ORACLES_DOMAIN);
        for descriptor in [self.response, self.plan] {
            hasher.update(&descriptor.parameter_digest);
            hasher.update(&descriptor.commitment_root);
            hasher.update(&[descriptor.polynomial_domain_log2]);
        }
        hasher.update(&self.response_layout_digest);
        hasher.update(&self.plan_layout_digest);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Fifteen physical base-field points derived after the joint GKR reduction.
/// Response order is semantic `(lambda_0, lambda_1, mu, runtime, g_0, g_1)`
/// major, then limb `(c0, c1)`; fixed plan order is `(opcode, lhs, rhs)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOpeningPoints {
    input_point: Vec<Fp2>,
    response: [Vec<Fp2>; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    plan: [Vec<Fp2>; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    digest: [u8; 32],
}

impl C61SparseRationalCompilerOpeningPoints {
    pub fn new(input_point: &[Fp2]) -> Result<Self> {
        if input_point.len() != usize::from(C61_SPARSE_RATIONAL_INPUT_LOG2) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 GKR input point must be D25",
            ));
        }
        let dimension = input_point.len();
        let append = |prefix: &[Fp2], suffix: &[Fp2]| {
            prefix.iter().chain(suffix).copied().collect::<Vec<_>>()
        };
        let semantic_response = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ONE]),
            append(&input_point[..dimension - 1], &[Fp2::ZERO, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..dimension - 2], &[Fp2::ZERO, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
            append(&input_point[..dimension - 2], &[Fp2::ONE, Fp2::ONE, Fp2::ZERO, Fp2::ONE]),
        ];
        let response = semantic_response
            .iter()
            .flat_map(|point| {
                [Fp2::ZERO, Fp2::ONE].into_iter().map(move |limb| {
                    point.iter().copied().chain(std::iter::once(limb)).collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| {
                C61TerminalFunctionalStatementError::new(
                    "C6SPR3 physical response-point census mismatch",
                )
            })?;
        let plan = [
            append(input_point, &[Fp2::ZERO, Fp2::ZERO]),
            append(input_point, &[Fp2::ONE, Fp2::ZERO]),
            append(input_point, &[Fp2::ZERO, Fp2::ONE]),
        ];
        let mut points =
            Self { input_point: input_point.to_vec(), response, plan, digest: [0; 32] };
        points.digest = points.recompute_digest();
        Ok(points)
    }

    pub fn input_point(&self) -> &[Fp2] {
        &self.input_point
    }

    pub fn response(&self) -> &[Vec<Fp2>; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] {
        &self.response
    }

    pub fn plan(&self) -> &[Vec<Fp2>; C61_SPARSE_RATIONAL_PLAN_OPENINGS] {
        &self.plan
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if *self != Self::new(&self.input_point)? {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 compiler opening points are noncanonical",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-zk/c6.1/sparse-compiler-opening-points/v1");
        for (role, points) in [(0u8, self.response.as_slice()), (1u8, self.plan.as_slice())] {
            hasher.update(&[role]);
            hasher.update(&(points.len() as u64).to_le_bytes());
            for (ordinal, point) in points.iter().enumerate() {
                hasher.update(&(ordinal as u64).to_le_bytes());
                hash_point(&mut hasher, point);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalCompilerOpeningStatement {
    pub compiler_statement_digest: [u8; 32],
    pub sparse_relation_digest: [u8; 32],
    pub gkr_transcript_digest: [u8; 32],
    pub oracles: C61SparseRationalCompilerOracles,
    pub points: C61SparseRationalCompilerOpeningPoints,
    digest: [u8; 32],
}

impl C61SparseRationalCompilerOpeningStatement {
    pub fn new(
        compiler_statement_digest: [u8; 32],
        sparse_relation_digest: [u8; 32],
        gkr_transcript_digest: [u8; 32],
        oracles: C61SparseRationalCompilerOracles,
        input_point: &[Fp2],
    ) -> Result<Self> {
        if [compiler_statement_digest, sparse_relation_digest, gkr_transcript_digest]
            .contains(&[0; 32])
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 opening statement contains a zero binding digest",
            ));
        }
        oracles.validate()?;
        let points = C61SparseRationalCompilerOpeningPoints::new(input_point)?;
        let mut statement = Self {
            compiler_statement_digest,
            sparse_relation_digest,
            gkr_transcript_digest,
            oracles,
            points,
            digest: [0; 32],
        };
        statement.digest = statement.recompute_digest()?;
        Ok(statement)
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn validate(&self) -> Result<()> {
        self.oracles.validate()?;
        self.points.validate()?;
        if [self.compiler_statement_digest, self.sparse_relation_digest, self.gkr_transcript_digest]
            .contains(&[0; 32])
            || self.digest != self.recompute_digest()?
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6SPR2 opening statement binding is inconsistent",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new_derive_key(SPARSE_OPENING_STATEMENT_DOMAIN);
        hasher.update(&self.compiler_statement_digest);
        hasher.update(&self.sparse_relation_digest);
        hasher.update(&self.gkr_transcript_digest);
        hasher.update(&self.oracles.digest()?);
        hasher.update(&self.points.digest());
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalProverOpeningStatement {
    pub public: C61SparseRationalCompilerOpeningStatement,
    pub response_targets: [ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    pub plan_targets: [ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
}

impl C61SparseRationalProverOpeningStatement {
    pub fn new(
        public: C61SparseRationalCompilerOpeningStatement,
        response_targets: [ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
        plan_targets: [ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    ) -> Result<Self> {
        public.validate()?;
        Ok(Self { public, response_targets, plan_targets })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61SparseRationalVerifierOpeningStatement {
    pub public: C61SparseRationalCompilerOpeningStatement,
    pub response_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    pub plan_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
}

pub fn fold_c61_sparse_response_prover_targets(
    physical: &[ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
) -> [ProverAuthed; C61_SPARSE_RATIONAL_SEMANTIC_RESPONSE_OPENINGS] {
    let extension_generator = Fp2::new(volta_field::Fp::ZERO, volta_field::Fp::ONE);
    std::array::from_fn(|index| {
        physical[2 * index].add(physical[2 * index + 1].scale(extension_generator))
    })
}

pub fn fold_c61_sparse_response_verifier_keys(
    physical: &[VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
) -> [VerifierKey; C61_SPARSE_RATIONAL_SEMANTIC_RESPONSE_OPENINGS] {
    let extension_generator = Fp2::new(volta_field::Fp::ZERO, volta_field::Fp::ONE);
    std::array::from_fn(|index| {
        physical[2 * index].add(physical[2 * index + 1].scale(extension_generator))
    })
}

#[allow(clippy::too_many_arguments)]
pub fn finish_c61_sparse_rational_blind_physical_terminal_prover(
    terminal: volta_proto::c6_residual::C6SparseRationalBlindJointProverTerminal,
    response_targets: &[ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    plan_targets: &[ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    stream: &mut CorrelationStream,
    doms: &mut volta_proto::logup::Doms,
    tx: &mut Transcript,
    products: &mut volta_proto::logup::ProdTriples,
    zeros: &mut Vec<ProverAuthed>,
) -> Result<volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof> {
    let semantic_response = fold_c61_sparse_response_prover_targets(response_targets);
    volta_proto::c6_residual::finish_c6_residual_sparse_rational_joint_leaf_blind_prover(
        terminal,
        &semantic_response,
        plan_targets,
        stream,
        doms,
        tx,
        products,
        zeros,
    )
    .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn finish_c61_sparse_rational_blind_physical_terminal_verifier(
    terminal: volta_proto::c6_residual::C6SparseRationalBlindJointVerifierTerminal,
    response_keys: &[VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
    plan_keys: &[VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    proof: &volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof,
    ctx: &mut VerifierCtx,
    doms: &mut volta_proto::logup::Doms,
    tx: &mut Transcript,
    products: &mut volta_proto::logup::ProdKeyTriples,
    zeros: &mut Vec<VerifierKey>,
) -> Result<()> {
    let semantic_response = fold_c61_sparse_response_verifier_keys(response_keys);
    volta_proto::c6_residual::finish_c6_residual_sparse_rational_joint_leaf_blind_verifier(
        terminal,
        &semantic_response,
        plan_keys,
        proof,
        ctx,
        doms,
        tx,
        products,
        zeros,
    )
    .map_err(|error| C61TerminalFunctionalStatementError::new(error.to_string()))
}

/// Connect the twelve physical base-field response targets to the six
/// semantic Fp2 inputs of the blind joint terminal relation.  The typed PCS
/// statement must carry the same relation digest and common input point.
#[allow(clippy::too_many_arguments)]
pub fn finish_c61_sparse_rational_blind_terminal_prover(
    terminal: volta_proto::c6_residual::C6SparseRationalBlindJointProverTerminal,
    statement: &C61SparseRationalProverOpeningStatement,
    stream: &mut CorrelationStream,
    doms: &mut volta_proto::logup::Doms,
    tx: &mut Transcript,
    products: &mut volta_proto::logup::ProdTriples,
    zeros: &mut Vec<ProverAuthed>,
) -> Result<volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof> {
    statement.public.validate()?;
    if statement.public.sparse_relation_digest != terminal.relation_digest()
        || statement.public.points.input_point() != terminal.points().input_point()
    {
        return Err(C61TerminalFunctionalStatementError::new(
            "C6SPR3 prover PCS statement differs from the blind terminal relation",
        ));
    }
    finish_c61_sparse_rational_blind_physical_terminal_prover(
        terminal,
        &statement.response_targets,
        &statement.plan_targets,
        stream,
        doms,
        tx,
        products,
        zeros,
    )
}

/// Verifier mirror of
/// [`finish_c61_sparse_rational_blind_terminal_prover`].
#[allow(clippy::too_many_arguments)]
pub fn finish_c61_sparse_rational_blind_terminal_verifier(
    terminal: volta_proto::c6_residual::C6SparseRationalBlindJointVerifierTerminal,
    statement: &C61SparseRationalVerifierOpeningStatement,
    proof: &volta_proto::c6_residual::C6ResidualSparseRationalBlindJointTerminalProof,
    ctx: &mut VerifierCtx,
    doms: &mut volta_proto::logup::Doms,
    tx: &mut Transcript,
    products: &mut volta_proto::logup::ProdKeyTriples,
    zeros: &mut Vec<VerifierKey>,
) -> Result<()> {
    statement.public.validate()?;
    if statement.public.sparse_relation_digest != terminal.relation_digest()
        || statement.public.points.input_point() != terminal.points().input_point()
    {
        return Err(C61TerminalFunctionalStatementError::new(
            "C6SPR3 verifier PCS statement differs from the blind terminal relation",
        ));
    }
    finish_c61_sparse_rational_blind_physical_terminal_verifier(
        terminal,
        &statement.response_target_keys,
        &statement.plan_target_keys,
        proof,
        ctx,
        doms,
        tx,
        products,
        zeros,
    )
}

impl C61SparseRationalVerifierOpeningStatement {
    pub fn new(
        public: C61SparseRationalCompilerOpeningStatement,
        response_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS],
        plan_target_keys: [VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS],
    ) -> Result<Self> {
        public.validate()?;
        Ok(Self { public, response_target_keys, plan_target_keys })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61CommittedOpeningStatement {
    pub commitment: C61NativeCommitmentDescriptor,
    pub ordered_points: Vec<Vec<Fp2>>,
}

impl C61CommittedOpeningStatement {
    fn validate(&self, expected_targets: usize) -> Result<()> {
        self.commitment.validate()?;
        if self.ordered_points.len() != expected_targets {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 committed-opening statement has the wrong target census",
            ));
        }
        let point_dimension = usize::from(self.commitment.polynomial_domain_log2);
        if self.ordered_points.iter().any(|point| point.len() != point_dimension) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 committed-opening statement has a malformed point",
            ));
        }
        Ok(())
    }

    fn digest(&self, component: C61NativeComponent) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(COMMITTED_OPENINGS_DOMAIN);
        hasher.update(&(component as u16).to_le_bytes());
        hasher.update(&self.commitment.parameter_digest);
        hasher.update(&self.commitment.commitment_root);
        hasher.update(&[self.commitment.polynomial_domain_log2]);
        hasher.update(&(self.ordered_points.len() as u64).to_le_bytes());
        for (ordinal, point) in self.ordered_points.iter().enumerate() {
            hasher.update(&(ordinal as u64).to_le_bytes());
            hash_point(&mut hasher, point);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Complete public input of each of the two compiler chains.  The two chains
/// use independent native-proof randomness/MAC coordinates but bind the same
/// exact two-repetition C6TFR1 relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalCompilerBinding {
    pub operation_plan_digest: [u8; 32],
    pub operation_topology_digest: [u8; 32],
    pub terminal_metadata_digest: [u8; 32],
    pub extraction_map_digest: [u8; 32],
    pub runtime_root: [u8; 32],
    pub residual_manifest_digest: [u8; 32],
    pub residual_public_claims_digest: [u8; 32],
    pub relation_challenges_digest: [u8; 32],
    pub sparse_oracles: C61SparseRationalCompilerOracles,
    pub leaf_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub auxiliary_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    pub output_beta: Fp2,
    pub relation_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TerminalFunctionalCompilerStatement {
    pub operation_plan_digest: [u8; 32],
    pub operation_topology_digest: [u8; 32],
    pub terminal_metadata_digest: [u8; 32],
    pub extraction_map_digest: [u8; 32],
    pub runtime_root: [u8; 32],
    pub residual_manifest_digest: [u8; 32],
    pub residual_public_claims_digest: [u8; 32],
    pub relation_challenges_digest: [u8; 32],
    pub sparse_oracles: C61SparseRationalCompilerOracles,
    pub leaf_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub auxiliary_points: [Vec<Fp2>; C61_TERMINAL_FUNCTIONAL_PROOF_REPETITIONS],
    pub terminal_claims: [Fp2; C61_TERMINAL_CLAIMS],
    pub terminal_claims_digest: [u8; 32],
    pub output_beta: Fp2,
    pub relation_root: [u8; 32],
    pub functional_fold: Fp2,
}

impl C61TerminalFunctionalCompilerStatement {
    pub fn new(binding: C61TerminalFunctionalCompilerBinding) -> Result<Self> {
        let C61TerminalFunctionalCompilerBinding {
            operation_plan_digest,
            operation_topology_digest,
            terminal_metadata_digest,
            extraction_map_digest,
            runtime_root,
            residual_manifest_digest,
            residual_public_claims_digest,
            relation_challenges_digest,
            sparse_oracles,
            leaf_points,
            auxiliary_points,
            terminal_claims,
            output_beta,
            relation_root,
        } = binding;
        let terminal_claims_digest = terminal_claims_digest(&terminal_claims);
        let functional_fold = fold_terminal_claims(&terminal_claims, output_beta);
        let statement = Self {
            operation_plan_digest,
            operation_topology_digest,
            terminal_metadata_digest,
            extraction_map_digest,
            runtime_root,
            residual_manifest_digest,
            residual_public_claims_digest,
            relation_challenges_digest,
            sparse_oracles,
            leaf_points,
            auxiliary_points,
            terminal_claims,
            terminal_claims_digest,
            output_beta,
            relation_root,
            functional_fold,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn validate(&self) -> Result<()> {
        let required_digests = [
            self.operation_plan_digest,
            self.operation_topology_digest,
            self.terminal_metadata_digest,
            self.extraction_map_digest,
            self.runtime_root,
            self.residual_manifest_digest,
            self.residual_public_claims_digest,
            self.relation_challenges_digest,
            self.relation_root,
        ];
        if required_digests.contains(&[0; 32]) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement contains a zero binding digest",
            ));
        }
        self.sparse_oracles.validate()?;
        if self.leaf_points.iter().any(|point| point.len() != C6_RESIDUAL_LEAF_ROUNDS) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement has a malformed leaf point",
            ));
        }
        if self.auxiliary_points.iter().any(|point| point.len() != C6_RESIDUAL_AUXILIARY_ROUNDS) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler statement has a malformed auxiliary point",
            ));
        }
        if self.terminal_claims_digest != terminal_claims_digest(&self.terminal_claims) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler terminal digest is inconsistent",
            ));
        }
        if self.functional_fold != fold_terminal_claims(&self.terminal_claims, self.output_beta) {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6TFR1 compiler functional fold is inconsistent",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(COMPILER_RELATION_DOMAIN);
        hasher.update(&[C61_TERMINAL_FUNCTIONAL_RELATION_LOG2]);
        for digest in [
            self.operation_plan_digest,
            self.operation_topology_digest,
            self.terminal_metadata_digest,
            self.extraction_map_digest,
            self.runtime_root,
            self.residual_manifest_digest,
            self.residual_public_claims_digest,
            self.relation_challenges_digest,
        ] {
            hasher.update(&digest);
        }
        hasher.update(&self.sparse_oracles.digest()?);
        for (repetition, point) in self.leaf_points.iter().enumerate() {
            hasher.update(&[repetition as u8, 0]);
            hash_point(&mut hasher, point);
        }
        for (repetition, point) in self.auxiliary_points.iter().enumerate() {
            hasher.update(&[repetition as u8, 1]);
            hash_point(&mut hasher, point);
        }
        hasher.update(&self.terminal_claims_digest);
        hash_fp2(&mut hasher, self.output_beta);
        hasher.update(&self.relation_root);
        hash_fp2(&mut hasher, self.functional_fold);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C61TypedNativeRelationStatement {
    Model(C61CommittedOpeningStatement),
    Embedding(C61CommittedOpeningStatement),
    Compiler(Box<C61TerminalFunctionalCompilerStatement>),
}

impl C61TypedNativeRelationStatement {
    fn component(&self) -> C61NativeComponent {
        match self {
            Self::Model(_) => C61NativeComponent::Model,
            Self::Embedding(_) => C61NativeComponent::Embedding,
            Self::Compiler(_) => C61NativeComponent::Compiler,
        }
    }

    fn target_count(&self) -> usize {
        match self {
            Self::Model(_) => C61_MODEL_OPENING_TARGETS,
            Self::Embedding(_) => C61_EMBEDDING_OPENING_TARGETS,
            Self::Compiler(_) => C61_COMPILER_TERMINAL_TARGETS,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Model(statement) => statement.validate(C61_MODEL_OPENING_TARGETS),
            Self::Embedding(statement) => statement.validate(C61_EMBEDDING_OPENING_TARGETS),
            Self::Compiler(statement) => statement.validate(),
        }
    }

    fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        match self {
            Self::Model(statement) => Ok(statement.digest(C61NativeComponent::Model)),
            Self::Embedding(statement) => Ok(statement.digest(C61NativeComponent::Embedding)),
            Self::Compiler(statement) => statement.digest(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61TypedNativeChainPublicStatement {
    id: C61NativeChainId,
    relation: C61TypedNativeRelationStatement,
    digest: [u8; 32],
}

impl C61TypedNativeChainPublicStatement {
    pub fn new(id: C61NativeChainId, relation: C61TypedNativeRelationStatement) -> Result<Self> {
        if id.repetition >= 2 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native chain repetition is out of range",
            ));
        }
        if id.component != relation.component() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 native chain component does not match its typed relation",
            ));
        }
        relation.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(PUBLIC_STATEMENT_DOMAIN);
        hasher.update(&(id.component as u16).to_le_bytes());
        hasher.update(&[id.repetition]);
        hasher.update(&relation.digest()?);
        let digest = *hasher.finalize().as_bytes();
        Ok(Self { id, relation, digest })
    }

    pub fn id(&self) -> C61NativeChainId {
        self.id
    }

    pub fn relation(&self) -> &C61TypedNativeRelationStatement {
        &self.relation
    }

    pub fn target_count(&self) -> usize {
        self.relation.target_count()
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn validate(&self) -> Result<()> {
        if self.id.component != self.relation.component() || self.id.repetition >= 2 {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 typed native chain identity is inconsistent",
            ));
        }
        if self.digest
            != C61TypedNativeChainPublicStatement::new(self.id, self.relation.clone())?.digest
        {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 typed native chain digest is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeProverChainStatement {
    public: C61TypedNativeChainPublicStatement,
    targets: Vec<ProverAuthed>,
}

impl C61NativeProverChainStatement {
    pub fn new(
        public: C61TypedNativeChainPublicStatement,
        targets: Vec<ProverAuthed>,
    ) -> Result<Self> {
        public.validate()?;
        if targets.len() != public.target_count() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 provider target census does not match the typed statement",
            ));
        }
        if let C61TypedNativeRelationStatement::Compiler(compiler) = public.relation() {
            if targets.iter().zip(compiler.terminal_claims).any(|(target, claim)| target.x != claim)
            {
                return Err(C61TerminalFunctionalStatementError::new(
                    "C6TFR1 provider target plaintext differs from its terminal claim",
                ));
            }
        }
        Ok(Self { public, targets })
    }

    pub fn public(&self) -> &C61TypedNativeChainPublicStatement {
        &self.public
    }

    pub fn targets(&self) -> &[ProverAuthed] {
        &self.targets
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeVerifierChainStatement {
    public: C61TypedNativeChainPublicStatement,
    target_keys: Vec<VerifierKey>,
}

impl C61NativeVerifierChainStatement {
    pub fn new(
        public: C61TypedNativeChainPublicStatement,
        target_keys: Vec<VerifierKey>,
    ) -> Result<Self> {
        public.validate()?;
        if target_keys.len() != public.target_count() {
            return Err(C61TerminalFunctionalStatementError::new(
                "C6.1 verifier target census does not match the typed statement",
            ));
        }
        Ok(Self { public, target_keys })
    }

    pub fn public(&self) -> &C61TypedNativeChainPublicStatement {
        &self.public
    }

    pub fn target_keys(&self) -> &[VerifierKey] {
        &self.target_keys
    }
}

/// Future production backends must consume the structured verifier
/// statement.  The historical opaque digest/payload adapter does not
/// implement this trait and remains ineligible for C6TFR1 credit.
pub trait C61TypedNativeBackendVerifier {
    fn verify_typed_chain(
        &self,
        statement: &C61NativeVerifierChainStatement,
        payload: &[u8],
        transcript: &mut Transcript,
    ) -> Result<()>;
}

pub fn fold_terminal_claims(claims: &[Fp2; C61_TERMINAL_CLAIMS], output_beta: Fp2) -> Fp2 {
    claims
        .iter()
        .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), claim| {
            (sum + power * *claim, power * output_beta)
        })
        .0
}

pub fn terminal_claims_digest(claims: &[Fp2; C61_TERMINAL_CLAIMS]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TERMINAL_CLAIMS_DOMAIN);
    hasher.update(&(claims.len() as u64).to_le_bytes());
    for (ordinal, claim) in claims.iter().enumerate() {
        hasher.update(&(ordinal as u64).to_le_bytes());
        hash_fp2(&mut hasher, *claim);
    }
    *hasher.finalize().as_bytes()
}

fn hash_point(hasher: &mut blake3::Hasher, point: &[Fp2]) {
    hasher.update(&(point.len() as u64).to_le_bytes());
    for coordinate in point {
        hash_fp2(hasher, *coordinate);
    }
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, P};

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(17).wrapping_add(3)))
    }

    fn commitment(marker: u8, dimension: u8) -> C61NativeCommitmentDescriptor {
        C61NativeCommitmentDescriptor {
            parameter_digest: [marker; 32],
            commitment_root: [marker.wrapping_add(1); 32],
            polynomial_domain_log2: dimension,
        }
    }

    fn opening_statement(marker: u8, dimension: u8, claims: usize) -> C61CommittedOpeningStatement {
        C61CommittedOpeningStatement {
            commitment: commitment(marker, dimension),
            ordered_points: (0..claims)
                .map(|claim| {
                    (0..dimension)
                        .map(|coordinate| {
                            fp2(u64::from(marker) + claim as u64 + u64::from(coordinate))
                        })
                        .collect()
                })
                .collect(),
        }
    }

    fn compiler_statement() -> C61TerminalFunctionalCompilerStatement {
        let terminal_claims = std::array::from_fn(|index| fp2(index as u64 + 101));
        C61TerminalFunctionalCompilerStatement::new(C61TerminalFunctionalCompilerBinding {
            operation_plan_digest: [1; 32],
            operation_topology_digest: [2; 32],
            terminal_metadata_digest: [3; 32],
            extraction_map_digest: [4; 32],
            runtime_root: [5; 32],
            residual_manifest_digest: [6; 32],
            residual_public_claims_digest: [7; 32],
            relation_challenges_digest: [8; 32],
            sparse_oracles: C61SparseRationalCompilerOracles::new(
                commitment(41, C61_SPARSE_RATIONAL_RESPONSE_PACKED_LOG2),
                commitment(51, C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2),
            )
            .unwrap(),
            leaf_points: std::array::from_fn(|repetition| {
                (0..C6_RESIDUAL_LEAF_ROUNDS)
                    .map(|coordinate| fp2(200 + (repetition * 31 + coordinate) as u64))
                    .collect()
            }),
            auxiliary_points: std::array::from_fn(|repetition| {
                (0..C6_RESIDUAL_AUXILIARY_ROUNDS)
                    .map(|coordinate| fp2(400 + (repetition * 31 + coordinate) as u64))
                    .collect()
            }),
            terminal_claims,
            output_beta: fp2(509),
            relation_root: [9; 32],
        })
        .unwrap()
    }

    fn role_targets(values: &[Fp2]) -> (Vec<ProverAuthed>, Vec<VerifierKey>) {
        let delta = fp2(P - 91);
        let provider = values
            .iter()
            .enumerate()
            .map(|(index, value)| ProverAuthed::new(*value, fp2(index as u64 + 601)))
            .collect::<Vec<_>>();
        let verifier =
            provider.iter().map(|target| VerifierKey::new(target.m + delta * target.x)).collect();
        (provider, verifier)
    }

    #[test]
    fn all_six_role_typed_statements_bind_exact_censuses_without_hashing_keys() {
        for (component, relation, values) in [
            (
                C61NativeComponent::Model,
                C61TypedNativeRelationStatement::Model(opening_statement(
                    11,
                    14,
                    C61_MODEL_OPENING_TARGETS,
                )),
                (0..C61_MODEL_OPENING_TARGETS).map(|index| fp2(index as u64 + 1)).collect(),
            ),
            (
                C61NativeComponent::Embedding,
                C61TypedNativeRelationStatement::Embedding(opening_statement(
                    21,
                    14,
                    C61_EMBEDDING_OPENING_TARGETS,
                )),
                (0..C61_EMBEDDING_OPENING_TARGETS).map(|index| fp2(index as u64 + 301)).collect(),
            ),
            {
                let compiler = compiler_statement();
                (
                    C61NativeComponent::Compiler,
                    C61TypedNativeRelationStatement::Compiler(Box::new(compiler.clone())),
                    compiler.terminal_claims.to_vec(),
                )
            },
        ] {
            for repetition in 0..2 {
                let public = C61TypedNativeChainPublicStatement::new(
                    C61NativeChainId { component, repetition },
                    relation.clone(),
                )
                .unwrap();
                let (provider_targets, verifier_keys) = role_targets(&values);
                let provider =
                    C61NativeProverChainStatement::new(public.clone(), provider_targets).unwrap();
                let verifier =
                    C61NativeVerifierChainStatement::new(public.clone(), verifier_keys).unwrap();
                assert_eq!(provider.public().digest(), verifier.public().digest());
                assert_eq!(provider.targets().len(), public.target_count());
                assert_eq!(verifier.target_keys().len(), public.target_count());

                let changed_keys = verifier
                    .target_keys()
                    .iter()
                    .enumerate()
                    .map(|(index, key)| VerifierKey::new(key.k + fp2(index as u64 + 701)))
                    .collect();
                let changed_verifier =
                    C61NativeVerifierChainStatement::new(public.clone(), changed_keys).unwrap();
                assert_eq!(changed_verifier.public().digest(), public.digest());
            }
        }
    }

    #[test]
    fn compiler_statement_rejects_terminal_point_order_binding_and_target_mutations() {
        let compiler = compiler_statement();
        compiler.validate().unwrap();
        assert_eq!(
            compiler.functional_fold,
            fold_terminal_claims(&compiler.terminal_claims, compiler.output_beta)
        );
        assert_eq!(
            compiler.terminal_claims_digest,
            terminal_claims_digest(&compiler.terminal_claims)
        );

        let mut changed_terminal = compiler.clone();
        changed_terminal.terminal_claims[0] += Fp2::ONE;
        assert!(changed_terminal.validate().is_err());

        let mut changed_fold = compiler.clone();
        changed_fold.functional_fold += Fp2::ONE;
        assert!(changed_fold.validate().is_err());

        let mut changed_point = compiler.clone();
        changed_point.leaf_points[0][0] += Fp2::ONE;
        assert_ne!(compiler.digest().unwrap(), changed_point.digest().unwrap());

        let mut swapped_points = compiler.clone();
        swapped_points.leaf_points.swap(0, 1);
        assert_ne!(compiler.digest().unwrap(), swapped_points.digest().unwrap());

        let mut changed_relation_root = compiler.clone();
        changed_relation_root.relation_root[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_relation_root.digest().unwrap());

        let mut changed_terminal_metadata = compiler.clone();
        changed_terminal_metadata.terminal_metadata_digest[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_terminal_metadata.digest().unwrap());

        let public = C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
            C61TypedNativeRelationStatement::Compiler(Box::new(compiler.clone())),
        )
        .unwrap();
        let (mut provider_targets, verifier_keys) = role_targets(&compiler.terminal_claims);
        provider_targets[3].x += Fp2::ONE;
        assert!(C61NativeProverChainStatement::new(public.clone(), provider_targets).is_err());
        assert!(C61NativeVerifierChainStatement::new(
            public.clone(),
            verifier_keys[..C61_COMPILER_TERMINAL_TARGETS - 1].to_vec(),
        )
        .is_err());
        assert!(C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 },
            C61TypedNativeRelationStatement::Compiler(Box::new(compiler)),
        )
        .is_err());
    }

    #[test]
    fn sparse_compiler_oracles_points_and_role_targets_are_exact_and_typed() {
        let compiler = compiler_statement();
        let compiler_digest = compiler.digest().unwrap();
        let input_point: Vec<Fp2> = (0..C61_SPARSE_RATIONAL_INPUT_LOG2)
            .map(|coordinate| fp2(900 + u64::from(coordinate)))
            .collect();
        let public = C61SparseRationalCompilerOpeningStatement::new(
            compiler_digest,
            [61; 32],
            [62; 32],
            compiler.sparse_oracles,
            &input_point,
        )
        .unwrap();
        public.validate().unwrap();
        assert_eq!(public.points.response().len(), C61_SPARSE_RATIONAL_RESPONSE_OPENINGS);
        assert_eq!(public.points.plan().len(), C61_SPARSE_RATIONAL_PLAN_OPENINGS);

        let proto_points = volta_proto::c6_residual::C6SparseRationalPhysicalOpeningPoints::new(
            C61_SPARSE_RATIONAL_INPUT_LOG2,
            compiler.sparse_oracles.response.commitment_root,
            compiler.sparse_oracles.plan.commitment_root,
            &input_point,
        )
        .unwrap();
        assert_eq!(public.points.response(), proto_points.response());
        assert_eq!(public.points.plan(), proto_points.plan());

        let response_values: [Fp2; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] =
            std::array::from_fn(|index| fp2(1_000 + index as u64));
        let plan_values: [Fp2; C61_SPARSE_RATIONAL_PLAN_OPENINGS] =
            std::array::from_fn(|index| fp2(1_100 + index as u64));
        let (response_targets, response_keys) = {
            let (targets, keys) = role_targets(&response_values);
            (targets.try_into().unwrap(), keys.try_into().unwrap())
        };
        let (plan_targets, plan_keys) = {
            let (targets, keys) = role_targets(&plan_values);
            (targets.try_into().unwrap(), keys.try_into().unwrap())
        };
        let prover = C61SparseRationalProverOpeningStatement::new(
            public.clone(),
            response_targets,
            plan_targets,
        )
        .unwrap();
        let verifier = C61SparseRationalVerifierOpeningStatement::new(
            public.clone(),
            response_keys,
            plan_keys,
        )
        .unwrap();
        assert_eq!(prover.public.digest(), verifier.public.digest());
        let semantic_targets = fold_c61_sparse_response_prover_targets(&prover.response_targets);
        let semantic_keys = fold_c61_sparse_response_verifier_keys(&verifier.response_target_keys);
        let extension_generator = Fp2::new(Fp::ZERO, Fp::ONE);
        for index in 0..C61_SPARSE_RATIONAL_SEMANTIC_RESPONSE_OPENINGS {
            assert_eq!(
                semantic_targets[index].x,
                response_values[2 * index] + extension_generator * response_values[2 * index + 1],
            );
            assert_eq!(
                semantic_keys[index].k,
                response_keys[2 * index].k + extension_generator * response_keys[2 * index + 1].k,
            );
        }
        assert!(C61SparseRationalCompilerOracles::new(
            commitment(41, C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2),
            commitment(51, C61_SPARSE_RATIONAL_PLAN_PACKED_LOG2),
        )
        .is_err());

        let mut changed_key_verifier = verifier.clone();
        changed_key_verifier.response_target_keys[0] =
            VerifierKey::new(changed_key_verifier.response_target_keys[0].k + Fp2::ONE);
        assert_eq!(changed_key_verifier.public.digest(), public.digest());

        let mut changed_layout = compiler.sparse_oracles;
        changed_layout.response_layout_digest[0] ^= 1;
        assert!(changed_layout.validate().is_err());
        let mut changed_points = public.clone();
        changed_points.points.response.swap(0, 1);
        assert!(changed_points.validate().is_err());
        let mut changed_root = compiler.clone();
        changed_root.sparse_oracles.response.commitment_root[0] ^= 1;
        assert_ne!(compiler.digest().unwrap(), changed_root.digest().unwrap());
    }

    #[test]
    fn production_blind_arithmetic_codec_census_is_exact() {
        let tree_bytes = |depth: u64| 16 * (depth * depth + 6 * depth + 3);
        assert_eq!(
            C61_SPARSE_RATIONAL_BLIND_PRODUCTION_GKR_BYTES,
            C61_SPARSE_RATIONAL_BLIND_PRODUCTION_DEPTHS
                .into_iter()
                .map(|depth| tree_bytes(u64::from(depth)))
                .sum::<u64>(),
        );
        assert_eq!(C61_SPARSE_RATIONAL_BLIND_PRODUCTION_JOINT_BYTES, 16 * (3 + 25 * 8));
        assert_eq!(
            C61_SPARSE_RATIONAL_BLIND_PRODUCTION_ARITHMETIC_BYTES,
            C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES
                + C61_SPARSE_RATIONAL_BLIND_PRODUCTION_GKR_BYTES
                + C61_SPARSE_RATIONAL_BLIND_PRODUCTION_JOINT_BYTES
                + C61_SPARSE_RATIONAL_BLIND_TERMINAL_BYTES
                + C61_SPARSE_RATIONAL_BLIND_PRODUCT_BYTES,
        );
        assert!(
            C61_SPARSE_RATIONAL_BLIND_PRODUCTION_ARITHMETIC_BYTES
                < C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_MAX_BYTES
        );
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn physical_limb_targets_close_the_blind_sparse_terminal() {
        use volta_mac::{
            zero_batch_exchange, C6OperationPlanTerminalMetadata, C6TraceSourceManifest,
            CorrelationStream, VerifierCtx,
        };
        use volta_proto::c6_residual::*;
        use volta_proto::logup::Doms;
        use volta_proto::{prod_batch_prover, prod_batch_verify};

        let direct = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let topology = direct.operation_plan().topology();
        let source_manifest = C6TraceSourceManifest::new(
            topology.source_count,
            topology.source_schedule_digest,
            direct.manifest().product_mask_sources().to_vec(),
        )
        .unwrap();
        let terminal_metadata = C6OperationPlanTerminalMetadata::from_installed(
            direct.operation_plan(),
            &source_manifest,
        )
        .unwrap();
        let leaf_point = [fp2(2), fp2(3), fp2(5), fp2(7), fp2(11), fp2(13), fp2(17)];
        let output_beta = fp2(191);
        let lanes: [C6ResidualFoldedTerminalAdjointLaneReference;
            C6_RESIDUAL_PROOF_REPETITIONS as usize] = std::array::from_fn(|repetition| {
            compile_c6_residual_folded_terminal_adjoint_lane_reference(
                direct.operation_plan(),
                &terminal_metadata,
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                repetition as u8,
                &leaf_point,
                output_beta,
            )
            .unwrap()
        });
        let sparse_challenges = C6ResidualSparseRationalChallenges::new(
            topology,
            fp2(197),
            fp2(199),
            fp2(211),
            fp2(223),
        )
        .unwrap();
        let relation = compile_c6_residual_sparse_rational_relation_reference(
            direct.operation_plan(),
            &terminal_metadata,
            direct.extraction(),
            direct.runtime(),
            direct.relation(),
            [&lanes[0], &lanes[1]],
            sparse_challenges,
            output_beta,
        )
        .unwrap();
        let packed = compile_c6_sparse_rational_packed_oracle_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            [&lanes[0], &lanes[1]],
        )
        .unwrap();

        let correlation_seed = [0x81; 32];
        let transcript_seed = [0x82; 32];
        let delta = fp2(P - 103);
        let mut prover_stream = CorrelationStream::new(correlation_seed);
        let mut prover_doms = Doms::new(50_000);
        let mut prover_transcript = Transcript::new(transcript_seed);
        let mut prover_products = Vec::new();
        let mut prover_zeros = Vec::new();
        let (gkr_proof, leaf_claims) = prove_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            direct.extraction(),
            direct.runtime(),
            &relation,
            &mut prover_stream,
            &mut prover_doms,
            &mut prover_transcript,
            &mut volta_proto::logup::Counters::default(),
            &mut prover_products,
            &mut prover_zeros,
        )
        .unwrap();
        let mut verifier = VerifierCtx::new(correlation_seed, delta);
        let mut verifier_doms = Doms::new(50_000);
        let mut verifier_transcript = Transcript::new(transcript_seed);
        let mut verifier_products = Vec::new();
        let mut verifier_zeros = Vec::new();
        let leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_reference(
            direct.operation_plan(),
            &relation,
            &gkr_proof,
            &mut verifier,
            &mut verifier_doms,
            &mut verifier_transcript,
            &mut verifier_products,
            &mut verifier_zeros,
        )
        .unwrap()
        .unwrap();
        let (rounds, prover_terminal) =
            prove_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
                direct.operation_plan(),
                &relation,
                &packed,
                &leaf_claims,
                &mut prover_stream,
                &mut prover_doms,
                &mut prover_transcript,
            )
            .unwrap();
        let verifier_terminal =
            verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
                direct.operation_plan(),
                &relation,
                packed.base_domain_log2(),
                packed.response_digest(),
                packed.plan_digest(),
                &leaf_keys,
                &rounds,
                &mut verifier,
                &mut verifier_doms,
                &mut verifier_transcript,
            )
            .unwrap()
            .unwrap();
        let physical_points =
            packed.physical_opening_points(prover_terminal.points().input_point()).unwrap();
        let physical_response =
            packed.evaluate_physical_response_openings(&physical_points).unwrap();
        let physical_plan = packed.evaluate_physical_plan_openings(&physical_points).unwrap();
        let target_values =
            physical_response.iter().chain(&physical_plan).copied().collect::<Vec<_>>();
        let target_domain = prover_doms.take(1);
        assert_eq!(target_domain, verifier_doms.take(1));
        let masks = prover_stream.draw_fulls(target_domain, target_values.len());
        prover_stream.record_c6_fullfield_plaintexts(target_domain, &target_values).unwrap();
        let corrections = target_values
            .iter()
            .zip(&masks)
            .map(|(&value, mask)| value - mask.x)
            .collect::<Vec<_>>();
        let keys = verifier.correct_full_verifier_keys(target_domain, &corrections);
        let response_targets: [ProverAuthed; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] = masks
            [..C61_SPARSE_RATIONAL_RESPONSE_OPENINGS]
            .iter()
            .zip(physical_response)
            .map(|(mask, value)| mask.authenticate(value))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let plan_targets: [ProverAuthed; C61_SPARSE_RATIONAL_PLAN_OPENINGS] = masks
            [C61_SPARSE_RATIONAL_RESPONSE_OPENINGS..]
            .iter()
            .zip(physical_plan)
            .map(|(mask, value)| mask.authenticate(value))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let response_keys: [VerifierKey; C61_SPARSE_RATIONAL_RESPONSE_OPENINGS] =
            keys[..C61_SPARSE_RATIONAL_RESPONSE_OPENINGS].try_into().unwrap();
        let plan_keys: [VerifierKey; C61_SPARSE_RATIONAL_PLAN_OPENINGS] =
            keys[C61_SPARSE_RATIONAL_RESPONSE_OPENINGS..].try_into().unwrap();
        assert_eq!(
            fold_c61_sparse_response_prover_targets(&response_targets).map(|target| target.x),
            packed.evaluate_response_openings(prover_terminal.points()).unwrap(),
        );
        let mut changed_targets = response_targets;
        changed_targets[0].x += Fp2::ONE;
        assert!(finish_c61_sparse_rational_blind_physical_terminal_prover(
            prover_terminal.clone(),
            &changed_targets,
            &plan_targets,
            &mut prover_stream,
            &mut prover_doms,
            &mut prover_transcript,
            &mut prover_products,
            &mut prover_zeros,
        )
        .is_err());
        let terminal_proof = finish_c61_sparse_rational_blind_physical_terminal_prover(
            prover_terminal,
            &response_targets,
            &plan_targets,
            &mut prover_stream,
            &mut prover_doms,
            &mut prover_transcript,
            &mut prover_products,
            &mut prover_zeros,
        )
        .unwrap();
        finish_c61_sparse_rational_blind_physical_terminal_verifier(
            verifier_terminal,
            &response_keys,
            &plan_keys,
            &terminal_proof,
            &mut verifier,
            &mut verifier_doms,
            &mut verifier_transcript,
            &mut verifier_products,
            &mut verifier_zeros,
        )
        .unwrap();
        let chi = prover_transcript.challenge_fp2();
        assert_eq!(chi, verifier_transcript.challenge_fp2());
        let product_mask = prover_stream.draw_product_mask(60_000, prover_products.len());
        let product_key =
            verifier.expand_product_mask_verifier_key(60_000, verifier_products.len());
        let product_proof =
            prod_batch_prover(&prover_products, chi, product_mask, &mut prover_transcript);
        assert!(prod_batch_verify(&verifier_products, product_key, delta, chi, &product_proof,));
        let expected_arithmetic_bytes = C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES
            + gkr_proof.bytes()
            + rounds.bytes()
            + terminal_proof.bytes()
            + C61_SPARSE_RATIONAL_BLIND_PRODUCT_BYTES;
        let arithmetic_proof = C61SparseRationalBlindArithmeticProof::new(
            direct.operation_plan(),
            relation.digest(),
            gkr_proof,
            rounds,
            terminal_proof,
            product_proof,
        )
        .unwrap();
        let encoded = arithmetic_proof.encode(direct.operation_plan(), relation.digest()).unwrap();
        assert_eq!(encoded.len() as u64, expected_arithmetic_bytes);
        assert_eq!(
            arithmetic_proof.encoded_len(direct.operation_plan(), relation.digest()).unwrap(),
            expected_arithmetic_bytes,
        );
        let decoded = C61SparseRationalBlindArithmeticProof::decode(
            direct.operation_plan(),
            relation.digest(),
            &encoded,
        )
        .unwrap();
        assert_eq!(decoded, arithmetic_proof);
        let rejects = |payload: Vec<u8>| {
            C61SparseRationalBlindArithmeticProof::decode(
                direct.operation_plan(),
                relation.digest(),
                &payload,
            )
            .is_err()
        };
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = encoded.clone();
        bad_version[8] ^= 1;
        let mut bad_base_dimension = encoded.clone();
        bad_base_dimension[10] ^= 1;
        let mut bad_subcheck_count = encoded.clone();
        bad_subcheck_count[11] ^= 1;
        let mut bad_depth = encoded.clone();
        bad_depth[12] ^= 1;
        let mut bad_reserved = encoded.clone();
        bad_reserved[19] ^= 1;
        let mut bad_relation = encoded.clone();
        bad_relation[20] ^= 1;
        let mut bad_gkr_len = encoded.clone();
        bad_gkr_len[52] ^= 1;
        let mut bad_joint_len = encoded.clone();
        bad_joint_len[56] ^= 1;
        let mut noncanonical = encoded.clone();
        noncanonical[C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_HEADER_BYTES as usize
            ..C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_HEADER_BYTES as usize + 8]
            .copy_from_slice(&P.to_le_bytes());
        let digest_offset =
            noncanonical.len() - C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_DIGEST_BYTES as usize;
        let digest = sparse_blind_arithmetic_proof_digest(&noncanonical[..digest_offset]);
        noncanonical[digest_offset..].copy_from_slice(&digest);
        let mut trailing = encoded.clone();
        trailing.push(0);
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!([
            bad_magic,
            bad_version,
            bad_base_dimension,
            bad_subcheck_count,
            bad_depth,
            bad_reserved,
            bad_relation,
            bad_gkr_len,
            bad_joint_len,
            noncanonical,
            trailing,
            truncated,
        ]
        .into_iter()
        .all(rejects));
        assert!(zero_batch_exchange(
            &prover_zeros,
            &verifier_zeros,
            &mut prover_stream,
            &mut verifier,
            60_001,
            &mut prover_transcript,
        ));
    }

    #[test]
    fn committed_openings_bind_commitment_point_order_and_component() {
        let model = opening_statement(31, 14, C61_MODEL_OPENING_TARGETS);
        let public = C61TypedNativeChainPublicStatement::new(
            C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 },
            C61TypedNativeRelationStatement::Model(model.clone()),
        )
        .unwrap();

        let mut changed_commitment = model.clone();
        changed_commitment.commitment.commitment_root[0] ^= 1;
        let changed_commitment = C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(changed_commitment),
        )
        .unwrap();
        assert_ne!(public.digest(), changed_commitment.digest());

        let mut reordered = model.clone();
        reordered.ordered_points.swap(0, 1);
        let reordered = C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(reordered),
        )
        .unwrap();
        assert_ne!(public.digest(), reordered.digest());

        let mut malformed = model;
        malformed.ordered_points.pop();
        assert!(C61TypedNativeChainPublicStatement::new(
            public.id(),
            C61TypedNativeRelationStatement::Model(malformed),
        )
        .is_err());
    }
}

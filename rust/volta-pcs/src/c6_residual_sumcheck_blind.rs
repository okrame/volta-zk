//! C6RSC3: dual-tape blind residual sumcheck.
//!
//! C6RSC2 remains the immutable clear/scaled arithmetic reference.  This
//! separately versioned layer authenticates every hidden round value on both
//! residual MAC tapes, checks the first-family split before its challenge,
//! closes the eight quadratic terminal factors with one ProductClosure per
//! tape, and closes the two terminal rows with one ZeroBatch per tape.
//!
//! The scaled reference prover deliberately calls C6RSC2 only as an
//! arithmetic oracle.  Production T1 must replace that oracle with the fused
//! semantic compiler; no coefficient-array digest appears in the C6RSC3
//! statement or wire.

use std::{array, fmt};

use volta_field::{Fp, Fp2, P};
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_prover,
    zero_open_verify, CorrelationStream, ProductMaskCorr, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey, RESERVED_DOMAIN_BITS,
};
#[cfg(feature = "c6-trace")]
use volta_mac::{
    C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan, C6RuntimeInstanceValues,
};
use volta_proto::logup::lagrange4;
use volta_proto::mle::{eval_mle, lagrange3};
use volta_proto::prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
use volta_proto::C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS;
#[cfg(feature = "c6-trace")]
use volta_proto::{
    compile_c6_residual_fused_first_round, compile_c6_residual_fused_folded_coefficients,
    compile_c6_residual_fused_terminal_coefficients, C6CompiledLinearResidual,
    C6ResidualFusedCoefficientArena, C6ResidualFusedCoefficientFamily,
    C6ResidualFusedFoldedCoefficients, C6ResidualFusedWitnessView, C6ResidualRelationChallenges,
};

use crate::c6_residual_sumcheck::{
    prepare_residual_sumcheck_prover_round_state, C6ResidualOpeningClaim, C6ResidualSumcheckFamily,
    C6ResidualSumcheckProverRoundState, C6ResidualSumcheckRepetitionProof,
    C6ResidualSumcheckStatement, C6ResidualSumcheckTerm, C6ResidualSumcheckWitness,
    C6ResidualTableRef, C6_RESIDUAL_AUXILIARY_ROUNDS, C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION,
    C6_RESIDUAL_LEAF_ROUNDS, C6_RESIDUAL_LEAF_TABLES_PER_REPETITION,
    C6_RESIDUAL_SUMCHECK_REPETITIONS, C6_RESIDUAL_TABLES_PER_REPETITION,
};

const PROOF_MAGIC: [u8; 8] = *b"C6RSC3\0\0";
const PROOF_VERSION: u16 = 3;
const PROOF_DOMAIN: &str = "volta-zk/c6/residual-sumcheck-proof/v3";
const STATEMENT_DOMAIN: &str = "volta-zk/c6/residual-sumcheck-statement/v3";
const PROOF_FIXED_FRAMING_BYTES: u64 = 116;
const MAC_TAPES: usize = 2;
const FP2_BYTES: u64 = 16;
const TERMINAL_PRODUCTS: usize = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len();
const TERMINAL_SCALARS_PER_TAPE: u64 = 1 + TERMINAL_PRODUCTS as u64 + 2 + 2;
const PENDING_CORRECTION_BYTES_PER_CLAIM: u64 = MAC_TAPES as u64 * FP2_BYTES;

pub const C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION: u64 = 3
    + 2 * (C6_RESIDUAL_LEAF_ROUNDS as u64 - 1)
    + 4
    + 3 * (C6_RESIDUAL_AUXILIARY_ROUNDS as u64 - 1);
const CORE_FULL_CORRELATIONS_PER_REPETITION_PER_TAPE: u64 =
    C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION + TERMINAL_PRODUCTS as u64 + 1 + 1;
pub const C6_RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE: u64 =
    C6_RESIDUAL_SUMCHECK_REPETITIONS as u64 * CORE_FULL_CORRELATIONS_PER_REPETITION_PER_TAPE;
pub const C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE: u64 =
    C6_RESIDUAL_SUMCHECK_REPETITIONS as u64 * C6_RESIDUAL_TABLES_PER_REPETITION as u64;
pub const C6_RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE: u64 =
    C6_RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE
        + C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE;
pub const C6_RESIDUAL_BLIND_PROOF_BYTES: u64 = PROOF_FIXED_FRAMING_BYTES
    + C6_RESIDUAL_SUMCHECK_REPETITIONS as u64
        * MAC_TAPES as u64
        * (C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION + TERMINAL_SCALARS_PER_TAPE)
        * FP2_BYTES;

type Result<T> = std::result::Result<T, C6BlindResidualError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualError(String);

impl C6BlindResidualError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6BlindResidualError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6BlindResidualError {}

fn clear_error(error: impl fmt::Display) -> C6BlindResidualError {
    C6BlindResidualError::new(error.to_string())
}

/// C6RSC3 statement wrapper.  `semantic_compiler_digest` commits to the
/// installed root/manifest/topology/source schedule and runtime public frame.
/// The local C6RSC2 statement is retained only for the scaled differential;
/// its coefficient-array digest is intentionally absent from `digest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualStatement {
    reference: C6ResidualSumcheckStatement,
    semantic_compiler_digest: [u8; 32],
    digest: [u8; 32],
}

impl C6BlindResidualStatement {
    pub fn repetition(&self) -> u8 {
        self.reference.repetition()
    }

    pub fn target(&self) -> Fp2 {
        self.reference.target()
    }

    pub fn semantic_compiler_digest(&self) -> [u8; 32] {
        self.semantic_compiler_digest
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    fn reference(&self) -> &C6ResidualSumcheckStatement {
        &self.reference
    }

    pub fn auxiliary_activation_round(&self) -> usize {
        self.reference.auxiliary_activation_round()
    }

    fn validate(&self) -> Result<()> {
        validate_reference_topology(&self.reference)?;
        if self.semantic_compiler_digest == [0; 32]
            || self.digest == [0; 32]
            || self.digest
                != semantic_statement_digest(&self.reference, self.semantic_compiler_digest)
        {
            return Err(C6BlindResidualError::new("C6RSC3 semantic statement binding mismatch"));
        }
        Ok(())
    }
}

pub fn prepare_c6_blind_residual_statement(
    reference: C6ResidualSumcheckStatement,
    semantic_compiler_digest: [u8; 32],
) -> Result<C6BlindResidualStatement> {
    validate_reference_topology(&reference)?;
    if semantic_compiler_digest == [0; 32] {
        return Err(C6BlindResidualError::new("C6RSC3 semantic compiler digest is zero"));
    }
    let digest = semantic_statement_digest(&reference, semantic_compiler_digest);
    let statement = C6BlindResidualStatement { reference, semantic_compiler_digest, digest };
    statement.validate()?;
    Ok(statement)
}

fn validate_reference_topology(statement: &C6ResidualSumcheckStatement) -> Result<()> {
    let leaf = statement.leaf();
    let auxiliary = statement.auxiliary();
    if leaf.rounds() == 0
        || auxiliary.rounds() == 0
        || leaf.rounds() < auxiliary.rounds()
        || leaf.tables().len() != C6_RESIDUAL_LEAF_TABLES_PER_REPETITION
        || auxiliary.tables().len() != C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION
        || leaf.terms().len() != C6_RESIDUAL_LEAF_TABLES_PER_REPETITION
        || auxiliary.terms().len()
            != C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION + TERMINAL_PRODUCTS
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 reference topology does not match the frozen owner census",
        ));
    }
    for (index, term) in leaf.terms().iter().enumerate() {
        if !matches!(term, C6ResidualSumcheckTerm::Linear { table, .. }
            if usize::from(*table) == index)
        {
            return Err(C6BlindResidualError::new("C6RSC3 leaf factor topology is noncanonical"));
        }
    }
    for (index, term) in
        auxiliary.terms().iter().take(C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION).enumerate()
    {
        if !matches!(term, C6ResidualSumcheckTerm::Linear { table, .. }
            if usize::from(*table) == index)
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 auxiliary linear topology is noncanonical",
            ));
        }
    }
    for (term, expected) in auxiliary
        .terms()
        .iter()
        .skip(C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION)
        .zip(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS)
    {
        if !matches!(term, C6ResidualSumcheckTerm::Quadratic { lhs, rhs, .. }
            if (*lhs, *rhs) == expected)
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 auxiliary quadratic topology is noncanonical",
            ));
        }
    }
    Ok(())
}

fn semantic_statement_digest(
    reference: &C6ResidualSumcheckStatement,
    semantic_compiler_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(&semantic_compiler_digest);
    hasher.update(&[reference.repetition()]);
    hash_fp2(&mut hasher, reference.target());
    for family in [reference.leaf(), reference.auxiliary()] {
        hasher.update(&[family.family() as u8]);
        hasher.update(&(family.rounds() as u64).to_le_bytes());
        hasher.update(&(family.tables().len() as u64).to_le_bytes());
        for table in family.tables() {
            hasher.update(&table.cohort_id.to_le_bytes());
            hasher.update(&table.slot.to_le_bytes());
        }
        hasher.update(&(family.terms().len() as u64).to_le_bytes());
        for term in family.terms() {
            match term {
                C6ResidualSumcheckTerm::Linear { table, coefficients } => {
                    hasher.update(&[1, *table, 0]);
                    hasher.update(&(coefficients.len() as u64).to_le_bytes());
                }
                C6ResidualSumcheckTerm::Quadratic { lhs, rhs, coefficients } => {
                    hasher.update(&[2, *lhs, *rhs]);
                    hasher.update(&(coefficients.len() as u64).to_le_bytes());
                }
            }
        }
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualTapeProof {
    leaf_round_corrections: Vec<Vec<Fp2>>,
    auxiliary_round_corrections: Vec<Vec<Fp2>>,
    activation_tag: Fp2,
    product_corrections: [Fp2; TERMINAL_PRODUCTS],
    product_m0: Fp2,
    product_m1: Fp2,
    zero_mask_correction: Fp2,
    zero_tag: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualRepetitionProof {
    repetition: u8,
    statement_digest: [u8; 32],
    tapes: [C6BlindResidualTapeProof; MAC_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualSumcheckProof {
    repetitions: Vec<C6BlindResidualRepetitionProof>,
}

impl C6BlindResidualSumcheckProof {
    pub fn encode(&self, statements: &[C6BlindResidualStatement]) -> Result<Vec<u8>> {
        self.validate_shape(statements)?;
        let encoded_len = blind_residual_sumcheck_encoded_len(statements)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(encoded_len)
                .map_err(|_| C6BlindResidualError::new("C6RSC3 proof length exceeds usize"))?,
        );
        bytes.extend_from_slice(&PROOF_MAGIC);
        bytes.extend_from_slice(&PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.repetitions.len() as u16).to_le_bytes());
        for (repetition, statement) in self.repetitions.iter().zip(statements) {
            bytes.push(repetition.repetition);
            bytes.push(
                u8::try_from(statement.reference.leaf().rounds())
                    .map_err(|_| C6BlindResidualError::new("C6RSC3 leaf rounds exceed codec"))?,
            );
            bytes.push(
                u8::try_from(statement.reference.auxiliary().rounds()).map_err(|_| {
                    C6BlindResidualError::new("C6RSC3 auxiliary rounds exceed codec")
                })?,
            );
            bytes.push(0);
            bytes.extend_from_slice(&repetition.statement_digest);
            for tape in &repetition.tapes {
                for round in &tape.leaf_round_corrections {
                    for correction in round {
                        encode_fp2(&mut bytes, *correction);
                    }
                }
                for round in &tape.auxiliary_round_corrections {
                    for correction in round {
                        encode_fp2(&mut bytes, *correction);
                    }
                }
                encode_fp2(&mut bytes, tape.activation_tag);
                for correction in tape.product_corrections {
                    encode_fp2(&mut bytes, correction);
                }
                encode_fp2(&mut bytes, tape.product_m0);
                encode_fp2(&mut bytes, tape.product_m1);
                encode_fp2(&mut bytes, tape.zero_mask_correction);
                encode_fp2(&mut bytes, tape.zero_tag);
            }
        }
        bytes.extend_from_slice(&proof_digest(&bytes));
        if bytes.len() as u64 != encoded_len {
            return Err(C6BlindResidualError::new(
                "C6RSC3 encoder length disagrees with strict formula",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(statements: &[C6BlindResidualStatement], bytes: &[u8]) -> Result<Self> {
        validate_statement_pair(statements)?;
        if bytes.len() as u64 != blind_residual_sumcheck_encoded_len(statements)? {
            return Err(C6BlindResidualError::new("C6RSC3 strict proof length mismatch"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != PROOF_MAGIC {
            return Err(C6BlindResidualError::new("bad C6RSC3 proof magic"));
        }
        if cursor.u16()? != PROOF_VERSION {
            return Err(C6BlindResidualError::new("unknown C6RSC3 proof version"));
        }
        if cursor.u16()? as usize != C6_RESIDUAL_SUMCHECK_REPETITIONS {
            return Err(C6BlindResidualError::new("C6RSC3 repetition count mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
        for (index, statement) in statements.iter().enumerate() {
            let repetition = cursor.u8()?;
            let leaf_rounds = cursor.u8()? as usize;
            let auxiliary_rounds = cursor.u8()? as usize;
            if usize::from(repetition) != index
                || leaf_rounds != statement.reference.leaf().rounds()
                || auxiliary_rounds != statement.reference.auxiliary().rounds()
                || cursor.u8()? != 0
            {
                return Err(C6BlindResidualError::new("C6RSC3 repetition header mismatch"));
            }
            let statement_digest = cursor.digest()?;
            if statement_digest != statement.digest {
                return Err(C6BlindResidualError::new("C6RSC3 proof/semantic statement mismatch"));
            }
            let mut tapes = Vec::with_capacity(MAC_TAPES);
            for _ in 0..MAC_TAPES {
                let mut leaf_round_corrections = Vec::with_capacity(leaf_rounds);
                for round in 0..leaf_rounds {
                    leaf_round_corrections.push(cursor.fp2_vec(if round == 0 { 3 } else { 2 })?);
                }
                let mut auxiliary_round_corrections = Vec::with_capacity(auxiliary_rounds);
                for round in 0..auxiliary_rounds {
                    auxiliary_round_corrections.push(cursor.fp2_vec(if round == 0 {
                        4
                    } else {
                        3
                    })?);
                }
                let activation_tag = cursor.fp2()?;
                let product_corrections: [Fp2; TERMINAL_PRODUCTS] = cursor
                    .fp2_vec(TERMINAL_PRODUCTS)?
                    .try_into()
                    .map_err(|_| C6BlindResidualError::new("C6RSC3 product correction census"))?;
                tapes.push(C6BlindResidualTapeProof {
                    leaf_round_corrections,
                    auxiliary_round_corrections,
                    activation_tag,
                    product_corrections,
                    product_m0: cursor.fp2()?,
                    product_m1: cursor.fp2()?,
                    zero_mask_correction: cursor.fp2()?,
                    zero_tag: cursor.fp2()?,
                });
            }
            repetitions.push(C6BlindResidualRepetitionProof {
                repetition,
                statement_digest,
                tapes: tapes
                    .try_into()
                    .map_err(|_| C6BlindResidualError::new("C6RSC3 tape census mismatch"))?,
            });
        }
        let digest_offset = cursor.position();
        let encoded_digest = cursor.digest()?;
        if !cursor.is_eof() || encoded_digest != proof_digest(&bytes[..digest_offset]) {
            return Err(C6BlindResidualError::new(
                "noncanonical, corrupt or trailing C6RSC3 proof",
            ));
        }
        let proof = Self { repetitions };
        proof.validate_shape(statements)?;
        Ok(proof)
    }

    pub fn encoded_len(&self, statements: &[C6BlindResidualStatement]) -> Result<u64> {
        self.validate_shape(statements)?;
        blind_residual_sumcheck_encoded_len(statements)
    }

    fn validate_shape(&self, statements: &[C6BlindResidualStatement]) -> Result<()> {
        validate_statement_pair(statements)?;
        if self.repetitions.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
            return Err(C6BlindResidualError::new("C6RSC3 proof repetition mismatch"));
        }
        for (index, (proof, statement)) in self.repetitions.iter().zip(statements).enumerate() {
            if usize::from(proof.repetition) != index || proof.statement_digest != statement.digest
            {
                return Err(C6BlindResidualError::new("C6RSC3 proof shape mismatch"));
            }
            for tape in &proof.tapes {
                validate_round_correction_shape(
                    &tape.leaf_round_corrections,
                    statement.reference.leaf().rounds(),
                    3,
                    2,
                )?;
                validate_round_correction_shape(
                    &tape.auxiliary_round_corrections,
                    statement.reference.auxiliary().rounds(),
                    4,
                    3,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_round_correction_shape(
    rounds: &[Vec<Fp2>],
    expected_rounds: usize,
    first_values: usize,
    later_values: usize,
) -> Result<()> {
    if rounds.len() != expected_rounds
        || rounds.iter().enumerate().any(|(round, values)| {
            values.len() != if round == 0 { first_values } else { later_values }
        })
    {
        return Err(C6BlindResidualError::new("C6RSC3 compressed round correction shape mismatch"));
    }
    Ok(())
}

pub fn blind_residual_sumcheck_encoded_len(statements: &[C6BlindResidualStatement]) -> Result<u64> {
    validate_statement_pair(statements)?;
    let scalar_count = statements.iter().try_fold(0u64, |total, statement| {
        let round_values = round_values_per_repetition(statement)?;
        total
            .checked_add(MAC_TAPES as u64 * (round_values + TERMINAL_SCALARS_PER_TAPE))
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 scalar count overflows"))
    })?;
    PROOF_FIXED_FRAMING_BYTES
        .checked_add(
            scalar_count
                .checked_mul(FP2_BYTES)
                .ok_or_else(|| C6BlindResidualError::new("C6RSC3 byte count overflows"))?,
        )
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3 byte count overflows"))
}

pub const fn production_c6_blind_residual_sumcheck_encoded_len() -> u64 {
    C6_RESIDUAL_BLIND_PROOF_BYTES
}

fn round_values_per_repetition(statement: &C6BlindResidualStatement) -> Result<u64> {
    let leaf_rounds = statement.reference.leaf().rounds();
    let auxiliary_rounds = statement.reference.auxiliary().rounds();
    if leaf_rounds == 0 || auxiliary_rounds == 0 {
        return Err(C6BlindResidualError::new("C6RSC3 empty round family"));
    }
    let leaf = 3u64
        .checked_add(2 * (leaf_rounds as u64 - 1))
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3 leaf scalar count overflows"))?;
    let auxiliary = 4u64
        .checked_add(3 * (auxiliary_rounds as u64 - 1))
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3 auxiliary scalar count overflows"))?;
    leaf.checked_add(auxiliary)
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3 round scalar count overflows"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualPendingDescriptor {
    statement_digest: [u8; 32],
    repetition: u8,
    family: C6ResidualSumcheckFamily,
    table: C6ResidualTableRef,
    point: Vec<Fp2>,
}

impl C6BlindResidualPendingDescriptor {
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn family(&self) -> C6ResidualSumcheckFamily {
        self.family
    }

    pub fn table(&self) -> C6ResidualTableRef {
        self.table
    }

    pub fn point(&self) -> &[Fp2] {
        &self.point
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualPendingTransfer {
    descriptor: C6BlindResidualPendingDescriptor,
    corrections: [Fp2; MAC_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualPendingTransferFrame {
    entries: Vec<C6BlindResidualPendingTransfer>,
}

impl C6BlindResidualPendingTransferFrame {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn correction_wire_bytes(&self) -> u64 {
        self.entries.len() as u64 * PENDING_CORRECTION_BYTES_PER_CLAIM
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualPendingClaimProver {
    descriptor: C6BlindResidualPendingDescriptor,
    auth: [ProverAuthed; MAC_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualPendingClaimsProver {
    claims: Vec<C6BlindResidualPendingClaimProver>,
}

impl C6BlindResidualPendingClaimsProver {
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6BlindResidualPendingDescriptor> {
        self.claims.get(index).map(|claim| &claim.descriptor)
    }

    pub fn authed_for_tape(&self, index: usize, tape: usize) -> Option<ProverAuthed> {
        self.claims.get(index).and_then(|claim| claim.auth.get(tape)).copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualPendingClaimVerifier {
    descriptor: C6BlindResidualPendingDescriptor,
    keys: [VerifierKey; MAC_TAPES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualPendingClaimsVerifier {
    claims: Vec<C6BlindResidualPendingClaimVerifier>,
}

impl C6BlindResidualPendingClaimsVerifier {
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    pub fn descriptor(&self, index: usize) -> Option<&C6BlindResidualPendingDescriptor> {
        self.claims.get(index).map(|claim| &claim.descriptor)
    }

    pub fn key_for_tape(&self, index: usize, tape: usize) -> Option<VerifierKey> {
        self.claims.get(index).and_then(|claim| claim.keys.get(tape)).copied()
    }
}

#[derive(Default)]
struct TapeProofBuilder {
    leaf_round_corrections: Vec<Vec<Fp2>>,
    auxiliary_round_corrections: Vec<Vec<Fp2>>,
    activation_tag: Option<Fp2>,
    product_corrections: Option<[Fp2; TERMINAL_PRODUCTS]>,
    product_m0: Option<Fp2>,
    product_m1: Option<Fp2>,
    zero_mask_correction: Option<Fp2>,
    zero_tag: Option<Fp2>,
}

impl TapeProofBuilder {
    fn finish(self) -> Result<C6BlindResidualTapeProof> {
        Ok(C6BlindResidualTapeProof {
            leaf_round_corrections: self.leaf_round_corrections,
            auxiliary_round_corrections: self.auxiliary_round_corrections,
            activation_tag: self
                .activation_tag
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 activation tag"))?,
            product_corrections: self
                .product_corrections
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 product corrections"))?,
            product_m0: self
                .product_m0
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 ProductClosure M0"))?,
            product_m1: self
                .product_m1
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 ProductClosure M1"))?,
            zero_mask_correction: self.zero_mask_correction.ok_or_else(|| {
                C6BlindResidualError::new("missing C6RSC3 ZeroBatch mask correction")
            })?,
            zero_tag: self
                .zero_tag
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 ZeroBatch tag"))?,
        })
    }
}

#[derive(Default)]
struct ProverFamilyAuthState {
    initial: Option<ProverAuthed>,
    current: Option<ProverAuthed>,
    rounds: usize,
}

impl ProverFamilyAuthState {
    fn fix_round(
        &mut self,
        family: C6ResidualSumcheckFamily,
        full_message: &[Fp2],
        stream: &mut CorrelationStream,
        domain: u64,
    ) -> Result<(Vec<Fp2>, Vec<ProverAuthed>)> {
        let degree = family_degree(family);
        if full_message.len() != degree + 1 {
            return Err(C6BlindResidualError::new(
                "C6RSC3 clear reference message degree mismatch",
            ));
        }
        let sent_values = if self.rounds == 0 {
            full_message.to_vec()
        } else {
            match family {
                C6ResidualSumcheckFamily::LeafRaw => {
                    vec![full_message[0], full_message[2]]
                }
                C6ResidualSumcheckFamily::Auxiliary => {
                    vec![full_message[0], full_message[2], full_message[3]]
                }
            }
        };
        let (corrections, sent_auth) = authenticate_prover_values(stream, domain, &sent_values)?;
        let nodes = if self.rounds == 0 {
            sent_auth
        } else {
            let live = self
                .current
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 live prover claim"))?;
            let g1 = live.sub(sent_auth[0]);
            if g1.x != full_message[1] {
                return Err(C6BlindResidualError::new(
                    "C6RSC3 compressed prover reconstruction diverges from C6RSC2",
                ));
            }
            match family {
                C6ResidualSumcheckFamily::LeafRaw => {
                    vec![sent_auth[0], g1, sent_auth[1]]
                }
                C6ResidualSumcheckFamily::Auxiliary => {
                    vec![sent_auth[0], g1, sent_auth[1], sent_auth[2]]
                }
            }
        };
        if self.rounds == 0 {
            self.initial = Some(nodes[0].add(nodes[1]));
        }
        Ok((corrections, nodes))
    }

    fn bind_challenge(
        &mut self,
        family: C6ResidualSumcheckFamily,
        nodes: &[ProverAuthed],
        challenge: Fp2,
    ) -> Result<()> {
        self.current = Some(interpolate_prover(family, nodes, challenge)?);
        self.rounds += 1;
        Ok(())
    }
}

#[derive(Default)]
struct VerifierFamilyAuthState {
    initial: Option<VerifierKey>,
    current: Option<VerifierKey>,
    rounds: usize,
}

impl VerifierFamilyAuthState {
    fn fix_round(
        &mut self,
        family: C6ResidualSumcheckFamily,
        corrections: &[Fp2],
        context: &mut VerifierCtx,
        domain: u64,
    ) -> Result<Vec<VerifierKey>> {
        let expected =
            if self.rounds == 0 { family_degree(family) + 1 } else { family_degree(family) };
        if corrections.len() != expected {
            return Err(C6BlindResidualError::new("C6RSC3 verifier correction degree mismatch"));
        }
        let sent_keys = context.correct_full_verifier_keys(domain, corrections);
        let nodes = if self.rounds == 0 {
            sent_keys
        } else {
            let live = self
                .current
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 live verifier claim"))?;
            let g1 = live.sub(sent_keys[0]);
            match family {
                C6ResidualSumcheckFamily::LeafRaw => {
                    vec![sent_keys[0], g1, sent_keys[1]]
                }
                C6ResidualSumcheckFamily::Auxiliary => {
                    vec![sent_keys[0], g1, sent_keys[1], sent_keys[2]]
                }
            }
        };
        if self.rounds == 0 {
            self.initial = Some(nodes[0].add(nodes[1]));
        }
        Ok(nodes)
    }

    fn bind_challenge(
        &mut self,
        family: C6ResidualSumcheckFamily,
        nodes: &[VerifierKey],
        challenge: Fp2,
    ) -> Result<()> {
        self.current = Some(interpolate_verifier(family, nodes, challenge)?);
        self.rounds += 1;
        Ok(())
    }
}

#[allow(dead_code)]
struct ReferenceTrace {
    challenges: Vec<Vec<Fp2>>,
    proofs: Vec<C6ResidualSumcheckRepetitionProof>,
    claims: Vec<Vec<C6ResidualOpeningClaim>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualTerminalScalars {
    leaf_linear: [Fp2; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
    auxiliary_linear: [Fp2; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
    auxiliary_quadratic: [Fp2; TERMINAL_PRODUCTS],
}

fn terminal_scalars_from_reference(
    statement: &C6BlindResidualStatement,
    leaf_point: &[Fp2],
    auxiliary_point: &[Fp2],
) -> Result<C6BlindResidualTerminalScalars> {
    let mut terminal = C6BlindResidualTerminalScalars {
        leaf_linear: [Fp2::ZERO; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
        auxiliary_linear: [Fp2::ZERO; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
        auxiliary_quadratic: [Fp2::ZERO; TERMINAL_PRODUCTS],
    };
    for (index, term) in statement.reference.leaf().terms().iter().enumerate() {
        let C6ResidualSumcheckTerm::Linear { table, coefficients } = term else {
            return Err(C6BlindResidualError::new("quadratic term in C6RSC3 leaf family"));
        };
        if usize::from(*table) != index {
            return Err(C6BlindResidualError::new(
                "C6RSC3 leaf terminal scalar owner is noncanonical",
            ));
        }
        terminal.leaf_linear[index] = eval_mle(coefficients, leaf_point);
    }
    for (index, term) in statement.reference.auxiliary().terms().iter().enumerate() {
        match term {
            C6ResidualSumcheckTerm::Linear { table, coefficients } => {
                if index >= C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION
                    || usize::from(*table) != index
                {
                    return Err(C6BlindResidualError::new(
                        "C6RSC3 auxiliary terminal scalar owner is noncanonical",
                    ));
                }
                terminal.auxiliary_linear[index] = eval_mle(coefficients, auxiliary_point);
            }
            C6ResidualSumcheckTerm::Quadratic { lhs, rhs, coefficients } => {
                let product_index = index
                    .checked_sub(C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION)
                    .ok_or_else(|| {
                        C6BlindResidualError::new(
                            "C6RSC3 quadratic terminal scalar precedes linear owners",
                        )
                    })?;
                if C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.get(product_index) != Some(&(*lhs, *rhs))
                {
                    return Err(C6BlindResidualError::new(
                        "C6RSC3 quadratic terminal scalar owner is noncanonical",
                    ));
                }
                terminal.auxiliary_quadratic[product_index] =
                    eval_mle(coefficients, auxiliary_point);
            }
        }
    }
    Ok(terminal)
}

struct C6BlindResidualArithmeticFinish {
    opening_claims: Vec<C6ResidualOpeningClaim>,
    terminal_scalars: C6BlindResidualTerminalScalars,
    reference_proof: Option<C6ResidualSumcheckRepetitionProof>,
}

trait C6BlindResidualProverArithmetic {
    fn repetition(&self) -> u8;
    fn target(&self) -> Fp2;
    fn round_count(&self) -> usize;
    fn round_index(&self) -> usize;
    fn auxiliary_activation_round(&self) -> usize;
    fn fix_next_round(&mut self) -> Result<(Vec<Fp2>, Option<Vec<Fp2>>)>;
    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()>;
    fn finish(self: Box<Self>) -> Result<C6BlindResidualArithmeticFinish>;
}

struct C6BlindResidualReferenceArithmetic<'a> {
    statement: &'a C6BlindResidualStatement,
    clear: C6ResidualSumcheckProverRoundState,
}

impl<'a> C6BlindResidualReferenceArithmetic<'a> {
    fn new(
        statement: &'a C6BlindResidualStatement,
        witness: &C6ResidualSumcheckWitness,
    ) -> Result<Self> {
        let clear = prepare_residual_sumcheck_prover_round_state(&statement.reference, witness)
            .map_err(clear_error)?;
        Ok(Self { statement, clear })
    }
}

impl C6BlindResidualProverArithmetic for C6BlindResidualReferenceArithmetic<'_> {
    fn repetition(&self) -> u8 {
        self.clear.repetition()
    }

    fn target(&self) -> Fp2 {
        self.statement.target()
    }

    fn round_count(&self) -> usize {
        self.clear.round_count()
    }

    fn round_index(&self) -> usize {
        self.clear.round_index()
    }

    fn auxiliary_activation_round(&self) -> usize {
        self.clear.auxiliary_activation_round()
    }

    fn fix_next_round(&mut self) -> Result<(Vec<Fp2>, Option<Vec<Fp2>>)> {
        self.clear.fix_next_round().map_err(clear_error)?;
        let (leaf, auxiliary) = self.clear.pending_round_messages().map_err(clear_error)?;
        Ok((leaf.to_vec(), auxiliary.map(<[Fp2]>::to_vec)))
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        self.clear.bind_challenge(challenge).map_err(clear_error)
    }

    fn finish(self: Box<Self>) -> Result<C6BlindResidualArithmeticFinish> {
        let this = *self;
        let (reference_proof, opening_claims) = this.clear.finish().map_err(clear_error)?;
        let terminal_scalars = terminal_scalars_from_reference(
            this.statement,
            &opening_claims[0].point,
            &opening_claims[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION].point,
        )?;
        Ok(C6BlindResidualArithmeticFinish {
            opening_claims,
            terminal_scalars,
            reference_proof: Some(reference_proof),
        })
    }
}

/// Shared semantic compiler inputs for the diagnostic fused C6RSC3 path.
///
/// The `c6-trace` feature is deliberately required because the current
/// adapter still obtains folded witness tables from a scaled materialized
/// witness.  It carries no production memory or timing claim.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy)]
pub struct C6BlindResidualFusedCompilerContext<'a> {
    operation_plan: &'a C6InstalledOperationPlan,
    extraction: &'a C6DecodedInstanceExtractionPlan,
    runtime: &'a C6RuntimeInstanceValues,
    linear: &'a C6CompiledLinearResidual,
    relation: &'a C6ResidualRelationChallenges,
}

#[cfg(feature = "c6-trace")]
impl<'a> C6BlindResidualFusedCompilerContext<'a> {
    pub fn new(
        operation_plan: &'a C6InstalledOperationPlan,
        extraction: &'a C6DecodedInstanceExtractionPlan,
        runtime: &'a C6RuntimeInstanceValues,
        linear: &'a C6CompiledLinearResidual,
        relation: &'a C6ResidualRelationChallenges,
    ) -> Self {
        Self { operation_plan, extraction, runtime, linear, relation }
    }
}

#[cfg(feature = "c6-trace")]
struct C6BlindResidualFusedArithmetic<'a> {
    statement: &'a C6BlindResidualStatement,
    compiler: C6BlindResidualFusedCompilerContext<'a>,
    scaled_witness: &'a C6ResidualSumcheckWitness,
    arena: &'a C6ResidualFusedCoefficientArena,
    first_leaf_message: [Fp2; 3],
    first_auxiliary_message: [Fp2; 4],
    leaf_coefficients: Option<C6ResidualFusedFoldedCoefficients>,
    auxiliary_coefficients: Option<C6ResidualFusedFoldedCoefficients>,
    leaf_witness: Option<Vec<Vec<Fp2>>>,
    auxiliary_witness: Option<Vec<Vec<Fp2>>>,
    global_round: usize,
    pending_round: bool,
}

#[cfg(feature = "c6-trace")]
impl<'a> C6BlindResidualFusedArithmetic<'a> {
    fn new(
        statement: &'a C6BlindResidualStatement,
        compiler: C6BlindResidualFusedCompilerContext<'a>,
        fused_witness: C6ResidualFusedWitnessView<'a>,
        scaled_witness: &'a C6ResidualSumcheckWitness,
        arena: &'a C6ResidualFusedCoefficientArena,
    ) -> Result<Self> {
        let manifest = compiler.relation.manifest();
        let leaf_entries = usize::try_from(manifest.leaf_entries())
            .map_err(|_| C6BlindResidualError::new("C6RSC3 fused leaf length exceeds usize"))?;
        let auxiliary_entries = usize::try_from(manifest.auxiliary_entries()).map_err(|_| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary length exceeds usize")
        })?;
        if fused_witness.manifest_digest() != manifest.digest()
            || arena.manifest_digest() != manifest.digest()
            || arena.active_repetition().is_some()
            || arena.is_faulted()
            || leaf_entries != 1usize << statement.reference.leaf().rounds()
            || auxiliary_entries != 1usize << statement.reference.auxiliary().rounds()
            || scaled_witness.leaf_tables().len() != C6_RESIDUAL_LEAF_TABLES_PER_REPETITION
            || scaled_witness.auxiliary_tables().len()
                != C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION
            || scaled_witness.leaf_tables().iter().any(|table| table.len() != leaf_entries)
            || scaled_witness
                .auxiliary_tables()
                .iter()
                .any(|table| table.len() != auxiliary_entries)
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused compiler/witness/arena geometry mismatch",
            ));
        }
        let first = compile_c6_residual_fused_first_round(
            compiler.operation_plan,
            compiler.extraction,
            compiler.runtime,
            compiler.linear,
            compiler.relation,
            statement.repetition(),
            fused_witness,
        )
        .map_err(clear_error)?;
        if first.proof_repetition() != statement.repetition()
            || first.target() != statement.target()
            || first.semantic_digest() != statement.semantic_compiler_digest()
            || first.leaf_message()[0]
                + first.leaf_message()[1]
                + first.auxiliary_message()[0]
                + first.auxiliary_message()[1]
                != statement.target()
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused first round differs from its semantic statement",
            ));
        }
        Ok(Self {
            statement,
            compiler,
            scaled_witness,
            arena,
            first_leaf_message: *first.leaf_message(),
            first_auxiliary_message: *first.auxiliary_message(),
            leaf_coefficients: None,
            auxiliary_coefficients: None,
            leaf_witness: None,
            auxiliary_witness: None,
            global_round: 0,
            pending_round: false,
        })
    }

    fn validate_new_coefficients(
        &self,
        coefficients: &C6ResidualFusedFoldedCoefficients,
        family: C6ResidualFusedCoefficientFamily,
        challenge: Fp2,
    ) -> Result<()> {
        if coefficients.proof_repetition() != self.statement.repetition()
            || coefficients.family() != family
            || coefficients.challenge() != challenge
            || coefficients.point() != [challenge]
            || coefficients.target() != self.statement.target()
            || coefficients.semantic_digest() != self.statement.semantic_compiler_digest()
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused folded coefficients differ from their semantic statement",
            ));
        }
        Ok(())
    }

    fn fixed_leaf_message(&self) -> Result<Vec<Fp2>> {
        if self.global_round == 0 {
            return Ok(self.first_leaf_message.to_vec());
        }
        let coefficients = self.leaf_coefficients.as_ref().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused leaf coefficients are not live")
        })?;
        let witness = self
            .leaf_witness
            .as_ref()
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused leaf witness is not live"))?;
        coefficients
            .with_leaf_linear(|tables| fused_leaf_round_message(tables, witness))
            .map_err(clear_error)?
    }

    fn fixed_auxiliary_message(&self) -> Result<Vec<Fp2>> {
        if self.global_round == self.auxiliary_activation_round() {
            return Ok(self.first_auxiliary_message.to_vec());
        }
        let coefficients = self.auxiliary_coefficients.as_ref().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary coefficients are not live")
        })?;
        let witness = self.auxiliary_witness.as_ref().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary witness is not live")
        })?;
        coefficients
            .with_auxiliary_tables(|linear, quadratic| {
                fused_auxiliary_round_message(linear, quadratic, witness)
            })
            .map_err(clear_error)?
    }

    fn bind_first_leaf_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let coefficients = compile_c6_residual_fused_folded_coefficients(
            self.compiler.operation_plan,
            self.compiler.extraction,
            self.compiler.runtime,
            self.compiler.linear,
            self.compiler.relation,
            self.arena,
            self.statement.repetition(),
            C6ResidualFusedCoefficientFamily::Leaf,
            challenge,
        )
        .map_err(clear_error)?;
        self.validate_new_coefficients(
            &coefficients,
            C6ResidualFusedCoefficientFamily::Leaf,
            challenge,
        )?;
        let witness =
            fold_witness_tables_from_source(self.scaled_witness.leaf_tables(), challenge, "leaf")?;
        self.leaf_coefficients = Some(coefficients);
        self.leaf_witness = Some(witness);
        Ok(())
    }

    fn bind_leaf_challenge(&mut self, challenge: Fp2) -> Result<()> {
        self.leaf_coefficients
            .as_mut()
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused leaf state is absent"))?
            .fold_next(challenge)
            .map_err(clear_error)?;
        fold_witness_tables_in_place(
            self.leaf_witness
                .as_mut()
                .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused leaf witness is absent"))?,
            challenge,
            "leaf",
        )
    }

    fn admit_auxiliary(&mut self, challenge: Fp2) -> Result<()> {
        let coefficients = compile_c6_residual_fused_folded_coefficients(
            self.compiler.operation_plan,
            self.compiler.extraction,
            self.compiler.runtime,
            self.compiler.linear,
            self.compiler.relation,
            self.arena,
            self.statement.repetition(),
            C6ResidualFusedCoefficientFamily::Auxiliary,
            challenge,
        )
        .map_err(clear_error)?;
        self.validate_new_coefficients(
            &coefficients,
            C6ResidualFusedCoefficientFamily::Auxiliary,
            challenge,
        )?;
        let witness = fold_witness_tables_from_source(
            self.scaled_witness.auxiliary_tables(),
            challenge,
            "auxiliary",
        )?;
        self.auxiliary_coefficients = Some(coefficients);
        self.auxiliary_witness = Some(witness);
        Ok(())
    }

    fn bind_auxiliary_challenge(&mut self, challenge: Fp2) -> Result<()> {
        self.auxiliary_coefficients
            .as_mut()
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused auxiliary state is absent"))?
            .fold_next(challenge)
            .map_err(clear_error)?;
        fold_witness_tables_in_place(
            self.auxiliary_witness.as_mut().ok_or_else(|| {
                C6BlindResidualError::new("C6RSC3 fused auxiliary witness is absent")
            })?,
            challenge,
            "auxiliary",
        )
    }
}

#[cfg(feature = "c6-trace")]
impl C6BlindResidualProverArithmetic for C6BlindResidualFusedArithmetic<'_> {
    fn repetition(&self) -> u8 {
        self.statement.repetition()
    }

    fn target(&self) -> Fp2 {
        self.statement.target()
    }

    fn round_count(&self) -> usize {
        self.statement.reference.leaf().rounds()
    }

    fn round_index(&self) -> usize {
        self.global_round
    }

    fn auxiliary_activation_round(&self) -> usize {
        self.statement.auxiliary_activation_round()
    }

    fn fix_next_round(&mut self) -> Result<(Vec<Fp2>, Option<Vec<Fp2>>)> {
        if self.pending_round || self.global_round >= self.round_count() {
            return Err(C6BlindResidualError::new("invalid C6RSC3 fused prover round transition"));
        }
        let leaf = self.fixed_leaf_message()?;
        let auxiliary = if self.global_round >= self.auxiliary_activation_round() {
            Some(self.fixed_auxiliary_message()?)
        } else {
            None
        };
        self.pending_round = true;
        Ok((leaf, auxiliary))
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if !self.pending_round || self.global_round >= self.round_count() {
            return Err(C6BlindResidualError::new(
                "invalid C6RSC3 fused prover challenge transition",
            ));
        }
        match self.global_round {
            0 => self.bind_first_leaf_challenge(challenge)?,
            round if round == self.auxiliary_activation_round() => {
                // The shared-suffix challenge folds leaf first.  Only then
                // may auxiliary reuse the reclaimed tail in the same arena.
                self.bind_leaf_challenge(challenge)?;
                self.admit_auxiliary(challenge)?;
            }
            round if round > self.auxiliary_activation_round() => {
                self.bind_leaf_challenge(challenge)?;
                self.bind_auxiliary_challenge(challenge)?;
            }
            _ => self.bind_leaf_challenge(challenge)?,
        }
        self.global_round += 1;
        self.pending_round = false;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<C6BlindResidualArithmeticFinish> {
        let mut this = *self;
        if this.pending_round || this.global_round != this.round_count() {
            return Err(C6BlindResidualError::new("incomplete C6RSC3 fused prover repetition"));
        }
        let leaf_coefficients = this.leaf_coefficients.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused leaf terminal state is absent")
        })?;
        let auxiliary_coefficients = this.auxiliary_coefficients.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary terminal state is absent")
        })?;
        let leaf_witness = this.leaf_witness.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused leaf terminal witness is absent")
        })?;
        let auxiliary_witness = this.auxiliary_witness.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary terminal witness is absent")
        })?;
        if !leaf_coefficients.is_terminal()
            || !auxiliary_coefficients.is_terminal()
            || leaf_witness.iter().any(|table| table.len() != 1)
            || auxiliary_witness.iter().any(|table| table.len() != 1)
        {
            return Err(C6BlindResidualError::new("C6RSC3 fused terminal geometry is incomplete"));
        }
        let leaf_point = leaf_coefficients.point().to_vec();
        let auxiliary_point = auxiliary_coefficients.point().to_vec();
        let auxiliary_start = leaf_point
            .len()
            .checked_sub(auxiliary_point.len())
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused terminal suffix underflows"))?;
        if auxiliary_point != leaf_point[auxiliary_start..] {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused terminal points do not share the frozen suffix",
            ));
        }
        let leaf_linear = leaf_coefficients
            .with_leaf_linear(|tables| {
                (!tables.iter().any(|table| table.len() != 1))
                    .then(|| array::from_fn(|table| tables[table][0]))
            })
            .map_err(clear_error)?
            .ok_or_else(|| {
                C6BlindResidualError::new("C6RSC3 fused leaf terminal table is not scalar")
            })?;
        let (auxiliary_linear, auxiliary_quadratic) = auxiliary_coefficients
            .with_auxiliary_tables(|linear, quadratic| {
                (!linear.iter().chain(quadratic.iter()).any(|table| table.len() != 1)).then(|| {
                    (
                        array::from_fn(|table| linear[table][0]),
                        array::from_fn(|table| quadratic[table][0]),
                    )
                })
            })
            .map_err(clear_error)?
            .ok_or_else(|| {
                C6BlindResidualError::new("C6RSC3 fused auxiliary terminal table is not scalar")
            })?;
        let terminal_scalars =
            C6BlindResidualTerminalScalars { leaf_linear, auxiliary_linear, auxiliary_quadratic };

        let mut opening_claims = Vec::with_capacity(C6_RESIDUAL_TABLES_PER_REPETITION);
        for (table, witness) in this.statement.reference.leaf().tables().iter().zip(&leaf_witness) {
            opening_claims.push(C6ResidualOpeningClaim {
                repetition: this.statement.repetition(),
                family: C6ResidualSumcheckFamily::LeafRaw,
                table: *table,
                point: leaf_point.clone(),
                value: witness[0],
            });
        }
        for (table, witness) in
            this.statement.reference.auxiliary().tables().iter().zip(&auxiliary_witness)
        {
            opening_claims.push(C6ResidualOpeningClaim {
                repetition: this.statement.repetition(),
                family: C6ResidualSumcheckFamily::Auxiliary,
                table: *table,
                point: auxiliary_point.clone(),
                value: witness[0],
            });
        }
        if opening_claims.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
            return Err(C6BlindResidualError::new("C6RSC3 fused terminal opening census mismatch"));
        }
        drop(auxiliary_coefficients);
        drop(leaf_coefficients);
        if this.arena.active_repetition().is_some() || this.arena.is_faulted() {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused coefficient arena did not release cleanly",
            ));
        }
        Ok(C6BlindResidualArithmeticFinish {
            opening_claims,
            terminal_scalars,
            reference_proof: None,
        })
    }
}

#[cfg(feature = "c6-trace")]
fn fold_witness_tables_from_source(
    source: &[Vec<Fp2>],
    challenge: Fp2,
    family: &str,
) -> Result<Vec<Vec<Fp2>>> {
    if source.is_empty()
        || source.iter().any(|table| table.len() < 2 || table.len() & 1 != 0)
        || source.iter().any(|table| table.len() != source[0].len())
    {
        return Err(C6BlindResidualError::new(format!(
            "C6RSC3 fused {family} source witness geometry diverged"
        )));
    }
    let folded_entries = source[0].len() / 2;
    let mut folded = Vec::new();
    folded.try_reserve_exact(source.len()).map_err(|_| {
        C6BlindResidualError::new(format!("C6RSC3 fused {family} witness table allocation failed"))
    })?;
    for table in source {
        let mut values = Vec::new();
        values.try_reserve_exact(folded_entries).map_err(|_| {
            C6BlindResidualError::new(format!(
                "C6RSC3 fused {family} witness row allocation failed"
            ))
        })?;
        values.extend(table.chunks_exact(2).map(|pair| pair[0] + (pair[1] - pair[0]) * challenge));
        folded.push(values);
    }
    Ok(folded)
}

#[cfg(feature = "c6-trace")]
fn fold_witness_tables_in_place(
    tables: &mut [Vec<Fp2>],
    challenge: Fp2,
    family: &str,
) -> Result<()> {
    if tables.is_empty()
        || tables.iter().any(|table| table.len() < 2 || table.len() & 1 != 0)
        || tables.iter().any(|table| table.len() != tables[0].len())
    {
        return Err(C6BlindResidualError::new(format!(
            "C6RSC3 fused {family} folded witness geometry diverged"
        )));
    }
    let next = tables[0].len() / 2;
    for table in tables {
        for row in 0..next {
            let low = table[2 * row];
            table[row] = low + (table[2 * row + 1] - low) * challenge;
        }
        table.truncate(next);
    }
    Ok(())
}

#[cfg(feature = "c6-trace")]
fn fused_leaf_round_message(
    coefficients: [&[Fp2]; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
    witness: &[Vec<Fp2>],
) -> Result<Vec<Fp2>> {
    if witness.len() != coefficients.len()
        || coefficients.iter().any(|table| table.len() < 2 || table.len() & 1 != 0)
        || coefficients.iter().any(|table| table.len() != coefficients[0].len())
        || witness
            .iter()
            .zip(coefficients)
            .any(|(values, coefficients)| values.len() != coefficients.len())
    {
        return Err(C6BlindResidualError::new("C6RSC3 fused leaf round geometry diverged"));
    }
    let mut message = [Fp2::ZERO; 3];
    for (coefficients, witness) in coefficients.iter().zip(witness) {
        for pair in 0..coefficients.len() / 2 {
            for (node, evaluation) in message.iter_mut().enumerate() {
                let at = Fp2::from_base(Fp::new(node as u64));
                *evaluation += fused_affine_pair(coefficients, pair, at)
                    * fused_affine_pair(witness, pair, at);
            }
        }
    }
    Ok(message.to_vec())
}

#[cfg(feature = "c6-trace")]
fn fused_auxiliary_round_message(
    linear: [&[Fp2]; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
    quadratic: [&[Fp2]; TERMINAL_PRODUCTS],
    witness: &[Vec<Fp2>],
) -> Result<Vec<Fp2>> {
    if witness.len() != linear.len()
        || linear.iter().any(|table| table.len() < 2 || table.len() & 1 != 0)
        || linear.iter().any(|table| table.len() != linear[0].len())
        || quadratic.iter().any(|table| table.len() != linear[0].len())
        || witness
            .iter()
            .zip(linear)
            .any(|(values, coefficients)| values.len() != coefficients.len())
    {
        return Err(C6BlindResidualError::new("C6RSC3 fused auxiliary round geometry diverged"));
    }
    let mut message = [Fp2::ZERO; 4];
    for (coefficients, witness) in linear.iter().zip(witness) {
        for pair in 0..coefficients.len() / 2 {
            for (node, evaluation) in message.iter_mut().enumerate() {
                let at = Fp2::from_base(Fp::new(node as u64));
                *evaluation += fused_affine_pair(coefficients, pair, at)
                    * fused_affine_pair(witness, pair, at);
            }
        }
    }
    for ((lhs, rhs), coefficients) in C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.iter().zip(quadratic)
    {
        let lhs = &witness[usize::from(*lhs)];
        let rhs = &witness[usize::from(*rhs)];
        for pair in 0..coefficients.len() / 2 {
            for (node, evaluation) in message.iter_mut().enumerate() {
                let at = Fp2::from_base(Fp::new(node as u64));
                *evaluation += fused_affine_pair(coefficients, pair, at)
                    * fused_affine_pair(lhs, pair, at)
                    * fused_affine_pair(rhs, pair, at);
            }
        }
    }
    Ok(message.to_vec())
}

#[cfg(feature = "c6-trace")]
fn fused_affine_pair(values: &[Fp2], pair: usize, at: Fp2) -> Fp2 {
    let low = values[2 * pair];
    low + at * (values[2 * pair + 1] - low)
}

struct C6BlindResidualProverRepetitionOutput {
    proof: C6BlindResidualRepetitionProof,
    pending_claims: Vec<C6BlindResidualPendingClaimProver>,
    pending_transfers: Vec<C6BlindResidualPendingTransfer>,
    challenges: Vec<Fp2>,
    reference_proof: Option<C6ResidualSumcheckRepetitionProof>,
    opening_claims: Vec<C6ResidualOpeningClaim>,
}

fn prove_c6_blind_residual_repetition(
    statement: &C6BlindResidualStatement,
    mut arithmetic: Box<dyn C6BlindResidualProverArithmetic + '_>,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualProverRepetitionOutput> {
    let repetition = statement.repetition();
    if arithmetic.repetition() != repetition
        || arithmetic.target() != statement.target()
        || arithmetic.round_count() != statement.reference.leaf().rounds()
        || arithmetic.auxiliary_activation_round() != statement.auxiliary_activation_round()
        || arithmetic.round_index() != 0
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 prover arithmetic does not match its semantic statement",
        ));
    }
    let mut builders: [TapeProofBuilder; MAC_TAPES] =
        array::from_fn(|_| TapeProofBuilder::default());
    let mut leaf_states: [ProverFamilyAuthState; MAC_TAPES] =
        array::from_fn(|_| ProverFamilyAuthState::default());
    let mut auxiliary_states: [ProverFamilyAuthState; MAC_TAPES] =
        array::from_fn(|_| ProverFamilyAuthState::default());
    let mut challenge_trace = Vec::with_capacity(arithmetic.round_count());

    while arithmetic.round_index() < arithmetic.round_count() {
        let global_round = arithmetic.round_index();
        let (leaf_message, auxiliary_message) = arithmetic.fix_next_round()?;
        let mut leaf_nodes: [Vec<ProverAuthed>; MAC_TAPES] = array::from_fn(|_| Vec::new());
        let mut auxiliary_nodes: [Vec<ProverAuthed>; MAC_TAPES] = array::from_fn(|_| Vec::new());

        for tape in 0..MAC_TAPES {
            let domain =
                correlation_domain(repetition, tape, CorrelationPurpose::LeafRound, global_round)?;
            let (corrections, nodes) = leaf_states[tape].fix_round(
                C6ResidualSumcheckFamily::LeafRaw,
                &leaf_message,
                &mut streams[tape],
                domain,
            )?;
            transcript.append(
                "c6_residual_blind_round_corrections",
                corrections.len() as u64 * FP2_BYTES,
            );
            builders[tape].leaf_round_corrections.push(corrections);
            leaf_nodes[tape] = nodes;

            if let Some(message) = &auxiliary_message {
                let local_round = global_round - statement.auxiliary_activation_round();
                let domain = correlation_domain(
                    repetition,
                    tape,
                    CorrelationPurpose::AuxiliaryRound,
                    local_round,
                )?;
                let (corrections, nodes) = auxiliary_states[tape].fix_round(
                    C6ResidualSumcheckFamily::Auxiliary,
                    message,
                    &mut streams[tape],
                    domain,
                )?;
                transcript.append(
                    "c6_residual_blind_round_corrections",
                    corrections.len() as u64 * FP2_BYTES,
                );
                builders[tape].auxiliary_round_corrections.push(corrections);
                auxiliary_nodes[tape] = nodes;
            }
        }

        if global_round == statement.auxiliary_activation_round() {
            for tape in 0..MAC_TAPES {
                let leaf_initial = leaf_states[tape]
                    .initial
                    .ok_or_else(|| C6BlindResidualError::new("missing leaf initial claim"))?;
                let auxiliary_initial = auxiliary_states[tape]
                    .initial
                    .ok_or_else(|| C6BlindResidualError::new("missing auxiliary initial claim"))?;
                let residual = leaf_initial
                    .add(auxiliary_initial)
                    .sub(ProverAuthed::from_public(statement.target()));
                if residual.x != Fp2::ZERO {
                    return Err(C6BlindResidualError::new("C6RSC3 activation residual is nonzero"));
                }
                builders[tape].activation_tag = Some(zero_open_prover(&residual, transcript));
            }
        }

        let challenge = transcript.challenge_fp2();
        challenge_trace.push(challenge);
        arithmetic.bind_challenge(challenge)?;
        for tape in 0..MAC_TAPES {
            leaf_states[tape].bind_challenge(
                C6ResidualSumcheckFamily::LeafRaw,
                &leaf_nodes[tape],
                challenge,
            )?;
            if !auxiliary_nodes[tape].is_empty() {
                auxiliary_states[tape].bind_challenge(
                    C6ResidualSumcheckFamily::Auxiliary,
                    &auxiliary_nodes[tape],
                    challenge,
                )?;
            }
        }
    }

    let finished = arithmetic.finish()?;
    let (local_pending, local_transfers) = authenticate_pending_prover_claims(
        statement,
        &finished.opening_claims,
        streams,
        transcript,
    )?;
    finish_prover_terminal(
        statement,
        &local_pending,
        &finished.terminal_scalars,
        &leaf_states,
        &auxiliary_states,
        streams,
        transcript,
        &mut builders,
    )?;

    let tapes = builders
        .into_iter()
        .map(TapeProofBuilder::finish)
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| C6BlindResidualError::new("C6RSC3 tape builder census mismatch"))?;
    Ok(C6BlindResidualProverRepetitionOutput {
        proof: C6BlindResidualRepetitionProof {
            repetition,
            statement_digest: statement.digest,
            tapes,
        },
        pending_claims: local_pending,
        pending_transfers: local_transfers,
        challenges: challenge_trace,
        reference_proof: finished.reference_proof,
        opening_claims: finished.opening_claims,
    })
}

/// Scaled/reference C6RSC3 prover.  The returned pending claims are not PCS
/// bound and deliberately have no constructor that upgrades them.
pub fn prove_c6_blind_residual_sumchecks_reference(
    statements: &[C6BlindResidualStatement],
    witnesses: &[C6ResidualSumcheckWitness],
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
)> {
    let (proof, frame, pending, _) = prove_c6_blind_residual_sumchecks_reference_inner(
        statements, witnesses, streams, transcript,
    )?;
    Ok((proof, frame, pending))
}

/// Diagnostic scaled prover that feeds the fused atomic sinks and
/// single-backing coefficient arena into the canonical C6RSC3 coordinator.
///
/// The materialized witness supplies only the scaled folded witness state;
/// coefficient arithmetic never reads the reference coefficient arrays.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_blind_residual_sumchecks_fused_scaled(
    statements: &[C6BlindResidualStatement],
    witnesses: &[C6ResidualSumcheckWitness],
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    fused_witness: C6ResidualFusedWitnessView<'_>,
    arena: &C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
)> {
    validate_statement_pair(statements)?;
    if witnesses.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS
        || arena.active_repetition().is_some()
        || arena.is_faulted()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 fused scaled prover starts from invalid witness/arena state",
        ));
    }
    transcript.append("c6_residual_blind_framing", PROOF_FIXED_FRAMING_BYTES - 32);
    let mut repetition_proofs = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    let mut pending_transfers =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    let mut pending_claims =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    for (statement, witness) in statements.iter().zip(witnesses) {
        let arithmetic = Box::new(C6BlindResidualFusedArithmetic::new(
            statement,
            compiler,
            fused_witness,
            witness,
            arena,
        )?);
        let output =
            prove_c6_blind_residual_repetition(statement, arithmetic, streams, transcript)?;
        if output.reference_proof.is_some()
            || arena.active_repetition().is_some()
            || arena.is_faulted()
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused arithmetic retained reference proof or coefficient state",
            ));
        }
        repetition_proofs.push(output.proof);
        pending_claims.extend(output.pending_claims);
        pending_transfers.extend(output.pending_transfers);
    }
    transcript.append("c6_residual_blind_framing", 32);
    let proof = C6BlindResidualSumcheckProof { repetitions: repetition_proofs };
    proof.validate_shape(statements)?;
    let frame = C6BlindResidualPendingTransferFrame { entries: pending_transfers };
    validate_pending_frame_shape(statements, &frame)?;
    Ok((proof, frame, C6BlindResidualPendingClaimsProver { claims: pending_claims }))
}

fn prove_c6_blind_residual_sumchecks_reference_inner(
    statements: &[C6BlindResidualStatement],
    witnesses: &[C6ResidualSumcheckWitness],
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
    ReferenceTrace,
)> {
    validate_statement_pair(statements)?;
    if witnesses.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
        return Err(C6BlindResidualError::new("C6RSC3 witness repetition count mismatch"));
    }
    transcript.append("c6_residual_blind_framing", PROOF_FIXED_FRAMING_BYTES - 32);
    let mut repetition_proofs = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    let mut pending_transfers =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    let mut pending_claims =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    let mut reference_challenges = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    let mut reference_proofs = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    let mut reference_claims = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);

    for (statement, witness) in statements.iter().zip(witnesses) {
        let arithmetic = Box::new(C6BlindResidualReferenceArithmetic::new(statement, witness)?);
        let output =
            prove_c6_blind_residual_repetition(statement, arithmetic, streams, transcript)?;
        let reference_proof = output.reference_proof.ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 reference arithmetic omitted its clear proof")
        })?;
        repetition_proofs.push(output.proof);
        pending_claims.extend(output.pending_claims);
        pending_transfers.extend(output.pending_transfers);
        reference_challenges.push(output.challenges);
        reference_proofs.push(reference_proof);
        reference_claims.push(output.opening_claims);
    }

    transcript.append("c6_residual_blind_framing", 32);
    let proof = C6BlindResidualSumcheckProof { repetitions: repetition_proofs };
    proof.validate_shape(statements)?;
    let frame = C6BlindResidualPendingTransferFrame { entries: pending_transfers };
    validate_pending_frame_shape(statements, &frame)?;
    Ok((
        proof,
        frame,
        C6BlindResidualPendingClaimsProver { claims: pending_claims },
        ReferenceTrace {
            challenges: reference_challenges,
            proofs: reference_proofs,
            claims: reference_claims,
        },
    ))
}

fn authenticate_pending_prover_claims(
    statement: &C6BlindResidualStatement,
    clear_claims: &[C6ResidualOpeningClaim],
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(Vec<C6BlindResidualPendingClaimProver>, Vec<C6BlindResidualPendingTransfer>)> {
    if clear_claims.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3 pending claim census mismatch"));
    }
    let descriptors = clear_claims
        .iter()
        .map(|claim| C6BlindResidualPendingDescriptor {
            statement_digest: statement.digest,
            repetition: claim.repetition,
            family: claim.family,
            table: claim.table,
            point: claim.point.clone(),
        })
        .collect::<Vec<_>>();
    let values = clear_claims.iter().map(|claim| claim.value).collect::<Vec<_>>();
    let mut corrections: [Vec<Fp2>; MAC_TAPES] = array::from_fn(|_| Vec::new());
    let mut auths: [Vec<ProverAuthed>; MAC_TAPES] = array::from_fn(|_| Vec::new());
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::PendingClaims, 0)?;
        (corrections[tape], auths[tape]) =
            authenticate_prover_values(&mut streams[tape], domain, &values)?;
    }
    transcript.append(
        "c6_residual_pending_transfers",
        values.len() as u64 * PENDING_CORRECTION_BYTES_PER_CLAIM,
    );
    let mut pending = Vec::with_capacity(values.len());
    let mut transfers = Vec::with_capacity(values.len());
    for index in 0..values.len() {
        if auths[0][index].x != auths[1][index].x {
            return Err(C6BlindResidualError::new("C6RSC3 pending plaintext differs across tapes"));
        }
        pending.push(C6BlindResidualPendingClaimProver {
            descriptor: descriptors[index].clone(),
            auth: [auths[0][index], auths[1][index]],
        });
        transfers.push(C6BlindResidualPendingTransfer {
            descriptor: descriptors[index].clone(),
            corrections: [corrections[0][index], corrections[1][index]],
        });
    }
    Ok((pending, transfers))
}

#[allow(clippy::too_many_arguments)]
fn finish_prover_terminal(
    statement: &C6BlindResidualStatement,
    pending: &[C6BlindResidualPendingClaimProver],
    terminal_scalars: &C6BlindResidualTerminalScalars,
    leaf_states: &[ProverFamilyAuthState; MAC_TAPES],
    auxiliary_states: &[ProverFamilyAuthState; MAC_TAPES],
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
    builders: &mut [TapeProofBuilder; MAC_TAPES],
) -> Result<()> {
    validate_pending_prover_claims(statement, pending)?;
    let leaf = &pending[..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION];
    let auxiliary = &pending[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION..];
    let mut product_auth: [Vec<ProverAuthed>; MAC_TAPES] =
        array::from_fn(|_| Vec::with_capacity(TERMINAL_PRODUCTS));
    let mut product_corrections: [Vec<Fp2>; MAC_TAPES] =
        array::from_fn(|_| Vec::with_capacity(TERMINAL_PRODUCTS));
    let product_plaintexts = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
        .iter()
        .map(|(lhs, rhs)| {
            let lhs = auxiliary[usize::from(*lhs)].auth[0].x;
            let rhs = auxiliary[usize::from(*rhs)].auth[0].x;
            lhs * rhs
        })
        .collect::<Vec<_>>();
    for (index, claim) in auxiliary.iter().enumerate() {
        if claim.auth[0].x != claim.auth[1].x {
            return Err(C6BlindResidualError::new(format!(
                "C6RSC3 auxiliary plaintext differs across tapes at slot {index}"
            )));
        }
    }
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ProductValues, 0)?;
        (product_corrections[tape], product_auth[tape]) =
            authenticate_prover_values(&mut streams[tape], domain, &product_plaintexts)?;
        builders[tape].product_corrections = Some(
            product_corrections[tape]
                .clone()
                .try_into()
                .map_err(|_| C6BlindResidualError::new("C6RSC3 product correction census"))?,
        );
    }
    transcript.append(
        "c6_residual_product_corrections",
        MAC_TAPES as u64 * TERMINAL_PRODUCTS as u64 * FP2_BYTES,
    );
    let mut product_masks: [Option<ProductMaskCorr>; MAC_TAPES] = array::from_fn(|_| None);
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ProductMask, 0)?;
        product_masks[tape] = Some(streams[tape].draw_product_mask(domain, TERMINAL_PRODUCTS));
    }
    let product_challenge = transcript.challenge_fp2();
    let mut leaf_rows = [ProverAuthed::ZERO; MAC_TAPES];
    let mut auxiliary_rows = [ProverAuthed::ZERO; MAC_TAPES];
    for tape in 0..MAC_TAPES {
        let triples = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            .iter()
            .enumerate()
            .map(|(index, (lhs, rhs))| {
                (
                    auxiliary[usize::from(*lhs)].auth[tape],
                    auxiliary[usize::from(*rhs)].auth[tape],
                    product_auth[tape][index],
                )
            })
            .collect::<Vec<_>>();
        let product = prod_batch_prover(
            &triples,
            product_challenge,
            product_masks[tape]
                .take()
                .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 product mask"))?,
            transcript,
        );
        builders[tape].product_m0 = Some(product.m0);
        builders[tape].product_m1 = Some(product.m1);

        let leaf_expression = terminal_leaf_expression_prover(terminal_scalars, leaf, tape)?;
        let auxiliary_expression = terminal_auxiliary_expression_prover(
            terminal_scalars,
            auxiliary,
            &product_auth[tape],
            tape,
        )?;
        leaf_rows[tape] = leaf_states[tape]
            .current
            .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 leaf terminal claim"))?
            .sub(leaf_expression);
        auxiliary_rows[tape] = auxiliary_states[tape]
            .current
            .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 auxiliary terminal claim"))?
            .sub(auxiliary_expression);
        if leaf_rows[tape].x != Fp2::ZERO || auxiliary_rows[tape].x != Fp2::ZERO {
            return Err(C6BlindResidualError::new("C6RSC3 terminal residual is nonzero"));
        }
    }

    let mut zero_masks = [ProverAuthed::ZERO; MAC_TAPES];
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ZeroMask, 0)?;
        let corr = streams[tape]
            .draw_fulls(domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C6BlindResidualError::new("missing C6RSC3 zero mask"))?;
        streams[tape].record_c6_fullfield_plaintexts(domain, &[Fp2::ZERO]).map_err(clear_error)?;
        let (mask, correction) = fresh_zero_mask(corr, transcript);
        zero_masks[tape] = mask;
        builders[tape].zero_mask_correction = Some(correction);
    }
    let zero_challenge = transcript.challenge_fp2();
    for tape in 0..MAC_TAPES {
        builders[tape].zero_tag = Some(zero_batch_prover(
            &[leaf_rows[tape], auxiliary_rows[tape]],
            &zero_masks[tape],
            zero_challenge,
            transcript,
        ));
    }
    Ok(())
}

pub fn verify_c6_blind_residual_sumchecks(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualPendingClaimsVerifier> {
    verify_c6_blind_residual_sumchecks_inner(
        statements,
        proof,
        pending_frame,
        contexts,
        transcript,
        terminal_scalars_from_reference,
    )
}

fn verify_c6_blind_residual_sumchecks_inner<T>(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
    mut terminal_compiler: T,
) -> Result<C6BlindResidualPendingClaimsVerifier>
where
    T: FnMut(&C6BlindResidualStatement, &[Fp2], &[Fp2]) -> Result<C6BlindResidualTerminalScalars>,
{
    proof.validate_shape(statements)?;
    validate_pending_frame_shape(statements, pending_frame)?;
    if contexts[0].delta == contexts[1].delta {
        return Err(C6BlindResidualError::new(
            "C6RSC3 residual MAC coordinates are not independent",
        ));
    }
    transcript.append("c6_residual_blind_framing", PROOF_FIXED_FRAMING_BYTES - 32);
    let mut accepted_pending = Vec::with_capacity(pending_frame.entries.len());
    for (statement, repetition_proof) in statements.iter().zip(&proof.repetitions) {
        let repetition = statement.repetition();
        let mut leaf_states: [VerifierFamilyAuthState; MAC_TAPES] =
            array::from_fn(|_| VerifierFamilyAuthState::default());
        let mut auxiliary_states: [VerifierFamilyAuthState; MAC_TAPES] =
            array::from_fn(|_| VerifierFamilyAuthState::default());
        let mut points = Vec::with_capacity(statement.reference.leaf().rounds());

        for global_round in 0..statement.reference.leaf().rounds() {
            let mut leaf_nodes: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
            let mut auxiliary_nodes: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
            for tape in 0..MAC_TAPES {
                let corrections =
                    &repetition_proof.tapes[tape].leaf_round_corrections[global_round];
                let domain = correlation_domain(
                    repetition,
                    tape,
                    CorrelationPurpose::LeafRound,
                    global_round,
                )?;
                leaf_nodes[tape] = leaf_states[tape].fix_round(
                    C6ResidualSumcheckFamily::LeafRaw,
                    corrections,
                    &mut contexts[tape],
                    domain,
                )?;
                transcript.append(
                    "c6_residual_blind_round_corrections",
                    corrections.len() as u64 * FP2_BYTES,
                );
                if global_round >= statement.auxiliary_activation_round() {
                    let local_round = global_round - statement.auxiliary_activation_round();
                    let corrections =
                        &repetition_proof.tapes[tape].auxiliary_round_corrections[local_round];
                    let domain = correlation_domain(
                        repetition,
                        tape,
                        CorrelationPurpose::AuxiliaryRound,
                        local_round,
                    )?;
                    auxiliary_nodes[tape] = auxiliary_states[tape].fix_round(
                        C6ResidualSumcheckFamily::Auxiliary,
                        corrections,
                        &mut contexts[tape],
                        domain,
                    )?;
                    transcript.append(
                        "c6_residual_blind_round_corrections",
                        corrections.len() as u64 * FP2_BYTES,
                    );
                }
            }
            if global_round == statement.auxiliary_activation_round() {
                for tape in 0..MAC_TAPES {
                    let leaf_initial = leaf_states[tape].initial.ok_or_else(|| {
                        C6BlindResidualError::new("missing leaf verifier initial")
                    })?;
                    let auxiliary_initial = auxiliary_states[tape].initial.ok_or_else(|| {
                        C6BlindResidualError::new("missing auxiliary verifier initial")
                    })?;
                    let residual_key = leaf_initial
                        .add(auxiliary_initial)
                        .sub(VerifierKey::from_public(statement.target(), contexts[tape].delta));
                    transcript.append("zero_open_tag", FP2_BYTES);
                    if !zero_open_verify(residual_key, repetition_proof.tapes[tape].activation_tag)
                    {
                        return Err(C6BlindResidualError::new("C6RSC3 activation ZeroOpen failed"));
                    }
                }
            }
            let challenge = transcript.challenge_fp2();
            points.push(challenge);
            for tape in 0..MAC_TAPES {
                leaf_states[tape].bind_challenge(
                    C6ResidualSumcheckFamily::LeafRaw,
                    &leaf_nodes[tape],
                    challenge,
                )?;
                if !auxiliary_nodes[tape].is_empty() {
                    auxiliary_states[tape].bind_challenge(
                        C6ResidualSumcheckFamily::Auxiliary,
                        &auxiliary_nodes[tape],
                        challenge,
                    )?;
                }
            }
        }

        let frame_start = usize::from(repetition) * C6_RESIDUAL_TABLES_PER_REPETITION;
        let frame_end = frame_start + C6_RESIDUAL_TABLES_PER_REPETITION;
        let local_pending = authenticate_pending_verifier_claims(
            statement,
            &pending_frame.entries[frame_start..frame_end],
            &points,
            contexts,
            transcript,
        )?;
        let terminal_scalars = terminal_compiler(
            statement,
            &local_pending[0].descriptor.point,
            &local_pending[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION].descriptor.point,
        )?;
        finish_verifier_terminal(
            statement,
            repetition_proof,
            &local_pending,
            &terminal_scalars,
            &leaf_states,
            &auxiliary_states,
            contexts,
            transcript,
        )?;
        accepted_pending.extend(local_pending);
    }
    transcript.append("c6_residual_blind_framing", 32);
    Ok(C6BlindResidualPendingClaimsVerifier { claims: accepted_pending })
}

/// Diagnostic designated verifier whose terminal coefficient evaluation is
/// the witness-free fused atomic replay.  It never reads the materialized
/// coefficient arrays retained by the scaled C6RSC2 statement.
#[cfg(feature = "c6-trace")]
pub fn verify_c6_blind_residual_sumchecks_fused_scaled(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualPendingClaimsVerifier> {
    verify_c6_blind_residual_sumchecks_inner(
        statements,
        proof,
        pending_frame,
        contexts,
        transcript,
        |statement, leaf_point, auxiliary_point| {
            let terminal = compile_c6_residual_fused_terminal_coefficients(
                compiler.operation_plan,
                compiler.extraction,
                compiler.runtime,
                compiler.linear,
                compiler.relation,
                statement.repetition(),
                leaf_point,
                auxiliary_point,
            )
            .map_err(clear_error)?;
            if terminal.proof_repetition() != statement.repetition()
                || terminal.target() != statement.target()
                || terminal.leaf_point() != leaf_point
                || terminal.auxiliary_point() != auxiliary_point
                || terminal.semantic_digest() != statement.semantic_compiler_digest()
                || terminal.coefficient_writes() == 0
            {
                return Err(C6BlindResidualError::new(
                    "C6RSC3 fused terminal replay differs from its semantic statement",
                ));
            }
            Ok(C6BlindResidualTerminalScalars {
                leaf_linear: *terminal.leaf_linear(),
                auxiliary_linear: *terminal.auxiliary_linear(),
                auxiliary_quadratic: *terminal.auxiliary_quadratic(),
            })
        },
    )
}

fn authenticate_pending_verifier_claims(
    statement: &C6BlindResidualStatement,
    transfers: &[C6BlindResidualPendingTransfer],
    common_point: &[Fp2],
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<Vec<C6BlindResidualPendingClaimVerifier>> {
    validate_pending_transfer_descriptors(statement, transfers, common_point)?;
    let mut keys: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
    for tape in 0..MAC_TAPES {
        let corrections = transfers.iter().map(|entry| entry.corrections[tape]).collect::<Vec<_>>();
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::PendingClaims, 0)?;
        keys[tape] = contexts[tape].correct_full_verifier_keys(domain, &corrections);
    }
    transcript.append(
        "c6_residual_pending_transfers",
        transfers.len() as u64 * PENDING_CORRECTION_BYTES_PER_CLAIM,
    );
    Ok(transfers
        .iter()
        .enumerate()
        .map(|(index, transfer)| C6BlindResidualPendingClaimVerifier {
            descriptor: transfer.descriptor.clone(),
            keys: [keys[0][index], keys[1][index]],
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn finish_verifier_terminal(
    statement: &C6BlindResidualStatement,
    proof: &C6BlindResidualRepetitionProof,
    pending: &[C6BlindResidualPendingClaimVerifier],
    terminal_scalars: &C6BlindResidualTerminalScalars,
    leaf_states: &[VerifierFamilyAuthState; MAC_TAPES],
    auxiliary_states: &[VerifierFamilyAuthState; MAC_TAPES],
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<()> {
    validate_pending_verifier_claims(statement, pending)?;
    let leaf = &pending[..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION];
    let auxiliary = &pending[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION..];
    let mut product_keys: [Vec<VerifierKey>; MAC_TAPES] =
        array::from_fn(|_| Vec::with_capacity(TERMINAL_PRODUCTS));
    let mut product_mask_keys = [VerifierKey::ZERO; MAC_TAPES];
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ProductValues, 0)?;
        product_keys[tape] = contexts[tape]
            .correct_full_verifier_keys(domain, &proof.tapes[tape].product_corrections);
        let mask_domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ProductMask, 0)?;
        product_mask_keys[tape] =
            contexts[tape].expand_product_mask_verifier_key(mask_domain, TERMINAL_PRODUCTS);
    }
    transcript.append(
        "c6_residual_product_corrections",
        MAC_TAPES as u64 * TERMINAL_PRODUCTS as u64 * FP2_BYTES,
    );
    let product_challenge = transcript.challenge_fp2();
    let mut leaf_rows = [VerifierKey::ZERO; MAC_TAPES];
    let mut auxiliary_rows = [VerifierKey::ZERO; MAC_TAPES];
    for tape in 0..MAC_TAPES {
        let triples = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            .iter()
            .enumerate()
            .map(|(index, (lhs, rhs))| {
                (
                    auxiliary[usize::from(*lhs)].keys[tape],
                    auxiliary[usize::from(*rhs)].keys[tape],
                    product_keys[tape][index],
                )
            })
            .collect::<Vec<_>>();
        let product_proof =
            ProdProof { m0: proof.tapes[tape].product_m0, m1: proof.tapes[tape].product_m1 };
        transcript.append("prod_check_m0_m1", 2 * FP2_BYTES);
        if !prod_batch_verify(
            &triples,
            product_mask_keys[tape],
            contexts[tape].delta,
            product_challenge,
            &product_proof,
        ) {
            return Err(C6BlindResidualError::new("C6RSC3 terminal ProductClosure failed"));
        }
        let leaf_expression = terminal_leaf_expression_verifier(terminal_scalars, leaf, tape)?;
        let auxiliary_expression = terminal_auxiliary_expression_verifier(
            terminal_scalars,
            auxiliary,
            &product_keys[tape],
            tape,
        )?;
        leaf_rows[tape] = leaf_states[tape]
            .current
            .ok_or_else(|| C6BlindResidualError::new("missing leaf verifier terminal"))?
            .sub(leaf_expression);
        auxiliary_rows[tape] = auxiliary_states[tape]
            .current
            .ok_or_else(|| C6BlindResidualError::new("missing auxiliary verifier terminal"))?
            .sub(auxiliary_expression);
    }
    let mut zero_mask_keys = [VerifierKey::ZERO; MAC_TAPES];
    for tape in 0..MAC_TAPES {
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::ZeroMask, 0)?;
        let full = contexts[tape]
            .expand_full_verifier_keys(domain, 1)
            .into_iter()
            .next()
            .ok_or_else(|| C6BlindResidualError::new("missing verifier zero mask"))?;
        zero_mask_keys[tape] =
            zero_mask_key(&contexts[tape], full, proof.tapes[tape].zero_mask_correction);
        transcript.append("mask_correction", FP2_BYTES);
    }
    let zero_challenge = transcript.challenge_fp2();
    for tape in 0..MAC_TAPES {
        transcript.append("zero_batch_tag", FP2_BYTES);
        if !zero_batch_verify(
            &[leaf_rows[tape], auxiliary_rows[tape]],
            zero_mask_keys[tape],
            zero_challenge,
            proof.tapes[tape].zero_tag,
        ) {
            return Err(C6BlindResidualError::new("C6RSC3 terminal ZeroBatch failed"));
        }
    }
    Ok(())
}

fn terminal_leaf_expression_prover(
    terminal: &C6BlindResidualTerminalScalars,
    claims: &[C6BlindResidualPendingClaimProver],
    tape: usize,
) -> Result<ProverAuthed> {
    if claims.len() != terminal.leaf_linear.len() {
        return Err(C6BlindResidualError::new("C6RSC3 leaf terminal claim/scalar census mismatch"));
    }
    let mut expression = ProverAuthed::ZERO;
    for (claim, coefficient) in claims.iter().zip(terminal.leaf_linear) {
        expression = expression.add(claim.auth[tape].scale(coefficient));
    }
    Ok(expression)
}

fn terminal_leaf_expression_verifier(
    terminal: &C6BlindResidualTerminalScalars,
    claims: &[C6BlindResidualPendingClaimVerifier],
    tape: usize,
) -> Result<VerifierKey> {
    if claims.len() != terminal.leaf_linear.len() {
        return Err(C6BlindResidualError::new(
            "C6RSC3 verifier leaf terminal claim/scalar census mismatch",
        ));
    }
    let mut expression = VerifierKey::ZERO;
    for (claim, coefficient) in claims.iter().zip(terminal.leaf_linear) {
        expression = expression.add(claim.keys[tape].scale(coefficient));
    }
    Ok(expression)
}

fn terminal_auxiliary_expression_prover(
    terminal: &C6BlindResidualTerminalScalars,
    claims: &[C6BlindResidualPendingClaimProver],
    products: &[ProverAuthed],
    tape: usize,
) -> Result<ProverAuthed> {
    if claims.len() != terminal.auxiliary_linear.len()
        || products.len() != terminal.auxiliary_quadratic.len()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 auxiliary terminal claim/scalar census mismatch",
        ));
    }
    let mut expression = ProverAuthed::ZERO;
    for (claim, coefficient) in claims.iter().zip(terminal.auxiliary_linear) {
        expression = expression.add(claim.auth[tape].scale(coefficient));
    }
    for (product, coefficient) in products.iter().zip(terminal.auxiliary_quadratic) {
        expression = expression.add(product.scale(coefficient));
    }
    Ok(expression)
}

fn terminal_auxiliary_expression_verifier(
    terminal: &C6BlindResidualTerminalScalars,
    claims: &[C6BlindResidualPendingClaimVerifier],
    products: &[VerifierKey],
    tape: usize,
) -> Result<VerifierKey> {
    if claims.len() != terminal.auxiliary_linear.len()
        || products.len() != terminal.auxiliary_quadratic.len()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 verifier auxiliary terminal claim/scalar census mismatch",
        ));
    }
    let mut expression = VerifierKey::ZERO;
    for (claim, coefficient) in claims.iter().zip(terminal.auxiliary_linear) {
        expression = expression.add(claim.keys[tape].scale(coefficient));
    }
    for (product, coefficient) in products.iter().zip(terminal.auxiliary_quadratic) {
        expression = expression.add(product.scale(coefficient));
    }
    Ok(expression)
}

fn validate_pending_prover_claims(
    statement: &C6BlindResidualStatement,
    pending: &[C6BlindResidualPendingClaimProver],
) -> Result<()> {
    if pending.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3 pending prover census mismatch"));
    }
    for (index, claim) in pending.iter().enumerate() {
        validate_pending_descriptor(statement, index, &claim.descriptor)?;
    }
    Ok(())
}

fn validate_pending_verifier_claims(
    statement: &C6BlindResidualStatement,
    pending: &[C6BlindResidualPendingClaimVerifier],
) -> Result<()> {
    if pending.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3 pending verifier census mismatch"));
    }
    for (index, claim) in pending.iter().enumerate() {
        validate_pending_descriptor(statement, index, &claim.descriptor)?;
    }
    Ok(())
}

fn validate_pending_frame_shape(
    statements: &[C6BlindResidualStatement],
    frame: &C6BlindResidualPendingTransferFrame,
) -> Result<()> {
    validate_statement_pair(statements)?;
    if frame.entries.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3 pending transfer frame census mismatch"));
    }
    for (statement, entries) in
        statements.iter().zip(frame.entries.chunks_exact(C6_RESIDUAL_TABLES_PER_REPETITION))
    {
        for (index, entry) in entries.iter().enumerate() {
            validate_pending_descriptor(statement, index, &entry.descriptor)?;
        }
    }
    Ok(())
}

fn validate_pending_transfer_descriptors(
    statement: &C6BlindResidualStatement,
    transfers: &[C6BlindResidualPendingTransfer],
    common_point: &[Fp2],
) -> Result<()> {
    if transfers.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3 local pending transfer census mismatch"));
    }
    let auxiliary_point =
        &common_point[common_point.len() - statement.reference.auxiliary().rounds()..];
    for (index, transfer) in transfers.iter().enumerate() {
        validate_pending_descriptor(statement, index, &transfer.descriptor)?;
        let expected_point = if index < C6_RESIDUAL_LEAF_TABLES_PER_REPETITION {
            common_point
        } else {
            auxiliary_point
        };
        if transfer.descriptor.point != expected_point {
            return Err(C6BlindResidualError::new("C6RSC3 pending transfer point mismatch"));
        }
    }
    Ok(())
}

fn validate_pending_descriptor(
    statement: &C6BlindResidualStatement,
    index: usize,
    descriptor: &C6BlindResidualPendingDescriptor,
) -> Result<()> {
    let (family, table) = if index < C6_RESIDUAL_LEAF_TABLES_PER_REPETITION {
        (C6ResidualSumcheckFamily::LeafRaw, statement.reference.leaf().tables()[index])
    } else {
        let auxiliary_index = index - C6_RESIDUAL_LEAF_TABLES_PER_REPETITION;
        (
            C6ResidualSumcheckFamily::Auxiliary,
            statement.reference.auxiliary().tables()[auxiliary_index],
        )
    };
    if descriptor.statement_digest != statement.digest
        || descriptor.repetition != statement.repetition()
        || descriptor.family != family
        || descriptor.table != table
    {
        return Err(C6BlindResidualError::new("C6RSC3 pending descriptor owner mismatch"));
    }
    Ok(())
}

fn authenticate_prover_values(
    stream: &mut CorrelationStream,
    domain: u64,
    values: &[Fp2],
) -> Result<(Vec<Fp2>, Vec<ProverAuthed>)> {
    let correlations = stream.draw_fulls(domain, values.len());
    stream.record_c6_fullfield_plaintexts(domain, values).map_err(clear_error)?;
    let mut corrections = Vec::with_capacity(values.len());
    let mut auth = Vec::with_capacity(values.len());
    for (&value, correlation) in values.iter().zip(correlations) {
        corrections.push(value - correlation.x);
        auth.push(correlation.authenticate(value));
    }
    Ok((corrections, auth))
}

fn interpolate_prover(
    family: C6ResidualSumcheckFamily,
    nodes: &[ProverAuthed],
    challenge: Fp2,
) -> Result<ProverAuthed> {
    let weights = interpolation_weights(family, nodes.len(), challenge)?;
    Ok(nodes
        .iter()
        .zip(weights)
        .fold(ProverAuthed::ZERO, |sum, (node, weight)| sum.add(node.scale(weight))))
}

fn interpolate_verifier(
    family: C6ResidualSumcheckFamily,
    nodes: &[VerifierKey],
    challenge: Fp2,
) -> Result<VerifierKey> {
    let weights = interpolation_weights(family, nodes.len(), challenge)?;
    Ok(nodes
        .iter()
        .zip(weights)
        .fold(VerifierKey::ZERO, |sum, (node, weight)| sum.add(node.scale(weight))))
}

fn interpolation_weights(
    family: C6ResidualSumcheckFamily,
    count: usize,
    challenge: Fp2,
) -> Result<Vec<Fp2>> {
    match family {
        C6ResidualSumcheckFamily::LeafRaw if count == 3 => Ok(lagrange3(challenge).to_vec()),
        C6ResidualSumcheckFamily::Auxiliary if count == 4 => Ok(lagrange4(challenge).to_vec()),
        _ => Err(C6BlindResidualError::new("C6RSC3 interpolation degree mismatch")),
    }
}

fn family_degree(family: C6ResidualSumcheckFamily) -> usize {
    match family {
        C6ResidualSumcheckFamily::LeafRaw => 2,
        C6ResidualSumcheckFamily::Auxiliary => 3,
    }
}

fn validate_statement_pair(statements: &[C6BlindResidualStatement]) -> Result<()> {
    if statements.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
        return Err(C6BlindResidualError::new(
            "C6RSC3 semantic statement repetition count mismatch",
        ));
    }
    for (index, statement) in statements.iter().enumerate() {
        statement.validate()?;
        if usize::from(statement.repetition()) != index {
            return Err(C6BlindResidualError::new("C6RSC3 semantic statements are reordered"));
        }
    }
    Ok(())
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum CorrelationPurpose {
    LeafRound = 1,
    AuxiliaryRound = 2,
    PendingClaims = 3,
    ProductValues = 4,
    ProductMask = 5,
    ZeroMask = 6,
}

fn correlation_domain(
    repetition: u8,
    tape: usize,
    purpose: CorrelationPurpose,
    index: usize,
) -> Result<u64> {
    if usize::from(repetition) >= C6_RESIDUAL_SUMCHECK_REPETITIONS
        || tape >= MAC_TAPES
        || index > u16::MAX as usize
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 correlation domain component is out of range",
        ));
    }
    let domain = 0x0C63_0000_0000_0000u64
        | (u64::from(repetition) << 28)
        | ((tape as u64) << 24)
        | ((purpose as u64) << 16)
        | index as u64;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(C6BlindResidualError::new("C6RSC3 correlation domain uses reserved bits"));
    }
    Ok(domain)
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

fn proof_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PROOF_DOMAIN);
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    *hasher.finalize().as_bytes()
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
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

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6BlindResidualError::new("truncated C6RSC3 proof"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2_vec(&mut self, count: usize) -> Result<Vec<Fp2>> {
        (0..count).map(|_| self.fp2()).collect()
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let mut c0 = [0; 8];
        let mut c1 = [0; 8];
        c0.copy_from_slice(self.take(8)?);
        c1.copy_from_slice(self.take(8)?);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C6BlindResidualError::new("noncanonical C6RSC3 field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c6_residual_sumcheck::{
        prepare_residual_sumcheck_verifier_round_state, C6ResidualSumcheckTerm,
    };
    use volta_mac::CorrCounters;
    #[cfg(feature = "c6-trace")]
    use volta_proto::{build_c6_residual_fused_scaled_fixture, C6ResidualFusedCoefficientArena};

    const LEAF_ROUNDS: usize = 5;
    const AUXILIARY_ROUNDS: usize = 3;
    const CHALLENGE_SEED: [u8; 32] = [0x91; 32];
    const TAPE_SEEDS: [[u8; 32]; MAC_TAPES] = [[0x31; 32], [0x52; 32]];

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(19 * value + 7))
    }

    fn table(rounds: usize, base: u64) -> Vec<Fp2> {
        (0..(1usize << rounds)).map(|index| symbol(base + index as u64 + 1)).collect()
    }

    fn expression_sum(terms: &[C6ResidualSumcheckTerm], tables: &[Vec<Fp2>]) -> Fp2 {
        terms.iter().fold(Fp2::ZERO, |total, term| match term {
            C6ResidualSumcheckTerm::Linear { table, coefficients } => {
                total
                    + coefficients
                        .iter()
                        .zip(&tables[usize::from(*table)])
                        .fold(Fp2::ZERO, |sum, (&coefficient, &value)| sum + coefficient * value)
            }
            C6ResidualSumcheckTerm::Quadratic { lhs, rhs, coefficients } => {
                total
                    + coefficients
                        .iter()
                        .zip(tables[usize::from(*lhs)].iter().zip(&tables[usize::from(*rhs)]))
                        .fold(Fp2::ZERO, |sum, (&coefficient, (&left, &right))| {
                            sum + coefficient * left * right
                        })
            }
        })
    }

    fn scaled_statement_and_witness(
        repetition: u8,
    ) -> (C6BlindResidualStatement, C6ResidualSumcheckWitness) {
        let base = 10_000 * u64::from(repetition);
        let leaf_tables = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION as u64)
            .map(|table_index| table(LEAF_ROUNDS, base + 100 * table_index))
            .collect::<Vec<_>>();
        let auxiliary_tables = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION as u64)
            .map(|table_index| table(AUXILIARY_ROUNDS, base + 2_000 + 100 * table_index))
            .collect::<Vec<_>>();
        let leaf_terms = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION)
            .map(|table_index| {
                C6ResidualSumcheckTerm::linear(
                    table_index as u8,
                    table(LEAF_ROUNDS, base + 4_000 + 100 * table_index as u64),
                )
            })
            .collect::<Vec<_>>();
        let mut auxiliary_terms = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION)
            .map(|table_index| {
                C6ResidualSumcheckTerm::linear(
                    table_index as u8,
                    table(AUXILIARY_ROUNDS, base + 6_000 + 100 * table_index as u64),
                )
            })
            .collect::<Vec<_>>();
        auxiliary_terms.extend(C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.iter().enumerate().map(
            |(index, (lhs, rhs))| {
                C6ResidualSumcheckTerm::quadratic(
                    *lhs,
                    *rhs,
                    table(AUXILIARY_ROUNDS, base + 8_000 + 100 * index as u64),
                )
                .unwrap()
            },
        ));
        let target = expression_sum(&leaf_terms, &leaf_tables)
            + expression_sum(&auxiliary_terms, &auxiliary_tables);
        let reference = C6ResidualSumcheckStatement::new_test(
            repetition,
            target,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            leaf_terms,
            auxiliary_terms,
        )
        .unwrap();
        let witness =
            C6ResidualSumcheckWitness::new(&reference, leaf_tables, auxiliary_tables).unwrap();
        let semantic_digest = [0xA0 + repetition; 32];
        (prepare_c6_blind_residual_statement(reference, semantic_digest).unwrap(), witness)
    }

    fn fixture() -> (Vec<C6BlindResidualStatement>, Vec<C6ResidualSumcheckWitness>) {
        let pairs = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS as u8)
            .map(scaled_statement_and_witness)
            .collect::<Vec<_>>();
        pairs.into_iter().unzip()
    }

    fn prover_streams() -> [CorrelationStream; MAC_TAPES] {
        array::from_fn(|tape| CorrelationStream::new(TAPE_SEEDS[tape]))
    }

    fn verifier_contexts() -> [VerifierCtx; MAC_TAPES] {
        [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xE2)),
        ]
    }

    struct ProvedFixture {
        statements: Vec<C6BlindResidualStatement>,
        proof: C6BlindResidualSumcheckProof,
        frame: C6BlindResidualPendingTransferFrame,
        pending: C6BlindResidualPendingClaimsProver,
        trace: ReferenceTrace,
        transcript: Transcript,
        counters: [CorrCounters; MAC_TAPES],
    }

    fn prove_fixture() -> ProvedFixture {
        let (statements, witnesses) = fixture();
        let mut streams = prover_streams();
        let mut transcript = Transcript::new(CHALLENGE_SEED);
        let (proof, frame, pending, trace) = prove_c6_blind_residual_sumchecks_reference_inner(
            &statements,
            &witnesses,
            &mut streams,
            &mut transcript,
        )
        .unwrap();
        let counters = array::from_fn(|tape| streams[tape].counters);
        ProvedFixture { statements, proof, frame, pending, trace, transcript, counters }
    }

    fn verify_fixture(
        fixture: &ProvedFixture,
        proof: &C6BlindResidualSumcheckProof,
        frame: &C6BlindResidualPendingTransferFrame,
    ) -> Result<(C6BlindResidualPendingClaimsVerifier, Transcript)> {
        let mut contexts = verifier_contexts();
        let mut transcript = Transcript::new(CHALLENGE_SEED);
        let pending = verify_c6_blind_residual_sumchecks(
            &fixture.statements,
            proof,
            frame,
            &mut contexts,
            &mut transcript,
        )?;
        Ok((pending, transcript))
    }

    #[test]
    fn production_codec_and_correlation_census_are_exact() {
        assert_eq!(C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION, 93);
        assert_eq!(C6_RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE, 206);
        assert_eq!(C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE, 48);
        assert_eq!(C6_RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE, 254);
        assert_eq!(
            PROOF_FIXED_FRAMING_BYTES
                + 2 * 2 * (C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION + 13) * FP2_BYTES,
            C6_RESIDUAL_BLIND_PROOF_BYTES,
        );
        assert_eq!(production_c6_blind_residual_sumcheck_encoded_len(), 6_900);
        for repetition in 0..2 {
            for tape in 0..2 {
                for purpose in [
                    CorrelationPurpose::LeafRound,
                    CorrelationPurpose::AuxiliaryRound,
                    CorrelationPurpose::PendingClaims,
                    CorrelationPurpose::ProductValues,
                    CorrelationPurpose::ProductMask,
                    CorrelationPurpose::ZeroMask,
                ] {
                    assert_eq!(
                        correlation_domain(repetition, tape, purpose, 7).unwrap()
                            & RESERVED_DOMAIN_BITS,
                        0
                    );
                }
            }
        }
    }

    #[test]
    fn scaled_dual_tape_proof_is_strict_and_matches_clear_reference() {
        let fixture = prove_fixture();
        let encoded = fixture.proof.encode(&fixture.statements).unwrap();
        assert_eq!(encoded.len(), 2_292);
        assert_eq!(fixture.proof.encoded_len(&fixture.statements).unwrap(), encoded.len() as u64);
        assert_eq!(
            C6BlindResidualSumcheckProof::decode(&fixture.statements, &encoded).unwrap(),
            fixture.proof
        );
        assert_eq!(fixture.frame.len(), 48);
        assert_eq!(fixture.frame.correction_wire_bytes(), 1_536);
        assert_eq!(fixture.pending.len(), 48);
        assert_ne!(
            fixture.proof.repetitions[0].tapes[0].leaf_round_corrections[0],
            fixture.proof.repetitions[0].tapes[1].leaf_round_corrections[0]
        );
        assert_ne!(fixture.statements[0].digest(), fixture.statements[1].digest());

        for tape in 0..MAC_TAPES {
            assert_eq!(fixture.counters[tape].full_corrs, 110);
            assert_eq!(fixture.counters[tape].sub_corrs, 0);
            assert_eq!(fixture.counters[tape].domains, 24);
        }

        let (verified, verifier_transcript) =
            verify_fixture(&fixture, &fixture.proof, &fixture.frame).unwrap();
        assert_eq!(verified.len(), 48);
        assert_eq!(fixture.transcript.ledger(), verifier_transcript.ledger());
        assert_eq!(
            fixture.transcript.total_bytes(),
            encoded.len() as u64 + fixture.frame.correction_wire_bytes()
        );

        let deltas = [symbol(0xD1), symbol(0xE2)];
        for index in 0..fixture.pending.len() {
            for (tape, delta) in deltas.iter().copied().enumerate() {
                let prover = fixture.pending.authed_for_tape(index, tape).unwrap();
                let verifier = verified.key_for_tape(index, tape).unwrap();
                assert_eq!(verifier.k, prover.m + delta * prover.x);
            }
        }

        for repetition in 0..C6_RESIDUAL_SUMCHECK_REPETITIONS {
            let mut verifier = prepare_residual_sumcheck_verifier_round_state(
                fixture.statements[repetition].reference(),
                &fixture.trace.proofs[repetition],
            )
            .unwrap();
            for challenge in &fixture.trace.challenges[repetition] {
                verifier.check_next_round().unwrap();
                verifier.bind_challenge(*challenge).unwrap();
            }
            assert_eq!(
                verifier.finish(&fixture.trace.claims[repetition]).unwrap(),
                fixture.trace.claims[repetition]
            );
            for (local_index, clear_claim) in fixture.trace.claims[repetition].iter().enumerate() {
                let global_index = repetition * C6_RESIDUAL_TABLES_PER_REPETITION + local_index;
                assert_eq!(
                    fixture.pending.authed_for_tape(global_index, 0).unwrap().x,
                    clear_claim.value
                );
            }
        }
    }

    #[test]
    fn strict_codec_rejects_old_noncanonical_corrupt_and_mismatched_bytes() {
        let fixture = prove_fixture();
        let encoded = fixture.proof.encode(&fixture.statements).unwrap();

        let mut old = encoded.clone();
        old[..8].copy_from_slice(b"C6RSC2\0\0");
        old[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(C6BlindResidualSumcheckProof::decode(&fixture.statements, &old).is_err());

        let mut noncanonical = encoded.clone();
        // 12-byte global prefix + 36-byte repetition header.
        noncanonical[48..56].copy_from_slice(&P.to_le_bytes());
        assert!(C6BlindResidualSumcheckProof::decode(&fixture.statements, &noncanonical).is_err());

        let mut corrupt = encoded.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(C6BlindResidualSumcheckProof::decode(&fixture.statements, &corrupt).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6BlindResidualSumcheckProof::decode(&fixture.statements, &trailing).is_err());

        let mut wrong_statements = fixture.statements.clone();
        wrong_statements[0].semantic_compiler_digest[0] ^= 1;
        wrong_statements[0].digest = semantic_statement_digest(
            wrong_statements[0].reference(),
            wrong_statements[0].semantic_compiler_digest,
        );
        assert!(C6BlindResidualSumcheckProof::decode(&wrong_statements, &encoded).is_err());
    }

    #[test]
    fn every_blind_terminal_seam_fails_closed_on_tamper() {
        let fixture = prove_fixture();

        let mut round = fixture.proof.clone();
        round.repetitions[0].tapes[0].leaf_round_corrections[1][0] += Fp2::ONE;
        assert!(verify_fixture(&fixture, &round, &fixture.frame).is_err());

        let mut activation = fixture.proof.clone();
        activation.repetitions[0].tapes[1].activation_tag += Fp2::ONE;
        assert!(verify_fixture(&fixture, &activation, &fixture.frame).is_err());

        let mut product_value = fixture.proof.clone();
        product_value.repetitions[1].tapes[0].product_corrections[3] += Fp2::ONE;
        assert!(verify_fixture(&fixture, &product_value, &fixture.frame).is_err());

        let mut product_proof = fixture.proof.clone();
        product_proof.repetitions[0].tapes[1].product_m0 += Fp2::ONE;
        assert!(verify_fixture(&fixture, &product_proof, &fixture.frame).is_err());

        let mut zero_mask = fixture.proof.clone();
        zero_mask.repetitions[1].tapes[0].zero_mask_correction += Fp2::ONE;
        assert!(verify_fixture(&fixture, &zero_mask, &fixture.frame).is_err());

        let mut zero_tag = fixture.proof.clone();
        zero_tag.repetitions[0].tapes[0].zero_tag += Fp2::ONE;
        assert!(verify_fixture(&fixture, &zero_tag, &fixture.frame).is_err());

        let mut pending = fixture.frame.clone();
        pending.entries[7].corrections[1] += Fp2::ONE;
        assert!(verify_fixture(&fixture, &fixture.proof, &pending).is_err());

        let mut owner = fixture.frame.clone();
        owner.entries.swap(0, 1);
        assert!(verify_fixture(&fixture, &fixture.proof, &owner).is_err());

        let mut tape_swap = fixture.proof.clone();
        tape_swap.repetitions[0].tapes.swap(0, 1);
        assert!(verify_fixture(&fixture, &tape_swap, &fixture.frame).is_err());
    }

    #[test]
    fn equal_mac_coordinates_and_bad_topology_are_rejected() {
        let fixture = prove_fixture();
        let mut contexts = [
            VerifierCtx::new(TAPE_SEEDS[0], symbol(0xD1)),
            VerifierCtx::new(TAPE_SEEDS[1], symbol(0xD1)),
        ];
        let mut transcript = Transcript::new(CHALLENGE_SEED);
        assert!(verify_c6_blind_residual_sumchecks(
            &fixture.statements,
            &fixture.proof,
            &fixture.frame,
            &mut contexts,
            &mut transcript,
        )
        .is_err());

        let (statement, _) = scaled_statement_and_witness(0);
        let mut bad_reference = statement.reference.clone();
        let mut auxiliary_terms = bad_reference.auxiliary().terms().to_vec();
        auxiliary_terms.pop();
        bad_reference = C6ResidualSumcheckStatement::new_test(
            0,
            bad_reference.target(),
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            bad_reference.leaf().terms().to_vec(),
            auxiliary_terms,
        )
        .unwrap();
        assert!(prepare_c6_blind_residual_statement(bad_reference, [0xA0; 32]).is_err());
        assert!(prepare_c6_blind_residual_statement(statement.reference, [0; 32]).is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn fused_scaled_prover_is_byte_transcript_and_pending_identical() {
        let fused_fixture = build_c6_residual_fused_scaled_fixture().unwrap();
        let mut statements = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
        let mut witnesses = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
        for atomic in fused_fixture.compilation().statements() {
            let reference =
                C6ResidualSumcheckStatement::from_atomic_relation_reference(atomic).unwrap();
            let witness = C6ResidualSumcheckWitness::new(
                &reference,
                fused_fixture.reference().leaf_tables().to_vec(),
                fused_fixture.reference().auxiliary_tables().to_vec(),
            )
            .unwrap();
            let semantic =
                fused_fixture.semantic_compiler_digest(atomic.proof_repetition()).unwrap();
            statements.push(prepare_c6_blind_residual_statement(reference, semantic).unwrap());
            witnesses.push(witness);
        }
        let compiler = C6BlindResidualFusedCompilerContext::new(
            fused_fixture.operation_plan(),
            fused_fixture.extraction(),
            fused_fixture.runtime(),
            fused_fixture.linear(),
            fused_fixture.relation(),
        );
        let arena = C6ResidualFusedCoefficientArena::new(fused_fixture.manifest());

        let mut reference_streams = prover_streams();
        let mut reference_transcript = Transcript::new(CHALLENGE_SEED);
        let (reference_proof, reference_frame, reference_pending, reference_trace) =
            prove_c6_blind_residual_sumchecks_reference_inner(
                &statements,
                &witnesses,
                &mut reference_streams,
                &mut reference_transcript,
            )
            .unwrap();

        let mut fused_streams = prover_streams();
        let mut fused_transcript = Transcript::new(CHALLENGE_SEED);
        let (fused_proof, fused_frame, fused_pending) =
            prove_c6_blind_residual_sumchecks_fused_scaled(
                &statements,
                &witnesses,
                compiler,
                fused_fixture.witness_view().unwrap(),
                &arena,
                &mut fused_streams,
                &mut fused_transcript,
            )
            .unwrap();

        assert_eq!(fused_proof, reference_proof);
        assert_eq!(fused_frame, reference_frame);
        assert_eq!(fused_pending, reference_pending);
        assert_eq!(
            fused_proof.encode(&statements).unwrap(),
            reference_proof.encode(&statements).unwrap()
        );
        assert_eq!(fused_transcript.ledger(), reference_transcript.ledger());
        assert_eq!(fused_transcript.total_bytes(), reference_transcript.total_bytes());
        assert_eq!(
            array::from_fn::<_, MAC_TAPES, _>(|tape| fused_streams[tape].counters),
            array::from_fn::<_, MAC_TAPES, _>(|tape| reference_streams[tape].counters),
        );
        assert_eq!(arena.active_repetition(), None);
        assert_eq!(arena.active_elements(), 0);
        assert_eq!(arena.reserved_elements(), 0);
        assert_eq!(arena.peak_elements(), 512);
        assert_eq!(arena.peak_reserved_elements(), 512);
        assert!(!arena.is_faulted());

        for repetition in 0..C6_RESIDUAL_SUMCHECK_REPETITIONS {
            assert_eq!(
                reference_trace.claims[repetition]
                    .iter()
                    .map(|claim| claim.value)
                    .collect::<Vec<_>>(),
                (0..C6_RESIDUAL_TABLES_PER_REPETITION)
                    .map(|local| {
                        fused_pending
                            .authed_for_tape(
                                repetition * C6_RESIDUAL_TABLES_PER_REPETITION + local,
                                0,
                            )
                            .unwrap()
                            .x
                    })
                    .collect::<Vec<_>>()
            );
        }
        let mut reference_contexts = verifier_contexts();
        let mut reference_verifier_transcript = Transcript::new(CHALLENGE_SEED);
        let reference_verified = verify_c6_blind_residual_sumchecks(
            &statements,
            &fused_proof,
            &fused_frame,
            &mut reference_contexts,
            &mut reference_verifier_transcript,
        )
        .unwrap();
        let mut fused_contexts = verifier_contexts();
        let mut fused_verifier_transcript = Transcript::new(CHALLENGE_SEED);
        let fused_verified = verify_c6_blind_residual_sumchecks_fused_scaled(
            &statements,
            &fused_proof,
            &fused_frame,
            compiler,
            &mut fused_contexts,
            &mut fused_verifier_transcript,
        )
        .unwrap();
        assert_eq!(fused_verified, reference_verified);
        assert_eq!(fused_verified.len(), C6_RESIDUAL_SUMCHECK_REPETITIONS * 24);
        assert_eq!(reference_verifier_transcript.ledger(), fused_transcript.ledger());
        assert_eq!(fused_verifier_transcript.ledger(), fused_transcript.ledger());

        // The blind statement digest intentionally binds coefficient
        // semantics, geometry and owners, not the scaled materialized arrays.
        // Mutating those diagnostic arrays must break only the old reference
        // terminal evaluator; the fused verifier remains byte-identical.
        let mut mutated_statements = Vec::with_capacity(statements.len());
        for (repetition, statement) in statements.iter().enumerate() {
            let table = reference_trace.claims[repetition]
                [..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION]
                .iter()
                .position(|claim| claim.value != Fp2::ZERO)
                .expect("scaled fixture has a nonzero leaf terminal claim");
            let mut leaf_terms = statement.reference.leaf().terms().to_vec();
            let C6ResidualSumcheckTerm::Linear { coefficients, .. } = &mut leaf_terms[table] else {
                panic!("canonical leaf term is linear");
            };
            for coefficient in coefficients {
                *coefficient += Fp2::ONE;
            }
            let mutated_reference = C6ResidualSumcheckStatement::new_test(
                statement.repetition(),
                statement.target(),
                statement.reference.leaf().rounds(),
                statement.reference.auxiliary().rounds(),
                leaf_terms,
                statement.reference.auxiliary().terms().to_vec(),
            )
            .unwrap();
            let mutated = prepare_c6_blind_residual_statement(
                mutated_reference,
                statement.semantic_compiler_digest(),
            )
            .unwrap();
            assert_eq!(mutated.digest(), statement.digest());
            mutated_statements.push(mutated);
        }
        let mut stale_reference_contexts = verifier_contexts();
        let mut stale_reference_transcript = Transcript::new(CHALLENGE_SEED);
        assert!(verify_c6_blind_residual_sumchecks(
            &mutated_statements,
            &fused_proof,
            &fused_frame,
            &mut stale_reference_contexts,
            &mut stale_reference_transcript,
        )
        .is_err());
        let mut independent_fused_contexts = verifier_contexts();
        let mut independent_fused_transcript = Transcript::new(CHALLENGE_SEED);
        let independent_fused = verify_c6_blind_residual_sumchecks_fused_scaled(
            &mutated_statements,
            &fused_proof,
            &fused_frame,
            compiler,
            &mut independent_fused_contexts,
            &mut independent_fused_transcript,
        )
        .unwrap();
        assert_eq!(independent_fused, fused_verified);
        assert_eq!(independent_fused_transcript.ledger(), fused_transcript.ledger());

        let mut wrong_semantic_statements = statements.clone();
        wrong_semantic_statements[0].semantic_compiler_digest[0] ^= 1;
        wrong_semantic_statements[0].digest = semantic_statement_digest(
            wrong_semantic_statements[0].reference(),
            wrong_semantic_statements[0].semantic_compiler_digest(),
        );
        let mut wrong_semantic_proof = fused_proof.clone();
        wrong_semantic_proof.repetitions[0].statement_digest =
            wrong_semantic_statements[0].digest();
        let mut wrong_semantic_frame = fused_frame.clone();
        for entry in &mut wrong_semantic_frame.entries[..C6_RESIDUAL_TABLES_PER_REPETITION] {
            entry.descriptor.statement_digest = wrong_semantic_statements[0].digest();
        }
        let mut wrong_semantic_contexts = verifier_contexts();
        let mut wrong_semantic_transcript = Transcript::new(CHALLENGE_SEED);
        assert!(verify_c6_blind_residual_sumchecks_fused_scaled(
            &wrong_semantic_statements,
            &wrong_semantic_proof,
            &wrong_semantic_frame,
            compiler,
            &mut wrong_semantic_contexts,
            &mut wrong_semantic_transcript,
        )
        .is_err());
    }
}

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

#[cfg(feature = "c6-trace")]
use rayon::prelude::*;
use volta_field::{Fp, Fp2, P};
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_verify,
    CorrelationStream, ProductMaskCorr, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
    RESERVED_DOMAIN_BITS,
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
    compile_c6_residual_fused_terminal_coefficients, replay_c6_residual_atomic_events,
    C6CompiledLinearResidual, C6ResidualAtomicEventAuditSink, C6ResidualFusedCoefficientArena,
    C6ResidualFusedCoefficientFamily, C6ResidualFusedFirstRound, C6ResidualFusedFoldedCoefficients,
    C6ResidualFusedWitnessView, C6ResidualRelationChallenges,
    C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE, C6_RESIDUAL_TERMINAL_FUNCTIONALS,
    C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION,
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
#[cfg(feature = "c6-trace")]
const DIRECT_TERMINAL_OUTPUTS_DOMAIN: &str =
    "volta-zk/c6/residual-sumcheck-direct-terminal-outputs/v4";
#[cfg(feature = "c6-trace")]
const DIRECT_TERMINAL_FOLD_DOMAIN: &str = "volta-zk/c6/residual-sumcheck-direct-terminal-fold/v4";
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
pub const C6_RESIDUAL_BLIND_PENDING_BYTES: u64 =
    C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE * PENDING_CORRECTION_BYTES_PER_CLAIM;
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
    reference: Option<C6ResidualSumcheckStatement>,
    repetition: u8,
    target: Fp2,
    leaf_rounds: usize,
    auxiliary_rounds: usize,
    leaf_tables: [C6ResidualTableRef; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
    auxiliary_tables: [C6ResidualTableRef; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
    semantic_compiler_digest: [u8; 32],
    digest: [u8; 32],
}

impl C6BlindResidualStatement {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn semantic_compiler_digest(&self) -> [u8; 32] {
        self.semantic_compiler_digest
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    fn reference(&self) -> &C6ResidualSumcheckStatement {
        self.reference.as_ref().expect("scaled C6RSC3 statement retains its reference")
    }

    pub fn auxiliary_activation_round(&self) -> usize {
        self.leaf_rounds - self.auxiliary_rounds
    }

    fn leaf_rounds(&self) -> usize {
        self.leaf_rounds
    }

    fn auxiliary_rounds(&self) -> usize {
        self.auxiliary_rounds
    }

    fn leaf_tables(&self) -> &[C6ResidualTableRef; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] {
        &self.leaf_tables
    }

    fn auxiliary_tables(
        &self,
    ) -> &[C6ResidualTableRef; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION] {
        &self.auxiliary_tables
    }

    fn reference_result(&self) -> Result<&C6ResidualSumcheckStatement> {
        self.reference.as_ref().ok_or_else(|| {
            C6BlindResidualError::new("compact C6RSC3 statement has no materialized reference")
        })
    }

    fn validate(&self) -> Result<()> {
        validate_statement_shape(self)?;
        if let Some(reference) = &self.reference {
            validate_reference_topology(reference)?;
            if reference.repetition() != self.repetition
                || reference.target() != self.target
                || reference.leaf().rounds() != self.leaf_rounds
                || reference.auxiliary().rounds() != self.auxiliary_rounds
                || reference.leaf().tables() != self.leaf_tables
                || reference.auxiliary().tables() != self.auxiliary_tables
            {
                return Err(C6BlindResidualError::new(
                    "C6RSC3 reference differs from compact statement shape",
                ));
            }
        }
        if self.semantic_compiler_digest == [0; 32]
            || self.digest == [0; 32]
            || self.digest != semantic_statement_digest(self, self.semantic_compiler_digest)
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
    let leaf_tables = reference
        .leaf()
        .tables()
        .try_into()
        .map_err(|_| C6BlindResidualError::new("C6RSC3 leaf owner census mismatch"))?;
    let auxiliary_tables = reference
        .auxiliary()
        .tables()
        .try_into()
        .map_err(|_| C6BlindResidualError::new("C6RSC3 auxiliary owner census mismatch"))?;
    let mut statement = C6BlindResidualStatement {
        repetition: reference.repetition(),
        target: reference.target(),
        leaf_rounds: reference.leaf().rounds(),
        auxiliary_rounds: reference.auxiliary().rounds(),
        leaf_tables,
        auxiliary_tables,
        reference: Some(reference),
        semantic_compiler_digest,
        digest: [0; 32],
    };
    statement.digest = semantic_statement_digest(&statement, semantic_compiler_digest);
    statement.validate()?;
    Ok(statement)
}

#[cfg(feature = "c6-trace")]
pub fn prepare_c6_blind_residual_statement_fused(
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    repetition: u8,
) -> Result<C6BlindResidualStatement> {
    let mut audit = C6ResidualAtomicEventAuditSink::new(repetition);
    let summary = replay_c6_residual_atomic_events(
        compiler.operation_plan,
        compiler.extraction,
        compiler.runtime,
        compiler.linear,
        compiler.relation,
        repetition,
        &mut audit,
    )
    .map_err(clear_error)?;
    fused_statement_from_summary(compiler, repetition, summary.target(), summary.semantic_digest())
}

#[cfg(feature = "c6-trace")]
fn fused_statement_from_summary(
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    repetition: u8,
    target: Fp2,
    semantic_compiler_digest: [u8; 32],
) -> Result<C6BlindResidualStatement> {
    let manifest = compiler.relation.manifest();
    let leaf_tables = std::array::from_fn(|slot| C6ResidualTableRef {
        cohort_id: crate::c6_wrapper_pcs::C6_DELTA_RESIDUAL_COHORT_ID,
        slot: slot as u16,
    });
    let auxiliary_tables = std::array::from_fn(|slot| C6ResidualTableRef {
        cohort_id: crate::c6_wrapper_pcs::C6_WRAPPER_AUXILIARY_COHORT_ID,
        slot: slot as u16,
    });
    let mut statement = C6BlindResidualStatement {
        reference: None,
        repetition,
        target,
        leaf_rounds: usize::from(manifest.leaf_log2()),
        auxiliary_rounds: usize::from(manifest.auxiliary_log2()),
        leaf_tables,
        auxiliary_tables,
        semantic_compiler_digest,
        digest: [0; 32],
    };
    statement.digest = semantic_statement_digest(&statement, statement.semantic_compiler_digest);
    statement.validate()?;
    Ok(statement)
}

/// One replay supplies both the compact statement and the sealed first-round
/// message. The latter precedes every verifier challenge, so preparing it
/// here does not alter Fiat-Shamir or interactive transcript order.
#[cfg(feature = "c6-trace")]
#[derive(Clone)]
pub struct C6BlindResidualFusedPreparedRepetition {
    statement: C6BlindResidualStatement,
    first_round: C6ResidualFusedFirstRound,
}

#[cfg(feature = "c6-trace")]
impl C6BlindResidualFusedPreparedRepetition {
    pub fn statement(&self) -> &C6BlindResidualStatement {
        &self.statement
    }
}

#[cfg(feature = "c6-trace")]
pub fn prepare_c6_blind_residual_prover_repetition_fused(
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    fused_witness: C6ResidualFusedWitnessView<'_>,
    repetition: u8,
) -> Result<C6BlindResidualFusedPreparedRepetition> {
    let first_round = compile_c6_residual_fused_first_round(
        compiler.operation_plan,
        compiler.extraction,
        compiler.runtime,
        compiler.linear,
        compiler.relation,
        repetition,
        fused_witness,
    )
    .map_err(clear_error)?;
    let statement = fused_statement_from_summary(
        compiler,
        repetition,
        first_round.target(),
        first_round.semantic_digest(),
    )?;
    if first_round.proof_repetition() != repetition
        || first_round.witness_view_digest() != fused_witness.digest()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 prepared first round differs from its witness/repetition",
        ));
    }
    Ok(C6BlindResidualFusedPreparedRepetition { statement, first_round })
}

fn validate_statement_shape(statement: &C6BlindResidualStatement) -> Result<()> {
    if usize::from(statement.repetition) >= C6_RESIDUAL_SUMCHECK_REPETITIONS
        || statement.auxiliary_rounds == 0
        || statement.leaf_rounds < statement.auxiliary_rounds
        || statement.leaf_rounds >= usize::BITS as usize
        || statement.leaf_tables.iter().enumerate().any(|(slot, table)| {
            table.cohort_id != crate::c6_wrapper_pcs::C6_DELTA_RESIDUAL_COHORT_ID
                || usize::from(table.slot) != slot
        })
        || statement.auxiliary_tables.iter().enumerate().any(|(slot, table)| {
            table.cohort_id != crate::c6_wrapper_pcs::C6_WRAPPER_AUXILIARY_COHORT_ID
                || usize::from(table.slot) != slot
        })
    {
        return Err(C6BlindResidualError::new("C6RSC3 compact statement topology is noncanonical"));
    }
    Ok(())
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
    statement: &C6BlindResidualStatement,
    semantic_compiler_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(&semantic_compiler_digest);
    hasher.update(&[statement.repetition()]);
    hash_fp2(&mut hasher, statement.target());
    let families = [
        (
            C6ResidualSumcheckFamily::LeafRaw,
            statement.leaf_rounds(),
            statement.leaf_tables().as_slice(),
        ),
        (
            C6ResidualSumcheckFamily::Auxiliary,
            statement.auxiliary_rounds(),
            statement.auxiliary_tables().as_slice(),
        ),
    ];
    for (family, rounds, tables) in families {
        hasher.update(&[family as u8]);
        hasher.update(&(rounds as u64).to_le_bytes());
        hasher.update(&(tables.len() as u64).to_le_bytes());
        for table in tables {
            hasher.update(&table.cohort_id.to_le_bytes());
            hasher.update(&table.slot.to_le_bytes());
        }
        let entries = 1u64 << rounds;
        match family {
            C6ResidualSumcheckFamily::LeafRaw => {
                hasher.update(&(C6_RESIDUAL_LEAF_TABLES_PER_REPETITION as u64).to_le_bytes());
                for table in 0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION {
                    hasher.update(&[1, table as u8, 0]);
                    hasher.update(&entries.to_le_bytes());
                }
            }
            C6ResidualSumcheckFamily::Auxiliary => {
                hasher.update(
                    &((C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION + TERMINAL_PRODUCTS) as u64)
                        .to_le_bytes(),
                );
                for table in 0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION {
                    hasher.update(&[1, table as u8, 0]);
                    hasher.update(&entries.to_le_bytes());
                }
                for (lhs, rhs) in C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS {
                    hasher.update(&[2, lhs, rhs]);
                    hasher.update(&entries.to_le_bytes());
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
                u8::try_from(statement.leaf_rounds())
                    .map_err(|_| C6BlindResidualError::new("C6RSC3 leaf rounds exceed codec"))?,
            );
            bytes.push(
                u8::try_from(statement.auxiliary_rounds()).map_err(|_| {
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
                || leaf_rounds != statement.leaf_rounds()
                || auxiliary_rounds != statement.auxiliary_rounds()
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
                    statement.leaf_rounds(),
                    3,
                    2,
                )?;
                validate_round_correction_shape(
                    &tape.auxiliary_round_corrections,
                    statement.auxiliary_rounds(),
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
    let leaf_rounds = statement.leaf_rounds();
    let auxiliary_rounds = statement.auxiliary_rounds();
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
pub struct C6BlindResidualPendingTransferFrame {
    corrections: Vec<[Fp2; MAC_TAPES]>,
}

impl C6BlindResidualPendingTransferFrame {
    pub fn len(&self) -> usize {
        self.corrections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.corrections.is_empty()
    }

    pub fn correction_wire_bytes(&self) -> u64 {
        self.corrections.len() as u64 * PENDING_CORRECTION_BYTES_PER_CLAIM
    }

    /// Canonical wire is corrections only.  Statement owners, table kinds
    /// and evaluation points are reconstructed by the designated verifier
    /// from the already-bound statements and round challenges.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_pending_correction_census(self)?;
        let mut bytes = Vec::with_capacity(C6_RESIDUAL_BLIND_PENDING_BYTES as usize);
        for correction in &self.corrections {
            for value in correction {
                encode_fp2(&mut bytes, *value);
            }
        }
        debug_assert_eq!(bytes.len() as u64, C6_RESIDUAL_BLIND_PENDING_BYTES);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 != C6_RESIDUAL_BLIND_PENDING_BYTES {
            return Err(C6BlindResidualError::new(
                "C6RSC3 pending correction frame length mismatch",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        let mut corrections =
            Vec::with_capacity(C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE as usize);
        for _ in 0..C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE {
            corrections.push([cursor.fp2()?, cursor.fp2()?]);
        }
        if !cursor.is_eof() {
            return Err(C6BlindResidualError::new("trailing C6RSC3 pending correction bytes"));
        }
        let frame = Self { corrections };
        validate_pending_correction_census(&frame)?;
        Ok(frame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualPendingClaimProver {
    descriptor: C6BlindResidualPendingDescriptor,
    auth: [ProverAuthed; MAC_TAPES],
}

#[derive(Clone, PartialEq, Eq)]
pub struct C6BlindResidualPendingClaimsProver {
    claims: Vec<C6BlindResidualPendingClaimProver>,
}

impl fmt::Debug for C6BlindResidualPendingClaimsProver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BlindResidualPendingClaimsProver")
            .field("len", &self.claims.len())
            .field(
                "descriptors",
                &self.claims.iter().map(|claim| &claim.descriptor).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
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

    #[allow(dead_code)]
    pub(crate) fn link_entries(
        &self,
    ) -> Vec<(C6BlindResidualPendingDescriptor, [ProverAuthed; MAC_TAPES])> {
        self.claims.iter().map(|claim| (claim.descriptor.clone(), claim.auth)).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C6BlindResidualPendingClaimVerifier {
    descriptor: C6BlindResidualPendingDescriptor,
    keys: [VerifierKey; MAC_TAPES],
}

#[derive(Clone, PartialEq, Eq)]
pub struct C6BlindResidualPendingClaimsVerifier {
    claims: Vec<C6BlindResidualPendingClaimVerifier>,
}

impl fmt::Debug for C6BlindResidualPendingClaimsVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C6BlindResidualPendingClaimsVerifier")
            .field("len", &self.claims.len())
            .field(
                "descriptors",
                &self.claims.iter().map(|claim| &claim.descriptor).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
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

    #[allow(dead_code)]
    pub(crate) fn link_entries(
        &self,
    ) -> Vec<(C6BlindResidualPendingDescriptor, [VerifierKey; MAC_TAPES])> {
        self.claims.iter().map(|claim| (claim.descriptor.clone(), claim.keys)).collect()
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

#[cfg(feature = "c6-trace")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct C6BlindResidualDirectTerminalRepetition {
    leaf_point: Vec<Fp2>,
    auxiliary_point: Vec<Fp2>,
    terminal_functionals: [Fp2; C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION],
}

/// The exact 64 C6RSC3-v4 terminal coefficient functionals, fixed by the
/// fused prover before the independent output-fold challenge exists.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6BlindResidualDirectTerminalOutputs {
    relation_challenges_digest: [u8; 32],
    statement_digests: [[u8; 32]; C6_RESIDUAL_SUMCHECK_REPETITIONS],
    leaf_points: [Vec<Fp2>; C6_RESIDUAL_SUMCHECK_REPETITIONS],
    auxiliary_points: [Vec<Fp2>; C6_RESIDUAL_SUMCHECK_REPETITIONS],
    terminal_functionals: [Fp2; C6_RESIDUAL_TERMINAL_FUNCTIONALS],
    digest: [u8; 32],
}

#[cfg(feature = "c6-trace")]
impl C6BlindResidualDirectTerminalOutputs {
    fn new(
        statements: &[C6BlindResidualStatement],
        relation: &C6ResidualRelationChallenges,
        repetitions: Vec<C6BlindResidualDirectTerminalRepetition>,
    ) -> Result<Self> {
        if relation.protocol_version() != C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE
            || statements.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS
            || repetitions.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3-v4 terminal outputs require the direct-MLE relation and two repetitions",
            ));
        }
        let statement_digests = statements
            .iter()
            .map(C6BlindResidualStatement::digest)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| C6BlindResidualError::new("C6RSC3-v4 statement census mismatch"))?;
        let leaf_points = repetitions
            .iter()
            .map(|repetition| repetition.leaf_point.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| C6BlindResidualError::new("C6RSC3-v4 leaf-point census mismatch"))?;
        let auxiliary_points = repetitions
            .iter()
            .map(|repetition| repetition.auxiliary_point.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| C6BlindResidualError::new("C6RSC3-v4 auxiliary-point census mismatch"))?;
        let mut terminal_functionals = [Fp2::ZERO; C6_RESIDUAL_TERMINAL_FUNCTIONALS];
        for (repetition, values) in repetitions.iter().enumerate() {
            let start = repetition * C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION;
            terminal_functionals[start..start + C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION]
                .copy_from_slice(&values.terminal_functionals);
        }
        let mut outputs = Self {
            relation_challenges_digest: relation.digest(),
            statement_digests,
            leaf_points,
            auxiliary_points,
            terminal_functionals,
            digest: [0; 32],
        };
        outputs.digest = direct_terminal_outputs_digest(&outputs);
        if outputs.digest == [0; 32] {
            return Err(C6BlindResidualError::new("C6RSC3-v4 terminal-output digest is zero"));
        }
        Ok(outputs)
    }

    pub fn relation_challenges_digest(&self) -> [u8; 32] {
        self.relation_challenges_digest
    }

    pub fn leaf_point(&self, repetition: usize) -> Result<&[Fp2]> {
        self.leaf_points
            .get(repetition)
            .map(Vec::as_slice)
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3-v4 leaf repetition is out of range"))
    }

    pub fn auxiliary_point(&self, repetition: usize) -> Result<&[Fp2]> {
        self.auxiliary_points.get(repetition).map(Vec::as_slice).ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3-v4 auxiliary repetition is out of range")
        })
    }

    pub fn terminal_functionals(&self) -> &[Fp2; C6_RESIDUAL_TERMINAL_FUNCTIONALS] {
        &self.terminal_functionals
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn terminal_scalars_for(
        &self,
        statement: &C6BlindResidualStatement,
        leaf_point: &[Fp2],
        auxiliary_point: &[Fp2],
    ) -> Result<C6BlindResidualTerminalScalars> {
        if self.relation_challenges_digest == [0; 32]
            || self.digest == [0; 32]
            || self.digest != direct_terminal_outputs_digest(self)
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3-v4 direct terminal object is noncanonical",
            ));
        }
        let repetition = usize::from(statement.repetition());
        if repetition >= C6_RESIDUAL_SUMCHECK_REPETITIONS
            || self.statement_digests[repetition] != statement.digest()
            || self.leaf_points[repetition] != leaf_point
            || self.auxiliary_points[repetition] != auxiliary_point
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3-v4 direct terminal statement or point mismatch",
            ));
        }
        let start = repetition * C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION;
        let values = &self.terminal_functionals
            [start..start + C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION];
        let leaf_end = C6_RESIDUAL_LEAF_TABLES_PER_REPETITION;
        let auxiliary_end = leaf_end + C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION;
        Ok(C6BlindResidualTerminalScalars {
            leaf_linear: values[..leaf_end].try_into().map_err(|_| {
                C6BlindResidualError::new("C6RSC3-v4 leaf terminal census mismatch")
            })?,
            auxiliary_linear: values[leaf_end..auxiliary_end].try_into().map_err(|_| {
                C6BlindResidualError::new("C6RSC3-v4 auxiliary terminal census mismatch")
            })?,
            auxiliary_quadratic: values[auxiliary_end..].try_into().map_err(|_| {
                C6BlindResidualError::new("C6RSC3-v4 product terminal census mismatch")
            })?,
        })
    }

    pub fn bind_output_beta(self, beta: Fp2) -> C6BlindResidualDirectTerminalFold {
        let functional_fold = self
            .terminal_functionals
            .iter()
            .fold((Fp2::ZERO, Fp2::ONE), |(sum, power), value| (sum + power * *value, power * beta))
            .0;
        let mut fold = C6BlindResidualDirectTerminalFold {
            terminal_outputs_digest: self.digest,
            beta,
            functional_fold,
            digest: [0; 32],
        };
        let mut hasher = blake3::Hasher::new_derive_key(DIRECT_TERMINAL_FOLD_DOMAIN);
        hasher.update(&fold.terminal_outputs_digest);
        hash_fp2(&mut hasher, fold.beta);
        hash_fp2(&mut hasher, fold.functional_fold);
        fold.digest = *hasher.finalize().as_bytes();
        fold
    }
}

#[cfg(feature = "c6-trace")]
fn direct_terminal_outputs_digest(outputs: &C6BlindResidualDirectTerminalOutputs) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DIRECT_TERMINAL_OUTPUTS_DOMAIN);
    hasher.update(&outputs.relation_challenges_digest);
    for repetition in 0..C6_RESIDUAL_SUMCHECK_REPETITIONS {
        hasher.update(&(repetition as u64).to_le_bytes());
        hasher.update(&outputs.statement_digests[repetition]);
        for point in [&outputs.leaf_points[repetition], &outputs.auxiliary_points[repetition]] {
            hasher.update(&(point.len() as u64).to_le_bytes());
            for coordinate in point {
                hash_fp2(&mut hasher, *coordinate);
            }
        }
    }
    for value in outputs.terminal_functionals {
        hash_fp2(&mut hasher, value);
    }
    *hasher.finalize().as_bytes()
}

/// Post-beta scalar fold of the already-fixed 64 direct-schedule terminal
/// outputs.  This adds no proof or response bytes.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6BlindResidualDirectTerminalFold {
    terminal_outputs_digest: [u8; 32],
    beta: Fp2,
    functional_fold: Fp2,
    digest: [u8; 32],
}

#[cfg(feature = "c6-trace")]
impl C6BlindResidualDirectTerminalFold {
    pub fn terminal_outputs_digest(&self) -> [u8; 32] {
        self.terminal_outputs_digest
    }

    pub fn beta(&self) -> Fp2 {
        self.beta
    }

    pub fn functional_fold(&self) -> Fp2 {
        self.functional_fold
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn terminal_scalars_from_reference(
    statement: &C6BlindResidualStatement,
    leaf_point: &[Fp2],
    auxiliary_point: &[Fp2],
) -> Result<C6BlindResidualTerminalScalars> {
    let reference = statement.reference_result()?;
    let mut terminal = C6BlindResidualTerminalScalars {
        leaf_linear: [Fp2::ZERO; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
        auxiliary_linear: [Fp2::ZERO; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
        auxiliary_quadratic: [Fp2::ZERO; TERMINAL_PRODUCTS],
    };
    for (index, term) in reference.leaf().terms().iter().enumerate() {
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
    for (index, term) in reference.auxiliary().terms().iter().enumerate() {
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
        let clear =
            prepare_residual_sumcheck_prover_round_state(statement.reference_result()?, witness)
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

/// Shared semantic compiler inputs for the fused C6RSC3 path.
///
/// The `c6-trace` feature remains deliberate until the complete response path
/// passes its memory and timing gates.  Fused arithmetic now folds directly
/// from the installed witness view and does not require a materialized padded
/// witness or coefficient statement.
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
    fused_witness: C6ResidualFusedWitnessView<'a>,
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
        arena: &'a C6ResidualFusedCoefficientArena,
        prepared_first_round: Option<&C6ResidualFusedFirstRound>,
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
            || leaf_entries != 1usize << statement.leaf_rounds()
            || auxiliary_entries != 1usize << statement.auxiliary_rounds()
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused compiler/witness/arena geometry mismatch",
            ));
        }
        let first = if let Some(first) = prepared_first_round {
            first.clone()
        } else {
            compile_c6_residual_fused_first_round(
                compiler.operation_plan,
                compiler.extraction,
                compiler.runtime,
                compiler.linear,
                compiler.relation,
                statement.repetition(),
                fused_witness,
            )
            .map_err(clear_error)?
        };
        if first.proof_repetition() != statement.repetition()
            || first.target() != statement.target()
            || first.semantic_digest() != statement.semantic_compiler_digest()
            || first.witness_view_digest() != fused_witness.digest()
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
            fused_witness,
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
        let witness = fold_fused_witness_view(
            C6_RESIDUAL_LEAF_TABLES_PER_REPETITION,
            1usize << self.statement.leaf_rounds(),
            challenge,
            "leaf",
            |table| self.fused_witness.leaf_live_entries(table).map_err(clear_error),
            |table, row| self.fused_witness.leaf_value(table, row).map_err(clear_error),
        )?;
        self.leaf_coefficients = Some(coefficients);
        self.leaf_witness = Some(witness);
        Ok(())
    }

    fn bind_leaf_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let coefficients = self
            .leaf_coefficients
            .as_mut()
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused leaf state is absent"))?;
        let logical_entries = usize::try_from(coefficients.entries_per_table()).map_err(|_| {
            C6BlindResidualError::new("C6RSC3 fused leaf logical length exceeds usize")
        })?;
        coefficients.fold_next(challenge).map_err(clear_error)?;
        fold_witness_tables_in_place(
            self.leaf_witness
                .as_mut()
                .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused leaf witness is absent"))?,
            logical_entries,
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
        let witness = fold_fused_witness_view(
            C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION,
            1usize << self.statement.auxiliary_rounds(),
            challenge,
            "auxiliary",
            |table| self.fused_witness.auxiliary_live_entries(table).map_err(clear_error),
            |table, row| self.fused_witness.auxiliary_value(table, row).map_err(clear_error),
        )?;
        self.auxiliary_coefficients = Some(coefficients);
        self.auxiliary_witness = Some(witness);
        Ok(())
    }

    fn bind_auxiliary_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let coefficients = self
            .auxiliary_coefficients
            .as_mut()
            .ok_or_else(|| C6BlindResidualError::new("C6RSC3 fused auxiliary state is absent"))?;
        let logical_entries = usize::try_from(coefficients.entries_per_table()).map_err(|_| {
            C6BlindResidualError::new("C6RSC3 fused auxiliary logical length exceeds usize")
        })?;
        coefficients.fold_next(challenge).map_err(clear_error)?;
        fold_witness_tables_in_place(
            self.auxiliary_witness.as_mut().ok_or_else(|| {
                C6BlindResidualError::new("C6RSC3 fused auxiliary witness is absent")
            })?,
            logical_entries,
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
        self.statement.leaf_rounds()
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
            || leaf_witness.iter().any(|table| table.len() > 1)
            || auxiliary_witness.iter().any(|table| table.len() > 1)
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
        for (table, witness) in this.statement.leaf_tables().iter().zip(&leaf_witness) {
            opening_claims.push(C6ResidualOpeningClaim {
                repetition: this.statement.repetition(),
                family: C6ResidualSumcheckFamily::LeafRaw,
                table: *table,
                point: leaf_point.clone(),
                value: witness.first().copied().unwrap_or(Fp2::ZERO),
            });
        }
        for (table, witness) in this.statement.auxiliary_tables().iter().zip(&auxiliary_witness) {
            opening_claims.push(C6ResidualOpeningClaim {
                repetition: this.statement.repetition(),
                family: C6ResidualSumcheckFamily::Auxiliary,
                table: *table,
                point: auxiliary_point.clone(),
                value: witness.first().copied().unwrap_or(Fp2::ZERO),
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
fn fold_fused_witness_view<L, V>(
    table_count: usize,
    logical_entries: usize,
    challenge: Fp2,
    family: &str,
    live_entries: L,
    value: V,
) -> Result<Vec<Vec<Fp2>>>
where
    L: Fn(usize) -> Result<usize> + Sync,
    V: Fn(usize, usize) -> Result<Fp2> + Sync,
{
    if table_count == 0 || logical_entries < 2 || logical_entries & 1 != 0 {
        return Err(C6BlindResidualError::new(format!(
            "C6RSC3 fused {family} source witness geometry diverged"
        )));
    }
    (0..table_count)
        .into_par_iter()
        .map(|table| {
            let live_entries = live_entries(table)?;
            if live_entries > logical_entries {
                return Err(C6BlindResidualError::new(format!(
                    "C6RSC3 fused {family} live prefix exceeds its logical table"
                )));
            }
            let folded_entries = live_entries.div_ceil(2);
            let mut values = Vec::new();
            values.try_reserve_exact(folded_entries).map_err(|_| {
                C6BlindResidualError::new(format!(
                    "C6RSC3 fused {family} witness row allocation failed"
                ))
            })?;
            if values.capacity() != folded_entries {
                return Err(C6BlindResidualError::new(format!(
                    "C6RSC3 fused {family} witness reservation is not exact"
                )));
            }
            for row in 0..folded_entries {
                let low = value(table, 2 * row)?;
                let high =
                    if 2 * row + 1 < live_entries { value(table, 2 * row + 1)? } else { Fp2::ZERO };
                values.push(low + (high - low) * challenge);
            }
            Ok(values)
        })
        .collect()
}

#[cfg(feature = "c6-trace")]
fn fold_witness_tables_in_place(
    tables: &mut [Vec<Fp2>],
    logical_entries: usize,
    challenge: Fp2,
    family: &str,
) -> Result<()> {
    if tables.is_empty()
        || logical_entries < 2
        || logical_entries & 1 != 0
        || tables.iter().any(|table| table.len() > logical_entries)
    {
        return Err(C6BlindResidualError::new(format!(
            "C6RSC3 fused {family} folded witness geometry diverged"
        )));
    }
    tables.par_iter_mut().for_each(|table| {
        let next = table.len().div_ceil(2);
        for row in 0..next {
            let low = table[2 * row];
            let high = table.get(2 * row + 1).copied().unwrap_or(Fp2::ZERO);
            table[row] = low + (high - low) * challenge;
        }
        table.truncate(next);
    });
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
            .any(|(values, coefficients)| values.len() > coefficients.len())
    {
        return Err(C6BlindResidualError::new("C6RSC3 fused leaf round geometry diverged"));
    }
    let table_messages = coefficients
        .par_iter()
        .zip(witness.par_iter())
        .map(|(coefficients, witness)| {
            let mut table_message = [Fp2::ZERO; 3];
            for pair in 0..witness.len().div_ceil(2) {
                for (node, evaluation) in table_message.iter_mut().enumerate() {
                    let at = Fp2::from_base(Fp::new(node as u64));
                    *evaluation += fused_affine_pair(coefficients, pair, at)
                        * fused_compact_affine_pair(witness, pair, at);
                }
            }
            table_message
        })
        .collect::<Vec<_>>();
    let mut message = [Fp2::ZERO; 3];
    for table_message in table_messages {
        for (evaluation, contribution) in message.iter_mut().zip(table_message) {
            *evaluation += contribution;
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
            .any(|(values, coefficients)| values.len() > coefficients.len())
    {
        return Err(C6BlindResidualError::new("C6RSC3 fused auxiliary round geometry diverged"));
    }
    let linear_messages = linear
        .par_iter()
        .zip(witness.par_iter())
        .map(|(coefficients, witness)| {
            let mut table_message = [Fp2::ZERO; 4];
            for pair in 0..witness.len().div_ceil(2) {
                for (node, evaluation) in table_message.iter_mut().enumerate() {
                    let at = Fp2::from_base(Fp::new(node as u64));
                    *evaluation += fused_affine_pair(coefficients, pair, at)
                        * fused_compact_affine_pair(witness, pair, at);
                }
            }
            table_message
        })
        .collect::<Vec<_>>();
    let quadratic_messages = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
        .par_iter()
        .zip(quadratic.par_iter())
        .map(|((lhs, rhs), coefficients)| {
            let lhs = &witness[usize::from(*lhs)];
            let rhs = &witness[usize::from(*rhs)];
            let live_pairs = lhs.len().div_ceil(2).min(rhs.len().div_ceil(2));
            let mut table_message = [Fp2::ZERO; 4];
            for pair in 0..live_pairs {
                for (node, evaluation) in table_message.iter_mut().enumerate() {
                    let at = Fp2::from_base(Fp::new(node as u64));
                    *evaluation += fused_affine_pair(coefficients, pair, at)
                        * fused_compact_affine_pair(lhs, pair, at)
                        * fused_compact_affine_pair(rhs, pair, at);
                }
            }
            table_message
        })
        .collect::<Vec<_>>();
    let mut message = [Fp2::ZERO; 4];
    for table_message in linear_messages.into_iter().chain(quadratic_messages) {
        for (evaluation, contribution) in message.iter_mut().zip(table_message) {
            *evaluation += contribution;
        }
    }
    Ok(message.to_vec())
}

#[cfg(feature = "c6-trace")]
fn fused_affine_pair(values: &[Fp2], pair: usize, at: Fp2) -> Fp2 {
    let low = values[2 * pair];
    low + at * (values[2 * pair + 1] - low)
}

#[cfg(feature = "c6-trace")]
fn fused_compact_affine_pair(values: &[Fp2], pair: usize, at: Fp2) -> Fp2 {
    let low = values[2 * pair];
    let high = values.get(2 * pair + 1).copied().unwrap_or(Fp2::ZERO);
    low + at * (high - low)
}

pub(crate) struct C6BlindResidualProverRepetitionOutput {
    proof: C6BlindResidualRepetitionProof,
    pending_claims: Vec<C6BlindResidualPendingClaimProver>,
    pending_transfers: Vec<[Fp2; MAC_TAPES]>,
    challenges: Vec<Fp2>,
    reference_proof: Option<C6ResidualSumcheckRepetitionProof>,
    opening_claims: Vec<C6ResidualOpeningClaim>,
    #[cfg(feature = "c6-trace")]
    terminal_scalars: C6BlindResidualTerminalScalars,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C6BlindResidualFixedRoundReceipt {
    pub(crate) message_bytes: u64,
    pub(crate) correction_bytes: u64,
    pub(crate) activation_tag_bytes: u64,
}

struct C6BlindResidualPendingProverRound {
    leaf_nodes: [Vec<ProverAuthed>; MAC_TAPES],
    auxiliary_nodes: [Vec<ProverAuthed>; MAC_TAPES],
}

pub(crate) struct C6BlindResidualProverRoundState<'a> {
    statement: &'a C6BlindResidualStatement,
    arithmetic: Box<dyn C6BlindResidualProverArithmetic + 'a>,
    builders: [TapeProofBuilder; MAC_TAPES],
    leaf_states: [ProverFamilyAuthState; MAC_TAPES],
    auxiliary_states: [ProverFamilyAuthState; MAC_TAPES],
    challenge_trace: Vec<Fp2>,
    pending: Option<C6BlindResidualPendingProverRound>,
}

fn prepare_c6_blind_residual_prover_round_state_with_arithmetic<'a>(
    statement: &'a C6BlindResidualStatement,
    arithmetic: Box<dyn C6BlindResidualProverArithmetic + 'a>,
) -> Result<C6BlindResidualProverRoundState<'a>> {
    if arithmetic.repetition() != statement.repetition()
        || arithmetic.target() != statement.target()
        || arithmetic.round_count() != statement.leaf_rounds()
        || arithmetic.auxiliary_activation_round() != statement.auxiliary_activation_round()
        || arithmetic.round_index() != 0
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 prover arithmetic does not match its semantic statement",
        ));
    }
    let rounds = arithmetic.round_count();
    Ok(C6BlindResidualProverRoundState {
        statement,
        arithmetic,
        builders: array::from_fn(|_| TapeProofBuilder::default()),
        leaf_states: array::from_fn(|_| ProverFamilyAuthState::default()),
        auxiliary_states: array::from_fn(|_| ProverFamilyAuthState::default()),
        challenge_trace: Vec::with_capacity(rounds),
        pending: None,
    })
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_c6_blind_residual_prover_round_state_fused<'a>(
    statement: &'a C6BlindResidualStatement,
    compiler: C6BlindResidualFusedCompilerContext<'a>,
    fused_witness: C6ResidualFusedWitnessView<'a>,
    arena: &'a C6ResidualFusedCoefficientArena,
    first_round: Option<&'a C6ResidualFusedFirstRound>,
) -> Result<C6BlindResidualProverRoundState<'a>> {
    prepare_c6_blind_residual_prover_round_state_with_arithmetic(
        statement,
        Box::new(C6BlindResidualFusedArithmetic::new(
            statement,
            compiler,
            fused_witness,
            arena,
            first_round,
        )?),
    )
}

impl C6BlindResidualProverRoundState<'_> {
    #[allow(dead_code)]
    pub(crate) fn repetition(&self) -> u8 {
        self.statement.repetition()
    }

    pub(crate) fn round_index(&self) -> usize {
        self.arithmetic.round_index()
    }

    pub(crate) fn round_count(&self) -> usize {
        self.arithmetic.round_count()
    }

    pub(crate) fn fix_next_round(
        &mut self,
        streams: &mut [CorrelationStream; MAC_TAPES],
    ) -> Result<C6BlindResidualFixedRoundReceipt> {
        if self.pending.is_some() || self.round_index() >= self.round_count() {
            return Err(C6BlindResidualError::new(
                "C6RSC3 step-wise prover is not awaiting a round message",
            ));
        }
        let repetition = self.statement.repetition();
        let global_round = self.arithmetic.round_index();
        let (leaf_message, auxiliary_message) = self.arithmetic.fix_next_round()?;
        let mut leaf_nodes: [Vec<ProverAuthed>; MAC_TAPES] = array::from_fn(|_| Vec::new());
        let mut auxiliary_nodes: [Vec<ProverAuthed>; MAC_TAPES] = array::from_fn(|_| Vec::new());
        let mut correction_bytes = 0u64;
        for tape in 0..MAC_TAPES {
            let domain =
                correlation_domain(repetition, tape, CorrelationPurpose::LeafRound, global_round)?;
            let (corrections, nodes) = self.leaf_states[tape].fix_round(
                C6ResidualSumcheckFamily::LeafRaw,
                &leaf_message,
                &mut streams[tape],
                domain,
            )?;
            correction_bytes =
                correction_bytes
                    .checked_add(corrections.len() as u64 * FP2_BYTES)
                    .ok_or_else(|| C6BlindResidualError::new("C6RSC3 round bytes overflow"))?;
            self.builders[tape].leaf_round_corrections.push(corrections);
            leaf_nodes[tape] = nodes;

            if let Some(message) = &auxiliary_message {
                let local_round = global_round - self.statement.auxiliary_activation_round();
                let domain = correlation_domain(
                    repetition,
                    tape,
                    CorrelationPurpose::AuxiliaryRound,
                    local_round,
                )?;
                let (corrections, nodes) = self.auxiliary_states[tape].fix_round(
                    C6ResidualSumcheckFamily::Auxiliary,
                    message,
                    &mut streams[tape],
                    domain,
                )?;
                correction_bytes = correction_bytes
                    .checked_add(corrections.len() as u64 * FP2_BYTES)
                    .ok_or_else(|| C6BlindResidualError::new("C6RSC3 round bytes overflow"))?;
                self.builders[tape].auxiliary_round_corrections.push(corrections);
                auxiliary_nodes[tape] = nodes;
            }
        }

        let activation_tag_bytes = if global_round == self.statement.auxiliary_activation_round() {
            for tape in 0..MAC_TAPES {
                let leaf_initial = self.leaf_states[tape]
                    .initial
                    .ok_or_else(|| C6BlindResidualError::new("missing leaf initial claim"))?;
                let auxiliary_initial = self.auxiliary_states[tape]
                    .initial
                    .ok_or_else(|| C6BlindResidualError::new("missing auxiliary initial claim"))?;
                let residual = leaf_initial
                    .add(auxiliary_initial)
                    .sub(ProverAuthed::from_public(self.statement.target()));
                if residual.x != Fp2::ZERO {
                    return Err(C6BlindResidualError::new("C6RSC3 activation residual is nonzero"));
                }
                self.builders[tape].activation_tag = Some(residual.m);
            }
            MAC_TAPES as u64 * FP2_BYTES
        } else {
            0
        };
        self.pending = Some(C6BlindResidualPendingProverRound { leaf_nodes, auxiliary_nodes });
        Ok(C6BlindResidualFixedRoundReceipt {
            message_bytes: correction_bytes + activation_tag_bytes,
            correction_bytes,
            activation_tag_bytes,
        })
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let pending = self.pending.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 prover challenge precedes round message")
        })?;
        self.challenge_trace.push(challenge);
        self.arithmetic.bind_challenge(challenge)?;
        for tape in 0..MAC_TAPES {
            self.leaf_states[tape].bind_challenge(
                C6ResidualSumcheckFamily::LeafRaw,
                &pending.leaf_nodes[tape],
                challenge,
            )?;
            if !pending.auxiliary_nodes[tape].is_empty() {
                self.auxiliary_states[tape].bind_challenge(
                    C6ResidualSumcheckFamily::Auxiliary,
                    &pending.auxiliary_nodes[tape],
                    challenge,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        streams: &mut [CorrelationStream; MAC_TAPES],
        transcript: &mut Transcript,
    ) -> Result<C6BlindResidualProverRepetitionOutput> {
        if self.pending.is_some() || self.round_index() != self.round_count() {
            return Err(C6BlindResidualError::new("incomplete C6RSC3 step-wise prover repetition"));
        }
        let finished = self.arithmetic.finish()?;
        let (local_pending, local_transfers) = authenticate_pending_prover_claims(
            self.statement,
            &finished.opening_claims,
            streams,
            transcript,
        )?;
        finish_prover_terminal(
            self.statement,
            &local_pending,
            &finished.terminal_scalars,
            &self.leaf_states,
            &self.auxiliary_states,
            streams,
            transcript,
            &mut self.builders,
        )?;
        let tapes = self
            .builders
            .into_iter()
            .map(TapeProofBuilder::finish)
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| C6BlindResidualError::new("C6RSC3 tape builder census mismatch"))?;
        Ok(C6BlindResidualProverRepetitionOutput {
            proof: C6BlindResidualRepetitionProof {
                repetition: self.statement.repetition(),
                statement_digest: self.statement.digest,
                tapes,
            },
            pending_claims: local_pending,
            pending_transfers: local_transfers,
            challenges: self.challenge_trace,
            reference_proof: finished.reference_proof,
            opening_claims: finished.opening_claims,
            #[cfg(feature = "c6-trace")]
            terminal_scalars: finished.terminal_scalars,
        })
    }
}

#[cfg(feature = "c6-trace")]
fn direct_terminal_repetition(
    statement: &C6BlindResidualStatement,
    output: &C6BlindResidualProverRepetitionOutput,
) -> Result<C6BlindResidualDirectTerminalRepetition> {
    if output.opening_claims.len() != C6_RESIDUAL_TABLES_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3-v4 terminal output opening census mismatch"));
    }
    let (leaf_claims, auxiliary_claims) =
        output.opening_claims.split_at(C6_RESIDUAL_LEAF_TABLES_PER_REPETITION);
    let leaf_point = leaf_claims
        .first()
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3-v4 leaf point is missing"))?
        .point
        .clone();
    let auxiliary_point = auxiliary_claims
        .first()
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3-v4 auxiliary point is missing"))?
        .point
        .clone();
    if leaf_claims.iter().any(|claim| {
        claim.repetition != statement.repetition()
            || claim.family != C6ResidualSumcheckFamily::LeafRaw
            || claim.point != leaf_point
    }) || auxiliary_claims.iter().any(|claim| {
        claim.repetition != statement.repetition()
            || claim.family != C6ResidualSumcheckFamily::Auxiliary
            || claim.point != auxiliary_point
    }) {
        return Err(C6BlindResidualError::new(
            "C6RSC3-v4 terminal output points or owners are noncanonical",
        ));
    }
    let mut terminal_functionals = [Fp2::ZERO; C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION];
    let mut cursor = 0usize;
    for values in [
        output.terminal_scalars.leaf_linear.as_slice(),
        output.terminal_scalars.auxiliary_linear.as_slice(),
        output.terminal_scalars.auxiliary_quadratic.as_slice(),
    ] {
        terminal_functionals[cursor..cursor + values.len()].copy_from_slice(values);
        cursor += values.len();
    }
    if cursor != C6_RESIDUAL_TERMINAL_FUNCTIONALS_PER_REPETITION {
        return Err(C6BlindResidualError::new("C6RSC3-v4 terminal functional census mismatch"));
    }
    Ok(C6BlindResidualDirectTerminalRepetition {
        leaf_point,
        auxiliary_point,
        terminal_functionals,
    })
}

fn prove_c6_blind_residual_repetition(
    statement: &C6BlindResidualStatement,
    arithmetic: Box<dyn C6BlindResidualProverArithmetic + '_>,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualProverRepetitionOutput> {
    let state =
        prepare_c6_blind_residual_prover_round_state_with_arithmetic(statement, arithmetic)?;
    prove_c6_blind_residual_round_state(state, streams, transcript)
}

fn prove_c6_blind_residual_round_state(
    mut state: C6BlindResidualProverRoundState<'_>,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualProverRepetitionOutput> {
    while state.round_index() < state.round_count() {
        let receipt = state.fix_next_round(streams)?;
        if receipt.correction_bytes > 0 {
            transcript.append("c6_residual_blind_round_corrections", receipt.correction_bytes);
        }
        if receipt.activation_tag_bytes > 0 {
            transcript.append("zero_open_tag", receipt.activation_tag_bytes);
        }
        let challenge = transcript.challenge_fp2();
        state.bind_challenge(challenge)?;
    }
    state.finish(streams, transcript)
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

/// Fused C6RSC3 prover over compact semantic statements and the installed
/// live-prefix witness view.  It never materializes the padded source witness
/// or the reference coefficient arrays.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_blind_residual_sumchecks_fused(
    statements: &[C6BlindResidualStatement],
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
    let (proof, frame, pending, _) = prove_c6_blind_residual_sumchecks_fused_inner(
        statements,
        None,
        compiler,
        fused_witness,
        arena,
        streams,
        transcript,
    )?;
    Ok((proof, frame, pending))
}

/// Direct-MLE C6RSC3-v4 prover seam.  The fourth result is fixed by the
/// actual fused terminal coefficient state before a caller may draw and bind
/// the independent output-fold challenge.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_blind_residual_sumchecks_fused_direct(
    statements: &[C6BlindResidualStatement],
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    fused_witness: C6ResidualFusedWitnessView<'_>,
    arena: &C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
    C6BlindResidualDirectTerminalOutputs,
)> {
    if compiler.relation.protocol_version() != C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE {
        return Err(C6BlindResidualError::new(
            "C6RSC3-v4 direct prover received a legacy relation schedule",
        ));
    }
    let (proof, frame, pending, terminal_outputs) = prove_c6_blind_residual_sumchecks_fused_inner(
        statements,
        None,
        compiler,
        fused_witness,
        arena,
        streams,
        transcript,
    )?;
    Ok((
        proof,
        frame,
        pending,
        terminal_outputs.ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3-v4 direct prover omitted its terminal outputs")
        })?,
    ))
}

/// Prover entry point that reuses the first-round messages which already
/// supplied the compact statements. No response bytes, challenges or
/// correlations differ from [`prove_c6_blind_residual_sumchecks_fused`].
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_blind_residual_sumchecks_fused_prepared(
    prepared: &[C6BlindResidualFusedPreparedRepetition],
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    fused_witness: C6ResidualFusedWitnessView<'_>,
    arena: &C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    Vec<C6BlindResidualStatement>,
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
)> {
    if prepared.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
        return Err(C6BlindResidualError::new("C6RSC3 prepared repetition census mismatch"));
    }
    let statements = prepared.iter().map(|item| item.statement.clone()).collect::<Vec<_>>();
    let first_rounds = prepared.iter().map(|item| item.first_round.clone()).collect::<Vec<_>>();
    let (proof, frame, pending, _) = prove_c6_blind_residual_sumchecks_fused_inner(
        &statements,
        Some(&first_rounds),
        compiler,
        fused_witness,
        arena,
        streams,
        transcript,
    )?;
    Ok((statements, proof, frame, pending))
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
fn prove_c6_blind_residual_sumchecks_fused_inner(
    statements: &[C6BlindResidualStatement],
    first_rounds: Option<&[C6ResidualFusedFirstRound]>,
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    fused_witness: C6ResidualFusedWitnessView<'_>,
    arena: &C6ResidualFusedCoefficientArena,
    streams: &mut [CorrelationStream; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
    Option<C6BlindResidualDirectTerminalOutputs>,
)> {
    if first_rounds.is_some_and(|rounds| rounds.len() != statements.len()) {
        return Err(C6BlindResidualError::new("C6RSC3 prepared first-round census mismatch"));
    }
    begin_c6_blind_residual_prover_stepwise(statements, arena, transcript)?;
    let mut outputs = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    for (index, statement) in statements.iter().enumerate() {
        let state = prepare_c6_blind_residual_prover_round_state_fused(
            statement,
            compiler,
            fused_witness,
            arena,
            first_rounds.map(|rounds| &rounds[index]),
        )?;
        let output = prove_c6_blind_residual_round_state(state, streams, transcript)?;
        if output.reference_proof.is_some()
            || arena.active_repetition().is_some()
            || arena.is_faulted()
        {
            return Err(C6BlindResidualError::new(
                "C6RSC3 fused arithmetic retained reference proof or coefficient state",
            ));
        }
        outputs.push(output);
    }
    assemble_c6_blind_residual_prover_stepwise(statements, compiler, arena, outputs, transcript)
}

#[cfg(feature = "c6-trace")]
pub(crate) fn begin_c6_blind_residual_prover_stepwise(
    statements: &[C6BlindResidualStatement],
    arena: &C6ResidualFusedCoefficientArena,
    transcript: &mut Transcript,
) -> Result<()> {
    validate_statement_pair(statements)?;
    if arena.active_repetition().is_some() || arena.is_faulted() {
        return Err(C6BlindResidualError::new(
            "C6RSC3 fused prover starts from invalid coefficient-arena state",
        ));
    }
    transcript.append("c6_residual_blind_framing", PROOF_FIXED_FRAMING_BYTES - 32);
    Ok(())
}

#[cfg(feature = "c6-trace")]
pub(crate) fn assemble_c6_blind_residual_prover_stepwise(
    statements: &[C6BlindResidualStatement],
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    arena: &C6ResidualFusedCoefficientArena,
    outputs: Vec<C6BlindResidualProverRepetitionOutput>,
    transcript: &mut Transcript,
) -> Result<(
    C6BlindResidualSumcheckProof,
    C6BlindResidualPendingTransferFrame,
    C6BlindResidualPendingClaimsProver,
    Option<C6BlindResidualDirectTerminalOutputs>,
)> {
    validate_statement_pair(statements)?;
    if outputs.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS
        || arena.active_repetition().is_some()
        || arena.is_faulted()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 coordinated prover repetition or arena mismatch",
        ));
    }
    let mut repetition_proofs = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    let mut pending_transfers =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    let mut pending_claims =
        Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION);
    let mut terminal_repetitions = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    for (index, output) in outputs.into_iter().enumerate() {
        if usize::from(output.proof.repetition) != index || output.reference_proof.is_some() {
            return Err(C6BlindResidualError::new(
                "C6RSC3 coordinated prover repetition order mismatch",
            ));
        }
        if compiler.relation.protocol_version() == C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE {
            terminal_repetitions.push(direct_terminal_repetition(&statements[index], &output)?);
        }
        repetition_proofs.push(output.proof);
        pending_claims.extend(output.pending_claims);
        pending_transfers.extend(output.pending_transfers);
    }
    transcript.append("c6_residual_blind_framing", 32);
    let proof = C6BlindResidualSumcheckProof { repetitions: repetition_proofs };
    proof.validate_shape(statements)?;
    let frame = C6BlindResidualPendingTransferFrame { corrections: pending_transfers };
    validate_pending_frame_shape(statements, &frame)?;
    let terminal_outputs =
        if compiler.relation.protocol_version() == C6_RESIDUAL_RELATION_PROTOCOL_DIRECT_MLE {
            Some(C6BlindResidualDirectTerminalOutputs::new(
                statements,
                compiler.relation,
                terminal_repetitions,
            )?)
        } else {
            None
        };
    Ok((
        proof,
        frame,
        C6BlindResidualPendingClaimsProver { claims: pending_claims },
        terminal_outputs,
    ))
}

/// Compatibility entry point for the scaled differential harness.  The
/// materialized witnesses are shape-audited for the oracle but are not read by
/// fused arithmetic; all folded values come from `fused_witness`.
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
    if witnesses.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
        return Err(C6BlindResidualError::new(
            "C6RSC3 fused scaled oracle witness census mismatch",
        ));
    }
    prove_c6_blind_residual_sumchecks_fused(
        statements,
        compiler,
        fused_witness,
        arena,
        streams,
        transcript,
    )
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
    let frame = C6BlindResidualPendingTransferFrame { corrections: pending_transfers };
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
) -> Result<(Vec<C6BlindResidualPendingClaimProver>, Vec<[Fp2; MAC_TAPES]>)> {
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
        transfers.push([corrections[0][index], corrections[1][index]]);
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

struct C6BlindResidualPendingVerifierRound {
    leaf_nodes: [Vec<VerifierKey>; MAC_TAPES],
    auxiliary_nodes: [Vec<VerifierKey>; MAC_TAPES],
}

pub(crate) struct C6BlindResidualVerifierRoundState<'a> {
    statement: &'a C6BlindResidualStatement,
    repetition_proof: &'a C6BlindResidualRepetitionProof,
    leaf_states: [VerifierFamilyAuthState; MAC_TAPES],
    auxiliary_states: [VerifierFamilyAuthState; MAC_TAPES],
    points: Vec<Fp2>,
    global_round: usize,
    pending: Option<C6BlindResidualPendingVerifierRound>,
}

pub(crate) fn prepare_c6_blind_residual_verifier_round_state<'a>(
    statement: &'a C6BlindResidualStatement,
    proof: &'a C6BlindResidualSumcheckProof,
) -> Result<C6BlindResidualVerifierRoundState<'a>> {
    let repetition = usize::from(statement.repetition());
    let repetition_proof = proof
        .repetitions
        .get(repetition)
        .ok_or_else(|| C6BlindResidualError::new("C6RSC3 verifier repetition is absent"))?;
    if repetition_proof.repetition != statement.repetition()
        || repetition_proof.statement_digest != statement.digest()
    {
        return Err(C6BlindResidualError::new("C6RSC3 verifier repetition statement mismatch"));
    }
    Ok(C6BlindResidualVerifierRoundState {
        statement,
        repetition_proof,
        leaf_states: array::from_fn(|_| VerifierFamilyAuthState::default()),
        auxiliary_states: array::from_fn(|_| VerifierFamilyAuthState::default()),
        points: Vec::with_capacity(statement.leaf_rounds()),
        global_round: 0,
        pending: None,
    })
}

impl C6BlindResidualVerifierRoundState<'_> {
    #[allow(dead_code)]
    pub(crate) fn repetition(&self) -> u8 {
        self.statement.repetition()
    }

    pub(crate) fn round_index(&self) -> usize {
        self.global_round
    }

    pub(crate) fn round_count(&self) -> usize {
        self.statement.leaf_rounds()
    }

    pub(crate) fn check_next_round(
        &mut self,
        contexts: &mut [VerifierCtx; MAC_TAPES],
    ) -> Result<C6BlindResidualFixedRoundReceipt> {
        if self.pending.is_some() || self.global_round >= self.round_count() {
            return Err(C6BlindResidualError::new(
                "C6RSC3 step-wise verifier is not awaiting a round message",
            ));
        }
        let repetition = self.statement.repetition();
        let mut leaf_nodes: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
        let mut auxiliary_nodes: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
        let mut correction_bytes = 0u64;
        for tape in 0..MAC_TAPES {
            let corrections =
                &self.repetition_proof.tapes[tape].leaf_round_corrections[self.global_round];
            let domain = correlation_domain(
                repetition,
                tape,
                CorrelationPurpose::LeafRound,
                self.global_round,
            )?;
            leaf_nodes[tape] = self.leaf_states[tape].fix_round(
                C6ResidualSumcheckFamily::LeafRaw,
                corrections,
                &mut contexts[tape],
                domain,
            )?;
            correction_bytes =
                correction_bytes
                    .checked_add(corrections.len() as u64 * FP2_BYTES)
                    .ok_or_else(|| C6BlindResidualError::new("C6RSC3 verifier bytes overflow"))?;
            if self.global_round >= self.statement.auxiliary_activation_round() {
                let local_round = self.global_round - self.statement.auxiliary_activation_round();
                let corrections =
                    &self.repetition_proof.tapes[tape].auxiliary_round_corrections[local_round];
                let domain = correlation_domain(
                    repetition,
                    tape,
                    CorrelationPurpose::AuxiliaryRound,
                    local_round,
                )?;
                auxiliary_nodes[tape] = self.auxiliary_states[tape].fix_round(
                    C6ResidualSumcheckFamily::Auxiliary,
                    corrections,
                    &mut contexts[tape],
                    domain,
                )?;
                correction_bytes = correction_bytes
                    .checked_add(corrections.len() as u64 * FP2_BYTES)
                    .ok_or_else(|| C6BlindResidualError::new("C6RSC3 verifier bytes overflow"))?;
            }
        }
        let activation_tag_bytes = if self.global_round
            == self.statement.auxiliary_activation_round()
        {
            for tape in 0..MAC_TAPES {
                let leaf_initial = self.leaf_states[tape]
                    .initial
                    .ok_or_else(|| C6BlindResidualError::new("missing leaf verifier initial"))?;
                let auxiliary_initial = self.auxiliary_states[tape].initial.ok_or_else(|| {
                    C6BlindResidualError::new("missing auxiliary verifier initial")
                })?;
                let residual_key = leaf_initial
                    .add(auxiliary_initial)
                    .sub(VerifierKey::from_public(self.statement.target(), contexts[tape].delta));
                if !zero_open_verify(residual_key, self.repetition_proof.tapes[tape].activation_tag)
                {
                    return Err(C6BlindResidualError::new("C6RSC3 activation ZeroOpen failed"));
                }
            }
            MAC_TAPES as u64 * FP2_BYTES
        } else {
            0
        };
        self.pending = Some(C6BlindResidualPendingVerifierRound { leaf_nodes, auxiliary_nodes });
        Ok(C6BlindResidualFixedRoundReceipt {
            message_bytes: correction_bytes + activation_tag_bytes,
            correction_bytes,
            activation_tag_bytes,
        })
    }

    pub(crate) fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let pending = self.pending.take().ok_or_else(|| {
            C6BlindResidualError::new("C6RSC3 verifier challenge precedes round message")
        })?;
        self.points.push(challenge);
        for tape in 0..MAC_TAPES {
            self.leaf_states[tape].bind_challenge(
                C6ResidualSumcheckFamily::LeafRaw,
                &pending.leaf_nodes[tape],
                challenge,
            )?;
            if !pending.auxiliary_nodes[tape].is_empty() {
                self.auxiliary_states[tape].bind_challenge(
                    C6ResidualSumcheckFamily::Auxiliary,
                    &pending.auxiliary_nodes[tape],
                    challenge,
                )?;
            }
        }
        self.global_round += 1;
        Ok(())
    }

    fn finish<T>(
        self,
        pending_corrections: &[[Fp2; MAC_TAPES]],
        contexts: &mut [VerifierCtx; MAC_TAPES],
        transcript: &mut Transcript,
        terminal_compiler: T,
    ) -> Result<Vec<C6BlindResidualPendingClaimVerifier>>
    where
        T: FnOnce(
            &C6BlindResidualStatement,
            &[Fp2],
            &[Fp2],
        ) -> Result<C6BlindResidualTerminalScalars>,
    {
        if self.pending.is_some() || self.global_round != self.round_count() {
            return Err(C6BlindResidualError::new(
                "incomplete C6RSC3 step-wise verifier repetition",
            ));
        }
        let local_pending = authenticate_pending_verifier_claims(
            self.statement,
            pending_corrections,
            &self.points,
            contexts,
            transcript,
        )?;
        let terminal_scalars = terminal_compiler(
            self.statement,
            &local_pending[0].descriptor.point,
            &local_pending[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION].descriptor.point,
        )?;
        finish_verifier_terminal(
            self.statement,
            self.repetition_proof,
            &local_pending,
            &terminal_scalars,
            &self.leaf_states,
            &self.auxiliary_states,
            contexts,
            transcript,
        )?;
        Ok(local_pending)
    }
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
    begin_c6_blind_residual_verifier_stepwise(
        statements,
        proof,
        pending_frame,
        contexts,
        transcript,
    )?;
    let mut repetitions = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
    for statement in statements {
        let repetition = statement.repetition();
        let mut state = prepare_c6_blind_residual_verifier_round_state(statement, proof)?;
        while state.round_index() < state.round_count() {
            let receipt = state.check_next_round(contexts)?;
            if receipt.correction_bytes > 0 {
                transcript.append("c6_residual_blind_round_corrections", receipt.correction_bytes);
            }
            if receipt.activation_tag_bytes > 0 {
                transcript.append("zero_open_tag", receipt.activation_tag_bytes);
            }
            let challenge = transcript.challenge_fp2();
            state.bind_challenge(challenge)?;
        }

        let frame_start = usize::from(repetition) * C6_RESIDUAL_TABLES_PER_REPETITION;
        let frame_end = frame_start + C6_RESIDUAL_TABLES_PER_REPETITION;
        let local_pending = state.finish(
            &pending_frame.corrections[frame_start..frame_end],
            contexts,
            transcript,
            |statement, leaf_point, auxiliary_point| {
                terminal_compiler(statement, leaf_point, auxiliary_point)
            },
        )?;
        repetitions.push(local_pending);
    }
    assemble_c6_blind_residual_verifier_stepwise(repetitions, transcript)
}

pub(crate) fn begin_c6_blind_residual_verifier_stepwise(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    contexts: &[VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<()> {
    proof.validate_shape(statements)?;
    validate_pending_frame_shape(statements, pending_frame)?;
    if contexts[0].delta == contexts[1].delta {
        return Err(C6BlindResidualError::new(
            "C6RSC3 residual MAC coordinates are not independent",
        ));
    }
    transcript.append("c6_residual_blind_framing", PROOF_FIXED_FRAMING_BYTES - 32);
    Ok(())
}

pub(crate) fn assemble_c6_blind_residual_verifier_stepwise(
    repetitions: Vec<Vec<C6BlindResidualPendingClaimVerifier>>,
    transcript: &mut Transcript,
) -> Result<C6BlindResidualPendingClaimsVerifier> {
    if repetitions.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS
        || repetitions.iter().any(|pending| pending.len() != C6_RESIDUAL_TABLES_PER_REPETITION)
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 coordinated verifier repetition/pending census mismatch",
        ));
    }
    transcript.append("c6_residual_blind_framing", 32);
    Ok(C6BlindResidualPendingClaimsVerifier { claims: repetitions.into_iter().flatten().collect() })
}

#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
pub(crate) fn finish_c6_blind_residual_verifier_round_state_fused(
    state: C6BlindResidualVerifierRoundState<'_>,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<Vec<C6BlindResidualPendingClaimVerifier>> {
    let repetition = state.repetition();
    let frame_start = usize::from(repetition) * C6_RESIDUAL_TABLES_PER_REPETITION;
    let frame_end = frame_start + C6_RESIDUAL_TABLES_PER_REPETITION;
    let corrections = pending_frame.corrections.get(frame_start..frame_end).ok_or_else(|| {
        C6BlindResidualError::new("C6RSC3 coordinated verifier pending slice is absent")
    })?;
    state.finish(corrections, contexts, transcript, |statement, leaf_point, auxiliary_point| {
        terminal_scalars_from_fused(compiler, statement, leaf_point, auxiliary_point)
    })
}

/// Finish one coordinated verifier repetition from the exact 64-scalar
/// C6RSC3-v4 terminal object.  The values are already fixed by the blind
/// terminal corrections that precede the independent output challenge; the
/// enclosing C6RSC4 proof is responsible for attesting their compiler fold.
#[cfg(feature = "c6-trace")]
pub(crate) fn finish_c6_blind_residual_verifier_round_state_direct(
    state: C6BlindResidualVerifierRoundState<'_>,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    direct: &C6BlindResidualDirectTerminalOutputs,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<Vec<C6BlindResidualPendingClaimVerifier>> {
    let repetition = state.repetition();
    let frame_start = usize::from(repetition) * C6_RESIDUAL_TABLES_PER_REPETITION;
    let frame_end = frame_start + C6_RESIDUAL_TABLES_PER_REPETITION;
    let corrections = pending_frame.corrections.get(frame_start..frame_end).ok_or_else(|| {
        C6BlindResidualError::new("C6RSC3 coordinated verifier pending slice is absent")
    })?;
    state.finish(corrections, contexts, transcript, |statement, leaf_point, auxiliary_point| {
        direct.terminal_scalars_for(statement, leaf_point, auxiliary_point)
    })
}

/// Designated verifier whose terminal coefficient evaluation is the
/// witness-free fused atomic replay.  It accepts compact statements and never
/// reads materialized coefficient arrays.
#[cfg(feature = "c6-trace")]
pub fn verify_c6_blind_residual_sumchecks_fused(
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
            terminal_scalars_from_fused(compiler, statement, leaf_point, auxiliary_point)
        },
    )
}

/// Standalone verifier differential for the production direct-terminal
/// path.  Unlike the historical fused verifier, this never replays the
/// coefficient compiler.
#[cfg(feature = "c6-trace")]
#[allow(dead_code)]
pub(crate) fn verify_c6_blind_residual_sumchecks_direct(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    direct: &C6BlindResidualDirectTerminalOutputs,
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
            direct.terminal_scalars_for(statement, leaf_point, auxiliary_point)
        },
    )
}

#[cfg(feature = "c6-trace")]
fn terminal_scalars_from_fused(
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    statement: &C6BlindResidualStatement,
    leaf_point: &[Fp2],
    auxiliary_point: &[Fp2],
) -> Result<C6BlindResidualTerminalScalars> {
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
}

/// Compatibility name retained for the scaled differential harness.
#[cfg(feature = "c6-trace")]
pub fn verify_c6_blind_residual_sumchecks_fused_scaled(
    statements: &[C6BlindResidualStatement],
    proof: &C6BlindResidualSumcheckProof,
    pending_frame: &C6BlindResidualPendingTransferFrame,
    compiler: C6BlindResidualFusedCompilerContext<'_>,
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<C6BlindResidualPendingClaimsVerifier> {
    verify_c6_blind_residual_sumchecks_fused(
        statements,
        proof,
        pending_frame,
        compiler,
        contexts,
        transcript,
    )
}

fn authenticate_pending_verifier_claims(
    statement: &C6BlindResidualStatement,
    corrections: &[[Fp2; MAC_TAPES]],
    common_point: &[Fp2],
    contexts: &mut [VerifierCtx; MAC_TAPES],
    transcript: &mut Transcript,
) -> Result<Vec<C6BlindResidualPendingClaimVerifier>> {
    if corrections.len() != C6_RESIDUAL_TABLES_PER_REPETITION
        || common_point.len() != statement.leaf_rounds()
    {
        return Err(C6BlindResidualError::new(
            "C6RSC3 local pending correction/point census mismatch",
        ));
    }
    let auxiliary_point = &common_point[common_point.len() - statement.auxiliary_rounds()..];
    let descriptors = (0..corrections.len())
        .map(|index| {
            let (family, table, point) = if index < C6_RESIDUAL_LEAF_TABLES_PER_REPETITION {
                (C6ResidualSumcheckFamily::LeafRaw, statement.leaf_tables()[index], common_point)
            } else {
                let auxiliary_index = index - C6_RESIDUAL_LEAF_TABLES_PER_REPETITION;
                (
                    C6ResidualSumcheckFamily::Auxiliary,
                    statement.auxiliary_tables()[auxiliary_index],
                    auxiliary_point,
                )
            };
            C6BlindResidualPendingDescriptor {
                statement_digest: statement.digest,
                repetition: statement.repetition(),
                family,
                table,
                point: point.to_vec(),
            }
        })
        .collect::<Vec<_>>();
    let mut keys: [Vec<VerifierKey>; MAC_TAPES] = array::from_fn(|_| Vec::new());
    for tape in 0..MAC_TAPES {
        let tape_corrections = corrections.iter().map(|entry| entry[tape]).collect::<Vec<_>>();
        let domain =
            correlation_domain(statement.repetition(), tape, CorrelationPurpose::PendingClaims, 0)?;
        keys[tape] = contexts[tape].correct_full_verifier_keys(domain, &tape_corrections);
    }
    transcript.append(
        "c6_residual_pending_transfers",
        corrections.len() as u64 * PENDING_CORRECTION_BYTES_PER_CLAIM,
    );
    Ok(descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| C6BlindResidualPendingClaimVerifier {
            descriptor: descriptor.clone(),
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
    validate_pending_correction_census(frame)
}

fn validate_pending_correction_census(frame: &C6BlindResidualPendingTransferFrame) -> Result<()> {
    if frame.corrections.len()
        != C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION
    {
        return Err(C6BlindResidualError::new("C6RSC3 pending correction frame census mismatch"));
    }
    Ok(())
}

fn validate_pending_descriptor(
    statement: &C6BlindResidualStatement,
    index: usize,
    descriptor: &C6BlindResidualPendingDescriptor,
) -> Result<()> {
    let (family, table) = if index < C6_RESIDUAL_LEAF_TABLES_PER_REPETITION {
        (C6ResidualSumcheckFamily::LeafRaw, statement.leaf_tables()[index])
    } else {
        let auxiliary_index = index - C6_RESIDUAL_LEAF_TABLES_PER_REPETITION;
        (C6ResidualSumcheckFamily::Auxiliary, statement.auxiliary_tables()[auxiliary_index])
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
    use volta_proto::{
        build_c6_residual_direct_fused_scaled_fixture, build_c6_residual_fused_scaled_fixture,
        build_c6_response_residual_fixture_production_geometry,
        compile_c6_residual_terminal_functional_relation_reference,
        C6ResidualFusedCoefficientArena, C6ResponseProofEnvelope, C6_RESPONSE_CACHE_SOURCE_BYTES,
    };

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
        assert_eq!(C6_RESIDUAL_BLIND_PENDING_BYTES, 1_536);
        let pending_bytes = fixture.frame.encode().unwrap();
        assert_eq!(pending_bytes.len() as u64, C6_RESIDUAL_BLIND_PENDING_BYTES);
        assert_eq!(
            C6BlindResidualPendingTransferFrame::decode(&pending_bytes).unwrap(),
            fixture.frame
        );
        assert!(C6BlindResidualPendingTransferFrame::decode(
            &pending_bytes[..pending_bytes.len() - 1]
        )
        .is_err());
        let mut noncanonical_pending = pending_bytes;
        noncanonical_pending[..8].copy_from_slice(&P.to_le_bytes());
        assert!(C6BlindResidualPendingTransferFrame::decode(&noncanonical_pending).is_err());
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
                let prover = fixture.pending.claims[index].auth[tape];
                let verifier = verified.claims[index].keys[tape];
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
                assert_eq!(fixture.pending.claims[global_index].auth[0].x, clear_claim.value);
            }
        }
    }

    #[test]
    fn stepwise_blind_rounds_fix_messages_before_challenges() {
        let (statements, witnesses) = fixture();
        let arithmetic =
            C6BlindResidualReferenceArithmetic::new(&statements[0], &witnesses[0]).unwrap();
        let mut prover = prepare_c6_blind_residual_prover_round_state_with_arithmetic(
            &statements[0],
            Box::new(arithmetic),
        )
        .unwrap();
        let mut streams = prover_streams();
        assert!(prover.bind_challenge(Fp2::ONE).is_err());
        let prover_receipt = prover.fix_next_round(&mut streams).unwrap();
        assert!(prover_receipt.message_bytes > 0);
        assert_eq!(prover_receipt.activation_tag_bytes, 0);
        assert!(prover.fix_next_round(&mut streams).is_err());
        prover.bind_challenge(Fp2::ONE).unwrap();
        assert_eq!(prover.round_index(), 1);

        let fixture = prove_fixture();
        let mut verifier =
            prepare_c6_blind_residual_verifier_round_state(&fixture.statements[0], &fixture.proof)
                .unwrap();
        let mut contexts = verifier_contexts();
        assert!(verifier.bind_challenge(Fp2::ONE).is_err());
        let verifier_receipt = verifier.check_next_round(&mut contexts).unwrap();
        assert_eq!(verifier_receipt, prover_receipt);
        assert!(verifier.check_next_round(&mut contexts).is_err());
        verifier.bind_challenge(Fp2::ONE).unwrap();
        assert_eq!(verifier.round_index(), 1);
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
            &wrong_statements[0],
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
        pending.corrections[7][1] += Fp2::ONE;
        assert!(verify_fixture(&fixture, &fixture.proof, &pending).is_err());

        let mut correction_order = fixture.frame.clone();
        correction_order.corrections.swap(0, 1);
        assert!(verify_fixture(&fixture, &fixture.proof, &correction_order).is_err());

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
        let mut bad_reference = statement.reference().clone();
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
        assert!(
            prepare_c6_blind_residual_statement(statement.reference().clone(), [0; 32]).is_err()
        );
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn compact_fused_witness_folds_odd_and_empty_zero_tails() {
        let challenge_0 = Fp2::new(Fp::new(7), Fp::new(11));
        let challenge_1 = Fp2::new(Fp::new(13), Fp::new(17));
        let challenge_2 = Fp2::new(Fp::new(19), Fp::new(23));
        let source = [
            vec![
                Fp2::from_base(Fp::new(1)),
                Fp2::from_base(Fp::new(2)),
                Fp2::from_base(Fp::new(3)),
                Fp2::from_base(Fp::new(4)),
                Fp2::from_base(Fp::new(5)),
            ],
            vec![Fp2::from_base(Fp::new(29))],
            Vec::new(),
        ];
        let mut compact = fold_fused_witness_view(
            source.len(),
            8,
            challenge_0,
            "test",
            |table| Ok(source[table].len()),
            |table, row| Ok(source[table][row]),
        )
        .unwrap();
        let mut padded = source.map(|values| {
            let mut padded = values;
            padded.resize(8, Fp2::ZERO);
            padded
        });
        let fold_full = |tables: &mut [Vec<Fp2>], challenge: Fp2| {
            for table in tables {
                let next = table.len() / 2;
                for row in 0..next {
                    let low = table[2 * row];
                    table[row] = low + (table[2 * row + 1] - low) * challenge;
                }
                table.truncate(next);
            }
        };
        fold_full(&mut padded, challenge_0);
        assert_eq!(compact[0], padded[0][..3]);
        assert_eq!(compact[1], padded[1][..1]);
        assert!(compact[2].is_empty());

        fold_witness_tables_in_place(&mut compact, 4, challenge_1, "test").unwrap();
        fold_full(&mut padded, challenge_1);
        assert_eq!(compact[0], padded[0][..2]);
        assert_eq!(compact[1], padded[1][..1]);
        assert!(compact[2].is_empty());

        fold_witness_tables_in_place(&mut compact, 2, challenge_2, "test").unwrap();
        fold_full(&mut padded, challenge_2);
        assert_eq!(compact[0], padded[0][..1]);
        assert_eq!(compact[1], padded[1][..1]);
        assert!(compact[2].is_empty());
        assert_eq!(compact[0][0], padded[0][0]);
        assert_eq!(compact[1][0], padded[1][0]);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn fused_scaled_prover_is_byte_transcript_and_pending_identical() {
        let fused_fixture = build_c6_residual_fused_scaled_fixture().unwrap();
        assert!(fused_fixture.uses_installed_terminal_witness());
        let closure_memory = fused_fixture.closure_memory_census();
        assert!(closure_memory.peak_live_node_values > 0);
        assert!(closure_memory.peak_live_node_values < closure_memory.canonical_nodes);
        assert!(closure_memory.closure_value_heap_bytes > 0);
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

        let compact_statements = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS)
            .map(|repetition| prepare_c6_blind_residual_statement_fused(compiler, repetition as u8))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        for (compact, reference) in compact_statements.iter().zip(&statements) {
            assert!(compact.reference.is_none());
            assert_eq!(compact.digest(), reference.digest());
            assert_eq!(compact.semantic_compiler_digest(), reference.semantic_compiler_digest());
        }
        let compact_arena = C6ResidualFusedCoefficientArena::new(fused_fixture.manifest());
        let mut compact_streams = prover_streams();
        let mut compact_transcript = Transcript::new(CHALLENGE_SEED);
        let (compact_proof, compact_frame, compact_pending) =
            prove_c6_blind_residual_sumchecks_fused(
                &compact_statements,
                compiler,
                fused_fixture.witness_view().unwrap(),
                &compact_arena,
                &mut compact_streams,
                &mut compact_transcript,
            )
            .unwrap();
        assert_eq!(compact_proof, fused_proof);
        assert_eq!(compact_frame, fused_frame);
        assert_eq!(compact_pending, fused_pending);
        assert_eq!(
            compact_proof.encode(&compact_statements).unwrap(),
            fused_proof.encode(&statements).unwrap()
        );
        assert_eq!(compact_transcript.ledger(), fused_transcript.ledger());
        assert_eq!(compact_transcript.total_bytes(), fused_transcript.total_bytes());
        assert_eq!(
            array::from_fn::<_, MAC_TAPES, _>(|tape| compact_streams[tape].counters),
            array::from_fn::<_, MAC_TAPES, _>(|tape| fused_streams[tape].counters),
        );
        assert_eq!(compact_arena.active_repetition(), None);
        assert_eq!(compact_arena.active_elements(), 0);
        assert!(!compact_arena.is_faulted());

        let prepared = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS)
            .map(|repetition| {
                prepare_c6_blind_residual_prover_repetition_fused(
                    compiler,
                    fused_fixture.witness_view().unwrap(),
                    repetition as u8,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let prepared_arena = C6ResidualFusedCoefficientArena::new(fused_fixture.manifest());
        let mut prepared_streams = prover_streams();
        let mut prepared_transcript = Transcript::new(CHALLENGE_SEED);
        let (prepared_statements, prepared_proof, prepared_frame, prepared_pending) =
            prove_c6_blind_residual_sumchecks_fused_prepared(
                &prepared,
                compiler,
                fused_fixture.witness_view().unwrap(),
                &prepared_arena,
                &mut prepared_streams,
                &mut prepared_transcript,
            )
            .unwrap();
        assert_eq!(prepared_statements, compact_statements);
        assert_eq!(prepared_proof, compact_proof);
        assert_eq!(prepared_frame, compact_frame);
        assert_eq!(prepared_pending, compact_pending);
        assert_eq!(prepared_transcript.ledger(), compact_transcript.ledger());
        assert_eq!(prepared_transcript.total_bytes(), compact_transcript.total_bytes());
        assert_eq!(
            array::from_fn::<_, MAC_TAPES, _>(|tape| prepared_streams[tape].counters),
            array::from_fn::<_, MAC_TAPES, _>(|tape| compact_streams[tape].counters),
        );
        assert_eq!(prepared_arena.active_repetition(), None);
        assert_eq!(prepared_arena.active_elements(), 0);
        assert!(!prepared_arena.is_faulted());

        for repetition in 0..C6_RESIDUAL_SUMCHECK_REPETITIONS {
            assert_eq!(
                reference_trace.claims[repetition]
                    .iter()
                    .map(|claim| claim.value)
                    .collect::<Vec<_>>(),
                (0..C6_RESIDUAL_TABLES_PER_REPETITION)
                    .map(|local| {
                        fused_pending.claims[repetition * C6_RESIDUAL_TABLES_PER_REPETITION + local]
                            .auth[0]
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
        let mut compact_contexts = verifier_contexts();
        let mut compact_verifier_transcript = Transcript::new(CHALLENGE_SEED);
        let compact_verified = verify_c6_blind_residual_sumchecks_fused(
            &compact_statements,
            &compact_proof,
            &compact_frame,
            compiler,
            &mut compact_contexts,
            &mut compact_verifier_transcript,
        )
        .unwrap();
        assert_eq!(fused_verified, reference_verified);
        assert_eq!(compact_verified, fused_verified);
        assert_eq!(fused_verified.len(), C6_RESIDUAL_SUMCHECK_REPETITIONS * 24);
        assert_eq!(reference_verifier_transcript.ledger(), fused_transcript.ledger());
        assert_eq!(fused_verifier_transcript.ledger(), fused_transcript.ledger());
        assert_eq!(compact_verifier_transcript.ledger(), compact_transcript.ledger());

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
            let reference = statement.reference();
            let mut leaf_terms = reference.leaf().terms().to_vec();
            let C6ResidualSumcheckTerm::Linear { coefficients, .. } = &mut leaf_terms[table] else {
                panic!("canonical leaf term is linear");
            };
            for coefficient in coefficients {
                *coefficient += Fp2::ONE;
            }
            let mutated_reference = C6ResidualSumcheckStatement::new_test(
                statement.repetition(),
                statement.target(),
                reference.leaf().rounds(),
                reference.auxiliary().rounds(),
                leaf_terms,
                reference.auxiliary().terms().to_vec(),
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
            &wrong_semantic_statements[0],
            wrong_semantic_statements[0].semantic_compiler_digest(),
        );
        let mut wrong_semantic_proof = fused_proof.clone();
        wrong_semantic_proof.repetitions[0].statement_digest =
            wrong_semantic_statements[0].digest();
        let mut wrong_semantic_contexts = verifier_contexts();
        let mut wrong_semantic_transcript = Transcript::new(CHALLENGE_SEED);
        assert!(verify_c6_blind_residual_sumchecks_fused_scaled(
            &wrong_semantic_statements,
            &wrong_semantic_proof,
            &fused_frame,
            compiler,
            &mut wrong_semantic_contexts,
            &mut wrong_semantic_transcript,
        )
        .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn direct_fused_prover_fixes_exact_terminal_outputs_before_beta() {
        let fixture = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let compiler = C6BlindResidualFusedCompilerContext::new(
            fixture.operation_plan(),
            fixture.extraction(),
            fixture.runtime(),
            fixture.linear(),
            fixture.relation(),
        );
        let statements = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS)
            .map(|repetition| prepare_c6_blind_residual_statement_fused(compiler, repetition as u8))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let arena = C6ResidualFusedCoefficientArena::new(fixture.manifest());
        let mut streams = prover_streams();
        let mut prover_transcript = Transcript::new(CHALLENGE_SEED);
        let (proof, frame, pending, terminal_outputs) =
            prove_c6_blind_residual_sumchecks_fused_direct(
                &statements,
                compiler,
                fixture.witness_view().unwrap(),
                &arena,
                &mut streams,
                &mut prover_transcript,
            )
            .unwrap();
        assert_eq!(
            pending.len(),
            C6_RESIDUAL_SUMCHECK_REPETITIONS * C6_RESIDUAL_TABLES_PER_REPETITION
        );
        assert_eq!(terminal_outputs.relation_challenges_digest(), fixture.relation().digest());
        assert_eq!(terminal_outputs.leaf_point(0).unwrap().len(), 7);
        assert_eq!(terminal_outputs.auxiliary_point(0).unwrap().len(), 2);
        assert_ne!(terminal_outputs.digest(), [0; 32]);
        assert_eq!(
            C6BlindResidualSumcheckProof::decode(&statements, &proof.encode(&statements).unwrap(),)
                .unwrap(),
            proof
        );

        let output_beta = prover_transcript.challenge_fp2();
        let terminal_reference = compile_c6_residual_terminal_functional_relation_reference(
            fixture.operation_plan(),
            fixture.extraction(),
            fixture.runtime(),
            fixture.linear(),
            fixture.relation(),
            [terminal_outputs.leaf_point(0).unwrap(), terminal_outputs.leaf_point(1).unwrap()],
            [
                terminal_outputs.auxiliary_point(0).unwrap(),
                terminal_outputs.auxiliary_point(1).unwrap(),
            ],
            output_beta,
        )
        .unwrap();
        assert_eq!(
            terminal_outputs.terminal_functionals(),
            terminal_reference.terminal_functionals()
        );
        let mut direct_contexts = verifier_contexts();
        let mut direct_transcript = Transcript::new(CHALLENGE_SEED);
        verify_c6_blind_residual_sumchecks_direct(
            &statements,
            &proof,
            &frame,
            &terminal_outputs,
            &mut direct_contexts,
            &mut direct_transcript,
        )
        .unwrap();
        assert_eq!(direct_transcript.challenge_fp2(), output_beta);

        let mut changed_outputs = terminal_outputs.clone();
        changed_outputs.terminal_functionals[0] += Fp2::ONE;
        changed_outputs.digest = direct_terminal_outputs_digest(&changed_outputs);
        let mut changed_contexts = verifier_contexts();
        let mut changed_transcript = Transcript::new(CHALLENGE_SEED);
        assert!(verify_c6_blind_residual_sumchecks_direct(
            &statements,
            &proof,
            &frame,
            &changed_outputs,
            &mut changed_contexts,
            &mut changed_transcript,
        )
        .is_err());
        let terminal_output_digest = terminal_outputs.digest();
        let terminal_fold = terminal_outputs.bind_output_beta(output_beta);
        assert_eq!(terminal_fold.terminal_outputs_digest(), terminal_output_digest);
        assert_eq!(terminal_fold.beta(), output_beta);
        assert_eq!(terminal_fold.functional_fold(), terminal_reference.functional_fold());
        assert_ne!(terminal_fold.digest(), [0; 32]);

        let mut contexts = verifier_contexts();
        let mut verifier_transcript = Transcript::new(CHALLENGE_SEED);
        verify_c6_blind_residual_sumchecks_fused(
            &statements,
            &proof,
            &frame,
            compiler,
            &mut contexts,
            &mut verifier_transcript,
        )
        .unwrap();
        assert_eq!(verifier_transcript.challenge_fp2(), output_beta);

        let legacy = build_c6_residual_fused_scaled_fixture().unwrap();
        let legacy_compiler = C6BlindResidualFusedCompilerContext::new(
            legacy.operation_plan(),
            legacy.extraction(),
            legacy.runtime(),
            legacy.linear(),
            legacy.relation(),
        );
        let legacy_statements = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS)
            .map(|repetition| {
                prepare_c6_blind_residual_statement_fused(legacy_compiler, repetition as u8)
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            blind_residual_sumcheck_encoded_len(&statements).unwrap(),
            blind_residual_sumcheck_encoded_len(&legacy_statements).unwrap()
        );
        let legacy_arena = C6ResidualFusedCoefficientArena::new(legacy.manifest());
        assert!(prove_c6_blind_residual_sumchecks_fused_direct(
            &legacy_statements,
            legacy_compiler,
            legacy.witness_view().unwrap(),
            &legacy_arena,
            &mut prover_streams(),
            &mut Transcript::new(CHALLENGE_SEED),
        )
        .is_err());
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    #[ignore = "artifact-gated complete T=4,Q=2 CPU response and sealed residual gate"]
    fn response_wide_installed_witness_enters_compact_sealed_coordinator() {
        let gate_start = std::time::Instant::now();
        let Some(mut fixture) = build_c6_response_residual_fixture_production_geometry().unwrap()
        else {
            eprintln!("skipping C6 response-wide sealed gate: GPT-2 artifact not present");
            return;
        };
        let census = fixture.census();
        assert_eq!(census.source_groups, 48);
        assert_eq!(census.corrected_targets, 576);
        assert_eq!(census.source_cells, 184_320);
        assert_eq!(census.verifier_linear_auxiliary_source_cells, 110_592);
        assert_eq!(census.scheduled_sources, 593_876);
        assert_eq!(census.product_closures, 673);
        assert_eq!(census.product_triples, 14_653);
        assert_eq!(census.zero_roots, 5_590);

        let arena = C6ResidualFusedCoefficientArena::new(fixture.manifest());
        let residual_prover_start = std::time::Instant::now();
        let (statements, proof, frame, prover_pending_len, encoded_len, witness_memory) = {
            let provider = fixture.provider_inputs().unwrap();
            let witness_memory =
                provider.witness.memory_census(provider.relation.manifest()).unwrap();
            let compiler = C6BlindResidualFusedCompilerContext::new(
                provider.operation_plan,
                provider.extraction,
                provider.runtime,
                provider.linear,
                provider.relation,
            );
            let prepared = (0..C6_RESIDUAL_SUMCHECK_REPETITIONS)
                .map(|repetition| {
                    prepare_c6_blind_residual_prover_repetition_fused(
                        compiler,
                        provider.witness,
                        repetition as u8,
                    )
                })
                .collect::<Result<Vec<_>>>()
                .unwrap();
            let (statements, proof, frame, pending) =
                prove_c6_blind_residual_sumchecks_fused_prepared(
                    &prepared,
                    compiler,
                    provider.witness,
                    &arena,
                    provider.streams,
                    provider.transcript,
                )
                .unwrap();
            let encoded_len = proof.encoded_len(&statements).unwrap();
            (statements, proof, frame, pending.len(), encoded_len, witness_memory)
        };
        let residual_prover_wall = residual_prover_start.elapsed();
        eprintln!(
            "C6 production-geometry provider checkpoint: proof_bytes={encoded_len} provider_response_residual_s={:.6} residual_prover_s={:.6} inline_subtotal_s={:.6}",
            fixture.timing().provider_response_and_residual_ns as f64 / 1e9,
            residual_prover_wall.as_secs_f64(),
            fixture.timing().provider_response_and_residual_ns as f64 / 1e9
                + residual_prover_wall.as_secs_f64(),
        );
        assert_eq!(prover_pending_len, 48);
        assert_eq!(arena.active_repetition(), None);
        assert_eq!(arena.active_elements(), 0);
        assert_eq!(arena.reserved_elements(), 0);
        assert_eq!(arena.peak_elements(), 33_554_432);
        assert_eq!(arena.peak_reserved_elements(), 33_554_432);
        assert_eq!(arena.peak_bytes(), 536_870_912);
        assert_eq!(witness_memory.input_live_elements, 4_553_588);
        assert_eq!(witness_memory.leaf_first_fold_elements, 2_177_696);
        assert_eq!(witness_memory.leaf_at_auxiliary_activation_elements, 8_508);
        assert_eq!(witness_memory.auxiliary_first_fold_elements, 99_104);
        assert_eq!(witness_memory.activation_logical_elements, 107_612);
        assert_eq!(witness_memory.peak_logical_bytes, 34_843_136);
        assert_eq!(witness_memory.peak_reserved_bytes, 36_428_800);
        assert!(!arena.is_faulted());

        let response_envelope = C6ResponseProofEnvelope::new(
            proof.encode(&statements).unwrap(),
            frame.encode().unwrap(),
            vec![0x61],
            vec![0x62; C6_RESPONSE_CACHE_SOURCE_BYTES as usize],
            vec![0x63],
            fixture.cache_fold_target_frame().to_vec(),
            vec![0x64],
        )
        .unwrap();
        let response_envelope =
            C6ResponseProofEnvelope::decode(&response_envelope.encode().unwrap()).unwrap();
        assert_eq!(
            C6BlindResidualSumcheckProof::decode(
                &statements,
                response_envelope.residual_sumcheck(),
            )
            .unwrap(),
            proof
        );
        assert_eq!(
            C6BlindResidualPendingTransferFrame::decode(
                response_envelope.residual_pending_corrections(),
            )
            .unwrap(),
            frame
        );
        assert_eq!(response_envelope.cache_fold_targets(), fixture.cache_fold_target_frame());

        let residual_verifier_start = std::time::Instant::now();
        let verifier_pending_len = {
            let verifier = fixture.verifier_inputs();
            let compiler = C6BlindResidualFusedCompilerContext::new(
                verifier.operation_plan,
                verifier.extraction,
                verifier.runtime,
                verifier.linear,
                verifier.relation,
            );
            verify_c6_blind_residual_sumchecks_fused(
                &statements,
                &proof,
                &frame,
                compiler,
                verifier.contexts,
                verifier.transcript,
            )
            .unwrap()
            .len()
        };
        let residual_verifier_wall = residual_verifier_start.elapsed();
        assert_eq!(verifier_pending_len, 48);
        assert!(fixture.continued_protocol_states_match());
        let closure_memory = fixture.closure_memory_census();
        let timing = fixture.timing();
        assert_eq!(closure_memory.canonical_nodes, 2_501_849);
        assert_eq!(closure_memory.peak_live_node_values, 149_074);
        eprintln!(
            "C6 response sealed gate: proof_bytes={encoded_len} coefficient_peak_bytes={} compact_witness_logical_peak_bytes={} compact_witness_reserved_peak_bytes={} combined_coefficient_witness_reserved_peak_bytes={} closure_working_heap_bytes={} provider_response_residual_s={:.6} residual_prover_s={:.6} verifier_response_residual_s={:.6} residual_verifier_s={:.6} complete_gate_s={:.6}",
            arena.peak_bytes(),
            witness_memory.peak_logical_bytes,
            witness_memory.peak_reserved_bytes,
            arena.peak_reserved_bytes() + witness_memory.peak_reserved_bytes,
            closure_memory.peak_working_heap_bytes,
            timing.provider_response_and_residual_ns as f64 / 1e9,
            residual_prover_wall.as_secs_f64(),
            timing.verifier_response_and_residual_ns as f64 / 1e9,
            residual_verifier_wall.as_secs_f64(),
            gate_start.elapsed().as_secs_f64(),
        );
    }
}

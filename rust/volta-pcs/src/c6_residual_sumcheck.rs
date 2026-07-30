//! Statement-generic arithmetic engine for the two C6 residual sumchecks.
//!
//! A statement contains already-precombined public coefficient MLEs and
//! refers to the exact packed-wrapper slots that own its witness factors.
//! The scaled reference path accepts only an opaque atomic-relation statement
//! emitted by the C6RLM1 compiler and binds that compiler digest into the
//! sumcheck statement.  Production T1 still requires the fused streaming
//! compiler and must never materialize these coefficient arrays.
//!
//! Terminal factor values are returned as typed opening claims.  They remain
//! untrusted until the response-local packed PCS opens the same wrapper slots
//! at the same points.

use std::fmt;

use volta_field::{Fp, Fp2, P};
use volta_proto::logup::lagrange4;
use volta_proto::mle::{eval_mle, fold_low, lagrange3};
use volta_proto::{C6ResidualAtomicRelationStatement, C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS};

use crate::c6_wrapper_pcs::{C6_DELTA_RESIDUAL_COHORT_ID, C6_WRAPPER_AUXILIARY_COHORT_ID};

const PROOF_MAGIC: [u8; 8] = *b"C6RSC2\0\0";
const PROOF_VERSION: u16 = 2;
const PROOF_DOMAIN: &str = "volta-zk/c6/residual-sumcheck-proof/v2";
const STATEMENT_DOMAIN: &str = "volta-zk/c6/residual-sumcheck-statement/v2";
const ATOMIC_COMPILER_BINDING_MARKER: u8 = 0xC6;

pub const C6_RESIDUAL_SUMCHECK_REPETITIONS: usize = 2;
pub const C6_RESIDUAL_LEAF_TABLES_PER_REPETITION: usize = 8;
pub const C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION: usize = 16;
pub const C6_RESIDUAL_TABLES_PER_REPETITION: usize =
    C6_RESIDUAL_LEAF_TABLES_PER_REPETITION + C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION;
const C6_RESIDUAL_LEAF_TABLE_SLOTS: [u16; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] =
    [0, 1, 2, 3, 4, 5, 6, 7];
const C6_RESIDUAL_AUXILIARY_TABLE_SLOTS: [u16; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const C6_RESIDUAL_LEAF_ROUNDS: usize = 23;
pub const C6_RESIDUAL_AUXILIARY_ROUNDS: usize = 15;
pub const C6_RESIDUAL_AUXILIARY_LOCAL_ACTIVATION: usize =
    C6_RESIDUAL_LEAF_ROUNDS - C6_RESIDUAL_AUXILIARY_ROUNDS;
pub const C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES: u64 = 16;
pub const C6_RESIDUAL_SUMCHECK_ROUND_BYTES: u64 = 4_128;
pub const C6_RESIDUAL_SUMCHECK_PROOF_BYTES: u64 = 4_244;

type Result<T> = std::result::Result<T, C6ResidualSumcheckError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckError(String);

impl C6ResidualSumcheckError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6ResidualSumcheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6ResidualSumcheckError {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6ResidualSumcheckFamily {
    LeafRaw = 1,
    Auxiliary = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct C6ResidualTableRef {
    pub cohort_id: u32,
    pub slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C6ResidualSumcheckTerm {
    /// `coefficient(x) * table[table](x)`.
    Linear { table: u8, coefficients: Vec<Fp2> },
    /// `coefficient(x) * table[lhs](x) * table[rhs](x)`.
    ///
    /// Statements require `lhs <= rhs`; a coefficient table must already
    /// combine every source contribution for this exact factor tuple.
    Quadratic { lhs: u8, rhs: u8, coefficients: Vec<Fp2> },
}

impl C6ResidualSumcheckTerm {
    pub fn linear(table: u8, coefficients: Vec<Fp2>) -> Self {
        Self::Linear { table, coefficients }
    }

    pub fn quadratic(lhs: u8, rhs: u8, coefficients: Vec<Fp2>) -> Result<Self> {
        if lhs > rhs {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual quadratic factor tuple is not canonical",
            ));
        }
        Ok(Self::Quadratic { lhs, rhs, coefficients })
    }

    pub fn coefficients(&self) -> &[Fp2] {
        match self {
            Self::Linear { coefficients, .. } | Self::Quadratic { coefficients, .. } => {
                coefficients
            }
        }
    }

    fn factor_key(&self) -> (u8, u8, u8) {
        match self {
            Self::Linear { table, .. } => (1, *table, 0),
            Self::Quadratic { lhs, rhs, .. } => (2, *lhs, *rhs),
        }
    }

    fn factor_indices(&self) -> (usize, Option<usize>) {
        match self {
            Self::Linear { table, .. } => (usize::from(*table), None),
            Self::Quadratic { lhs, rhs, .. } => (usize::from(*lhs), Some(usize::from(*rhs))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckFamilyStatement {
    family: C6ResidualSumcheckFamily,
    rounds: usize,
    tables: Vec<C6ResidualTableRef>,
    terms: Vec<C6ResidualSumcheckTerm>,
}

impl C6ResidualSumcheckFamilyStatement {
    pub fn family(&self) -> C6ResidualSumcheckFamily {
        self.family
    }

    pub fn rounds(&self) -> usize {
        self.rounds
    }

    pub fn tables(&self) -> &[C6ResidualTableRef] {
        &self.tables
    }

    pub fn terms(&self) -> &[C6ResidualSumcheckTerm] {
        &self.terms
    }

    fn table_len(&self) -> Result<usize> {
        checked_table_len(self.rounds)
    }

    fn validate(&self) -> Result<()> {
        if self.rounds == 0 || self.rounds > usize::from(u8::MAX) || self.tables.is_empty() {
            return Err(C6ResidualSumcheckError::new("invalid C6 residual family geometry"));
        }
        if self.terms.is_empty() {
            return Err(C6ResidualSumcheckError::new("empty C6 residual family expression"));
        }
        let table_len = self.table_len()?;
        let mut used = vec![false; self.tables.len()];
        let mut previous = None;
        for term in &self.terms {
            let key = term.factor_key();
            if previous.is_some_and(|prior| prior >= key) {
                return Err(C6ResidualSumcheckError::new(
                    "duplicate or noncanonical C6 residual factor tuple",
                ));
            }
            previous = Some(key);
            if term.coefficients().len() != table_len {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual coefficient-table geometry mismatch",
                ));
            }
            let (lhs, rhs) = term.factor_indices();
            if lhs >= self.tables.len() || rhs.is_some_and(|index| index >= self.tables.len()) {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual term references an unknown table",
                ));
            }
            if matches!(term, C6ResidualSumcheckTerm::Quadratic { lhs, rhs, .. } if lhs > rhs) {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual quadratic factor tuple is not canonical",
                ));
            }
            used[lhs] = true;
            if let Some(rhs) = rhs {
                if self.family == C6ResidualSumcheckFamily::LeafRaw {
                    return Err(C6ResidualSumcheckError::new(
                        "C6 leaf/raw family exceeds frozen degree two",
                    ));
                }
                used[rhs] = true;
            }
        }
        if used.iter().any(|is_used| !is_used) {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual statement has an unused terminal table",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckStatement {
    repetition: u8,
    target: Fp2,
    leaf: C6ResidualSumcheckFamilyStatement,
    auxiliary: C6ResidualSumcheckFamilyStatement,
    compiler_binding_digest: [u8; 32],
    digest: [u8; 32],
}

impl C6ResidualSumcheckStatement {
    /// Build one production-geometry statement.  Public coefficient tables
    /// are reference materializations; this constructor carries no
    /// production memory or timing claim.
    pub fn new(
        repetition: u8,
        target: Fp2,
        leaf_terms: Vec<C6ResidualSumcheckTerm>,
        auxiliary_terms: Vec<C6ResidualSumcheckTerm>,
    ) -> Result<Self> {
        Self::build(
            repetition,
            target,
            C6_RESIDUAL_LEAF_ROUNDS,
            C6_RESIDUAL_AUXILIARY_ROUNDS,
            expected_tables(repetition, C6ResidualSumcheckFamily::LeafRaw)?,
            expected_tables(repetition, C6ResidualSumcheckFamily::Auxiliary)?,
            leaf_terms,
            auxiliary_terms,
            [0; 32],
        )
    }

    /// Convert a scaled C6RLM1 compiler output into the generic two-family
    /// arithmetic engine.
    ///
    /// This clones every coefficient table and is intentionally a reference
    /// path.  The production T1 compiler must stream the same relation into
    /// the prover instead of calling this allocation-heavy constructor.
    pub fn from_atomic_relation_reference(
        atomic: &C6ResidualAtomicRelationStatement,
    ) -> Result<Self> {
        Self::from_atomic_relation_reference_parts(
            atomic.proof_repetition(),
            atomic.target(),
            atomic.leaf_linear(),
            atomic.auxiliary_linear(),
            atomic.auxiliary_quadratic(),
            atomic.atomic_outputs_consumed(),
            atomic.digest(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_atomic_relation_reference_parts(
        repetition: u8,
        target: Fp2,
        leaf_linear: &[Vec<Fp2>; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
        auxiliary_linear: &[Vec<Fp2>; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
        auxiliary_quadratic: &[((u8, u8), Vec<Fp2>)],
        atomic_outputs_consumed: u64,
        compiler_binding_digest: [u8; 32],
    ) -> Result<Self> {
        if compiler_binding_digest == [0; 32] || atomic_outputs_consumed == 0 {
            return Err(C6ResidualSumcheckError::new("unbound C6 atomic relation statement"));
        }

        let leaf_len = common_atomic_table_len("leaf", leaf_linear.iter().map(Vec::as_slice))?;
        let auxiliary_len =
            common_atomic_table_len("auxiliary", auxiliary_linear.iter().map(Vec::as_slice))?;
        let leaf_rounds = exact_rounds_for_table_len("leaf", leaf_len)?;
        let auxiliary_rounds = exact_rounds_for_table_len("auxiliary", auxiliary_len)?;
        if leaf_rounds < auxiliary_rounds {
            return Err(C6ResidualSumcheckError::new(
                "C6 atomic relation has an invalid suffix schedule",
            ));
        }
        if auxiliary_quadratic.len() != C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS.len() {
            return Err(C6ResidualSumcheckError::new(
                "C6 atomic relation has the wrong quadratic tuple census",
            ));
        }

        let leaf_terms = leaf_linear
            .iter()
            .enumerate()
            .map(|(table, coefficients)| {
                C6ResidualSumcheckTerm::linear(table as u8, coefficients.clone())
            })
            .collect();
        let mut auxiliary_terms = auxiliary_linear
            .iter()
            .enumerate()
            .map(|(table, coefficients)| {
                C6ResidualSumcheckTerm::linear(table as u8, coefficients.clone())
            })
            .collect::<Vec<_>>();
        for (index, ((lhs, rhs), coefficients)) in auxiliary_quadratic.iter().enumerate() {
            if (*lhs, *rhs) != C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS[index]
                || coefficients.len() != auxiliary_len
            {
                return Err(C6ResidualSumcheckError::new(
                    "C6 atomic relation quadratic tuple/geometry mismatch",
                ));
            }
            auxiliary_terms.push(C6ResidualSumcheckTerm::quadratic(
                *lhs,
                *rhs,
                coefficients.clone(),
            )?);
        }

        Self::build(
            repetition,
            target,
            leaf_rounds,
            auxiliary_rounds,
            expected_tables(repetition, C6ResidualSumcheckFamily::LeafRaw)?,
            expected_tables(repetition, C6ResidualSumcheckFamily::Auxiliary)?,
            leaf_terms,
            auxiliary_terms,
            compiler_binding_digest,
        )
    }

    #[cfg(test)]
    fn new_test(
        repetition: u8,
        target: Fp2,
        leaf_rounds: usize,
        auxiliary_rounds: usize,
        leaf_terms: Vec<C6ResidualSumcheckTerm>,
        auxiliary_terms: Vec<C6ResidualSumcheckTerm>,
    ) -> Result<Self> {
        Self::build(
            repetition,
            target,
            leaf_rounds,
            auxiliary_rounds,
            expected_tables(repetition, C6ResidualSumcheckFamily::LeafRaw)?,
            expected_tables(repetition, C6ResidualSumcheckFamily::Auxiliary)?,
            leaf_terms,
            auxiliary_terms,
            [0; 32],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        repetition: u8,
        target: Fp2,
        leaf_rounds: usize,
        auxiliary_rounds: usize,
        leaf_tables: Vec<C6ResidualTableRef>,
        auxiliary_tables: Vec<C6ResidualTableRef>,
        leaf_terms: Vec<C6ResidualSumcheckTerm>,
        auxiliary_terms: Vec<C6ResidualSumcheckTerm>,
        compiler_binding_digest: [u8; 32],
    ) -> Result<Self> {
        if usize::from(repetition) >= C6_RESIDUAL_SUMCHECK_REPETITIONS
            || auxiliary_rounds == 0
            || leaf_rounds < auxiliary_rounds
        {
            return Err(C6ResidualSumcheckError::new(
                "invalid C6 residual repetition or suffix schedule",
            ));
        }
        if leaf_tables != expected_tables(repetition, C6ResidualSumcheckFamily::LeafRaw)?
            || auxiliary_tables != expected_tables(repetition, C6ResidualSumcheckFamily::Auxiliary)?
        {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual table owners do not match the frozen complete relation",
            ));
        }
        let leaf = C6ResidualSumcheckFamilyStatement {
            family: C6ResidualSumcheckFamily::LeafRaw,
            rounds: leaf_rounds,
            tables: leaf_tables,
            terms: canonical_terms(leaf_terms)?,
        };
        let auxiliary = C6ResidualSumcheckFamilyStatement {
            family: C6ResidualSumcheckFamily::Auxiliary,
            rounds: auxiliary_rounds,
            tables: auxiliary_tables,
            terms: canonical_terms(auxiliary_terms)?,
        };
        leaf.validate()?;
        auxiliary.validate()?;
        let mut statement =
            Self { repetition, target, leaf, auxiliary, compiler_binding_digest, digest: [0; 32] };
        statement.digest = statement_digest(&statement);
        statement.validate()?;
        Ok(statement)
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn target(&self) -> Fp2 {
        self.target
    }

    pub fn leaf(&self) -> &C6ResidualSumcheckFamilyStatement {
        &self.leaf
    }

    pub fn auxiliary(&self) -> &C6ResidualSumcheckFamilyStatement {
        &self.auxiliary
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn compiler_binding_digest(&self) -> Option<[u8; 32]> {
        (self.compiler_binding_digest != [0; 32]).then_some(self.compiler_binding_digest)
    }

    pub fn auxiliary_activation_round(&self) -> usize {
        self.leaf.rounds - self.auxiliary.rounds
    }

    fn validate(&self) -> Result<()> {
        if usize::from(self.repetition) >= C6_RESIDUAL_SUMCHECK_REPETITIONS
            || self.leaf.family != C6ResidualSumcheckFamily::LeafRaw
            || self.auxiliary.family != C6ResidualSumcheckFamily::Auxiliary
            || self.leaf.rounds < self.auxiliary.rounds
            || self.leaf.tables
                != expected_tables(self.repetition, C6ResidualSumcheckFamily::LeafRaw)?
            || self.auxiliary.tables
                != expected_tables(self.repetition, C6ResidualSumcheckFamily::Auxiliary)?
        {
            return Err(C6ResidualSumcheckError::new("invalid C6 residual statement geometry"));
        }
        self.leaf.validate()?;
        self.auxiliary.validate()?;
        if self.digest == [0; 32] || self.digest != statement_digest(self) {
            return Err(C6ResidualSumcheckError::new("C6 residual statement digest mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckWitness {
    leaf_tables: Vec<Vec<Fp2>>,
    auxiliary_tables: Vec<Vec<Fp2>>,
}

impl C6ResidualSumcheckWitness {
    pub fn new(
        statement: &C6ResidualSumcheckStatement,
        leaf_tables: Vec<Vec<Fp2>>,
        auxiliary_tables: Vec<Vec<Fp2>>,
    ) -> Result<Self> {
        statement.validate()?;
        validate_witness_tables(&statement.leaf, &leaf_tables)?;
        validate_witness_tables(&statement.auxiliary, &auxiliary_tables)?;
        Ok(Self { leaf_tables, auxiliary_tables })
    }

    pub fn leaf_tables(&self) -> &[Vec<Fp2>] {
        &self.leaf_tables
    }

    pub fn auxiliary_tables(&self) -> &[Vec<Fp2>] {
        &self.auxiliary_tables
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualOpeningClaim {
    pub repetition: u8,
    pub family: C6ResidualSumcheckFamily,
    pub table: C6ResidualTableRef,
    /// Point on the semantic half, in LSB-first order.
    pub point: Vec<Fp2>,
    pub value: Fp2,
}

impl C6ResidualOpeningClaim {
    /// Both frozen residual cohorts append a zero coordinate to select the
    /// semantic half rather than the independently masked upper half.
    pub fn wrapper_point(&self) -> Vec<Fp2> {
        let mut point = self.point.clone();
        point.push(Fp2::ZERO);
        point
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckRepetitionProof {
    repetition: u8,
    statement_digest: [u8; 32],
    leaf_rounds: Vec<[Fp2; 3]>,
    auxiliary_rounds: Vec<[Fp2; 4]>,
}

impl C6ResidualSumcheckRepetitionProof {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn leaf_rounds(&self) -> &[[Fp2; 3]] {
        &self.leaf_rounds
    }

    pub fn auxiliary_rounds(&self) -> &[[Fp2; 4]] {
        &self.auxiliary_rounds
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6ResidualSumcheckProof {
    repetitions: Vec<C6ResidualSumcheckRepetitionProof>,
}

impl C6ResidualSumcheckProof {
    pub fn new(
        statements: &[C6ResidualSumcheckStatement],
        repetitions: Vec<C6ResidualSumcheckRepetitionProof>,
    ) -> Result<Self> {
        let proof = Self { repetitions };
        proof.validate_shape(statements)?;
        Ok(proof)
    }

    pub fn repetitions(&self) -> &[C6ResidualSumcheckRepetitionProof] {
        &self.repetitions
    }

    pub fn encode(&self, statements: &[C6ResidualSumcheckStatement]) -> Result<Vec<u8>> {
        self.validate_shape(statements)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(residual_sumcheck_encoded_len(statements)?).map_err(|_| {
                C6ResidualSumcheckError::new("C6 residual proof length exceeds usize")
            })?,
        );
        bytes.extend_from_slice(&PROOF_MAGIC);
        bytes.extend_from_slice(&PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.repetitions.len() as u16).to_le_bytes());
        for repetition in &self.repetitions {
            bytes.push(repetition.repetition);
            bytes.push(
                u8::try_from(repetition.leaf_rounds.len())
                    .map_err(|_| C6ResidualSumcheckError::new("C6 leaf rounds exceed codec"))?,
            );
            bytes.push(
                u8::try_from(repetition.auxiliary_rounds.len()).map_err(|_| {
                    C6ResidualSumcheckError::new("C6 auxiliary rounds exceed codec")
                })?,
            );
            bytes.push(0);
            bytes.extend_from_slice(&repetition.statement_digest);
            for round in &repetition.leaf_rounds {
                for value in round {
                    encode_fp2(&mut bytes, *value);
                }
            }
            for round in &repetition.auxiliary_rounds {
                for value in round {
                    encode_fp2(&mut bytes, *value);
                }
            }
        }
        bytes.extend_from_slice(&proof_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(statements: &[C6ResidualSumcheckStatement], bytes: &[u8]) -> Result<Self> {
        validate_statement_pair(statements)?;
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != PROOF_MAGIC {
            return Err(C6ResidualSumcheckError::new("bad C6 residual sumcheck magic"));
        }
        if cursor.u16()? != PROOF_VERSION {
            return Err(C6ResidualSumcheckError::new("unknown C6 residual sumcheck version"));
        }
        if cursor.u16()? as usize != C6_RESIDUAL_SUMCHECK_REPETITIONS {
            return Err(C6ResidualSumcheckError::new("C6 residual sumcheck repetition mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_RESIDUAL_SUMCHECK_REPETITIONS);
        for (repetition_index, statement) in statements.iter().enumerate() {
            let repetition = cursor.u8()?;
            let leaf_rounds = cursor.u8()? as usize;
            let auxiliary_rounds = cursor.u8()? as usize;
            if repetition as usize != repetition_index
                || leaf_rounds != statement.leaf.rounds
                || auxiliary_rounds != statement.auxiliary.rounds
                || cursor.u8()? != 0
            {
                return Err(C6ResidualSumcheckError::new("C6 residual repetition header mismatch"));
            }
            let encoded_statement_digest = cursor.digest()?;
            if encoded_statement_digest != statement.digest {
                return Err(C6ResidualSumcheckError::new("C6 residual proof/statement mismatch"));
            }
            let mut leaf_messages = Vec::with_capacity(leaf_rounds);
            for _ in 0..leaf_rounds {
                leaf_messages.push([cursor.fp2()?, cursor.fp2()?, cursor.fp2()?]);
            }
            let mut auxiliary_messages = Vec::with_capacity(auxiliary_rounds);
            for _ in 0..auxiliary_rounds {
                auxiliary_messages.push([
                    cursor.fp2()?,
                    cursor.fp2()?,
                    cursor.fp2()?,
                    cursor.fp2()?,
                ]);
            }
            repetitions.push(C6ResidualSumcheckRepetitionProof {
                repetition,
                statement_digest: encoded_statement_digest,
                leaf_rounds: leaf_messages,
                auxiliary_rounds: auxiliary_messages,
            });
        }
        let digest_offset = cursor.position();
        let encoded_digest = cursor.digest()?;
        if !cursor.is_eof() || encoded_digest != proof_digest(&bytes[..digest_offset]) {
            return Err(C6ResidualSumcheckError::new(
                "noncanonical or trailing C6 residual sumcheck bytes",
            ));
        }
        Self::new(statements, repetitions)
    }

    pub fn encoded_len(&self, statements: &[C6ResidualSumcheckStatement]) -> Result<u64> {
        self.validate_shape(statements)?;
        residual_sumcheck_encoded_len(statements)
    }

    fn validate_shape(&self, statements: &[C6ResidualSumcheckStatement]) -> Result<()> {
        validate_statement_pair(statements)?;
        if self.repetitions.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual proof repetition count mismatch",
            ));
        }
        for (index, (proof, statement)) in self.repetitions.iter().zip(statements).enumerate() {
            if usize::from(proof.repetition) != index
                || proof.statement_digest != statement.digest
                || proof.leaf_rounds.len() != statement.leaf.rounds
                || proof.auxiliary_rounds.len() != statement.auxiliary.rounds
            {
                return Err(C6ResidualSumcheckError::new("C6 residual proof shape mismatch"));
            }
        }
        Ok(())
    }
}

pub fn residual_sumcheck_encoded_len(statements: &[C6ResidualSumcheckStatement]) -> Result<u64> {
    validate_statement_pair(statements)?;
    // magic/version/count + two repetition headers/digests + round values +
    // final digest.
    statements
        .iter()
        .try_fold(12u64, |bytes, statement| {
            let leaf = u64::try_from(statement.leaf.rounds)
                .map_err(|_| C6ResidualSumcheckError::new("C6 leaf rounds exceed u64"))?
                .checked_mul(3 * C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES)
                .ok_or_else(|| C6ResidualSumcheckError::new("C6 leaf round bytes overflow"))?;
            let auxiliary = u64::try_from(statement.auxiliary.rounds)
                .map_err(|_| C6ResidualSumcheckError::new("C6 auxiliary rounds exceed u64"))?
                .checked_mul(4 * C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES)
                .ok_or_else(|| C6ResidualSumcheckError::new("C6 auxiliary round bytes overflow"))?;
            bytes
                .checked_add(36)
                .and_then(|value| value.checked_add(leaf))
                .and_then(|value| value.checked_add(auxiliary))
                .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual proof bytes overflow"))
        })?
        .checked_add(32)
        .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual proof bytes overflow"))
}

pub const fn production_c6_residual_sumcheck_round_bytes() -> u64 {
    C6_RESIDUAL_SUMCHECK_ROUND_BYTES
}

pub const fn production_c6_residual_sumcheck_encoded_len() -> u64 {
    C6_RESIDUAL_SUMCHECK_PROOF_BYTES
}

/// One repetition of the honest residual prover, exposed round-by-round for
/// the response-global wrapper coordinator.  The first auxiliary message is
/// fixed before the state checks the public unsplit target, and no challenge
/// can be bound before that check succeeds.
pub struct C6ResidualSumcheckProverRoundState {
    repetition: u8,
    statement_digest: [u8; 32],
    target: Fp2,
    leaf: FamilyProverState,
    auxiliary: FamilyProverState,
    auxiliary_activation: usize,
    global_round: usize,
    pending_round: bool,
    split_checked: bool,
}

impl C6ResidualSumcheckProverRoundState {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn round_count(&self) -> usize {
        self.leaf.rounds
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn auxiliary_activation_round(&self) -> usize {
        self.auxiliary_activation
    }

    pub fn is_complete(&self) -> bool {
        !self.pending_round
            && self.global_round == self.round_count()
            && self.leaf.is_complete()
            && self.auxiliary.is_complete()
            && self.split_checked
    }

    /// Fix the next leaf/raw message and, on the aligned suffix, the
    /// auxiliary message.  The returned byte count is the single residual
    /// participant receipt for the outer coordinator.
    pub fn fix_next_round(&mut self) -> Result<u64> {
        if self.pending_round || self.global_round >= self.round_count() {
            return Err(C6ResidualSumcheckError::new(
                "invalid C6 residual prover round transition",
            ));
        }
        self.leaf.fix_next_round()?;
        let auxiliary_active = self.global_round >= self.auxiliary_activation;
        if auxiliary_active {
            self.auxiliary.fix_next_round()?;
        }
        if self.global_round == self.auxiliary_activation {
            let leaf_initial = self.leaf.initial_claim().ok_or_else(|| {
                C6ResidualSumcheckError::new("missing C6 residual leaf initial claim")
            })?;
            let auxiliary_initial = self.auxiliary.initial_claim().ok_or_else(|| {
                C6ResidualSumcheckError::new("missing C6 residual auxiliary initial claim")
            })?;
            if leaf_initial + auxiliary_initial != self.target {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual initial claims do not equal the public target",
                ));
            }
            self.split_checked = true;
        }
        self.pending_round = true;
        residual_round_message_bytes(auxiliary_active)
    }

    pub fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if !self.pending_round || self.global_round >= self.round_count() {
            return Err(C6ResidualSumcheckError::new(
                "invalid C6 residual prover challenge transition",
            ));
        }
        self.leaf.bind_challenge(challenge)?;
        if self.global_round >= self.auxiliary_activation {
            self.auxiliary.bind_challenge(challenge)?;
        }
        self.global_round += 1;
        self.pending_round = false;
        Ok(())
    }

    pub fn finish(
        self,
    ) -> Result<(C6ResidualSumcheckRepetitionProof, Vec<C6ResidualOpeningClaim>)> {
        if !self.is_complete() {
            return Err(C6ResidualSumcheckError::new("incomplete C6 residual prover repetition"));
        }
        let (leaf_messages, leaf_point, mut leaf_claims) = self.leaf.finish(self.repetition)?;
        let (auxiliary_messages, auxiliary_point, auxiliary_claims) =
            self.auxiliary.finish(self.repetition)?;
        if auxiliary_point != leaf_point[leaf_point.len() - auxiliary_point.len()..] {
            return Err(C6ResidualSumcheckError::new("C6 residual prover suffix points diverged"));
        }
        let leaf_rounds = leaf_messages
            .into_iter()
            .map(|round| {
                round.try_into().map_err(|_| {
                    C6ResidualSumcheckError::new("C6 residual leaf message degree mismatch")
                })
            })
            .collect::<Result<Vec<[Fp2; 3]>>>()?;
        let auxiliary_rounds = auxiliary_messages
            .into_iter()
            .map(|round| {
                round.try_into().map_err(|_| {
                    C6ResidualSumcheckError::new("C6 residual auxiliary message degree mismatch")
                })
            })
            .collect::<Result<Vec<[Fp2; 4]>>>()?;
        leaf_claims.extend(auxiliary_claims);
        Ok((
            C6ResidualSumcheckRepetitionProof {
                repetition: self.repetition,
                statement_digest: self.statement_digest,
                leaf_rounds,
                auxiliary_rounds,
            },
            leaf_claims,
        ))
    }
}

pub fn prepare_residual_sumcheck_prover_round_state(
    statement: &C6ResidualSumcheckStatement,
    witness: &C6ResidualSumcheckWitness,
) -> Result<C6ResidualSumcheckProverRoundState> {
    statement.validate()?;
    validate_witness_tables(&statement.leaf, &witness.leaf_tables)?;
    validate_witness_tables(&statement.auxiliary, &witness.auxiliary_tables)?;
    let leaf = FamilyProverState::new(&statement.leaf, witness.leaf_tables.clone())?;
    let auxiliary = FamilyProverState::new(&statement.auxiliary, witness.auxiliary_tables.clone())?;
    Ok(C6ResidualSumcheckProverRoundState {
        repetition: statement.repetition,
        statement_digest: statement.digest,
        target: statement.target,
        leaf,
        auxiliary,
        auxiliary_activation: statement.auxiliary_activation_round(),
        global_round: 0,
        pending_round: false,
        split_checked: false,
    })
}

/// Verifier-side repetition with the same activation and pending-message
/// discipline as [`C6ResidualSumcheckProverRoundState`].
pub struct C6ResidualSumcheckVerifierRoundState<'a> {
    statement: &'a C6ResidualSumcheckStatement,
    leaf: FamilyVerifierState<'a>,
    auxiliary: FamilyVerifierState<'a>,
    auxiliary_activation: usize,
    global_round: usize,
    pending_round: bool,
    split_checked: bool,
}

impl C6ResidualSumcheckVerifierRoundState<'_> {
    pub fn repetition(&self) -> u8 {
        self.statement.repetition
    }

    pub fn round_count(&self) -> usize {
        self.statement.leaf.rounds
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn auxiliary_activation_round(&self) -> usize {
        self.auxiliary_activation
    }

    pub fn is_complete(&self) -> bool {
        !self.pending_round
            && self.global_round == self.round_count()
            && self.leaf.is_complete()
            && self.auxiliary.is_complete()
            && self.split_checked
    }

    /// Check all active messages, including the unsplit public target at the
    /// auxiliary activation boundary, before the outer coordinator releases
    /// its shared challenge.
    pub fn check_next_round(&mut self) -> Result<u64> {
        if self.pending_round || self.global_round >= self.round_count() {
            return Err(C6ResidualSumcheckError::new(
                "invalid C6 residual verifier round transition",
            ));
        }
        self.leaf.check_next_round()?;
        let auxiliary_active = self.global_round >= self.auxiliary_activation;
        if auxiliary_active {
            self.auxiliary.check_next_round()?;
        }
        if self.global_round == self.auxiliary_activation {
            let leaf_initial = self.leaf.initial_claim().ok_or_else(|| {
                C6ResidualSumcheckError::new("missing C6 residual leaf initial claim")
            })?;
            let auxiliary_initial = self.auxiliary.initial_claim().ok_or_else(|| {
                C6ResidualSumcheckError::new("missing C6 residual auxiliary initial claim")
            })?;
            if leaf_initial + auxiliary_initial != self.statement.target {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual proof does not match the public target",
                ));
            }
            self.split_checked = true;
        }
        self.pending_round = true;
        residual_round_message_bytes(auxiliary_active)
    }

    pub fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if !self.pending_round || self.global_round >= self.round_count() {
            return Err(C6ResidualSumcheckError::new(
                "invalid C6 residual verifier challenge transition",
            ));
        }
        self.leaf.bind_challenge(challenge)?;
        if self.global_round >= self.auxiliary_activation {
            self.auxiliary.bind_challenge(challenge)?;
        }
        self.global_round += 1;
        self.pending_round = false;
        Ok(())
    }

    /// Check the final arithmetic expression against externally supplied
    /// same-point slot values.  Successful return is still not a production
    /// acceptance decision: the packed PCS must bind every returned claim.
    pub fn finish(
        self,
        opening_claims: &[C6ResidualOpeningClaim],
    ) -> Result<Vec<C6ResidualOpeningClaim>> {
        if !self.is_complete() {
            return Err(C6ResidualSumcheckError::new("incomplete C6 residual verifier repetition"));
        }
        let leaf_count = self.statement.leaf.tables.len();
        let auxiliary_count = self.statement.auxiliary.tables.len();
        if opening_claims.len() != leaf_count + auxiliary_count {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual terminal opening census mismatch",
            ));
        }
        let (leaf_claims, auxiliary_claims) = opening_claims.split_at(leaf_count);
        let leaf_point = self.leaf.finish(self.statement.repetition, leaf_claims)?;
        let auxiliary_point = self.auxiliary.finish(self.statement.repetition, auxiliary_claims)?;
        if auxiliary_point != leaf_point[leaf_point.len() - auxiliary_point.len()..] {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual verifier suffix points diverged",
            ));
        }
        Ok(opening_claims.to_vec())
    }
}

pub fn prepare_residual_sumcheck_verifier_round_state<'a>(
    statement: &'a C6ResidualSumcheckStatement,
    proof: &'a C6ResidualSumcheckRepetitionProof,
) -> Result<C6ResidualSumcheckVerifierRoundState<'a>> {
    statement.validate()?;
    if proof.repetition != statement.repetition
        || proof.statement_digest != statement.digest
        || proof.leaf_rounds.len() != statement.leaf.rounds
        || proof.auxiliary_rounds.len() != statement.auxiliary.rounds
    {
        return Err(C6ResidualSumcheckError::new("C6 residual verifier proof/statement mismatch"));
    }
    Ok(C6ResidualSumcheckVerifierRoundState {
        statement,
        leaf: FamilyVerifierState::new_leaf(&statement.leaf, &proof.leaf_rounds)?,
        auxiliary: FamilyVerifierState::new_auxiliary(
            &statement.auxiliary,
            &proof.auxiliary_rounds,
        )?,
        auxiliary_activation: statement.auxiliary_activation_round(),
        global_round: 0,
        pending_round: false,
        split_checked: false,
    })
}

#[derive(Clone)]
struct FoldedTerm {
    lhs: usize,
    rhs: Option<usize>,
    coefficients: Vec<Fp2>,
}

struct FamilyProverState {
    family: C6ResidualSumcheckFamily,
    rounds: usize,
    tables: Vec<C6ResidualTableRef>,
    witnesses: Vec<Vec<Fp2>>,
    terms: Vec<FoldedTerm>,
    messages: Vec<Vec<Fp2>>,
    point: Vec<Fp2>,
    initial_claim: Option<Fp2>,
    current_claim: Option<Fp2>,
    pending_round: bool,
}

type FamilyProverOutput = (Vec<Vec<Fp2>>, Vec<Fp2>, Vec<C6ResidualOpeningClaim>);

impl FamilyProverState {
    fn new(
        statement: &C6ResidualSumcheckFamilyStatement,
        witnesses: Vec<Vec<Fp2>>,
    ) -> Result<Self> {
        statement.validate()?;
        validate_witness_tables(statement, &witnesses)?;
        let terms = statement
            .terms
            .iter()
            .map(|term| {
                let (lhs, rhs) = term.factor_indices();
                FoldedTerm { lhs, rhs, coefficients: term.coefficients().to_vec() }
            })
            .collect();
        Ok(Self {
            family: statement.family,
            rounds: statement.rounds,
            tables: statement.tables.clone(),
            witnesses,
            terms,
            messages: Vec::with_capacity(statement.rounds),
            point: Vec::with_capacity(statement.rounds),
            initial_claim: None,
            current_claim: None,
            pending_round: false,
        })
    }

    fn degree(&self) -> usize {
        match self.family {
            C6ResidualSumcheckFamily::LeafRaw => 2,
            C6ResidualSumcheckFamily::Auxiliary => 3,
        }
    }

    fn initial_claim(&self) -> Option<Fp2> {
        self.initial_claim
    }

    fn is_complete(&self) -> bool {
        !self.pending_round && self.messages.len() == self.rounds && self.point.len() == self.rounds
    }

    fn fix_next_round(&mut self) -> Result<()> {
        if self.pending_round
            || self.messages.len() >= self.rounds
            || self.witnesses.iter().any(|table| table.len() < 2)
            || self.terms.iter().any(|term| term.coefficients.len() < 2)
        {
            return Err(C6ResidualSumcheckError::new("invalid C6 residual family prover state"));
        }
        let remaining = self.witnesses[0].len();
        if self.witnesses.iter().any(|table| table.len() != remaining)
            || self.terms.iter().any(|term| term.coefficients.len() != remaining)
        {
            return Err(C6ResidualSumcheckError::new("C6 residual folded-table geometry diverged"));
        }
        let mut message = vec![Fp2::ZERO; self.degree() + 1];
        for pair in 0..remaining / 2 {
            for (node, evaluation) in message.iter_mut().enumerate() {
                let at = Fp2::from_base(Fp::new(node as u64));
                for term in &self.terms {
                    let coefficient = affine_pair(&term.coefficients, pair, at);
                    let lhs = affine_pair(&self.witnesses[term.lhs], pair, at);
                    let mut value = coefficient * lhs;
                    if let Some(rhs) = term.rhs {
                        value = value * affine_pair(&self.witnesses[rhs], pair, at);
                    }
                    *evaluation += value;
                }
            }
        }
        let boolean_sum = message[0] + message[1];
        if self.messages.is_empty() {
            self.initial_claim = Some(boolean_sum);
        } else if self.current_claim != Some(boolean_sum) {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual prover round does not sum to its claim",
            ));
        }
        self.messages.push(message);
        self.pending_round = true;
        Ok(())
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if !self.pending_round || self.messages.is_empty() {
            return Err(C6ResidualSumcheckError::new("invalid C6 residual family challenge state"));
        }
        let message = self.messages.last().expect("checked nonempty");
        self.current_claim = Some(interpolate_round(self.family, message, challenge)?);
        for table in &mut self.witnesses {
            fold_low(table, challenge);
        }
        for term in &mut self.terms {
            fold_low(&mut term.coefficients, challenge);
        }
        self.point.push(challenge);
        self.pending_round = false;
        Ok(())
    }

    fn finish(self, repetition: u8) -> Result<FamilyProverOutput> {
        if !self.is_complete()
            || self.witnesses.iter().any(|table| table.len() != 1)
            || self.terms.iter().any(|term| term.coefficients.len() != 1)
        {
            return Err(C6ResidualSumcheckError::new("incomplete C6 residual family prover state"));
        }
        let terminal = evaluate_folded_terminal(&self.terms, &self.witnesses)?;
        if self.current_claim != Some(terminal) {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual prover terminal expression mismatch",
            ));
        }
        let claims = self
            .tables
            .iter()
            .zip(&self.witnesses)
            .map(|(table, values)| C6ResidualOpeningClaim {
                repetition,
                family: self.family,
                table: *table,
                point: self.point.clone(),
                value: values[0],
            })
            .collect();
        Ok((self.messages, self.point, claims))
    }
}

enum FamilyProofRounds<'a> {
    Leaf(&'a [[Fp2; 3]]),
    Auxiliary(&'a [[Fp2; 4]]),
}

struct FamilyVerifierState<'a> {
    statement: &'a C6ResidualSumcheckFamilyStatement,
    proof_rounds: FamilyProofRounds<'a>,
    round_index: usize,
    point: Vec<Fp2>,
    initial_claim: Option<Fp2>,
    current_claim: Option<Fp2>,
    pending_message: Option<Vec<Fp2>>,
}

impl<'a> FamilyVerifierState<'a> {
    fn new_leaf(
        statement: &'a C6ResidualSumcheckFamilyStatement,
        proof_rounds: &'a [[Fp2; 3]],
    ) -> Result<Self> {
        if statement.family != C6ResidualSumcheckFamily::LeafRaw
            || proof_rounds.len() != statement.rounds
        {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual leaf verifier geometry mismatch",
            ));
        }
        Ok(Self::new(statement, FamilyProofRounds::Leaf(proof_rounds)))
    }

    fn new_auxiliary(
        statement: &'a C6ResidualSumcheckFamilyStatement,
        proof_rounds: &'a [[Fp2; 4]],
    ) -> Result<Self> {
        if statement.family != C6ResidualSumcheckFamily::Auxiliary
            || proof_rounds.len() != statement.rounds
        {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual auxiliary verifier geometry mismatch",
            ));
        }
        Ok(Self::new(statement, FamilyProofRounds::Auxiliary(proof_rounds)))
    }

    fn new(
        statement: &'a C6ResidualSumcheckFamilyStatement,
        proof_rounds: FamilyProofRounds<'a>,
    ) -> Self {
        Self {
            statement,
            proof_rounds,
            round_index: 0,
            point: Vec::with_capacity(statement.rounds),
            initial_claim: None,
            current_claim: None,
            pending_message: None,
        }
    }

    fn initial_claim(&self) -> Option<Fp2> {
        self.initial_claim
    }

    fn is_complete(&self) -> bool {
        self.pending_message.is_none()
            && self.round_index == self.statement.rounds
            && self.point.len() == self.statement.rounds
    }

    fn message(&self) -> Result<Vec<Fp2>> {
        match &self.proof_rounds {
            FamilyProofRounds::Leaf(rounds) => rounds
                .get(self.round_index)
                .map(|round| round.to_vec())
                .ok_or_else(|| C6ResidualSumcheckError::new("missing C6 residual leaf round")),
            FamilyProofRounds::Auxiliary(rounds) => rounds
                .get(self.round_index)
                .map(|round| round.to_vec())
                .ok_or_else(|| C6ResidualSumcheckError::new("missing C6 residual auxiliary round")),
        }
    }

    fn check_next_round(&mut self) -> Result<()> {
        if self.pending_message.is_some() || self.round_index >= self.statement.rounds {
            return Err(C6ResidualSumcheckError::new("invalid C6 residual family verifier state"));
        }
        let message = self.message()?;
        let boolean_sum = message[0] + message[1];
        if self.round_index == 0 {
            self.initial_claim = Some(boolean_sum);
        } else if self.current_claim != Some(boolean_sum) {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual verifier round does not sum to its claim",
            ));
        }
        self.pending_message = Some(message);
        Ok(())
    }

    fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        let message = self.pending_message.take().ok_or_else(|| {
            C6ResidualSumcheckError::new("C6 residual verifier has no fixed message")
        })?;
        self.current_claim = Some(interpolate_round(self.statement.family, &message, challenge)?);
        self.point.push(challenge);
        self.round_index += 1;
        Ok(())
    }

    fn finish(self, repetition: u8, claims: &[C6ResidualOpeningClaim]) -> Result<Vec<Fp2>> {
        if !self.is_complete() || claims.len() != self.statement.tables.len() {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual terminal family census mismatch",
            ));
        }
        let mut values = Vec::with_capacity(claims.len());
        for (claim, table) in claims.iter().zip(&self.statement.tables) {
            if claim.repetition != repetition
                || claim.family != self.statement.family
                || claim.table != *table
                || claim.point != self.point
            {
                return Err(C6ResidualSumcheckError::new(
                    "C6 residual terminal owner or point mismatch",
                ));
            }
            values.push(claim.value);
        }
        let mut terminal = Fp2::ZERO;
        for term in &self.statement.terms {
            let coefficient = eval_mle(term.coefficients(), &self.point);
            let (lhs, rhs) = term.factor_indices();
            let mut value = coefficient * values[lhs];
            if let Some(rhs) = rhs {
                value = value * values[rhs];
            }
            terminal += value;
        }
        if self.current_claim != Some(terminal) {
            return Err(C6ResidualSumcheckError::new("C6 residual terminal expression mismatch"));
        }
        Ok(self.point)
    }
}

fn evaluate_folded_terminal(terms: &[FoldedTerm], witnesses: &[Vec<Fp2>]) -> Result<Fp2> {
    let mut terminal = Fp2::ZERO;
    for term in terms {
        let coefficient = *term
            .coefficients
            .first()
            .ok_or_else(|| C6ResidualSumcheckError::new("empty folded coefficient table"))?;
        let mut value = coefficient
            * witnesses
                .get(term.lhs)
                .and_then(|table| table.first())
                .copied()
                .ok_or_else(|| C6ResidualSumcheckError::new("empty folded witness table"))?;
        if let Some(rhs) = term.rhs {
            value =
                value
                    * witnesses.get(rhs).and_then(|table| table.first()).copied().ok_or_else(
                        || C6ResidualSumcheckError::new("empty folded witness table"),
                    )?;
        }
        terminal += value;
    }
    Ok(terminal)
}

fn interpolate_round(
    family: C6ResidualSumcheckFamily,
    message: &[Fp2],
    challenge: Fp2,
) -> Result<Fp2> {
    match family {
        C6ResidualSumcheckFamily::LeafRaw if message.len() == 3 => {
            let weights = lagrange3(challenge);
            Ok(weights[0] * message[0] + weights[1] * message[1] + weights[2] * message[2])
        }
        C6ResidualSumcheckFamily::Auxiliary if message.len() == 4 => {
            let weights = lagrange4(challenge);
            Ok(weights[0] * message[0]
                + weights[1] * message[1]
                + weights[2] * message[2]
                + weights[3] * message[3])
        }
        _ => Err(C6ResidualSumcheckError::new("C6 residual interpolation degree mismatch")),
    }
}

fn affine_pair(values: &[Fp2], pair: usize, at: Fp2) -> Fp2 {
    let low = values[2 * pair];
    low + at * (values[2 * pair + 1] - low)
}

fn residual_round_message_bytes(auxiliary_active: bool) -> Result<u64> {
    let leaf = 3u64
        .checked_mul(C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES)
        .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual leaf bytes overflow"))?;
    if auxiliary_active {
        leaf.checked_add(4 * C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES)
            .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual round bytes overflow"))
    } else {
        Ok(leaf)
    }
}

fn validate_statement_pair(statements: &[C6ResidualSumcheckStatement]) -> Result<()> {
    if statements.len() != C6_RESIDUAL_SUMCHECK_REPETITIONS {
        return Err(C6ResidualSumcheckError::new(
            "C6 residual statement repetition count mismatch",
        ));
    }
    for (index, statement) in statements.iter().enumerate() {
        statement.validate()?;
        if usize::from(statement.repetition) != index {
            return Err(C6ResidualSumcheckError::new("C6 residual statements are reordered"));
        }
    }
    Ok(())
}

fn canonical_terms(mut terms: Vec<C6ResidualSumcheckTerm>) -> Result<Vec<C6ResidualSumcheckTerm>> {
    terms.sort_by_key(C6ResidualSumcheckTerm::factor_key);
    if terms.windows(2).any(|pair| pair[0].factor_key() == pair[1].factor_key()) {
        return Err(C6ResidualSumcheckError::new("duplicate C6 residual factor tuple"));
    }
    Ok(terms)
}

fn validate_witness_tables(
    statement: &C6ResidualSumcheckFamilyStatement,
    tables: &[Vec<Fp2>],
) -> Result<()> {
    let table_len = statement.table_len()?;
    if tables.len() != statement.tables.len() || tables.iter().any(|table| table.len() != table_len)
    {
        return Err(C6ResidualSumcheckError::new("C6 residual witness-table geometry mismatch"));
    }
    Ok(())
}

fn expected_tables(
    repetition: u8,
    family: C6ResidualSumcheckFamily,
) -> Result<Vec<C6ResidualTableRef>> {
    let slots: &[u16] = match (repetition, family) {
        (0 | 1, C6ResidualSumcheckFamily::LeafRaw) => &C6_RESIDUAL_LEAF_TABLE_SLOTS,
        (0 | 1, C6ResidualSumcheckFamily::Auxiliary) => &C6_RESIDUAL_AUXILIARY_TABLE_SLOTS,
        _ => {
            return Err(C6ResidualSumcheckError::new(
                "C6 residual table repetition is out of range",
            ))
        }
    };
    let cohort_id = match family {
        C6ResidualSumcheckFamily::LeafRaw => C6_DELTA_RESIDUAL_COHORT_ID,
        C6ResidualSumcheckFamily::Auxiliary => C6_WRAPPER_AUXILIARY_COHORT_ID,
    };
    Ok(slots.iter().map(|slot| C6ResidualTableRef { cohort_id, slot: *slot }).collect())
}

fn checked_table_len(rounds: usize) -> Result<usize> {
    1usize
        .checked_shl(
            u32::try_from(rounds)
                .map_err(|_| C6ResidualSumcheckError::new("C6 residual rounds exceed u32"))?,
        )
        .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual table length overflows"))
}

fn common_atomic_table_len<'a>(
    family: &str,
    mut tables: impl Iterator<Item = &'a [Fp2]>,
) -> Result<usize> {
    let expected = tables
        .next()
        .ok_or_else(|| C6ResidualSumcheckError::new("empty C6 atomic relation family"))?
        .len();
    if tables.any(|table| table.len() != expected) {
        return Err(C6ResidualSumcheckError::new(format!(
            "C6 atomic {family} coefficient-table geometry mismatch"
        )));
    }
    Ok(expected)
}

fn exact_rounds_for_table_len(family: &str, table_len: usize) -> Result<usize> {
    if table_len < 2 || !table_len.is_power_of_two() {
        return Err(C6ResidualSumcheckError::new(format!(
            "C6 atomic {family} coefficient-table length is not a nontrivial power of two"
        )));
    }
    Ok(table_len.trailing_zeros() as usize)
}

fn statement_digest(statement: &C6ResidualSumcheckStatement) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATEMENT_DOMAIN);
    hasher.update(&[statement.repetition]);
    hash_fp2(&mut hasher, statement.target);
    if statement.compiler_binding_digest != [0; 32] {
        hasher.update(&[ATOMIC_COMPILER_BINDING_MARKER]);
        hasher.update(&statement.compiler_binding_digest);
    }
    for family in [&statement.leaf, &statement.auxiliary] {
        hasher.update(&[family.family as u8]);
        hasher.update(&(family.rounds as u64).to_le_bytes());
        hasher.update(&(family.tables.len() as u64).to_le_bytes());
        for table in &family.tables {
            hasher.update(&table.cohort_id.to_le_bytes());
            hasher.update(&table.slot.to_le_bytes());
        }
        hasher.update(&(family.terms.len() as u64).to_le_bytes());
        for term in &family.terms {
            let (arity, lhs, rhs) = term.factor_key();
            hasher.update(&[arity, lhs, rhs]);
            hasher.update(&(term.coefficients().len() as u64).to_le_bytes());
            for coefficient in term.coefficients() {
                hash_fp2(&mut hasher, *coefficient);
            }
        }
    }
    *hasher.finalize().as_bytes()
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
            .ok_or_else(|| C6ResidualSumcheckError::new("C6 residual decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6ResidualSumcheckError::new("truncated C6 residual proof"))?;
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

    fn fp2(&mut self) -> Result<Fp2> {
        let mut c0 = [0; 8];
        let mut c1 = [0; 8];
        c0.copy_from_slice(self.take(8)?);
        c1.copy_from_slice(self.take(8)?);
        let c0 = u64::from_le_bytes(c0);
        let c1 = u64::from_le_bytes(c1);
        if c0 >= P || c1 >= P {
            return Err(C6ResidualSumcheckError::new("noncanonical C6 residual field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c6_wrapper_pcs::{
        fix_test_c6_wrapper_commitments, C6WrapperCohortSpec, C6WrapperCommitment,
        C6WrapperOracleKind, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
        C6_CACHE_COHORT_ID, C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
        C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
    };
    use volta_mac::Transcript;

    const LEAF_ROUNDS: usize = 5;
    const AUXILIARY_ROUNDS: usize = 3;
    const GLOBAL_ROUNDS: usize = 6;
    const DELTA_ACTIVATION: usize = 1;
    const HIDDEN_ACTIVATION: usize = 4;

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
                        .fold(Fp2::ZERO, |sum, (coefficient, value)| sum + *coefficient * *value)
            }
            C6ResidualSumcheckTerm::Quadratic { lhs, rhs, coefficients } => {
                total
                    + coefficients
                        .iter()
                        .zip(&tables[usize::from(*lhs)])
                        .zip(&tables[usize::from(*rhs)])
                        .fold(Fp2::ZERO, |sum, ((coefficient, lhs), rhs)| {
                            sum + *coefficient * *lhs * *rhs
                        })
            }
        })
    }

    fn scaled_fixture(repetition: u8) -> (C6ResidualSumcheckStatement, C6ResidualSumcheckWitness) {
        let leaf_tables = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION as u64)
            .map(|table_index| {
                table(LEAF_ROUNDS, 10_000 * u64::from(repetition) + 1_000 * table_index + 10)
            })
            .collect::<Vec<_>>();
        let auxiliary_tables = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION as u64)
            .map(|table_index| {
                table(AUXILIARY_ROUNDS, 20_000 * u64::from(repetition) + 1_000 * table_index + 20)
            })
            .collect::<Vec<_>>();
        let leaf_terms = (0..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION as u8)
            .map(|table_index| {
                C6ResidualSumcheckTerm::linear(
                    table_index,
                    table(
                        LEAF_ROUNDS,
                        30_000 * u64::from(repetition) + 200 * u64::from(table_index) + 30,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let mut auxiliary_terms = (0..C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION as u8)
            .map(|table_index| {
                C6ResidualSumcheckTerm::linear(
                    table_index,
                    table(
                        AUXILIARY_ROUNDS,
                        40_000 * u64::from(repetition) + 200 * u64::from(table_index) + 40,
                    ),
                )
            })
            .collect::<Vec<_>>();
        auxiliary_terms.push(
            C6ResidualSumcheckTerm::quadratic(
                0,
                1,
                table(AUXILIARY_ROUNDS, 50_000 * u64::from(repetition) + 50),
            )
            .unwrap(),
        );
        let target = expression_sum(&leaf_terms, &leaf_tables)
            + expression_sum(&auxiliary_terms, &auxiliary_tables);
        let statement = C6ResidualSumcheckStatement::new_test(
            repetition,
            target,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            leaf_terms,
            auxiliary_terms,
        )
        .unwrap();
        let witness =
            C6ResidualSumcheckWitness::new(&statement, leaf_tables, auxiliary_tables).unwrap();
        (statement, witness)
    }

    fn atomic_reference_fixture(
        repetition: u8,
        compiler_binding_digest: [u8; 32],
    ) -> (C6ResidualSumcheckStatement, C6ResidualSumcheckWitness) {
        let leaf_tables: [Vec<Fp2>; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] =
            std::array::from_fn(|table_index| {
                table(
                    LEAF_ROUNDS,
                    110_000 * u64::from(repetition) + 1_000 * table_index as u64 + 110,
                )
            });
        let auxiliary_tables: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION] =
            std::array::from_fn(|table_index| {
                table(
                    AUXILIARY_ROUNDS,
                    120_000 * u64::from(repetition) + 1_000 * table_index as u64 + 120,
                )
            });
        let leaf_linear: [Vec<Fp2>; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] =
            std::array::from_fn(|table_index| {
                table(LEAF_ROUNDS, 130_000 * u64::from(repetition) + 200 * table_index as u64 + 130)
            });
        let auxiliary_linear: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION] =
            std::array::from_fn(|table_index| {
                table(
                    AUXILIARY_ROUNDS,
                    140_000 * u64::from(repetition) + 200 * table_index as u64 + 140,
                )
            });
        let auxiliary_quadratic = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            .iter()
            .enumerate()
            .map(|(tuple_index, factors)| {
                (
                    *factors,
                    table(
                        AUXILIARY_ROUNDS,
                        150_000 * u64::from(repetition) + 200 * tuple_index as u64 + 150,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let leaf_terms = leaf_linear
            .iter()
            .enumerate()
            .map(|(table, coefficients)| {
                C6ResidualSumcheckTerm::linear(table as u8, coefficients.clone())
            })
            .collect::<Vec<_>>();
        let mut auxiliary_terms = auxiliary_linear
            .iter()
            .enumerate()
            .map(|(table, coefficients)| {
                C6ResidualSumcheckTerm::linear(table as u8, coefficients.clone())
            })
            .collect::<Vec<_>>();
        auxiliary_terms.extend(auxiliary_quadratic.iter().map(|((lhs, rhs), coefficients)| {
            C6ResidualSumcheckTerm::quadratic(*lhs, *rhs, coefficients.clone()).unwrap()
        }));
        let target = expression_sum(&leaf_terms, &leaf_tables)
            + expression_sum(&auxiliary_terms, &auxiliary_tables);

        let statement = C6ResidualSumcheckStatement::from_atomic_relation_reference_parts(
            repetition,
            target,
            &leaf_linear,
            &auxiliary_linear,
            &auxiliary_quadratic,
            1_056,
            compiler_binding_digest,
        )
        .unwrap();
        let witness = C6ResidualSumcheckWitness::new(
            &statement,
            leaf_tables.into_iter().collect(),
            auxiliary_tables.into_iter().collect(),
        )
        .unwrap();
        (statement, witness)
    }

    fn challenges() -> Vec<Fp2> {
        (0..LEAF_ROUNDS).map(|round| symbol(70_000 + round as u64)).collect()
    }

    fn prove_scaled_repetition(
        statement: &C6ResidualSumcheckStatement,
        witness: &C6ResidualSumcheckWitness,
        challenges: &[Fp2],
    ) -> (C6ResidualSumcheckRepetitionProof, Vec<C6ResidualOpeningClaim>) {
        let mut state = prepare_residual_sumcheck_prover_round_state(statement, witness).unwrap();
        for (round, challenge) in challenges.iter().enumerate() {
            let expected = if round < LEAF_ROUNDS - AUXILIARY_ROUNDS { 48 } else { 112 };
            assert_eq!(state.fix_next_round().unwrap(), expected);
            state.bind_challenge(*challenge).unwrap();
        }
        state.finish().unwrap()
    }

    fn verify_scaled_repetition(
        statement: &C6ResidualSumcheckStatement,
        proof: &C6ResidualSumcheckRepetitionProof,
        claims: &[C6ResidualOpeningClaim],
        challenges: &[Fp2],
    ) -> Result<Vec<C6ResidualOpeningClaim>> {
        let mut state = prepare_residual_sumcheck_verifier_round_state(statement, proof)?;
        for challenge in challenges {
            state.check_next_round()?;
            state.bind_challenge(*challenge)?;
        }
        state.finish(claims)
    }

    fn scaled_wrapper_specs() -> [C6WrapperCohortSpec; 3] {
        [
            C6WrapperCohortSpec {
                cohort_id: C6_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 6,
                slot_count: 2,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_DELTA_RESIDUAL_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: LEAF_ROUNDS as u8,
                slot_count: 8,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: (AUXILIARY_ROUNDS + 1) as u8,
                slot_count: 32,
            },
        ]
    }

    fn wrapper_commitments() -> Vec<C6WrapperCommitment> {
        scaled_wrapper_specs()
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                C6WrapperCommitment::from_root([0x6d; 32], spec, [(index + 1) as u8; 32]).unwrap()
            })
            .collect()
    }

    fn receipts(
        participant_ids: &[u32],
        residual_bytes: Option<u64>,
    ) -> Vec<C6WrapperRoundMessageReceipt> {
        participant_ids
            .iter()
            .map(|participant_id| C6WrapperRoundMessageReceipt {
                participant_id: *participant_id,
                message_bytes: match *participant_id {
                    C6_CACHE_ROUND_PARTICIPANT_ID | C6_HIDDEN_U_ROUND_PARTICIPANT_ID => 48,
                    C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID => {
                        residual_bytes.expect("residual participant is active")
                    }
                    _ => panic!("unexpected participant"),
                },
            })
            .collect()
    }

    #[test]
    fn scaled_two_family_states_join_the_global_coordinator_and_pcs_points() {
        let fixtures = [scaled_fixture(0), scaled_fixture(1)];
        let statements = fixtures.iter().map(|fixture| fixture.0.clone()).collect::<Vec<_>>();
        let commitments = wrapper_commitments();
        let specs = scaled_wrapper_specs();
        let seed = [0x71; 32];
        let mut prover_tx = Transcript::new(seed);
        let fixed =
            fix_test_c6_wrapper_commitments([0x6d; 32], &commitments, &mut prover_tx).unwrap();
        let mut repetition_proofs = Vec::new();
        let mut all_claims = Vec::new();
        let mut prover_points = Vec::new();

        for (repetition, (statement, witness)) in fixtures.iter().enumerate() {
            let mut state =
                prepare_residual_sumcheck_prover_round_state(statement, witness).unwrap();
            let mut coordinator = C6WrapperRoundCoordinator::new_test(
                &fixed,
                repetition as u8,
                GLOBAL_ROUNDS,
                DELTA_ACTIVATION,
                HIDDEN_ACTIVATION,
            )
            .unwrap();
            while coordinator.round_index() < GLOBAL_ROUNDS {
                let participant_ids = coordinator.expected_participant_ids().unwrap();
                let residual_bytes = if coordinator.round_index() >= DELTA_ACTIVATION {
                    Some(state.fix_next_round().unwrap())
                } else {
                    None
                };
                let challenge = coordinator
                    .fix_messages_and_release_challenge(
                        &receipts(&participant_ids, residual_bytes),
                        &mut prover_tx,
                    )
                    .unwrap();
                if residual_bytes.is_some() {
                    state.bind_challenge(challenge).unwrap();
                }
                coordinator.confirm_participants_bound(&participant_ids).unwrap();
            }
            let point = coordinator.finish().unwrap();
            let (proof, claims) = state.finish().unwrap();
            assert_eq!(claims.len(), C6_RESIDUAL_TABLES_PER_REPETITION);
            for (claim, source) in
                claims[..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION].iter().zip(witness.leaf_tables())
            {
                assert_eq!(claim.value, eval_mle(source, &claim.point));
            }
            for (claim, source) in claims[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION..]
                .iter()
                .zip(witness.auxiliary_tables())
            {
                assert_eq!(claim.value, eval_mle(source, &claim.point));
            }
            let residual_point = point.cohort_point(specs[1]).unwrap();
            let auxiliary_point = point.cohort_point(specs[2]).unwrap();
            for claim in &claims[..C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] {
                assert_eq!(claim.wrapper_point(), residual_point);
            }
            for claim in &claims[C6_RESIDUAL_LEAF_TABLES_PER_REPETITION..] {
                assert_eq!(claim.wrapper_point(), auxiliary_point);
            }
            repetition_proofs.push(proof);
            all_claims.push(claims);
            prover_points.push(point);
        }

        let proof = C6ResidualSumcheckProof::new(&statements, repetition_proofs).unwrap();
        let encoded = proof.encode(&statements).unwrap();
        assert_eq!(encoded.len() as u64, residual_sumcheck_encoded_len(&statements).unwrap());
        let decoded = C6ResidualSumcheckProof::decode(&statements, &encoded).unwrap();

        let mut verifier_tx = Transcript::new(seed);
        let verifier_fixed =
            fix_test_c6_wrapper_commitments([0x6d; 32], &commitments, &mut verifier_tx).unwrap();
        for repetition in 0..C6_RESIDUAL_SUMCHECK_REPETITIONS {
            let mut state = prepare_residual_sumcheck_verifier_round_state(
                &statements[repetition],
                &decoded.repetitions()[repetition],
            )
            .unwrap();
            let mut coordinator = C6WrapperRoundCoordinator::new_test(
                &verifier_fixed,
                repetition as u8,
                GLOBAL_ROUNDS,
                DELTA_ACTIVATION,
                HIDDEN_ACTIVATION,
            )
            .unwrap();
            while coordinator.round_index() < GLOBAL_ROUNDS {
                let participant_ids = coordinator.expected_participant_ids().unwrap();
                let residual_bytes = if coordinator.round_index() >= DELTA_ACTIVATION {
                    Some(state.check_next_round().unwrap())
                } else {
                    None
                };
                let challenge = coordinator
                    .fix_messages_and_release_challenge(
                        &receipts(&participant_ids, residual_bytes),
                        &mut verifier_tx,
                    )
                    .unwrap();
                if residual_bytes.is_some() {
                    state.bind_challenge(challenge).unwrap();
                }
                coordinator.confirm_participants_bound(&participant_ids).unwrap();
            }
            assert_eq!(state.finish(&all_claims[repetition]).unwrap(), all_claims[repetition]);
            assert_eq!(coordinator.finish().unwrap(), prover_points[repetition]);
        }
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
    }

    #[test]
    fn tampering_rounds_targets_and_terminal_owners_fails_closed() {
        let (statement, witness) = scaled_fixture(0);
        let challenges = challenges();
        let (proof, claims) = prove_scaled_repetition(&statement, &witness, &challenges);
        assert!(verify_scaled_repetition(&statement, &proof, &claims, &challenges).is_ok());

        let mut bad_leaf = proof.clone();
        bad_leaf.leaf_rounds[1][0] += Fp2::ONE;
        assert!(verify_scaled_repetition(&statement, &bad_leaf, &claims, &challenges).is_err());

        let mut bad_auxiliary = proof.clone();
        bad_auxiliary.auxiliary_rounds[0][0] += Fp2::ONE;
        assert!(verify_scaled_repetition(&statement, &bad_auxiliary, &claims, &challenges).is_err());

        let mut bad_terminal = claims.clone();
        bad_terminal[0].value += Fp2::ONE;
        assert!(verify_scaled_repetition(&statement, &proof, &bad_terminal, &challenges).is_err());
        let mut reordered = claims.clone();
        reordered.swap(0, 1);
        assert!(verify_scaled_repetition(&statement, &proof, &reordered, &challenges).is_err());
        let mut wrong_point = claims.clone();
        wrong_point[0].point[0] += Fp2::ONE;
        assert!(verify_scaled_repetition(&statement, &proof, &wrong_point, &challenges).is_err());
        assert!(verify_scaled_repetition(
            &statement,
            &proof,
            &claims[..claims.len() - 1],
            &challenges
        )
        .is_err());

        let mut wrong_digest = proof.clone();
        wrong_digest.statement_digest[0] ^= 1;
        assert!(prepare_residual_sumcheck_verifier_round_state(&statement, &wrong_digest).is_err());

        let mismatched_statement = C6ResidualSumcheckStatement::new_test(
            0,
            statement.target() + Fp2::ONE,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            statement.leaf().terms().to_vec(),
            statement.auxiliary().terms().to_vec(),
        )
        .unwrap();
        let mismatched_witness = C6ResidualSumcheckWitness::new(
            &mismatched_statement,
            witness.leaf_tables().to_vec(),
            witness.auxiliary_tables().to_vec(),
        )
        .unwrap();
        let mut state = prepare_residual_sumcheck_prover_round_state(
            &mismatched_statement,
            &mismatched_witness,
        )
        .unwrap();
        for challenge in challenges.iter().take(LEAF_ROUNDS - AUXILIARY_ROUNDS) {
            state.fix_next_round().unwrap();
            state.bind_challenge(*challenge).unwrap();
        }
        assert!(state.fix_next_round().is_err());
        assert!(state.bind_challenge(challenges[LEAF_ROUNDS - AUXILIARY_ROUNDS]).is_err());
    }

    #[test]
    fn transition_discipline_and_statement_ownership_reject_malformed_inputs() {
        let (statement, witness) = scaled_fixture(0);
        let mut prover =
            prepare_residual_sumcheck_prover_round_state(&statement, &witness).unwrap();
        assert!(prover.bind_challenge(symbol(1)).is_err());
        prover.fix_next_round().unwrap();
        assert!(prover.fix_next_round().is_err());
        prover.bind_challenge(symbol(1)).unwrap();
        assert!(prover.bind_challenge(symbol(2)).is_err());
        assert!(prover.finish().is_err());

        let coefficients = table(LEAF_ROUNDS, 90);
        let leaf_quadratic = vec![
            C6ResidualSumcheckTerm::Quadratic {
                lhs: 0,
                rhs: 0,
                coefficients: coefficients.clone(),
            },
            C6ResidualSumcheckTerm::linear(1, coefficients.clone()),
            C6ResidualSumcheckTerm::linear(2, coefficients.clone()),
            C6ResidualSumcheckTerm::linear(3, coefficients.clone()),
            C6ResidualSumcheckTerm::linear(4, coefficients.clone()),
        ];
        assert!(C6ResidualSumcheckStatement::new_test(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            leaf_quadratic,
            statement.auxiliary().terms().to_vec(),
        )
        .is_err());

        let mut duplicate = statement.leaf().terms().to_vec();
        duplicate.push(duplicate[0].clone());
        assert!(C6ResidualSumcheckStatement::new_test(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            duplicate,
            statement.auxiliary().terms().to_vec(),
        )
        .is_err());

        assert!(C6ResidualSumcheckStatement::new_test(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            statement.leaf().terms()[..4].to_vec(),
            statement.auxiliary().terms().to_vec(),
        )
        .is_err());

        let reversed = C6ResidualSumcheckTerm::Quadratic {
            lhs: 1,
            rhs: 0,
            coefficients: table(AUXILIARY_ROUNDS, 91),
        };
        let mut reversed_terms = statement.auxiliary().terms().to_vec();
        reversed_terms.push(reversed);
        assert!(C6ResidualSumcheckStatement::new_test(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            statement.leaf().terms().to_vec(),
            reversed_terms,
        )
        .is_err());

        let mut wrong_leaf_owners = expected_tables(0, C6ResidualSumcheckFamily::LeafRaw).unwrap();
        wrong_leaf_owners[0] = C6ResidualTableRef { cohort_id: C6_CACHE_COHORT_ID, slot: 0 };
        assert!(C6ResidualSumcheckStatement::build(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            wrong_leaf_owners,
            expected_tables(0, C6ResidualSumcheckFamily::Auxiliary).unwrap(),
            statement.leaf().terms().to_vec(),
            statement.auxiliary().terms().to_vec(),
            [0; 32],
        )
        .is_err());

        let mut wrong_auxiliary_owner =
            expected_tables(0, C6ResidualSumcheckFamily::Auxiliary).unwrap();
        wrong_auxiliary_owner[0].slot = 16;
        assert!(C6ResidualSumcheckStatement::build(
            0,
            Fp2::ZERO,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            expected_tables(0, C6ResidualSumcheckFamily::LeafRaw).unwrap(),
            wrong_auxiliary_owner,
            statement.leaf().terms().to_vec(),
            statement.auxiliary().terms().to_vec(),
            [0; 32],
        )
        .is_err());

        let mut short_leaf = witness.leaf_tables().to_vec();
        short_leaf[0].pop();
        assert!(C6ResidualSumcheckWitness::new(
            &statement,
            short_leaf,
            witness.auxiliary_tables().to_vec(),
        )
        .is_err());
    }

    #[test]
    fn strict_codec_and_wire_accounting_are_canonical() {
        let fixtures = [scaled_fixture(0), scaled_fixture(1)];
        let statements = fixtures.iter().map(|fixture| fixture.0.clone()).collect::<Vec<_>>();
        let challenge_values = challenges();
        let repetitions = fixtures
            .iter()
            .map(|(statement, witness)| {
                prove_scaled_repetition(statement, witness, &challenge_values).0
            })
            .collect::<Vec<_>>();
        let proof = C6ResidualSumcheckProof::new(&statements, repetitions).unwrap();
        let encoded = proof.encode(&statements).unwrap();
        assert_eq!(encoded.len(), 980);
        assert_eq!(proof.encoded_len(&statements).unwrap(), 980);
        assert_eq!(C6ResidualSumcheckProof::decode(&statements, &encoded).unwrap(), proof);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6ResidualSumcheckProof::decode(&statements, &trailing).is_err());

        let mut bad_version = encoded.clone();
        bad_version[8] ^= 1;
        assert!(C6ResidualSumcheckProof::decode(&statements, &bad_version).is_err());

        let mut noncanonical = encoded.clone();
        noncanonical[48..56].copy_from_slice(&P.to_le_bytes());
        let digest_offset = noncanonical.len() - 32;
        let digest = proof_digest(&noncanonical[..digest_offset]);
        noncanonical[digest_offset..].copy_from_slice(&digest);
        assert!(C6ResidualSumcheckProof::decode(&statements, &noncanonical).is_err());

        let mut wrong_statement = encoded.clone();
        wrong_statement[16] ^= 1;
        let digest_offset = wrong_statement.len() - 32;
        let digest = proof_digest(&wrong_statement[..digest_offset]);
        wrong_statement[digest_offset..].copy_from_slice(&digest);
        assert!(C6ResidualSumcheckProof::decode(&statements, &wrong_statement).is_err());

        let mut wrong_digest = encoded;
        let last = wrong_digest.len() - 1;
        wrong_digest[last] ^= 1;
        assert!(C6ResidualSumcheckProof::decode(&statements, &wrong_digest).is_err());

        let per_repetition =
            C6_RESIDUAL_LEAF_ROUNDS as u64 * 3 * 16 + C6_RESIDUAL_AUXILIARY_ROUNDS as u64 * 4 * 16;
        assert_eq!(per_repetition, 2_064);
        assert_eq!(production_c6_residual_sumcheck_round_bytes(), 2 * per_repetition);
        assert_eq!(production_c6_residual_sumcheck_round_bytes(), 4_128);
        assert_eq!(
            production_c6_residual_sumcheck_encoded_len(),
            12 + 2 * (4 + 32 + per_repetition) + 32
        );
        assert_eq!(production_c6_residual_sumcheck_encoded_len(), 4_244);
    }

    #[test]
    fn statement_digest_binds_coefficients_target_and_complete_repetition() {
        let (statement, _) = scaled_fixture(0);
        let mut changed_terms = statement.leaf().terms().to_vec();
        match &mut changed_terms[0] {
            C6ResidualSumcheckTerm::Linear { coefficients, .. }
            | C6ResidualSumcheckTerm::Quadratic { coefficients, .. } => {
                coefficients[0] += Fp2::ONE;
            }
        }
        let changed_coefficient = C6ResidualSumcheckStatement::new_test(
            0,
            statement.target(),
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            changed_terms,
            statement.auxiliary().terms().to_vec(),
        )
        .unwrap();
        assert_ne!(changed_coefficient.digest(), statement.digest());

        let changed_target = C6ResidualSumcheckStatement::new_test(
            0,
            statement.target() + Fp2::ONE,
            LEAF_ROUNDS,
            AUXILIARY_ROUNDS,
            statement.leaf().terms().to_vec(),
            statement.auxiliary().terms().to_vec(),
        )
        .unwrap();
        assert_ne!(changed_target.digest(), statement.digest());

        let (other_repetition, _) = scaled_fixture(1);
        assert_ne!(other_repetition.digest(), statement.digest());
        assert_eq!(
            statement.leaf().tables().iter().map(|table| table.slot).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(
            other_repetition.leaf().tables().iter().map(|table| table.slot).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(
            statement.auxiliary().tables().iter().map(|table| table.slot).collect::<Vec<_>>(),
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(
            other_repetition
                .auxiliary()
                .tables()
                .iter()
                .map(|table| table.slot)
                .collect::<Vec<_>>(),
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(C6_RESIDUAL_TABLES_PER_REPETITION, 24);
    }

    #[test]
    fn atomic_reference_bridge_proves_and_binds_the_compiler_statement() {
        let compiler_binding_digest = [0xE1; 32];
        let (statement, witness) = atomic_reference_fixture(0, compiler_binding_digest);
        assert_eq!(statement.compiler_binding_digest(), Some(compiler_binding_digest));
        assert_eq!(statement.leaf().terms().len(), 8);
        assert_eq!(statement.auxiliary().terms().len(), 24);
        assert_eq!(
            statement
                .auxiliary()
                .terms()
                .iter()
                .filter_map(|term| match term {
                    C6ResidualSumcheckTerm::Quadratic { lhs, rhs, .. } => Some((*lhs, *rhs)),
                    C6ResidualSumcheckTerm::Linear { .. } => None,
                })
                .collect::<Vec<_>>(),
            C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
        );

        let challenge_values = challenges();
        let (repetition_proof, claims) =
            prove_scaled_repetition(&statement, &witness, &challenge_values);
        assert_eq!(
            verify_scaled_repetition(&statement, &repetition_proof, &claims, &challenge_values,)
                .unwrap(),
            claims
        );

        let (other_statement, other_witness) = atomic_reference_fixture(1, [0xE4; 32]);
        let (other_repetition_proof, other_claims) =
            prove_scaled_repetition(&other_statement, &other_witness, &challenge_values);
        assert_eq!(
            verify_scaled_repetition(
                &other_statement,
                &other_repetition_proof,
                &other_claims,
                &challenge_values,
            )
            .unwrap(),
            other_claims
        );
        let statements = vec![statement.clone(), other_statement];
        let proof = C6ResidualSumcheckProof::new(
            &statements,
            vec![repetition_proof.clone(), other_repetition_proof],
        )
        .unwrap();
        let encoded = proof.encode(&statements).unwrap();
        assert_eq!(encoded.len(), 980);
        assert_eq!(C6ResidualSumcheckProof::decode(&statements, &encoded).unwrap(), proof);

        let (changed_binding, _) = atomic_reference_fixture(0, [0xE2; 32]);
        assert_eq!(changed_binding.target(), statement.target());
        assert_ne!(changed_binding.digest(), statement.digest());
        assert!(prepare_residual_sumcheck_verifier_round_state(
            &changed_binding,
            &repetition_proof
        )
        .is_err());

        let mut post_build_mutation = statement.clone();
        post_build_mutation.compiler_binding_digest[0] ^= 1;
        assert!(post_build_mutation.validate().is_err());

        let (legacy, _) = scaled_fixture(0);
        assert_eq!(legacy.compiler_binding_digest(), None);
        assert_ne!(legacy.digest(), statement.digest());
        assert_eq!(production_c6_residual_sumcheck_encoded_len(), 4_244);
    }

    #[test]
    fn atomic_reference_bridge_rejects_noncanonical_parts() {
        let leaf_linear: [Vec<Fp2>; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION] =
            std::array::from_fn(|_| vec![Fp2::ONE; 32]);
        let auxiliary_linear: [Vec<Fp2>; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION] =
            std::array::from_fn(|_| vec![Fp2::ONE; 8]);
        let quadratic = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            .map(|factors| (factors, vec![Fp2::ONE; 8]))
            .to_vec();
        let build = |repetition,
                     leaf: &[Vec<Fp2>; C6_RESIDUAL_LEAF_TABLES_PER_REPETITION],
                     auxiliary: &[Vec<Fp2>; C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION],
                     quadratic: &[((u8, u8), Vec<Fp2>)],
                     outputs,
                     digest| {
            C6ResidualSumcheckStatement::from_atomic_relation_reference_parts(
                repetition,
                Fp2::ZERO,
                leaf,
                auxiliary,
                quadratic,
                outputs,
                digest,
            )
        };
        assert!(build(0, &leaf_linear, &auxiliary_linear, &quadratic, 1_056, [0xE3; 32],).is_ok());
        assert!(build(0, &leaf_linear, &auxiliary_linear, &quadratic, 0, [0xE3; 32],).is_err());
        assert!(build(0, &leaf_linear, &auxiliary_linear, &quadratic, 1_056, [0; 32],).is_err());
        assert!(build(2, &leaf_linear, &auxiliary_linear, &quadratic, 1_056, [0xE3; 32],).is_err());

        let mut reordered = quadratic.clone();
        reordered.swap(0, 1);
        assert!(build(0, &leaf_linear, &auxiliary_linear, &reordered, 1_056, [0xE3; 32],).is_err());

        let non_power_leaf = std::array::from_fn(|_| vec![Fp2::ONE; 24]);
        assert!(
            build(0, &non_power_leaf, &auxiliary_linear, &quadratic, 1_056, [0xE3; 32],).is_err()
        );

        let oversized_auxiliary = std::array::from_fn(|_| vec![Fp2::ONE; 64]);
        let oversized_quadratic = C6_RESIDUAL_AUXILIARY_QUADRATIC_FACTORS
            .map(|factors| (factors, vec![Fp2::ONE; 64]))
            .to_vec();
        assert!(build(
            0,
            &leaf_linear,
            &oversized_auxiliary,
            &oversized_quadratic,
            1_056,
            [0xE3; 32],
        )
        .is_err());
    }
}

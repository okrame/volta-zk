//! Native-field C6 reduction of all hidden Ligero `u` relations to packed
//! PCS opening claims.
//!
//! This module is deliberately one layer short of production acceptance:
//! [`reduce_hidden_u_sumchecks`] verifies the two complete interactive
//! sumcheck repetitions and returns the exact `U(r)` claims that a C6 packed
//! opening must bind. It never treats prover-supplied terminal values as an
//! opening proof by themselves.

use crate::c6_hidden_u::{
    encode_fp2_ntt, hidden_u_functional_digest, C6HiddenUDigest, C6HiddenUError, C6HiddenUFamily,
    C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUPrequery, C6SealedHiddenUBundle,
    C6_HIDDEN_U_REPETITIONS,
};
use crate::ntt::{root_of_unity, NttPlan};
use rayon::prelude::*;
use volta_field::{Fp, Fp2, FpStream, P};
use volta_mac::Transcript;
use volta_proto::mle::{eval_mle, lagrange3};

const PROOF_MAGIC: [u8; 8] = *b"C6HUSC1\0";
const PROOF_VERSION: u16 = 1;
const PROOF_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-sumcheck-proof/v1";
const ROUND_BYTES: u64 = 3 * 16;
const BATCH_STREAM_DOMAINS: [u64; 2] = [0xC6_48_55_52_4C_43_01, 0xC6_48_55_52_4C_43_02];

type Result<T> = std::result::Result<T, C6HiddenUError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUSumcheckFamilyProof {
    pub family: C6HiddenUFamily,
    pub rounds: Vec<[Fp2; 3]>,
    /// This is only a claim until the packed C6 PCS opens the corresponding
    /// family oracle at [`C6HiddenUOpeningClaim::wrapper_point`].
    pub terminal_u: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUSumcheckRepetition {
    pub families: Vec<C6HiddenUSumcheckFamilyProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUSumcheckProof {
    pub postcommit_digest: C6HiddenUDigest,
    pub repetitions: Vec<C6HiddenUSumcheckRepetition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUOpeningClaim {
    pub repetition: u8,
    pub family: C6HiddenUFamily,
    /// Point on the fixed `2^mu` family witness in LSB-first order.
    pub point: Vec<Fp2>,
    pub value: Fp2,
}

impl C6HiddenUOpeningClaim {
    /// The strict-rate wrapper stores the witness in the zero half of a
    /// `2^(mu+1)` ZK extension. Appending zero selects that half.
    pub fn wrapper_point(&self) -> Vec<Fp2> {
        let mut point = self.point.clone();
        point.push(Fp2::ZERO);
        point
    }
}

impl C6HiddenUSumcheckProof {
    pub fn encode(&self, layouts: &[C6HiddenULayout]) -> Result<Vec<u8>> {
        self.validate_shape(layouts)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PROOF_MAGIC);
        bytes.extend_from_slice(&PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.repetitions.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.postcommit_digest);
        for (repetition_index, repetition) in self.repetitions.iter().enumerate() {
            bytes.push(repetition_index as u8);
            bytes.push(repetition.families.len() as u8);
            bytes.extend_from_slice(&0u16.to_le_bytes());
            for family in &repetition.families {
                bytes.push(family.family as u8);
                bytes.push(family.rounds.len() as u8);
                bytes.extend_from_slice(&0u16.to_le_bytes());
                encode_fp2(&mut bytes, family.terminal_u);
                for round in &family.rounds {
                    for value in round {
                        encode_fp2(&mut bytes, *value);
                    }
                }
            }
        }
        bytes.extend_from_slice(&proof_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(
        layouts: &[C6HiddenULayout],
        expected_postcommit_digest: C6HiddenUDigest,
        bytes: &[u8],
    ) -> Result<Self> {
        validate_layouts(layouts)?;
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != PROOF_MAGIC {
            return Err(C6HiddenUError::new("bad C6 hidden-u sumcheck magic"));
        }
        if cursor.u16()? != PROOF_VERSION {
            return Err(C6HiddenUError::new("unknown C6 hidden-u sumcheck version"));
        }
        if cursor.u16()? as usize != C6_HIDDEN_U_REPETITIONS as usize {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck repetition mismatch"));
        }
        let postcommit_digest = cursor.digest()?;
        if postcommit_digest != expected_postcommit_digest {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck postcommit mismatch"));
        }
        let mut repetitions = Vec::with_capacity(C6_HIDDEN_U_REPETITIONS as usize);
        for repetition_index in 0..C6_HIDDEN_U_REPETITIONS as usize {
            if cursor.u8()? as usize != repetition_index
                || cursor.u8()? as usize != layouts.len()
                || cursor.u16()? != 0
            {
                return Err(C6HiddenUError::new("C6 hidden-u sumcheck repetition header mismatch"));
            }
            let mut families = Vec::with_capacity(layouts.len());
            for layout in layouts {
                let family = decode_family(cursor.u8()?)?;
                let round_count = cursor.u8()? as usize;
                if family != layout.family
                    || round_count != layout.padded_entries().ilog2() as usize
                    || cursor.u16()? != 0
                {
                    return Err(C6HiddenUError::new("C6 hidden-u sumcheck family header mismatch"));
                }
                let terminal_u = cursor.fp2()?;
                let mut rounds = Vec::with_capacity(round_count);
                for _ in 0..round_count {
                    rounds.push([cursor.fp2()?, cursor.fp2()?, cursor.fp2()?]);
                }
                families.push(C6HiddenUSumcheckFamilyProof { family, rounds, terminal_u });
            }
            repetitions.push(C6HiddenUSumcheckRepetition { families });
        }
        let digest_offset = cursor.position();
        let encoded_digest = cursor.digest()?;
        if !cursor.is_eof() || proof_digest(&bytes[..digest_offset]) != encoded_digest {
            return Err(C6HiddenUError::new("noncanonical or trailing C6 hidden-u sumcheck bytes"));
        }
        let proof = Self { postcommit_digest, repetitions };
        proof.validate_shape(layouts)?;
        Ok(proof)
    }

    pub fn encoded_len(&self, layouts: &[C6HiddenULayout]) -> Result<u64> {
        u64::try_from(self.encode(layouts)?.len())
            .map_err(|_| C6HiddenUError::new("C6 hidden-u sumcheck length exceeds u64"))
    }

    fn validate_shape(&self, layouts: &[C6HiddenULayout]) -> Result<()> {
        validate_layouts(layouts)?;
        if self.postcommit_digest == [0; 32]
            || self.repetitions.len() != C6_HIDDEN_U_REPETITIONS as usize
        {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck proof shape mismatch"));
        }
        for repetition in &self.repetitions {
            if repetition.families.len() != layouts.len() {
                return Err(C6HiddenUError::new("C6 hidden-u sumcheck family count mismatch"));
            }
            for (family, layout) in repetition.families.iter().zip(layouts) {
                if family.family != layout.family
                    || family.rounds.len() != layout.padded_entries().ilog2() as usize
                {
                    return Err(C6HiddenUError::new(
                        "C6 hidden-u sumcheck round geometry mismatch",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn hidden_u_sumcheck_encoded_len(layouts: &[C6HiddenULayout]) -> Result<u64> {
    validate_layouts(layouts)?;
    let repetition_count = C6_HIDDEN_U_REPETITIONS;
    let family_count = u64::try_from(layouts.len())
        .map_err(|_| C6HiddenUError::new("C6 hidden-u sumcheck family count exceeds u64"))?;
    let round_count = layouts.iter().try_fold(0u64, |sum, layout| {
        sum.checked_add(u64::from(layout.padded_entries().ilog2()))
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u sumcheck round count overflows"))
    })?;
    // magic/version/repetitions/postcommit + repetition headers + family
    // headers/terminal claims + round polynomials + terminal digest.
    44u64
        .checked_add(
            repetition_count
                .checked_mul(4)
                .ok_or_else(|| C6HiddenUError::new("C6 hidden-u repetition headers overflow"))?,
        )
        .and_then(|bytes| {
            bytes.checked_add(repetition_count.checked_mul(family_count)?.checked_mul(20)?)
        })
        .and_then(|bytes| {
            bytes.checked_add(repetition_count.checked_mul(round_count)?.checked_mul(ROUND_BYTES)?)
        })
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u sumcheck encoded length overflows"))
}

/// One repetition of the hidden-`u` prover, exposed round-by-round so the
/// response-global wrapper coordinator can synchronize it with larger cache
/// and residual sumchecks.  A caller cannot form the next round before
/// binding the current challenge.
pub struct C6HiddenUProverRoundState {
    repetition: u8,
    max_rounds: usize,
    global_round: usize,
    pending_active: Vec<usize>,
    states: Vec<InnerProductProverState>,
}

impl C6HiddenUProverRoundState {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn round_count(&self) -> usize {
        self.max_rounds
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn is_complete(&self) -> bool {
        self.global_round == self.max_rounds && self.pending_active.is_empty()
    }

    /// Materialize and fix every active hidden-family message for the next
    /// local round.  The returned byte count is appended by the outer
    /// coordinator before it releases the shared challenge.
    pub fn fix_next_round(&mut self) -> Result<u64> {
        if !self.pending_active.is_empty() || self.global_round >= self.max_rounds {
            return Err(C6HiddenUError::new("invalid C6 hidden-u prover round transition"));
        }
        for (state_index, state) in self.states.iter_mut().enumerate() {
            let family_rounds = state.layout.padded_entries().ilog2() as usize;
            if self.global_round >= self.max_rounds - family_rounds {
                state.round_message()?;
                self.pending_active.push(state_index);
            }
        }
        round_message_bytes(self.pending_active.len())
    }

    pub fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if self.pending_active.is_empty() || self.global_round >= self.max_rounds {
            return Err(C6HiddenUError::new("invalid C6 hidden-u prover challenge transition"));
        }
        for state_index in self.pending_active.drain(..) {
            self.states[state_index].bind_round(challenge)?;
        }
        self.global_round += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<(C6HiddenUSumcheckRepetition, Vec<C6HiddenUOpeningClaim>)> {
        if !self.is_complete() {
            return Err(C6HiddenUError::new("incomplete C6 hidden-u prover repetition"));
        }
        let mut families = Vec::with_capacity(self.states.len());
        let mut claims = Vec::with_capacity(self.states.len());
        for state in self.states {
            let (family_proof, point) = state.finish()?;
            claims.push(C6HiddenUOpeningClaim {
                repetition: self.repetition,
                family: family_proof.family,
                point,
                value: family_proof.terminal_u,
            });
            families.push(family_proof);
        }
        Ok((C6HiddenUSumcheckRepetition { families }, claims))
    }
}

/// Prepare one honest-prover repetition without sampling any sumcheck
/// challenge.  Production calls this state from the 24-round wrapper
/// coordinator at the preregistered activation offset.
pub fn prepare_hidden_u_prover_round_state(
    sealed: &C6SealedHiddenUBundle,
    claimed_prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    repetition: u8,
) -> Result<C6HiddenUProverRoundState> {
    if usize::from(repetition) >= C6_HIDDEN_U_REPETITIONS as usize {
        return Err(C6HiddenUError::new("C6 hidden-u prover repetition out of range"));
    }
    let layouts = sealed.validate_prequery_binding(claimed_prequery)?;
    if postcommit.prequery_digest != claimed_prequery.digest() {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck prequery mismatch"));
    }
    postcommit.validate(&layouts)?;
    let q_cols =
        sealed.families().iter().map(|family| family.q_cols().to_vec()).collect::<Vec<_>>();
    let schedules = build_schedules(&layouts, claimed_prequery, postcommit, &q_cols)?;
    let repetition_index = usize::from(repetition);
    let mut states = Vec::with_capacity(layouts.len());
    for (((layout, family), schedule), family_q_cols) in
        layouts.iter().zip(sealed.families()).zip(&schedules).zip(&q_cols)
    {
        let functional =
            materialize_functional(*layout, schedule, repetition_index, family_q_cols)?;
        let witness = flatten_witness(*layout, family.vectors())?;
        states.push(InnerProductProverState::new(*layout, witness, functional)?);
    }
    let max_rounds = hidden_u_round_count(&layouts)?;
    Ok(C6HiddenUProverRoundState {
        repetition,
        max_rounds,
        global_round: 0,
        pending_active: Vec::with_capacity(states.len()),
        states,
    })
}

/// One verifier repetition with the same step-wise ownership discipline as
/// [`C6HiddenUProverRoundState`].
pub struct C6HiddenUVerifierRoundState<'a> {
    repetition: u8,
    layouts: &'a [C6HiddenULayout],
    q_cols: &'a [Vec<Vec<Fp2>>],
    family_proofs: &'a [C6HiddenUSumcheckFamilyProof],
    schedules: Vec<FamilySchedule>,
    current_claims: Vec<Fp2>,
    points: Vec<Vec<Fp2>>,
    max_rounds: usize,
    global_round: usize,
    pending_active: Vec<usize>,
}

impl C6HiddenUVerifierRoundState<'_> {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn round_count(&self) -> usize {
        self.max_rounds
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn is_complete(&self) -> bool {
        self.global_round == self.max_rounds && self.pending_active.is_empty()
    }

    /// Check every active message against the current claims before the
    /// outer coordinator samples the shared challenge.
    pub fn check_next_round(&mut self) -> Result<u64> {
        if !self.pending_active.is_empty() || self.global_round >= self.max_rounds {
            return Err(C6HiddenUError::new("invalid C6 hidden-u verifier round transition"));
        }
        for (family_index, (layout, family_proof)) in
            self.layouts.iter().zip(self.family_proofs).enumerate()
        {
            let family_rounds = layout.padded_entries().ilog2() as usize;
            let start = self.max_rounds - family_rounds;
            if self.global_round < start {
                continue;
            }
            let round = family_proof.rounds[self.global_round - start];
            if round[0] + round[1] != self.current_claims[family_index] {
                return Err(C6HiddenUError::new(
                    "C6 hidden-u sumcheck round does not sum to its claim",
                ));
            }
            self.pending_active.push(family_index);
        }
        round_message_bytes(self.pending_active.len())
    }

    pub fn bind_challenge(&mut self, challenge: Fp2) -> Result<()> {
        if self.pending_active.is_empty() || self.global_round >= self.max_rounds {
            return Err(C6HiddenUError::new("invalid C6 hidden-u verifier challenge transition"));
        }
        let weights = lagrange3(challenge);
        for family_index in self.pending_active.drain(..) {
            let family_rounds = self.layouts[family_index].padded_entries().ilog2() as usize;
            let start = self.max_rounds - family_rounds;
            let round = self.family_proofs[family_index].rounds[self.global_round - start];
            self.current_claims[family_index] =
                weights[0] * round[0] + weights[1] * round[1] + weights[2] * round[2];
            self.points[family_index].push(challenge);
        }
        self.global_round += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<C6HiddenUOpeningClaim>> {
        if !self.is_complete() {
            return Err(C6HiddenUError::new("incomplete C6 hidden-u verifier repetition"));
        }
        let repetition_index = usize::from(self.repetition);
        let mut claims = Vec::with_capacity(self.layouts.len());
        for (family_index, (((layout, family_proof), schedule), family_q_cols)) in self
            .layouts
            .iter()
            .zip(self.family_proofs)
            .zip(&self.schedules)
            .zip(self.q_cols)
            .enumerate()
        {
            let functional_at_point = evaluate_functional(
                *layout,
                schedule,
                repetition_index,
                family_q_cols,
                &self.points[family_index],
            )?;
            if self.current_claims[family_index] != family_proof.terminal_u * functional_at_point {
                return Err(C6HiddenUError::new("C6 hidden-u sumcheck terminal product mismatch"));
            }
            claims.push(C6HiddenUOpeningClaim {
                repetition: self.repetition,
                family: layout.family,
                point: self.points[family_index].clone(),
                value: family_proof.terminal_u,
            });
        }
        Ok(claims)
    }
}

pub fn prepare_hidden_u_verifier_round_state<'a>(
    layouts: &'a [C6HiddenULayout],
    q_cols: &'a [Vec<Vec<Fp2>>],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    proof: &'a C6HiddenUSumcheckProof,
    repetition: u8,
) -> Result<C6HiddenUVerifierRoundState<'a>> {
    let repetition_index = usize::from(repetition);
    if repetition_index >= C6_HIDDEN_U_REPETITIONS as usize {
        return Err(C6HiddenUError::new("C6 hidden-u verifier repetition out of range"));
    }
    validate_layouts(layouts)?;
    if postcommit.prequery_digest != prequery.digest() {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck prequery mismatch"));
    }
    postcommit.validate(layouts)?;
    let postcommit_digest = postcommit.digest(layouts)?;
    if proof.postcommit_digest != postcommit_digest {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck proof/postcommit mismatch"));
    }
    proof.validate_shape(layouts)?;
    let schedules = build_schedules(layouts, prequery, postcommit, q_cols)?;
    let family_proofs = &proof.repetitions[repetition_index].families;
    let current_claims =
        schedules.iter().map(|schedule| schedule.rhs[repetition_index]).collect::<Vec<_>>();
    let points = layouts
        .iter()
        .map(|layout| Vec::with_capacity(layout.padded_entries().ilog2() as usize))
        .collect::<Vec<_>>();
    let max_rounds = hidden_u_round_count(layouts)?;
    Ok(C6HiddenUVerifierRoundState {
        repetition,
        layouts,
        q_cols,
        family_proofs,
        schedules,
        current_claims,
        points,
        max_rounds,
        global_round: 0,
        pending_active: Vec::with_capacity(layouts.len()),
    })
}

/// Hidden-only convenience driver.  It is valid for isolated arithmetic
/// tests; production uses the step-wise state above inside the 24-round
/// response-global coordinator.
pub fn prove_hidden_u_sumchecks(
    sealed: &C6SealedHiddenUBundle,
    claimed_prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    tx: &mut Transcript,
) -> Result<(C6HiddenUSumcheckProof, Vec<C6HiddenUOpeningClaim>)> {
    let layouts = sealed.validate_prequery_binding(claimed_prequery)?;
    if postcommit.prequery_digest != claimed_prequery.digest() {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck prequery mismatch"));
    }
    postcommit.validate(&layouts)?;
    let postcommit_digest = postcommit.digest(&layouts)?;
    let mut repetitions = Vec::with_capacity(C6_HIDDEN_U_REPETITIONS as usize);
    let mut claims = Vec::with_capacity(layouts.len() * C6_HIDDEN_U_REPETITIONS as usize);
    for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
        let mut state =
            prepare_hidden_u_prover_round_state(sealed, claimed_prequery, postcommit, repetition)?;
        while !state.is_complete() {
            let bytes = state.fix_next_round()?;
            tx.append("c6_hidden_u_sumcheck_round", bytes);
            let challenge = tx.challenge_fp2();
            state.bind_challenge(challenge)?;
        }
        let (repetition_proof, repetition_claims) = state.finish()?;
        repetitions.push(repetition_proof);
        claims.extend(repetition_claims);
    }
    let proof = C6HiddenUSumcheckProof { postcommit_digest, repetitions };
    proof.validate_shape(&layouts)?;
    Ok((proof, claims))
}

/// Verifier-side hidden-only convenience driver.  Acceptance remains
/// insufficient until every returned value is bound by the packed PCS.
pub fn reduce_hidden_u_sumchecks(
    layouts: &[C6HiddenULayout],
    q_cols: &[Vec<Vec<Fp2>>],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    proof: &C6HiddenUSumcheckProof,
    tx: &mut Transcript,
) -> Result<Vec<C6HiddenUOpeningClaim>> {
    let mut claims = Vec::with_capacity(layouts.len() * C6_HIDDEN_U_REPETITIONS as usize);
    for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
        let mut state = prepare_hidden_u_verifier_round_state(
            layouts, q_cols, prequery, postcommit, proof, repetition,
        )?;
        while !state.is_complete() {
            let bytes = state.check_next_round()?;
            tx.append("c6_hidden_u_sumcheck_round", bytes);
            let challenge = tx.challenge_fp2();
            state.bind_challenge(challenge)?;
        }
        claims.extend(state.finish()?);
    }
    Ok(claims)
}

#[derive(Clone)]
struct FamilySchedule {
    query_indices: Vec<usize>,
    query_alphas: Vec<Vec<[Fp2; 2]>>,
    ip_alphas: Vec<[Fp2; 2]>,
    rhs: [Fp2; 2],
}

fn build_schedules(
    layouts: &[C6HiddenULayout],
    prequery: &C6HiddenUPrequery,
    postcommit: &C6HiddenUPostCommit,
    q_cols: &[Vec<Vec<Fp2>>],
) -> Result<Vec<FamilySchedule>> {
    if q_cols.len() != layouts.len() {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck q_col family mismatch"));
    }
    let mut streams = BATCH_STREAM_DOMAINS
        .map(|domain| FpStream::domain_separated(postcommit.batching_seed, domain));
    let mut schedules = Vec::with_capacity(layouts.len());
    for (family_index, ((layout, family_post), family_q_cols)) in
        layouts.iter().zip(&postcommit.families).zip(q_cols).enumerate()
    {
        if family_q_cols.len() != layout.claim_count
            || family_q_cols.iter().any(|q_col| q_col.len() != layout.cols())
        {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck q_col census mismatch"));
        }
        if hidden_u_functional_digest(*layout, family_q_cols)?
            != prequery
                .functional_digest(family_index)
                .ok_or_else(|| C6HiddenUError::new("missing hidden-u functional digest"))?
        {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck functional digest mismatch"));
        }
        let mut rhs = [Fp2::ZERO; 2];
        let mut query_indices = Vec::with_capacity(family_post.queries.len());
        let mut query_alphas = Vec::with_capacity(family_post.queries.len());
        for query in &family_post.queries {
            query_indices.push(query.index as usize);
            let mut row = Vec::with_capacity(layout.live_vectors());
            for relation_rhs in &query.rhs {
                let alphas = [streams[0].next_fp2(), streams[1].next_fp2()];
                for repetition in 0..2 {
                    rhs[repetition] += alphas[repetition] * *relation_rhs;
                }
                row.push(alphas);
            }
            query_alphas.push(row);
        }
        let public_ips = prequery
            .public_ips(family_index)
            .ok_or_else(|| C6HiddenUError::new("missing hidden-u public ips"))?;
        let mut ip_alphas = Vec::with_capacity(layout.claim_count);
        for public_ip in public_ips {
            let alphas = [streams[0].next_fp2(), streams[1].next_fp2()];
            for repetition in 0..2 {
                rhs[repetition] += alphas[repetition] * *public_ip;
            }
            ip_alphas.push(alphas);
        }
        schedules.push(FamilySchedule { query_indices, query_alphas, ip_alphas, rhs });
    }
    Ok(schedules)
}

fn flatten_witness(layout: C6HiddenULayout, vectors: &[Vec<Fp2>]) -> Result<Vec<Fp2>> {
    if vectors.len() != layout.live_vectors()
        || vectors.iter().any(|vector| vector.len() != layout.msg_len())
    {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck witness shape mismatch"));
    }
    let mut flattened = vec![Fp2::ZERO; layout.padded_entries()];
    for (source, destination) in vectors.iter().zip(flattened.chunks_mut(layout.vector_stride)) {
        destination[..layout.msg_len()].copy_from_slice(source);
    }
    Ok(flattened)
}

fn materialize_functional(
    layout: C6HiddenULayout,
    schedule: &FamilySchedule,
    repetition: usize,
    q_cols: &[Vec<Fp2>],
) -> Result<Vec<Fp2>> {
    if repetition >= 2 || q_cols.len() != layout.claim_count {
        return Err(C6HiddenUError::new("C6 hidden-u functional materialization shape"));
    }
    let plan = NttPlan::new(layout.code_len());
    let mut functional = vec![Fp2::ZERO; layout.padded_entries()];
    functional.par_chunks_mut(layout.vector_stride).enumerate().try_for_each(
        |(vector_index, row)| -> Result<()> {
            if vector_index >= layout.live_vectors() {
                return Ok(());
            }
            let mut sparse = vec![Fp2::ZERO; layout.code_len()];
            for (query_ordinal, &index) in schedule.query_indices.iter().enumerate() {
                sparse[index] += schedule.query_alphas[query_ordinal][vector_index][repetition];
            }
            let transformed = encode_fp2_ntt(&plan, &sparse);
            row[..layout.msg_len()].copy_from_slice(&transformed[..layout.msg_len()]);
            if vector_index > 0 {
                let alpha = schedule.ip_alphas[vector_index - 1][repetition];
                for (value, q) in row[..layout.cols()].iter_mut().zip(&q_cols[vector_index - 1]) {
                    *value += alpha * *q;
                }
            }
            Ok(())
        },
    )?;
    Ok(functional)
}

struct InnerProductProverState {
    layout: C6HiddenULayout,
    witness: Vec<Fp2>,
    functional: Vec<Fp2>,
    rounds: Vec<[Fp2; 3]>,
    point: Vec<Fp2>,
    pending_round: bool,
}

impl InnerProductProverState {
    fn new(layout: C6HiddenULayout, witness: Vec<Fp2>, functional: Vec<Fp2>) -> Result<Self> {
        if witness.len() != layout.padded_entries() || functional.len() != witness.len() {
            return Err(C6HiddenUError::new("C6 hidden-u sumcheck table geometry mismatch"));
        }
        let round_count = witness.len().ilog2() as usize;
        Ok(Self {
            layout,
            witness,
            functional,
            rounds: Vec::with_capacity(round_count),
            point: Vec::with_capacity(round_count),
            pending_round: false,
        })
    }

    fn round_message(&mut self) -> Result<()> {
        if self.pending_round || self.witness.len() < 2 {
            return Err(C6HiddenUError::new("invalid C6 hidden-u prover round state"));
        }
        let half = self.witness.len() / 2;
        let mut evaluations = [Fp2::ZERO; 3];
        for pair in 0..half {
            let u0 = self.witness[2 * pair];
            let u1 = self.witness[2 * pair + 1];
            let f0 = self.functional[2 * pair];
            let f1 = self.functional[2 * pair + 1];
            evaluations[0] += u0 * f0;
            evaluations[1] += u1 * f1;
            evaluations[2] += (u1 + u1 - u0) * (f1 + f1 - f0);
        }
        self.rounds.push(evaluations);
        self.pending_round = true;
        Ok(())
    }

    fn bind_round(&mut self, challenge: Fp2) -> Result<()> {
        if !self.pending_round || self.witness.len() < 2 {
            return Err(C6HiddenUError::new("invalid C6 hidden-u challenge state"));
        }
        let half = self.witness.len() / 2;
        for pair in 0..half {
            self.witness[pair] = self.witness[2 * pair]
                + challenge * (self.witness[2 * pair + 1] - self.witness[2 * pair]);
            self.functional[pair] = self.functional[2 * pair]
                + challenge * (self.functional[2 * pair + 1] - self.functional[2 * pair]);
        }
        self.witness.truncate(half);
        self.functional.truncate(half);
        self.point.push(challenge);
        self.pending_round = false;
        Ok(())
    }

    fn finish(self) -> Result<(C6HiddenUSumcheckFamilyProof, Vec<Fp2>)> {
        if self.pending_round
            || self.witness.len() != 1
            || self.functional.len() != 1
            || self.rounds.len() != self.layout.padded_entries().ilog2() as usize
        {
            return Err(C6HiddenUError::new("incomplete C6 hidden-u sumcheck state"));
        }
        Ok((
            C6HiddenUSumcheckFamilyProof {
                family: self.layout.family,
                rounds: self.rounds,
                terminal_u: self.witness[0],
            },
            self.point,
        ))
    }
}

fn hidden_u_round_count(layouts: &[C6HiddenULayout]) -> Result<usize> {
    layouts
        .iter()
        .map(|layout| layout.padded_entries().ilog2() as usize)
        .max()
        .ok_or_else(|| C6HiddenUError::new("empty C6 hidden-u sumcheck schedule"))
}

fn round_message_bytes(active_families: usize) -> Result<u64> {
    if active_families == 0 {
        return Err(C6HiddenUError::new("empty C6 hidden-u active round"));
    }
    ROUND_BYTES
        .checked_mul(
            u64::try_from(active_families)
                .map_err(|_| C6HiddenUError::new("C6 hidden-u active count exceeds u64"))?,
        )
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u round bytes overflow"))
}

fn evaluate_functional(
    layout: C6HiddenULayout,
    schedule: &FamilySchedule,
    repetition: usize,
    q_cols: &[Vec<Fp2>],
    point: &[Fp2],
) -> Result<Fp2> {
    let stride_bits = layout.vector_stride.ilog2() as usize;
    let vector_bits = layout.vector_capacity.ilog2() as usize;
    if repetition >= 2 || point.len() != stride_bits + vector_bits {
        return Err(C6HiddenUError::new("C6 hidden-u terminal point length mismatch"));
    }
    let (within, vector_point) = point.split_at(stride_bits);
    let omega = root_of_unity(layout.params.code_bits);
    let mut total = Fp2::ZERO;
    for vector_index in 0..layout.live_vectors() {
        let vector_weight = eq_index(vector_point, vector_index);
        let mut row = Fp2::ZERO;
        for (query_ordinal, query) in schedule.query_alphas.iter().enumerate() {
            let z = omega.pow(schedule.query_indices[query_ordinal] as u64);
            row += query[vector_index][repetition]
                * truncated_geometric_mle(z, layout.msg_len(), within)?;
        }
        if vector_index > 0 {
            let q_col = q_cols
                .get(vector_index - 1)
                .ok_or_else(|| C6HiddenUError::new("missing C6 hidden-u terminal q_col"))?;
            row += schedule.ip_alphas[vector_index - 1][repetition] * padded_mle(q_col, within)?;
        }
        total += vector_weight * row;
    }
    Ok(total)
}

fn truncated_geometric_mle(z: Fp, length: usize, point: &[Fp2]) -> Result<Fp2> {
    let capacity = 1usize
        .checked_shl(point.len() as u32)
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u geometric capacity overflow"))?;
    if length > capacity {
        return Err(C6HiddenUError::new("C6 hidden-u geometric interval exceeds capacity"));
    }
    let mut total = Fp2::ZERO;
    let mut start = 0usize;
    for bit in (0..point.len()).rev() {
        let block = 1usize << bit;
        if length & block == 0 {
            continue;
        }
        let mut contribution = Fp2::from_base(z.pow(start as u64));
        for (variable, coordinate) in point.iter().enumerate() {
            if variable < bit {
                contribution = contribution
                    * (Fp2::ONE - *coordinate + coordinate.mul_base(z.pow(1u64 << variable)));
            } else {
                contribution = contribution
                    * if (start >> variable) & 1 == 1 {
                        *coordinate
                    } else {
                        Fp2::ONE - *coordinate
                    };
            }
        }
        total += contribution;
        start += block;
    }
    Ok(total)
}

fn padded_mle(values: &[Fp2], point: &[Fp2]) -> Result<Fp2> {
    let capacity = 1usize
        .checked_shl(point.len() as u32)
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u padded MLE capacity overflow"))?;
    if values.is_empty() || !values.len().is_power_of_two() || values.len() > capacity {
        return Err(C6HiddenUError::new("C6 hidden-u padded MLE geometry mismatch"));
    }
    let live_bits = values.len().ilog2() as usize;
    let mut result = eval_mle(values, &point[..live_bits]);
    for coordinate in &point[live_bits..] {
        result = result * (Fp2::ONE - *coordinate);
    }
    Ok(result)
}

fn eq_index(point: &[Fp2], index: usize) -> Fp2 {
    point.iter().enumerate().fold(Fp2::ONE, |product, (bit, coordinate)| {
        product * if (index >> bit) & 1 == 1 { *coordinate } else { Fp2::ONE - *coordinate }
    })
}

fn validate_layouts(layouts: &[C6HiddenULayout]) -> Result<()> {
    if layouts.is_empty() || !layouts.windows(2).all(|pair| pair[0].family < pair[1].family) {
        return Err(C6HiddenUError::new("C6 hidden-u sumcheck layouts are empty or noncanonical"));
    }
    for layout in layouts {
        layout.validate()?;
    }
    Ok(())
}

fn proof_digest(prefix: &[u8]) -> C6HiddenUDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(PROOF_DOMAIN.len() as u64).to_le_bytes());
    hasher.update(PROOF_DOMAIN);
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    *hasher.finalize().as_bytes()
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

fn decode_family(value: u8) -> Result<C6HiddenUFamily> {
    match value {
        1 => Ok(C6HiddenUFamily::Weights),
        2 => Ok(C6HiddenUFamily::Embed),
        _ => Err(C6HiddenUError::new("unknown C6 hidden-u sumcheck family")),
    }
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
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u sumcheck decoder overflow"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6HiddenUError::new("truncated C6 hidden-u sumcheck proof"))?;
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn digest(&mut self) -> Result<C6HiddenUDigest> {
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
            return Err(C6HiddenUError::new("noncanonical C6 hidden-u sumcheck field element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c6_hidden_u::{
        C6HiddenUBundleWitness, C6HiddenUFamilyPostCommit, C6HiddenUFamilyWitness,
        C6HiddenUQueryClaim,
    };
    use crate::c6_wrapper_pcs::{
        fix_test_c6_wrapper_commitments, C6WrapperCohortSpec, C6WrapperCommitment,
        C6WrapperOracleKind, C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt,
        C6_CACHE_COHORT_ID, C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_COHORT_ID,
        C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_EMBED_COHORT_ID,
        C6_HIDDEN_U_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_WEIGHTS_COHORT_ID,
        C6_WRAPPER_AUXILIARY_COHORT_ID,
    };
    use crate::ligero::LigeroParams;

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 13 + 7))
    }

    fn layout(family: C6HiddenUFamily, claims: usize) -> C6HiddenULayout {
        let vector_capacity = if family == C6HiddenUFamily::Weights { 4 } else { 2 };
        C6HiddenULayout {
            family,
            params: LigeroParams { rows: 8, col_bits: 3, pad: 4, code_bits: 4, n_queries: 4 },
            claim_count: claims,
            vector_capacity,
            vector_stride: 16,
        }
    }

    fn family_witness(
        layout: C6HiddenULayout,
        seed: u64,
    ) -> (C6HiddenUFamilyWitness, Vec<Vec<Fp2>>) {
        let vectors = (0..layout.live_vectors())
            .map(|vector| {
                (0..layout.msg_len())
                    .map(|index| fp2(seed + 100 * vector as u64 + index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let q_cols = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.cols())
                    .map(|index| fp2(seed + 1_000 + 100 * claim as u64 + index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let witness = C6HiddenUFamilyWitness::new(
            layout,
            vectors[0].clone(),
            vectors[1..].to_vec(),
            q_cols.clone(),
        )
        .unwrap();
        (witness, q_cols)
    }

    fn postcommit(
        sealed: &C6SealedHiddenUBundle,
        layouts: &[C6HiddenULayout],
    ) -> C6HiddenUPostCommit {
        let families = layouts
            .iter()
            .zip(sealed.families())
            .map(|(layout, family)| {
                let plan = NttPlan::new(layout.code_len());
                let encoded = family
                    .vectors()
                    .iter()
                    .map(|vector| encode_fp2_ntt(&plan, vector))
                    .collect::<Vec<_>>();
                let queries = [0usize, 3, 7, 15]
                    .into_iter()
                    .map(|index| C6HiddenUQueryClaim {
                        index: index as u32,
                        rhs: encoded.iter().map(|vector| vector[index]).collect(),
                    })
                    .collect();
                C6HiddenUFamilyPostCommit { family: layout.family, queries }
            })
            .collect();
        C6HiddenUPostCommit {
            prequery_digest: sealed.prequery().digest(),
            batching_seed: [0x45; 32],
            families,
        }
    }

    fn fixture(
    ) -> (Vec<C6HiddenULayout>, Vec<Vec<Vec<Fp2>>>, C6SealedHiddenUBundle, C6HiddenUPostCommit)
    {
        let layouts = vec![layout(C6HiddenUFamily::Weights, 2), layout(C6HiddenUFamily::Embed, 1)];
        let (weights, weights_q) = family_witness(layouts[0], 11);
        let (embed, embed_q) = family_witness(layouts[1], 29);
        let sealed = C6HiddenUBundleWitness::new(vec![weights, embed])
            .unwrap()
            .seal(vec![[0x31; 32], [0x32; 32]], [0x33; 32])
            .unwrap();
        let postcommit = postcommit(&sealed, &layouts);
        (layouts, vec![weights_q, embed_q], sealed, postcommit)
    }

    #[test]
    fn interactive_sumchecks_reduce_to_exact_hidden_u_openings() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let seed = [0x51; 32];
        let mut prover_tx = Transcript::new(seed);
        let (proof, prover_claims) =
            prove_hidden_u_sumchecks(&sealed, sealed.prequery(), &postcommit, &mut prover_tx)
                .unwrap();
        let mut verifier_tx = Transcript::new(seed);
        let verifier_claims = reduce_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &proof,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(prover_claims, verifier_claims);
        assert_eq!(prover_tx.total_bytes(), 2 * (6 + 5) * ROUND_BYTES);
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());

        for claim in &verifier_claims {
            let family_index = usize::from(claim.family == C6HiddenUFamily::Embed);
            let flat =
                flatten_witness(layouts[family_index], sealed.families()[family_index].vectors())
                    .unwrap();
            assert_eq!(eval_mle(&flat, &claim.point), claim.value);
            let wrapper_point = claim.wrapper_point();
            assert_eq!(wrapper_point.last(), Some(&Fp2::ZERO));
        }
        for repetition in 0..2 {
            let weights = &verifier_claims[2 * repetition];
            let embed = &verifier_claims[2 * repetition + 1];
            assert_eq!(&weights.point[weights.point.len() - embed.point.len()..], embed.point);
            let weights_wrapper = weights.wrapper_point();
            let embed_wrapper = embed.wrapper_point();
            assert_eq!(
                &weights_wrapper[weights_wrapper.len() - embed_wrapper.len()..],
                embed_wrapper,
            );
        }
    }

    #[test]
    fn stepwise_state_joins_a_larger_round_coordinator_at_an_offset() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let seed = [0x5a; 32];
        let leading_rounds = 3usize;
        let wrapper_specs = [
            C6WrapperCohortSpec {
                cohort_id: C6_CACHE_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 9,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_DELTA_RESIDUAL_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 8,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_WEIGHTS_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 6,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_EMBED_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 5,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: 3,
                slot_count: 1,
            },
        ];
        let commitments = wrapper_specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                C6WrapperCommitment::from_root([0x5b; 32], spec, [(index + 1) as u8; 32]).unwrap()
            })
            .collect::<Vec<_>>();
        let mut prover_tx = Transcript::new(seed);
        let fixed =
            fix_test_c6_wrapper_commitments([0x5b; 32], &commitments, &mut prover_tx).unwrap();
        let mut repetitions = Vec::new();
        let mut prover_claims = Vec::new();
        let mut global_points = Vec::new();

        for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
            let mut state = prepare_hidden_u_prover_round_state(
                &sealed,
                sealed.prequery(),
                &postcommit,
                repetition,
            )
            .unwrap();
            assert!(state.bind_challenge(fp2(999)).is_err());
            let total_rounds = leading_rounds + state.round_count();
            let mut coordinator =
                C6WrapperRoundCoordinator::new_test(&fixed, repetition, total_rounds, 1, 3)
                    .unwrap();
            for global_round in 0..total_rounds {
                let ids = coordinator.expected_participant_ids().unwrap();
                let mut receipts = Vec::with_capacity(ids.len());
                for participant_id in &ids {
                    let message_bytes = match *participant_id {
                        C6_CACHE_ROUND_PARTICIPANT_ID | C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID => {
                            ROUND_BYTES
                        }
                        C6_HIDDEN_U_ROUND_PARTICIPANT_ID => {
                            let bytes = state.fix_next_round().unwrap();
                            if global_round == leading_rounds {
                                assert!(state.fix_next_round().is_err());
                            }
                            bytes
                        }
                        _ => panic!("unexpected scaled C6 participant"),
                    };
                    receipts.push(C6WrapperRoundMessageReceipt {
                        participant_id: *participant_id,
                        message_bytes,
                    });
                }
                let challenge = coordinator
                    .fix_messages_and_release_challenge(&receipts, &mut prover_tx)
                    .unwrap();
                if global_round >= leading_rounds {
                    state.bind_challenge(challenge).unwrap();
                }
                coordinator.confirm_participants_bound(&ids).unwrap();
            }
            let (repetition_proof, claims) = state.finish().unwrap();
            repetitions.push(repetition_proof);
            prover_claims.extend(claims);
            global_points.push(coordinator.finish().unwrap());
        }
        let proof = C6HiddenUSumcheckProof {
            postcommit_digest: postcommit.digest(&layouts).unwrap(),
            repetitions,
        };
        proof.validate_shape(&layouts).unwrap();

        let mut verifier_tx = Transcript::new(seed);
        let verifier_fixed =
            fix_test_c6_wrapper_commitments([0x5b; 32], &commitments, &mut verifier_tx).unwrap();
        let mut verifier_claims = Vec::new();
        for repetition in 0..C6_HIDDEN_U_REPETITIONS as u8 {
            let mut state = prepare_hidden_u_verifier_round_state(
                &layouts,
                &q_cols,
                sealed.prequery(),
                &postcommit,
                &proof,
                repetition,
            )
            .unwrap();
            let total_rounds = leading_rounds + state.round_count();
            let mut coordinator = C6WrapperRoundCoordinator::new_test(
                &verifier_fixed,
                repetition,
                total_rounds,
                1,
                3,
            )
            .unwrap();
            for global_round in 0..total_rounds {
                let ids = coordinator.expected_participant_ids().unwrap();
                let mut receipts = Vec::with_capacity(ids.len());
                for participant_id in &ids {
                    let message_bytes = match *participant_id {
                        C6_CACHE_ROUND_PARTICIPANT_ID | C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID => {
                            ROUND_BYTES
                        }
                        C6_HIDDEN_U_ROUND_PARTICIPANT_ID => {
                            let bytes = state.check_next_round().unwrap();
                            if global_round == leading_rounds {
                                assert!(state.check_next_round().is_err());
                            }
                            bytes
                        }
                        _ => panic!("unexpected scaled C6 participant"),
                    };
                    receipts.push(C6WrapperRoundMessageReceipt {
                        participant_id: *participant_id,
                        message_bytes,
                    });
                }
                let challenge = coordinator
                    .fix_messages_and_release_challenge(&receipts, &mut verifier_tx)
                    .unwrap();
                if global_round >= leading_rounds {
                    state.bind_challenge(challenge).unwrap();
                }
                coordinator.confirm_participants_bound(&ids).unwrap();
            }
            let verifier_point = coordinator.finish().unwrap();
            assert_eq!(verifier_point, global_points[usize::from(repetition)]);
            verifier_claims.extend(state.finish().unwrap());
        }
        assert_eq!(prover_claims, verifier_claims);
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());

        for repetition in 0..C6_HIDDEN_U_REPETITIONS as usize {
            for claim in &verifier_claims[2 * repetition..2 * repetition + 2] {
                let claim_point = claim.wrapper_point();
                let wrapper_point = global_points[repetition].common_point();
                assert_eq!(claim_point, wrapper_point[wrapper_point.len() - claim_point.len()..]);
            }
        }
    }

    #[test]
    fn codec_is_strict_and_sumcheck_tampering_rejects() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let seed = [0x52; 32];
        let mut prover_tx = Transcript::new(seed);
        let (proof, _) =
            prove_hidden_u_sumchecks(&sealed, sealed.prequery(), &postcommit, &mut prover_tx)
                .unwrap();
        let digest = postcommit.digest(&layouts).unwrap();
        let encoded = proof.encode(&layouts).unwrap();
        assert_eq!(encoded.len(), 1_220);
        assert_eq!(hidden_u_sumcheck_encoded_len(&layouts).unwrap(), encoded.len() as u64);
        assert_eq!(C6HiddenUSumcheckProof::decode(&layouts, digest, &encoded).unwrap(), proof);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6HiddenUSumcheckProof::decode(&layouts, digest, &trailing).is_err());
        let mut bad_version = encoded.clone();
        bad_version[8] = 2;
        assert!(C6HiddenUSumcheckProof::decode(&layouts, digest, &bad_version).is_err());
        let mut bad_field = encoded.clone();
        // Header 44 + repetition header 4 + family header 4: terminal c0.
        bad_field[52..60].copy_from_slice(&P.to_le_bytes());
        assert!(C6HiddenUSumcheckProof::decode(&layouts, digest, &bad_field).is_err());

        let mut bad_round = proof.clone();
        bad_round.repetitions[0].families[0].rounds[0][0] += Fp2::ONE;
        assert!(reduce_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &bad_round,
            &mut Transcript::new(seed),
        )
        .is_err());

        let mut bad_terminal = proof;
        bad_terminal.repetitions[1].families[1].terminal_u += Fp2::ONE;
        assert!(reduce_hidden_u_sumchecks(
            &layouts,
            &q_cols,
            sealed.prequery(),
            &postcommit,
            &bad_terminal,
            &mut Transcript::new(seed),
        )
        .is_err());
    }

    #[test]
    fn analytic_functional_evaluation_matches_materialized_table() {
        let (layouts, q_cols, sealed, postcommit) = fixture();
        let schedules = build_schedules(&layouts, sealed.prequery(), &postcommit, &q_cols).unwrap();
        for family_index in 0..layouts.len() {
            let point = (0..layouts[family_index].padded_entries().ilog2())
                .map(|index| fp2(71 + u64::from(index)))
                .collect::<Vec<_>>();
            for repetition in 0..2 {
                let materialized = materialize_functional(
                    layouts[family_index],
                    &schedules[family_index],
                    repetition,
                    &q_cols[family_index],
                )
                .unwrap();
                let direct = eval_mle(&materialized, &point);
                let analytic = evaluate_functional(
                    layouts[family_index],
                    &schedules[family_index],
                    repetition,
                    &q_cols[family_index],
                    &point,
                )
                .unwrap();
                assert_eq!(analytic, direct);
            }
        }
    }

    #[test]
    fn production_sumcheck_codec_is_four_thousand_four_bytes() {
        let layouts = [C6HiddenULayout::production_weights(), C6HiddenULayout::production_embed()];
        assert_eq!(hidden_u_sumcheck_encoded_len(&layouts).unwrap(), 4_004);
    }
}

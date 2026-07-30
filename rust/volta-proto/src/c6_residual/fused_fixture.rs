//! Diagnostic-only scaled fixture for cross-crate C6 fused differentials.
//!
//! This module is available only with `c6-trace`.  It deliberately
//! materializes the small reference relation and therefore carries no
//! production memory, timing, or response-removal credit.

use super::*;
use volta_mac::{
    begin_c6_prover_trace, begin_c6_runtime_instance_capture, compile_c6_operation_trace_for_role,
    finish_c6_prover_trace, record_c6_product_closure, record_c6_zero_roots,
    C6InstanceExtractionRole, C6TraceSourceManifest, CorrelationStream,
};

pub struct C6ResidualFusedScaledFixture {
    operation_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    runtime: C6RuntimeInstanceValues,
    linear: C6CompiledLinearResidual,
    relation: C6ResidualRelationChallenges,
    leaf: C6PairedResidualLeafWitness,
    closure: C6PairedResidualClosureWitness,
    auxiliary: C6PairedResidualAuxiliaryWitness,
    reference: C6ResidualRelationReferenceWitness,
    compilation: C6ResidualAtomicReferenceCompilation,
    semantic_compiler_digests: [C6ResidualDigest; C6_RESIDUAL_PROOF_REPETITIONS as usize],
}

impl C6ResidualFusedScaledFixture {
    pub fn operation_plan(&self) -> &C6InstalledOperationPlan {
        &self.operation_plan
    }

    pub fn extraction(&self) -> &C6DecodedInstanceExtractionPlan {
        &self.extraction
    }

    pub fn runtime(&self) -> &C6RuntimeInstanceValues {
        &self.runtime
    }

    pub fn linear(&self) -> &C6CompiledLinearResidual {
        &self.linear
    }

    pub fn relation(&self) -> &C6ResidualRelationChallenges {
        &self.relation
    }

    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        self.relation.manifest()
    }

    pub fn reference(&self) -> &C6ResidualRelationReferenceWitness {
        &self.reference
    }

    pub fn compilation(&self) -> &C6ResidualAtomicReferenceCompilation {
        &self.compilation
    }

    pub fn semantic_compiler_digest(
        &self,
        proof_repetition: u8,
    ) -> C6ResidualResult<C6ResidualDigest> {
        self.semantic_compiler_digests
            .get(usize::from(proof_repetition))
            .copied()
            .ok_or_else(|| C6ResidualError::new("C6 scaled fixture repetition is out of range"))
    }

    pub fn witness_view(&self) -> C6ResidualResult<C6ResidualFusedWitnessView<'_>> {
        C6ResidualFusedWitnessView::new(
            self.relation.manifest(),
            &self.leaf,
            &self.closure,
            &self.auxiliary,
        )
    }
}

struct ProgramFixture {
    builder: C6ResidualBuilder,
    witnesses: Vec<C6SourceWitness>,
    chi: Fp2,
}

fn fp2(value: u64) -> Fp2 {
    Fp2::from_base(Fp::new(value))
}

fn leaf(index: u32, domain: u64, kind: C6LeafKind) -> C6LeafId {
    C6LeafId { schedule_index: index, stage: 1, domain, offset: 0, kind }
}

fn source_full(r: u64, x: u64, tag: u64) -> C6SourceWitness {
    C6SourceWitness::FullField { r: fp2(r), correction: fp2(x) - fp2(r), tag: fp2(tag) }
}

fn program_fixture(tag_delta: Fp2) -> C6ResidualResult<ProgramFixture> {
    let mut builder = C6ResidualBuilder::new();
    let a_witness = match source_full(1, 3, 19) {
        C6SourceWitness::FullField { r, correction, tag } => {
            C6SourceWitness::FullField { r, correction, tag: tag + tag_delta }
        }
        C6SourceWitness::Subfield { .. } => unreachable!("fixture source is full-field"),
    };
    let b_witness = source_full(2, 4, 23);
    let c_witness = source_full(5, 12, 29);
    let mask_witness =
        C6SourceWitness::FullField { r: fp2(7), correction: Fp2::ZERO, tag: fp2(31) };
    let witnesses = vec![a_witness, b_witness, c_witness, mask_witness];

    let a =
        builder.add_source(leaf(0, 0x100, C6LeafKind::FullField), C6LeafRole::Direct, a_witness)?;
    let b =
        builder.add_source(leaf(1, 0x200, C6LeafKind::FullField), C6LeafRole::Direct, b_witness)?;
    let c =
        builder.add_source(leaf(2, 0x300, C6LeafKind::FullField), C6LeafRole::Direct, c_witness)?;
    let mask = builder.add_source(
        leaf(3, 0x400, C6LeafKind::FullField),
        C6LeafRole::ProductMask,
        mask_witness,
    )?;

    let seven = builder.add_public(fp2(7))?;
    let sum = builder.add(a, b)?;
    let zero = builder.sub(sum, seven)?;
    builder.add_zero_closure(zero)?;
    let six = builder.add_public(fp2(6))?;
    let twice_a = builder.scale(a, fp2(2))?;
    let scaled_zero = builder.sub(twice_a, six)?;
    builder.add_zero_closure(scaled_zero)?;
    builder.add_product_closure(vec![[a, b, c], [b, a, c]], mask)?;
    Ok(ProgramFixture { builder, witnesses, chi: fp2(37) })
}

fn installed_fixture(
    witnesses: &[C6SourceWitness],
) -> C6ResidualResult<(
    C6InstalledOperationPlan,
    C6DecodedInstanceExtractionPlan,
    C6RuntimeInstanceValues,
)> {
    begin_c6_prover_trace().map_err(trace_error)?;
    let mut correlations = CorrelationStream::new([0xC6; 32]);
    correlations.enable_c6_operation_trace().map_err(trace_error)?;
    let direct = correlations.draw_fulls(0x100, 3);
    let mask = correlations.draw_product_mask(0x200, 2);
    let a = direct[0].authenticate(fp2(3));
    let b = direct[1].authenticate(fp2(4));
    let c = direct[2].authenticate(fp2(12));
    let seven = ProverAuthed::from_public(fp2(7));
    let zero = a.add(b).sub(seven);
    let six = ProverAuthed::from_public(fp2(6));
    let scaled_zero = a.scale(fp2(2)).sub(six);
    record_c6_zero_roots(&[zero.c6_trace_token(), scaled_zero.c6_trace_token()])
        .map_err(trace_error)?;
    record_c6_product_closure(
        &[
            [a.c6_trace_token(), b.c6_trace_token(), c.c6_trace_token()],
            [b.c6_trace_token(), a.c6_trace_token(), c.c6_trace_token()],
        ],
        mask.c6_trace_token(),
    )
    .map_err(trace_error)?;
    let snapshot = finish_c6_prover_trace().map_err(trace_error)?;
    let source_manifest =
        C6TraceSourceManifest::new(4, [0x5A; 32], vec![3]).map_err(trace_error)?;
    let compiled = compile_c6_operation_trace_for_role(
        &snapshot,
        &source_manifest,
        C6InstanceExtractionRole::Prover,
    )
    .map_err(trace_error)?;
    let extraction =
        compiled.instance_extraction.decode(compiled.plan.topology).map_err(trace_error)?;
    let installed = compiled.artifact.install(&source_manifest).map_err(trace_error)?;

    let capture = begin_c6_runtime_instance_capture(&extraction).map_err(trace_error)?;
    let a = witnesses
        .first()
        .ok_or_else(|| C6ResidualError::new("C6 scaled fixture lacks source a"))?
        .prover_value();
    let b = witnesses
        .get(1)
        .ok_or_else(|| C6ResidualError::new("C6 scaled fixture lacks source b"))?
        .prover_value();
    let seven = ProverAuthed::from_public(fp2(7));
    let _zero = a.add(b).sub(seven);
    let six = ProverAuthed::from_public(fp2(6));
    let _scaled_zero = a.scale(fp2(2)).sub(six);
    let runtime = capture.finish_installed(&installed, &extraction).map_err(trace_error)?;
    Ok((installed, extraction, runtime))
}

fn paired_leaf_witness_from_programs(
    primary: &C6CommittedResidualProgram,
    secondary: &C6CommittedResidualProgram,
    source_schedule_digest: C6ResidualDigest,
) -> C6ResidualResult<C6PairedResidualLeafWitness> {
    if primary.sources.len() != secondary.sources.len() {
        return Err(C6ResidualError::new("C6 scaled fixture coordinate source counts differ"));
    }
    let mut columns: [Vec<Fp2>; C6_RESIDUAL_LEAF_ALIGNED_SLOTS as usize] =
        std::array::from_fn(|_| Vec::with_capacity(primary.sources.len()));
    let mut product_mask_count = 0u32;
    for (left, right) in primary.sources.iter().zip(&secondary.sources) {
        if left.id != right.id || left.role != right.role {
            return Err(C6ResidualError::new(
                "C6 scaled fixture coordinate source schedules differ",
            ));
        }
        let is_mask = left.role == C6LeafRole::ProductMask;
        if is_mask {
            product_mask_count = product_mask_count
                .checked_add(1)
                .ok_or_else(|| C6ResidualError::new("C6 scaled mask census overflows"))?;
            if left.witness.correction() != Fp2::ZERO || right.witness.correction() != Fp2::ZERO {
                return Err(C6ResidualError::new("C6 scaled product mask has a correction"));
            }
        }
        let common = if is_mask {
            Fp2::ZERO
        } else {
            let left_x = left.witness.base_plaintext() + left.witness.correction();
            let right_x = right.witness.base_plaintext() + right.witness.correction();
            if left_x != right_x {
                return Err(C6ResidualError::new(
                    "C6 scaled coordinates authenticate different plaintexts",
                ));
            }
            left_x
        };
        let row = [
            common,
            left.witness.base_plaintext(),
            left.witness.tag(),
            left.witness.correction(),
            right.witness.base_plaintext(),
            right.witness.tag(),
            right.witness.correction(),
        ];
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(value);
        }
    }
    Ok(C6PairedResidualLeafWitness {
        source_schedule_digest,
        paired_source_digest: [0xA1; 32],
        source_count: u32::try_from(primary.sources.len())
            .map_err(|_| C6ResidualError::new("C6 scaled source count exceeds u32"))?,
        product_mask_count,
        columns,
        witness_digest: [0xA2; 32],
    })
}

fn build_relation(
    installed: &C6InstalledOperationPlan,
    extraction: &C6DecodedInstanceExtractionPlan,
    runtime: &C6RuntimeInstanceValues,
    manifest: C6ResidualRelationManifest,
    reference: &C6ResidualRelationReferenceWitness,
    chi: Fp2,
) -> C6ResidualResult<(C6CompiledLinearResidual, C6ResidualRelationChallenges)> {
    let retained = C6ResidualRetainedChallenges::new(&manifest, vec![chi], fp2(79))?;
    let zero_weights = retained.zero_weights(installed.zero_roots().len());
    let linear = C6CompiledLinearResidual::compile(installed, extraction, runtime, &zero_weights)?;
    let root = C6ResidualRelationRootBound::bind_fixed_roots(manifest, [0xD1; 32], [0xD2; 32])?;
    let base = root.release_base_share_seed(retained, [0xD3; 32])?;

    let mut alphas: [Vec<Fp2>; 2] =
        std::array::from_fn(|_| Vec::with_capacity(linear.source_count()));
    for coordinate in 0..2u8 {
        let mut stream = base.alpha_stream(coordinate)?;
        for _ in 0..linear.source_count() {
            alphas[usize::from(coordinate)].push(stream.next_fp2());
        }
    }
    let mut residuals =
        [C6DeltaResidual { correction_rlc: Fp2::ZERO, public_tag_rlc: Fp2::ZERO }; 2];
    for (coordinate, (coordinate_alphas, residual)) in alphas.iter().zip(&mut residuals).enumerate()
    {
        let (r_table, m_table, d_table) = if coordinate == 0 { (1, 2, 3) } else { (4, 5, 6) };
        let mut correction = linear.public_plaintext();
        let mut message = Fp2::ZERO;
        for (source, &alpha) in coordinate_alphas.iter().enumerate() {
            correction +=
                linear.leaf_coefficients()[source] * reference.leaf_tables[d_table][source];
            correction = correction - alpha * reference.leaf_tables[r_table][source];
            message += (linear.leaf_coefficients()[source] + alpha)
                * reference.leaf_tables[m_table][source];
        }
        *residual = C6DeltaResidual { correction_rlc: correction, public_tag_rlc: message };
    }

    let mut product_claims = Vec::with_capacity(installed.products().len());
    let mut triple_cursor = 0usize;
    for (closure_index, product) in installed.products().iter().enumerate() {
        let mask_source = usize::try_from(
            *base
                .manifest()
                .product_mask_sources()
                .get(closure_index)
                .ok_or_else(|| C6ResidualError::new("C6 scaled product mask is missing"))?,
        )
        .map_err(|_| C6ResidualError::new("C6 scaled product mask index exceeds usize"))?;
        let mut messages = [[Fp2::ZERO; 2]; 2];
        for (coordinate, message) in messages.iter_mut().enumerate() {
            let lane = 6 * coordinate;
            let r_table = if coordinate == 0 { 1 } else { 4 };
            let m_table = if coordinate == 0 { 2 } else { 5 };
            let mut q = Fp2::ZERO;
            let mut m0 = reference.leaf_tables[m_table][mask_source];
            let mut m1 = reference.leaf_tables[r_table][mask_source];
            let mut power = Fp2::ONE;
            for triple in 0..product.triples().len() {
                power = power * chi;
                let row = triple_cursor + triple;
                q += power
                    * (reference.auxiliary_tables[lane][row]
                        * reference.auxiliary_tables[lane + 2][row]
                        - reference.auxiliary_tables[lane + 4][row]);
                m0 += power
                    * reference.auxiliary_tables[lane + 1][row]
                    * reference.auxiliary_tables[lane + 3][row];
                m1 += power
                    * (reference.auxiliary_tables[lane][row]
                        * reference.auxiliary_tables[lane + 3][row]
                        + reference.auxiliary_tables[lane + 1][row]
                            * reference.auxiliary_tables[lane + 2][row]
                        - reference.auxiliary_tables[lane + 5][row]);
            }
            if q != Fp2::ZERO {
                return Err(C6ResidualError::new(
                    "C6 scaled fixture ProductClosure witness is false",
                ));
            }
            *message = [m0, m1];
        }
        triple_cursor = triple_cursor
            .checked_add(product.triples().len())
            .ok_or_else(|| C6ResidualError::new("C6 scaled triple cursor overflows"))?;
        product_claims.push(C6ResidualProductPublicClaim { messages });
    }
    if triple_cursor
        != usize::try_from(base.manifest().topology.product_triple_count)
            .map_err(|_| C6ResidualError::new("C6 scaled triple count exceeds usize"))?
    {
        return Err(C6ResidualError::new(
            "C6 scaled fixture product triple census differs from its manifest",
        ));
    }
    let relation = base
        .commit_public_claims(
            linear.linear_form_digest(),
            product_claims,
            C6PairedDeltaResidual { coordinates: residuals },
        )?
        .release_relation_seed(installed, [0xD4; 32])?;
    Ok((linear, relation))
}

pub fn build_c6_residual_fused_scaled_fixture() -> C6ResidualResult<C6ResidualFusedScaledFixture> {
    let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK
        .lock()
        .map_err(|_| C6ResidualError::new("C6 scaled fixture lock is poisoned"))?;

    let primary_fixture = program_fixture(Fp2::ZERO)?;
    let installed_witnesses = primary_fixture.witnesses.clone();
    let chi = primary_fixture.chi;
    let primary_census = primary_fixture.builder.census()?;
    let primary = primary_fixture.builder.commit([0xC1; 32], primary_census)?;
    let secondary_fixture = program_fixture(fp2(1))?;
    let secondary_census = secondary_fixture.builder.census()?;
    let secondary = secondary_fixture.builder.commit([0xC2; 32], secondary_census)?;
    let leaf = paired_leaf_witness_from_programs(&primary, &secondary, [0x5A; 32])?;
    let closure = primary.build_paired_closure_witness(&secondary)?;
    let auxiliary = closure.transpose_auxiliary_lanes()?;

    let (operation_plan, extraction, runtime) = installed_fixture(&installed_witnesses)?;
    let manifest = C6ResidualRelationManifest::new_with_geometry(
        &operation_plan,
        &extraction,
        &runtime,
        7,
        2,
        false,
    )?;
    let reference =
        C6ResidualRelationReferenceWitness::from_live(&manifest, &leaf, &closure, &auxiliary)?;
    let (linear, relation) =
        build_relation(&operation_plan, &extraction, &runtime, manifest, &reference, chi)?;
    let compilation = compile_c6_residual_atomic_relation_reference(
        &operation_plan,
        &extraction,
        &runtime,
        &linear,
        &relation,
        &reference,
    )?;
    if !compilation.is_satisfied() {
        return Err(C6ResidualError::new(
            "C6 scaled fused fixture reference relation is not satisfied",
        ));
    }
    let mut semantic_compiler_digests = [[0; 32]; C6_RESIDUAL_PROOF_REPETITIONS as usize];
    for proof_repetition in 0..C6_RESIDUAL_PROOF_REPETITIONS {
        let mut audit = C6ResidualAtomicEventAuditSink::new(proof_repetition);
        let summary = replay_c6_residual_atomic_events(
            &operation_plan,
            &extraction,
            &runtime,
            &linear,
            &relation,
            proof_repetition,
            &mut audit,
        )?;
        semantic_compiler_digests[usize::from(proof_repetition)] = summary.semantic_digest();
    }
    Ok(C6ResidualFusedScaledFixture {
        operation_plan,
        extraction,
        runtime,
        linear,
        relation,
        leaf,
        closure,
        auxiliary,
        reference,
        compilation,
        semantic_compiler_digests,
    })
}

fn trace_error(error: impl fmt::Display) -> C6ResidualError {
    C6ResidualError::new(error.to_string())
}

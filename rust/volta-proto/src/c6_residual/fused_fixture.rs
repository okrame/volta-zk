//! Diagnostic-only scaled fixture for cross-crate C6 fused differentials.
//!
//! This module is available only with `c6-trace`.  It deliberately
//! materializes the small reference relation and therefore carries no
//! production memory, timing, or response-removal credit.

use super::*;
use crate::c6_source::{replay_c6_source_coordinate, C6SourceCoordinate};
use volta_mac::{
    begin_c6_prover_trace, compile_c6_operation_trace_for_role,
    derive_c6_runtime_instance_from_trace_diagnostic, finish_c6_prover_trace,
    record_c6_product_closure, record_c6_zero_roots, C6InstanceExtractionRole,
    C6TraceSourceManifest, CorrelationStream,
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
    closure_memory_census: C6InstalledClosureEvaluationMemoryCensus,
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

    pub fn closure_memory_census(&self) -> C6InstalledClosureEvaluationMemoryCensus {
        self.closure_memory_census
    }

    pub fn uses_installed_terminal_witness(&self) -> bool {
        self.closure.installed_binding.is_some()
    }
}

fn fp2(value: u64) -> Fp2 {
    Fp2::from_base(Fp::new(value))
}

fn installed_fixture() -> C6ResidualResult<(
    C6InstalledOperationPlan,
    C6DecodedInstanceExtractionPlan,
    C6RuntimeInstanceValues,
    CorrScheduleAudit,
    C6PairedSourceWitness,
)> {
    let source_schedule_digest = [0x5A; 32];

    let mut primary_stream = CorrelationStream::new([0xB0; 32]);
    primary_stream.enable_c6_source_witness_collection().map_err(trace_error)?;
    let sub = primary_stream.draw_subs(0x90, 1);
    primary_stream
        .record_c6_subfield_corrections(0x90, &[(Fp::new(9) - sub[0].r).value()])
        .map_err(trace_error)?;
    let _direct = primary_stream.draw_fulls(0x100, 3);
    primary_stream
        .record_c6_fullfield_plaintexts(0x100, &[fp2(3), fp2(4), fp2(12)])
        .map_err(trace_error)?;
    let _mask = primary_stream.draw_product_mask(0x200, 2);
    let schedule = primary_stream
        .schedule_audit()
        .ok_or_else(|| C6ResidualError::new("C6 scaled fixture omitted its source schedule"))?;
    let primary = C6SourceCoordinate::new(
        primary_stream.finish_c6_subfield_witness_collection().map_err(trace_error)?,
        primary_stream.finish_c6_fullfield_witness_collection().map_err(trace_error)?,
        &schedule,
    )
    .map_err(trace_error)?;
    let mut secondary_stream = CorrelationStream::new([0xB1; 32]);
    let secondary = replay_c6_source_coordinate(&primary, &schedule, &mut secondary_stream)
        .map_err(trace_error)?;
    let paired = C6PairedSourceWitness::new(
        [[0xE0; 32], [0xE1; 32]],
        [primary, secondary],
        &schedule,
        source_schedule_digest,
    )
    .map_err(trace_error)?;

    begin_c6_prover_trace().map_err(trace_error)?;
    let mut correlations = CorrelationStream::new([0xC6; 32]);
    correlations.enable_c6_operation_trace().map_err(trace_error)?;
    let sub = correlations.draw_subs(0x90, 1)[0].authenticate(Fp::new(9)).embed();
    let direct = correlations.draw_fulls(0x100, 3);
    let mask = correlations.draw_product_mask(0x200, 2);
    let a = direct[0].authenticate(fp2(3));
    let b = direct[1].authenticate(fp2(4));
    let c = direct[2].authenticate(fp2(12));
    let seven = ProverAuthed::from_public(fp2(7));
    let zero = a.add(b).sub(seven);
    let six = ProverAuthed::from_public(fp2(6));
    let scaled_zero = a.scale(fp2(2)).sub(six);
    let nine = ProverAuthed::from_public(fp2(9));
    let sub_zero = sub.sub(nine);
    record_c6_zero_roots(&[
        zero.c6_trace_token(),
        scaled_zero.c6_trace_token(),
        sub_zero.c6_trace_token(),
    ])
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
        C6TraceSourceManifest::new(5, source_schedule_digest, vec![4]).map_err(trace_error)?;
    let compiled = compile_c6_operation_trace_for_role(
        &snapshot,
        &source_manifest,
        C6InstanceExtractionRole::Prover,
    )
    .map_err(trace_error)?;
    let extraction =
        compiled.instance_extraction.decode(compiled.plan.topology).map_err(trace_error)?;
    let runtime = derive_c6_runtime_instance_from_trace_diagnostic(
        &snapshot,
        &compiled.artifact,
        &extraction,
        compiled.plan.instance,
    )
    .map_err(trace_error)?;
    let installed = compiled.artifact.install(&source_manifest).map_err(trace_error)?;
    Ok((installed, extraction, runtime, schedule, paired))
}

fn build_relation(
    installed: &C6InstalledOperationPlan,
    linear: &C6CompiledLinearResidual,
    manifest: C6ResidualRelationManifest,
    leaf: &C6PairedResidualLeafWitness,
    auxiliary: &C6PairedResidualAuxiliaryWitness,
    reference: &C6ResidualRelationReferenceWitness,
    chi: Fp2,
) -> C6ResidualResult<C6ResidualRelationChallenges> {
    let retained = C6ResidualRetainedChallenges::new(&manifest, vec![chi], fp2(79))?;
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
    let live_relation = base
        .clone()
        .commit_public_claims_from_live(installed, linear, leaf, auxiliary)?
        .release_relation_seed(installed, [0xD4; 32])?;
    let relation = base
        .commit_public_claims(
            linear.linear_form_digest(),
            product_claims,
            C6PairedDeltaResidual { coordinates: residuals },
        )?
        .release_relation_seed(installed, [0xD4; 32])?;
    if live_relation != relation {
        return Err(C6ResidualError::new(
            "C6 live public-claim compiler differs from the materialized oracle",
        ));
    }
    Ok(relation)
}

fn build_direct_relation(
    installed: &C6InstalledOperationPlan,
    linear: &C6CompiledLinearResidual,
    manifest: C6ResidualRelationManifest,
    leaf: &C6PairedResidualLeafWitness,
    auxiliary: &C6PairedResidualAuxiliaryWitness,
    chi: Fp2,
) -> C6ResidualResult<C6ResidualRelationChallenges> {
    let dimensions = C6ResidualDirectEqualityPoints::dimensions(&manifest)?;
    let point = |base: u64, stream: usize, dimension: usize| {
        (0..dimension)
            .map(|coordinate| fp2(base + 31 * stream as u64 + coordinate as u64))
            .collect::<Vec<_>>()
    };
    let alpha = std::array::from_fn(|stream| point(0x401, stream, dimensions.alpha));
    let terminal = std::array::from_fn(|stream| point(0x501, stream, dimensions.terminal));
    let atomic = std::array::from_fn(|stream| point(0x601, stream, dimensions.atomic));
    let alpha = C6ResidualDirectAlphaPoints::new(&manifest, alpha)?;
    let postclaim = C6ResidualDirectPostClaimPoints::new(&manifest, terminal, atomic)?;
    let retained = C6ResidualRetainedChallenges::new(&manifest, vec![chi], fp2(79))?;
    let root = C6ResidualRelationRootBound::bind_fixed_roots(manifest, [0xD1; 32], [0xD2; 32])?;
    root.release_direct_alpha_points(retained, alpha)?
        .commit_public_claims_from_live(installed, linear, leaf, auxiliary)?
        .release_direct_postclaim_points(installed, postclaim)
}

#[derive(Clone, Copy)]
enum ScaledRelationSchedule {
    LegacyV3,
    DirectV4,
}

fn build_scaled_fixture(
    schedule: ScaledRelationSchedule,
) -> C6ResidualResult<C6ResidualFusedScaledFixture> {
    let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK
        .lock()
        .map_err(|_| C6ResidualError::new("C6 scaled fixture lock is poisoned"))?;

    let chi = fp2(37);
    let (operation_plan, extraction, runtime, source_schedule, paired_sources) =
        installed_fixture()?;
    let manifest = C6ResidualRelationManifest::new_with_geometry(
        &operation_plan,
        &extraction,
        &runtime,
        7,
        2,
        false,
    )?;
    let retained = C6ResidualRetainedChallenges::new(&manifest, vec![chi], fp2(79))?;
    let zero_weights = retained.zero_weights(operation_plan.zero_roots().len());
    let linear =
        C6CompiledLinearResidual::compile(&operation_plan, &extraction, &runtime, &zero_weights)?;
    let leaf = linear.build_paired_residual_leaf_witness(&paired_sources, &source_schedule)?;
    let closure_evaluation = linear.evaluate_installed_paired_closure(
        &operation_plan,
        &extraction,
        &runtime,
        &paired_sources,
        &source_schedule,
    )?;
    let closure_memory_census = closure_evaluation.memory_census();
    let closure = closure_evaluation.into_closure();
    let auxiliary = closure.transpose_auxiliary_lanes()?;
    let reference =
        C6ResidualRelationReferenceWitness::from_live(&manifest, &leaf, &closure, &auxiliary)?;
    let relation = match schedule {
        ScaledRelationSchedule::LegacyV3 => {
            build_relation(&operation_plan, &linear, manifest, &leaf, &auxiliary, &reference, chi)?
        }
        ScaledRelationSchedule::DirectV4 => {
            build_direct_relation(&operation_plan, &linear, manifest, &leaf, &auxiliary, chi)?
        }
    };
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
        closure_memory_census,
        reference,
        compilation,
        semantic_compiler_digests,
    })
}

pub fn build_c6_residual_fused_scaled_fixture() -> C6ResidualResult<C6ResidualFusedScaledFixture> {
    build_scaled_fixture(ScaledRelationSchedule::LegacyV3)
}

pub fn build_c6_residual_direct_fused_scaled_fixture(
) -> C6ResidualResult<C6ResidualFusedScaledFixture> {
    build_scaled_fixture(ScaledRelationSchedule::DirectV4)
}

fn trace_error(error: impl fmt::Display) -> C6ResidualError {
    C6ResidualError::new(error.to_string())
}

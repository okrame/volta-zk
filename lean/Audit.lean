import VoltaZk

/-!
Machine-readable named-assumption audit for the M1–M10 boundary.

Run with `lake env lean Audit.lean`. None of the four declarations in
`VoltaZk.Ideal` should appear below; M9 carries `BindsIntoMac` as an explicit
theorem hypothesis rather than importing the global PCS placeholder.

The first block is the generic M1--M9 boundary. The second block audits the
scalar-power soundness theorems that match Rust's concrete
`chi^(j+1)` batching format; keeping both blocks prevents the stronger generic
vector-RLC bounds from being mistaken for implementation bounds.
-/

#print axioms VoltaZk.bsc_zeroBatch_perfect_zk
#print axioms VoltaZk.blind_sumcheck_sound
#print axioms VoltaZk.authenticated_cache_sound
#print axioms VoltaZk.sub_zeroOpen_sound
#print axioms VoltaZk.sequential_composition_perfect_zk
#print axioms VoltaZk.prod_perfect_sim
#print axioms VoltaZk.prodBatch_sound
#print axioms VoltaZk.PCSOpening.opening_mac_sound

-- Concrete Rust scalar-power batching map.
#print axioms VoltaZk.card_scalarRlc_zero_le
#print axioms VoltaZk.zeroBatch_sound_scalar
#print axioms VoltaZk.prodBatch_sound_scalar
#print axioms VoltaZk.blind_sumcheck_sound_scalar
#print axioms VoltaZk.kv_cache_sound_scalar
#print axioms VoltaZk.authenticated_cache_sound_scalar

-- P7 shared-round outer scalar batch: K fixed claims, one common r.
#print axioms VoltaZk.outer_scalar_batch_blind_sumcheck_sound
#print axioms VoltaZk.scalar_batch_blind_sumcheck_sound

-- Fase-D M10: one Delta across domain-separated responses.
#print axioms VoltaZk.response_domains_noncolliding
#print axioms VoltaZk.connection_response_sound_scalar
#print axioms VoltaZk.response_bad_card_le
#print axioms VoltaZk.connection_soundness_union_bound
#print axioms VoltaZk.connection_m4_soundness_union_bound
#print axioms VoltaZk.connection_m4_tape_card
#print axioms VoltaZk.connection_corrections_uniform
#print axioms VoltaZk.connection_responses_perfect_zk

-- T1 M11: late-point eq reduction and concrete full-vector aux leaf.
#print axioms VoltaZk.vec2_zero
#print axioms VoltaZk.vec2_one
#print axioms VoltaZk.vec3_zero
#print axioms VoltaZk.vec3_one
#print axioms VoltaZk.vec3_two
#print axioms VoltaZk.vec4_zero
#print axioms VoltaZk.vec4_one
#print axioms VoltaZk.vec4_two
#print axioms VoltaZk.vec4_three
#print axioms VoltaZk.compressedRoundPoly_natDegree_le
#print axioms VoltaZk.quadraticCoeffs_zero
#print axioms VoltaZk.quadraticCoeffs_one
#print axioms VoltaZk.cubicCoeffs_zero
#print axioms VoltaZk.cubicCoeffs_one
#print axioms VoltaZk.compressedRoundPoly_eval_zero
#print axioms VoltaZk.compressedRoundPoly_eval_one
#print axioms VoltaZk.compressedRoundPoly_sum01
#print axioms VoltaZk.quadraticCoeffs_two
#print axioms VoltaZk.cubicCoeffs_two_three
#print axioms VoltaZk.evalAuthedCoeffs_valid
#print axioms VoltaZk.evalAuthedCoeffs_x
#print axioms VoltaZk.evalAuthedCoeffs_m
#print axioms VoltaZk.evalAuthedCoeffs_k
#print axioms VoltaZk.evalAuthedCoeffs_k_poly
#print axioms VoltaZk.quadraticAuthedCoeffs_valid
#print axioms VoltaZk.cubicAuthedCoeffs_valid
#print axioms VoltaZk.compressedEvalAuthed_valid
#print axioms VoltaZk.quadraticAuthedCoeffs_x
#print axioms VoltaZk.cubicAuthedCoeffs_x
#print axioms VoltaZk.compressedEvalAuthed_x
#print axioms VoltaZk.lateRoundPoly_natDegree_le
#print axioms VoltaZk.trunc_trunc_succ
#print axioms VoltaZk.trunc_succ_apply_self
#print axioms VoltaZk.lateRoundPoly_first
#print axioms VoltaZk.lateRoundPoly_step
#print axioms VoltaZk.lateEvalAuthed_valid
#print axioms VoltaZk.lateEvalAuthed_x
#print axioms VoltaZk.lateOpeningAuthed_valid
#print axioms VoltaZk.lateOpeningAuthed_x
#print axioms VoltaZk.lateClaimAt_valid
#print axioms VoltaZk.quadraticAuthedCoeffs_k
#print axioms VoltaZk.cubicAuthedCoeffs_k
#print axioms VoltaZk.compressedEvalAuthed_k_eq_key
#print axioms VoltaZk.lateEvalAuthed_k_eq_verifier
#print axioms VoltaZk.lateOpeningAuthed_k_eq_verifier
#print axioms VoltaZk.lateClaimAt_k_eq_verifier
#print axioms VoltaZk.lateClaimAt_x_zero
#print axioms VoltaZk.lateClaimAt_x_mid
#print axioms VoltaZk.lateClaimAt_x_last
#print axioms VoltaZk.clear_of_late_claims_zero
#print axioms VoltaZk.affinePair_collision_card_le_one
#print axioms VoltaZk.affine_late_atoms_then_chain_sound
#print axioms VoltaZk.shared_pair_collapse_then_chain_sound
#print axioms VoltaZk.fullLeafPair_p
#print axioms VoltaZk.fullLeafPair_q
#print axioms VoltaZk.fullLeafPair_col
#print axioms VoltaZk.fullLeafPair_card
#print axioms VoltaZk.lsbMle_cons
#print axioms VoltaZk.layerLeafOnesAux_sigma
#print axioms VoltaZk.layerLeafOnesAux_total
#print axioms VoltaZk.layerLeafOnesAux_terminal
#print axioms VoltaZk.layerLeafOnesAux_children
#print axioms VoltaZk.layerLeafChildrenAt_apply
#print axioms VoltaZk.layerLeaf_claim_pair_ne_of_external
#print axioms VoltaZk.layer_leaf_ones_aux_full_vector_collapse_sound
#print axioms VoltaZk.layerLeafAuxWireProverOfInput_sigma
#print axioms VoltaZk.layer_leaf_ones_aux_round_degree_le_three
#print axioms VoltaZk.layer_leaf_ones_aux_clearAccepts_iff_terminal
#print axioms VoltaZk.layer_leaf_ones_aux_affine_then_chain_sound

-- X4 amended zkDeepFold-UD folding PCS (Amendments 1--2).
#print axioms VoltaZk.goldilocksP_prime
#print axioms VoltaZk.goldilocks_fp2_card
#print axioms VoltaZk.goldilocks_fp2_two_adicity
#print axioms VoltaZk.goldilocks_fp2_domain_root
#print axioms VoltaZk.rs_rate_eighth_unique_decode
#print axioms VoltaZk.rs_eighth_strict_unique_decode_property
#print axioms VoltaZk.split_block_eval
#print axioms VoltaZk.masked_aux_eval
#print axioms VoltaZk.masked_aux_hiding_count
#print axioms VoltaZk.one_opening_per_epoch
#print axioms VoltaZk.ResponseZeroBatchValid
#print axioms VoltaZk.direct_mask_transfer
#print axioms VoltaZk.masked_sum_zeroBatch_link_counterexample
#print axioms VoltaZk.X4FrameKind.ofCode_code
#print axioms VoltaZk.x4FrameHeader_length
#print axioms VoltaZk.X4FrameV2.ext
#print axioms VoltaZk.x4_frame_decode_encode
#print axioms VoltaZk.x4_frame_decode_canonical
#print axioms VoltaZk.x4_frame_kind_encoding_disjoint
#print axioms VoltaZk.cohort_opening_binding
#print axioms VoltaZk.blind_claim_reduce_sound
#print axioms VoltaZk.folding_different_point_batch_sound
#print axioms VoltaZk.ud_cohort_folding_sound
#print axioms VoltaZk.x4_ud_pcs_binding
#print axioms VoltaZk.masked_aux_perfect_zk
#print axioms VoltaZk.x4_masked_zk
#print axioms VoltaZk.x4_batch_sound
#print axioms VoltaZk.MaskedBatchBindsIntoMac
#print axioms VoltaZk.masked_batch_opening_mac_sound
#print axioms VoltaZk.masked_batch_transfers_evals
#print axioms VoltaZk.x4ResponseError
#print axioms VoltaZk.x4_wrong_response_event_cover
#print axioms VoltaZk.x4_response_soundness
#print axioms VoltaZk.x4_response_error_lt_two_pow_neg_83
#print axioms VoltaZk.x4_response_error_meets_registered_target
#print axioms VoltaZk.ligero_binding_discharge
#print axioms VoltaZk.ligero_blinded_zk_discharge
#print axioms VoltaZk.ligero_multi_point_batch_discharge
#print axioms VoltaZk.uc_composition_of_realizations
#print axioms VoltaZk.logup_gkr_sound_of_char_gt

-- X4 authenticated-output folding PCS (Amendments 3--4).
-- The historical 133/40 audit above remains present verbatim; these are the
-- 30 additional kernel targets required by the v3 statement freeze.
#print axioms VoltaZk.corr_correction_view_bijective
#print axioms VoltaZk.corr_correction_views_unique_preimage
#print axioms VoltaZk.masked_aux_authenticated_link_hiding_count
#print axioms VoltaZk.x4_aux_mask_entropy_budget_max_v3
#print axioms VoltaZk.blind_authenticated_output_link_perfect_zk
#print axioms VoltaZk.pending_aux_cannot_escape
#print axioms VoltaZk.authenticated_output_link_produces_bound_aux
#print axioms VoltaZk.bound_aux_has_verified_origin
#print axioms VoltaZk.x4_v3_m9_fixed_before_link_challenge
#print axioms VoltaZk.authenticated_output_batch_link_sound
#print axioms VoltaZk.authenticated_output_batch_beta_collision_counterexample
#print axioms VoltaZk.X4FrameKindV3.ofCode_code
#print axioms VoltaZk.x4FrameHeaderV3_length
#print axioms VoltaZk.X4FrameV3.ext
#print axioms VoltaZk.x4_v3_frame_decode_encode
#print axioms VoltaZk.x4_v3_frame_decode_canonical
#print axioms VoltaZk.x4_v3_frame_kind_encoding_disjoint
#print axioms VoltaZk.cohort_opening_binding_v3
#print axioms VoltaZk.x4_ud_pcs_binding_v3
#print axioms VoltaZk.authenticated_output_link_excludes_delta_shift
#print axioms VoltaZk.accepted_delta_shift_event_cover_v3
#print axioms VoltaZk.masked_batch_transfers_evals_v3
#print axioms VoltaZk.x4_authenticated_output_zk
#print axioms VoltaZk.x4_v3_max_link_frame_bytes
#print axioms VoltaZk.x4_v3_max_seam_frame_bytes
#print axioms VoltaZk.x4_v3_max_seam_full_corrs
#print axioms VoltaZk.x4_wrong_response_event_cover_v3
#print axioms VoltaZk.x4_response_soundness_v3
#print axioms VoltaZk.x4_response_error_v3_lt_two_pow_neg_83
#print axioms VoltaZk.x4_response_error_v3_meets_registered_target

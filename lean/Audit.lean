import VoltaZk

/-!
Machine-readable named-assumption audit for the M1–M12 boundary.

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

-- X4 Amendment 5: model-global schema-4 packed opening, s=111.
-- Binding, ZK and different-size batching remain separate targets.  The
-- historical delta-shift and beta-collision negative artifacts above stay in
-- the audit and are not replaced by these declarations.
#print axioms VoltaZk.x4V4QueryCount
#print axioms VoltaZk.x4_v4_field_domain_capacity
#print axioms VoltaZk.x4_aux_mask_entropy_budget_max_v4
#print axioms VoltaZk.masked_aux_authenticated_link_hiding_count_v4
#print axioms VoltaZk.AuthenticatedLinkViewV4.ext
#print axioms VoltaZk.blind_authenticated_output_link_perfect_zk_v4
#print axioms VoltaZk.X4FrameKindV4.ofCode_code
#print axioms VoltaZk.x4FrameHeaderV4_length
#print axioms VoltaZk.X4FrameV4.ext
#print axioms VoltaZk.x4_v4_frame_decode_encode
#print axioms VoltaZk.x4_v4_frame_decode_canonical
#print axioms VoltaZk.x4_v4_frame_kind_encoding_disjoint
#print axioms VoltaZk.x4_v4_packed_schedule_is_derived
#print axioms VoltaZk.x4_v4_reconstructed_leaf_hash_eq_explicit
#print axioms VoltaZk.x4_v4_packed_verify_iff_explicit_verify
#print axioms VoltaZk.x4_v4_all_commitments_fixed_before_queries
#print axioms VoltaZk.x4_v4_no_early_query_transition
#print axioms VoltaZk.cohort_opening_binding_v4
#print axioms VoltaZk.model_global_slot_identity_binding_v4
#print axioms VoltaZk.model_global_same_domain_reduce_sound_v4
#print axioms VoltaZk.deepfold_different_size_global_chain_sound_v4
#print axioms VoltaZk.ud_model_global_folding_sound_v4
#print axioms VoltaZk.x4_ud_pcs_binding_v4
#print axioms VoltaZk.x4_masked_zk_v4
#print axioms VoltaZk.x4_batch_sound_v4
#print axioms VoltaZk.authenticated_output_link_produces_bound_aux_v4
#print axioms VoltaZk.bound_aux_has_verified_origin_v4
#print axioms VoltaZk.authenticated_output_batch_link_sound_v4
#print axioms VoltaZk.authenticated_output_link_excludes_delta_shift_v4
#print axioms VoltaZk.accepted_delta_shift_event_cover_v4
#print axioms VoltaZk.masked_batch_transfers_evals_v4
#print axioms VoltaZk.x4V4PackedOpeningBytes
#print axioms VoltaZk.x4_v4_gpt2_packed_opening_bytes
#print axioms VoltaZk.x4_v4_gpt2_complete_pcs_bytes
#print axioms VoltaZk.x4_v4_gpt2_g3_and_response_caps
#print axioms VoltaZk.x4_v4_gptoss_codec_upper_bound
#print axioms VoltaZk.x4V4SeamFullCorrs
#print axioms VoltaZk.x4V4FullCorrs
#print axioms VoltaZk.x4_v4_gpt2_full_corrs
#print axioms VoltaZk.x4_v4_max_seam_full_corrs
#print axioms VoltaZk.x4_v4_max_full_corrs
#print axioms VoltaZk.x4ResponseErrorV4
#print axioms VoltaZk.x4_wrong_response_event_cover_v4
#print axioms VoltaZk.x4_response_soundness_v4
#print axioms VoltaZk.x4_response_error_v4_lt_two_pow_neg_80
#print axioms VoltaZk.x4_response_error_v4_meets_registered_target

-- X4d M12: deferred settlement over the exact frozen-claim union.
-- This block must remain a composition of M9, M10 and the audited v4 events;
-- no new ideal functionality is admitted.
#print axioms VoltaZk.x4d_claim_cap_is_v4_cap
#print axioms VoltaZk.x4d_query_count_is_v4_query_count
#print axioms VoltaZk.x4d_claim_cap_implies_v4_bounds
#print axioms VoltaZk.x4d_claim_3321_refused
#print axioms VoltaZk.x4d_accumulator_append_binding
#print axioms VoltaZk.x4d_settlement_range_is_exact_union
#print axioms VoltaZk.x4d_settlement_range_roles_agree
#print axioms VoltaZk.x4d_frozen_response_m9_or_mac_bad
#print axioms VoltaZk.x4d_frozen_claim_bad_card_le
#print axioms VoltaZk.x4d_frozen_claim_opening_mac_sound
#print axioms VoltaZk.x4d_batched_mask_fiber_lower_bound
#print axioms VoltaZk.x4d_gpt2_mask_budget
#print axioms VoltaZk.x4d_verified_settlement_has_exact_frozen_union

-- C6 inline Δ-residual and predecessor-conditional persistent cache.
#print axioms VoltaZk.correctedKey
#print axioms VoltaZk.c6_delta_residual_decompose
#print axioms VoltaZk.c6_delta_residual_keyOf
#print axioms VoltaZk.c6_delta_residual_complete
#print axioms VoltaZk.c6_delta_residual_sound
#print axioms VoltaZk.c6_seventeen_certificate_union_bound
#print axioms VoltaZk.C6CorrelationShare.authed_valid
#print axioms VoltaZk.C6CorrectedSource.correctedKey_eq
#print axioms VoltaZk.C6CorrectedSource.authed_valid
#print axioms VoltaZk.c6_base_share_error_rlc
#print axioms VoltaZk.c6_base_share_binding_complete
#print axioms VoltaZk.c6_base_share_binding_sound
#print axioms VoltaZk.c6_product_key_matches_prodKey
#print axioms VoltaZk.c6_product_polynomial_expand
#print axioms VoltaZk.c6_product_closure
#print axioms VoltaZk.c6_product_true_implies_q_zero
#print axioms VoltaZk.c6_product_q_collapse_sound
#print axioms VoltaZk.c6_corrected_source_product_closure
#print axioms VoltaZk.C6Certificate.accepted_certificate_not_replayable
#print axioms VoltaZk.C6CacheTransition.old_cache_unique
#print axioms VoltaZk.C6CacheTransition.append_only
#print axioms VoltaZk.C6CacheTransition.cache_length_monotone
#print axioms VoltaZk.c6_reserve_starts_at_high_water
#print axioms VoltaZk.c6_reserve_ends_at_new_high_water
#print axioms VoltaZk.c6_reserve_counts_match
#print axioms VoltaZk.c6_reserve_preserves_capacity
#print axioms VoltaZk.c6_burn_preserves_raw_high_water
#print axioms VoltaZk.c6_retry_after_burn_is_disjoint
#print axioms VoltaZk.C6Slot.retransmission_digest_unique
#print axioms VoltaZk.C6Slot.burn_preserves_range
#print axioms VoltaZk.C6Slot.burn_preserves_attempt_identity
#print axioms VoltaZk.c6_independent_pair_accepting_card
#print axioms VoltaZk.c6_independent_pair_accepting_card_le
#print axioms VoltaZk.c6_same_secret_repetition_no_amplification
#print axioms VoltaZk.c6_split_coordinate_accepting_card
#print axioms VoltaZk.c6_complete_relation_two_repetition_card_le
#print axioms VoltaZk.c6_adaptive_two_claim_batch_has_nonzero_kernel
#print axioms VoltaZk.c6_adaptive_three_claim_two_batch_kernel
#print axioms VoltaZk.c6_fixed_relation_batching_sound
#print axioms VoltaZk.c6_fixed_relation_two_repetition_sound
#print axioms VoltaZk.c6_delta_residual_accepting_secrets_card_le_one
#print axioms VoltaZk.c6_delta_residual_two_secret_sound
#print axioms VoltaZk.c6_base_share_binding_two_vector_sound
#print axioms VoltaZk.goldilocks_fp2_card_lt_two_pow_128
#print axioms VoltaZk.two_pow_255_lt_goldilocks_fp2_pair_card
#print axioms VoltaZk.c6_hidden_linear_error_better_than_243
#print axioms VoltaZk.c6_delta_event_error_better_than_253
#print axioms VoltaZk.c6_delta_wrapper_event_better_than_239
#print axioms VoltaZk.C6FullFirstRoundWire.initialAuthed_valid
#print axioms VoltaZk.C6FullFirstRoundWire.compressedRoundPoly_initialClaim
#print axioms VoltaZk.C6FullFirstRoundWire.polynomial_sum01
#print axioms VoltaZk.c6_activation_residual_valid
#print axioms VoltaZk.c6_full_first_round_activation_closes
#print axioms VoltaZk.c6_terminal_eight_products_two_zero_rows_close
#print axioms VoltaZk.c6_eight_product_closure
#print axioms VoltaZk.c6_eight_product_closure_sound_scalar
#print axioms VoltaZk.c6_two_terminal_rows_zeroBatch_sound_scalar
#print axioms VoltaZk.c6_blind_transcript_root_census
#print axioms VoltaZk.c6_blind_transcript_root_census_le_256
#print axioms VoltaZk.c6_blind_two_repetition_card_le_256
#print axioms VoltaZk.c6_clear_blind_union_card_le
#print axioms VoltaZk.c6_clear_blind_union_card_le_2_pow_17
#print axioms VoltaZk.c6_delta_blind_wrapper_event_better_than_238
#print axioms VoltaZk.c6_linear_link_event_better_than_239
#print axioms VoltaZk.c6_packed_link_root_census
#print axioms VoltaZk.c6_packed_authenticated_output_link_sound
#print axioms VoltaZk.c6_packed_link_two_repetition_card_le
#print axioms VoltaZk.c6_hidden_linear_plus_link_numerator
#print axioms VoltaZk.c6_hidden_linear_plus_link_numerator_le_2_pow_16
#print axioms VoltaZk.c6_blind_hidden_compressed_round_sum01
#print axioms VoltaZk.c6_blind_hidden_degree_root_census
#print axioms VoltaZk.c6_blind_hidden_root_census
#print axioms VoltaZk.c6_blind_hidden_two_repetition_card_le
#print axioms VoltaZk.c6_blind_hidden_numerator
#print axioms VoltaZk.c6_blind_hidden_plus_link_numerator
#print axioms VoltaZk.c6_blind_hidden_plus_link_numerator_le_2_pow_16
#print axioms VoltaZk.c6_cache_live_entry_census
#print axioms VoltaZk.c6_cache_padded_geometry_is_slot_capacity
#print axioms VoltaZk.c6_cache_live_entries_fit_slot
#print axioms VoltaZk.c6_source_bootstrap_aggregate_corrected_key_eq
#print axioms VoltaZk.c6_pcs_cache_transition_refines_append
#print axioms VoltaZk.c6_pcs_cache_transition_respects_context_cap
#print axioms VoltaZk.c6_pcs_cache_successor_unique
#print axioms VoltaZk.c6_persistent_cache_root_census
#print axioms VoltaZk.c6_persistent_cache_root_census_le_conservative
#print axioms VoltaZk.c6_persistent_cache_two_repetition_numerator
#print axioms VoltaZk.c6_persistent_cache_two_repetition_numerator_lt_2_pow_12
#print axioms VoltaZk.c6_persistent_cache_two_repetition_card_le
#print axioms VoltaZk.c6_persistent_cache_blind_root_census
#print axioms VoltaZk.c6_persistent_cache_blind_root_census_le_conservative
#print axioms VoltaZk.c6_persistent_cache_blind_two_repetition_numerator
#print axioms VoltaZk.c6_persistent_cache_blind_two_repetition_numerator_lt_2_pow_13
#print axioms VoltaZk.c6_persistent_cache_blind_two_repetition_card_le
#print axioms VoltaZk.c6_persistent_packed_link_root_census
#print axioms VoltaZk.c6_persistent_packed_link_two_repetition_numerator
#print axioms VoltaZk.c6_blind_hidden_plus_persistent_link_numerator
#print axioms VoltaZk.c6_blind_hidden_plus_persistent_link_numerator_lt_2_pow_15
#print axioms VoltaZk.c6_persistent_packed_authenticated_output_link_sound
#print axioms VoltaZk.c6_abort_preserves_accepted_state
#print axioms VoltaZk.c6_atomic_state_is_old_or_new
#print axioms VoltaZk.c6_false_transition_event_cover
#print axioms VoltaZk.x4d_accepted_settlement_implies_each_m9_or_bad
#print axioms VoltaZk.x4d_settlement_error_is_v4
#print axioms VoltaZk.x4d_settlement_error_expanded
#print axioms VoltaZk.x4d_response_mac_union_error_le_sum
#print axioms VoltaZk.x4d_settlement_soundness_m12
#print axioms VoltaZk.x4d_connection_composition_m12
#print axioms VoltaZk.x4d_connection_fixed_slice_lift_m10
#print axioms VoltaZk.x4d_one_settlement_opening_per_epoch
#print axioms VoltaZk.x4d_pending_never_weight_accepted
#print axioms VoltaZk.x4d_abort_pending_is_terminal_unverified
#print axioms VoltaZk.x4d_abort_preserves_older_verified
#print axioms VoltaZk.x4d_failed_settlement_cannot_retry
#print axioms VoltaZk.x4d_gpt2_codec_preflight
#print axioms VoltaZk.x4d_gpt2_cap_geometry

import VoltaZk.C6ProductClosure
import VoltaZk.X4Field

/-!
# C6 exact-field two-repetition amplification

The Goldilocks quadratic extension has cardinality just below `2^128`.
Consequently, a single field challenge is not literally a 128-bit
statistical event.  This additive C6 module records the generic cardinality
square obtained from two independent complete repetitions and specializes it
to the two independent designated-verifier secrets used by the amplified
Δ-residual seam.

Nothing in this file changes the frozen M1--M11 or X4 statements.  In
particular:

* duplicating a predicate on the same secret does not amplify it;
* independent repetitions live in a product challenge space;
* the two Δ coordinates may have different provider shares, corrections and
  messages, but each must be false on its own coordinate;
* provider public claims batched by a relation challenge must be fixed before
  that challenge; otherwise adaptive errors have a nontrivial kernel even
  across two batching repetitions;
* transcript-seed expansion and commitment binding remain explicit
  computational assumptions outside these counting lemmas.
-/

namespace VoltaZk

open Finset

/-- Accepting pairs for two genuinely independent challenge tapes. -/
def c6IndependentPairAccepting {Omega₀ Omega₁ : Type*}
    [DecidableEq Omega₀] [DecidableEq Omega₁]
    (accept₀ : Finset Omega₀) (accept₁ : Finset Omega₁) :
    Finset (Omega₀ × Omega₁) :=
  accept₀.product accept₁

/-- The accepting count of two independent repetitions is the product of
the two individual accepting counts. -/
theorem c6_independent_pair_accepting_card {Omega₀ Omega₁ : Type*}
    [DecidableEq Omega₀] [DecidableEq Omega₁]
    (accept₀ : Finset Omega₀) (accept₁ : Finset Omega₁) :
    (c6IndependentPairAccepting accept₀ accept₁).card
      = accept₀.card * accept₁.card := by
  simp [c6IndependentPairAccepting]

/-- If both complete repetitions accept on at most `B` challenges, their
independent product accepts on at most `B²` challenge pairs. -/
theorem c6_independent_pair_accepting_card_le {Omega₀ Omega₁ : Type*}
    [DecidableEq Omega₀] [DecidableEq Omega₁]
    (accept₀ : Finset Omega₀) (accept₁ : Finset Omega₁) {B : Nat}
    (h₀ : accept₀.card ≤ B) (h₁ : accept₁.card ≤ B) :
    (c6IndependentPairAccepting accept₀ accept₁).card ≤ B ^ 2 := by
  rw [c6_independent_pair_accepting_card]
  simpa [pow_two] using Nat.mul_le_mul h₀ h₁

/-- Rechecking the same predicate on the same secret is definitionally the
same event, not an independent repetition. -/
theorem c6_same_secret_repetition_no_amplification {Omega : Type*}
    [Fintype Omega] (accept : Omega → Prop)
    [DecidablePred accept] :
    (univ.filter fun omega => accept omega ∧ accept omega)
      = univ.filter accept := by
  ext omega
  simp

/-- If only coordinate zero carries a false relation while coordinate one is
unconstrained/honest, the accepting set retains the complete second
challenge space.  This is the formal obstruction to identifying the two
proof repetitions with two different MAC coordinates and then citing a
squared bound for every relation error. -/
theorem c6_split_coordinate_accepting_card {Omega₀ Omega₁ : Type*}
    [Fintype Omega₁] (accept₀ : Finset Omega₀) :
    (accept₀.product (univ : Finset Omega₁)).card
      = accept₀.card * Fintype.card Omega₁ := by
  classical
  simp

/-- When each independent proof tape checks the same *complete* relation
containing both MAC coordinates, accepting that relation entails accepting
its coordinate-local bad branch.  We model the rest of each complete
relation by an arbitrary intersected accepting set: the bad-branch bound
survives each intersection and the two per-tape bounds then multiply.

The Rust owner map must therefore expose all residual leaf and auxiliary
tables to both proof repetitions; a split-coordinate statement cannot use
this theorem. -/
theorem c6_complete_relation_two_repetition_card_le
    {Omega₀ Omega₁ : Type*}
    [DecidableEq Omega₀] [DecidableEq Omega₁]
    (badAccept₀ otherAccept₀ : Finset Omega₀)
    (badAccept₁ otherAccept₁ : Finset Omega₁) {B : Nat}
    (h₀ : badAccept₀.card ≤ B) (h₁ : badAccept₁.card ≤ B) :
    (c6IndependentPairAccepting
      (badAccept₀ ∩ otherAccept₀)
      (badAccept₁ ∩ otherAccept₁)).card ≤ B ^ 2 := by
  apply c6_independent_pair_accepting_card_le
  · exact (card_le_card inter_subset_left).trans h₀
  · exact (card_le_card inter_subset_left).trans h₁

/-- One batching equation gives no soundness against claims chosen after its
weights are known.  For every pair of weights there is a nonzero adaptive
two-claim error vector whose weighted sum is exactly zero. -/
theorem c6_adaptive_two_claim_batch_has_nonzero_kernel {F : Type*}
    [Field F] (rho₀ rho₁ : F) :
    ∃ e₀ e₁ : F, (e₀ ≠ 0 ∨ e₁ ≠ 0) ∧ rho₀ * e₀ + rho₁ * e₁ = 0 := by
  by_cases hzero : rho₀ = 0 ∧ rho₁ = 0
  · exact ⟨1, 0, Or.inl one_ne_zero, by simp [hzero.1, hzero.2]⟩
  · have hweight : rho₀ ≠ 0 ∨ rho₁ ≠ 0 := by
      by_cases h₀ : rho₀ = 0
      · exact Or.inr fun h₁ => hzero ⟨h₀, h₁⟩
      · exact Or.inl h₀
    refine ⟨rho₁, -rho₀, ?_, by ring⟩
    rcases hweight with h₀ | h₁
    · exact Or.inr (neg_ne_zero.mpr h₀)
    · exact Or.inl h₁

/-- The two batching rows applied to three provider-adjustable errors. -/
def c6TwoBatchLinearMap {F : Type*} [Field F]
    (rho : Fin 2 → Fin 3 → F) : (Fin 3 → F) →ₗ[F] (Fin 2 → F) where
  toFun := fun error repetition => ∑ claim, rho repetition claim * error claim
  map_add' := by
    intro left right
    funext repetition
    simp only [Pi.add_apply, mul_add, Finset.sum_add_distrib]
  map_smul' := by
    intro scalar error
    funext repetition
    simp only [Pi.smul_apply, smul_eq_mul, RingHom.id_apply, Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro claim _
    ring

/-- Two complete batching repetitions still do not repair adaptive public
claims when at least three error coordinates remain adjustable.  Rank-nullity
gives a nonzero error vector accepted by both already-known batching rows. -/
theorem c6_adaptive_three_claim_two_batch_kernel {F : Type*}
    [Field F] (rho : Fin 2 → Fin 3 → F) :
    ∃ error : Fin 3 → F, error ≠ 0 ∧
      ∀ repetition, ∑ claim, rho repetition claim * error claim = 0 := by
  let batch := c6TwoBatchLinearMap rho
  have hdim :
      Module.finrank F (Fin 2 → F) < Module.finrank F (Fin 3 → F) := by
    simp
  have hker : LinearMap.ker batch ≠ ⊥ :=
    LinearMap.ker_ne_bot_of_finrank_lt hdim
  obtain ⟨error, hmem, hne⟩ := (LinearMap.ker batch).ne_bot_iff.mp hker
  refine ⟨error, hne, ?_⟩
  have hmap : batch error = 0 := LinearMap.mem_ker.mp hmem
  intro repetition
  exact congrFun hmap repetition

/-- Accepting relation-weight vectors for one error vector that was fixed
before the verifier sampled the vector. -/
noncomputable def c6FixedRelationAcceptingWeights {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (error : Fin T → F) : Finset (Fin T → F) := by
  classical
  exact univ.filter fun rho => ∑ claim, rho claim * error claim = 0

/-- Once the complete relation errors are fixed before the weights, one
nonzero atomic error restores the standard independent-vector RLC bound. -/
theorem c6_fixed_relation_batching_sound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (error : Fin T → F) {bad : Fin T} (hbad : error bad ≠ 0) :
    (c6FixedRelationAcceptingWeights error).card
      ≤ Fintype.card F ^ (T - 1) := by
  classical
  unfold c6FixedRelationAcceptingWeights
  exact card_linearForm_zero_le error hbad

/-- Two independent complete-relation weight vectors square the fixed-error
RLC bound.  The fixed `error` argument is the formal claims-before-weights
boundary; replacing it by a function of either challenge is invalid. -/
theorem c6_fixed_relation_two_repetition_sound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (error : Fin T → F) {bad : Fin T} (hbad : error bad ≠ 0) :
    (c6IndependentPairAccepting
      (c6FixedRelationAcceptingWeights error)
      (c6FixedRelationAcceptingWeights error)).card
        ≤ (Fintype.card F ^ (T - 1)) ^ 2 := by
  exact c6_independent_pair_accepting_card_le
    (c6FixedRelationAcceptingWeights error)
    (c6FixedRelationAcceptingWeights error)
    (c6_fixed_relation_batching_sound error hbad)
    (c6_fixed_relation_batching_sound error hbad)

/-- Accepting secrets for one fixed C6 Δ-residual coordinate. -/
noncomputable def c6DeltaResidualAcceptingSecrets {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (coeff : Fin T → F) (base : Fin T → F × F)
    (correction : Fin T → F) (msg : F) : Finset F := by
  classical
  exact univ.filter fun Delta =>
    msg = c6BaseKeyAggregate Delta coeff base
      + Delta * c6CorrectionAggregate coeff correction

/-- The existing one-coordinate residual theorem in named-set form. -/
theorem c6_delta_residual_accepting_secrets_card_le_one {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (coeff : Fin T → F) (base : Fin T → F × F)
    (correction : Fin T → F)
    (hbad : c6PlaintextAggregate coeff base correction ≠ 0) (msg : F) :
    (c6DeltaResidualAcceptingSecrets coeff base correction msg).card ≤ 1 := by
  classical
  simpa [c6DeltaResidualAcceptingSecrets] using
    c6_delta_residual_sound coeff base correction hbad msg

/-- **Amplified C6 Δ-residual soundness.**  Two independently sampled
designated-verifier secrets, with independently generated correlation tapes,
have at most one accepting pair when both committed coordinates contain a
nonzero plaintext residual.  The challenge space has `|F|²` elements.

The two `hbad` premises are deliberate: the wrapper must bind both MAC
coordinates to the same typed plaintext DAG.  This theorem does not smuggle
that cross-coordinate binding in as an algebraic fact. -/
theorem c6_delta_residual_two_secret_sound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T₀ T₁ : Nat}
    (coeff₀ : Fin T₀ → F) (base₀ : Fin T₀ → F × F)
    (correction₀ : Fin T₀ → F)
    (hbad₀ : c6PlaintextAggregate coeff₀ base₀ correction₀ ≠ 0) (msg₀ : F)
    (coeff₁ : Fin T₁ → F) (base₁ : Fin T₁ → F × F)
    (correction₁ : Fin T₁ → F)
    (hbad₁ : c6PlaintextAggregate coeff₁ base₁ correction₁ ≠ 0) (msg₁ : F) :
    (c6IndependentPairAccepting
      (c6DeltaResidualAcceptingSecrets coeff₀ base₀ correction₀ msg₀)
      (c6DeltaResidualAcceptingSecrets coeff₁ base₁ correction₁ msg₁)).card
        ≤ 1 := by
  have h₀ := c6_delta_residual_accepting_secrets_card_le_one
    coeff₀ base₀ correction₀ hbad₀ msg₀
  have h₁ := c6_delta_residual_accepting_secrets_card_le_one
    coeff₁ base₁ correction₁ hbad₁ msg₁
  simpa using
    (c6_independent_pair_accepting_card_le
      (c6DeltaResidualAcceptingSecrets coeff₀ base₀ correction₀ msg₀)
      (c6DeltaResidualAcceptingSecrets coeff₁ base₁ correction₁ msg₁)
      h₀ h₁)

/-- Two independent base-share coefficient vectors square the existing
`|F|^(T-1)` accepting-vector bound. -/
theorem c6_base_share_binding_two_vector_sound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] {T : Nat}
    (Delta₀ Delta₁ : F) (key₀ key₁ : Fin T → F)
    (share₀ share₁ : Fin T → C6CorrelationShare F)
    {j₀ j₁ : Fin T}
    (hbad₀ : key₀ j₀ ≠ (share₀ j₀).baseKey Delta₀)
    (hbad₁ : key₁ j₁ ≠ (share₁ j₁).baseKey Delta₁) :
    (c6IndependentPairAccepting
      (c6BaseShareAcceptingVectors Delta₀ key₀ share₀)
      (c6BaseShareAcceptingVectors Delta₁ key₁ share₁)).card
        ≤ (Fintype.card F ^ (T - 1)) ^ 2 := by
  classical
  exact c6_independent_pair_accepting_card_le
    (c6BaseShareAcceptingVectors Delta₀ key₀ share₀)
    (c6BaseShareAcceptingVectors Delta₁ key₁ share₁)
    (c6_base_share_binding_sound Delta₀ key₀ share₀ hbad₀)
    (c6_base_share_binding_sound Delta₁ key₁ share₁ hbad₁)

/-- One Goldilocks `Fp2` challenge is strictly smaller than a 128-bit
challenge space. -/
theorem goldilocks_fp2_card_lt_two_pow_128 :
    Fintype.card X4E < 2 ^ 128 := by
  rw [goldilocks_fp2_card]
  norm_num

/-- Two independent Goldilocks `Fp2` challenges have more than 255 bits of
challenge space. -/
theorem two_pow_255_lt_goldilocks_fp2_pair_card :
    2 ^ 255 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

/-- Exact integer certificate for the hidden-linear block bound
`(1 + 80²)/|Fp2|² < 2^-243`.  Here `80 = 2*(21+19)` is the conservative
degree-times-round count of one complete repetition. -/
theorem c6_hidden_linear_error_better_than_243 :
    (1 + 80 ^ 2) * 2 ^ 243 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

/-- Exact integer certificate for the conservative amplified Δ-event bound
`(2/|Fp2|)² < 2^-253`: one one-root MAC term plus one base-share-vector term
per independent coordinate. -/
theorem c6_delta_event_error_better_than_253 :
    4 * 2 ^ 253 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

/-- Exact integer certificate for the complete residual-wrapper allocation.
The repaired arithmetization reserves at most `256/|Fp2|` roots in each
independent *complete proof repetition*, including its degree-round sumcheck
subtotal and both MAC coordinates.  Thus `256²/|Fp2|² < 2^-239`.  Splitting
one MAC coordinate into each repetition would not justify this theorem for a
coordinate-local error.  The sharper theorem above remains the
MAC/base-share core subterm. -/
theorem c6_delta_wrapper_event_better_than_239 :
    (2 ^ 16) * 2 ^ 239 < (Fintype.card X4E) ^ 2 := by
  rw [goldilocks_fp2_card]
  norm_num

end VoltaZk

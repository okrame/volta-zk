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

end VoltaZk

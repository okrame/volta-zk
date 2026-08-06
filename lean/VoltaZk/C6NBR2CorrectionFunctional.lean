import VoltaZk.C6AuthenticatedOutputLink
import VoltaZk.C61PublicCompression
import Mathlib.Tactic

/-!
# C6NBR2 authenticated correction functional

This additive module records the algebra used by the wire-neutral C6NBR2
amendment.  The correction coefficients are fixed after the native bodies and
their compiler challenges, but before either packed-link batching challenge.
The existing residual slot-6 opening then authenticates both its old point
claim and the compiled correction inner product in one degree-two reduction.

The module does not change the frozen M1--M11 statements or assume a concrete
PCS implementation.  Commitment binding, transcript order, native-backend
soundness and the single final ZeroOpen remain explicit Rust/backend
obligations.
-/

namespace VoltaZk

open Finset

/-! ## Selector and zero-padding identity -/

def c6Nbr2Selector {F : Type*} [Zero F] [One F] (bit : Fin 2) : F :=
  if bit = 0 then 1 else 0

/-- Summing the two virtual selector coordinates retains exactly the
`y = 0, z = 0` source half. -/
theorem c6_nbr2_selector_identity
    {F X : Type*} [CommSemiring F] [Fintype X]
    (coefficients : X → F) (residual : X → Fin 2 → F) :
    (∑ y : Fin 2, ∑ z : Fin 2, ∑ x : X,
      c6Nbr2Selector y * c6Nbr2Selector z
        * coefficients x * residual x z)
      = ∑ x : X, coefficients x * residual x 0 := by
  classical
  simp [c6Nbr2Selector]

/-- If the compiled coefficient table is zero outside its registered source
prefix, the full D23 Boolean sum equals the source-prefix inner product. -/
theorem c6_nbr2_zero_padding_identity
    {F : Type*} [CommSemiring F]
    {n sourceCount : Nat}
    (coefficients residual : Fin n → F)
    (hpad : ∀ i : Fin n, sourceCount ≤ i.val → coefficients i = 0) :
    (∑ i : Fin n, coefficients i * residual i)
      = ∑ i ∈ (Finset.univ.filter fun i : Fin n => i.val < sourceCount),
          coefficients i * residual i := by
  classical
  rw [Finset.sum_filter]
  apply Finset.sum_congr rfl
  intro i _
  by_cases hsource : i.val < sourceCount
  · simp [hsource]
  · have houtside : sourceCount ≤ i.val := Nat.le_of_not_gt hsource
    simp [hsource, hpad i houtside]

/-! ## Individual degree-two round relation -/

/-- One source-coordinate round is the product of two affine interpolants:
the committed residual and the public affine equality/compiler weight. -/
noncomputable def c6Nbr2RoundPolynomial
    {F : Type*} [Field F]
    (residualZero residualOne weightZero weightOne : F) : Polynomial F :=
  (Polynomial.C residualZero
      + Polynomial.X * Polynomial.C (residualOne - residualZero))
    * (Polynomial.C weightZero
      + Polynomial.X * Polynomial.C (weightOne - weightZero))

theorem c6_nbr2_round_degree_le_two
    {F : Type*} [Field F]
    (residualZero residualOne weightZero weightOne : F) :
    (c6Nbr2RoundPolynomial residualZero residualOne weightZero weightOne).natDegree ≤ 2 := by
  unfold c6Nbr2RoundPolynomial
  have affineDegree (zero one : F) :
      (Polynomial.C zero
        + Polynomial.X * Polynomial.C (one - zero)).natDegree ≤ 1 := by
    refine (Polynomial.natDegree_add_le _ _).trans (max_le ?_ ?_)
    · simp only [Polynomial.natDegree_C]
      omega
    · refine Polynomial.natDegree_mul_le.trans ?_
      simp only [Polynomial.natDegree_X, Polynomial.natDegree_C]
      norm_num
  exact Polynomial.natDegree_mul_le.trans
    (Nat.add_le_add (affineDegree residualZero residualOne)
      (affineDegree weightZero weightOne))

/-! ## Common-point terminal weight -/

/-- Replacing residual slot 6's old equality weight by the affine combined
weight closes both the old opening and the correction at the same point. -/
theorem c6_nbr2_terminal_slot_weight_identity
    {F : Type*} [CommRing F]
    (rho gamma y z equality compiler residual oldClaim correction : F)
    (hold : oldClaim = equality * residual)
    (hcorrection : correction = (1 - y) * (1 - z) * compiler * residual) :
    rho * oldClaim + gamma * correction
      = (rho * equality + gamma * (1 - y) * (1 - z) * compiler) * residual := by
  rw [hold, hcorrection]
  ring

/-! ## Production root census -/

def c6Nbr2LinkRelationCount : Nat := 73
def c6Nbr2LinkRounds : Nat := 25
def c6Nbr2LinkRoots : Nat :=
  c6Nbr2LinkRelationCount + 3 * c6Nbr2LinkRounds + 2

def c6Nbr2TwoRepetitionNumerator : Nat := c6Nbr2LinkRoots ^ 2

theorem c6_nbr2_link_root_census : c6Nbr2LinkRoots = 150 := by
  norm_num [c6Nbr2LinkRoots, c6Nbr2LinkRelationCount, c6Nbr2LinkRounds]

theorem c6_nbr2_link_root_census_le_256 : c6Nbr2LinkRoots ≤ 256 := by
  rw [c6_nbr2_link_root_census]
  norm_num

/-- C6NBR2 specializes the existing different-point quadratic reduction at
the actual 73-claim, 25-round production census. -/
theorem c6_nbr2_packed_authenticated_output_link_sound
    {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    (claims : DifferentPointBatchReduction F
      c6Nbr2LinkRelationCount c6Nbr2LinkRounds ι)
    (points : Fin c6Nbr2LinkRelationCount → Fin c6Nbr2LinkRounds → F)
    (commonPoint : Fin c6Nbr2LinkRounds → F)
    (hfixed : MaskedClaimsFixed claims)
    (hcommon : HasCommonPoint points commonPoint) :
    x4ReductionBadTapeCard (by norm_num [c6Nbr2LinkRounds]) claims
      ≤ c6Nbr2LinkRoots * x4FieldTapeCard F c6Nbr2LinkRounds := by
  have h := folding_different_point_batch_sound
    (F := F) (ι := ι)
    (claimCount := c6Nbr2LinkRelationCount)
    (rounds := c6Nbr2LinkRounds)
    (by norm_num [c6Nbr2LinkRounds])
    claims points commonPoint hfixed
    (by norm_num [c6Nbr2LinkRelationCount])
    hcommon
    (by norm_num [c6Nbr2LinkRounds])
  simpa [c6Nbr2LinkRoots] using h

theorem c6_nbr2_two_repetition_numerator :
    c6Nbr2TwoRepetitionNumerator = 22500 := by
  norm_num [c6Nbr2TwoRepetitionNumerator, c6Nbr2LinkRoots,
    c6Nbr2LinkRelationCount, c6Nbr2LinkRounds]

theorem c6_nbr2_two_repetition_numerator_lt_2_pow_16 :
    c6Nbr2TwoRepetitionNumerator < 2 ^ 16 := by
  rw [c6_nbr2_two_repetition_numerator]
  norm_num

/-! ## Joint compiler/native/link closure -/

/-- Logical composition boundary for the C6NBR1/C6NBR2 joint bridge.  The
Rust typestate instantiates the four antecedents in transcript order; each
backend failure event remains named rather than being hidden in a digest. -/
theorem C6NBR1JointBridgeSound
    (nativeAccept compilerAccept linkAccept zeroOpenAccept
      targetFunctionalValid correctionFunctionalValid linkedCorrection
      certificateValid nativeBad compilerBad linkBad zeroOpenBad : Prop)
    (hnative : nativeAccept → targetFunctionalValid ∨ nativeBad)
    (hcompiler : targetFunctionalValid → compilerAccept →
      correctionFunctionalValid ∨ compilerBad)
    (hlink : correctionFunctionalValid → linkAccept →
      linkedCorrection ∨ linkBad)
    (hzero : linkedCorrection → zeroOpenAccept →
      certificateValid ∨ zeroOpenBad)
    (hna : nativeAccept) (hca : compilerAccept)
    (hla : linkAccept) (hza : zeroOpenAccept) :
    certificateValid ∨ nativeBad ∨ compilerBad ∨ linkBad ∨ zeroOpenBad := by
  rcases hnative hna with htarget | hbad
  · rcases hcompiler htarget hca with hcorrection | hbad
    · rcases hlink hcorrection hla with hlinked | hbad
      · rcases hzero hlinked hza with hvalid | hbad
        · exact Or.inl hvalid
        · exact Or.inr (Or.inr (Or.inr (Or.inr hbad)))
      · exact Or.inr (Or.inr (Or.inr (Or.inl hbad)))
    · exact Or.inr (Or.inr (Or.inl hbad))
  · exact Or.inr (Or.inl hbad)

end VoltaZk

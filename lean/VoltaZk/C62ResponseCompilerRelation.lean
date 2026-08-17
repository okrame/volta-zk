import VoltaZk.C6NativeHiddenUElimination
import Mathlib.Tactic

/-!
# C6.2 response/compiler value relation

This additive module records the algebra of `C62JVR1`. The secondary WHIR
opening `N`, the response-owned target fold `R`, and the compiled source fold
`C` are fixed before Fiat--Shamir derives `eta`.
-/

namespace VoltaZk

/-- The exact C6.2 model and embedding claim schedule.  The point digests are
abstract here.  Their typed positions make the 96+6 census part of the
statement. -/
structure C62ClaimSchedule where
  modelPoint : Fin 96 → Nat
  embeddingPoint : Fin 6 → Nat

/-- Values and verifier-derived weights on the exact claim schedule. -/
structure C62ClaimFrame (F : Type*) where
  schedule : C62ClaimSchedule
  modelWeight : Fin 96 → F
  embeddingWeight : Fin 6 → F
  modelValue : Fin 96 → F
  embeddingValue : Fin 6 → F

def c62ClaimFold
    {F : Type*} [AddCommMonoid F] [Mul F] (frame : C62ClaimFrame F) : F :=
  (∑ i, frame.modelWeight i * frame.modelValue i) +
    ∑ i, frame.embeddingWeight i * frame.embeddingValue i

def C62SamePointWeight
    {F : Type*} (left right : C62ClaimFrame F) : Prop :=
  left.schedule = right.schedule ∧
    left.modelWeight = right.modelWeight ∧
    left.embeddingWeight = right.embeddingWeight

theorem c62_claim_schedule_census :
    Fintype.card (Fin 96) + Fintype.card (Fin 6) = 102 := by
  decide

/-- Point and weight equality plus per-claim value equality forces the same
fold.  This is the formal boundary used by the response and secondary WHIR
owners. -/
theorem c62_same_points_weights_values_force_same_fold
    {F : Type*} [CommSemiring F]
    (secondary response : C62ClaimFrame F)
    (hschedule : C62SamePointWeight secondary response)
    (hmodel : secondary.modelValue = response.modelValue)
    (hembedding : secondary.embeddingValue = response.embeddingValue) :
    c62ClaimFold secondary = c62ClaimFold response := by
  rcases hschedule with ⟨hs, hmw, hew⟩
  cases secondary
  cases response
  simp_all [c62ClaimFold]

/-- The installed reverse DAG carries the same final claim weights. -/
structure C62InstalledReverseDag (F : Type*) where
  schedule : C62ClaimSchedule
  compiledModelWeight : Fin 96 → F
  compiledEmbeddingWeight : Fin 6 → F

def C62ReverseDagMatches
    {F : Type*} (dag : C62InstalledReverseDag F) (frame : C62ClaimFrame F) : Prop :=
  dag.schedule = frame.schedule ∧
    dag.compiledModelWeight = frame.modelWeight ∧
    dag.compiledEmbeddingWeight = frame.embeddingWeight

def c62CompilerFold
    {F : Type*} [AddCommMonoid F] [Mul F]
    (dag : C62InstalledReverseDag F) (frame : C62ClaimFrame F) : F :=
  (∑ i, dag.compiledModelWeight i * frame.modelValue i) +
    ∑ i, dag.compiledEmbeddingWeight i * frame.embeddingValue i

theorem c62_installed_reverse_dag_uses_same_weights
    {F : Type*} [CommSemiring F]
    (dag : C62InstalledReverseDag F) (frame : C62ClaimFrame F)
    (hmatch : C62ReverseDagMatches dag frame) :
    c62CompilerFold dag frame = c62ClaimFold frame := by
  rcases hmatch with ⟨_, hmodel, hembedding⟩
  simp [c62CompilerFold, c62ClaimFold, hmodel, hembedding]

def c62JointValueResidual
    {F : Type*} [Ring F] (native response compiler eta : F) : F :=
  (native - response) + eta * (native - compiler)

theorem c62_joint_value_residual_honest
    {F : Type*} [Ring F] (native response compiler eta : F)
    (hresponse : native = response) (hcompiler : native = compiler) :
    c62JointValueResidual native response compiler eta = 0 := by
  subst response
  subst compiler
  simp [c62JointValueResidual]

/-- A false fixed tuple can satisfy the degree-one relation for at most one
`eta`. Thus two distinct accepting challenges force both required
equalities. -/
theorem c62_two_distinct_eta_force_both_equalities
    {F : Type*} [Field F]
    (native response compiler eta₀ eta₁ : F)
    (heta : eta₀ ≠ eta₁)
    (h₀ : c62JointValueResidual native response compiler eta₀ = 0)
    (h₁ : c62JointValueResidual native response compiler eta₁ = 0) :
    native = response ∧ native = compiler := by
  have hmul : (eta₀ - eta₁) * (native - compiler) = 0 := by
    rw [c62JointValueResidual] at h₀ h₁
    linear_combination h₀ - h₁
  have hetaSub : eta₀ - eta₁ ≠ 0 := sub_ne_zero.mpr heta
  have hcompilerSub : native - compiler = 0 :=
    (mul_eq_zero.mp hmul).resolve_left hetaSub
  have hcompiler : native = compiler := sub_eq_zero.mp hcompilerSub
  have hcompilerResponse : compiler = response := by
    apply sub_eq_zero.mp
    simpa [c62JointValueResidual, hcompiler] using h₀
  exact ⟨hcompiler.trans hcompilerResponse, hcompiler⟩

/-- Distinct commitment roots do not permit divergent fixed values to pass
for every deterministic Fiat--Shamir challenge. -/
theorem c62_distinct_roots_divergent_values_fail_some_eta
    {F Root : Type*} [Field F]
    (primaryRoot secondaryRoot : Root)
    (native response compiler : F)
    (_hroot : primaryRoot ≠ secondaryRoot)
    (hdivergent : native ≠ response ∨ native ≠ compiler) :
    ¬ ∀ eta, c62JointValueResidual native response compiler eta = 0 := by
  intro hall
  have hequalities := c62_two_distinct_eta_force_both_equalities
    native response compiler 0 1 zero_ne_one (hall 0) (hall 1)
  exact hdivergent.elim (fun h => h hequalities.1) (fun h => h hequalities.2)

/-- The implementation composition keeps each backend failure event explicit.
Fiat--Shamir state-restoration is a hypothesis at this boundary. -/
theorem C62JointValueCompositionSound
    (secondaryWhirAccept responseBindingAccept compilerBindingAccept
      jointZeroOpenAccept fiatShamirStateRestoring bothEqual
      whirBad responseBad compilerBad zeroOpenBad fiatShamirBad : Prop)
    (hwhir : secondaryWhirAccept → bothEqual ∨ whirBad)
    (hresponse : responseBindingAccept → bothEqual ∨ responseBad)
    (hcompiler : compilerBindingAccept → bothEqual ∨ compilerBad)
    (hzero : bothEqual → jointZeroOpenAccept → bothEqual ∨ zeroOpenBad)
    (hfs : fiatShamirStateRestoring ∨ fiatShamirBad)
    (hwa : secondaryWhirAccept) (hra : responseBindingAccept)
    (hca : compilerBindingAccept) (hza : jointZeroOpenAccept) :
    bothEqual ∨ whirBad ∨ responseBad ∨ compilerBad ∨ zeroOpenBad ∨ fiatShamirBad := by
  rcases hfs with hrestoring | hbad
  · rcases hwhir hwa with hequal | hbad
    · rcases hresponse hra with _ | hbad
      · rcases hcompiler hca with _ | hbad
        · rcases hzero hequal hza with hvalid | hbad
          · exact Or.inl hvalid
          · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hbad))))
        · exact Or.inr (Or.inr (Or.inr (Or.inl hbad)))
      · exact Or.inr (Or.inr (Or.inl hbad))
    · exact Or.inr (Or.inl hbad)
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr hbad))))

end VoltaZk

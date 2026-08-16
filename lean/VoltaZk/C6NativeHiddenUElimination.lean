import VoltaZk.C6NBR2CorrectionFunctional
import Mathlib.Tactic

/-!
# C6ICT5 native hidden-u elimination

This additive module records the typed refinement used when C6.1 deletes the
legacy Ligero/C6HUB2 branch.  One ordered response schedule supplies exactly
96 model claims and six embedding claims.  Both native repetitions attest the
same global points and plaintexts.  C6NBR2 then binds the compiled functional
to the residual correction before the joint authenticated ZeroOpen.

The theorem boundary keeps commitment binding, WHIR and MAC soundness,
transcript order, BLAKE3 binding and ZeroOpen soundness as explicit
hypotheses.  They are not Lean axioms.  There is deliberately no hidden-u
owner, claim, root or bad event in this statement.
-/

namespace VoltaZk

/-! ## Exact ordered 96+6 response schedule -/

abbrev C61ModelClaimIndex := Fin 96
abbrev C61EmbeddingClaimIndex := Fin 6
abbrev C61NativeClaimIndex := C61ModelClaimIndex ⊕ C61EmbeddingClaimIndex

/-- The response-owned points and plaintexts consumed by all four native
model/embedding chains. -/
structure C61OrderedNativeClaimSchedule (F Point : Type*) where
  modelPoint : C61ModelClaimIndex → Point
  modelValue : C61ModelClaimIndex → F
  embeddingPoint : C61EmbeddingClaimIndex → Point
  embeddingValue : C61EmbeddingClaimIndex → F

def C61OrderedNativeClaimSchedule.point
    {F Point : Type*} (schedule : C61OrderedNativeClaimSchedule F Point) :
    C61NativeClaimIndex → Point
  | Sum.inl index => schedule.modelPoint index
  | Sum.inr index => schedule.embeddingPoint index

def C61OrderedNativeClaimSchedule.value
    {F Point : Type*} (schedule : C61OrderedNativeClaimSchedule F Point) :
    C61NativeClaimIndex → F
  | Sum.inl index => schedule.modelValue index
  | Sum.inr index => schedule.embeddingValue index

/-- The four native chains are represented by component and repetition, but
there is still only one response-owned schedule. -/
structure C61FourNativeChainClaims (F Point : Type*) where
  modelPoint : Fin 2 → C61ModelClaimIndex → Point
  modelValue : Fin 2 → C61ModelClaimIndex → F
  embeddingPoint : Fin 2 → C61EmbeddingClaimIndex → Point
  embeddingValue : Fin 2 → C61EmbeddingClaimIndex → F

def C61FourNativeChainClaims.point
    {F Point : Type*} (chains : C61FourNativeChainClaims F Point)
    (repetition : Fin 2) : C61NativeClaimIndex → Point
  | Sum.inl index => chains.modelPoint repetition index
  | Sum.inr index => chains.embeddingPoint repetition index

def C61FourNativeChainClaims.value
    {F Point : Type*} (chains : C61FourNativeChainClaims F Point)
    (repetition : Fin 2) : C61NativeClaimIndex → F
  | Sum.inl index => chains.modelValue repetition index
  | Sum.inr index => chains.embeddingValue repetition index

def C61FourNativeChainClaims.Attest
    {F Point : Type*} (chains : C61FourNativeChainClaims F Point)
    (schedule : C61OrderedNativeClaimSchedule F Point) : Prop :=
  (∀ repetition index,
      chains.modelPoint repetition index = schedule.modelPoint index ∧
      chains.modelValue repetition index = schedule.modelValue index) ∧
  (∀ repetition index,
      chains.embeddingPoint repetition index = schedule.embeddingPoint index ∧
      chains.embeddingValue repetition index = schedule.embeddingValue index)

/-- Acceptance of all four typed chains refines exactly the single ordered
response schedule, including global points and paired plaintexts. -/
theorem c61_four_native_chains_refine_ordered_response
    {F Point : Type*}
    (schedule : C61OrderedNativeClaimSchedule F Point)
    (chains : C61FourNativeChainClaims F Point)
    (hattest : chains.Attest schedule) :
    ∀ repetition index,
      chains.point repetition index = schedule.point index ∧
      chains.value repetition index = schedule.value index := by
  intro repetition index
  cases index with
  | inl index => exact hattest.1 repetition index
  | inr index => exact hattest.2 repetition index

theorem c61_ordered_native_claim_census : 96 + 6 = 102 := by
  norm_num

/-! ## Hidden-free 56+1 authenticated-link census -/

def c61Ict5ActiveLinkSlots : Nat := 56
def c61Ict5LinkRelations : Nat := c61Ict5ActiveLinkSlots + 1
def c61Ict5LinkRounds : Nat := 25
def c61Ict5LinkRoots : Nat :=
  c61Ict5LinkRelations + 3 * c61Ict5LinkRounds + 2
def c61Ict5TwoRepetitionNumerator : Nat := c61Ict5LinkRoots ^ 2

theorem c61_ict5_link_relation_census : c61Ict5LinkRelations = 57 := by
  norm_num [c61Ict5LinkRelations, c61Ict5ActiveLinkSlots]

theorem c61_ict5_link_root_census : c61Ict5LinkRoots = 134 := by
  norm_num [c61Ict5LinkRoots, c61Ict5LinkRelations,
    c61Ict5ActiveLinkSlots, c61Ict5LinkRounds]

theorem c61_ict5_two_repetition_numerator :
    c61Ict5TwoRepetitionNumerator = 17956 := by
  norm_num [c61Ict5TwoRepetitionNumerator, c61Ict5LinkRoots,
    c61Ict5LinkRelations, c61Ict5ActiveLinkSlots, c61Ict5LinkRounds]

theorem c61_ict5_two_repetition_numerator_lt_2_pow_15 :
    c61Ict5TwoRepetitionNumerator < 2 ^ 15 := by
  rw [c61_ict5_two_repetition_numerator]
  norm_num

/-- The native 57-relation profile instantiates the existing authenticated
different-point reduction without a hidden relation. -/
theorem c61_ict5_packed_authenticated_output_link_sound
    {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    (claims : DifferentPointBatchReduction F
      c61Ict5LinkRelations c61Ict5LinkRounds ι)
    (points : Fin c61Ict5LinkRelations → Fin c61Ict5LinkRounds → F)
    (commonPoint : Fin c61Ict5LinkRounds → F)
    (hfixed : MaskedClaimsFixed claims)
    (hcommon : HasCommonPoint points commonPoint) :
    x4ReductionBadTapeCard (by norm_num [c61Ict5LinkRounds]) claims
      ≤ c61Ict5LinkRoots * x4FieldTapeCard F c61Ict5LinkRounds := by
  have h := folding_different_point_batch_sound
    (F := F) (ι := ι)
    (claimCount := c61Ict5LinkRelations)
    (rounds := c61Ict5LinkRounds)
    (by norm_num [c61Ict5LinkRounds])
    claims points commonPoint hfixed
    (by norm_num [c61Ict5LinkRelations, c61Ict5ActiveLinkSlots])
    hcommon
    (by norm_num [c61Ict5LinkRounds])
  simpa [c61Ict5LinkRoots] using h

/-! ## Explicit hidden-free source binding and composition boundary -/

structure C61Ict5SourceBindingPreimage (D : Type*) where
  statement : D
  cacheProfile : D
  oldLength : Nat
  newLength : Nat
  residualManifest : D
  residualView : D
  pairedSource : D
  maskSeedCommitment : D
  fixedFourRoots : D
  deriving DecidableEq

def c61Ict5SourceBindingCollision
    {D : Type*}
    (compress : C61Ict5SourceBindingPreimage D → D)
    (left right : C61Ict5SourceBindingPreimage D) : Prop :=
  compress left = compress right ∧ left ≠ right

theorem c61_ict5_equal_source_binding_or_collision
    {D : Type*}
    (compress : C61Ict5SourceBindingPreimage D → D)
    (left right : C61Ict5SourceBindingPreimage D)
    (hequal : compress left = compress right) :
    left = right ∨ c61Ict5SourceBindingCollision compress left right := by
  classical
  by_cases hpreimage : left = right
  · exact Or.inl hpreimage
  · exact Or.inr ⟨hequal, hpreimage⟩

/-- Backend assumptions remain values passed to the composition theorem.
No global axiom and no hidden-u failure event is introduced. -/
structure C61Ict5SecurityAssumptions
    (fourWhirAccept orderedClaimsExact compiledFunctionalValid nbr2Accept
      correctionBound linkAccept transcriptBound sourceBindingAccept
      sourceBound jointZeroOpenAccept certificateValid : Prop) where
  commitmentBinding : fourWhirAccept → orderedClaimsExact
  whirSoundness : orderedClaimsExact → compiledFunctionalValid
  macAndNbr2Soundness : compiledFunctionalValid → nbr2Accept → correctionBound
  transcriptOrder : correctionBound → linkAccept → transcriptBound
  blake3Binding : transcriptBound → sourceBindingAccept → sourceBound
  jointZeroOpenSoundness : sourceBound → jointZeroOpenAccept → certificateValid

/-- Four native WHIR chains, C6NBR2 and the joint ZeroOpen compose directly.
The result has no premise or alternative corresponding to legacy hidden-u. -/
theorem c61_ict5_native_hidden_free_composition
    (fourWhirAccept orderedClaimsExact compiledFunctionalValid nbr2Accept
      correctionBound linkAccept transcriptBound sourceBindingAccept
      sourceBound jointZeroOpenAccept certificateValid : Prop)
    (security : C61Ict5SecurityAssumptions fourWhirAccept orderedClaimsExact
      compiledFunctionalValid nbr2Accept correctionBound linkAccept
      transcriptBound sourceBindingAccept sourceBound jointZeroOpenAccept
      certificateValid)
    (hwhir : fourWhirAccept) (hnbr2 : nbr2Accept) (hlink : linkAccept)
    (hsource : sourceBindingAccept) (hzero : jointZeroOpenAccept) :
    certificateValid := by
  have hclaims := security.commitmentBinding hwhir
  have hfunctional := security.whirSoundness hclaims
  have hcorrection := security.macAndNbr2Soundness hfunctional hnbr2
  have htranscript := security.transcriptOrder hcorrection hlink
  have hsourceBound := security.blake3Binding htranscript hsource
  exact security.jointZeroOpenSoundness hsourceBound hzero

end VoltaZk

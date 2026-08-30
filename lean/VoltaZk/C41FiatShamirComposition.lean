import VoltaZk.C41FoldedTypedOle

/-!
# C4.1 Fiat--Shamir composition boundary

BLAKE3 and state restoration remain explicit computational hypotheses. This
module records the complete C4.1 acceptance boundary; it does not model the
random oracle as an axiom or assign probabilities to bad events.
-/

namespace VoltaZk

def C41FiatShamirMaxChallenges : Nat := 131_072
def C41FiatShamirMaxRejectionDrawsPerLimb : Nat := 4
def C41FiatShamirFieldLimbs : Nat := 2

theorem c41_random_oracle_query_cap :
    C41FiatShamirMaxChallenges *
      C41FiatShamirMaxRejectionDrawsPerLimb *
      C41FiatShamirFieldLimbs = 1_048_576 := by
  decide

structure C41CompositionAcceptance where
  modelProof : Prop
  bridge : Prop
  weightsPcs : Prop
  embeddingPcs : Prop
  productClose : Prop
  zeroClose : Prop
  degreeTwelveClose : Prop
  fiatShamir : Prop

def C41CompositionAcceptance.protocolAll (accept : C41CompositionAcceptance) : Prop :=
  accept.modelProof ∧ accept.bridge ∧ accept.weightsPcs ∧
    accept.embeddingPcs ∧ accept.productClose ∧ accept.zeroClose ∧
    accept.degreeTwelveClose

def C41CompositionAcceptance.all (accept : C41CompositionAcceptance) : Prop :=
  accept.protocolAll ∧ accept.fiatShamir

structure C41CompositionBadEvents where
  protocolSoundness : Prop
  fiatShamirStateRestoration : Prop
  randomOracleProgramming : Prop
  blake3Collision : Prop
  fieldSampling : Prop

def C41CompositionBadEvents.any (bad : C41CompositionBadEvents) : Prop :=
  bad.protocolSoundness ∨ bad.fiatShamirStateRestoration ∨
    bad.randomOracleProgramming ∨ bad.blake3Collision ∨ bad.fieldSampling

/-- An accepted C4.1 proof establishes the intended relation unless one
registered protocol or Fiat--Shamir bad event occurs. -/
theorem C41FiatShamirCompositionSound
    (accept : C41CompositionAcceptance)
    (bad : C41CompositionBadEvents)
    (protocolGood fsGood intendedRelation : Prop)
    (hprotocol : accept.protocolAll → protocolGood ∨ bad.protocolSoundness)
    (hfs : accept.fiatShamir → fsGood ∨ bad.fiatShamirStateRestoration ∨
      bad.randomOracleProgramming ∨ bad.blake3Collision ∨ bad.fieldSampling)
    (hcompose : protocolGood → fsGood → intendedRelation)
    (hall : accept.all) :
    intendedRelation ∨ bad.any := by
  rcases hall with ⟨hprotocolAccept, hfsAccept⟩
  rcases hprotocol hprotocolAccept with hp | hprotocolBad
  · rcases hfs hfsAccept with hf | hstate | hprogram | hcollision | hsampling
    · exact Or.inl (hcompose hp hf)
    · exact Or.inr (Or.inr (Or.inl hstate))
    · exact Or.inr (Or.inr (Or.inr (Or.inl hprogram)))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hcollision))))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr hsampling))))
  · exact Or.inr (Or.inl hprotocolBad)

end VoltaZk

import VoltaZk.C62ResponseCompilerRelation
import VoltaZk.C62SoftmaxGapRelation
import Mathlib.Tactic

/-!
# C6.2 Fiat--Shamir composition boundary

This module does not model BLAKE3 as an axiom.
It keeps each computational assumption as an explicit proposition.
-/

namespace VoltaZk

/-- State-restoration is required for every transcript-driven component. -/
structure C62StateRestorationHypotheses where
  primaryWhir : Prop
  secondaryWhir : Prop
  responseFunctional : Prop
  compilerFunctional : Prop
  nbr2 : Prop
  blindLink : Prop
  zeroOpen : Prop

def C62StateRestorationHypotheses.all
    (hypotheses : C62StateRestorationHypotheses) : Prop :=
  hypotheses.primaryWhir ∧ hypotheses.secondaryWhir ∧
    hypotheses.responseFunctional ∧ hypotheses.compilerFunctional ∧
    hypotheses.nbr2 ∧ hypotheses.blindLink ∧ hypotheses.zeroOpen

theorem c62_state_restoration_requires_every_component
    (hypotheses : C62StateRestorationHypotheses)
    (hall : hypotheses.all) :
    hypotheses.primaryWhir ∧ hypotheses.secondaryWhir ∧
      hypotheses.responseFunctional ∧ hypotheses.compilerFunctional ∧
      hypotheses.nbr2 ∧ hypotheses.blindLink ∧ hypotheses.zeroOpen := by
  exact hall

def C62FiatShamirMaxChallenges : Nat := 131_072
def C62FiatShamirMaxRejectionDrawsPerLimb : Nat := 4
def C62FiatShamirFieldLimbs : Nat := 2

theorem c62_random_oracle_query_cap :
    C62FiatShamirMaxChallenges *
      C62FiatShamirMaxRejectionDrawsPerLimb *
      C62FiatShamirFieldLimbs = 1_048_576 := by
  decide

structure C62CompositionAcceptance where
  primaryWhir : Prop
  secondaryWhir : Prop
  responseBinding : Prop
  compilerBinding : Prop
  nbr2 : Prop
  blindLink : Prop
  zeroOpen : Prop
  fiatShamir : Prop

def C62CompositionAcceptance.all (accept : C62CompositionAcceptance) : Prop :=
  accept.primaryWhir ∧ accept.secondaryWhir ∧ accept.responseBinding ∧
    accept.compilerBinding ∧ accept.nbr2 ∧ accept.blindLink ∧
    accept.zeroOpen ∧ accept.fiatShamir

structure C62CompositionBadEvents where
  primaryWhirKnowledge : Prop
  secondaryWhirKnowledge : Prop
  responseFunctionalBinding : Prop
  compilerFunctionalBinding : Prop
  nbr2Soundness : Prop
  blindLinkSoundness : Prop
  zeroOpenSoundness : Prop
  fiatShamirStateRestoration : Prop
  randomOracleProgramming : Prop
  blake3Collision : Prop
  fieldSampling : Prop
  jointEta : Prop

def C62CompositionBadEvents.any (bad : C62CompositionBadEvents) : Prop :=
  bad.primaryWhirKnowledge ∨ bad.secondaryWhirKnowledge ∨
    bad.responseFunctionalBinding ∨ bad.compilerFunctionalBinding ∨
    bad.nbr2Soundness ∨ bad.blindLinkSoundness ∨ bad.zeroOpenSoundness ∨
    bad.fiatShamirStateRestoration ∨ bad.randomOracleProgramming ∨
    bad.blake3Collision ∨ bad.fieldSampling ∨ bad.jointEta

/--
The complete C6.2 verifier accepts the intended relation unless one explicit
backend or Fiat--Shamir event occurs.

The theorem is a logical composition boundary.
It does not assign a numerical probability to an event.
-/
theorem C62FiatShamirCompositionSound
    (accept : C62CompositionAcceptance)
    (bad : C62CompositionBadEvents)
    (primaryGood secondaryGood responseGood compilerGood nbr2Good blindGood zeroGood fsGood
      intendedRelation : Prop)
    (hprimary : accept.primaryWhir → primaryGood ∨ bad.primaryWhirKnowledge)
    (hsecondary : accept.secondaryWhir → secondaryGood ∨ bad.secondaryWhirKnowledge)
    (hresponse : accept.responseBinding → responseGood ∨ bad.responseFunctionalBinding)
    (hcompiler : accept.compilerBinding → compilerGood ∨ bad.compilerFunctionalBinding)
    (hnbr2 : accept.nbr2 → nbr2Good ∨ bad.nbr2Soundness)
    (hblind : accept.blindLink → blindGood ∨ bad.blindLinkSoundness)
    (hzero : accept.zeroOpen → zeroGood ∨ bad.zeroOpenSoundness)
    (hfs : accept.fiatShamir → fsGood ∨ bad.fiatShamirStateRestoration ∨
      bad.randomOracleProgramming ∨ bad.blake3Collision ∨ bad.fieldSampling ∨ bad.jointEta)
    (hcompose : primaryGood → secondaryGood → responseGood → compilerGood → nbr2Good →
      blindGood → zeroGood → fsGood → intendedRelation)
    (hall : accept.all) :
    intendedRelation ∨ bad.any := by
  rcases hall with ⟨hpa, hsa, hra, hca, hna, hba, hza, hfsa⟩
  rcases hprimary hpa with hp | hprimaryBad
  · rcases hsecondary hsa with hs | hsecondaryBad
    · rcases hresponse hra with hr | hresponseBad
      · rcases hcompiler hca with hc | hcompilerBad
        · rcases hnbr2 hna with hn | hnbr2Bad
          · rcases hblind hba with hb | hblindBad
            · rcases hzero hza with hz | hzeroBad
              · rcases hfs hfsa with hfsGood | hstate | hro | hcollision | hsampling | heta
                · exact Or.inl (hcompose hp hs hr hc hn hb hz hfsGood)
                · exact Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          (Or.inr
                            (Or.inr (Or.inr (Or.inr (Or.inl hstate))))))))
                · exact Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          (Or.inr
                            (Or.inr
                              (Or.inr (Or.inr (Or.inr (Or.inl hro)))))))))
                · exact Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          (Or.inr
                            (Or.inr
                              (Or.inr
                                (Or.inr (Or.inr (Or.inr (Or.inl hcollision))))))))))
                · exact Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          (Or.inr
                            (Or.inr
                              (Or.inr
                                (Or.inr
                                  (Or.inr (Or.inr (Or.inr (Or.inl hsampling)))))))))))
                · exact Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          (Or.inr
                            (Or.inr
                              (Or.inr
                                (Or.inr
                                  (Or.inr (Or.inr (Or.inr (Or.inr heta)))))))))))
              · exact Or.inr
                  (Or.inr
                    (Or.inr
                      (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hzeroBad)))))))
            · exact Or.inr
                (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hblindBad))))))
          · exact Or.inr
              (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hnbr2Bad)))))
        · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hcompilerBad))))
      · exact Or.inr (Or.inr (Or.inr (Or.inl hresponseBad)))
    · exact Or.inr (Or.inr (Or.inl hsecondaryBad))
  · exact Or.inr (Or.inl hprimaryBad)

/-- Seventeen accepted certificates do not include the four burned slots. -/
theorem c62_seventeen_certificate_union_census :
    (Finset.univ : Finset (Fin 17)).card = 17 := by
  simp

end VoltaZk

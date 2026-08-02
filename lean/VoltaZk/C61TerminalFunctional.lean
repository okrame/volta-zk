import VoltaZk.C61PublicCompression
import Mathlib.Tactic

/-!
# C6.1 exact terminal-functional relation

This additive module replaces the ineligible fixed-node interpretation of the
64 C6RSC3 terminal values.  A coefficient write is assigned to one typed
terminal-functional slot and receives exactly one leaf or auxiliary equality
weight.  The postclaim scalar `beta` folds the 64 accumulated functionals.

The theorem is deliberately independent of the installed sparse-DAG node
type: the native compiler relation must constrain the event generator, while
this module proves the exact event-to-functional projection that its verifier
consumes.
-/

namespace VoltaZk

open Finset

def c61TerminalProofRepetitions : Nat := 2
def c61LeafLinearSlots : Nat := 8
def c61AuxiliaryLinearSlots : Nat := 16
def c61AuxiliaryQuadraticSlots : Nat := 8
def c61TerminalSlotsPerRepetition : Nat :=
  c61LeafLinearSlots + c61AuxiliaryLinearSlots
    + c61AuxiliaryQuadraticSlots
def c61TerminalFunctionalSlots : Nat :=
  c61TerminalProofRepetitions * c61TerminalSlotsPerRepetition

theorem c61_terminal_functional_slot_census :
    c61TerminalFunctionalSlots = 64 := by
  norm_num [c61TerminalFunctionalSlots, c61TerminalProofRepetitions,
    c61TerminalSlotsPerRepetition, c61LeafLinearSlots,
    c61AuxiliaryLinearSlots, c61AuxiliaryQuadraticSlots]

/-! The constructors mirror `C6ResidualAtomicCoefficientTarget`. -/

inductive C61TerminalFunctionalTarget where
  | leafLinear (repetition : Fin 2) (table : Fin 8) (row : Nat)
  | auxiliaryLinear (repetition : Fin 2) (table : Fin 16) (row : Nat)
  | auxiliaryQuadratic (repetition : Fin 2) (pair : Fin 8) (row : Nat)
  deriving DecidableEq

def C61TerminalFunctionalTarget.slot :
    C61TerminalFunctionalTarget → Fin 64
  | .leafLinear repetition table _ =>
      ⟨32 * repetition.val + table.val, by omega⟩
  | .auxiliaryLinear repetition table _ =>
      ⟨32 * repetition.val + 8 + table.val, by omega⟩
  | .auxiliaryQuadratic repetition pair _ =>
      ⟨32 * repetition.val + 24 + pair.val, by omega⟩

theorem c61_leaf_slot_value
    (repetition : Fin 2) (table : Fin 8) (row : Nat) :
    (C61TerminalFunctionalTarget.leafLinear repetition table row).slot.val
      = 32 * repetition.val + table.val := rfl

theorem c61_auxiliary_linear_slot_value
    (repetition : Fin 2) (table : Fin 16) (row : Nat) :
    (C61TerminalFunctionalTarget.auxiliaryLinear repetition table row).slot.val
      = 32 * repetition.val + 8 + table.val := rfl

theorem c61_auxiliary_quadratic_slot_value
    (repetition : Fin 2) (pair : Fin 8) (row : Nat) :
    (C61TerminalFunctionalTarget.auxiliaryQuadratic repetition pair row).slot.val
      = 32 * repetition.val + 24 + pair.val := rfl

structure C61TerminalFunctionalWrite (F : Type*) where
  target : C61TerminalFunctionalTarget
  coefficient : F

def C61TerminalFunctionalTarget.equalityWeight
    {F : Type*}
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F) :
    C61TerminalFunctionalTarget → F
  | .leafLinear repetition _ row => leafEquality repetition row
  | .auxiliaryLinear repetition _ row => auxiliaryEquality repetition row
  | .auxiliaryQuadratic repetition _ row => auxiliaryEquality repetition row

def C61TerminalFunctionalWrite.kernel
    {F : Type*} [Mul F]
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (write : C61TerminalFunctionalWrite F) : F :=
  write.coefficient
    * write.target.equalityWeight leafEquality auxiliaryEquality

def c61TerminalFunctional
    {F E : Type*} [Semiring F] [DecidableEq E]
    (events : Finset E) (write : E → C61TerminalFunctionalWrite F)
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (slot : Fin 64) : F :=
  ∑ event ∈ events,
    if (write event).target.slot = slot then
      (write event).kernel leafEquality auxiliaryEquality
    else 0

def c61TerminalFunctionalEventFold
    {F E : Type*} [Semiring F] [DecidableEq E]
    (events : Finset E) (write : E → C61TerminalFunctionalWrite F)
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (beta : F) : F :=
  ∑ event ∈ events,
    beta ^ (write event).target.slot.val
      * (write event).kernel leafEquality auxiliaryEquality

/-- The exact C6TFR1 identity.  It is a reindexing of the typed coefficient
writes, not an assumption about terminal nodes of another graph. -/
theorem c61_terminal_functional_event_fold_exact
    {F E : Type*} [CommSemiring F] [DecidableEq E]
    (events : Finset E) (write : E → C61TerminalFunctionalWrite F)
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (beta : F) :
    (∑ slot : Fin 64,
      beta ^ slot.val
        * c61TerminalFunctional events write leafEquality auxiliaryEquality slot)
      = c61TerminalFunctionalEventFold events write
          leafEquality auxiliaryEquality beta := by
  classical
  unfold c61TerminalFunctional c61TerminalFunctionalEventFold
  calc
    (∑ slot : Fin 64,
        beta ^ slot.val * ∑ event ∈ events,
          if (write event).target.slot = slot then
            (write event).kernel leafEquality auxiliaryEquality
          else 0)
        = ∑ slot : Fin 64, ∑ event ∈ events,
            beta ^ slot.val
              * (if (write event).target.slot = slot then
                  (write event).kernel leafEquality auxiliaryEquality
                else 0) := by
            apply sum_congr rfl
            intro slot _
            rw [mul_sum]
    _ = ∑ event ∈ events, ∑ slot : Fin 64,
          beta ^ slot.val
            * (if (write event).target.slot = slot then
                (write event).kernel leafEquality auxiliaryEquality
              else 0) := by
          rw [sum_comm]
    _ = ∑ event ∈ events,
          beta ^ (write event).target.slot.val
            * (write event).kernel leafEquality auxiliaryEquality := by
          apply sum_congr rfl
          intro event _
          rw [sum_eq_single (write event).target.slot]
          · simp
          · intro slot _ hne
            simp [hne.symm]
          · simp

/-- If the concrete C6RSC3 accumulator exposes exactly the event-defined
functionals, its postclaim fold is the C6TFR1 event fold. -/
theorem c61_terminal_accumulator_yields_exact_event_fold
    {F E : Type*} [CommSemiring F] [DecidableEq E]
    (events : Finset E) (write : E → C61TerminalFunctionalWrite F)
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (terminal : Fin 64 → F) (beta : F)
    (hexact : ∀ slot, terminal slot =
      c61TerminalFunctional events write leafEquality auxiliaryEquality slot) :
    (∑ slot : Fin 64, beta ^ slot.val * terminal slot)
      = c61TerminalFunctionalEventFold events write
          leafEquality auxiliaryEquality beta := by
  calc
    (∑ slot : Fin 64, beta ^ slot.val * terminal slot)
        = ∑ slot : Fin 64,
            beta ^ slot.val
              * c61TerminalFunctional events write
                  leafEquality auxiliaryEquality slot := by
            apply sum_congr rfl
            intro slot _
            rw [hexact slot]
    _ = c61TerminalFunctionalEventFold events write
          leafEquality auxiliaryEquality beta :=
      c61_terminal_functional_event_fold_exact events write
        leafEquality auxiliaryEquality beta

/-- A claimed vector that passes against the exact event fold has the usual
zero-based degree-63 error root.  This connects C6TFR1 to the already audited
postclaim output-RLC theorem. -/
theorem c61_terminal_functional_acceptance_is_error_root
    {F E : Type*} [CommRing F] [DecidableEq E]
    (events : Finset E) (write : E → C61TerminalFunctionalWrite F)
    (leafEquality auxiliaryEquality : Fin 2 → Nat → F)
    (claimed : Fin 64 → F) (beta : F)
    (haccept : (∑ slot : Fin 64, beta ^ slot.val * claimed slot)
      = c61TerminalFunctionalEventFold events write
          leafEquality auxiliaryEquality beta) :
    ∑ slot : Fin 64,
      beta ^ slot.val
        * (claimed slot
          - c61TerminalFunctional events write
              leafEquality auxiliaryEquality slot) = 0 := by
  simp_rw [mul_sub]
  rw [sum_sub_distrib]
  rw [c61_terminal_functional_event_fold_exact]
  exact sub_eq_zero.mpr haccept

/-! ## Amended exact soundness registration -/

def c61TerminalFunctionalRelationError : ℚ :=
  (28 : ℚ) / c61Fp2CardQ

def c61TerminalFunctionalCompleteCertificateError : ℚ :=
  (234 : ℚ) / c61Fp2CardQ
    + (576 : ℚ) / c61Fp2CardQ ^ 2
    + (63 : ℚ) / c61Fp2CardQ
    + c61TerminalFunctionalRelationError
    + (3 : ℚ) / 2 ^ 148
    + c61RetainedWrapperError

theorem c61_terminal_functional_relation_error_eq :
    c61TerminalFunctionalRelationError = (28 : ℚ) / c61Fp2CardQ := rfl

theorem c61_terminal_functional_complete_error_lt_two_pow_neg_119 :
    c61TerminalFunctionalCompleteCertificateError < (1 : ℚ) / 2 ^ 119 := by
  norm_num [c61TerminalFunctionalCompleteCertificateError,
    c61TerminalFunctionalRelationError, c61RetainedWrapperError,
    c61RetainedWrapperPcsOneError, c61Fp2CardQ, c61GoldilocksP,
    goldilocksP]

theorem c61_terminal_functional_complete_error_meets_literal_79_bits :
    c61TerminalFunctionalCompleteCertificateError < (1 : ℚ) / 2 ^ 79 := by
  exact c61_terminal_functional_complete_error_lt_two_pow_neg_119.trans
    (by norm_num)

theorem c61_terminal_functional_seventeen_error_lt_two_pow_neg_115 :
    17 * c61TerminalFunctionalCompleteCertificateError
      < (1 : ℚ) / 2 ^ 115 := by
  norm_num [c61TerminalFunctionalCompleteCertificateError,
    c61TerminalFunctionalRelationError, c61RetainedWrapperError,
    c61RetainedWrapperPcsOneError, c61Fp2CardQ, c61GoldilocksP,
    goldilocksP]

end VoltaZk

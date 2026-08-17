import Mathlib.Tactic

/-!
# C6.2 total softmax reciprocal relation

This additive module records the integer boundary of `C62SRE1`.
The old 16-bit table remains exact on its full domain.
The new relation proves the denominator shift and rounded division.
-/

namespace VoltaZk

def C62RecipInputLimit : Nat := 2 ^ 18
def C62FrozenRecipInputLimit : Nat := 2 ^ 16
def C62RegisteredSequenceLimit : Nat := 950
def C62RegisteredExpMaximum : Nat := 2 ^ 14

/-- Every registered denominator produces an 18-bit reciprocal input. -/
theorem c62_registered_recip_input_fits_18_bits
    (sequence expMaximum denominator input : Nat)
    (hsequence : sequence ≤ C62RegisteredSequenceLimit)
    (hexp : expMaximum ≤ C62RegisteredExpMaximum)
    (hdenominator : denominator ≤ sequence * expMaximum)
    (hinput : input = denominator / 64) :
    input < C62RecipInputLimit := by
  have hproduct : sequence * expMaximum ≤ 950 * 16384 :=
    Nat.mul_le_mul hsequence hexp
  have hdenominator' : denominator ≤ 950 * 16384 := hdenominator.trans hproduct
  simp only [C62RegisteredSequenceLimit, C62RegisteredExpMaximum,
    C62RecipInputLimit] at *
  omega

/-- C6.2 uses the frozen value on every old-domain input. -/
def c62ExtendedReciprocal
    (frozen : Nat → Int) (recipLog2 denShift input : Nat) : Int :=
  if input < C62FrozenRecipInputLimit then frozen input
  else
    Int.ofNat (((2 ^ recipLog2) +
      (((input * 2 ^ denShift) + 2 ^ (denShift - 1)) / 2)) /
      ((input * 2 ^ denShift) + 2 ^ (denShift - 1)))

theorem c62_extended_reciprocal_matches_frozen_domain
    (frozen : Nat → Int) (recipLog2 denShift input : Nat)
    (hinput : input < C62FrozenRecipInputLimit) :
    c62ExtendedReciprocal frozen recipLog2 denShift input = frozen input := by
  simp [c62ExtendedReciprocal, hinput]

def c62RecipDivisor (input : Int) : Int := 64 * input + 32
def c62RecipRoundedNumerator (input : Int) : Int := 268435456 + 32 * input + 16

/-- The executable relation uses range-checked limbs for every inequality. -/
structure C62RecipRelation where
  input : Int
  quotient : Int
  remainder : Int
  slack : Int
  input_nonnegative : 0 ≤ input
  input_lt : input < 262144
  quotient_nonnegative : 0 ≤ quotient
  quotient_lt : quotient < 32768
  remainder_nonnegative : 0 ≤ remainder
  slack_nonnegative : 0 ≤ slack
  divide : c62RecipRoundedNumerator input =
    quotient * c62RecipDivisor input + remainder
  slack_relation : remainder + slack = c62RecipDivisor input - 1

theorem c62_recip_relation_remainder_is_strict
    (relation : C62RecipRelation) :
    relation.remainder < c62RecipDivisor relation.input := by
  have hslack := relation.slack_nonnegative
  have hrelation := relation.slack_relation
  simp only [c62RecipDivisor] at hrelation ⊢
  omega

/-- The six-bit shift remainder proves the exact reciprocal input. -/
theorem c62_recip_shift_relation_is_exact
    (denominator input low : Int)
    (hdenominator : denominator = 64 * input + low)
    (hlow : 0 ≤ low ∧ low < 64) :
    denominator / 64 = input := by
  have hlowDiv : low / 64 = 0 := Int.ediv_eq_zero_of_lt hlow.1 hlow.2
  rw [hdenominator, mul_comm 64 input,
    Int.mul_add_ediv_right input low (by norm_num), hlowDiv, add_zero]

/-- Two accepted rounded-division witnesses have the same quotient. -/
theorem c62_recip_relation_quotient_unique
    (left right : C62RecipRelation)
    (hinput : left.input = right.input) :
    left.quotient = right.quotient := by
  have hdpos : 0 < c62RecipDivisor left.input := by
    simp only [c62RecipDivisor]
    nlinarith [left.input_nonnegative]
  have hleftRem := c62_recip_relation_remainder_is_strict left
  have hrightRem := c62_recip_relation_remainder_is_strict right
  have hleftDivide := left.divide
  have hrightDivide := right.divide
  rw [← hinput] at hrightRem
  rw [← hinput] at hrightDivide
  by_contra hne
  rcases lt_or_gt_of_ne hne with hlt | hgt
  · have hstep : left.quotient + 1 ≤ right.quotient := by omega
    have hmul := mul_le_mul_of_nonneg_right hstep (le_of_lt hdpos)
    simp only [c62RecipRoundedNumerator] at hleftDivide hrightDivide
    nlinarith [hleftDivide, hrightDivide, left.remainder_nonnegative,
      right.remainder_nonnegative, hleftRem, hrightRem, hmul]
  · have hstep : right.quotient + 1 ≤ left.quotient := by omega
    have hmul := mul_le_mul_of_nonneg_right hstep (le_of_lt hdpos)
    simp only [c62RecipRoundedNumerator] at hleftDivide hrightDivide
    nlinarith [hleftDivide, hrightDivide, left.remainder_nonnegative,
      right.remainder_nonnegative, hleftRem, hrightRem, hmul]

end VoltaZk

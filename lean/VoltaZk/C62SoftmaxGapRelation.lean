import Mathlib.Tactic

/-!
# C6.2 total stable-softmax gap relation

This additive module records the integer boundary of `C62SGE1`.
The score and its row maximum are signed 16-bit integers.
Their nonnegative distance is an unsigned 16-bit integer.
-/

namespace VoltaZk

def C62I16Min : Int := -32768
def C62I16Max : Int := 32767
def C62SignedGapLimit : Int := 32768
def C62UnsignedGapMax : Int := 65535

def c62ScoreGap (score rowMax : Int) : Int := rowMax - score

/-- A signed i16 score below a signed i16 row maximum has one unsigned
16-bit gap. -/
theorem c62_score_gap_is_unsigned_u16
    (score rowMax : Int)
    (hscoreLow : C62I16Min ≤ score)
    (hrowHigh : rowMax ≤ C62I16Max)
    (hmax : score ≤ rowMax) :
    0 ≤ c62ScoreGap score rowMax ∧
      c62ScoreGap score rowMax ≤ C62UnsignedGapMax := by
  constructor <;> simp only [c62ScoreGap, C62I16Min, C62I16Max, C62UnsignedGapMax] at * <;>
    omega

/-- The score is recovered exactly from the row maximum and its gap. -/
theorem c62_score_gap_reconstructs_score (score rowMax : Int) :
    rowMax - c62ScoreGap score rowMax = score := by
  simp [c62ScoreGap]

/-- A zero gap identifies an exact row maximum. -/
theorem c62_zero_gap_iff_score_is_row_max (score rowMax : Int) :
    c62ScoreGap score rowMax = 0 ↔ score = rowMax := by
  constructor
  · simp only [c62ScoreGap]
    omega
  · intro h
    subst rowMax
    simp [c62ScoreGap]

/-- C62SGE1 uses the frozen signed exp table in its old domain.
It returns zero only in the previously undefined lower tail. -/
def c62GapExp {A : Type*} [Zero A] (signedExp : Int → A) (gap : Int) : A :=
  if gap ≤ C62SignedGapLimit then signedExp (-gap) else 0

theorem c62_gap_exp_matches_frozen_domain
    {A : Type*} [Zero A] (signedExp : Int → A) (gap : Int)
    (hgap : gap ≤ C62SignedGapLimit) :
    c62GapExp signedExp gap = signedExp (-gap) := by
  simp [c62GapExp, hgap]

theorem c62_gap_exp_zero_extends_lower_tail
    {A : Type*} [Zero A] (signedExp : Int → A) (gap : Int)
    (hgap : C62SignedGapLimit < gap) :
    c62GapExp signedExp gap = 0 := by
  simp [c62GapExp, Int.not_le.mpr hgap]

/-- The exact gap relation proves that every score is at most `rowMax`.
One zero gap proves that `rowMax` occurs in the row. -/
theorem c62_gap_relation_proves_exact_row_max
    {n : Nat} (score : Fin n → Int) (rowMax : Int)
    (gap : Fin n → Int)
    (hrelation : ∀ i, gap i = c62ScoreGap (score i) rowMax)
    (hnonnegative : ∀ i, 0 ≤ gap i)
    (zeroIndex : Fin n)
    (hzero : gap zeroIndex = 0) :
    (∀ i, score i ≤ rowMax) ∧ score zeroIndex = rowMax := by
  constructor
  · intro i
    have h := hnonnegative i
    rw [hrelation i] at h
    simp only [c62ScoreGap] at h
    omega
  · rw [hrelation zeroIndex] at hzero
    exact (c62_zero_gap_iff_score_is_row_max (score zeroIndex) rowMax).mp hzero

end VoltaZk

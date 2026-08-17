import Mathlib.Tactic

/-!
# C6.2 signed score clamp relation

This additive module records the integer boundary of `C62SCR1`.
The lookup input is a signed 17-bit score quotient shifted by `2^16`.
The lookup output is the exact signed 16-bit clamp.
-/

namespace VoltaZk

def c62ScoreIndex (raw : Int) : Int := raw + 65536

def c62ScoreClamp (raw : Int) : Int :=
  if raw < -32768 then -32768
  else if raw > 32767 then 32767
  else raw

theorem c62_score_index_fits_17_bits
    (raw : Int) (hlow : -65536 ≤ raw) (hhigh : raw < 65536) :
    0 ≤ c62ScoreIndex raw ∧ c62ScoreIndex raw < 131072 := by
  simp only [c62ScoreIndex]
  omega

theorem c62_score_clamp_is_identity
    (raw : Int) (hlow : -32768 ≤ raw) (hhigh : raw ≤ 32767) :
    c62ScoreClamp raw = raw := by
  have hnlow : ¬ raw < -32768 := by omega
  have hnhigh : ¬ raw > 32767 := by omega
  simp [c62ScoreClamp, hnlow, hnhigh]

theorem c62_score_clamp_lower
    (raw : Int) (hlow : raw < -32768) :
    c62ScoreClamp raw = -32768 := by
  simp [c62ScoreClamp, hlow]

theorem c62_score_clamp_upper
    (raw : Int) (hhigh : 32767 < raw) :
    c62ScoreClamp raw = 32767 := by
  simp [c62ScoreClamp, hhigh]
  omega

theorem c62_measured_score_has_registered_headroom :
    (34526 : Int) < 65536 := by
  norm_num

end VoltaZk

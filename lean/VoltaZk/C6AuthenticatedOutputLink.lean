import VoltaZk.C6Amplification
import VoltaZk.X4FoldingPCS
import Mathlib.Tactic

/-!
# C6 packed authenticated-output link

This additive module specializes the already-proved X4 different-point
quadratic reduction to the frozen C6 packed-link geometry.  It changes
neither the generic X4 theorem nor the four-event C6 allocation.

One C6 proof repetition links exactly 64 pending slot claims at suffix-aligned
target points to one fresh 25-coordinate PCS point.  The generic scalar
reduction therefore charges

`64 + 3 * 25 + 2 = 141`

field roots.  Two independent complete repetitions square that numerator.
The resulting link allocation is unioned with the previously frozen
hidden-linear numerator `1 + (2 * (21 + 19))^2 = 6401`; their exact sum is
`26282 < 2^16`, so the existing `c6_linear_link_event_better_than_239`
certificate remains conservative.
-/

namespace VoltaZk

open Finset

def c6PackedLinkRelationCount : Nat := 64
def c6PackedLinkRounds : Nat := 25

def c6PackedLinkRoots : Nat :=
  c6PackedLinkRelationCount + 3 * c6PackedLinkRounds + 2

def c6HiddenLinearNumerator : Nat :=
  1 + (2 * (21 + 19)) ^ 2

def c6PackedLinkTwoRepetitionNumerator : Nat :=
  c6PackedLinkRoots ^ 2

def c6HiddenLinearPlusLinkNumerator : Nat :=
  c6HiddenLinearNumerator + c6PackedLinkTwoRepetitionNumerator

theorem c6_packed_link_root_census :
    c6PackedLinkRoots = 141 := by
  norm_num [c6PackedLinkRoots, c6PackedLinkRelationCount,
    c6PackedLinkRounds]

theorem c6_packed_link_root_census_le_256 :
    c6PackedLinkRoots ≤ 256 := by
  rw [c6_packed_link_root_census]
  norm_num

/-- Exact specialization of the existing M3/X4 different-point theorem.
The hypotheses retain the load-bearing fixed-before-`beta` and common-point
boundaries; C6 supplies them through its opaque pending registry and packed
PCS schedule. -/
theorem c6_packed_authenticated_output_link_sound
    {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    (claims : DifferentPointBatchReduction F
      c6PackedLinkRelationCount c6PackedLinkRounds ι)
    (points : Fin c6PackedLinkRelationCount →
      Fin c6PackedLinkRounds → F)
    (commonPoint : Fin c6PackedLinkRounds → F)
    (hfixed : MaskedClaimsFixed claims)
    (hcommon : HasCommonPoint points commonPoint) :
    x4ReductionBadTapeCard
        (by norm_num [c6PackedLinkRounds]) claims
      ≤ c6PackedLinkRoots * x4FieldTapeCard F c6PackedLinkRounds := by
  have h := folding_different_point_batch_sound
    (F := F) (ι := ι)
    (claimCount := c6PackedLinkRelationCount)
    (rounds := c6PackedLinkRounds)
    (by norm_num [c6PackedLinkRounds])
    claims points commonPoint hfixed
    (by norm_num [c6PackedLinkRelationCount])
    hcommon
    (by norm_num [c6PackedLinkRounds])
  simpa [c6PackedLinkRoots] using h

/-- The two C6 link repetitions are independent complete reductions; their
bad-set numerators therefore multiply. -/
theorem c6_packed_link_two_repetition_card_le
    {Omega0 Omega1 : Type*}
    [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1)
    (h0 : bad0.card ≤ c6PackedLinkRoots)
    (h1 : bad1.card ≤ c6PackedLinkRoots) :
    (c6IndependentPairAccepting bad0 bad1).card
      ≤ c6PackedLinkTwoRepetitionNumerator := by
  simpa [c6PackedLinkTwoRepetitionNumerator] using
    (c6_independent_pair_accepting_card_le bad0 bad1 h0 h1)

theorem c6_packed_link_two_repetition_numerator :
    c6PackedLinkTwoRepetitionNumerator = 19881 := by
  norm_num [c6PackedLinkTwoRepetitionNumerator,
    c6_packed_link_root_census]

theorem c6_hidden_linear_numerator :
    c6HiddenLinearNumerator = 6401 := by
  norm_num [c6HiddenLinearNumerator]

theorem c6_hidden_linear_plus_link_numerator :
    c6HiddenLinearPlusLinkNumerator = 26282 := by
  norm_num [c6HiddenLinearPlusLinkNumerator,
    c6HiddenLinearNumerator, c6PackedLinkTwoRepetitionNumerator,
    c6PackedLinkRoots, c6PackedLinkRelationCount, c6PackedLinkRounds]

theorem c6_hidden_linear_plus_link_numerator_le_2_pow_16 :
    c6HiddenLinearPlusLinkNumerator < 2 ^ 16 := by
  rw [c6_hidden_linear_plus_link_numerator]
  norm_num

end VoltaZk

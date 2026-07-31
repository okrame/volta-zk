import VoltaZk.BoundaryThinningSound
import VoltaZk.C6AuthenticatedOutputLink
import Mathlib.Tactic

/-!
# C6 blind hidden-u transcript

This additive module records the descendant `C6HUB2` census without
rewriting the historical clear `C6HUSC1` or packed-link certificates.

Each complete hidden-linear repetition has 21 weights and 19 embedding
degree-two rounds.  The public initial claims permit the exact compressed
`g(0),g(2)` wire from the first round onward, contributing
`2 * (21 + 19) = 80` degree roots.  The final two-family pending-source batch
adds one batching root and one terminal MAC root.  Two independently
challenged complete repetitions square the resulting 82-root numerator.
-/

namespace VoltaZk

def c6BlindHiddenWeightsRounds : Nat := 21
def c6BlindHiddenEmbedRounds : Nat := 19

def c6BlindHiddenDegreeRoots : Nat :=
  2 * (c6BlindHiddenWeightsRounds + c6BlindHiddenEmbedRounds)

def c6BlindHiddenTerminalRoots : Nat := 2

def c6BlindHiddenRoots : Nat :=
  c6BlindHiddenDegreeRoots + c6BlindHiddenTerminalRoots

def c6BlindHiddenNumerator : Nat :=
  1 + c6BlindHiddenRoots ^ 2

def c6BlindHiddenPlusLinkNumerator : Nat :=
  c6BlindHiddenNumerator + c6PackedLinkTwoRepetitionNumerator

/-- The authenticated compressed wire reconstructs node one from the live
claim, so its Boolean-node sum is exactly that claim. -/
theorem c6_blind_hidden_compressed_round_sum01
    {F : Type*} [Field F] (live : F) (wire : LateRoundWire F) :
    (compressedRoundPoly live wire).eval 0 +
        (compressedRoundPoly live wire).eval 1 = live :=
  compressedRoundPoly_sum01 live wire

theorem c6_blind_hidden_degree_root_census :
    c6BlindHiddenDegreeRoots = 80 := by
  norm_num [c6BlindHiddenDegreeRoots, c6BlindHiddenWeightsRounds,
    c6BlindHiddenEmbedRounds]

theorem c6_blind_hidden_root_census :
    c6BlindHiddenRoots = 82 := by
  norm_num [c6BlindHiddenRoots, c6BlindHiddenDegreeRoots,
    c6BlindHiddenTerminalRoots, c6BlindHiddenWeightsRounds,
    c6BlindHiddenEmbedRounds]

theorem c6_blind_hidden_root_census_le_256 :
    c6BlindHiddenRoots ≤ 256 := by
  rw [c6_blind_hidden_root_census]
  norm_num

/-- The two full hidden transcripts use independent repetition challenges.
The terminal batch is included in each repetition's 82-root budget. -/
theorem c6_blind_hidden_two_repetition_card_le
    {Omega0 Omega1 : Type*}
    [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1)
    (h0 : bad0.card ≤ c6BlindHiddenRoots)
    (h1 : bad1.card ≤ c6BlindHiddenRoots) :
    (c6IndependentPairAccepting bad0 bad1).card
      ≤ c6BlindHiddenRoots ^ 2 := by
  simpa using c6_independent_pair_accepting_card_le bad0 bad1 h0 h1

theorem c6_blind_hidden_numerator :
    c6BlindHiddenNumerator = 6725 := by
  norm_num [c6BlindHiddenNumerator, c6BlindHiddenRoots,
    c6BlindHiddenDegreeRoots, c6BlindHiddenTerminalRoots,
    c6BlindHiddenWeightsRounds, c6BlindHiddenEmbedRounds]

theorem c6_blind_hidden_plus_link_numerator :
    c6BlindHiddenPlusLinkNumerator = 26606 := by
  norm_num [c6BlindHiddenPlusLinkNumerator, c6BlindHiddenNumerator,
    c6BlindHiddenRoots, c6BlindHiddenDegreeRoots,
    c6BlindHiddenTerminalRoots, c6BlindHiddenWeightsRounds,
    c6BlindHiddenEmbedRounds, c6PackedLinkTwoRepetitionNumerator,
    c6PackedLinkRoots, c6PackedLinkRelationCount, c6PackedLinkRounds]

theorem c6_blind_hidden_plus_link_numerator_le_2_pow_16 :
    c6BlindHiddenPlusLinkNumerator < 2 ^ 16 := by
  rw [c6_blind_hidden_plus_link_numerator]
  norm_num

end VoltaZk

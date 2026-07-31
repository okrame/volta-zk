import VoltaZk.C6HiddenUBlindTranscript
import VoltaZk.C6PersistentCache
import Mathlib.Tactic

/-!
# C6 PCS-native persistent cache descendant

This additive module records the dual-root cache amendment without changing
the historical single-cache-root C6 certificates.  A persistent cache state
uses a response-independent PCS descriptor, while the outer certificate binds
the ordered predecessor/successor roles and their dynamic head fields.

The concrete PCS binding assumption remains an explicit `Function.Injective`
hypothesis.  No hash or collision-resistance axiom is introduced here.
-/

namespace VoltaZk

/-- Static fields that make a PCS cache-state commitment reusable when a
successor becomes the next certificate's predecessor.  Dynamic response
fields are deliberately absent from this type. -/
structure C6PcsCacheStaticDescriptor (Digest : Type*) where
  protocolDigest : Digest
  modelDigest : Digest
  paramsDigest : Digest
  profileDigest : Digest
  slot : Fin 8
deriving DecidableEq

def c6CacheLayers : Nat := 12
def c6CacheCapacityTokens : Nat := 1024
def c6CacheWidth : Nat := 768
def c6CachePaddedLayers : Nat := 16
def c6CachePaddedWidth : Nat := 1024

def c6CacheLiveEntries : Nat :=
  c6CacheLayers * c6CacheCapacityTokens * c6CacheWidth

def c6CacheSlotCapacity : Nat := 2 ^ 24

def c6CachePaddedEntries : Nat :=
  c6CachePaddedLayers * c6CacheCapacityTokens * c6CachePaddedWidth

theorem c6_cache_live_entry_census :
    c6CacheLiveEntries = 9437184 := by
  norm_num [c6CacheLiveEntries, c6CacheLayers, c6CacheCapacityTokens,
    c6CacheWidth]

theorem c6_cache_padded_geometry_is_slot_capacity :
    c6CachePaddedEntries = c6CacheSlotCapacity := by
  norm_num [c6CachePaddedEntries, c6CachePaddedLayers,
    c6CacheCapacityTokens, c6CachePaddedWidth, c6CacheSlotCapacity]

theorem c6_cache_live_entries_fit_slot :
    c6CacheLiveEntries ≤ c6CacheSlotCapacity := by
  norm_num [c6CacheLiveEntries, c6CacheLayers, c6CacheCapacityTokens,
    c6CacheWidth, c6CacheSlotCapacity]

/-- The PCS-native refinement is the existing append transition plus the
public GPT-2 context-cap condition. -/
def C6PcsCacheTransitionValid {Value Digest : Type*}
    (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value) : Prop :=
  transition.Valid commit oldHead newHead
    ∧ newHead.cacheLen ≤ c6CacheCapacityTokens

/-- A PCS-native accepted transition still refines to the exact append
semantics; the commitment mechanism does not weaken the state relation. -/
theorem c6_pcs_cache_transition_refines_append
    {Value Digest : Type*}
    (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value)
    (h : C6PcsCacheTransitionValid commit oldHead newHead transition) :
    transition.newCache = transition.oldCache ++ transition.newSlab := by
  exact C6CacheTransition.append_only commit oldHead newHead transition h.1

theorem c6_pcs_cache_transition_respects_context_cap
    {Value Digest : Type*}
    (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value)
    (h : C6PcsCacheTransitionValid commit oldHead newHead transition) :
    newHead.cacheLen ≤ 1024 := by
  simpa [c6CacheCapacityTokens] using h.2

/-- Conditioned on commitment binding, one accepted predecessor and one
authenticated output slab determine a unique concrete successor cache. -/
theorem c6_pcs_cache_successor_unique
    {Value Digest : Type*}
    (commit : List Value → Digest)
    (hbind : Function.Injective commit)
    (oldHead newHead₁ newHead₂ : C6CacheHead Digest)
    (transition₁ transition₂ : C6CacheTransition Value)
    (h₁ : C6PcsCacheTransitionValid commit oldHead newHead₁ transition₁)
    (h₂ : C6PcsCacheTransitionValid commit oldHead newHead₂ transition₂)
    (hslab : transition₁.newSlab = transition₂.newSlab) :
    transition₁.newCache = transition₂.newCache := by
  have hold : transition₁.oldCache = transition₂.oldCache :=
    C6CacheTransition.old_cache_unique commit hbind oldHead newHead₁ newHead₂
      transition₁ transition₂ h₁.1 h₂.1
  rw [c6_pcs_cache_transition_refines_append commit oldHead newHead₁
      transition₁ h₁,
    c6_pcs_cache_transition_refines_append commit oldHead newHead₂
      transition₂ h₂,
    hold, hslab]

def c6PersistentCacheRounds : Nat := 24
def c6PersistentCacheDegree : Nat := 2
def c6PersistentCacheRelationRoots : Nat := 3
def c6PersistentCacheKvBatchRoots : Nat := 1
def c6PersistentCacheTerminalRoots : Nat := 1

def c6PersistentCacheRoots : Nat :=
  c6PersistentCacheDegree * c6PersistentCacheRounds
    + c6PersistentCacheRelationRoots
    + c6PersistentCacheKvBatchRoots
    + c6PersistentCacheTerminalRoots

def c6PersistentCacheTwoRepetitionNumerator : Nat :=
  c6PersistentCacheRoots ^ 2

theorem c6_persistent_cache_root_census :
    c6PersistentCacheRoots = 53 := by
  norm_num [c6PersistentCacheRoots, c6PersistentCacheDegree,
    c6PersistentCacheRounds, c6PersistentCacheRelationRoots,
    c6PersistentCacheKvBatchRoots, c6PersistentCacheTerminalRoots]

theorem c6_persistent_cache_root_census_le_conservative :
    c6PersistentCacheRoots ≤ 2 ^ 32 := by
  rw [c6_persistent_cache_root_census]
  norm_num

theorem c6_persistent_cache_two_repetition_numerator :
    c6PersistentCacheTwoRepetitionNumerator = 2809 := by
  norm_num [c6PersistentCacheTwoRepetitionNumerator,
    c6_persistent_cache_root_census]

theorem c6_persistent_cache_two_repetition_numerator_lt_2_pow_12 :
    c6PersistentCacheTwoRepetitionNumerator < 2 ^ 12 := by
  rw [c6_persistent_cache_two_repetition_numerator]
  norm_num

/-!
The direct layout checkpoint above counted the sumcheck and batching roots
but did not yet instantiate the pointwise transition test.  An unweighted
sum of cell residuals admits cancellation.  The blind adapter therefore
fixes one independent 24-coordinate relation point after all cache and
response-output roots, and proves the equality-weighted residual by the same
24-round degree-two sumcheck.  This adds 24 Schwartz--Zippel roots but no
wire field.
-/

def c6PersistentCacheRelationPointRoots : Nat := 24

def c6PersistentCacheBlindRoots : Nat :=
  c6PersistentCacheRoots + c6PersistentCacheRelationPointRoots

def c6PersistentCacheBlindTwoRepetitionNumerator : Nat :=
  c6PersistentCacheBlindRoots ^ 2

theorem c6_persistent_cache_blind_root_census :
    c6PersistentCacheBlindRoots = 77 := by
  norm_num [c6PersistentCacheBlindRoots,
    c6PersistentCacheRelationPointRoots, c6PersistentCacheRoots,
    c6PersistentCacheDegree, c6PersistentCacheRounds,
    c6PersistentCacheRelationRoots, c6PersistentCacheKvBatchRoots,
    c6PersistentCacheTerminalRoots]

theorem c6_persistent_cache_blind_root_census_le_conservative :
    c6PersistentCacheBlindRoots ≤ 2 ^ 32 := by
  rw [c6_persistent_cache_blind_root_census]
  norm_num

theorem c6_persistent_cache_blind_two_repetition_numerator :
    c6PersistentCacheBlindTwoRepetitionNumerator = 5929 := by
  norm_num [c6PersistentCacheBlindTwoRepetitionNumerator,
    c6_persistent_cache_blind_root_census]

theorem c6_persistent_cache_blind_two_repetition_numerator_lt_2_pow_13 :
    c6PersistentCacheBlindTwoRepetitionNumerator < 2 ^ 13 := by
  rw [c6_persistent_cache_blind_two_repetition_numerator]
  norm_num

theorem c6_persistent_cache_blind_two_repetition_card_le
    {Omega0 Omega1 : Type*}
    [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1)
    (h0 : bad0.card ≤ c6PersistentCacheBlindRoots)
    (h1 : bad1.card ≤ c6PersistentCacheBlindRoots) :
    (c6IndependentPairAccepting bad0 bad1).card
      ≤ c6PersistentCacheBlindTwoRepetitionNumerator := by
  simpa [c6PersistentCacheBlindTwoRepetitionNumerator] using
    (c6_independent_pair_accepting_card_le bad0 bad1 h0 h1)

/-- The two cache-transition repetitions use independent complete challenge
tapes, so their accepting-set numerator squares. -/
theorem c6_persistent_cache_two_repetition_card_le
    {Omega0 Omega1 : Type*}
    [DecidableEq Omega0] [DecidableEq Omega1]
    (bad0 : Finset Omega0) (bad1 : Finset Omega1)
    (h0 : bad0.card ≤ c6PersistentCacheRoots)
    (h1 : bad1.card ≤ c6PersistentCacheRoots) :
    (c6IndependentPairAccepting bad0 bad1).card
      ≤ c6PersistentCacheTwoRepetitionNumerator := by
  simpa [c6PersistentCacheTwoRepetitionNumerator] using
    (c6_independent_pair_accepting_card_le bad0 bad1 h0 h1)

/-- Descendant packed-link geometry after adding the predecessor cache-state
cohort.  The historical 64-relation specialization remains unchanged. -/
def c6PersistentPackedLinkRelationCount : Nat := 72
def c6PersistentPackedLinkRounds : Nat := 25

def c6PersistentPackedLinkRoots : Nat :=
  c6PersistentPackedLinkRelationCount + 3 * c6PersistentPackedLinkRounds + 2

def c6PersistentPackedLinkTwoRepetitionNumerator : Nat :=
  c6PersistentPackedLinkRoots ^ 2

def c6BlindHiddenPlusPersistentLinkNumerator : Nat :=
  c6BlindHiddenNumerator + c6PersistentPackedLinkTwoRepetitionNumerator

theorem c6_persistent_packed_link_root_census :
    c6PersistentPackedLinkRoots = 149 := by
  norm_num [c6PersistentPackedLinkRoots,
    c6PersistentPackedLinkRelationCount, c6PersistentPackedLinkRounds]

theorem c6_persistent_packed_link_two_repetition_numerator :
    c6PersistentPackedLinkTwoRepetitionNumerator = 22201 := by
  norm_num [c6PersistentPackedLinkTwoRepetitionNumerator,
    c6_persistent_packed_link_root_census]

theorem c6_blind_hidden_plus_persistent_link_numerator :
    c6BlindHiddenPlusPersistentLinkNumerator = 28926 := by
  norm_num [c6BlindHiddenPlusPersistentLinkNumerator,
    c6BlindHiddenNumerator, c6BlindHiddenRoots,
    c6BlindHiddenDegreeRoots, c6BlindHiddenTerminalRoots,
    c6BlindHiddenWeightsRounds, c6BlindHiddenEmbedRounds,
    c6PersistentPackedLinkTwoRepetitionNumerator,
    c6PersistentPackedLinkRoots, c6PersistentPackedLinkRelationCount,
    c6PersistentPackedLinkRounds]

theorem c6_blind_hidden_plus_persistent_link_numerator_lt_2_pow_15 :
    c6BlindHiddenPlusPersistentLinkNumerator < 2 ^ 15 := by
  rw [c6_blind_hidden_plus_persistent_link_numerator]
  norm_num

/-- Exact descendant specialization of the existing different-point batch
theorem.  Fixed-before-batching and common-point ownership remain explicit
hypotheses. -/
theorem c6_persistent_packed_authenticated_output_link_sound
    {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    (claims : DifferentPointBatchReduction F
      c6PersistentPackedLinkRelationCount c6PersistentPackedLinkRounds ι)
    (points : Fin c6PersistentPackedLinkRelationCount →
      Fin c6PersistentPackedLinkRounds → F)
    (commonPoint : Fin c6PersistentPackedLinkRounds → F)
    (hfixed : MaskedClaimsFixed claims)
    (hcommon : HasCommonPoint points commonPoint) :
    x4ReductionBadTapeCard
        (by norm_num [c6PersistentPackedLinkRounds]) claims
      ≤ c6PersistentPackedLinkRoots *
        x4FieldTapeCard F c6PersistentPackedLinkRounds := by
  have h := folding_different_point_batch_sound
    (F := F) (ι := ι)
    (claimCount := c6PersistentPackedLinkRelationCount)
    (rounds := c6PersistentPackedLinkRounds)
    (by norm_num [c6PersistentPackedLinkRounds])
    claims points commonPoint hfixed
    (by norm_num [c6PersistentPackedLinkRelationCount])
    hcommon
    (by norm_num [c6PersistentPackedLinkRounds])
  simpa [c6PersistentPackedLinkRoots] using h

end VoltaZk

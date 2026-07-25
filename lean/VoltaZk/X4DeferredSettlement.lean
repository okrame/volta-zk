import VoltaZk.Connection
import VoltaZk.X4FoldingPCSV4

/-!
# X4d deferred settlement (M12)

This file is the statement-first formal boundary for one deferred X4d
settlement.  It is deliberately a thin composition layer:

* accumulator and range binding are deterministic, conditional only on the
  same explicit collision-free premise used by the X4 commitment boundary;
* frozen per-response claims reuse `PCSOpening` and its M9 bad event;
* settlement soundness reuses the four audited v4 events and
  `x4ResponseErrorV4` without copying or changing the expression;
* connection composition reuses M10's fixed-rest lift and an ordinary union
  bound, never independence.

Durable journal I/O, BLAKE3 collision resistance and process crash/burn are
implementation obligations, not Lean axioms.
-/

namespace VoltaZk

open Finset

noncomputable local instance x4dPropDecidable (p : Prop) : Decidable p :=
  Classical.propDecidable p

/-! ## Frozen constants and canonical grouping -/

def x4dClaimCap : Nat := 3320

def x4dMaskedGroupCap : Nat := 1660

def x4dQueryCount : Nat := x4V4QueryCount

theorem x4d_claim_cap_is_v4_cap : x4dClaimCap = 3320 := rfl

theorem x4d_query_count_is_v4_query_count : x4dQueryCount = 111 := rfl

/-- Canonical X4d grouping has exactly two frozen claims per masked group.
Active chain polynomials are selected from those canonical claim slots, so
their cardinality cannot exceed the raw claim count. -/
structure X4dCanonicalGrouping where
  groupCount : Nat
  activePolySlots : Finset (Fin (2 * groupCount))

def X4dCanonicalGrouping.claimCount (grouping : X4dCanonicalGrouping) : Nat :=
  2 * grouping.groupCount

def X4dCanonicalGrouping.relationCount
    (grouping : X4dCanonicalGrouping) : Nat :=
  2 * grouping.groupCount

def X4dCanonicalGrouping.activePolys
    (grouping : X4dCanonicalGrouping) : Nat :=
  grouping.activePolySlots.card

/-- Semantic bridge required by M12: the runtime claim cap, the
authenticated-link relation cap and the v4 active-polynomial hypothesis are
the same bound because all three are derived from one canonical grouping. -/
theorem x4d_claim_cap_implies_v4_bounds
    (grouping : X4dCanonicalGrouping)
    (hclaims : grouping.claimCount ≤ x4dClaimCap) :
    grouping.groupCount ≤ x4dMaskedGroupCap ∧
      grouping.relationCount ≤ 3320 ∧
      grouping.activePolys ≤ 3320 := by
  have hactive :
      grouping.activePolySlots.card ≤ 2 * grouping.groupCount := by
    have h := card_le_univ grouping.activePolySlots
    simpa using h
  simp only [X4dCanonicalGrouping.claimCount,
    X4dCanonicalGrouping.relationCount,
    X4dCanonicalGrouping.activePolys, x4dClaimCap,
    x4dMaskedGroupCap] at hclaims ⊢
  omega

def x4dCanAppendClaims (pending incoming : Nat) : Prop :=
  pending + incoming ≤ x4dClaimCap

theorem x4d_claim_3321_refused :
    ¬ x4dCanAppendClaims 3320 1 := by
  norm_num [x4dCanAppendClaims, x4dClaimCap]

/-! ## Digest-chained accumulator and exact settlement range -/

structure X4dFrozenClaimIdentity (F : Type*) where
  connectionId : Nat
  responseNonce : Nat
  blockId : Nat
  evaluationPoint : List F
  authenticatedValueHandle : X4Digest
  claimIndex : Nat
  deriving DecidableEq

structure X4dAccumulatorPreimage (F : Type*) where
  priorDigest : X4Digest
  claim : X4dFrozenClaimIdentity F
  deriving DecidableEq

structure X4dAccumulatorHash (F : Type*) where
  digest : X4dAccumulatorPreimage F → X4Digest

noncomputable def X4dAccumulatorCollisionFreeOn
    {F : Type*} [DecidableEq F]
    (H : X4dAccumulatorHash F)
    (committedEntries : Finset (X4dAccumulatorPreimage F)) : Prop :=
  ∀ a ∈ committedEntries, ∀ b ∈ committedEntries,
    H.digest a = H.digest b → a = b

def x4dAppendDigest {F : Type*}
    (H : X4dAccumulatorHash F) (priorDigest : X4Digest)
    (claim : X4dFrozenClaimIdentity F) : X4Digest :=
  H.digest ⟨priorDigest, claim⟩

/-- Two admitted appends with the same prior digest and ending digest bind
the complete frozen claim entry. -/
theorem x4d_accumulator_append_binding
    {F : Type*} [DecidableEq F]
    (H : X4dAccumulatorHash F)
    (committedEntries : Finset (X4dAccumulatorPreimage F))
    (priorDigest : X4Digest)
    (claimA claimB : X4dFrozenClaimIdentity F)
    (hhash : X4dAccumulatorCollisionFreeOn H committedEntries)
    (ha : X4dAccumulatorPreimage.mk priorDigest claimA ∈ committedEntries)
    (hb : X4dAccumulatorPreimage.mk priorDigest claimB ∈ committedEntries)
    (hdigest :
      x4dAppendDigest H priorDigest claimA =
        x4dAppendDigest H priorDigest claimB) :
    claimA = claimB := by
  have hpre : X4dAccumulatorPreimage.mk priorDigest claimA =
      X4dAccumulatorPreimage.mk priorDigest claimB :=
    hhash _ ha _ hb hdigest
  exact congrArg X4dAccumulatorPreimage.claim hpre

structure X4dAccumulator (F : Type*) where
  entries : List (X4dFrozenClaimIdentity F)

structure X4dSettlementRange (F : Type*) where
  firstClaimIndex : Nat
  claimCount : Nat
  claims : List (X4dFrozenClaimIdentity F)

def x4dOrderedPendingClaimUnion {F : Type*}
    (accumulator : X4dAccumulator F) (range : X4dSettlementRange F) :
    List (X4dFrozenClaimIdentity F) :=
  (accumulator.entries.drop range.firstClaimIndex).take range.claimCount

/-- The verifier accepts a range only when both role journals agree and the
proof carries exactly the locally reconstructed contiguous union. -/
def VerifyX4dSettlementRange {F : Type*}
    (proverAccumulator verifierAccumulator : X4dAccumulator F)
    (range : X4dSettlementRange F) : Prop :=
  proverAccumulator.entries = verifierAccumulator.entries ∧
    range.claims = x4dOrderedPendingClaimUnion verifierAccumulator range

theorem x4d_settlement_range_is_exact_union
    {F : Type*}
    (proverAccumulator verifierAccumulator : X4dAccumulator F)
    (range : X4dSettlementRange F)
    (haccept :
      VerifyX4dSettlementRange proverAccumulator verifierAccumulator range) :
    range.claims =
      x4dOrderedPendingClaimUnion verifierAccumulator range :=
  haccept.2

theorem x4d_settlement_range_roles_agree
    {F : Type*}
    (proverAccumulator verifierAccumulator : X4dAccumulator F)
    (range : X4dSettlementRange F)
    (haccept :
      VerifyX4dSettlementRange proverAccumulator verifierAccumulator range) :
    proverAccumulator.entries = verifierAccumulator.entries :=
  haccept.1

/-! ## Frozen M9 claims -/

structure X4dFrozenMacClaim (F Omega : Type*) where
  identity : X4dFrozenClaimIdentity F
  opening : PCSOpening F Omega

structure X4dFrozenResponse (F Omega : Type*) where
  claims : List (X4dFrozenMacClaim F Omega)

noncomputable def X4dFrozenClaimMacBad
    {F Omega : Type*} [Fintype Omega]
    (claim : X4dFrozenMacClaim F Omega) : Finset Omega :=
  univ.filter fun omega =>
    claim.opening.accept omega ∧
      (claim.opening.out omega).1 ≠ claim.opening.eval

def X4dResponseM9OpeningIntoMac
    {F Omega : Type*}
    (response : X4dFrozenResponse F Omega) (omega : Omega) : Prop :=
  ∀ claim ∈ response.claims,
    claim.opening.accept omega →
      (claim.opening.out omega).1 = claim.opening.eval

noncomputable def X4dFrozenClaimMacBadForResponse
    {F Omega : Type*} [Fintype Omega]
    (response : X4dFrozenResponse F Omega) : Finset Omega :=
  univ.filter fun omega =>
    ∃ claim ∈ response.claims,
      claim.opening.accept omega ∧
        (claim.opening.out omega).1 ≠ claim.opening.eval

/-- A response's frozen handles either retain every M9 opening-into-MAC
statement or expose the already-counted per-response MAC event. -/
theorem x4d_frozen_response_m9_or_mac_bad
    {F Omega : Type*} [Fintype Omega]
    (response : X4dFrozenResponse F Omega) (omega : Omega) :
    X4dResponseM9OpeningIntoMac response omega ∨
      omega ∈ X4dFrozenClaimMacBadForResponse response := by
  classical
  by_cases hgood : X4dResponseM9OpeningIntoMac response omega
  · exact Or.inl hgood
  · right
    simp only [X4dFrozenClaimMacBadForResponse, mem_filter, mem_univ,
      true_and]
    simp only [X4dResponseM9OpeningIntoMac] at hgood
    push Not at hgood
    exact hgood

theorem x4d_frozen_claim_bad_card_le
    {F Omega : Type*} [Fintype Omega]
    (claim : X4dFrozenMacClaim F Omega) {epsPCS : Nat}
    (hbind : claim.opening.BindsIntoMac epsPCS) :
    (X4dFrozenClaimMacBad claim).card ≤ epsPCS := by
  simpa [X4dFrozenClaimMacBad, PCSOpening.BindsIntoMac] using hbind

/-- The quantitative freeze argument is exactly M9, not a new assumption. -/
theorem x4d_frozen_claim_opening_mac_sound
    {F Omega : Type*} [Field F] [Fintype F] [DecidableEq F]
    [Fintype Omega]
    (claim : X4dFrozenMacClaim F Omega) {epsPCS : Nat}
    (hbind : claim.opening.BindsIntoMac epsPCS)
    (sigmaM : F × F) (hsigma : sigmaM.1 ≠ claim.opening.eval)
    (msg : Omega → F) :
    (univ.filter fun tape : Omega × F =>
        claim.opening.accept tape.1 ∧
          msg tape.1 =
            keyOf tape.2 (sigmaM - claim.opening.out tape.1)).card
      ≤ epsPCS * Fintype.card F + Fintype.card Omega :=
  claim.opening.opening_mac_sound hbind sigmaM hsigma msg

/-! ## One batched auxiliary mask -/

/-- Simultaneous MLE evaluation at every frozen response-local point. -/
noncomputable def x4dBatchedMleMap
    {F : Type*} [Field F] {ell pointCount : Nat}
    (points : Fin pointCount → Fin ell → F) :
    (((Fin ell → Fin 2) → F) →ₗ[F] (Fin pointCount → F)) :=
  LinearMap.pi fun point => x4MleLinear (points point)

private def x4dLinearFiberEquivKer
    {F V W : Type*} [Field F]
    [AddCommGroup V] [Module F V] [AddCommGroup W] [Module F W]
    (f : V →ₗ[F] W) (target : W) (witness : V)
    (hwitness : f witness = target) :
    {x : V // f x = target} ≃ LinearMap.ker f where
  toFun x := ⟨x.1 - witness, by simp [x.2, hwitness]⟩
  invFun k := ⟨witness + k.1, by simp [hwitness]⟩
  left_inv x := by ext; simp
  right_inv k := by ext; simp

private theorem x4d_has_authenticated_link_view
    {F coefficient : Type*} [Field F] [Fintype coefficient]
    {corrCount : Nat}
    (Delta : F) (g : coefficient → F)
    (fixedView : AuthenticatedLinkCorrView F corrCount) :
    HasAuthenticatedLinkView Delta g fixedView := by
  classical
  refine ⟨fun i =>
    (corrCorrectionEquiv Delta (x4AuthenticatedLinkSecret g i)).symm
      (fixedView i), ?_⟩
  intro i
  exact (corrCorrectionEquiv Delta
    (x4AuthenticatedLinkSecret g i)).apply_symm_apply (fixedView i)

private def x4dBatchedViewFiberEquiv
    {F coefficient target : Type*} [Field F] [Fintype coefficient]
    [AddCommGroup target] [Module F target]
    {corrCount : Nat}
    (f : (coefficient → F) →ₗ[F] target) (value : target)
    (Delta : F) (fixedView : AuthenticatedLinkCorrView F corrCount) :
    {g : coefficient → F //
      f g = value ∧ HasAuthenticatedLinkView Delta g fixedView} ≃
      {g : coefficient → F // f g = value} where
  toFun g := ⟨g.1, g.2.1⟩
  invFun g := ⟨g.1, g.2,
    x4d_has_authenticated_link_view Delta g.1 fixedView⟩
  left_inv g := by apply Subtype.ext; rfl
  right_inv g := by apply Subtype.ext; rfl

/-- Fixing `m` response-local evaluations removes at most `m` dimensions
from one settlement mask.  The correction view removes none because its
one-time mask map is bijective for every coefficient table. -/
theorem x4d_batched_mask_fiber_lower_bound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {ell pointCount corrCount : Nat}
    (points : Fin pointCount → Fin ell → F)
    (target : Fin pointCount → F)
    (witness : (Fin ell → Fin 2) → F)
    (hwitness : x4dBatchedMleMap points witness = target)
    (Delta : F) (fixedView : AuthenticatedLinkCorrView F corrCount) :
    Fintype.card F ^ (2^ell - pointCount) ≤
      Fintype.card
        {g : (Fin ell → Fin 2) → F //
          x4dBatchedMleMap points g = target ∧
            HasAuthenticatedLinkView Delta g fixedView} := by
  classical
  let f := x4dBatchedMleMap points
  let viewEquiv := x4dBatchedViewFiberEquiv f target Delta fixedView
  rw [Fintype.card_congr viewEquiv]
  let kerEquiv := x4dLinearFiberEquivKer f target witness hwitness
  rw [Fintype.card_congr kerEquiv]
  have hkerCard :
      Fintype.card (LinearMap.ker f) =
        Fintype.card F ^ Module.finrank F (LinearMap.ker f) :=
    Module.card_eq_pow_finrank (K := F)
  rw [hkerCard]
  apply Nat.pow_le_pow_right Fintype.card_pos
  have hrange :
      Module.finrank F (LinearMap.range f) ≤ pointCount := by
    calc
      Module.finrank F (LinearMap.range f)
          ≤ Module.finrank F (Fin pointCount → F) :=
        Submodule.finrank_le _
      _ = pointCount := by
        rw [Module.finrank_pi F, Fintype.card_fin]
  have hrankKer := f.finrank_range_add_finrank_ker
  have hdomain :
      Module.finrank F ((Fin ell → Fin 2) → F) = 2^ell := by
    rw [Module.finrank_pi F, Fintype.card_fun, Fintype.card_fin,
      Fintype.card_fin]
  rw [hdomain] at hrankKer
  omega

def x4dGpt2AuxEll (mu : Nat) : Nat :=
  if mu = 26 then 17 else 16

theorem x4d_gpt2_mask_budget
    {mu pointCount : Nat}
    (hmu : mu = 20 ∨ mu = 22 ∨ mu = 26)
    (hpoints : pointCount ≤ 32) :
    111 * mu^2 < 2^(x4dGpt2AuxEll mu) - pointCount := by
  rcases hmu with rfl | rfl | rfl <;>
    norm_num [x4dGpt2AuxEll] <;> omega

/-! ## Settlement events and M12 composition -/

structure X4dSettlementM12
    (F Omega : Type*) [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    (blockCount responseCount : Nat) where
  pcs : AuthenticatedOutputBatch F Omega blockCount
  responses : Fin responseCount → X4dFrozenResponse F Omega
  range : X4dSettlementRange F

def X4dSettlementM12.frozenClaimIdentities
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount) :
    List (X4dFrozenClaimIdentity F) :=
  (List.ofFn settlement.responses).flatMap fun response =>
    response.claims.map X4dFrozenMacClaim.identity

def X4dExactPendingClaimUnion
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount) : Prop :=
  settlement.range.claims = settlement.frozenClaimIdentities

theorem x4d_verified_settlement_has_exact_frozen_union
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (proverAccumulator verifierAccumulator : X4dAccumulator F)
    (settlement : X4dSettlementM12 F Omega blockCount responseCount)
    (hrange : VerifyX4dSettlementRange proverAccumulator
      verifierAccumulator settlement.range)
    (hunion : X4dExactPendingClaimUnion settlement) :
    settlement.frozenClaimIdentities =
      x4dOrderedPendingClaimUnion verifierAccumulator settlement.range := by
  rw [← hunion]
  exact x4d_settlement_range_is_exact_union
    proverAccumulator verifierAccumulator settlement.range hrange

noncomputable def X4dSettlementResponseMacBad
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount) :
    Finset Omega :=
  univ.biUnion fun response =>
    X4dFrozenClaimMacBadForResponse (settlement.responses response)

noncomputable def X4dAcceptsWrongCoveredResponse
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount) :
    Finset Omega :=
  X4AcceptsWrongResponseV4 settlement.pcs ∪
    X4dSettlementResponseMacBad settlement

/-- Per covered response, accepted settlement yields its M9 statement or one
of the already-inventoried MAC/fold/claim/link/ZeroBatch events. -/
theorem x4d_accepted_settlement_implies_each_m9_or_bad
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount)
    (omega : Omega) (_haccept : X4ResponseAcceptsV4 settlement.pcs omega)
    (_hunion : X4dExactPendingClaimUnion settlement)
    (response : Fin responseCount) :
    X4dResponseM9OpeningIntoMac (settlement.responses response) omega ∨
      omega ∈
        X4dFrozenClaimMacBadForResponse
          (settlement.responses response) ∨
      omega ∈ X4FoldBadV4 settlement.pcs ∨
      omega ∈ X4ClaimReduceBadV4 settlement.pcs ∨
      omega ∈ X4AuthenticatedOutputLinkBadV4 settlement.pcs ∨
      omega ∈ X4ResponseZeroBatchBad settlement.pcs := by
  rcases x4d_frozen_response_m9_or_mac_bad
      (settlement.responses response) omega with hgood | hbad
  · exact Or.inl hgood
  · exact Or.inr (Or.inl hbad)

/-- M12 aliases the audited v4 expression; there is one source of truth. -/
def x4dSettlementError : ℚ := x4ResponseErrorV4

theorem x4d_settlement_error_is_v4 :
    x4dSettlementError = x4ResponseErrorV4 := rfl

theorem x4d_settlement_error_expanded :
    x4dSettlementError =
      (3320 : ℚ) * ((9 : ℚ) / 16)^111 +
      (28522064267253 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ) := rfl

private theorem x4d_two_event_union_error
    {Omega : Type*} [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    (a b : Finset Omega) :
    statisticalError (a ∪ b) ≤
      statisticalError a + statisticalError b := by
  change (((a ∪ b).card : Nat) : ℚ) / Fintype.card Omega ≤
    (a.card : ℚ) / Fintype.card Omega +
      (b.card : ℚ) / Fintype.card Omega
  have hcard : (((a ∪ b).card : Nat) : ℚ) ≤ a.card + b.card := by
    exact_mod_cast card_union_le a b
  rw [← add_div]
  exact div_le_div_of_nonneg_right hcard (by positivity)

theorem x4d_response_mac_union_error_le_sum
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount) :
    statisticalError (X4dSettlementResponseMacBad settlement) ≤
      ∑ response : Fin responseCount,
        statisticalError
          (X4dFrozenClaimMacBadForResponse
            (settlement.responses response)) := by
  have hcard :
      (X4dSettlementResponseMacBad settlement).card ≤
        ∑ response : Fin responseCount,
          (X4dFrozenClaimMacBadForResponse
            (settlement.responses response)).card := by
    exact Finset.card_biUnion_le
  have hcardQ :
      ((X4dSettlementResponseMacBad settlement).card : ℚ) ≤
        ∑ response : Fin responseCount,
          ((X4dFrozenClaimMacBadForResponse
            (settlement.responses response)).card : ℚ) := by
    exact_mod_cast hcard
  change
    ((X4dSettlementResponseMacBad settlement).card : ℚ) /
        Fintype.card Omega ≤
      ∑ response : Fin responseCount,
        ((X4dFrozenClaimMacBadForResponse
          (settlement.responses response)).card : ℚ) /
            Fintype.card Omega
  rw [← Finset.sum_div]
  exact div_le_div_of_nonneg_right hcardQ (by positivity)

/-- Union algebra once the audited v4 four-event theorem has supplied its
exact response-wide certificate.  The public M12 theorem below constructs
that certificate from every named v4 counter; callers cannot posit it in
place of the counter inventory. -/
private theorem x4d_settlement_soundness_of_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount)
    (_hunion : X4dExactPendingClaimUnion settlement)
    (_hcap : settlement.frozenClaimIdentities.length ≤ x4dClaimCap)
    (hv4 : statisticalError
        (X4AcceptsWrongResponseV4 settlement.pcs) ≤ x4dSettlementError) :
    statisticalError (X4dAcceptsWrongCoveredResponse settlement) ≤
      x4dSettlementError +
        ∑ response : Fin responseCount,
          statisticalError
            (X4dFrozenClaimMacBadForResponse
              (settlement.responses response)) := by
  calc
    statisticalError (X4dAcceptsWrongCoveredResponse settlement)
        ≤ statisticalError (X4AcceptsWrongResponseV4 settlement.pcs) +
            statisticalError (X4dSettlementResponseMacBad settlement) :=
      x4d_two_event_union_error
        (X4AcceptsWrongResponseV4 settlement.pcs)
        (X4dSettlementResponseMacBad settlement)
    _ ≤ x4dSettlementError +
          statisticalError (X4dSettlementResponseMacBad settlement) :=
      add_le_add hv4 (le_refl _)
    _ ≤ x4dSettlementError +
          ∑ response : Fin responseCount,
            statisticalError
              (X4dFrozenClaimMacBadForResponse
                (settlement.responses response)) :=
      add_le_add (le_refl _)
        (x4d_response_mac_union_error_le_sum
          (F := F) (Omega := Omega) (blockCount := blockCount)
          (responseCount := responseCount) settlement)

/-- M12 settlement soundness with the complete v4 LinkBad inventory exposed:
Fold, ClaimReduce, authenticated-output LinkBad and ZeroBatch are all
required with their frozen coefficients.  No fifth event, equality premise
or uncounted failure is introduced. -/
theorem x4d_settlement_soundness_m12
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {blockCount responseCount : Nat}
    (settlement : X4dSettlementM12 F Omega blockCount responseCount)
    (hunion : X4dExactPendingClaimUnion settlement)
    (hcap : settlement.frozenClaimIdentities.length ≤ x4dClaimCap)
    (hcover : X4WrongResponseCoveredByNamedEventsV4 settlement.pcs)
    (hfold : statisticalError (X4FoldBadV4 settlement.pcs) ≤
      (3320 : ℚ) * ((9 : ℚ) / 16) ^ 111 +
      (28522064111120 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hclaim : statisticalError (X4ClaimReduceBadV4 settlement.pcs) ≤
      (151060 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hlink :
      statisticalError
          (X4AuthenticatedOutputLinkBadV4 settlement.pcs) ≤
        (3412 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ))
    (hzero : statisticalError
        (X4ResponseZeroBatchBad settlement.pcs) ≤
      (1661 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ)) :
    statisticalError (X4dAcceptsWrongCoveredResponse settlement) ≤
      x4dSettlementError +
        ∑ response : Fin responseCount,
          statisticalError
            (X4dFrozenClaimMacBadForResponse
              (settlement.responses response)) := by
  have hv4Raw := x4_response_soundness_v4
    (F := F) (Omega := Omega) (blockCount := blockCount)
    settlement.pcs hcover hfold hclaim hlink hzero
  have hv4 :
      statisticalError (X4AcceptsWrongResponseV4 settlement.pcs) ≤
        x4dSettlementError := by
    rw [x4d_settlement_error_is_v4]
    exact hv4Raw
  exact x4d_settlement_soundness_of_v4
    (F := F) (Omega := Omega) (blockCount := blockCount)
    (responseCount := responseCount) settlement hunion hcap hv4

/-- Ordinary connection union bound over accepted settlements.  The MAC term
for one settlement is itself the sum over its covered responses. -/
theorem x4d_connection_composition_m12
    {Omega : Type*} [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {settlementCount : Nat}
    (bad : Fin settlementCount → Finset Omega)
    (settlementMacTerms : Fin settlementCount → ℚ)
    (hper : ∀ settlement,
      statisticalError (bad settlement) ≤
        x4dSettlementError + settlementMacTerms settlement) :
    statisticalError (univ.biUnion bad) ≤
      settlementCount * x4dSettlementError +
        ∑ settlement, settlementMacTerms settlement := by
  have hcard : (univ.biUnion bad).card ≤ ∑ settlement, (bad settlement).card :=
    Finset.card_biUnion_le
  have hunion :
      statisticalError (univ.biUnion bad) ≤
        ∑ settlement, statisticalError (bad settlement) := by
    have hcardQ :
        (((univ.biUnion bad).card : Nat) : ℚ) ≤
          ∑ settlement, ((bad settlement).card : ℚ) := by
      exact_mod_cast hcard
    change (((univ.biUnion bad).card : Nat) : ℚ) / Fintype.card Omega ≤
      ∑ settlement, ((bad settlement).card : ℚ) / Fintype.card Omega
    rw [← Finset.sum_div]
    exact div_le_div_of_nonneg_right hcardQ (by positivity)
  calc
    statisticalError (univ.biUnion bad)
        ≤ ∑ settlement, statisticalError (bad settlement) := hunion
    _ ≤ ∑ settlement,
          (x4dSettlementError + settlementMacTerms settlement) :=
      Finset.sum_le_sum fun settlement _ => hper settlement
    _ = settlementCount * x4dSettlementError +
          ∑ settlement, settlementMacTerms settlement := by
      simp [Finset.sum_add_distrib, mul_comm]

/-- Explicit M10 reuse: fixed-rest local bounds lift to a shared-Delta
connection tape without any independence assumption. -/
theorem x4d_connection_fixed_slice_lift_m10
    {Delta Xi : Type*}
    [Fintype Delta] [Fintype Xi] [DecidableEq Delta] [DecidableEq Xi]
    {n bound : Nat}
    (bad : Fin (n + 1) → Finset (Delta × (Fin (n + 1) → Xi)))
    (hslice : ∀ response (rest : Fin n → Xi),
      (univ.filter fun localTape : Delta × Xi =>
        responseTapeEquiv response (localTape, rest) ∈ bad response).card ≤
          bound) :
    (univ.biUnion bad).card ≤
      (n + 1) * bound * Fintype.card Xi ^ n :=
  connection_soundness_union_bound bad hslice

/-! ## One settlement epoch and terminal product state -/

theorem x4d_one_settlement_opening_per_epoch
    (st st1 st2 : X4OpeningState) (epoch : Nat)
    (transcript1 transcript2 : List X4Byte)
    (hfirst : acceptOpening st epoch transcript1 = some st1)
    (hsecond : acceptOpening st1 epoch transcript2 = some st2) :
    False :=
  one_opening_per_epoch st st1 st2 epoch transcript1 transcript2
    hfirst hsecond

inductive X4dResponseState
  | authorized
  | modelAuthenticated
  | weightPending
  | weightVerified
  | terminalUnverified
  deriving DecidableEq

def X4dWeightAccepted : X4dResponseState → Prop
  | .weightVerified => True
  | _ => False

theorem x4d_pending_never_weight_accepted
    (state : X4dResponseState)
    (hstate : state = .weightPending ∨ state = .terminalUnverified) :
    ¬ X4dWeightAccepted state := by
  rcases hstate with rfl | rfl <;> simp [X4dWeightAccepted]

def x4dAbortResponse : X4dResponseState → X4dResponseState
  | .weightVerified => .weightVerified
  | _ => .terminalUnverified

theorem x4d_abort_pending_is_terminal_unverified :
    x4dAbortResponse .weightPending = .terminalUnverified := rfl

theorem x4d_abort_preserves_older_verified :
    x4dAbortResponse .weightVerified = .weightVerified := rfl

inductive X4dConnectionState
  | open
  | settlementInFlight
  | burned
  deriving DecidableEq

def X4dCanStartSettlement : X4dConnectionState → Prop
  | .open => True
  | _ => False

def x4dSettlementFailed (_state : X4dConnectionState) :
    X4dConnectionState :=
  .burned

theorem x4d_failed_settlement_cannot_retry
    (state : X4dConnectionState) :
    ¬ X4dCanStartSettlement (x4dSettlementFailed state) := by
  simp [x4dSettlementFailed, X4dCanStartSettlement]

/-! ## Exact Phase-1 arithmetic -/

def x4dGpt2ResponseBytes : Nat := 41270464

def x4dGpt2SettlementBytes (responses : Nat) : Nat :=
  2632812 + 50424 * responses

theorem x4d_gpt2_codec_preflight :
    x4dGpt2ResponseBytes = 41270464 ∧
      x4dGpt2SettlementBytes 1 = 2683236 ∧
      x4dGpt2SettlementBytes 8 = 3036204 ∧
      x4dGpt2SettlementBytes 16 = 3439596 ∧
      x4dGpt2SettlementBytes 32 = 4246380 := by
  norm_num [x4dGpt2ResponseBytes, x4dGpt2SettlementBytes]

theorem x4d_gpt2_cap_geometry :
    102 * 32 = 3264 ∧ 51 * 32 = 1632 ∧
      3264 ≤ x4dClaimCap ∧ 1632 ≤ x4dMaskedGroupCap := by
  norm_num [x4dClaimCap, x4dMaskedGroupCap]

end VoltaZk

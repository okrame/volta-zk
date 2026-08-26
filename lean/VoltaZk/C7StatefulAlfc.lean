import VoltaZk.OpeningMac
import VoltaZk.C6PersistentCache
import VoltaZk.Connection

/-!
# C7 stateful authenticated linear-functional commitment seam

This additive R0 module records only the algebraic and state-machine facts
needed to state C7.  Concrete PCS binding, hash collision resistance, the
finite PCG, transcript completeness, and malicious-designated-verifier
multi-session privacy remain explicit hypotheses outside this module.  In
particular, none of the definitions below is an ideal cryptographic API.
-/

namespace VoltaZk

open Finset

/-! ## One packed functional over canonical disjoint segments -/

/-- The coefficient at packed coordinate `j`.  `owner j = none` is canonical
padding; `owner j = some i` gives the unique segment that owns `j`. -/
def packedFunctional
    {F I J K : Type*} [Semiring F]
    (owner : J → Option I) (localIndex : J → K)
    (beta : I → F) (eqAt : I → K → F) (j : J) : F :=
  match owner j with
  | none => 0
  | some i => beta i * eqAt i (localIndex j)

/-- One terminal claim for segment `i`; padding and all other segments are
absent from this sum. -/
def packedSegmentClaim
    {F I J K : Type*} [Semiring F] [Fintype J] [DecidableEq I]
    (owner : J → Option I) (localIndex : J → K)
    (eqAt : I → K → F) (w : J → F) (i : I) : F :=
  ∑ j ∈ (univ.filter fun j : J => owner j = some i),
    eqAt i (localIndex j) * w j

/-- The packed coefficient vector is exactly one beta-weighted MLE-style
linear claim per canonical segment.  A functional with `owner j = none`
contributes zero, so disjointness and padding are structural rather than a
side condition. -/
theorem packed_functional_eq
    {F I J K : Type*} [CommSemiring F]
    [Fintype I] [Fintype J] [DecidableEq I]
    (owner : J → Option I) (localIndex : J → K)
    (beta : I → F) (eqAt : I → K → F) (w : J → F) :
    (∑ j, packedFunctional owner localIndex beta eqAt j * w j) =
      ∑ i, beta i * packedSegmentClaim owner localIndex eqAt w i := by
  classical
  calc
    (∑ j, packedFunctional owner localIndex beta eqAt j * w j) =
        ∑ j, ∑ i,
          if owner j = some i then beta i * (eqAt i (localIndex j) * w j) else 0 := by
      apply Finset.sum_congr rfl
      intro j _
      cases howner : owner j with
      | none => simp [packedFunctional, howner]
      | some ownerIndex => simp [packedFunctional, howner, mul_assoc]
    _ = ∑ i, ∑ j,
          if owner j = some i then beta i * (eqAt i (localIndex j) * w j) else 0 :=
      Finset.sum_comm
    _ = ∑ i, beta i * packedSegmentClaim owner localIndex eqAt w i := by
      apply Finset.sum_congr rfl
      intro i _
      unfold packedSegmentClaim
      rw [Finset.mul_sum, Finset.sum_filter]

/-! ## Claims fixed before the response-wide batching challenge -/

/-- Commitments, claims, and query descriptions are arguments outside the
filter binder; hence the residual vector is fixed before `beta` is sampled.
The scalar-power RLC has at most `T` roots when one fixed residual is nonzero.
-/
theorem fixed_before_beta_rlc_root
    {F Commitments Claims Queries : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    {T : Nat}
    (_commitments : Commitments) (_claims : Claims) (_queries : Queries)
    (error : Fin T → F) {j₀ : Fin T} (herror : error j₀ ≠ 0) :
    (univ.filter fun beta : F =>
      ∑ j, beta ^ (j.val + 1) * error j = 0).card ≤ T :=
  card_scalarRlc_zero_le error herror

/-! ## One multi-commitment terminal in both Fp2 limbs -/

/-- Componentwise pair batch for one logical terminal over many commitment
planes.  `Fin 2` is the two-limb representation used for an `Fp2` value. -/
def multiCommitTerminalPair
    {F C : Type*} [Semiring F] [Fintype C]
    (coefficient : C → F) (value : C → Fin 2 → F × F) :
    Fin 2 → F × F :=
  fun limb =>
    (∑ c, coefficient c * (value c limb).1,
      ∑ c, coefficient c * (value c limb).2)

/-- Verifier-key projection commutes with the multi-commitment terminal for
each of the two `Fp` limbs. -/
theorem multi_commit_terminal_key_linearity_fp2
    {F C : Type*} [Field F] [Fintype C]
    (Delta : Fin 2 → F) (coefficient : C → F)
    (value : C → Fin 2 → F × F) :
    ∀ limb : Fin 2,
      keyOf (Delta limb) (multiCommitTerminalPair coefficient value limb) =
        ∑ c, coefficient c * keyOf (Delta limb) (value c limb) := by
  intro limb
  unfold multiCommitTerminalPair keyOf
  rw [Finset.mul_sum, ← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro c _
  ring

/-- Componentwise MAC batch corresponding to `multiCommitTerminalPair`. -/
def multiCommitTerminalAuthed
    {F C : Type*} [Field F] [Fintype C]
    (coefficient : C → F) (value : C → Fin 2 → Authed F) :
    Fin 2 → Authed F :=
  fun limb => ∑ c, coefficient c • value c limb

/-- MAC validity is preserved by the same multi-commitment linear batch in
both `Fp` limbs. -/
theorem multi_commit_terminal_mac_linearity_fp2
    {F C : Type*} [Field F] [Fintype C]
    (Delta : Fin 2 → F) (coefficient : C → F)
    (value : C → Fin 2 → Authed F)
    (hvalid : ∀ c limb, (value c limb).Valid (Delta limb)) :
    ∀ limb : Fin 2,
      (multiCommitTerminalAuthed coefficient value limb).Valid (Delta limb) := by
  intro limb
  apply Authed.Valid.sum
  intro c _
  exact (hvalid c limb).smul (coefficient c)

/-! ## Static-mask reuse is extractable -/

/-- Two independent affine folds using the same mask reveal the witness when
their coefficient matrix is invertible. -/
theorem reused_affine_mask_extract
    {F : Type*} [Field F]
    (a b c d W R X₁ X₂ : F)
    (h₁ : X₁ = a * W + b * R) (h₂ : X₂ = c * W + d * R)
    (hdet : a * d - b * c ≠ 0) :
    W = (d * X₁ - b * X₂) / (a * d - b * c) := by
  apply (eq_div_iff hdet).2
  rw [h₁, h₂]
  ring

/-! ## Append-only MLE linear functionals -/

/-- Linear evaluation from a packed offset.  In C7, `q i` is the public MLE
equality weight at canonical coordinate `i`. -/
def mleLinearFrom {F : Type*} [Semiring F]
    (q : Nat → F) : Nat → List F → F
  | _, [] => 0
  | offset, x :: xs => q offset * x + mleLinearFrom q (offset + 1) xs

theorem mleLinearFrom_append
    {F : Type*} [Semiring F]
    (q : Nat → F) (offset : Nat) (old tail : List F) :
    mleLinearFrom q offset (old ++ tail) =
      mleLinearFrom q offset old + mleLinearFrom q (offset + old.length) tail := by
  induction old generalizing offset with
  | nil => simp [mleLinearFrom]
  | cons x xs ih =>
      simp [mleLinearFrom, ih, Nat.add_comm 1 xs.length, add_assoc]

/-- MLE-style evaluation of an appended successor minus the zero-extended
predecessor is exactly the shifted functional of the canonical tail. -/
theorem mle_append_difference
    {F : Type*} [Field F]
    (q : Nat → F) (old tail : List F) :
    mleLinearFrom q 0 (old ++ tail) - mleLinearFrom q 0 old =
      mleLinearFrom q old.length tail := by
  rw [mleLinearFrom_append]
  simp

/-! ## Prefix stability across accepted response transitions -/

/-- Concrete append-prefix relation used by the C7 state seam. -/
def C7PrefixStable {Value : Type*} (old new : List Value) : Prop :=
  ∃ tail, new = old ++ tail

theorem prefix_stability {Value : Type*} (old tail : List Value) :
    C7PrefixStable old (old ++ tail) :=
  ⟨tail, rfl⟩

/-- Sequentially apply the tails of accepted append transitions. -/
def applyAcceptedTails {Value : Type*} :
    List Value → List (List Value) → List Value
  | state, [] => state
  | state, tail :: tails => applyAcceptedTails (state ++ tail) tails

/-- Induction over any finite list of accepted append tails preserves the
original predecessor as a prefix. -/
theorem accepted_append_tails_induction
    {Value : Type*} (old : List Value) (tails : List (List Value)) :
    C7PrefixStable old (applyAcceptedTails old tails) := by
  induction tails generalizing old with
  | nil => exact ⟨[], by simp [applyAcceptedTails]⟩
  | cons tail tails ih =>
      obtain ⟨suffix, hsuffix⟩ := ih (old := old ++ tail)
      refine ⟨tail ++ suffix, ?_⟩
      simp only [applyAcceptedTails]
      rw [hsuffix, List.append_assoc]

/-! ## Atomic promotion, replay, and fork exclusion -/

theorem atomic_promotion_old_or_new
    {Digest Nonce : Type*}
    (old : C6ClientState Digest) (certificate : C6Certificate Digest Nonce)
    (outcome : C6AtomicOutcome old certificate) :
    outcome.state = old ∨ outcome.state = certificate.advance old :=
  c6_atomic_state_is_old_or_new old certificate outcome

theorem atomic_promotion_replay_exclusion
    {Digest Nonce : Type*}
    (state : C6ClientState Digest) (certificate : C6Certificate Digest Nonce)
    (h : certificate.Admissible state) :
    ¬ certificate.Admissible (certificate.advance state) :=
  C6Certificate.accepted_certificate_not_replayable state certificate h

/-- If two certificates name the same accepted predecessor, committing one
prevents the competing fork from being admitted against the promoted head. -/
theorem atomic_promotion_fork_exclusion
    {Digest Nonce : Type*}
    (state : C6ClientState Digest)
    (left right : C6Certificate Digest Nonce)
    (hleft : left.Admissible state) (hright : right.Admissible state) :
    ¬ right.Admissible (left.advance state) := by
  intro hafter
  have hrightNew : right.oldHead = left.newHead := by
    calc
      right.oldHead = (left.advance state).head := hafter.1
      _ = left.newHead := rfl
  have holdNew : left.oldHead = left.newHead :=
    hleft.1.trans (hright.1.symm.trans hrightNew)
  have hepoch := hleft.2.2.1
  rw [holdNew] at hepoch
  omega

/-! ## Connection horizon with one shared Delta -/

/-- Exact `Rmax`-event union bound on a tape whose first coordinate is the
single connection-scoped `Delta`.  No response-independence is assumed. -/
theorem connection_union_bound_with_rmax_shared_delta
    {Delta Xi : Type*}
    [DecidableEq Delta] [DecidableEq Xi]
    {Rmax B : Nat}
    (bad : Fin Rmax → Finset (Delta × (Fin Rmax → Xi)))
    (hresponse : ∀ r, (bad r).card ≤ B) :
    (univ.biUnion bad).card ≤ Rmax * B := by
  simpa using Finset.card_biUnion_le_card_mul univ bad B
    (fun r _ => hresponse r)

/-- Positive-horizon sliced form, directly reusing M10.  Here the exact
connection horizon is `n + 1`; fixing the other responses preserves the same
shared `Delta` in every local slice. -/
theorem connection_sliced_union_bound_shared_delta
    {Delta Xi : Type*}
    [Fintype Delta] [Fintype Xi] [DecidableEq Delta] [DecidableEq Xi]
    {n B : Nat}
    (bad : Fin (n + 1) → Finset (Delta × (Fin (n + 1) → Xi)))
    (hslice : ∀ r (rest : Fin n → Xi),
      (univ.filter fun dxi : Delta × Xi =>
        responseTapeEquiv r (dxi, rest) ∈ bad r).card ≤ B) :
    (univ.biUnion bad).card ≤
      (n + 1) * B * Fintype.card Xi ^ n :=
  connection_soundness_union_bound bad hslice

/-! ## Transparent serialization refinement -/

/-- One canonical ALFC schedule entry.  The authenticated value has two
`Fp` limbs and is never modeled as a clear verifier output. -/
structure C7AlfcClaim (Commitment Query F : Type*) where
  commitment : Commitment
  query : Query
  authenticatedValue : Fin 2 → F × F

/-- The abstract relation is deliberately just successful decoding to the
canonical ordered schedule, not an ideal binding/privacy interface. -/
def C7AbstractAlfcRelation
    {Wire Commitment Query F : Type*}
    (decode : Wire → Option (List (C7AlfcClaim Commitment Query F)))
    (wire : Wire) (schedule : List (C7AlfcClaim Commitment Query F)) : Prop :=
  decode wire = some schedule

/-- A concrete canonical serializer refines the abstract ALFC schedule when
its stated decode/encode round trip holds. -/
theorem canonical_serialized_claim_schedule_refines_alfc
    {Wire Commitment Query F : Type*}
    (encode : List (C7AlfcClaim Commitment Query F) → Wire)
    (decode : Wire → Option (List (C7AlfcClaim Commitment Query F)))
    (schedule : List (C7AlfcClaim Commitment Query F))
    (hcodec : decode (encode schedule) = some schedule) :
    C7AbstractAlfcRelation decode (encode schedule) schedule :=
  hcodec

end VoltaZk

#print axioms VoltaZk.packed_functional_eq
#print axioms VoltaZk.fixed_before_beta_rlc_root
#print axioms VoltaZk.multi_commit_terminal_key_linearity_fp2
#print axioms VoltaZk.multi_commit_terminal_mac_linearity_fp2
#print axioms VoltaZk.reused_affine_mask_extract
#print axioms VoltaZk.mle_append_difference
#print axioms VoltaZk.accepted_append_tails_induction
#print axioms VoltaZk.atomic_promotion_fork_exclusion
#print axioms VoltaZk.connection_union_bound_with_rmax_shared_delta
#print axioms VoltaZk.canonical_serialized_claim_schedule_refines_alfc

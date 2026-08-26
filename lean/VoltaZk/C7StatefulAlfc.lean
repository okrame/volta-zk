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

/-- For one already serialized transcript prefix, if acceptance implies the
scalar-power residual identity and one residual is nonzero, at most `T`
challenges accept.  The concrete protocol must separately prove that `prefix`
binds every commitment/claim/query before the challenge and that Fiat--Shamir
samples it with the required distribution. -/
theorem fixed_prefix_rlc_accepting_card_le
    {F Prefix : Type*}
    [Field F] [Fintype F]
    {T : Nat}
    (transcriptPrefix : Prefix) (errorOf : Prefix → Fin T → F)
    (accept : Prefix → F → Bool)
    {j₀ : Fin T} (herror : errorOf transcriptPrefix j₀ ≠ 0)
    (haccept : ∀ beta, accept transcriptPrefix beta = true →
      ∑ j, beta ^ (j.val + 1) * errorOf transcriptPrefix j = 0) :
    (univ.filter fun beta : F => accept transcriptPrefix beta = true).card ≤ T := by
  classical
  refine (card_le_card ?_).trans
    (card_scalarRlc_zero_le (errorOf transcriptPrefix) herror)
  intro beta hbeta
  simp only [mem_filter, mem_univ, true_and] at hbeta ⊢
  exact haccept beta hbeta

/-! ## One multi-commitment terminal in the extension field -/

/-- Pair batch for one logical terminal over many commitment planes.  The
field is the actual MAC/challenge field (for C7, `Fp2`), not two independent
base-field MACs. -/
def multiCommitTerminalPair
    {E C : Type*} [Semiring E] [Fintype C]
    (coefficient : C → E) (value : C → E × E) : E × E :=
  (∑ c, coefficient c * (value c).1,
    ∑ c, coefficient c * (value c).2)

/-- Verifier-key projection commutes with the multi-commitment terminal for
one shared extension-field MAC key. -/
theorem multi_commit_terminal_key_linearity
    {E C : Type*} [Field E] [Fintype C]
    (Delta : E) (coefficient : C → E) (value : C → E × E) :
    keyOf Delta (multiCommitTerminalPair coefficient value) =
      ∑ c, coefficient c * keyOf Delta (value c) := by
  unfold multiCommitTerminalPair keyOf
  rw [Finset.mul_sum, ← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro c _
  ring

/-- Componentwise MAC batch corresponding to `multiCommitTerminalPair`. -/
def multiCommitTerminalAuthed
    {E C : Type*} [Field E] [Fintype C]
    (coefficient : C → E) (value : C → Authed E) : Authed E :=
  ∑ c, coefficient c • value c

/-- MAC validity is preserved by the same multi-commitment linear batch in
the extension field under the same `Delta`. -/
theorem multi_commit_terminal_mac_linearity
    {E C : Type*} [Field E] [Fintype C]
    (Delta : E) (coefficient : C → E) (value : C → Authed E)
    (hvalid : ∀ c, (value c).Valid Delta) :
    (multiCommitTerminalAuthed coefficient value).Valid Delta := by
  apply Authed.Valid.sum
  intro c _
  exact (hvalid c).smul (coefficient c)

/-- Equality of the extension-field key equation implies equality of every
serialized coordinate.  Instantiating `coordinate` with the two canonical
`Fp2` projections covers both base-field limbs without replacing `Fp2`
multiplication by two unrelated base-field MACs. -/
theorem multi_commit_terminal_mac_equation_on_coordinates
    {Fp E C : Type*} [Field E] [Fintype C]
    (coordinate : Fin 2 → E → Fp)
    (Delta : E) (coefficient : C → E) (value : C → Authed E)
    (hvalid : ∀ c, (value c).Valid Delta) :
    ∀ limb,
      coordinate limb (multiCommitTerminalAuthed coefficient value).k =
        coordinate limb
          ((multiCommitTerminalAuthed coefficient value).m +
            Delta * (multiCommitTerminalAuthed coefficient value).x) := by
  intro limb
  have h := multi_commit_terminal_mac_linearity Delta coefficient value hvalid
  unfold Authed.Valid at h
  exact congrArg (coordinate limb) h

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

/-! ## Conditional computational/statistical hybrid composition -/

/-- If `advantage r` is the distinguishing advantage after `r` attempts, a
base loss plus an additive per-attempt hybrid bound composes linearly.  The
cryptographic work is the `hstep` premise: this arithmetic lemma does not
manufacture the missing malicious-DV per-attempt simulator. -/
theorem connection_hybrid_advantage_bound
    (advantage : Nat → ℚ) (epsilonAttempt epsilonFixed : ℚ)
    (hzero : advantage 0 ≤ epsilonFixed)
    (hstep : ∀ r, advantage (r + 1) ≤ advantage r + epsilonAttempt) :
    ∀ Rmax, advantage Rmax ≤ epsilonFixed + Rmax * epsilonAttempt := by
  intro Rmax
  induction Rmax with
  | zero => simpa using hzero
  | succ r ih =>
      calc
        advantage (r + 1) ≤ advantage r + epsilonAttempt := hstep r
        _ ≤ (epsilonFixed + r * epsilonAttempt) + epsilonAttempt :=
          by linarith
        _ = epsilonFixed + (↑(Nat.succ r) : ℚ) * epsilonAttempt := by
          rw [Nat.cast_succ]
          ring

/-- Exact R0 arithmetic: if every one of the 64 attempt-local events really
has error at most `2^-110`, the `2^20`-attempt union plus the registered
hash/PCG/state/framing terms remains below `2^-78`. -/
theorem c7_registered_connection_error_below_78_bits :
    (2 ^ 20 : ℚ) * ((64 : ℚ) / 2 ^ 110) +
        1 / 2 ^ 128 + 1 / 2 ^ 128 + 1 / 2 ^ 120 + 1 / 2 ^ 128
      < 1 / 2 ^ 78 := by
  norm_num

/-! ## Transparent serialization refinement -/

/-- One canonical ALFC schedule entry.  The authenticated value has two
party-local shares represented only by an opaque handle; this structure does
not serialize a plaintext/tag pair. -/
structure C7AlfcClaim (Commitment Query Handle : Type*) where
  commitment : Commitment
  query : Query
  authenticatedHandle : Handle

/-- The abstract relation is deliberately just successful decoding to the
canonical ordered schedule, not an ideal binding/privacy interface. -/
def C7AbstractAlfcRelation
    {Wire Commitment Query Handle : Type*}
    (decode : Wire → Option (List (C7AlfcClaim Commitment Query Handle)))
    (wire : Wire)
    (schedule : List (C7AlfcClaim Commitment Query Handle)) : Prop :=
  decode wire = some schedule

/-- A concrete canonical serializer refines the abstract ALFC schedule when
its stated decode/encode round trip holds. -/
theorem canonical_serialized_claim_schedule_refines_alfc
    {Wire Commitment Query Handle : Type*}
    (encode : List (C7AlfcClaim Commitment Query Handle) → Wire)
    (decode : Wire → Option (List (C7AlfcClaim Commitment Query Handle)))
    (schedule : List (C7AlfcClaim Commitment Query Handle))
    (hcodec : decode (encode schedule) = some schedule) :
    C7AbstractAlfcRelation decode (encode schedule) schedule :=
  hcodec

end VoltaZk

#print axioms VoltaZk.packed_functional_eq
#print axioms VoltaZk.fixed_prefix_rlc_accepting_card_le
#print axioms VoltaZk.multi_commit_terminal_key_linearity
#print axioms VoltaZk.multi_commit_terminal_mac_linearity
#print axioms VoltaZk.multi_commit_terminal_mac_equation_on_coordinates
#print axioms VoltaZk.reused_affine_mask_extract
#print axioms VoltaZk.mle_append_difference
#print axioms VoltaZk.accepted_append_tails_induction
#print axioms VoltaZk.atomic_promotion_fork_exclusion
#print axioms VoltaZk.connection_union_bound_with_rmax_shared_delta
#print axioms VoltaZk.connection_hybrid_advantage_bound
#print axioms VoltaZk.c7_registered_connection_error_below_78_bits
#print axioms VoltaZk.canonical_serialized_claim_schedule_refines_alfc

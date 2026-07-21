import Mathlib.InformationTheory.Hamming
import Mathlib.LinearAlgebra.Dual.Lemmas
import VoltaZk.BatchSumcheckSound
import VoltaZk.BoundaryThinningSound
import VoltaZk.OpeningMac
import VoltaZk.X4Field

/-!
# X4 amended folding-PCS seam

This module is the Lean-first checkpoint for the amended
`x4-zkdeepfold-ud-e29-v2` profile.  It formalizes the concrete field/domain
facts, the strict rate-1/8 unique-decoding lemma, split-block MLE identity,
masked auxiliary fiber count, commitment-epoch state machine, canonical frame
boundary, scalar reductions, masked M9 transfer, and response-wide arithmetic.

The concrete BaseFold/DeepFold binding, simulator, collision-resistance and UC
realization statements remain explicit hypotheses at their named seams.  They
are not `axiom` declarations and are not bundled with one another.
-/

namespace VoltaZk

open Finset Polynomial

/-! ## Strict rate-1/8 Reed--Solomon unique decoding -/

/-- Evaluation-code membership for degree `< k` at a fixed ordered point set.
The X4 rate-1/8 instantiation uses `n = 8*k`. -/
def RSCodeword {F : Type*} [Field F] {n : Nat}
    (points : Fin n → F) (k : Nat) (c : Fin n → F) : Prop :=
  ∃ p : Polynomial F, p.natDegree < k ∧
    ∀ i, p.eval (points i) = c i

private theorem rs_rate_eighth_distance {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    {k : Nat} (hk : 0 < k) (points : Fin (8*k) → F)
    (hpoints : Function.Injective points)
    (c0 c1 : Fin (8*k) → F)
    (hc0 : RSCodeword points k c0)
    (hc1 : RSCodeword points k c1)
    (hne : c0 ≠ c1) :
    7*k + 1 ≤ hammingDist c0 c1 := by
  obtain ⟨p0, hp0, he0⟩ := hc0
  obtain ⟨p1, hp1, he1⟩ := hc1
  let q := p0 - p1
  have hq : q ≠ 0 := by
    intro hzero
    apply hne
    funext i
    have heval := congrArg
      (fun p : Polynomial F => p.eval (points i)) hzero
    simp only [q, Polynomial.eval_sub, Polynomial.eval_zero,
      sub_eq_zero] at heval
    rw [← he0 i, ← he1 i]
    exact heval
  have hqdeg : q.natDegree < k := by
    exact (Polynomial.natDegree_sub_le p0 p1).trans_lt
      (max_lt hp0 hp1)
  let agree := univ.filter fun i : Fin (8*k) => c0 i = c1 i
  have himage : agree.image points ⊆
      univ.filter fun x : F => q.eval x = 0 := by
    intro x hx
    simp only [mem_image] at hx
    obtain ⟨i, hi, rfl⟩ := hx
    simp only [mem_filter, mem_univ, true_and] at hi ⊢
    have hic : c0 i = c1 i := by simpa [agree] using hi
    simp only [q, Polynomial.eval_sub]
    rw [he0 i, he1 i, hic, sub_self]
  have hagree : agree.card < k := by
    calc
      agree.card = (agree.image points).card :=
        (card_image_iff.mpr hpoints.injOn).symm
      _ ≤ (univ.filter fun x : F => q.eval x = 0).card :=
        card_le_card himage
      _ ≤ q.natDegree := card_eval_zero_le hq
      _ < k := hqdeg
  have hpartition : hammingDist c0 c1 + agree.card = 8*k := by
    rw [hammingDist]
    simpa [agree, ne_eq] using
      (card_filter_add_card_filter_not
        (s := (univ : Finset (Fin (8*k))))
        (p := fun i => c0 i ≠ c1 i))
  omega

/-- Strict unique decoding at the preregistered radius.  Distances are kept
as exact integer inequalities, avoiding rational rounding: `16*d < 7*n`
means relative distance `< 7/16`. -/
theorem rs_rate_eighth_unique_decode {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    {k : Nat} (hk : 0 < k) (points : Fin (8*k) → F)
    (hpoints : Function.Injective points)
    (received c0 c1 : Fin (8*k) → F)
    (hc0 : RSCodeword points k c0)
    (hc1 : RSCodeword points k c1)
    (h0 : 16 * hammingDist received c0 < 7 * (8*k))
    (h1 : 16 * hammingDist received c1 < 7 * (8*k)) :
    c0 = c1 := by
  by_contra hne
  have hdist := rs_rate_eighth_distance hk points hpoints c0 c1
    hc0 hc1 hne
  have htri := hammingDist_triangle_left c0 c1 received
  omega

/-! ## Multilinear split and equal-fiber mask count -/

/-- The Boolean-cube MLE basis coefficient at `point`. -/
def x4MleWeight {F : Type*} [Field F] {ell : Nat}
    (point : Fin ell → F) (bits : Fin ell → Fin 2) : F :=
  ∏ i, if bits i = 0 then 1 - point i else point i

/-- MLE evaluation as a linear functional of the coefficient table. -/
noncomputable def x4MleLinear {F : Type*} [Field F] {ell : Nat}
    (point : Fin ell → F) :
    ((Fin ell → Fin 2) → F) →ₗ[F] F where
  toFun values := ∑ bits, x4MleWeight point bits * values bits
  map_add' x y := by
    simp only [Pi.add_apply, mul_add, Finset.sum_add_distrib]
  map_smul' c x := by
    simp only [Pi.smul_apply, RingHom.id_apply, smul_eq_mul]
    rw [Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro bits _
    ring

def EvalFunctionalNonzero {F : Type*} [Field F] {ell : Nat}
    (point : Fin ell → F) : Prop :=
  x4MleLinear point ≠ 0

/-- Put the split/high coordinate first, matching `lsbMle_cons`; this is the
same ordered Boolean variable selected by the amended physical split. -/
def x4ExtendPoint {F : Type*} {mu : Nat}
    (z : Fin mu → F) (hi : F) : Fin (mu + 1) → F :=
  Fin.cases hi z

/-- Concatenate the low and high coefficient halves in canonical order. -/
def x4SplitBlock {F : Type*} {mu : Nat}
    (W0 W1 : (Fin mu → Fin 2) → F) :
    (Fin (mu + 1) → Fin 2) → F :=
  fun bits => Fin.cases (W0 (fun i => bits i.succ))
    (fun _ => W1 (fun i => bits i.succ)) (bits 0)

theorem split_block_eval {F : Type*} [Field F] {mu : Nat}
    (W0 W1 : (Fin mu → Fin 2) → F)
    (z : Fin mu → F) (hi : F) :
    lsbMle (x4SplitBlock W0 W1) (x4ExtendPoint z hi) =
      (1 - hi) * lsbMle W0 z + hi * lsbMle W1 z := by
  unfold x4ExtendPoint
  rw [lsbMle_cons]
  simp only [lsbMlePair, pairFold, x4ExtendPoint]
  have h0 :
      (fun bits => x4SplitBlock W0 W1 (Fin.cases 0 bits)) = W0 := by
    funext bits
    simp [x4SplitBlock]
  have h1 :
      (fun bits => x4SplitBlock W0 W1 (Fin.cases 1 bits)) = W1 := by
    funext bits
    change W1 bits = W1 bits
    rfl
  rw [h0, h1]
  ring

/-- Direct-field masked relation.  There is no `E → K` embedding and no
tower component in the amended profile. -/
theorem masked_aux_eval {F : Type*} [Field F]
    {mu ell : Nat}
    (Wext : (Fin (mu + 1) → Fin 2) → F)
    (W : (Fin mu → Fin 2) → F)
    (g : (Fin ell → Fin 2) → F)
    (z : Fin mu → F) (u : Fin ell → F) (s h : F)
    (hWext : lsbMle Wext (x4ExtendPoint z 0) = lsbMle W z)
    (hs : s = x4MleLinear u g)
    (hh : h = lsbMle W z + s) :
    h = lsbMle Wext (x4ExtendPoint z 0) + x4MleLinear u g := by
  rw [hWext, ← hs]
  exact hh

section MaskFiber

noncomputable local instance x4FiberPropDecidable (p : Prop) : Decidable p :=
  Classical.propDecidable p

private def x4LinearFiberEquivKer {F V : Type*}
    [Field F] [AddCommGroup V] [Module F V]
    (f : V →ₗ[F] F) (y : F) (x0 : V) (hx0 : f x0 = y) :
    {x : V // f x = y} ≃ LinearMap.ker f where
  toFun x := ⟨x.1 - x0, by simp [x.2, hx0]⟩
  invFun k := ⟨x0 + k.1, by simp [hx0, k.2]⟩
  left_inv x := by ext; simp
  right_inv k := by ext; simp

private theorem x4_nonzero_linear_surjective {F V : Type*}
    [Field F] [AddCommGroup V] [Module F V]
    (f : V →ₗ[F] F) (hf : f ≠ 0) : Function.Surjective f := by
  have hex : ∃ x : V, f x ≠ 0 := by
    by_contra h
    push_neg at h
    apply hf
    ext x
    simpa using h x
  obtain ⟨x, hx⟩ := hex
  intro y
  refine ⟨(y / f x) • x, ?_⟩
  simp [hx]

private theorem x4_linear_fiber_card {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    (f : (ι → F) →ₗ[F] F) (hf : f ≠ 0) (y : F) :
    Fintype.card {x : ι → F // f x = y} =
      Fintype.card F ^ (Fintype.card ι - 1) := by
  classical
  obtain ⟨x0, hx0⟩ := x4_nonzero_linear_surjective f hf y
  rw [Fintype.card_congr (x4LinearFiberEquivKer f y x0 hx0)]
  rw [Module.card_eq_pow_finrank (K := F)]
  congr 1
  have hker := Module.Dual.finrank_ker_add_one_of_ne_zero hf
  rw [Module.finrank_pi F] at hker
  omega

private def x4MaskedFiberEquiv {F V : Type*}
    [Field F] [AddCommGroup V] [Module F V]
    (f : V →ₗ[F] F) (v h : F) :
    {x : V // h = v + f x} ≃ {x : V // f x = h - v} where
  toFun x := ⟨x.1, by
    calc
      f x.1 = (v + f x.1) - v := by ring
      _ = h - v := congrArg (fun t : F => t - v) x.2.symm⟩
  invFun x := ⟨x.1, by
    calc
      h = (h - v) + v := by ring
      _ = f x.1 + v := (congrArg (fun t : F => t + v) x.2).symm
      _ = v + f x.1 := add_comm _ _⟩
  left_inv _ := rfl
  right_inv _ := rfl

theorem masked_aux_hiding_count {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    {ell : Nat} (hell : 0 < ell) (point : Fin ell → F)
    (hfunc : EvalFunctionalNonzero point) (v h : F) :
    Fintype.card
        {g : (Fin ell → Fin 2) → F //
          h = v + x4MleLinear point g} =
      Fintype.card F ^ (2^ell - 1) := by
  classical
  let f : ((Fin ell → Fin 2) → F) →ₗ[F] F := x4MleLinear point
  have hf : f ≠ 0 := hfunc
  change Fintype.card {g : (Fin ell → Fin 2) → F // h = v + f g} = _
  obtain ⟨g0, hg0⟩ := x4_nonzero_linear_surjective f hf (h - v)
  let eMasked := x4MaskedFiberEquiv f v h
  let eKer := x4LinearFiberEquivKer f (h - v) g0 hg0
  let eTotal := eMasked.trans eKer
  rw [Fintype.card_congr eTotal, Module.card_eq_pow_finrank (K := F)]
  congr 1
  have hker := Module.Dual.finrank_ker_add_one_of_ne_zero hf
  rw [Module.finrank_pi F, Fintype.card_fun, Fintype.card_fin,
    Fintype.card_fin] at hker
  omega

end MaskFiber

/-! ## One-opening state and corrected direct M9 transfer -/

abbrev X4Byte := Fin 256

structure X4OpeningState where
  consumedEpochs : Finset Nat

def acceptOpening (st : X4OpeningState) (epoch : Nat)
    (transcript : List X4Byte) : Option X4OpeningState :=
  if epoch ∈ st.consumedEpochs then none
  else some { consumedEpochs := insert epoch st.consumedEpochs }

theorem one_opening_per_epoch
    (st st1 st2 : X4OpeningState) (epoch : Nat)
    (transcript1 transcript2 : List X4Byte)
    (hfirst : acceptOpening st epoch transcript1 = some st1)
    (hsecond : acceptOpening st1 epoch transcript2 = some st2) :
    False := by
  by_cases hmem : epoch ∈ st.consumedEpochs
  · simp [acceptOpening, hmem] at hfirst
  · simp [acceptOpening, hmem] at hfirst
    subst st1
    simp [acceptOpening] at hsecond

/-- Amendment 2's deterministic good-tape predicate.  Bare `Authed.Valid`
does not imply the required zero plaintext. -/
def ResponseZeroBatchValid {F : Type*} [Field F] (Delta : F)
    (a : Authed F) : Prop :=
  a.Valid Delta ∧ a.x = 0

theorem direct_mask_transfer {F : Type*} [Field F]
    (Delta h : F) (authV authS : Authed F)
    (hs : authS.Valid Delta)
    (hz : ResponseZeroBatchValid Delta
      (authV + authS - Authed.ofPublic Delta h)) :
    authV.x = h - authS.x := by
  have hplain := hz.2
  simp only [Authed.sub_x, Authed.add_x,
    Authed.ofPublic_x] at hplain
  linear_combination hplain

/-! ## Canonical v2 outer frame and typed cohort binding -/

/-- The eleven normative v2 child-frame kinds. -/
inductive X4FrameKind
  | descriptor
  | pcsLeaf
  | pcsNode
  | manifestLeaf
  | manifestNode
  | cohortMultiproof
  | responseEnvelope
  | reducedClaim
  | foldCommitment
  | m9Transfer
  | responseZeroBatch
  deriving DecidableEq, Repr

def X4FrameKind.code : X4FrameKind → X4Byte
  | .descriptor => 0x01
  | .pcsLeaf => 0x02
  | .pcsNode => 0x03
  | .manifestLeaf => 0x04
  | .manifestNode => 0x05
  | .cohortMultiproof => 0x06
  | .responseEnvelope => 0x07
  | .reducedClaim => 0x08
  | .foldCommitment => 0x09
  | .m9Transfer => 0x0a
  | .responseZeroBatch => 0x0b

def X4FrameKind.ofCode : X4Byte → Option X4FrameKind
  | 0x01 => some .descriptor
  | 0x02 => some .pcsLeaf
  | 0x03 => some .pcsNode
  | 0x04 => some .manifestLeaf
  | 0x05 => some .manifestNode
  | 0x06 => some .cohortMultiproof
  | 0x07 => some .responseEnvelope
  | 0x08 => some .reducedClaim
  | 0x09 => some .foldCommitment
  | 0x0a => some .m9Transfer
  | 0x0b => some .responseZeroBatch
  | _ => none

@[simp] theorem X4FrameKind.ofCode_code (kind : X4FrameKind) :
    X4FrameKind.ofCode kind.code = some kind := by
  cases kind <;> rfl

private def x4Byte (n : Nat) (h : n < 256 := by omega) : X4Byte :=
  ⟨n, h⟩

/-- Four-byte unsigned little-endian encoding. -/
def x4EncodeU32LE (n : Nat) : List X4Byte :=
  [x4Byte (n % 256), x4Byte ((n / 256) % 256),
    x4Byte ((n / 256^2) % 256), x4Byte ((n / 256^3) % 256)]

private theorem x4_decode_encode_u32 (n : Nat) (hn : n < 2^32) :
    let bytes := x4EncodeU32LE n
    bytes[0]!.val + 256*bytes[1]!.val +
      256^2*bytes[2]!.val + 256^3*bytes[3]!.val = n := by
  simp [x4EncodeU32LE, x4Byte]
  omega

/-- Exactly the normative 16-byte v2 header. -/
def x4FrameHeader (kind : X4FrameKind) (bodyLength : Nat) :
    List X4Byte :=
  [x4Byte 86, x4Byte 79, x4Byte 76, x4Byte 84,
    x4Byte 65, x4Byte 88, x4Byte 52, x4Byte 50,
    x4Byte 2, x4Byte 0, kind.code, x4Byte 0] ++
    x4EncodeU32LE bodyLength

@[simp] theorem x4FrameHeader_length (kind : X4FrameKind)
    (bodyLength : Nat) :
    (x4FrameHeader kind bodyLength).length = 16 := by
  simp [x4FrameHeader, x4EncodeU32LE]

/-- A typed v2 frame after its kind-specific body decoder has accepted the
body.  At this boundary `body` is already the canonical body byte string;
the outer codec proves the common magic/schema/kind/flags/length envelope. -/
structure X4FrameV2 where
  kind : X4FrameKind
  body : List X4Byte
  bodyLengthFits : body.length < 2^32
  deriving DecidableEq

@[ext] theorem X4FrameV2.ext {a b : X4FrameV2}
    (hkind : a.kind = b.kind) (hbody : a.body = b.body) : a = b := by
  cases a
  cases b
  simp_all

def encodeX4FrameV2 (f : X4FrameV2) : List X4Byte :=
  x4FrameHeader f.kind f.body.length ++ f.body

/-- Canonical outer decoder.  Deriving the body as `drop 16` and then
requiring byte-for-byte equality with the unique re-encoding simultaneously
checks magic, schema 2, kind, zero flags, little-endian length and absence of
bytes outside the declared body. -/
def decodeX4FrameV2 (bytes : List X4Byte) : Option X4FrameV2 :=
  match bytes[10]? with
  | none => none
  | some kindCode =>
      match X4FrameKind.ofCode kindCode with
      | none => none
      | some kind =>
          let body := bytes.drop 16
          if hfit : body.length < 2^32 then
            if bytes = x4FrameHeader kind body.length ++ body then
              some { kind := kind, body := body, bodyLengthFits := hfit }
            else none
          else none

theorem x4_frame_decode_encode (f : X4FrameV2) :
    decodeX4FrameV2 (encodeX4FrameV2 f) = some f := by
  have hfit : f.body.length < 4294967296 := by
    simpa using f.bodyLengthFits
  simp [decodeX4FrameV2, encodeX4FrameV2, x4FrameHeader,
    x4EncodeU32LE, hfit]

theorem x4_frame_decode_canonical {bytes : List X4Byte}
    {f : X4FrameV2}
    (h : decodeX4FrameV2 bytes = some f) :
    encodeX4FrameV2 f = bytes := by
  unfold decodeX4FrameV2 at h
  split at h <;> try contradiction
  rename_i kindCode hkindCode
  split at h <;> try contradiction
  rename_i kind hkind
  dsimp only at h
  split at h <;> try contradiction
  rename_i hfit
  split at h <;> try contradiction
  rename_i hcanonical
  simp only [Option.some.injEq] at h
  subst f
  exact hcanonical.symm

theorem x4_frame_kind_encoding_disjoint
    (a b : X4FrameV2) (hkind : a.kind ≠ b.kind) :
    encodeX4FrameV2 a ≠ encodeX4FrameV2 b := by
  intro heq
  have hdecode : some a = some b := by
    rw [← x4_frame_decode_encode a,
      ← x4_frame_decode_encode b, heq]
  have hab : a = b := Option.some.inj hdecode
  exact hkind (congrArg X4FrameV2.kind hab)

/-- Typed hash domains.  Including the domain in the preimage makes the
N4 leaf/node/manifest separation part of the binding proposition. -/
inductive X4HashDomain
  | descriptor
  | pcsLeaf
  | pcsNode
  | manifestLeaf
  | manifestNode
  | manifestId
  | transferTemplate
  deriving DecidableEq, Repr

abbrev X4Digest := Fin 32 → X4Byte

/-- Canonical object committed by the cohort root.  `authenticationFrames`
is the ordered leaf/path trace; the concrete implementation hashes its exact
v2 encodings under the typed domains above. -/
structure X4CommitmentPreimage (F : Type*) where
  domain : X4HashDomain
  descriptor : X4Digest
  point : List F
  slot : Nat
  symbols : List F
  authenticationFrames : List X4FrameV2
  deriving DecidableEq

structure X4V2Hash (F : Type*) where
  digest : X4CommitmentPreimage F → X4Digest

noncomputable def CollisionFreeOn {F : Type*} [DecidableEq F]
    (H : X4V2Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F)) : Prop :=
  ∀ a ∈ committedFrames, ∀ b ∈ committedFrames,
    H.digest a = H.digest b → a = b

structure X4CohortOpening (F : Type*) where
  preimage : X4CommitmentPreimage F

noncomputable def VerifyCohortOpening {F : Type*} [DecidableEq F]
    (H : X4V2Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root : X4Digest) (descriptor : X4Digest)
    (point : List F) (slot : Nat) (opening : X4CohortOpening F) : Prop :=
  opening.preimage ∈ committedFrames ∧
    opening.preimage.domain = .pcsLeaf ∧
    opening.preimage.descriptor = descriptor ∧
    opening.preimage.point = point ∧
    opening.preimage.slot = slot ∧
    H.digest opening.preimage = root

theorem cohort_opening_binding {F : Type*} [DecidableEq F]
    (H : X4V2Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root descriptor : X4Digest) (point : List F) (slot : Nat)
    (openA openB : X4CohortOpening F)
    (hhash : CollisionFreeOn H committedFrames)
    (ha : VerifyCohortOpening H committedFrames root descriptor point slot openA)
    (hb : VerifyCohortOpening H committedFrames root descriptor point slot openB) :
    openA.preimage.symbols = openB.preimage.symbols := by
  have hpre : openA.preimage = openB.preimage :=
    hhash openA.preimage ha.1 openB.preimage hb.1
      (ha.2.2.2.2.2.trans hb.2.2.2.2.2.symm)
  exact congrArg X4CommitmentPreimage.symbols hpre

/-! ## Fixed-before-challenge scalar reductions -/

/-- The concrete M3 instance used by both per-block claim collapse and the
different-point reduction: every sumcheck round has degree at most two. -/
abbrev X4QuadraticDegrees : Nat → Nat := fun _ => 2

/-- All malicious-prover data for one outer scalar reduction.  The functions
are fixed objects; only their explicitly modeled arguments may affect them. -/
structure X4ScalarReduction (F : Type*) [Field F]
    (claimCount rounds : Nat) (ι : Type*) [Fintype ι] where
  claimed : Fin claimCount → F
  trueTotal : Fin claimCount → F
  prover : F → MaliciousProver F rounds X4QuadraticDegrees ι
  functional : F → (Fin rounds → F) → ι → F
  truth : F → TrueRounds F rounds X4QuadraticDegrees

/-- The exact fixed-before-outer-challenge boundary plus a witness that one
of the collapsed claims is false. -/
def ClaimsFixedBeforeChallenge {F ι : Type*} [Field F] [Fintype ι]
    {claimCount rounds : Nat}
    (C : X4ScalarReduction F claimCount rounds ι) : Prop :=
  (∀ beta, (C.prover beta).σ₀ =
      ∑ k, batchWeight beta k * C.claimed k) ∧
  (∀ beta, (C.truth beta).total =
      ∑ k, batchWeight beta k * C.trueTotal k) ∧
  (∀ beta, (C.truth beta).finalEval =
      openEval (C.prover beta) (C.functional beta)) ∧
  ∃ k : Fin claimCount, C.claimed k ≠ C.trueTotal k

noncomputable def x4ReductionBadTapeCard {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    {claimCount rounds : Nat} (hrounds : 0 < rounds)
    (C : X4ScalarReduction F claimCount rounds ι) : Nat :=
  (univ.filter fun tape : F × (F × (Fin rounds → F) × F) =>
    acceptsScalar hrounds (C.prover tape.1) (C.functional tape.1)
      tape.2.1 tape.2.2.1 tape.2.2.2).card

def x4FieldTapeCard (F : Type*) [Fintype F] (rounds : Nat) : Nat :=
  Fintype.card F ^ (rounds + 2)

/-- Per-block specialization of the already-audited scalar M3 theorem.  For
`claimCount≤2` and `rounds≤29`, the displayed coefficient is exactly the
preregistered `claims.length + 3*mu + 2`; the inequalities pin admission but
are not spent to replace the exact coefficient by a looser maximum. -/
theorem blind_claim_reduce_sound {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    {claimCount mu : Nat} (hmuPos : 0 < mu)
    (claims : X4ScalarReduction F claimCount mu ι)
    (hfixed : ClaimsFixedBeforeChallenge claims)
    (hcount : claimCount ≤ 2) (hmu : mu ≤ 29) :
    x4ReductionBadTapeCard hmuPos claims ≤
      (claimCount + 3*mu + 2) * x4FieldTapeCard F mu := by
  obtain ⟨hclaimed, htrue, hfin, k0, hbad⟩ := hfixed
  have hsound := outer_scalar_batch_blind_sumcheck_sound
    (F := F) (n := mu) (K := claimCount)
    (d := X4QuadraticDegrees) hmuPos
    claims.claimed claims.trueTotal claims.prover claims.functional
    claims.truth hclaimed htrue hfin k0 hbad
  unfold x4ReductionBadTapeCard x4FieldTapeCard
  simp [X4QuadraticDegrees] at hsound
  exact hsound.trans_eq (by congr 1; omega)

abbrev DifferentPointBatchReduction := X4ScalarReduction

def MaskedClaimsFixed {F ι : Type*} [Field F] [Fintype ι]
    {claimCount rounds : Nat}
    (C : DifferentPointBatchReduction F claimCount rounds ι) : Prop :=
  ClaimsFixedBeforeChallenge C

/-- Different-point claims are reduced by scalar M3 only after the VOLTA
scheduler proves that the resulting round transcript uses one common point.
No naive cross-point RLC is admitted. -/
theorem folding_different_point_batch_sound {F ι : Type*}
    [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    {claimCount rounds : Nat} (hrounds : 0 < rounds)
    (claims : DifferentPointBatchReduction F claimCount rounds ι)
    (points : Fin claimCount → Fin rounds → F)
    (commonPoint : Fin rounds → F)
    (hfixed : MaskedClaimsFixed claims)
    (hP : claimCount ≤ 3320)
    (hcommon : HasCommonPoint points commonPoint)
    (hd : rounds ≤ 30) :
    x4ReductionBadTapeCard hrounds claims ≤
      (claimCount + 3*rounds + 2) *
        x4FieldTapeCard F rounds := by
  obtain ⟨hclaimed, htrue, hfin, k0, hbad⟩ := hfixed
  have hsound := outer_scalar_batch_blind_sumcheck_sound
    (F := F) (n := rounds) (K := claimCount)
    (d := X4QuadraticDegrees) hrounds
    claims.claimed claims.trueTotal claims.prover claims.functional
    claims.truth hclaimed htrue hfin k0 hbad
  unfold x4ReductionBadTapeCard x4FieldTapeCard
  simp [X4QuadraticDegrees] at hsound
  exact hsound.trans_eq (by congr 1; omega)

/-! ## Strict-UD cohort/fold accounting -/

class StatisticalExperiment (A : Type*) where
  error : A → ℚ

def statisticalError {A : Type*} [StatisticalExperiment A] (a : A) : ℚ :=
  StatisticalExperiment.error a

/-- Universal form of the strict rate-1/8 uniqueness property. -/
def RSEighthStrictUniqueDecode (F : Type*)
    [Field F] [Fintype F] [DecidableEq F] : Prop :=
  ∀ {k : Nat}, 0 < k → ∀ (points : Fin (8*k) → F),
    Function.Injective points →
    ∀ (received c0 c1 : Fin (8*k) → F),
      RSCodeword points k c0 → RSCodeword points k c1 →
      16 * hammingDist received c0 < 7 * (8*k) →
      16 * hammingDist received c1 < 7 * (8*k) → c0 = c1

theorem rs_eighth_strict_unique_decode_property {F : Type*}
    [Field F] [Fintype F] [DecidableEq F] :
    RSEighthStrictUniqueDecode F := by
  intro k hk points hpoints received c0 c1 hc0 hc1 h0 h1
  exact rs_rate_eighth_unique_decode hk points hpoints received c0 c1
    hc0 hc1 h0 h1

/-- The named error components exported by a concrete cohort/folding game.
`foldRootBound` is the construction-side certificate obtained by applying
the polynomial root bound at every explicitly enumerated fold point; the
theorem below performs the response-level specialization and maxima. -/
structure UDFoldingCohorts (F : Type*) [Field F] [Fintype F]
    [DecidableEq F] where
  activePolys : Nat
  weightOracleLength : Nat
  auxOracleLength : Nat
  missFraction : ℚ
  proximityError : ℚ
  foldError : ℚ
  totalError : ℚ
  proximity_nonneg : 0 ≤ proximityError
  fold_nonneg : 0 ≤ foldError
  miss_nonneg : 0 ≤ missFraction
  coverUnderUD :
    RSEighthStrictUniqueDecode F → totalError ≤ proximityError + foldError
  foldRootBound :
    foldError ≤
      activePolys *
        ((weightOracleLength - 1 : Nat) + (auxOracleLength - 1 : Nat)) /
          Fintype.card F

instance {F : Type*} [Field F] [Fintype F] [DecidableEq F] :
    StatisticalExperiment (UDFoldingCohorts F) where
  error P := P.totalError

def ExactUniformQueriesWithReplacement {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    (params : UDFoldingCohorts F) (sampleCount : Nat) : Prop :=
  params.proximityError ≤
    params.activePolys * params.missFraction ^ sampleCount

def WrongCandidateIsAtDistanceAtLeast {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    (params : UDFoldingCohorts F) (distance : ℚ) : Prop :=
  params.missFraction ≤ 1 - distance

theorem ud_cohort_folding_sound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    (params : UDFoldingCohorts F)
    (hUD : RSEighthStrictUniqueDecode F)
    (hsample : ExactUniformQueriesWithReplacement params 128)
    (hbranch : WrongCandidateIsAtDistanceAtLeast params (7/16 : ℚ))
    (hP : params.activePolys ≤ 3320)
    (hnW : params.weightOracleLength ≤ 2^33)
    (hng : params.auxOracleLength ≤ 2^20) :
    statisticalError params ≤
      params.activePolys * (9/16 : ℚ)^128 +
      params.activePolys * ((2^33 - 1 : Nat) + (2^20 - 1 : Nat)) /
        Fintype.card F := by
  have hmiss : params.missFraction ≤ (9/16 : ℚ) := by
    norm_num [WrongCandidateIsAtDistanceAtLeast] at hbranch ⊢
    exact hbranch
  have hpow : params.missFraction ^ 128 ≤ (9/16 : ℚ)^128 :=
    pow_le_pow_left₀ params.miss_nonneg hmiss 128
  have hprox : params.proximityError ≤
      params.activePolys * (9/16 : ℚ)^128 :=
    hsample.trans (mul_le_mul_of_nonneg_left hpow (by positivity))
  have hlenW : params.weightOracleLength - 1 ≤ 2^33 - 1 :=
    Nat.sub_le_sub_right hnW 1
  have hlenG : params.auxOracleLength - 1 ≤ 2^20 - 1 :=
    Nat.sub_le_sub_right hng 1
  have hlens :
      ((params.weightOracleLength - 1 : Nat) +
          (params.auxOracleLength - 1 : Nat) : ℚ) ≤
        ((2^33 - 1 : Nat) + (2^20 - 1 : Nat) : ℚ) := by
    exact_mod_cast Nat.add_le_add hlenW hlenG
  have hcard : (0 : ℚ) < Fintype.card F := by positivity
  have hfold : params.foldError ≤
      params.activePolys * ((2^33 - 1 : Nat) + (2^20 - 1 : Nat)) /
        Fintype.card F := by
    refine params.foldRootBound.trans ?_
    exact div_le_div_of_nonneg_right
      (mul_le_mul_of_nonneg_left hlens (by positivity)) hcard.le
  exact (params.coverUnderUD hUD).trans (add_le_add hprox hfold)

/-! ## Masked batch binding into MAC -/

/-- A finite bad event with its exact uniform-sample statistical error. -/
structure X4Event (Omega : Type*) [Fintype Omega] where
  outcomes : Finset Omega

instance {Omega : Type*} [Fintype Omega] :
    StatisticalExperiment (X4Event Omega) where
  error event := event.outcomes.card / Fintype.card Omega

/-- Abstract malicious masked opening after all PCS-side objects are fixed.
The residual pair at block `b` is the adversary's plaintext/tag pair for
`v_b+s_b-h_b`; the final message may depend on the public scalar batching
challenge but never on the hidden MAC key. -/
structure MaskedBatchOpening (F Omega : Type*) (blockCount : Nat) where
  accepts : Omega → Prop
  committedEvalWrong : Omega → Prop
  residual : Omega → Fin blockCount → F × F
  zeroBatchMsg : Omega → F → F

noncomputable def MaskedBatchBindsIntoMac
    {F Omega : Type*} [Fintype Omega]
    {blockCount : Nat} (P : MaskedBatchOpening F Omega blockCount)
    (epsPCS : Nat) : Prop := by
  classical
  exact (univ.filter fun omega : Omega =>
    P.accepts omega ∧ P.committedEvalWrong omega).card ≤ epsPCS

noncomputable def MaskedBatchOpening.acceptsAndTransfersWrong
    {F Omega : Type*} [Field F] [Fintype F] [Fintype Omega]
    {blockCount : Nat} (P : MaskedBatchOpening F Omega blockCount) :
    X4Event (Omega × (F × F)) := by
  classical
  exact ⟨univ.filter fun tape : Omega × (F × F) =>
    P.accepts tape.1 ∧
    P.zeroBatchMsg tape.1 tape.2.2 =
      ∑ b, tape.2.2 ^ (b.val + 1) *
        keyOf tape.2.1 (P.residual tape.1 b) ∧
    (P.committedEvalWrong tape.1 ∨
      ∃ b, (P.residual tape.1 b).1 ≠ 0)⟩

/-- The amended M9 count.  PCS-bad tapes contribute `epsPCS/|Omega|`;
on every other tape with a wrong transferred plaintext, the existing scalar
ZeroBatch theorem contributes exactly `(blockCount+1)/|F|`. -/
theorem masked_batch_opening_mac_sound
    {F Omega : Type*} [Field F] [Fintype F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega]
    {blockCount epsPCS : Nat}
    (P : MaskedBatchOpening F Omega blockCount)
    (hbind : MaskedBatchBindsIntoMac P epsPCS)
    (hB : blockCount ≤ 1660) :
    statisticalError P.acceptsAndTransfersWrong ≤
      (epsPCS : ℚ) / Fintype.card Omega +
      (blockCount + 1 : Nat) / Fintype.card F := by
  classical
  let pcsBad := univ.filter fun omega : Omega =>
    P.accepts omega ∧ P.committedEvalWrong omega
  let live := univ.filter fun tape : Omega × (F × F) =>
    P.accepts tape.1 ∧
    (∃ b, (P.residual tape.1 b).1 ≠ 0) ∧
    P.zeroBatchMsg tape.1 tape.2.2 =
      ∑ b, tape.2.2 ^ (b.val + 1) *
        keyOf tape.2.1 (P.residual tape.1 b)
  have hsub : P.acceptsAndTransfersWrong.outcomes ⊆
      (pcsBad ×ˢ (univ : Finset (F × F))) ∪ live := by
    intro tape htape
    simp only [MaskedBatchOpening.acceptsAndTransfersWrong,
      mem_filter, mem_univ, true_and] at htape
    simp only [mem_union, mem_product, mem_univ, and_true,
      pcsBad, live, mem_filter, true_and]
    rcases htape with ⟨hacc, hzero, hwrong⟩
    rcases hwrong with hpcs | hres
    · exact Or.inl ⟨hacc, hpcs⟩
    · exact Or.inr ⟨hacc, hres, hzero⟩
  have hbadCard : (pcsBad ×ˢ (univ : Finset (F × F))).card ≤
      epsPCS * Fintype.card F ^ 2 := by
    rw [card_product, card_univ, Fintype.card_prod]
    simpa [pow_two] using Nat.mul_le_mul_right
      (Fintype.card F * Fintype.card F) hbind
  have hliveCard : live.card ≤
      Fintype.card Omega * ((blockCount + 1) * Fintype.card F) := by
    refine card_filter_prod_le_right
      (fun tape : Omega × (F × F) =>
        P.accepts tape.1 ∧
        (∃ b, (P.residual tape.1 b).1 ≠ 0) ∧
        P.zeroBatchMsg tape.1 tape.2.2 =
          ∑ b, tape.2.2 ^ (b.val + 1) *
            keyOf tape.2.1 (P.residual tape.1 b)) fun omega => ?_
    by_cases hacc : P.accepts omega
    · by_cases hwrong : ∃ b, (P.residual omega b).1 ≠ 0
      · obtain ⟨b0, hb0⟩ := hwrong
        refine (Finset.card_le_card ?_).trans
          (zeroBatch_sound_scalar (P.residual omega) hb0
            (P.zeroBatchMsg omega))
        intro deltaChi hdeltaChi
        simp only [mem_filter, mem_univ, true_and] at hdeltaChi ⊢
        exact hdeltaChi.2.2
      · rw [Finset.card_eq_zero.mpr]
        · exact Nat.zero_le _
        · exact Finset.filter_eq_empty_iff.mpr fun _ _ ht =>
            hwrong ht.2.1
    · rw [Finset.card_eq_zero.mpr]
      · exact Nat.zero_le _
      · exact Finset.filter_eq_empty_iff.mpr fun _ _ ht =>
          hacc ht.1
  have hcount : P.acceptsAndTransfersWrong.outcomes.card ≤
      epsPCS * Fintype.card F ^ 2 +
        Fintype.card Omega * ((blockCount + 1) * Fintype.card F) := by
    exact (card_le_card hsub).trans
      ((card_union_le _ _).trans (Nat.add_le_add hbadCard hliveCard))
  have hq : (0 : ℚ) < Fintype.card F := by positivity
  have homega : (0 : ℚ) < Fintype.card Omega := by positivity
  change (P.acceptsAndTransfersWrong.outcomes.card : ℚ) /
      Fintype.card (Omega × (F × F)) ≤
    (epsPCS : ℚ) / Fintype.card Omega +
      (blockCount + 1 : Nat) / Fintype.card F
  rw [Fintype.card_prod, Fintype.card_prod]
  push_cast
  apply (div_le_iff₀ (mul_pos homega (mul_pos hq hq))).2
  have hcountQ : (P.acceptsAndTransfersWrong.outcomes.card : ℚ) ≤
      (epsPCS : ℚ) * Fintype.card F ^ 2 +
        Fintype.card Omega *
          ((blockCount + 1 : Nat) * Fintype.card F) := by
    exact_mod_cast hcount
  refine hcountQ.trans_eq ?_
  field_simp
  push_cast
  ring

/-- Completeness/good-tape data for transferring the masked evaluations into
the downstream authenticated GKR seam. -/
structure MaskedBatchTransfer (F Omega : Type*) [Field F]
    (blockCount : Nat) where
  delta : Omega → F
  accepts : Omega → Prop
  authV : Omega → Fin blockCount → Authed F
  authS : Omega → Fin blockCount → Authed F
  publicH : Omega → Fin blockCount → F
  committedEval : Omega → Fin blockCount → F
  authSValid : ∀ omega b, (authS omega b).Valid (delta omega)

def MaskedBatchTransfer.committedEvalWrong
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount) (omega : Omega) : Prop :=
  ∃ b, P.publicH omega b - (P.authS omega b).x ≠
    P.committedEval omega b

def ResponseZeroBatchAccepts
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount) (omega : Omega) : Prop :=
  ∀ b, ResponseZeroBatchValid (P.delta omega)
    (P.authV omega b + P.authS omega b -
      Authed.ofPublic (P.delta omega) (P.publicH omega b))

abbrev TouchedBlock {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount) := Fin blockCount

def ValidCommittedAuthEval
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount)
    (b : TouchedBlock P) (omega : Omega) : Prop :=
  (P.authV omega b).Valid (P.delta omega) ∧
    (P.authV omega b).x = P.committedEval omega b

theorem masked_batch_transfers_evals
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount) (omega : Omega)
    (hgood : P.accepts omega)
    (hnotbad : ¬ P.committedEvalWrong omega)
    (hzero : ResponseZeroBatchAccepts P omega) :
    ∀ b : TouchedBlock P, ValidCommittedAuthEval P b omega := by
  intro b
  have hx := direct_mask_transfer
    (P.delta omega) (P.publicH omega b)
    (P.authV omega b) (P.authS omega b)
    (P.authSValid omega b) (hzero b)
  have heval : P.publicH omega b - (P.authS omega b).x =
      P.committedEval omega b := by
    by_contra hne
    exact hnotbad ⟨b, hne⟩
  have hresValid := (hzero b).1
  have hv : (P.authV omega b).Valid (P.delta omega) := by
    have hrecovered :=
      (hresValid.sub (P.authSValid omega b)).add
        (Authed.ofPublic_valid (P.delta omega) (P.publicH omega b))
    have heq :
        (P.authV omega b + P.authS omega b -
            Authed.ofPublic (P.delta omega) (P.publicH omega b)) -
          P.authS omega b +
            Authed.ofPublic (P.delta omega) (P.publicH omega b) =
          P.authV omega b := by
      abel
    rw [heq] at hrecovered
    exact hrecovered
  exact ⟨hv, hx.trans heval⟩

/-! ## Explicit binding, ZK and batching seams -/

/-- A concrete X4 PCS instantiation supplies this reduction object rather
than a new ideal axiom.  Its `bindingReduction` field is the separately owned
BaseFold/strict-UD/cohort proof; ZK and batching do not occur in this type. -/
structure X4UDPCSSystem (F : Type*) [DecidableEq F] where
  Statement : Type
  Proof : Type
  hash : X4V2Hash F
  committedFrames : Statement → Finset (X4CommitmentPreimage F)
  canonicalLayout : Statement → Prop
  udAccepts : Statement → Proof → Prop
  boundToUnique : Statement → Proof → Prop
  bindingReduction : ∀ statement proof,
    canonicalLayout statement →
    CollisionFreeOn hash (committedFrames statement) →
    udAccepts statement proof → boundToUnique statement proof

def CanonicalCohortLayoutV2 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystem F) (statement : S.Statement) : Prop :=
  S.canonicalLayout statement

def UDFoldingAccepts {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystem F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.udAccepts statement proof

def BoundToUniqueCommittedBlocks {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystem F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.boundToUnique statement proof

theorem x4_ud_pcs_binding {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystem F) (statement : S.Statement) (proof : S.Proof)
    (hframe : CanonicalCohortLayoutV2 S statement)
    (hmerkle : CollisionFreeOn S.hash (S.committedFrames statement))
    (hud : UDFoldingAccepts S statement proof) :
    BoundToUniqueCommittedBlocks S statement proof :=
  S.bindingReduction statement proof hframe hmerkle hud

/-- Transcript system used to state the paper simulator boundary without
turning that boundary into an `Ideal.lean` axiom. -/
structure X4MaskedTranscriptSystem
    (F Params Epoch Transcript PublicH Statement : Type*) where
  realTranscript : Params → Epoch → Transcript
  simulatedTranscript : Params → Epoch → PublicH → Transcript
  oneOpening : Epoch → Transcript → Prop
  noIndividualEvalFields : Transcript → Prop
  equalFiberCounts : Statement → Prop

def OneOpeningPerEpoch
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (epoch : Epoch) (transcript : Transcript) : Prop :=
  S.oneOpening epoch transcript

def NoIndividualEvalFields
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (transcript : Transcript) : Prop :=
  S.noIndividualEvalFields transcript

def RealMaskedTranscript
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (params : Params) (epoch : Epoch) : Transcript :=
  S.realTranscript params epoch

def SimMaskedTranscript
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (params : Params) (epoch : Epoch) (publicH : PublicH) : Transcript :=
  S.simulatedTranscript params epoch publicH

/-- The cited zkDeepFold simulator, explicitly conditional on the one-use and
no-individual-evaluation transcript boundaries. -/
def ZkDeepFoldSimulator
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (params : Params) : Prop :=
  ∀ epoch transcript publicH,
    OneOpeningPerEpoch S epoch transcript →
    NoIndividualEvalFields S transcript →
    RealMaskedTranscript S params epoch =
      SimMaskedTranscript S params epoch publicH

theorem masked_aux_perfect_zk
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (params : Params) (epoch : Epoch) (transcript : Transcript)
    (publicH : PublicH)
    (hone : OneOpeningPerEpoch S epoch transcript)
    (hpaper : ZkDeepFoldSimulator S params)
    (hframes : NoIndividualEvalFields S transcript) :
    RealMaskedTranscript S params epoch =
      SimMaskedTranscript S params epoch publicH :=
  hpaper epoch transcript publicH hone hframes

def MaskedAuxEqualFiberCounts
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (statement : Statement) : Prop :=
  S.equalFiberCounts statement

def X4WeightOpeningZK
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (publicH : PublicH) : Prop :=
  MaskedAuxEqualFiberCounts S statement ∧
    RealMaskedTranscript S params epoch =
      SimMaskedTranscript S params epoch publicH

theorem x4_masked_zk
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4MaskedTranscriptSystem F Params Epoch Transcript PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (transcript : Transcript) (publicH : PublicH)
    (hcount : MaskedAuxEqualFiberCounts S statement)
    (hone : OneOpeningPerEpoch S epoch transcript)
    (hpaper : ZkDeepFoldSimulator S params)
    (hframes : NoIndividualEvalFields S transcript) :
    X4WeightOpeningZK S statement params epoch publicH :=
  ⟨hcount, masked_aux_perfect_zk S params epoch transcript publicH
    hone hpaper hframes⟩

/-- Separate different-point batching reduction object.  It contains neither
PCS binding nor a ZK simulator. -/
structure X4BatchSystem (Claims Schedule : Type*) where
  maskedClaimsFixed : Claims → Prop
  canonicalClaimOrder : Claims → Prop
  hasCommonPoint : Schedule → Prop
  reductionBound : Claims → Schedule → Prop
  batchSound : Claims → Schedule → Prop
  reduction : ∀ claims schedule,
    maskedClaimsFixed claims → canonicalClaimOrder claims →
    hasCommonPoint schedule → reductionBound claims schedule →
    batchSound claims schedule

def CanonicalClaimOrder {Claims Schedule : Type*}
    (S : X4BatchSystem Claims Schedule) (claims : Claims) : Prop :=
  S.canonicalClaimOrder claims

def FoldingDifferentPointBatchBound {Claims Schedule : Type*}
    (S : X4BatchSystem Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.reductionBound claims schedule

def X4WeightBatchSound {Claims Schedule : Type*}
    (S : X4BatchSystem Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.batchSound claims schedule

theorem x4_batch_sound {Claims Schedule : Type*}
    (S : X4BatchSystem Claims Schedule)
    (claims : Claims) (schedule : Schedule)
    (hfixed : S.maskedClaimsFixed claims)
    (horder : CanonicalClaimOrder S claims)
    (hcommon : S.hasCommonPoint schedule)
    (hreduce : FoldingDifferentPointBatchBound S claims schedule) :
    X4WeightBatchSound S claims schedule :=
  S.reduction claims schedule hfixed horder hcommon hreduce

/-! ## Full response event cover and exact stop rule -/

/-- Staged semantic reduction from an accepted wrong response to one of the
four named statistical events.  Hash collision resistance is kept as a
separate computational premise and therefore never appears as a rational
summand. -/
structure X4ResponseReduction (F Omega : Type*)
    [DecidableEq F] [Fintype Omega] where
  hash : X4V2Hash F
  committedFrames : Finset (X4CommitmentPreimage F)
  acceptsWrong : Finset Omega
  foldBad : Finset Omega
  claimReduceBad : Finset Omega
  differentPointBatchBad : Finset Omega
  m9Bad : Finset Omega
  framesGood : Omega → Prop
  cohortGood : Omega → Prop
  pcsGood : Omega → Prop
  transferGood : Omega → Prop
  transferGoodRulesOutWrong : ∀ omega,
    transferGood omega → omega ∉ acceptsWrong

def CanonicalFramesAndOrderV2
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Prop :=
  ∀ omega ∈ R.acceptsWrong, R.framesGood omega

def CohortOpeningsBind
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Prop :=
  CollisionFreeOn R.hash R.committedFrames →
    ∀ omega, R.framesGood omega →
      omega ∈ R.foldBad ∨ R.cohortGood omega

def ResponseBoundToUniqueCommittedBlocks
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Prop :=
  ∀ omega, R.cohortGood omega →
    omega ∈ R.claimReduceBad ∨
    omega ∈ R.differentPointBatchBad ∨ R.pcsGood omega

def MaskedM9TransfersAllTouchedEvals
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Prop :=
  ∀ omega, R.pcsGood omega →
    omega ∈ R.m9Bad ∨ R.transferGood omega

noncomputable def x4NamedBadEvents
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Finset Omega := by
  classical
  exact ((R.foldBad ∪ R.claimReduceBad) ∪ R.differentPointBatchBad) ∪ R.m9Bad

def X4WrongResponseCoveredByNamedEvents
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : Prop :=
  R.acceptsWrong ⊆ x4NamedBadEvents R

theorem x4_wrong_response_event_cover
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega)
    (hframes : CanonicalFramesAndOrderV2 R)
    (hhash : CollisionFreeOn R.hash R.committedFrames)
    (hcohort : CohortOpeningsBind R)
    (hpcs : ResponseBoundToUniqueCommittedBlocks R)
    (htransfer : MaskedM9TransfersAllTouchedEvals R) :
    X4WrongResponseCoveredByNamedEvents R := by
  classical
  intro omega hwrong
  have hfgood := hframes omega hwrong
  rcases hcohort hhash omega hfgood with hfold | hcgood
  · simp [x4NamedBadEvents, hfold]
  rcases hpcs omega hcgood with hclaim | hbatch | hpgood
  · simp [x4NamedBadEvents, hclaim]
  · simp [x4NamedBadEvents, hbatch]
  rcases htransfer omega hpgood with hm9 | htgood
  · simp [x4NamedBadEvents, hm9]
  exact (R.transferGoodRulesOutWrong omega htgood hwrong).elim

noncomputable def X4FoldBad
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : X4Event Omega :=
  ⟨R.foldBad⟩

noncomputable def X4ClaimReduceBad
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : X4Event Omega :=
  ⟨R.claimReduceBad⟩

noncomputable def X4DifferentPointBatchBad
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : X4Event Omega :=
  ⟨R.differentPointBatchBad⟩

noncomputable def X4M9Bad
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : X4Event Omega :=
  ⟨R.m9Bad⟩

noncomputable def X4AcceptsWrongResponse
    {F Omega : Type*} [DecidableEq F] [Fintype Omega]
    (R : X4ResponseReduction F Omega) : X4Event Omega :=
  ⟨R.acceptsWrong⟩

def x4ResponseError : ℚ :=
  (3320 : ℚ) * ((9 : ℚ) / 16)^128 +
  (28522064267253 : ℚ) /
    (340282366762482138490186164457219031041 : ℚ)

private theorem x4_four_event_union_error
    {Omega : Type*} [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    (a b c d : Finset Omega) :
    (((((a ∪ b) ∪ c) ∪ d).card : Nat) : ℚ) /
        Fintype.card Omega ≤
      (a.card : ℚ) / Fintype.card Omega +
      (b.card : ℚ) / Fintype.card Omega +
      (c.card : ℚ) / Fintype.card Omega +
      (d.card : ℚ) / Fintype.card Omega := by
  classical
  have hab := card_union_le a b
  have habc := card_union_le (a ∪ b) c
  have habcd := card_union_le ((a ∪ b) ∪ c) d
  have hcard : (((a ∪ b) ∪ c) ∪ d).card ≤
      a.card + b.card + c.card + d.card := by omega
  have hcardQ : (((((a ∪ b) ∪ c) ∪ d).card : Nat) : ℚ) ≤
      (a.card + b.card + c.card + d.card : Nat) := by
    exact_mod_cast hcard
  push_cast at hcardQ
  rw [← add_div, ← add_div, ← add_div]
  exact div_le_div_of_nonneg_right hcardQ (by positivity)

theorem x4_response_soundness
    {F Omega : Type*} [DecidableEq F] [Fintype Omega] [Nonempty Omega]
    (R : X4ResponseReduction F Omega)
    (hcover : X4WrongResponseCoveredByNamedEvents R)
    (hfold : statisticalError (X4FoldBad R) ≤
      (3320 : ℚ) * ((9 : ℚ) / 16)^128 +
      (28522064111120 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hclaim : statisticalError (X4ClaimReduceBad R) ≤
      (151060 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hbatch : statisticalError (X4DifferentPointBatchBad R) ≤
      (3412 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hm9 : statisticalError (X4M9Bad R) ≤
      (1661 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ)) :
    statisticalError (X4AcceptsWrongResponse R) ≤ x4ResponseError := by
  classical
  have hcard : R.acceptsWrong.card ≤ (x4NamedBadEvents R).card :=
    card_le_card hcover
  have hfirst : statisticalError (X4AcceptsWrongResponse R) ≤
      ((x4NamedBadEvents R).card : ℚ) / Fintype.card Omega := by
    exact div_le_div_of_nonneg_right (by exact_mod_cast hcard) (by positivity)
  have hunion : ((x4NamedBadEvents R).card : ℚ) /
      Fintype.card Omega ≤
      statisticalError (X4FoldBad R) +
      statisticalError (X4ClaimReduceBad R) +
      statisticalError (X4DifferentPointBatchBad R) +
      statisticalError (X4M9Bad R) := by
    change ((x4NamedBadEvents R).card : ℚ) / Fintype.card Omega ≤
      (R.foldBad.card : ℚ) / Fintype.card Omega +
      (R.claimReduceBad.card : ℚ) / Fintype.card Omega +
      (R.differentPointBatchBad.card : ℚ) / Fintype.card Omega +
      (R.m9Bad.card : ℚ) / Fintype.card Omega
    simpa [x4NamedBadEvents]
      using x4_four_event_union_error R.foldBad R.claimReduceBad
        R.differentPointBatchBad R.m9Bad
  calc
    statisticalError (X4AcceptsWrongResponse R)
        ≤ ((x4NamedBadEvents R).card : ℚ) / Fintype.card Omega := hfirst
    _ ≤ statisticalError (X4FoldBad R) +
        statisticalError (X4ClaimReduceBad R) +
        statisticalError (X4DifferentPointBatchBad R) +
        statisticalError (X4M9Bad R) := hunion
    _ ≤ ((3320 : ℚ) * ((9 : ℚ) / 16)^128 +
          (28522064111120 : ℚ) /
            (340282366762482138490186164457219031041 : ℚ)) +
        (151060 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (3412 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (1661 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) :=
      add_le_add (add_le_add (add_le_add hfold hclaim) hbatch) hm9
    _ = x4ResponseError := by
      norm_num [x4ResponseError]

theorem x4_response_error_lt_two_pow_neg_83 :
    x4ResponseError < (1 : ℚ) / 2^83 := by
  norm_num [x4ResponseError]

theorem x4_response_error_meets_registered_target :
    (x4ResponseError : ℝ) <
      Real.rpow 2 (-((78809294874 : ℝ) / 1000000000)) := by
  have hrat := x4_response_error_lt_two_pow_neg_83
  have hcast : (x4ResponseError : ℝ) < (1 : ℝ) / 2^83 := by
    have hcast' := (Rat.cast_lt (K := ℝ)).2 hrat
    have hden : ((((1 : ℚ) / 2^83 : ℚ) : ℝ)) =
        (1 : ℝ) / 2^83 := by norm_num
    rw [hden] at hcast'
    exact hcast'
  have hexp : (-(83 : ℝ)) <
      -((78809294874 : ℝ) / 1000000000) := by
    norm_num
  have hrpow := Real.rpow_lt_rpow_of_exponent_lt
    (by norm_num : (1 : ℝ) < 2) hexp
  have hpow83 : Real.rpow 2 (-(83 : ℝ)) = (1 : ℝ) / 2^83 := by
    calc
      Real.rpow 2 (-(83 : ℝ)) = (2 : ℝ) ^ (-(83 : ℤ)) := by
        convert Real.rpow_neg_natCast (2 : ℝ) 83 using 1 <;> norm_num
      _ = (1 : ℝ) / 2^83 := by
        norm_num only [zpow_neg, zpow_natCast, one_div]
  exact hcast.trans (hpow83 ▸ hrpow)

/-! ## Discharge-time separation and characteristic hypothesis -/

/-- Ligero binding/proximity discharge.  This boundary is intentionally a
different type and theorem from the mask simulator and batch reduction.
Normative source: Ligero (CCS 2017; extended ePrint 2022/1608), specialized
to the implemented code and Merkle layout. -/
structure LigeroBindingBoundary where
  implementedLigeroBinding : Prop
  currentWeightCommitmentBinding : Prop
  reduction : implementedLigeroBinding → currentWeightCommitmentBinding

def LigeroCommitmentBinding (D : LigeroBindingBoundary) : Prop :=
  D.implementedLigeroBinding

def CurrentWeightCommitmentBinding (D : LigeroBindingBoundary) : Prop :=
  D.currentWeightCommitmentBinding

theorem ligero_binding_discharge (D : LigeroBindingBoundary)
    (h : LigeroCommitmentBinding D) :
    CurrentWeightCommitmentBinding D :=
  D.reduction h

/-- VOLTA-specific blinded-Ligero simulator discharge.  Ligero is background
only; the premise is the system-specific mask-row/exposure simulator. -/
structure LigeroBlindedZKBoundary where
  voltaLigeroMaskSimulator : Prop
  currentWeightOpeningZK : Prop
  reduction : voltaLigeroMaskSimulator → currentWeightOpeningZK

def VoltaLigeroMaskSimulator (D : LigeroBlindedZKBoundary) : Prop :=
  D.voltaLigeroMaskSimulator

def CurrentWeightOpeningZK (D : LigeroBlindedZKBoundary) : Prop :=
  D.currentWeightOpeningZK

theorem ligero_blinded_zk_discharge (D : LigeroBlindedZKBoundary)
    (hmask : VoltaLigeroMaskSimulator D) :
    CurrentWeightOpeningZK D :=
  D.reduction hmask

/-- Current common-point multi-opening reduction, separately owned by the
repository's scalar blind-sumcheck theorem rather than the Ligero citation. -/
structure LigeroBatchBoundary (Claims Schedule : Type*) where
  claimsFixedBeforeChallenge : Claims → Prop
  hasCommonPoint : Schedule → Prop
  currentWeightBatchSound : Claims → Schedule → Prop
  reduction : ∀ claims schedule,
    claimsFixedBeforeChallenge claims → hasCommonPoint schedule →
      currentWeightBatchSound claims schedule

def CurrentWeightBatchSound {Claims Schedule : Type*}
    (D : LigeroBatchBoundary Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  D.currentWeightBatchSound claims schedule

theorem ligero_multi_point_batch_discharge
    {Claims Schedule : Type*} (D : LigeroBatchBoundary Claims Schedule)
    (claims : Claims) (schedule : Schedule)
    (hfixed : D.claimsFixedBeforeChallenge claims)
    (hcommon : D.hasCommonPoint schedule) :
    CurrentWeightBatchSound D claims schedule :=
  D.reduction claims schedule hfixed hcommon

/-- A compact formal carrier for a UC realization certificate.  The theorem
below does not manufacture such a certificate; the hybrid premise must expose
the exact composition map after *both* subfunctionalities are realized. -/
structure UCRealizes (Protocol Functionality : Type*) : Prop where
  realization : Nonempty (Protocol ≃ Functionality)

abbrev compose (PiVOLTA PiSVOLE PiPCS : Type*) :=
  PiVOLTA × PiSVOLE × PiPCS

structure UCHybridRealizes
    (PiVOLTA FVDec PiSVOLE FSVOLE PiPCS FPCS : Type*) : Prop where
  closeComposition :
    UCRealizes PiSVOLE FSVOLE → UCRealizes PiPCS FPCS →
      UCRealizes (compose PiVOLTA PiSVOLE PiPCS) FVDec

theorem uc_composition_of_realizations
    {PiVOLTA FVDec PiSVOLE FSVOLE PiPCS FPCS : Type*}
    (hsvole : UCRealizes PiSVOLE FSVOLE)
    (hpcs : UCRealizes PiPCS FPCS)
    (hhybrid : UCHybridRealizes
      PiVOLTA FVDec PiSVOLE FSVOLE PiPCS FPCS) :
    UCRealizes (compose PiVOLTA PiSVOLE PiPCS) FVDec :=
  hhybrid.closeComposition hsvole hpcs

/-- The three separately owned propositions entering a discharged LogUp--GKR
composition.  Keeping them as fields of the statement (rather than axioms)
lets concrete instantiations supply independently audited proofs. -/
structure LogUpDischargeStatement (F : Type*) (lookupCount : Nat) where
  logUpSound : Prop
  fractionalGKRCompositionSound : Prop
  authenticatedTranscriptSound : Prop

def LogUpSoundAtCount {F : Type*} {lookupCount : Nat}
    (S : LogUpDischargeStatement F lookupCount) : Prop :=
  S.logUpSound

def FractionalGKRCompositionSound {F : Type*} {lookupCount : Nat}
    (S : LogUpDischargeStatement F lookupCount) : Prop :=
  S.fractionalGKRCompositionSound

def AuthenticatedTranscriptSound {F : Type*} {lookupCount : Nat}
    (S : LogUpDischargeStatement F lookupCount) : Prop :=
  S.authenticatedTranscriptSound

/-- The discharged conclusion retains the characteristic witness and strict
`lookupCount < p` premise instead of hiding it in an informal citation. -/
def LogUpGKRSoundAtCount {F : Type*} {lookupCount p : Nat}
    (S : LogUpDischargeStatement F lookupCount) : Prop :=
  lookupCount < p ∧ LogUpSoundAtCount S ∧
    FractionalGKRCompositionSound S ∧ AuthenticatedTranscriptSound S

theorem logup_gkr_sound_of_char_gt
    {F : Type*} [Field F] {p lookupCount : Nat}
    [Fact (Nat.Prime p)] [CharP F p]
    (S : LogUpDischargeStatement F lookupCount)
    (hchar : lookupCount < p)
    (hlogup : LogUpSoundAtCount S)
    (hgkr : FractionalGKRCompositionSound S)
    (hmac : AuthenticatedTranscriptSound S) :
    LogUpGKRSoundAtCount (p := p) S :=
  ⟨hchar, hlogup, hgkr, hmac⟩

end VoltaZk

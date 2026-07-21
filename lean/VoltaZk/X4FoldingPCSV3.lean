import VoltaZk.X4FoldingPCS

/-!
# X4 authenticated-output folding PCS — Amendments 3 and 4

This file discharges the exact pre-code theorem set frozen in Sections
0.10.6 and 0.11 of `docs/x4-folding-pcs-design.md`.  Amendment 4 changes only
the two Bound-output conclusions from deterministic equality to
`equality ∨ LinkBad`; the latter is already one of the four response-wide
events.  No declaration here changes the v3 protocol or its accounting.
-/

namespace VoltaZk

open Finset

noncomputable local instance x4V3PropDecidable (p : Prop) : Decidable p :=
  Classical.propDecidable p

/-! ## Correction-view bijection and conditioned mask fiber -/

section CorrectionView

/-- Verifier-visible key/correction pair for one full-field correlation. -/
def corrCorrectionView {F : Type*} [Ring F]
    (Delta x : F) (am : F × F) : F × F :=
  (am.2 + Delta * am.1, x - am.1)

private def corrCorrectionViewInv {F : Type*} [Ring F]
    (Delta x : F) (kc : F × F) : F × F :=
  (x - kc.2, kc.1 - Delta * (x - kc.2))

def corrCorrectionEquiv {F : Type*} [CommRing F]
    (Delta x : F) : F × F ≃ F × F where
  toFun := corrCorrectionView Delta x
  invFun := corrCorrectionViewInv Delta x
  left_inv am := by
    rcases am with ⟨a, m⟩
    ext <;> simp [corrCorrectionView, corrCorrectionViewInv]
  right_inv kc := by
    rcases kc with ⟨k, c⟩
    ext <;> simp [corrCorrectionView, corrCorrectionViewInv]

theorem corr_correction_view_bijective {F : Type*} [CommRing F]
    (Delta x : F) :
    Function.Bijective (corrCorrectionView Delta x) :=
  (corrCorrectionEquiv Delta x).bijective

theorem corr_correction_views_unique_preimage
    {F : Type*} [CommRing F] [Fintype F] {n : Nat}
    (Delta : F) (secret : Fin n → F) (view : Fin n → F × F) :
    Fintype.card {am : Fin n → F × F //
      ∀ i, corrCorrectionView Delta (secret i) (am i) = view i} = 1 := by
  classical
  rw [Fintype.card_eq_one_iff]
  let target : Fin n → F × F := fun i =>
    (corrCorrectionEquiv Delta (secret i)).symm (view i)
  let targetInFiber : {am : Fin n → F × F //
      ∀ i, corrCorrectionView Delta (secret i) (am i) = view i} :=
    ⟨target, by
      intro i
      exact (corrCorrectionEquiv Delta (secret i)).apply_symm_apply
        (view i)⟩
  refine ⟨targetInFiber, ?_⟩
  intro am
  apply Subtype.ext
  funext i
  apply (corrCorrectionEquiv Delta (secret i)).injective
  calc
    corrCorrectionEquiv Delta (secret i) (am.1 i) = view i := am.2 i
    _ = corrCorrectionEquiv Delta (secret i) (target i) := by
      exact ((corrCorrectionEquiv Delta (secret i)).apply_symm_apply
        (view i)).symm

abbrev AuthenticatedLinkCorrView (F : Type*) (n : Nat) :=
  Fin n → F × F

/-- A deterministic stand-in for all link secrets derived from a coefficient
table.  The unique-preimage theorem above applies to arbitrary secret vectors;
this concrete map lets the fiber theorem state the product conditioning
without adding a second equation on `g`. -/
noncomputable def x4AuthenticatedLinkSecret
    {F ι : Type*} [Field F] [Fintype ι] {n : Nat}
    (g : ι → F) (i : Fin n) : F :=
  (i.val + 1 : Nat) * ∑ j, g j

def HasAuthenticatedLinkView
    {F ι : Type*} [Field F] [Fintype ι] {n : Nat}
    (Delta : F) (g : ι → F)
    (fixedView : AuthenticatedLinkCorrView F n) : Prop :=
  ∃ am : Fin n → F × F, ∀ i,
    corrCorrectionView Delta (x4AuthenticatedLinkSecret g i) (am i) =
      fixedView i

private theorem has_authenticated_link_view
    {F ι : Type*} [Field F] [Fintype ι] {n : Nat}
    (Delta : F) (g : ι → F)
    (fixedView : AuthenticatedLinkCorrView F n) :
    HasAuthenticatedLinkView Delta g fixedView := by
  classical
  refine ⟨fun i =>
    (corrCorrectionEquiv Delta (x4AuthenticatedLinkSecret g i)).symm
      (fixedView i), ?_⟩
  intro i
  exact (corrCorrectionEquiv Delta (x4AuthenticatedLinkSecret g i)).apply_symm_apply
    (fixedView i)

theorem masked_aux_authenticated_link_hiding_count
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {ell n : Nat} (hell : 0 < ell) (u : Fin ell → F)
    (hfunc : EvalFunctionalNonzero u)
    (h v Delta : F) (fixedView : AuthenticatedLinkCorrView F n) :
    Fintype.card
        {g : (Fin ell → Fin 2) → F //
          h = v + x4MleLinear u g ∧
            HasAuthenticatedLinkView Delta g fixedView} =
      Fintype.card F ^ (2^ell - 1) := by
  classical
  let e :
      {g : (Fin ell → Fin 2) → F //
        h = v + x4MleLinear u g ∧
          HasAuthenticatedLinkView Delta g fixedView} ≃
      {g : (Fin ell → Fin 2) → F //
        h = v + x4MleLinear u g} :=
    {
    toFun := fun g => ⟨g.1, g.2.1⟩
    invFun := fun g => ⟨g.1, g.2,
      has_authenticated_link_view Delta g.1 fixedView⟩
    left_inv := by intro g; apply Subtype.ext; rfl
    right_inv := by intro g; apply Subtype.ext; rfl }
  rw [Fintype.card_congr e]
  exact masked_aux_hiding_count hell u hfunc v h

end CorrectionView

theorem x4_aux_mask_entropy_budget_max_v3 :
    128 * 29^2 < 2^17 - 1 := by
  norm_num

/-! ## Product-view ZK composition -/

structure AuthenticatedLinkView
    (ScheduleView CorrView TerminalView : Type*) where
  schedule : ScheduleView
  corrections : CorrView
  terminal : TerminalView

structure AuthenticatedOutputLinkZKSystem
    (LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*) where
  domainsFresh : LinkSchedule → Prop
  realSchedule : LinkSchedule → ScheduleView
  simSchedule : LinkSchedule → ScheduleView
  realCorrections : Statement → CorrView
  simCorrections : Statement → PublicH → CorrView
  realTerminal : Statement → TerminalView
  simTerminal : Statement → PublicH → TerminalView

def FreshDisjointFullCorrDomains
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (schedule : LinkSchedule) : Prop :=
  S.domainsFresh schedule ∧ S.realSchedule schedule = S.simSchedule schedule

def CorrCorrectionViewsAreBijective
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (schedule : LinkSchedule) : Prop :=
  ∀ statement publicH,
    S.realCorrections statement = S.simCorrections statement publicH

def TerminalValuesCoveredByZkDeepFoldSimulator
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (statement : Statement) : Prop :=
  ∀ publicH, S.realTerminal statement = S.simTerminal statement publicH

def RealAuthenticatedLinkView
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (schedule : LinkSchedule) (statement : Statement) :
    AuthenticatedLinkView ScheduleView CorrView TerminalView :=
  ⟨S.realSchedule schedule, S.realCorrections statement,
    S.realTerminal statement⟩

def SimAuthenticatedLinkView
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (schedule : LinkSchedule) (statement : Statement) (publicH : PublicH) :
    AuthenticatedLinkView ScheduleView CorrView TerminalView :=
  ⟨S.simSchedule schedule, S.simCorrections statement publicH,
    S.simTerminal statement publicH⟩

theorem blind_authenticated_output_link_perfect_zk
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView : Type*}
    (S : AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView)
    (linkSchedule : LinkSchedule) (statement : Statement) (publicH : PublicH)
    (hfresh : FreshDisjointFullCorrDomains S linkSchedule)
    (hcorr : CorrCorrectionViewsAreBijective S linkSchedule)
    (hterminal : TerminalValuesCoveredByZkDeepFoldSimulator S statement) :
    RealAuthenticatedLinkView S linkSchedule statement =
      SimAuthenticatedLinkView S linkSchedule statement publicH := by
  unfold RealAuthenticatedLinkView SimAuthenticatedLinkView
  rw [hfresh.2, hcorr statement publicH, hterminal publicH]

/-! ## Pending-to-Bound typestate with Amendment-4 event conditioning -/

structure PendingAuxEval (F : Type*) where
  auth : Authed F

structure BoundAuxEval (F : Type*) where
  auth : Authed F

/-- Deliberately empty: a pending correction cannot be consumed by the
response ZeroBatch API. -/
inductive UsableByResponseZeroBatch {F : Type*} : PendingAuxEval F → Prop

theorem pending_aux_cannot_escape {F : Type*}
    (p : PendingAuxEval F) :
    ¬ UsableByResponseZeroBatch p := by
  intro h
  exact nomatch h

structure AuthenticatedOutputLinkStatement
    (F : Type*) (blockCount : Nat) where
  authS : Fin blockCount → Authed F
  committedAuxEval : Fin blockCount → F
  claimsFixedBeforeChallenge : Prop

structure AuthenticatedOutputLinkProof where
  accepted : Bool
  terminalClosed : Bool
  m9Positions : List Nat
  linkChallengePosition : Nat

def AllM9FramesFixedBeforeLinkChallenge
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  ∀ position ∈ proof.m9Positions, position < proof.linkChallengePosition

/-- Raw verifier acceptance includes the normative order check, but never
committed equality or `¬LinkBad`. -/
def VerifyAuthenticatedOutputLink
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  proof.accepted = true ∧ AllM9FramesFixedBeforeLinkChallenge proof

def LinkTerminalClosedByUDFoldQueries
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  proof.terminalClosed = true

def AuthenticatedOutputClaimsFixedBeforeChallenge
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount) : Prop :=
  statement.claimsFixedBeforeChallenge

/-- The named event is raw acceptance and truthful terminal closure with at
least one wrong authenticated auxiliary plaintext. -/
def LinkBad
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  VerifyAuthenticatedOutputLink statement proof ∧
    LinkTerminalClosedByUDFoldQueries statement proof ∧
    ∃ b, (statement.authS b).x ≠ statement.committedAuxEval b

noncomputable def verifierBoundAuxOutput
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) (b : Fin blockCount) :
    Option (BoundAuxEval F) :=
  if VerifyAuthenticatedOutputLink statement proof ∧
      LinkTerminalClosedByUDFoldQueries statement proof then
    some ⟨statement.authS b⟩
  else none

theorem authenticated_output_link_produces_bound_aux
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof)
    (hfixed : AuthenticatedOutputClaimsFixedBeforeChallenge statement)
    (haccept : VerifyAuthenticatedOutputLink statement proof)
    (hterminal : LinkTerminalClosedByUDFoldQueries statement proof) :
    ∀ b : Fin blockCount,
      ∃ out : BoundAuxEval F,
        out.auth = statement.authS b ∧
          (out.auth.x = statement.committedAuxEval b ∨
            LinkBad statement proof) := by
  intro b
  refine ⟨⟨statement.authS b⟩, rfl, ?_⟩
  by_cases heq : (statement.authS b).x = statement.committedAuxEval b
  · exact Or.inl heq
  · exact Or.inr ⟨haccept, hterminal, b, heq⟩

theorem bound_aux_has_verified_origin
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) (b : Fin blockCount)
    (out : BoundAuxEval F)
    (hout : verifierBoundAuxOutput statement proof b = some out) :
    VerifyAuthenticatedOutputLink statement proof ∧
      LinkTerminalClosedByUDFoldQueries statement proof ∧
      out.auth = statement.authS b ∧
      (out.auth.x = statement.committedAuxEval b ∨
        LinkBad statement proof) := by
  unfold verifierBoundAuxOutput at hout
  split at hout
  · rename_i hchecks
    have houtEq : (⟨statement.authS b⟩ : BoundAuxEval F) = out :=
      Option.some.inj hout
    subst out
    refine ⟨hchecks.1, hchecks.2, rfl, ?_⟩
    by_cases heq : (statement.authS b).x = statement.committedAuxEval b
    · exact Or.inl heq
    · exact Or.inr ⟨hchecks.1, hchecks.2, b, heq⟩
  · contradiction

theorem x4_v3_m9_fixed_before_link_challenge
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof)
    (h : VerifyAuthenticatedOutputLink statement proof) :
    AllM9FramesFixedBeforeLinkChallenge proof :=
  h.2

/-! ## One blind batch and its permanent beta-collision artifact -/

structure AuthenticatedOutputBatchLink
    (F : Type*) [Field F] (relationCount rounds : Nat)
    (ι : Type*) [Fintype ι] where
  reduction : X4ScalarReduction F relationCount rounds ι
  points : Fin relationCount → Fin rounds → F
  commonPoint : Fin rounds → F

def AuthenticatedOutputClaimsFixedBeforeChallengeV3
    {F ι : Type*} [Field F] [Fintype ι]
    {relationCount rounds : Nat}
    (P : AuthenticatedOutputBatchLink F relationCount rounds ι) : Prop :=
  MaskedClaimsFixed P.reduction

def LinkTerminalBoundByUniqueCommittedOracles
    {F ι : Type*} [Field F] [Fintype ι]
    {relationCount rounds : Nat}
    (P : AuthenticatedOutputBatchLink F relationCount rounds ι) : Prop :=
  HasCommonPoint P.points P.commonPoint

theorem authenticated_output_batch_link_sound
    {F ι : Type*} [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    {relationCount rounds touchedBlocks : Nat}
    (P : AuthenticatedOutputBatchLink F relationCount rounds ι)
    (hfixed : AuthenticatedOutputClaimsFixedBeforeChallengeV3 P)
    (hBpos : 0 < touchedBlocks)
    (hrelations : relationCount = 2*touchedBlocks)
    (hcount : relationCount ≤ 3320)
    (hroundsPos : 0 < rounds)
    (hrounds : rounds ≤ 30)
    (hterminal : LinkTerminalBoundByUniqueCommittedOracles P) :
    x4ReductionBadTapeCard hroundsPos P.reduction ≤
      (relationCount + 3*rounds + 2) * x4FieldTapeCard F rounds := by
  exact folding_different_point_batch_sound hroundsPos P.reduction
    P.points P.commonPoint hfixed hcount hterminal hrounds

theorem authenticated_output_batch_beta_collision_counterexample :
    let committedW : ℚ := 3
    let committedG : ℚ := 5
    let publicH : ℚ := 7
    let authenticatedS : ℚ := 6
    let beta : ℚ := 1
    let maskedResidual := committedW + committedG - publicH
    let outputResidual := committedG - authenticatedS
    maskedResidual ≠ 0 ∧
      outputResidual ≠ 0 ∧
      maskedResidual + beta * outputResidual = 0 ∧
      authenticatedS ≠ committedG := by
  norm_num

/-! ## Normative schema-3 frame boundary -/

/-- The eleven historical kinds plus Amendment 3's authenticated-output
link schedule. -/
inductive X4FrameKindV3
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
  | authenticatedOutputLink
  deriving DecidableEq, Repr

def X4FrameKindV3.code : X4FrameKindV3 → X4Byte
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
  | .authenticatedOutputLink => 0x0c

def X4FrameKindV3.ofCode : X4Byte → Option X4FrameKindV3
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
  | 0x0c => some .authenticatedOutputLink
  | _ => none

@[simp] theorem X4FrameKindV3.ofCode_code (kind : X4FrameKindV3) :
    X4FrameKindV3.ofCode kind.code = some kind := by
  cases kind <;> rfl

private def x4V3Byte (n : Nat) (h : n < 256 := by omega) : X4Byte :=
  ⟨n, h⟩

def x4EncodeU32LEV3 (n : Nat) : List X4Byte :=
  [x4V3Byte (n % 256), x4V3Byte ((n / 256) % 256),
    x4V3Byte ((n / 256^2) % 256), x4V3Byte ((n / 256^3) % 256)]

/-- `VOLTAX43`, schema 3, zero flags, and a canonical little-endian body
length. -/
def x4FrameHeaderV3 (kind : X4FrameKindV3) (bodyLength : Nat) :
    List X4Byte :=
  [x4V3Byte 86, x4V3Byte 79, x4V3Byte 76, x4V3Byte 84,
    x4V3Byte 65, x4V3Byte 88, x4V3Byte 52, x4V3Byte 51,
    x4V3Byte 3, x4V3Byte 0, kind.code, x4V3Byte 0] ++
    x4EncodeU32LEV3 bodyLength

@[simp] theorem x4FrameHeaderV3_length (kind : X4FrameKindV3)
    (bodyLength : Nat) :
    (x4FrameHeaderV3 kind bodyLength).length = 16 := by
  simp [x4FrameHeaderV3, x4EncodeU32LEV3]

structure X4FrameV3 where
  kind : X4FrameKindV3
  body : List X4Byte
  bodyLengthFits : body.length < 2^32
  deriving DecidableEq

@[ext] theorem X4FrameV3.ext {a b : X4FrameV3}
    (hkind : a.kind = b.kind) (hbody : a.body = b.body) : a = b := by
  cases a
  cases b
  simp_all

def encodeX4FrameV3 (f : X4FrameV3) : List X4Byte :=
  x4FrameHeaderV3 f.kind f.body.length ++ f.body

def decodeX4FrameV3 (bytes : List X4Byte) : Option X4FrameV3 :=
  match bytes[10]? with
  | none => none
  | some kindCode =>
      match X4FrameKindV3.ofCode kindCode with
      | none => none
      | some kind =>
          let body := bytes.drop 16
          if hfit : body.length < 2^32 then
            if bytes = x4FrameHeaderV3 kind body.length ++ body then
              some { kind := kind, body := body, bodyLengthFits := hfit }
            else none
          else none

theorem x4_v3_frame_decode_encode (f : X4FrameV3) :
    decodeX4FrameV3 (encodeX4FrameV3 f) = some f := by
  have hfit : f.body.length < 4294967296 := by
    simpa using f.bodyLengthFits
  simp [decodeX4FrameV3, encodeX4FrameV3, x4FrameHeaderV3,
    x4EncodeU32LEV3, hfit]

theorem x4_v3_frame_decode_canonical {bytes : List X4Byte}
    {f : X4FrameV3}
    (h : decodeX4FrameV3 bytes = some f) :
    encodeX4FrameV3 f = bytes := by
  unfold decodeX4FrameV3 at h
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

theorem x4_v3_frame_kind_encoding_disjoint
    (a b : X4FrameV3) (hkind : a.kind ≠ b.kind) :
    encodeX4FrameV3 a ≠ encodeX4FrameV3 b := by
  intro heq
  have hdecode : some a = some b := by
    rw [← x4_v3_frame_decode_encode a,
      ← x4_v3_frame_decode_encode b, heq]
  have hab : a = b := Option.some.inj hdecode
  exact hkind (congrArg X4FrameV3.kind hab)

/-! ## Schema-3 cohort and strict-UD binding -/

/-- Version separation is enforced by the canonical schema-3 frame theorem
and the concrete `/v3` hash contexts.  The abstract digest carrier is shared
with the already proved typed-preimage collision reduction. -/
abbrev X4V3Hash (F : Type*) := X4V2Hash F

structure X4CohortOpeningV3 (F : Type*) where
  preimage : X4CommitmentPreimage F
  frame : X4FrameV3
  frameIsPcsLeaf : frame.kind = .pcsLeaf

def X4CohortOpeningV3.symbols {F : Type*}
    (opening : X4CohortOpeningV3 F) : List F :=
  opening.preimage.symbols

noncomputable def VerifyCohortOpeningV3
    {F : Type*} [DecidableEq F]
    (H : X4V3Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root : X4Digest) (descriptor : X4Digest)
    (point : List F) (slot : Nat) (opening : X4CohortOpeningV3 F) : Prop :=
  opening.preimage ∈ committedFrames ∧
    opening.frame.kind = .pcsLeaf ∧
    opening.preimage.domain = .pcsLeaf ∧
    opening.preimage.descriptor = descriptor ∧
    opening.preimage.point = point ∧
    opening.preimage.slot = slot ∧
    H.digest opening.preimage = root

theorem cohort_opening_binding_v3 {F : Type*} [DecidableEq F]
    (H : X4V3Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root descriptor : X4Digest) (point : List F) (slot : Nat)
    (openA openB : X4CohortOpeningV3 F)
    (hhash : CollisionFreeOn H committedFrames)
    (ha : VerifyCohortOpeningV3 H committedFrames root descriptor point slot openA)
    (hb : VerifyCohortOpeningV3 H committedFrames root descriptor point slot openB) :
    openA.symbols = openB.symbols := by
  have hpre : openA.preimage = openB.preimage :=
    hhash openA.preimage ha.1 openB.preimage hb.1
      (ha.2.2.2.2.2.2.trans hb.2.2.2.2.2.2.symm)
  exact congrArg X4CommitmentPreimage.symbols hpre

/-- V3 binding is a separate reduction object.  It contains neither a ZK
simulator nor a multi-point batching theorem. -/
structure X4UDPCSSystemV3 (F : Type*) [DecidableEq F] where
  Statement : Type
  Proof : Type
  hash : X4V3Hash F
  committedFrames : Statement → Finset (X4CommitmentPreimage F)
  canonicalLayout : Statement → Prop
  udAccepts : Statement → Proof → Prop
  boundToUnique : Statement → Proof → Prop
  bindingReduction : ∀ statement proof,
    canonicalLayout statement →
    CollisionFreeOn hash (committedFrames statement) →
    udAccepts statement proof → boundToUnique statement proof

def CanonicalCohortLayoutV3 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV3 F) (statement : S.Statement) : Prop :=
  S.canonicalLayout statement

def UDFoldingAcceptsV3 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV3 F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.udAccepts statement proof

def BoundToUniqueCommittedBlocksV3 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV3 F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.boundToUnique statement proof

theorem x4_ud_pcs_binding_v3 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV3 F) (statement : S.Statement) (proof : S.Proof)
    (hframe : CanonicalCohortLayoutV3 S statement)
    (hmerkle : CollisionFreeOn S.hash (S.committedFrames statement))
    (hud : UDFoldingAcceptsV3 S statement proof) :
    BoundToUniqueCommittedBlocksV3 S statement proof :=
  S.bindingReduction statement proof hframe hmerkle hud

/-! ## Authenticated-output transfer and four-event reduction -/

structure AuthenticatedOutputBatchCore
    (F Omega : Type*) [Field F] (blockCount : Nat) where
  transfer : MaskedBatchTransfer F Omega blockCount
  committedAuxEval : Omega → Fin blockCount → F

def AuthenticatedOutputLinkGoodCore
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : AuthenticatedOutputBatchCore F Omega blockCount)
    (omega : Omega) : Prop :=
  ∀ b,
    (P.transfer.authS omega b).x = P.committedAuxEval omega b ∧
    P.transfer.publicH omega b =
      P.transfer.committedEval omega b + P.committedAuxEval omega b

def ResponseZeroBatchAcceptsV3Core
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : AuthenticatedOutputBatchCore F Omega blockCount)
    (omega : Omega) : Prop :=
  ResponseZeroBatchAccepts P.transfer omega

def DeltaShiftAttemptCore
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : AuthenticatedOutputBatchCore F Omega blockCount)
    (omega : Omega) : Prop :=
  ∃ (b : Fin blockCount) (delta : F), delta ≠ 0 ∧
    (P.transfer.authV omega b).x =
      P.transfer.committedEval omega b - delta ∧
    (P.transfer.authS omega b).x =
      P.committedAuxEval omega b + delta ∧
    P.transfer.publicH omega b =
      P.transfer.committedEval omega b + P.committedAuxEval omega b

/-- The response carrier exposes each semantic stage separately.  In
particular, `linkStep` returns the Amendment-4 disjunction; it never defines
raw verifier acceptance to contain equality. -/
structure AuthenticatedOutputBatch
    (F Omega : Type*) [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] (blockCount : Nat) where
  core : AuthenticatedOutputBatchCore F Omega blockCount
  hash : X4V3Hash F
  committedFrames : Finset (X4CommitmentPreimage F)
  responseAccepts : Finset Omega
  acceptsWrong : Finset Omega
  foldBad : Finset Omega
  claimReduceBad : Finset Omega
  authenticatedOutputLinkBad : Finset Omega
  responseZeroBatchBad : Finset Omega
  framesGood : Omega → Prop
  cohortGood : Omega → Prop
  pcsGood : Omega → Prop
  wrongImpliesAccepts : acceptsWrong ⊆ responseAccepts
  cohortStep : CollisionFreeOn hash committedFrames →
    ∀ omega, framesGood omega → omega ∈ foldBad ∨ cohortGood omega
  pcsStep : ∀ omega, cohortGood omega →
    omega ∈ claimReduceBad ∨ pcsGood omega
  linkStep : ∀ omega, pcsGood omega →
    omega ∈ authenticatedOutputLinkBad ∨
      (AuthenticatedOutputLinkGoodCore core omega ∧
        omega ∉ authenticatedOutputLinkBad)
  zeroStep : ∀ omega, AuthenticatedOutputLinkGoodCore core omega →
    omega ∈ responseZeroBatchBad ∨
      ResponseZeroBatchAcceptsV3Core core omega
  goodRulesOutWrong : ∀ omega,
    AuthenticatedOutputLinkGoodCore core omega →
    ResponseZeroBatchAcceptsV3Core core omega →
    omega ∉ acceptsWrong
  deltaFoldOrPcs : CollisionFreeOn hash committedFrames →
    ∀ omega, framesGood omega → DeltaShiftAttemptCore core omega →
      omega ∈ responseAccepts → omega ∈ foldBad ∨ pcsGood omega

abbrev TouchedBlockV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) :=
  Fin blockCount

def DeltaShiftAttempt
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  DeltaShiftAttemptCore P.core omega

def ResponseZeroBatchAcceptsV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  ResponseZeroBatchAcceptsV3Core P.core omega

def AuthenticatedOutputLinkGood
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  AuthenticatedOutputLinkGoodCore P.core omega ∧
    omega ∉ P.authenticatedOutputLinkBad

def X4ResponseAcceptsV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  omega ∈ P.responseAccepts

def X4AuthenticatedOutputLinkBad
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.authenticatedOutputLinkBad

def X4FoldQueryBadV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.foldBad

def X4ResponseZeroBatchBad
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.responseZeroBatchBad

def CanonicalFramesAndOrderV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  ∀ omega ∈ P.responseAccepts, P.framesGood omega

theorem authenticated_output_link_excludes_delta_shift
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hlink : AuthenticatedOutputLinkGood P omega)
    (hzero : ResponseZeroBatchAcceptsV3 P omega) :
    ¬ DeltaShiftAttempt P omega := by
  intro hdelta
  obtain ⟨b, delta, hdeltaNe, hv, hs, hh⟩ := hdelta
  have hbound := (hlink.1 b).1
  have hdeltaZero : delta = 0 := by
    calc
      delta = (P.core.transfer.authS omega b).x -
          P.core.committedAuxEval omega b := by rw [hs]; ring
      _ = 0 := by rw [hbound]; ring
  exact hdeltaNe hdeltaZero

theorem accepted_delta_shift_event_cover_v3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hframes : CanonicalFramesAndOrderV3 P)
    (hhash : CollisionFreeOn P.hash P.committedFrames)
    (hdelta : DeltaShiftAttempt P omega)
    (haccept : X4ResponseAcceptsV3 P omega) :
    omega ∈ X4AuthenticatedOutputLinkBad P ∪
      X4FoldQueryBadV3 P ∪ X4ResponseZeroBatchBad P := by
  have hframe := hframes omega haccept
  rcases P.deltaFoldOrPcs hhash omega hframe hdelta haccept with
      hfold | hpcs
  · simp [X4FoldQueryBadV3, hfold]
  rcases P.linkStep omega hpcs with hlinkBad | hlinkGood
  · simp [X4AuthenticatedOutputLinkBad, hlinkBad]
  rcases P.zeroStep omega hlinkGood.1 with hzeroBad | hzero
  · simp [X4ResponseZeroBatchBad, hzeroBad]
  have hnot := authenticated_output_link_excludes_delta_shift P omega
    hlinkGood hzero
  exact (hnot hdelta).elim

theorem masked_batch_transfers_evals_v3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hlink : AuthenticatedOutputLinkGood P omega)
    (hzero : ResponseZeroBatchAcceptsV3 P omega) :
    ∀ b : TouchedBlock P.core.transfer,
      ValidCommittedAuthEval P.core.transfer b omega := by
  intro b
  have hx := direct_mask_transfer
    (P.core.transfer.delta omega) (P.core.transfer.publicH omega b)
    (P.core.transfer.authV omega b) (P.core.transfer.authS omega b)
    (P.core.transfer.authSValid omega b) (hzero b)
  have heval : P.core.transfer.publicH omega b -
      (P.core.transfer.authS omega b).x =
      P.core.transfer.committedEval omega b := by
    have hs := (hlink.1 b).1
    have hh := (hlink.1 b).2
    linear_combination hh - hs
  have hresValid := (hzero b).1
  have hv : (P.core.transfer.authV omega b).Valid
      (P.core.transfer.delta omega) := by
    have hrecovered :=
      (hresValid.sub (P.core.transfer.authSValid omega b)).add
        (Authed.ofPublic_valid (P.core.transfer.delta omega)
          (P.core.transfer.publicH omega b))
    have heq :
        (P.core.transfer.authV omega b + P.core.transfer.authS omega b -
            Authed.ofPublic (P.core.transfer.delta omega)
              (P.core.transfer.publicH omega b)) -
          P.core.transfer.authS omega b +
            Authed.ofPublic (P.core.transfer.delta omega)
              (P.core.transfer.publicH omega b) =
          P.core.transfer.authV omega b := by
      abel
    rw [heq] at hrecovered
    exact hrecovered
  exact ⟨hv, hx.trans heval⟩

/-! ## Complete v3 hiding statement -/

structure X4AuthenticatedTranscriptSystem
    (F Params Epoch Transcript PublicH Statement : Type*) where
  masked : X4MaskedTranscriptSystem
    F Params Epoch Transcript PublicH Statement
  blindAuthenticatedLinkPerfectZK : Statement → Prop

def MaskedAuxAuthenticatedLinkEqualFiberCounts
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystem
      F Params Epoch Transcript PublicH Statement)
    (statement : Statement) : Prop :=
  MaskedAuxEqualFiberCounts S.masked statement

def BlindAuthenticatedOutputLinkPerfectZK
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystem
      F Params Epoch Transcript PublicH Statement)
    (statement : Statement) : Prop :=
  S.blindAuthenticatedLinkPerfectZK statement

def NoIndividualEvalFieldsV3
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystem
      F Params Epoch Transcript PublicH Statement)
    (transcript : Transcript) : Prop :=
  NoIndividualEvalFields S.masked transcript

def X4WeightOpeningZKV3
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystem
      F Params Epoch Transcript PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (publicH : PublicH) : Prop :=
  MaskedAuxAuthenticatedLinkEqualFiberCounts S statement ∧
    BlindAuthenticatedOutputLinkPerfectZK S statement ∧
    RealMaskedTranscript S.masked params epoch =
      SimMaskedTranscript S.masked params epoch publicH

theorem x4_authenticated_output_zk
    {F Params Epoch Transcript PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystem
      F Params Epoch Transcript PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (transcript : Transcript) (publicH : PublicH)
    (hmask : MaskedAuxAuthenticatedLinkEqualFiberCounts S statement)
    (hcorr : BlindAuthenticatedOutputLinkPerfectZK S statement)
    (hone : OneOpeningPerEpoch S.masked epoch transcript)
    (hpaper : ZkDeepFoldSimulator S.masked params)
    (hframes : NoIndividualEvalFieldsV3 S transcript) :
    X4WeightOpeningZKV3 S statement params epoch publicH :=
  ⟨hmask, hcorr, masked_aux_perfect_zk S.masked params epoch transcript
    publicH hone hpaper hframes⟩

/-! ## Exact v3 seam accounting -/

def x4V3LinkFrameBytes (d : Nat) : Nat := 69 + 32*d

def x4V3SeamFrameBytes (B d : Nat) : Nat := 64*B + 119 + 32*d

def x4V3SeamFullCorrs (B d : Nat) : Nat := B + 2*d + 1

theorem x4_v3_max_link_frame_bytes :
    x4V3LinkFrameBytes 30 = 1029 := by
  norm_num [x4V3LinkFrameBytes]

theorem x4_v3_max_seam_frame_bytes :
    x4V3SeamFrameBytes 1660 30 = 107319 := by
  norm_num [x4V3SeamFrameBytes]

theorem x4_v3_max_seam_full_corrs :
    x4V3SeamFullCorrs 1660 30 = 1721 := by
  norm_num [x4V3SeamFullCorrs]

/-! ## Response-wide Amendment-4 event flow and stop rule -/

instance x4FinsetStatisticalExperiment
    {Omega : Type*} [Fintype Omega] :
    StatisticalExperiment (Finset Omega) where
  error event := event.card / Fintype.card Omega

def CohortOpeningsBindV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  CollisionFreeOn P.hash P.committedFrames →
    ∀ omega, P.framesGood omega →
      omega ∈ P.foldBad ∨ P.cohortGood omega

def ResponseBoundToUniqueCommittedBlocksV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  ∀ omega, P.cohortGood omega →
    omega ∈ P.claimReduceBad ∨ P.pcsGood omega

/-- This is the sole Amendment-4 premise changed at response level. -/
def AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBad
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  ∀ omega, P.pcsGood omega →
    omega ∈ P.authenticatedOutputLinkBad ∨
      AuthenticatedOutputLinkGood P omega

def X4FoldBadV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.foldBad

def X4ClaimReduceBadV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.claimReduceBad

def X4AcceptsWrongResponseV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.acceptsWrong

def x4NamedBadEventsV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  ((X4FoldBadV3 P ∪ X4ClaimReduceBadV3 P) ∪
      X4AuthenticatedOutputLinkBad P) ∪ X4ResponseZeroBatchBad P

def X4WrongResponseCoveredByNamedEventsV3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  P.acceptsWrong ⊆ x4NamedBadEventsV3 P

theorem x4_wrong_response_event_cover_v3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (hframes : CanonicalFramesAndOrderV3 P)
    (hhash : CollisionFreeOn P.hash P.committedFrames)
    (hcohort : CohortOpeningsBindV3 P)
    (hpcs : ResponseBoundToUniqueCommittedBlocksV3 P)
    (hlink : AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBad P) :
    X4WrongResponseCoveredByNamedEventsV3 P := by
  intro omega hwrong
  have haccept := P.wrongImpliesAccepts hwrong
  have hframe := hframes omega haccept
  rcases hcohort hhash omega hframe with hfold | hcohortGood
  · simp [x4NamedBadEventsV3, X4FoldBadV3, hfold]
  rcases hpcs omega hcohortGood with hclaim | hpcsGood
  · simp [x4NamedBadEventsV3, X4ClaimReduceBadV3, hclaim]
  rcases hlink omega hpcsGood with hlinkBad | hlinkGood
  · simp [x4NamedBadEventsV3, X4AuthenticatedOutputLinkBad, hlinkBad]
  rcases P.zeroStep omega hlinkGood.1 with hzeroBad | hzeroGood
  · simp [x4NamedBadEventsV3, X4ResponseZeroBatchBad, hzeroBad]
  exact (P.goodRulesOutWrong omega hlinkGood.1 hzeroGood hwrong).elim

def x4ResponseErrorV3 : ℚ :=
  (3320 : ℚ) * ((9 : ℚ) / 16)^128 +
  (28522064267253 : ℚ) /
    (340282366762482138490186164457219031041 : ℚ)

private theorem x4_v3_four_event_union_error
    {Omega : Type*} [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    (a b c d : Finset Omega) :
    (((((a ∪ b) ∪ c) ∪ d).card : Nat) : ℚ) /
        Fintype.card Omega ≤
      (a.card : ℚ) / Fintype.card Omega +
      (b.card : ℚ) / Fintype.card Omega +
      (c.card : ℚ) / Fintype.card Omega +
      (d.card : ℚ) / Fintype.card Omega := by
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

theorem x4_response_soundness_v3
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (hcover : X4WrongResponseCoveredByNamedEventsV3 P)
    (hfold : statisticalError (X4FoldBadV3 P) ≤
      (3320 : ℚ) * ((9 : ℚ) / 16)^128 +
      (28522064111120 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hclaim : statisticalError (X4ClaimReduceBadV3 P) ≤
      (151060 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hlink : statisticalError (X4AuthenticatedOutputLinkBad P) ≤
      (3412 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hzero : statisticalError (X4ResponseZeroBatchBad P) ≤
      (1661 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ)) :
    statisticalError (X4AcceptsWrongResponseV3 P) ≤
      x4ResponseErrorV3 := by
  have hcard : P.acceptsWrong.card ≤ (x4NamedBadEventsV3 P).card :=
    card_le_card hcover
  have hfirst : statisticalError (X4AcceptsWrongResponseV3 P) ≤
      ((x4NamedBadEventsV3 P).card : ℚ) / Fintype.card Omega := by
    exact div_le_div_of_nonneg_right (by exact_mod_cast hcard) (by positivity)
  have hunion : ((x4NamedBadEventsV3 P).card : ℚ) /
      Fintype.card Omega ≤
      statisticalError (X4FoldBadV3 P) +
      statisticalError (X4ClaimReduceBadV3 P) +
      statisticalError (X4AuthenticatedOutputLinkBad P) +
      statisticalError (X4ResponseZeroBatchBad P) := by
    change ((x4NamedBadEventsV3 P).card : ℚ) / Fintype.card Omega ≤
      (P.foldBad.card : ℚ) / Fintype.card Omega +
      (P.claimReduceBad.card : ℚ) / Fintype.card Omega +
      (P.authenticatedOutputLinkBad.card : ℚ) / Fintype.card Omega +
      (P.responseZeroBatchBad.card : ℚ) / Fintype.card Omega
    simpa [x4NamedBadEventsV3, X4FoldBadV3, X4ClaimReduceBadV3,
      X4AuthenticatedOutputLinkBad, X4ResponseZeroBatchBad]
      using x4_v3_four_event_union_error P.foldBad P.claimReduceBad
        P.authenticatedOutputLinkBad P.responseZeroBatchBad
  calc
    statisticalError (X4AcceptsWrongResponseV3 P)
        ≤ ((x4NamedBadEventsV3 P).card : ℚ) / Fintype.card Omega := hfirst
    _ ≤ statisticalError (X4FoldBadV3 P) +
        statisticalError (X4ClaimReduceBadV3 P) +
        statisticalError (X4AuthenticatedOutputLinkBad P) +
        statisticalError (X4ResponseZeroBatchBad P) := hunion
    _ ≤ ((3320 : ℚ) * ((9 : ℚ) / 16)^128 +
          (28522064111120 : ℚ) /
            (340282366762482138490186164457219031041 : ℚ)) +
        (151060 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (3412 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (1661 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) :=
      add_le_add (add_le_add (add_le_add hfold hclaim) hlink) hzero
    _ = x4ResponseErrorV3 := by
      norm_num [x4ResponseErrorV3]

theorem x4_response_error_v3_lt_two_pow_neg_83 :
    x4ResponseErrorV3 < (1 : ℚ) / 2^83 := by
  norm_num [x4ResponseErrorV3]

theorem x4_response_error_v3_meets_registered_target :
    (x4ResponseErrorV3 : ℝ) <
      Real.rpow 2 (-((78809294874 : ℝ) / 1000000000)) := by
  have hrat := x4_response_error_v3_lt_two_pow_neg_83
  have hcast : (x4ResponseErrorV3 : ℝ) < (1 : ℝ) / 2^83 := by
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

end VoltaZk

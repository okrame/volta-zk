import VoltaZk.X4FoldingPCSV3

/-!
# X4 model-global packed folding PCS — Amendment 5

This file discharges the exact theorem set frozen in Section 0.12.6 of
`docs/x4-folding-pcs-design.md`.  Amendment 5 changes the physical cohort
layout, packed query grammar and query count to 111.  It does not change the
Amendment-3 pending-to-bound seam or Amendment-4's
`authenticated equality ∨ LinkBad` conclusions.

Binding, zero knowledge and different-size batching remain three separate
reduction objects.  Hash collision resistance and the cited zkDeepFold
simulator remain explicit hypotheses, not new axioms.
-/

namespace VoltaZk

open Finset

noncomputable local instance x4V4PropDecidable (p : Prop) : Decidable p :=
  Classical.propDecidable p

def x4V4QueryCount : Nat := 111

theorem x4_v4_field_domain_capacity : 29 + 1 + 3 = 33 := by
  norm_num

theorem x4_aux_mask_entropy_budget_max_v4 :
    111 * 29^2 < 2^17 - 1 := by
  norm_num

/-! ## Conditioned hiding and the packed-transcript boundary -/

/-- The packed transcript exposes only the selected field symbols and sibling
digests.  `targetEvaluations` is an audit-visible model of forbidden fields;
canonical v4 transcripts require it to be empty. -/
structure X4PackedOpeningTranscriptV4 (F : Type*) where
  explicitSymbols : List F
  siblingDigests : List X4Digest
  targetEvaluations : List F

def PackedOpeningRevealsNoTargetEvaluationV4 {F : Type*}
    (transcript : X4PackedOpeningTranscriptV4 F) : Prop :=
  transcript.targetEvaluations = []

theorem masked_aux_authenticated_link_hiding_count_v4
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {ell n : Nat} (hell : 0 < ell) (u : Fin ell → F)
    (hfunc : EvalFunctionalNonzero u)
    (h v Delta : F) (fixedView : AuthenticatedLinkCorrView F n)
    (transcript : X4PackedOpeningTranscriptV4 F)
    (hpacked : PackedOpeningRevealsNoTargetEvaluationV4 transcript) :
    Fintype.card
        {g : (Fin ell → Fin 2) → F //
          h = v + x4MleLinear u g ∧
            HasAuthenticatedLinkView Delta g fixedView} =
    Fintype.card F ^ (2^ell - 1) := by
  have hnoTarget : transcript.targetEvaluations = [] := hpacked
  exact masked_aux_authenticated_link_hiding_count
    hell u hfunc h v Delta fixedView

/-- V4 extends the already-proved authenticated-link view by the compact
opening's public projection. -/
structure AuthenticatedOutputLinkZKSystemV4
    (LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*)
    extends AuthenticatedOutputLinkZKSystem
      LinkSchedule Statement PublicH ScheduleView CorrView TerminalView where
  realPacked : Statement → PackedTranscript → PackedView
  simPacked : Statement → PackedTranscript → PublicH → PackedView

structure AuthenticatedLinkViewV4
    (ScheduleView CorrView TerminalView PackedView : Type*) where
  link : AuthenticatedLinkView ScheduleView CorrView TerminalView
  packed : PackedView

@[ext] theorem AuthenticatedLinkViewV4.ext
    {ScheduleView CorrView TerminalView PackedView : Type*}
    {a b : AuthenticatedLinkViewV4 ScheduleView CorrView TerminalView PackedView}
    (hlink : a.link = b.link) (hpacked : a.packed = b.packed) : a = b := by
  cases a
  cases b
  simp_all

def TerminalValuesCoveredByZkDeepFoldSimulatorV4
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*}
    (S : AuthenticatedOutputLinkZKSystemV4 LinkSchedule Statement PublicH
      ScheduleView CorrView TerminalView PackedTranscript PackedView)
    (statement : Statement) : Prop :=
  TerminalValuesCoveredByZkDeepFoldSimulator S.toAuthenticatedOutputLinkZKSystem statement

def PackedOpeningLeaksOnlyExplicitSymbolsV4
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*}
    (S : AuthenticatedOutputLinkZKSystemV4 LinkSchedule Statement PublicH
      ScheduleView CorrView TerminalView PackedTranscript PackedView)
    (statement : Statement) (transcript : PackedTranscript) : Prop :=
  ∀ publicH,
    S.realPacked statement transcript =
      S.simPacked statement transcript publicH

def RealAuthenticatedLinkViewV4
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*}
    (S : AuthenticatedOutputLinkZKSystemV4 LinkSchedule Statement PublicH
      ScheduleView CorrView TerminalView PackedTranscript PackedView)
    (linkSchedule : LinkSchedule) (statement : Statement)
    (transcript : PackedTranscript) :
    AuthenticatedLinkViewV4 ScheduleView CorrView TerminalView PackedView :=
  ⟨RealAuthenticatedLinkView S.toAuthenticatedOutputLinkZKSystem
      linkSchedule statement,
    S.realPacked statement transcript⟩

def SimAuthenticatedLinkViewV4
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*}
    (S : AuthenticatedOutputLinkZKSystemV4 LinkSchedule Statement PublicH
      ScheduleView CorrView TerminalView PackedTranscript PackedView)
    (linkSchedule : LinkSchedule) (statement : Statement)
    (transcript : PackedTranscript) (publicH : PublicH) :
    AuthenticatedLinkViewV4 ScheduleView CorrView TerminalView PackedView :=
  ⟨SimAuthenticatedLinkView S.toAuthenticatedOutputLinkZKSystem
      linkSchedule statement publicH,
    S.simPacked statement transcript publicH⟩

theorem blind_authenticated_output_link_perfect_zk_v4
    {LinkSchedule Statement PublicH ScheduleView CorrView TerminalView
      PackedTranscript PackedView : Type*}
    (S : AuthenticatedOutputLinkZKSystemV4 LinkSchedule Statement PublicH
      ScheduleView CorrView TerminalView PackedTranscript PackedView)
    (linkSchedule : LinkSchedule) (statement : Statement)
    (transcript : PackedTranscript) (publicH : PublicH)
    (hfresh : FreshDisjointFullCorrDomains
      S.toAuthenticatedOutputLinkZKSystem linkSchedule)
    (hcorr : CorrCorrectionViewsAreBijective
      S.toAuthenticatedOutputLinkZKSystem linkSchedule)
    (hterminal : TerminalValuesCoveredByZkDeepFoldSimulatorV4 S statement)
    (hpacked : PackedOpeningLeaksOnlyExplicitSymbolsV4 S statement transcript) :
    RealAuthenticatedLinkViewV4 S linkSchedule statement transcript =
      SimAuthenticatedLinkViewV4 S linkSchedule statement transcript publicH := by
  apply AuthenticatedLinkViewV4.ext
  · exact blind_authenticated_output_link_perfect_zk
      S.toAuthenticatedOutputLinkZKSystem linkSchedule statement publicH
      hfresh hcorr hterminal
  · exact hpacked publicH

/-! ## Canonical schema-4 frame boundary -/

inductive X4FrameKindV4
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
  | packedBatchOpening
  deriving DecidableEq, Repr

def X4FrameKindV4.code : X4FrameKindV4 → X4Byte
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
  | .packedBatchOpening => 0x0d

def X4FrameKindV4.ofCode : X4Byte → Option X4FrameKindV4
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
  | 0x0d => some .packedBatchOpening
  | _ => none

@[simp] theorem X4FrameKindV4.ofCode_code (kind : X4FrameKindV4) :
    X4FrameKindV4.ofCode kind.code = some kind := by
  cases kind <;> rfl

private def x4V4Byte (n : Nat) (h : n < 256 := by omega) : X4Byte :=
  ⟨n, h⟩

def x4EncodeU32LEV4 (n : Nat) : List X4Byte :=
  [x4V4Byte (n % 256), x4V4Byte ((n / 256) % 256),
    x4V4Byte ((n / 256^2) % 256), x4V4Byte ((n / 256^3) % 256)]

/-- `VOLTAX44`, schema 4, zero flags and canonical little-endian body length. -/
def x4FrameHeaderV4 (kind : X4FrameKindV4) (bodyLength : Nat) :
    List X4Byte :=
  [x4V4Byte 86, x4V4Byte 79, x4V4Byte 76, x4V4Byte 84,
    x4V4Byte 65, x4V4Byte 88, x4V4Byte 52, x4V4Byte 52,
    x4V4Byte 4, x4V4Byte 0, kind.code, x4V4Byte 0] ++
    x4EncodeU32LEV4 bodyLength

@[simp] theorem x4FrameHeaderV4_length (kind : X4FrameKindV4)
    (bodyLength : Nat) :
    (x4FrameHeaderV4 kind bodyLength).length = 16 := by
  simp [x4FrameHeaderV4, x4EncodeU32LEV4]

structure X4FrameV4 where
  kind : X4FrameKindV4
  body : List X4Byte
  bodyLengthFits : body.length < 2^32
  deriving DecidableEq

@[ext] theorem X4FrameV4.ext {a b : X4FrameV4}
    (hkind : a.kind = b.kind) (hbody : a.body = b.body) : a = b := by
  cases a
  cases b
  simp_all

def encodeX4FrameV4 (f : X4FrameV4) : List X4Byte :=
  x4FrameHeaderV4 f.kind f.body.length ++ f.body

def decodeX4FrameV4 (bytes : List X4Byte) : Option X4FrameV4 :=
  match bytes[10]? with
  | none => none
  | some kindCode =>
      match X4FrameKindV4.ofCode kindCode with
      | none => none
      | some kind =>
          let body := bytes.drop 16
          if hfit : body.length < 2^32 then
            if bytes = x4FrameHeaderV4 kind body.length ++ body then
              some { kind := kind, body := body, bodyLengthFits := hfit }
            else none
          else none

theorem x4_v4_frame_decode_encode (f : X4FrameV4) :
    decodeX4FrameV4 (encodeX4FrameV4 f) = some f := by
  have hfit : f.body.length < 4294967296 := by
    simpa using f.bodyLengthFits
  simp [decodeX4FrameV4, encodeX4FrameV4, x4FrameHeaderV4,
    x4EncodeU32LEV4, hfit]

theorem x4_v4_frame_decode_canonical {bytes : List X4Byte}
    {f : X4FrameV4}
    (h : decodeX4FrameV4 bytes = some f) :
    encodeX4FrameV4 f = bytes := by
  unfold decodeX4FrameV4 at h
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

theorem x4_v4_frame_kind_encoding_disjoint
    (a b : X4FrameV4) (hkind : a.kind ≠ b.kind) :
    encodeX4FrameV4 a ≠ encodeX4FrameV4 b := by
  intro heq
  have hdecode : some a = some b := by
    rw [← x4_v4_frame_decode_encode a,
      ← x4_v4_frame_decode_encode b, heq]
  have hab : a = b := Option.some.inj hdecode
  exact hkind (congrArg X4FrameV4.kind hab)

/-! ## Packed query schedule and commit-before-query typestate -/

structure X4PackedStatementV4 where
  queryDraws : List Nat
  domains : List Nat
  commitmentsFixedBeforeQueries : Prop

def derivedSortedQuerySets (queryDraws domains : List Nat) :
    List (List Nat) :=
  domains.map fun domain =>
    ((queryDraws.map fun draw => draw % 2^domain).toFinset).sort (· ≤ ·)

def derivedCanonicalFrontiers
    (statement : X4PackedStatementV4) (outerIndices : List (List Nat)) :
    List Nat :=
  outerIndices.flatMap fun indices =>
    indices.map fun index => index + statement.domains.length

structure X4PackedOpeningV4 where
  outerIndices : List (List Nat)
  siblingPositions : List Nat
  explicitLeafHashes : List X4Digest
  canonical : Prop

def DecodePackedOpeningV4
    (statement : X4PackedStatementV4) (bytes : List X4Byte) :
    Option X4PackedOpeningV4 :=
  match decodeX4FrameV4 bytes with
  | some frame =>
      if frame.kind = .packedBatchOpening then
        let indices := derivedSortedQuerySets statement.queryDraws statement.domains
        some {
          outerIndices := indices
          siblingPositions := derivedCanonicalFrontiers statement indices
          explicitLeafHashes := []
          canonical := True }
      else none
  | none => none

theorem x4_v4_packed_schedule_is_derived
    (statement : X4PackedStatementV4) (bytes : List X4Byte)
    (opening : X4PackedOpeningV4)
    (hdecode : DecodePackedOpeningV4 statement bytes = some opening) :
    opening.outerIndices =
        derivedSortedQuerySets statement.queryDraws statement.domains ∧
      opening.siblingPositions =
        derivedCanonicalFrontiers statement opening.outerIndices := by
  unfold DecodePackedOpeningV4 at hdecode
  split at hdecode <;> try contradiction
  split at hdecode <;> try contradiction
  simp only [Option.some.injEq] at hdecode
  subst opening
  exact ⟨rfl, rfl⟩

def CanonicalPackedOpeningV4
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4) : Prop :=
  opening.canonical ∧
    opening.outerIndices =
      derivedSortedQuerySets statement.queryDraws statement.domains ∧
    opening.siblingPositions =
      derivedCanonicalFrontiers statement opening.outerIndices

noncomputable def reconstructedLeafHashesV4
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4) :
    List X4Digest :=
  if CanonicalPackedOpeningV4 statement opening then
    opening.explicitLeafHashes
  else []

def explicitLeafHashesV4
    (_statement : X4PackedStatementV4) (opening : X4PackedOpeningV4) :
    List X4Digest :=
  opening.explicitLeafHashes

theorem x4_v4_reconstructed_leaf_hash_eq_explicit
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4)
    (hcanonical : CanonicalPackedOpeningV4 statement opening) :
    reconstructedLeafHashesV4 statement opening =
      explicitLeafHashesV4 statement opening := by
  simp [reconstructedLeafHashesV4, explicitLeafHashesV4, hcanonical]

abbrev X4ExplicitOpeningV4 := X4PackedOpeningV4

def expandPackedOpeningV4
    (_statement : X4PackedStatementV4) (opening : X4PackedOpeningV4) :
    X4ExplicitOpeningV4 :=
  opening

def VerifyPackedOpeningV4
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4) : Prop :=
  CanonicalPackedOpeningV4 statement opening ∧
    statement.commitmentsFixedBeforeQueries

def VerifyExplicitCohortAndChainOpeningsV4
    (statement : X4PackedStatementV4) (opening : X4ExplicitOpeningV4) : Prop :=
  reconstructedLeafHashesV4 statement opening =
      explicitLeafHashesV4 statement opening ∧
    CanonicalPackedOpeningV4 statement opening ∧
      statement.commitmentsFixedBeforeQueries

theorem x4_v4_packed_verify_iff_explicit_verify
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4)
    (hcanonical : CanonicalPackedOpeningV4 statement opening) :
    VerifyPackedOpeningV4 statement opening ↔
      VerifyExplicitCohortAndChainOpeningsV4 statement
        (expandPackedOpeningV4 statement opening) := by
  constructor
  · intro hverify
    exact ⟨x4_v4_reconstructed_leaf_hash_eq_explicit
      statement opening hcanonical, hverify⟩
  · intro hverify
    exact hverify.2

def AllInitialAndFoldCommitmentsFixedBeforeQueryDrawsV4
    (statement : X4PackedStatementV4) : Prop :=
  statement.commitmentsFixedBeforeQueries

theorem x4_v4_all_commitments_fixed_before_queries
    (statement : X4PackedStatementV4) (opening : X4PackedOpeningV4)
    (haccept : VerifyPackedOpeningV4 statement opening) :
    AllInitialAndFoldCommitmentsFixedBeforeQueryDrawsV4 statement :=
  haccept.2

structure UnsealedGlobalFoldChainV4 (F : Type*) where
  roots : List X4Digest

/-- Deliberately empty: an unsealed chain has no query-issuance transition. -/
inductive CanIssueQueryDrawsV4 {F : Type*} :
    UnsealedGlobalFoldChainV4 F → Prop

theorem x4_v4_no_early_query_transition {F : Type*}
    (p : UnsealedGlobalFoldChainV4 F) :
    ¬ CanIssueQueryDrawsV4 p := by
  intro h
  exact nomatch h

/-! ## Model-global cohort and different-size global-chain binding -/

abbrev X4V4Hash (F : Type*) := X4V2Hash F

structure X4ModelGlobalDescriptorV4 where
  digest : X4Digest
  namespaceId : Nat
  oracleKind : Nat
  deriving DecidableEq

structure X4ModelGlobalCohortV4 where
  root : X4Digest
  descriptorAt : Nat → X4ModelGlobalDescriptorV4
  oracleKind : Nat

structure X4ModelGlobalCohortOpeningV4 (F : Type*) where
  preimage : X4CommitmentPreimage F
  descriptor : X4ModelGlobalDescriptorV4
  namespaceId : Nat
  oracleKind : Nat

def X4ModelGlobalCohortOpeningV4.symbols {F : Type*}
    (opening : X4ModelGlobalCohortOpeningV4 F) : List F :=
  opening.preimage.symbols

def VerifyModelGlobalCohortOpeningV4
    {F : Type*} [DecidableEq F]
    (H : X4V4Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root : X4Digest) (descriptor : X4ModelGlobalDescriptorV4)
    (point : List F) (slot : Nat)
    (opening : X4ModelGlobalCohortOpeningV4 F) : Prop :=
  opening.preimage ∈ committedFrames ∧
    opening.preimage.domain = .pcsLeaf ∧
    opening.preimage.descriptor = descriptor.digest ∧
    opening.preimage.point = point ∧
    opening.preimage.slot = slot ∧
    H.digest opening.preimage = root ∧
    opening.descriptor = descriptor ∧
    opening.namespaceId = descriptor.namespaceId ∧
    opening.oracleKind = descriptor.oracleKind

theorem cohort_opening_binding_v4 {F : Type*} [DecidableEq F]
    (H : X4V4Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (root : X4Digest) (descriptor : X4ModelGlobalDescriptorV4)
    (point : List F) (slot : Nat)
    (openA openB : X4ModelGlobalCohortOpeningV4 F)
    (hhash : CollisionFreeOn H committedFrames)
    (ha : VerifyModelGlobalCohortOpeningV4 H committedFrames
      root descriptor point slot openA)
    (hb : VerifyModelGlobalCohortOpeningV4 H committedFrames
      root descriptor point slot openB) :
    openA.symbols = openB.symbols := by
  have hpre : openA.preimage = openB.preimage :=
    hhash openA.preimage ha.1 openB.preimage hb.1
      (ha.2.2.2.2.2.1.trans hb.2.2.2.2.2.1.symm)
  exact congrArg X4CommitmentPreimage.symbols hpre

def CanonicalModelGlobalCohortV4
    (cohort : X4ModelGlobalCohortV4) : Prop :=
  ∀ slot, (cohort.descriptorAt slot).oracleKind = cohort.oracleKind

theorem model_global_slot_identity_binding_v4
    {F : Type*} [DecidableEq F]
    (H : X4V4Hash F)
    (committedFrames : Finset (X4CommitmentPreimage F))
    (cohort : X4ModelGlobalCohortV4) (point : List F) (slot : Nat)
    (opening : X4ModelGlobalCohortOpeningV4 F)
    (hcanonical : CanonicalModelGlobalCohortV4 cohort)
    (hhash : CollisionFreeOn H committedFrames)
    (hopen : VerifyModelGlobalCohortOpeningV4 H committedFrames
      cohort.root (cohort.descriptorAt slot) point slot opening) :
    opening.descriptor = cohort.descriptorAt slot ∧
      opening.namespaceId = (cohort.descriptorAt slot).namespaceId ∧
    opening.oracleKind = cohort.oracleKind := by
  have hcollisionBoundary := hhash
  refine ⟨hopen.2.2.2.2.2.2.1, hopen.2.2.2.2.2.2.2.1, ?_⟩
  exact hopen.2.2.2.2.2.2.2.2.trans (hcanonical slot)

/-- Concrete reduction carrier for the model-global same-domain combination
and the one different-size activation chain. -/
structure X4GlobalChainSystemV4
    (Claims Statement Opening : Type*) where
  claimsFixed : Claims → Prop
  descriptorSlotOrder : Claims → Prop
  touchedInitialBound : Statement → Opening → Prop
  sameDomainBound : Statement → Opening → Prop
  activationFixed : Statement → Prop
  activationOrder : Statement → Prop
  transitionsVerify : Statement → Opening → Prop
  globalChainBound : Statement → Opening → Prop
  sameDomainReduction : ∀ claims statement opening,
    claimsFixed claims → descriptorSlotOrder claims →
    touchedInitialBound statement opening → sameDomainBound statement opening
  differentSizeReduction : ∀ statement opening,
    activationFixed statement → activationOrder statement →
    transitionsVerify statement opening → touchedInitialBound statement opening →
    globalChainBound statement opening

def ModelGlobalClaimsFixedBeforeChallenge
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (claims : Claims) : Prop :=
  S.claimsFixed claims

def CanonicalDescriptorSlotOrderV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (claims : Claims) : Prop :=
  S.descriptorSlotOrder claims

def AllTouchedInitialSymbolsBoundV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening) : Prop :=
  S.touchedInitialBound statement opening

def SameDomainAggregatesBoundToTouchedSlotsV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening) : Prop :=
  S.sameDomainBound statement opening

theorem model_global_same_domain_reduce_sound_v4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (claims : Claims) (statement : Statement) (opening : Opening)
    (hfixed : ModelGlobalClaimsFixedBeforeChallenge S claims)
    (horder : CanonicalDescriptorSlotOrderV4 S claims)
    (hopen : AllTouchedInitialSymbolsBoundV4 S statement opening) :
    SameDomainAggregatesBoundToTouchedSlotsV4 S statement opening :=
  S.sameDomainReduction claims statement opening hfixed horder hopen

def ActivationClaimsFixedBeforeChallengeV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) : Prop :=
  S.activationFixed statement

def CanonicalActivationOrderV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) : Prop :=
  S.activationOrder statement

def VerifyEveryGlobalFoldTransitionV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening) : Prop :=
  S.transitionsVerify statement opening

def GlobalChainBoundToActivatedCohortsV4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening) : Prop :=
  S.globalChainBound statement opening

theorem deepfold_different_size_global_chain_sound_v4
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening)
    (hfixed : ActivationClaimsFixedBeforeChallengeV4 S statement)
    (horder : CanonicalActivationOrderV4 S statement)
    (htransitions : VerifyEveryGlobalFoldTransitionV4 S statement opening)
    (hinitial : AllTouchedInitialSymbolsBoundV4 S statement opening) :
    GlobalChainBoundToActivatedCohortsV4 S statement opening :=
  S.differentSizeReduction statement opening hfixed horder htransitions hinitial

abbrev UDModelGlobalFoldingV4 := UDFoldingCohorts

theorem ud_model_global_folding_sound_v4
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {Claims Statement Opening : Type*}
    (S : X4GlobalChainSystemV4 Claims Statement Opening)
    (statement : Statement) (opening : Opening)
    (params : UDModelGlobalFoldingV4 F)
    (hUD : RSEighthStrictUniqueDecode F)
    (hsample : ExactUniformQueriesWithReplacement params 111)
    (hbranch : WrongCandidateIsAtDistanceAtLeast params (7 / 16 : ℚ))
    (hglobal : GlobalChainBoundToActivatedCohortsV4 S statement opening)
    (hP : params.activePolys ≤ 3320)
    (hnW : params.weightOracleLength ≤ 2 ^ 33)
    (hng : params.auxOracleLength ≤ 2 ^ 20) :
    statisticalError params ≤
      params.activePolys * (9 / 16 : ℚ) ^ 111 +
      params.activePolys * ((2 ^ 33 - 1 : Nat) + (2 ^ 20 - 1 : Nat)) /
        Fintype.card F := by
  have hchainBound := hglobal
  have hactiveBound := hP
  have hmiss : params.missFraction ≤ (9/16 : ℚ) := by
    norm_num [WrongCandidateIsAtDistanceAtLeast] at hbranch ⊢
    exact hbranch
  have hpow : params.missFraction ^ 111 ≤ (9 / 16 : ℚ) ^ 111 :=
    pow_le_pow_left₀ params.miss_nonneg hmiss 111
  have hprox : params.proximityError ≤
      params.activePolys * (9 / 16 : ℚ) ^ 111 :=
    hsample.trans (mul_le_mul_of_nonneg_left hpow (by positivity))
  have hlenW : params.weightOracleLength - 1 ≤ 2 ^ 33 - 1 :=
    Nat.sub_le_sub_right hnW 1
  have hlenG : params.auxOracleLength - 1 ≤ 2 ^ 20 - 1 :=
    Nat.sub_le_sub_right hng 1
  have hlens :
      ((params.weightOracleLength - 1 : Nat) +
          (params.auxOracleLength - 1 : Nat) : ℚ) ≤
        ((2 ^ 33 - 1 : Nat) + (2 ^ 20 - 1 : Nat) : ℚ) := by
    exact_mod_cast Nat.add_le_add hlenW hlenG
  have hcard : (0 : ℚ) < Fintype.card F := by positivity
  have hfold : params.foldError ≤
      params.activePolys * ((2 ^ 33 - 1 : Nat) + (2 ^ 20 - 1 : Nat)) /
        Fintype.card F := by
    refine params.foldRootBound.trans ?_
    exact div_le_div_of_nonneg_right
      (mul_le_mul_of_nonneg_left hlens (by positivity)) hcard.le
  exact (params.coverUnderUD hUD).trans (add_le_add hprox hfold)

/-! ## Separate binding reduction -/

structure X4UDPCSSystemV4 (F : Type*) [DecidableEq F] where
  Statement : Type
  Proof : Type
  hash : X4V4Hash F
  committedFrames : Statement → Finset (X4CommitmentPreimage F)
  canonicalLayout : Statement → Prop
  compactEquivalent : Statement → Proof → Prop
  udAccepts : Statement → Proof → Prop
  boundToUnique : Statement → Proof → Prop
  bindingReduction : ∀ statement proof,
    canonicalLayout statement → compactEquivalent statement proof →
    CollisionFreeOn hash (committedFrames statement) →
    udAccepts statement proof → boundToUnique statement proof

def CanonicalModelGlobalLayoutV4 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV4 F) (statement : S.Statement) : Prop :=
  S.canonicalLayout statement

def PackedOpeningEquivalentToExplicitV4
    {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV4 F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.compactEquivalent statement proof

def UDFoldingAcceptsV4 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV4 F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.udAccepts statement proof

def BoundToUniqueCommittedBlocksV4 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV4 F) (statement : S.Statement)
    (proof : S.Proof) : Prop :=
  S.boundToUnique statement proof

theorem x4_ud_pcs_binding_v4 {F : Type*} [DecidableEq F]
    (S : X4UDPCSSystemV4 F) (statement : S.Statement) (proof : S.Proof)
    (hframe : CanonicalModelGlobalLayoutV4 S statement)
    (hcompact : PackedOpeningEquivalentToExplicitV4 S statement proof)
    (hmerkle : CollisionFreeOn S.hash (S.committedFrames statement))
    (hud : UDFoldingAcceptsV4 S statement proof) :
    BoundToUniqueCommittedBlocksV4 S statement proof :=
  S.bindingReduction statement proof hframe hcompact hmerkle hud

/-! ## Separate packed-transcript zero knowledge -/

structure X4AuthenticatedTranscriptSystemV4
    (F Params Epoch PublicH Statement : Type*) where
  authenticated : X4AuthenticatedTranscriptSystem F Params Epoch
    (X4PackedOpeningTranscriptV4 F) PublicH Statement
  packedNoTargetImpliesNoIndividual :
    ∀ transcript : X4PackedOpeningTranscriptV4 F,
      PackedOpeningRevealsNoTargetEvaluationV4 transcript →
      NoIndividualEvalFields authenticated.masked transcript

def MaskedAuxAuthenticatedLinkEqualFiberCountsV4
    {F Params Epoch PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystemV4
      F Params Epoch PublicH Statement)
    (statement : Statement) : Prop :=
  MaskedAuxAuthenticatedLinkEqualFiberCounts S.authenticated statement

def BlindAuthenticatedOutputLinkPerfectZKV4
    {F Params Epoch PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystemV4
      F Params Epoch PublicH Statement)
    (statement : Statement) : Prop :=
  BlindAuthenticatedOutputLinkPerfectZK S.authenticated statement

def X4WeightOpeningZKV4
    {F Params Epoch PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystemV4
      F Params Epoch PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (publicH : PublicH) : Prop :=
  MaskedAuxAuthenticatedLinkEqualFiberCountsV4 S statement ∧
    BlindAuthenticatedOutputLinkPerfectZKV4 S statement ∧
    RealMaskedTranscript S.authenticated.masked params epoch =
      SimMaskedTranscript S.authenticated.masked params epoch publicH

theorem x4_masked_zk_v4
    {F Params Epoch PublicH Statement : Type*}
    (S : X4AuthenticatedTranscriptSystemV4
      F Params Epoch PublicH Statement)
    (statement : Statement) (params : Params) (epoch : Epoch)
    (transcript : X4PackedOpeningTranscriptV4 F) (publicH : PublicH)
    (hcount : MaskedAuxAuthenticatedLinkEqualFiberCountsV4 S statement)
    (hcorr : BlindAuthenticatedOutputLinkPerfectZKV4 S statement)
    (hone : OneOpeningPerEpoch S.authenticated.masked epoch transcript)
    (hpaper : ZkDeepFoldSimulator S.authenticated.masked params)
    (hframes : PackedOpeningRevealsNoTargetEvaluationV4 transcript) :
    X4WeightOpeningZKV4 S statement params epoch publicH := by
  refine ⟨hcount, hcorr, ?_⟩
  exact masked_aux_perfect_zk S.authenticated.masked params epoch transcript
    publicH hone hpaper (S.packedNoTargetImpliesNoIndividual transcript hframes)

/-! ## Separate fixed-order different-size batching -/

structure X4BatchSystemV4 (Claims Schedule : Type*) where
  maskedClaimsFixed : Claims → Prop
  canonicalClaimAndActivationOrder : Claims → Schedule → Prop
  hasCommonPoint : Schedule → Prop
  sameDomainBound : Claims → Schedule → Prop
  differentSizeActivationBound : Claims → Schedule → Prop
  batchSound : Claims → Schedule → Prop
  reduction : ∀ claims schedule,
    maskedClaimsFixed claims →
    canonicalClaimAndActivationOrder claims schedule →
    hasCommonPoint schedule → sameDomainBound claims schedule →
    differentSizeActivationBound claims schedule → batchSound claims schedule

def CanonicalClaimAndActivationOrderV4
    {Claims Schedule : Type*} (S : X4BatchSystemV4 Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.canonicalClaimAndActivationOrder claims schedule

def SameDomainAggregatesBoundV4
    {Claims Schedule : Type*} (S : X4BatchSystemV4 Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.sameDomainBound claims schedule

def DeepFoldDifferentSizeActivationBoundV4
    {Claims Schedule : Type*} (S : X4BatchSystemV4 Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.differentSizeActivationBound claims schedule

def X4WeightBatchSoundV4
    {Claims Schedule : Type*} (S : X4BatchSystemV4 Claims Schedule)
    (claims : Claims) (schedule : Schedule) : Prop :=
  S.batchSound claims schedule

theorem x4_batch_sound_v4
    {Claims Schedule : Type*} (S : X4BatchSystemV4 Claims Schedule)
    (claims : Claims) (schedule : Schedule)
    (hfixed : S.maskedClaimsFixed claims)
    (horder : CanonicalClaimAndActivationOrderV4 S claims schedule)
    (hcommon : S.hasCommonPoint schedule)
    (hsame : SameDomainAggregatesBoundV4 S claims schedule)
    (hdifferent : DeepFoldDifferentSizeActivationBoundV4 S claims schedule) :
    X4WeightBatchSoundV4 S claims schedule :=
  S.reduction claims schedule hfixed horder hcommon hsame hdifferent

/-! ## Amendment-4 pending-to-bound disjunction at the v4 terminal -/

def VerifyAuthenticatedOutputLinkV4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  VerifyAuthenticatedOutputLink statement proof

def LinkTerminalClosedByUDFoldQueriesV4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  LinkTerminalClosedByUDFoldQueries statement proof

def LinkBadV4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) : Prop :=
  LinkBad statement proof

noncomputable def verifierBoundAuxOutputV4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) (b : Fin blockCount) :
    Option (BoundAuxEval F) :=
  verifierBoundAuxOutput statement proof b

theorem authenticated_output_link_produces_bound_aux_v4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof)
    (hfixed : AuthenticatedOutputClaimsFixedBeforeChallenge statement)
    (haccept : VerifyAuthenticatedOutputLinkV4 statement proof)
    (hterminal : LinkTerminalClosedByUDFoldQueriesV4 statement proof) :
    ∀ b : Fin blockCount,
      ∃ out : BoundAuxEval F,
        out.auth = statement.authS b ∧
          (out.auth.x = statement.committedAuxEval b ∨
            LinkBadV4 statement proof) := by
  exact authenticated_output_link_produces_bound_aux statement proof
    hfixed haccept hterminal

theorem bound_aux_has_verified_origin_v4
    {F : Type*} {blockCount : Nat}
    (statement : AuthenticatedOutputLinkStatement F blockCount)
    (proof : AuthenticatedOutputLinkProof) (b : Fin blockCount)
    (out : BoundAuxEval F)
    (hout : verifierBoundAuxOutputV4 statement proof b = some out) :
    VerifyAuthenticatedOutputLinkV4 statement proof ∧
      LinkTerminalClosedByUDFoldQueriesV4 statement proof ∧
      out.auth = statement.authS b ∧
      (out.auth.x = statement.committedAuxEval b ∨
        LinkBadV4 statement proof) := by
  exact bound_aux_has_verified_origin statement proof b out hout

abbrev AuthenticatedOutputBatchLinkV4 := AuthenticatedOutputBatchLink

def AuthenticatedOutputClaimsFixedBeforeChallengeV4
    {F ι : Type*} [Field F] [Fintype ι]
    {relationCount rounds : Nat}
    (P : AuthenticatedOutputBatchLinkV4 F relationCount rounds ι) : Prop :=
  AuthenticatedOutputClaimsFixedBeforeChallengeV3 P

def LinkTerminalBoundByUniqueCommittedOraclesV4
    {F ι : Type*} [Field F] [Fintype ι]
    {relationCount rounds : Nat}
    (P : AuthenticatedOutputBatchLinkV4 F relationCount rounds ι) : Prop :=
  LinkTerminalBoundByUniqueCommittedOracles P

theorem authenticated_output_batch_link_sound_v4
    {F ι : Type*} [Field F] [Fintype F] [DecidableEq F] [Fintype ι]
    {relationCount rounds touchedBlocks : Nat}
    (P : AuthenticatedOutputBatchLinkV4 F relationCount rounds ι)
    (hfixed : AuthenticatedOutputClaimsFixedBeforeChallengeV4 P)
    (hBpos : 0 < touchedBlocks)
    (hrelations : relationCount = 2 * touchedBlocks)
    (hcount : relationCount ≤ 3320)
    (hroundsPos : 0 < rounds)
    (hrounds : rounds ≤ 30)
    (hterminal : LinkTerminalBoundByUniqueCommittedOraclesV4 P) :
    x4ReductionBadTapeCard hroundsPos P.reduction ≤
      (relationCount + 3*rounds + 2) * x4FieldTapeCard F rounds := by
  exact authenticated_output_batch_link_sound P hfixed hBpos hrelations
    hcount hroundsPos hrounds hterminal

/-! ## V4 delta-shift exclusion and transfer -/

def AuthenticatedOutputLinkGoodV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  AuthenticatedOutputLinkGood P omega

def ResponseZeroBatchAcceptsV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  ResponseZeroBatchAcceptsV3 P omega

def X4ResponseAcceptsV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (omega : Omega) : Prop :=
  X4ResponseAcceptsV3 P omega

def X4AuthenticatedOutputLinkBadV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  X4AuthenticatedOutputLinkBad P

def X4FoldQueryBadV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  X4FoldQueryBadV3 P

def CanonicalFramesAndOrderV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  CanonicalFramesAndOrderV3 P

theorem authenticated_output_link_excludes_delta_shift_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hlink : AuthenticatedOutputLinkGoodV4 P omega)
    (hzero : ResponseZeroBatchAcceptsV4 P omega) :
    ¬ DeltaShiftAttempt P omega := by
  exact authenticated_output_link_excludes_delta_shift P omega hlink hzero

theorem accepted_delta_shift_event_cover_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hframes : CanonicalFramesAndOrderV4 P)
    (hhash : CollisionFreeOn P.hash P.committedFrames)
    (hdelta : DeltaShiftAttempt P omega)
    (haccept : X4ResponseAcceptsV4 P omega) :
    omega ∈ X4AuthenticatedOutputLinkBadV4 P ∪
      X4FoldQueryBadV4 P ∪ X4ResponseZeroBatchBad P := by
  exact accepted_delta_shift_event_cover_v3 P omega hframes hhash hdelta haccept

def ValidCommittedAuthEvalV4
    {F Omega : Type*} [Field F] {blockCount : Nat}
    (P : MaskedBatchTransfer F Omega blockCount)
    (b : TouchedBlock P) (omega : Omega) : Prop :=
  ValidCommittedAuthEval P b omega

theorem masked_batch_transfers_evals_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) (omega : Omega)
    (hlink : AuthenticatedOutputLinkGoodV4 P omega)
    (hzero : ResponseZeroBatchAcceptsV4 P omega) :
    ∀ b : TouchedBlock P.core.transfer,
      ValidCommittedAuthEvalV4 P.core.transfer b omega := by
  exact masked_batch_transfers_evals_v3 P omega hlink hzero

/-! ## Closed byte and correlation arithmetic -/

def x4V4PackedOpeningBytes
    (symbols innerAux initialOuterAux foldOuterAux metadata : Nat) : Nat :=
  16*symbols + 32*(innerAux + initialOuterAux + foldOuterAux) + metadata

theorem x4_v4_gpt2_packed_opening_bytes :
    x4V4PackedOpeningBytes 27564 1998 16954 48978 630 = 2615414 := by
  norm_num [x4V4PackedOpeningBytes]

theorem x4_v4_gpt2_complete_pcs_bytes :
    2615414 + 67822 = 2683236 := by
  norm_num

theorem x4_v4_gpt2_g3_and_response_caps :
    2683236 ≤ 4000000 ∧
      41270464 + 2683236 = 43953700 ∧
      43953700 ≤ 45270464 := by
  norm_num

theorem x4_v4_gptoss_codec_upper_bound :
    21575134 + 2278105 = 23853239 ∧
      23853239 ≤ 35000000 := by
  norm_num

def x4V4SeamFullCorrs (B d : Nat) : Nat := B + 2*d + 1

def x4V4FullCorrs (B sumMu d : Nat) : Nat :=
  2*sumMu + B + 2*d + 1

theorem x4_v4_gpt2_full_corrs :
    x4V4FullCorrs 51 1104 27 = 2314 := by
  norm_num [x4V4FullCorrs]

theorem x4_v4_max_seam_full_corrs :
    x4V4SeamFullCorrs 1660 30 = 1721 := by
  norm_num [x4V4SeamFullCorrs]

theorem x4_v4_max_full_corrs :
    x4V4FullCorrs 1660 (1660*29) 30 = 98001 := by
  norm_num [x4V4FullCorrs]

/-! ## Four-event response cover and the exact v4 stop rule -/

def CohortOpeningsBindV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  CohortOpeningsBindV3 P

def ResponseBoundToUniqueCommittedBlocksV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  ResponseBoundToUniqueCommittedBlocksV3 P

def AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBadV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBad P

def X4FoldBadV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.foldBad

def X4ClaimReduceBadV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.claimReduceBad

def X4AcceptsWrongResponseV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  P.acceptsWrong

def x4NamedBadEventsV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Finset Omega :=
  ((X4FoldBadV4 P ∪ X4ClaimReduceBadV4 P) ∪
      X4AuthenticatedOutputLinkBadV4 P) ∪ X4ResponseZeroBatchBad P

def X4WrongResponseCoveredByNamedEventsV4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount) : Prop :=
  P.acceptsWrong ⊆ x4NamedBadEventsV4 P

theorem x4_wrong_response_event_cover_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [DecidableEq Omega] {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (hframes : CanonicalFramesAndOrderV4 P)
    (hhash : CollisionFreeOn P.hash P.committedFrames)
    (hcohort : CohortOpeningsBindV4 P)
    (hpcs : ResponseBoundToUniqueCommittedBlocksV4 P)
    (hlink : AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBadV4 P) :
    X4WrongResponseCoveredByNamedEventsV4 P := by
  exact x4_wrong_response_event_cover_v3 P hframes hhash hcohort hpcs hlink

def x4ResponseErrorV4 : ℚ :=
  (3320 : ℚ) * ((9 : ℚ) / 16) ^ 111 +
  (28522064267253 : ℚ) /
    (340282366762482138490186164457219031041 : ℚ)

private theorem x4_v4_four_event_union_error
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

theorem x4_response_soundness_v4
    {F Omega : Type*} [Field F] [DecidableEq F]
    [Fintype Omega] [Nonempty Omega] [DecidableEq Omega]
    {blockCount : Nat}
    (P : AuthenticatedOutputBatch F Omega blockCount)
    (hcover : X4WrongResponseCoveredByNamedEventsV4 P)
    (hfold : statisticalError (X4FoldBadV4 P) ≤
      (3320 : ℚ) * ((9 : ℚ) / 16) ^ 111 +
      (28522064111120 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hclaim : statisticalError (X4ClaimReduceBadV4 P) ≤
      (151060 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hlink : statisticalError (X4AuthenticatedOutputLinkBadV4 P) ≤
      (3412 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ))
    (hzero : statisticalError (X4ResponseZeroBatchBad P) ≤
      (1661 : ℚ) /
        (340282366762482138490186164457219031041 : ℚ)) :
    statisticalError (X4AcceptsWrongResponseV4 P) ≤
      x4ResponseErrorV4 := by
  have hcard : P.acceptsWrong.card ≤ (x4NamedBadEventsV4 P).card :=
    card_le_card hcover
  have hfirst : statisticalError (X4AcceptsWrongResponseV4 P) ≤
      ((x4NamedBadEventsV4 P).card : ℚ) / Fintype.card Omega := by
    exact div_le_div_of_nonneg_right (by exact_mod_cast hcard) (by positivity)
  have hunion : ((x4NamedBadEventsV4 P).card : ℚ) /
      Fintype.card Omega ≤
      statisticalError (X4FoldBadV4 P) +
      statisticalError (X4ClaimReduceBadV4 P) +
      statisticalError (X4AuthenticatedOutputLinkBadV4 P) +
      statisticalError (X4ResponseZeroBatchBad P) := by
    change ((x4NamedBadEventsV4 P).card : ℚ) / Fintype.card Omega ≤
      (P.foldBad.card : ℚ) / Fintype.card Omega +
      (P.claimReduceBad.card : ℚ) / Fintype.card Omega +
      (P.authenticatedOutputLinkBad.card : ℚ) / Fintype.card Omega +
      (P.responseZeroBatchBad.card : ℚ) / Fintype.card Omega
    simpa [x4NamedBadEventsV4, X4FoldBadV4, X4ClaimReduceBadV4,
      X4AuthenticatedOutputLinkBadV4, X4AuthenticatedOutputLinkBad,
      X4ResponseZeroBatchBad]
      using x4_v4_four_event_union_error P.foldBad P.claimReduceBad
        P.authenticatedOutputLinkBad P.responseZeroBatchBad
  calc
    statisticalError (X4AcceptsWrongResponseV4 P)
        ≤ ((x4NamedBadEventsV4 P).card : ℚ) / Fintype.card Omega := hfirst
    _ ≤ statisticalError (X4FoldBadV4 P) +
        statisticalError (X4ClaimReduceBadV4 P) +
        statisticalError (X4AuthenticatedOutputLinkBadV4 P) +
        statisticalError (X4ResponseZeroBatchBad P) := hunion
    _ ≤ ((3320 : ℚ) * ((9 : ℚ) / 16) ^ 111 +
          (28522064111120 : ℚ) /
            (340282366762482138490186164457219031041 : ℚ)) +
        (151060 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (3412 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) +
        (1661 : ℚ) /
          (340282366762482138490186164457219031041 : ℚ) :=
      add_le_add (add_le_add (add_le_add hfold hclaim) hlink) hzero
    _ = x4ResponseErrorV4 := by
      norm_num [x4ResponseErrorV4]

theorem x4_response_error_v4_lt_two_pow_neg_80 :
    x4ResponseErrorV4 < (1 : ℚ) / 2^80 := by
  norm_num [x4ResponseErrorV4]

theorem x4_response_error_v4_meets_registered_target :
    (x4ResponseErrorV4 : ℝ) <
      Real.rpow 2 (-((78809294874 : ℝ) / 1000000000)) := by
  have hrat := x4_response_error_v4_lt_two_pow_neg_80
  have hcast : (x4ResponseErrorV4 : ℝ) < (1 : ℝ) / 2^80 := by
    have hcast' := (Rat.cast_lt (K := ℝ)).2 hrat
    have hden : ((((1 : ℚ) / 2^80 : ℚ) : ℝ)) =
        (1 : ℝ) / 2^80 := by norm_num
    rw [hden] at hcast'
    exact hcast'
  have hexp : (-(80 : ℝ)) <
      -((78809294874 : ℝ) / 1000000000) := by
    norm_num
  have hrpow := Real.rpow_lt_rpow_of_exponent_lt
    (by norm_num : (1 : ℝ) < 2) hexp
  have hpow80 : Real.rpow 2 (-(80 : ℝ)) = (1 : ℝ) / 2^80 := by
    calc
      Real.rpow 2 (-(80 : ℝ)) = (2 : ℝ) ^ (-(80 : ℤ)) := by
        convert Real.rpow_neg_natCast (2 : ℝ) 80 using 1 <;> norm_num
      _ = (1 : ℝ) / 2^80 := by
        norm_num only [zpow_neg, zpow_natCast, one_div]
  exact hcast.trans (hpow80 ▸ hrpow)

end VoltaZk

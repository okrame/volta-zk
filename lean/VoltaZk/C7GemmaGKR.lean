import VoltaZk.C7GemmaTerminalManifest
import VoltaZk.BatchSumcheckSound
import Mathlib.Tactic

/-!
# Gemma-31B runtime-manifest and heterogeneous GKR seams

This file contains only consequences of explicit premises.  In particular,
it does not assert that Rust emitted the canonical manifest, that concrete
Gemma GKR cohorts exist, or that a classical-ROM reduction maps every
adaptive transcript into the global query slots below.
-/

namespace VoltaZk

open Finset

/-! ## Runtime-manifest and public-scalar binding boundary -/

structure C7GemmaPublicLayerScalarSpec where
  rawLeHex : String
  bf16Bits : Nat
  valueHexfloat : String
  deriving DecidableEq, Repr

/-- The exact ordered BF16 bit patterns.  These are checkpoint values, not
ones and not model-independent constants. -/
def c7GemmaPublicLayerScalarSpecs : List C7GemmaPublicLayerScalarSpec :=
  [ ⟨"c63d", 15814, "0x1.8c00000000000p-4"⟩,
    ⟨"903d", 15760, "0x1.2000000000000p-4"⟩,
    ⟨"7e3f", 16254, "0x1.fc00000000000p-1"⟩,
    ⟨"783f", 16248, "0x1.f000000000000p-1"⟩,
    ⟨"7c3f", 16252, "0x1.f800000000000p-1"⟩,
    ⟨"613f", 16225, "0x1.c200000000000p-1"⟩,
    ⟨"6a3f", 16234, "0x1.d400000000000p-1"⟩,
    ⟨"5a3f", 16218, "0x1.b400000000000p-1"⟩,
    ⟨"5c3f", 16220, "0x1.b800000000000p-1"⟩,
    ⟨"5e3f", 16222, "0x1.bc00000000000p-1"⟩,
    ⟨"6a3f", 16234, "0x1.d400000000000p-1"⟩,
    ⟨"503f", 16208, "0x1.a000000000000p-1"⟩,
    ⟨"383f", 16184, "0x1.7000000000000p-1"⟩,
    ⟨"793f", 16249, "0x1.f200000000000p-1"⟩,
    ⟨"7a3f", 16250, "0x1.f400000000000p-1"⟩,
    ⟨"573f", 16215, "0x1.ae00000000000p-1"⟩,
    ⟨"7a3f", 16250, "0x1.f400000000000p-1"⟩,
    ⟨"583f", 16216, "0x1.b000000000000p-1"⟩,
    ⟨"783f", 16248, "0x1.f000000000000p-1"⟩,
    ⟨"683f", 16232, "0x1.d000000000000p-1"⟩,
    ⟨"673f", 16231, "0x1.ce00000000000p-1"⟩,
    ⟨"753f", 16245, "0x1.ea00000000000p-1"⟩,
    ⟨"693f", 16233, "0x1.d200000000000p-1"⟩,
    ⟨"323f", 16178, "0x1.6400000000000p-1"⟩,
    ⟨"563f", 16214, "0x1.ac00000000000p-1"⟩,
    ⟨"4b3f", 16203, "0x1.9600000000000p-1"⟩,
    ⟨"2a3f", 16170, "0x1.5400000000000p-1"⟩,
    ⟨"243f", 16164, "0x1.4800000000000p-1"⟩,
    ⟨"ea3e", 16106, "0x1.d400000000000p-2"⟩,
    ⟨"103f", 16144, "0x1.2000000000000p-1"⟩,
    ⟨"323f", 16178, "0x1.6400000000000p-1"⟩,
    ⟨"423f", 16194, "0x1.8400000000000p-1"⟩,
    ⟨"443f", 16196, "0x1.8800000000000p-1"⟩,
    ⟨"493f", 16201, "0x1.9200000000000p-1"⟩,
    ⟨"423f", 16194, "0x1.8400000000000p-1"⟩,
    ⟨"2b3f", 16171, "0x1.5600000000000p-1"⟩,
    ⟨"4a3f", 16202, "0x1.9400000000000p-1"⟩,
    ⟨"4f3f", 16207, "0x1.9e00000000000p-1"⟩,
    ⟨"4c3f", 16204, "0x1.9800000000000p-1"⟩,
    ⟨"2f3f", 16175, "0x1.5e00000000000p-1"⟩,
    ⟨"173f", 16151, "0x1.2e00000000000p-1"⟩,
    ⟨"253f", 16165, "0x1.4a00000000000p-1"⟩,
    ⟨"443f", 16196, "0x1.8800000000000p-1"⟩,
    ⟨"4f3f", 16207, "0x1.9e00000000000p-1"⟩,
    ⟨"593f", 16217, "0x1.b200000000000p-1"⟩,
    ⟨"5f3f", 16223, "0x1.be00000000000p-1"⟩,
    ⟨"653f", 16229, "0x1.ca00000000000p-1"⟩,
    ⟨"613f", 16225, "0x1.c200000000000p-1"⟩,
    ⟨"603f", 16224, "0x1.c000000000000p-1"⟩,
    ⟨"553f", 16213, "0x1.aa00000000000p-1"⟩,
    ⟨"5e3f", 16222, "0x1.bc00000000000p-1"⟩,
    ⟨"5f3f", 16223, "0x1.be00000000000p-1"⟩,
    ⟨"343f", 16180, "0x1.6800000000000p-1"⟩,
    ⟨"543f", 16212, "0x1.a800000000000p-1"⟩,
    ⟨"683f", 16232, "0x1.d000000000000p-1"⟩,
    ⟨"5f3f", 16223, "0x1.be00000000000p-1"⟩,
    ⟨"583f", 16216, "0x1.b000000000000p-1"⟩,
    ⟨"4f3f", 16207, "0x1.9e00000000000p-1"⟩,
    ⟨"3a3f", 16186, "0x1.7400000000000p-1"⟩,
    ⟨"233d", 15651, "0x1.4600000000000p-5"⟩ ]

def c7GemmaPublicLayerScalarSourceKey (layer : Nat) : String :=
  s!"model.language_model.layers.{layer}.layer_scalar"

def c7GemmaPublicLayerScalarLine
    (specAndLayer : C7GemmaPublicLayerScalarSpec × Nat) : String :=
  let spec := specAndLayer.1
  let layer := specAndLayer.2
  s!"{layer},{c7GemmaPublicLayerScalarSourceKey layer}," ++
    s!"{spec.rawLeHex},{spec.bf16Bits},{spec.valueHexfloat}"

def c7GemmaPublicLayerScalarHeader : List String :=
  ["@schema=volta-c7-d126-gemma31b-layer-scalars-v1",
   "@model=google/gemma-4-31B",
   "@revision=5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
   "@source_metadata_sha256=1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2",
   "@ordered_raw_sha256=4d4ddd2f27faee67f141f83903c02bc93864a92402fd2cb9896da2628e6dbb70",
   "@count=60",
   "@record_columns=layer|name|raw_le_hex|bf16_bits|value_hexfloat"]

def c7GemmaSharedPublicLayerScalarSource : String :=
  include_str "../../manifests/c7-d126-gemma31b-layer-scalars-v1.csv"

def c7GemmaCanonicalPublicLayerScalarLines : List String :=
  c7GemmaPublicLayerScalarHeader ++
    c7GemmaPublicLayerScalarSpecs.zipIdx.map c7GemmaPublicLayerScalarLine ++ [""]

set_option linter.hashCommand false in
#guard c7GemmaSharedPublicLayerScalarSource.splitOn "\n" ==
  c7GemmaCanonicalPublicLayerScalarLines

def c7GemmaOrderedPublicLayerScalarBits : List Nat :=
  c7GemmaPublicLayerScalarSpecs.map (·.bf16Bits)

def c7GemmaOrderedPublicLayerScalarSourceKeys : List String :=
  (List.range 60).map c7GemmaPublicLayerScalarSourceKey

theorem c7_gemma_public_layer_scalar_census :
    c7GemmaPublicLayerScalarSpecs.length = 60 ∧
      c7GemmaOrderedPublicLayerScalarBits.length = 60 ∧
      ∀ bits ∈ c7GemmaOrderedPublicLayerScalarBits, bits < 2 ^ 16 := by
  decide

/- The scalar-value order is exactly the public-key order already embedded
in the 480-terminal manifest.  This binds association, not runtime use in a
GKR relation. -/
set_option maxRecDepth 100000 in
theorem c7_gemma_manifest_public_scalar_key_order :
    (c7GemmaDeclaredTerminalManifest.flatMap
      (·.publicSourceKeys)) = c7GemmaOrderedPublicLayerScalarSourceKeys := by
  decide

/-- Exact data that an external runtime refinement must provide.  Equality to
the ordered list binds all 60 variable BF16 patterns; proving that Rust emits
this equality and interprets the raw little-endian bytes identically remains
an explicit obligation. -/
def C7GemmaRuntimeManifestAndPublicScalarsBound
    (runtimeOutput : List C7GemmaTerminalRecord)
    (orderedPublicScalars : List Nat) : Prop :=
  runtimeOutput = c7GemmaDeclaredTerminalManifest ∧
  orderedPublicScalars = c7GemmaOrderedPublicLayerScalarBits

/-- A complete caller-supplied manifest/scalar binding inherits the static
manifest refinement and preserves every ordered BF16 bit pattern.  This
theorem does not construct the binding, interpret BF16, or connect the values
to GKR relations. -/
theorem c7_gemma_bound_runtime_manifest_refines_stacked_profile
    (runtimeOutput : List C7GemmaTerminalRecord)
    (orderedPublicScalars : List Nat)
    (hbound : C7GemmaRuntimeManifestAndPublicScalarsBound
      runtimeOutput orderedPublicScalars) :
    C7GemmaDeclaredManifestRefinesStackedProfile
        runtimeOutput c7GemmaStackedUseProfile ∧
      (runtimeOutput.flatMap (·.publicSourceKeys)) =
        c7GemmaOrderedPublicLayerScalarSourceKeys ∧
      orderedPublicScalars = c7GemmaOrderedPublicLayerScalarBits := by
  rcases hbound with ⟨hmanifest, hscalars⟩
  subst runtimeOutput
  exact ⟨c7_gemma_declared_terminal_manifest_refines_stacked_profile,
    c7_gemma_manifest_public_scalar_key_order, hscalars⟩

/-! ## Heterogeneous cohort shapes -/

/-- One declared cohort shape. A family may mix different member counts,
round counts and degree schedules without artificial uniform padding. This
record intentionally contains no scheduler or runtime point claim. -/
structure C7GemmaGKRCohortShape where
  memberCount : Nat
  roundCount : Nat
  degreeBound : Nat → Nat

/-- The exact root numerator supplied by the generic scalar-batched blind
sumcheck theorem for one cohort. -/
def C7GemmaGKRCohortShape.rootNumerator
    (cohort : C7GemmaGKRCohortShape) : Nat :=
  cohort.memberCount +
    ((Finset.range cohort.roundCount).sum cohort.degreeBound +
      (cohort.roundCount + 2))

/-- Shape-only specialization of the existing malicious-prover theorem. For
one false member, one abstract batch has bad-tape numerator
`K + sum(d) + n + 2`. `hfin` remains the explicit final-opening premise.

This theorem does not prove that runtime member transcripts use a common
point. A scheduler refinement must expose the actual member point histories
and prove `HasCommonPoint` before this shape may be admitted. -/
theorem c7_gemma_gkr_cohort_shape_sound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {ι : Type*} [Fintype ι]
    (cohort : C7GemmaGKRCohortShape)
    (hn : 0 < cohort.roundCount)
    (claimed trueTotal : Fin cohort.memberCount → F)
    (A : F → MaliciousProver F cohort.roundCount cohort.degreeBound ι)
    (L : F → (Fin cohort.roundCount → F) → ι → F)
    (TR : F → TrueRounds F cohort.roundCount cohort.degreeBound)
    (hσ : ∀ β, (A β).σ₀ =
      ∑ k, batchWeight β k * claimed k)
    (htrue : ∀ β, (TR β).total =
      ∑ k, batchWeight β k * trueTotal k)
    (hfin : ∀ β, (TR β).finalEval = openEval (A β) (L β))
    (badMember : Fin cohort.memberCount)
    (hbad : claimed badMember ≠ trueTotal badMember) :
    (univ.filter fun Ω :
        F × (F × (Fin cohort.roundCount → F) × F) =>
      acceptsScalar hn (A Ω.1) (L Ω.1)
        Ω.2.1 Ω.2.2.1 Ω.2.2.2).card ≤
      cohort.rootNumerator * Fintype.card F ^ (cohort.roundCount + 2) := by
  simpa [C7GemmaGKRCohortShape.rootNumerator] using
    (outer_scalar_batch_blind_sumcheck_sound
      (F := F) (n := cohort.roundCount) (K := cohort.memberCount)
      (d := cohort.degreeBound) (ι := ι) hn claimed trueTotal A L TR
      hσ htrue hfin badMember hbad)

/-! ## One global Fiat--Shamir query axis -/

/-- Sum of the exact root numerators of a finite family.  The records may
have different member counts, round counts and degree schedules. -/
def c7GemmaGKRFamilyRootNumerator
    {cohortCount : Nat}
    (cohorts : Fin cohortCount → C7GemmaGKRCohortShape) : Nat :=
  ∑ cohort, (cohorts cohort).rootNumerator

/-- Pure union bound after a caller has mapped every concrete bad transcript
to one common finite tape space.  There is one outer axis of
`Q_FS_global + 1` slots and one inner axis of heterogeneous cohorts, hence the
global factor occurs exactly once.

The premise `hbad` is intentionally strong: a future classical-ROM theorem
must prove it for all local queries, concurrent sessions, aborts, retries and
the complete response-attempt lifetime.  This counting lemma is not that ROM
theorem and grants no security credit by itself. -/
theorem c7_gemma_gkr_heterogeneous_qfs_union_bound_once
    {Ω : Type*} [DecidableEq Ω]
    {cohortCount scale : Nat}
    (cohorts : Fin cohortCount → C7GemmaGKRCohortShape)
    (bad : Fin (c7QFSGlobal + 1) → Fin cohortCount → Finset Ω)
    (hbad : ∀ slot cohort,
      (bad slot cohort).card ≤
        (cohorts cohort).rootNumerator * scale) :
    (univ.biUnion fun slot => univ.biUnion (bad slot)).card ≤
      (c7QFSGlobal + 1) *
        (c7GemmaGKRFamilyRootNumerator cohorts * scale) := by
  have hslot : ∀ slot,
      (univ.biUnion (bad slot)).card ≤
        c7GemmaGKRFamilyRootNumerator cohorts * scale := by
    intro slot
    calc
      (univ.biUnion (bad slot)).card ≤
          ∑ cohort, (bad slot cohort).card := Finset.card_biUnion_le
      _ ≤ ∑ cohort, (cohorts cohort).rootNumerator * scale := by
        exact Finset.sum_le_sum fun cohort _ => hbad slot cohort
      _ = c7GemmaGKRFamilyRootNumerator cohorts * scale := by
        simp [c7GemmaGKRFamilyRootNumerator, Finset.sum_mul]
  simpa using Finset.card_biUnion_le_card_mul univ
    (fun slot => univ.biUnion (bad slot))
    (c7GemmaGKRFamilyRootNumerator cohorts * scale)
    (fun slot _ => hslot slot)

/-- The global axis has exactly `2^64 + 1` slots.  There is no response-
lifetime multiplier in this definition. -/
theorem c7_gemma_qfs_global_slot_census :
    c7QFSGlobal + 1 = 18446744073709551617 := by
  norm_num [c7QFSGlobal]

#print axioms c7_gemma_bound_runtime_manifest_refines_stacked_profile
#print axioms c7_gemma_public_layer_scalar_census
#print axioms c7_gemma_manifest_public_scalar_key_order
#print axioms c7_gemma_gkr_cohort_shape_sound
#print axioms c7_gemma_gkr_heterogeneous_qfs_union_bound_once
#print axioms c7_gemma_qfs_global_slot_census

end VoltaZk

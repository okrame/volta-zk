import VoltaZk.C7StatefulAlfc
import VoltaZk.ProdSound
import VoltaZk.X4Field
import Mathlib.Data.Matrix.Mul
import Mathlib.Tactic

/-!
# C7 stacked weight uses

This file proves only the algebraic part of the proposed Gemma stacked-use
profile.  It does not assert that the Rust compiler emits these relations.
That missing refinement is named `C7CompilerMatchesStackedWeightUse` below.

The ProductClosure fraction at the end is only a conditional use-axis budget.
It includes the eight B/KV identity triples, but excludes upstream B/KV
query/PCS terms and the transformer's base-GKR error.
-/

namespace VoltaZk

open Finset Matrix

/-! ## Prompt/response row stacking for `X * W` -/

/-- Put prompt and response rows in one matrix without changing columns. -/
def c7StackRows
    {F P R K : Type*}
    (prompt : Matrix P K F) (response : Matrix R K F) :
    Matrix (P ⊕ R) K F :=
  Sum.elim prompt response

@[simp]
theorem c7_stack_rows_inl
    {F P R K : Type*}
    (prompt : Matrix P K F) (response : Matrix R K F)
    (p : P) (k : K) :
    c7StackRows prompt response (Sum.inl p) k = prompt p k := rfl

@[simp]
theorem c7_stack_rows_inr
    {F P R K : Type*}
    (prompt : Matrix P K F) (response : Matrix R K F)
    (r : R) (k : K) :
    c7StackRows prompt response (Sum.inr r) k = response r k := rfl

/-- Right multiplication by one physical weight matrix commutes with stacking
the prompt and response activation rows. -/
theorem c7_stack_rows_mul_right
    {F P R K O : Type*} [Semiring F] [Fintype K]
    (prompt : Matrix P K F) (response : Matrix R K F)
    (weight : Matrix K O F) :
    c7StackRows prompt response * weight =
      c7StackRows (prompt * weight) (response * weight) := by
  ext row output
  cases row <;> rfl

/-- The one stacked matrix equation is equivalent to the two old phase
equations. -/
theorem c7_stack_rows_relation_iff
    {F P R K O : Type*} [Semiring F] [Fintype K]
    (prompt : Matrix P K F) (response : Matrix R K F)
    (weight : Matrix K O F)
    (promptOutput : Matrix P O F) (responseOutput : Matrix R O F) :
    c7StackRows prompt response * weight =
        c7StackRows promptOutput responseOutput ↔
      prompt * weight = promptOutput ∧ response * weight = responseOutput := by
  rw [c7_stack_rows_mul_right]
  constructor
  · intro h
    constructor
    · ext p o
      exact congrFun (congrFun h (Sum.inl p)) o
    · ext r o
      exact congrFun (congrFun h (Sum.inr r)) o
  · rintro ⟨hp, hr⟩
    rw [hp, hr]

/-! ## Exact active-coordinate coverage in one packed segment -/

/-- Active coordinates are owned by the segment; padding coordinates have no
owner. -/
def c7PackedOwner {A Padding : Type*} : A ⊕ Padding → Option Unit
  | Sum.inl _ => some ()
  | Sum.inr _ => none

/-- Active coordinates retain their exact index.  Padding has no local
index. -/
def c7PackedLocalIndex {A Padding : Type*} : A ⊕ Padding → Option A
  | Sum.inl a => some a
  | Sum.inr _ => none

/-- The query is zero on the distinguished padding index. -/
def c7PackedEqAt {F A : Type*} [Zero F]
    (query : A → F) : Unit → Option A → F
  | _, some a => query a
  | _, none => 0

/-- `packedSegmentClaim` includes every active coordinate exactly once and no
padding coordinate.  This is the algebraic coverage theorem; choosing the
actual compiler's active and padding index types remains a refinement
obligation. -/
theorem c7_one_segment_packed_claim_exact
    {F A Padding : Type*} [Semiring F]
    [Fintype A] [Fintype Padding]
    (query : A → F) (packedWeight : A ⊕ Padding → F) :
    packedSegmentClaim c7PackedOwner c7PackedLocalIndex
        (c7PackedEqAt query) packedWeight () =
      ∑ a : A, query a * packedWeight (Sum.inl a) := by
  classical
  unfold packedSegmentClaim
  rw [Finset.sum_filter, Fintype.sum_sum_type]
  simp [c7PackedOwner, c7PackedLocalIndex, c7PackedEqAt]

/-! ## Shared physical vectors with disjoint tags -/

/-- One sparse row for each `(tag, coordinate)`.  It selects exactly the same
physical coordinate and therefore creates no cross-tag or cross-coordinate
term. -/
def c7SharedDiagonalBundle
    {F Tag I : Type*} [Zero F] [DecidableEq I]
    (activation : Tag → I → F) : Matrix (Tag × I) I F :=
  fun tagged physical =>
    if tagged.2 = physical then activation tagged.1 tagged.2 else 0

theorem c7_shared_diagonal_no_cross_term
    {F Tag I : Type*} [Zero F] [DecidableEq I]
    (activation : Tag → I → F) (tag : Tag) (i j : I)
    (hij : i ≠ j) :
    c7SharedDiagonalBundle activation (tag, i) j = 0 := by
  simp [c7SharedDiagonalBundle, hij]

theorem c7_shared_diagonal_mulVec
    {F Tag I : Type*} [Semiring F] [Fintype I] [DecidableEq I]
    (activation : Tag → I → F) (weight : I → F)
    (tag : Tag) (i : I) :
    (c7SharedDiagonalBundle activation *ᵥ weight) (tag, i) =
      activation tag i * weight i := by
  classical
  simp [c7SharedDiagonalBundle, Matrix.mulVec, dotProduct]

def C7TwelveNormPerUseRelation
    {F D : Type*} [Mul F]
    (activation output : Fin 2 → Fin 6 → D → F)
    (weight : Fin 6 × D → F) : Prop :=
  ∀ phase role d, output phase role d = activation phase role d * weight (role, d)

def C7TwelveNormBundleRelation
    {F D : Type*} [Semiring F] [Fintype D] [DecidableEq D]
    (activation output : Fin 2 → Fin 6 → D → F)
    (weight : Fin 6 × D → F) : Prop :=
  c7SharedDiagonalBundle
      (fun phase rd => activation phase rd.1 rd.2) *ᵥ weight =
    fun tagged => output tagged.1 tagged.2.1 tagged.2.2

/-- The twelve old norm uses (two phases times six roles) are exactly one
tagged direct-sum relation on the six physical norm vectors. -/
theorem c7_twelve_norm_uses_bundle_direct_sum
    {F D : Type*} [Semiring F] [Fintype D] [DecidableEq D]
    (activation output : Fin 2 → Fin 6 → D → F)
    (weight : Fin 6 × D → F) :
    C7TwelveNormBundleRelation activation output weight ↔
      C7TwelveNormPerUseRelation activation output weight := by
  constructor
  · intro h phase role d
    have hrow := congrFun h (phase, (role, d))
    simpa [c7_shared_diagonal_mulVec] using hrow.symm
  · intro h
    funext tagged
    rcases tagged with ⟨phase, role, d⟩
    simpa [c7_shared_diagonal_mulVec] using (h phase role d).symm

/-- Explicitly, a norm row for one role cannot read any other role or
coordinate. -/
theorem c7_norm_bundle_no_cross_term
    {F D : Type*} [Zero F] [DecidableEq D]
    (activation : Fin 2 → Fin 6 → D → F)
    (phase : Fin 2) (role role' : Fin 6) (d d' : D)
    (h : (role, d) ≠ (role', d')) :
    c7SharedDiagonalBundle
        (fun phase rd => activation phase rd.1 rd.2)
        (phase, (role, d)) (role', d') = 0 :=
  c7_shared_diagonal_no_cross_term _ _ _ _ h

/-! ## Tied embedding, with distinct lookup and logits orientations -/

/-- Flatten the two differently shaped tied-embedding outputs into a tagged
direct sum.  The left summand is lookup (`selection * embedding`); the right
is logits (`hidden * embeddingᵀ`). -/
def c7TiedEmbeddingDirectSum
    {F Phase V D : Type*} [Semiring F] [Fintype V] [Fintype D]
    (selection : Matrix Phase V F) (hidden : Matrix Phase D F)
    (embedding : Matrix V D F) : (Phase × D) ⊕ (Phase × V) → F
  | Sum.inl pd => (selection * embedding) pd.1 pd.2
  | Sum.inr pv => (hidden * embeddingᵀ) pv.1 pv.2

/-- One direct-sum equation is equivalent to both old equations, while
retaining the two opposite orientations of the same physical embedding. -/
theorem c7_tied_embedding_direct_sum
    {F Phase V D : Type*} [Semiring F] [Fintype V] [Fintype D]
    (selection : Matrix Phase V F) (hidden : Matrix Phase D F)
    (embedding : Matrix V D F)
    (lookupOutput : Matrix Phase D F) (logitsOutput : Matrix Phase V F) :
    c7TiedEmbeddingDirectSum selection hidden embedding =
        Sum.elim (fun pd => lookupOutput pd.1 pd.2)
          (fun pv => logitsOutput pv.1 pv.2) ↔
      selection * embedding = lookupOutput ∧
        hidden * embeddingᵀ = logitsOutput := by
  constructor
  · intro h
    constructor
    · ext phase d
      exact congrFun h (Sum.inl (phase, d))
    · ext phase v
      exact congrFun h (Sum.inr (phase, v))
  · rintro ⟨hlookup, hlogits⟩
    funext tagged
    cases tagged with
    | inl pd =>
        exact congrFun (congrFun hlookup pd.1) pd.2
    | inr pv =>
        exact congrFun (congrFun hlogits pv.1) pv.2

/-! ## Final norm in both phases -/

def C7FinalNormPerUseRelation
    {F D : Type*} [Mul F]
    (activation output : Fin 2 → D → F) (weight : D → F) : Prop :=
  ∀ phase d, output phase d = activation phase d * weight d

def C7FinalNormBundleRelation
    {F D : Type*} [Semiring F] [Fintype D] [DecidableEq D]
    (activation output : Fin 2 → D → F) (weight : D → F) : Prop :=
  c7SharedDiagonalBundle activation *ᵥ weight =
    fun tagged => output tagged.1 tagged.2

theorem c7_final_norm_two_phase_direct_sum
    {F D : Type*} [Semiring F] [Fintype D] [DecidableEq D]
    (activation output : Fin 2 → D → F) (weight : D → F) :
    C7FinalNormBundleRelation activation output weight ↔
      C7FinalNormPerUseRelation activation output weight := by
  constructor
  · intro h phase d
    have hrow := congrFun h (phase, d)
    simpa [c7_shared_diagonal_mulVec] using hrow.symm
  · intro h
    funext tagged
    rcases tagged with ⟨phase, d⟩
    simpa [c7_shared_diagonal_mulVec] using (h phase d).symm

/-! ## Complete algebraic relation -/

structure C7StackedWeightUseInstance
    (F P R K O D V : Type*) where
  ordinaryWeight : Matrix K O F
  promptActivation : Matrix P K F
  responseActivation : Matrix R K F
  promptOutput : Matrix P O F
  responseOutput : Matrix R O F
  normWeight : Fin 6 × D → F
  normActivation : Fin 2 → Fin 6 → D → F
  normOutput : Fin 2 → Fin 6 → D → F
  tiedEmbedding : Matrix V D F
  tiedSelection : Matrix (Fin 2) V F
  tiedHidden : Matrix (Fin 2) D F
  tiedLookupOutput : Matrix (Fin 2) D F
  tiedLogitsOutput : Matrix (Fin 2) V F
  finalNormWeight : D → F
  finalNormActivation : Fin 2 → D → F
  finalNormOutput : Fin 2 → D → F

def C7PerUseWeightRelation
    {F P R K O D V : Type*} [Semiring F]
    [Fintype K] [Fintype D] [Fintype V] [DecidableEq D]
    (i : C7StackedWeightUseInstance F P R K O D V) : Prop :=
  i.promptActivation * i.ordinaryWeight = i.promptOutput ∧
  i.responseActivation * i.ordinaryWeight = i.responseOutput ∧
  C7TwelveNormPerUseRelation i.normActivation i.normOutput i.normWeight ∧
  i.tiedSelection * i.tiedEmbedding = i.tiedLookupOutput ∧
  i.tiedHidden * i.tiedEmbeddingᵀ = i.tiedLogitsOutput ∧
  C7FinalNormPerUseRelation
    i.finalNormActivation i.finalNormOutput i.finalNormWeight

def C7StackedWeightUseRelation
    {F P R K O D V : Type*} [Semiring F]
    [Fintype K] [Fintype D] [Fintype V] [DecidableEq D]
    (i : C7StackedWeightUseInstance F P R K O D V) : Prop :=
  c7StackRows i.promptActivation i.responseActivation * i.ordinaryWeight =
      c7StackRows i.promptOutput i.responseOutput ∧
  C7TwelveNormBundleRelation i.normActivation i.normOutput i.normWeight ∧
  c7TiedEmbeddingDirectSum i.tiedSelection i.tiedHidden i.tiedEmbedding =
      Sum.elim (fun pd => i.tiedLookupOutput pd.1 pd.2)
        (fun pv => i.tiedLogitsOutput pv.1 pv.2) ∧
  C7FinalNormBundleRelation
    i.finalNormActivation i.finalNormOutput i.finalNormWeight

/-- Algebraic completeness of the new relation against the old per-use
relations.  Despite the mandated name, this theorem does not claim a Rust
compiler refinement; that separate assumption is
`C7CompilerMatchesStackedWeightUse`. -/
theorem c7_stacked_weight_use_compiler_complete
    {F P R K O D V : Type*} [Semiring F]
    [Fintype K] [Fintype D] [Fintype V] [DecidableEq D]
    (i : C7StackedWeightUseInstance F P R K O D V) :
    C7StackedWeightUseRelation i ↔ C7PerUseWeightRelation i := by
  rw [C7StackedWeightUseRelation, C7PerUseWeightRelation,
    c7_stack_rows_relation_iff,
    c7_twelve_norm_uses_bundle_direct_sum,
    c7_tied_embedding_direct_sum,
    c7_final_norm_two_phase_direct_sum]
  tauto

/-- This is the deliberately unproved seam between an external compiler and
the algebraic relation above.  No theorem in this file supplies it. -/
def C7CompilerMatchesStackedWeightUse
    {F P R K O D V : Type*} [Semiring F]
    [Fintype K] [Fintype D] [Fintype V] [DecidableEq D]
    (compilerAccepts : C7StackedWeightUseInstance F P R K O D V → Prop) : Prop :=
  ∀ i, compilerAccepts i ↔ C7StackedWeightUseRelation i

/-! ## Computable stacked-use census -/

structure C7StackedUseProfile where
  localLayers : Nat
  localMatrixSegmentsPerLayer : Nat
  localNormSegmentsPerLayer : Nat
  globalLayers : Nat
  globalMatrixSegmentsPerLayer : Nat
  globalNormSegmentsPerLayer : Nat
  tiedEmbeddingSegments : Nat
  finalNormSegments : Nat
  nonWeightIdentityTerminals : Nat
  useAxisLengths : List Nat

def C7StackedUseProfile.weightTerminals (p : C7StackedUseProfile) : Nat :=
  p.localLayers *
      (p.localMatrixSegmentsPerLayer + p.localNormSegmentsPerLayer) +
    p.globalLayers *
      (p.globalMatrixSegmentsPerLayer + p.globalNormSegmentsPerLayer) +
    p.tiedEmbeddingSegments + p.finalNormSegments

def C7StackedUseProfile.allTerminals (p : C7StackedUseProfile) : Nat :=
  p.weightTerminals + p.nonWeightIdentityTerminals

/-- Number of binary reducer rounds needed by one use axis. -/
def c7UseReducerDepth (uses : Nat) : Nat :=
  if uses ≤ 1 then 0 else Nat.log2 (uses - 1) + 1

def C7StackedUseProfile.reducerInstances (p : C7StackedUseProfile) : Nat :=
  (p.useAxisLengths.map c7UseReducerDepth).sum

def C7StackedUseProfile.useEtaEvents (p : C7StackedUseProfile) : Nat :=
  (p.useAxisLengths.filter fun uses => 1 < uses).length

def c7GemmaStackedUseProfile : C7StackedUseProfile where
  localLayers := 50
  localMatrixSegmentsPerLayer := 7
  localNormSegmentsPerLayer := 1
  globalLayers := 10
  globalMatrixSegmentsPerLayer := 6
  globalNormSegmentsPerLayer := 1
  tiedEmbeddingSegments := 1
  finalNormSegments := 1
  nonWeightIdentityTerminals := 8
  useAxisLengths := List.replicate 480 1

set_option maxRecDepth 4096 in
theorem c7_gemma_stacked_use_census :
    c7GemmaStackedUseProfile.weightTerminals = 472 ∧
    c7GemmaStackedUseProfile.allTerminals = 480 ∧
    c7GemmaStackedUseProfile.useAxisLengths.length = 480 ∧
    (∀ uses ∈ c7GemmaStackedUseProfile.useAxisLengths, uses = 1) ∧
    c7GemmaStackedUseProfile.reducerInstances = 0 ∧
    c7GemmaStackedUseProfile.useEtaEvents = 0 := by
  constructor
  · norm_num [C7StackedUseProfile.weightTerminals, c7GemmaStackedUseProfile]
  constructor
  · norm_num [C7StackedUseProfile.allTerminals,
      C7StackedUseProfile.weightTerminals, c7GemmaStackedUseProfile]
  constructor
  · norm_num [c7GemmaStackedUseProfile]
  constructor
  · intro uses huses
    exact List.eq_of_mem_replicate huses
  constructor
  · change ((List.replicate 480 1).map c7UseReducerDepth).sum = 0
    rw [List.map_replicate, List.sum_replicate_nat]
    norm_num [c7UseReducerDepth]
  · change ((List.replicate 480 1).filter fun uses => 1 < uses).length = 0
    rw [List.filter_replicate]
    norm_num

/-! ## Isolated use-axis ProductClosure term -/

/-- `BadProductChi` has one root for each of the 480 product triples. -/
def c7GemmaBadProductChiRoots : Nat := c7GemmaStackedUseProfile.allTerminals

/-- `ProdSound` contributes two additional roots in `Delta`. -/
def c7GemmaProdSoundDeltaRoots : Nat := 2

/-- This 482-root numerator is ProductClosure on the use axis only. -/
def c7GemmaUseAxisProductClosureRoots : Nat :=
  c7GemmaBadProductChiRoots + c7GemmaProdSoundDeltaRoots

theorem c7_gemma_use_axis_product_closure_census :
    c7GemmaBadProductChiRoots = 480 ∧
    c7GemmaProdSoundDeltaRoots = 2 ∧
    c7GemmaUseAxisProductClosureRoots = 482 ∧
    c7GemmaStackedUseProfile.reducerInstances = 0 ∧
    c7GemmaStackedUseProfile.useEtaEvents = 0 := by
  rcases c7_gemma_stacked_use_census with
    ⟨_, hall, _, _, hreducers, heta⟩
  simp [c7GemmaBadProductChiRoots, c7GemmaProdSoundDeltaRoots,
    c7GemmaUseAxisProductClosureRoots, hall, hreducers, heta]

/-- Direct specialization of `prodBatch_sound_scalar`: for 480 product
triples, a false claim is accepted on at most `482 * |F|` challenge pairs
`(Delta, chi)`.  This is the use-axis ProductClosure result, not the
transformer's base-GKR soundness. -/
theorem c7_gemma_use_axis_prodBatch_sound_scalar
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    (z : Fin 480 → ProdClaim F) {j₀ : Fin 480}
    (hz : (z j₀).c.1 ≠ (z j₀).a.1 * (z j₀).b.1)
    (r : F × F) (msg : F → F × F) :
    (univ.filter fun Δχ : F × F =>
        (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1 =
          ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r).card
      ≤ 482 * Fintype.card F := by
  simpa using (prodBatch_sound_scalar z hz r msg)

def c7QFSGlobal : Nat := 2 ^ 64

/-- Selected rational budget expression for a future concrete C7/ROM bridge:
`(2^64 + 1) * (480 + 2) / p^3`.  It is not itself that bridge, nor the
complete GKR or protocol error. -/
def c7GemmaUseAxisProductClosureQ64Budget : ℚ :=
  (((c7QFSGlobal + 1 : Nat) : ℚ) *
      (c7GemmaUseAxisProductClosureRoots : ℚ)) /
    (goldilocksP : ℚ) ^ 3

/-- Arithmetic identity for the intended Q64 budget.  Instantiating the
abstract fixed-prefix theorem with concrete C7 Fp3 and lifting it through the
classical ROM transcript are separate obligations. -/
theorem c7_gemma_use_axis_product_closure_q64_budget_identity :
    c7GemmaUseAxisProductClosureQ64Budget =
      (((2 : ℚ) ^ 64 + 1) * 482) / (goldilocksP : ℚ) ^ 3 := by
  norm_num [c7GemmaUseAxisProductClosureQ64Budget, c7QFSGlobal,
    c7GemmaUseAxisProductClosureRoots, c7GemmaBadProductChiRoots,
    c7GemmaProdSoundDeltaRoots, c7GemmaStackedUseProfile,
    C7StackedUseProfile.weightTerminals, C7StackedUseProfile.allTerminals]

/-! ## Conditional q357 security arithmetic

This section is an arithmetic contract, not a claim of realized security.  In
particular, callers must establish all four complete plane bounds and the
residual bound; this file supplies none of those protocol premises.
-/

def c7Q357PlaneErrorCap : ℚ := 1 / (2 : ℚ) ^ 81

def c7Q357ResidualErrorCap : ℚ :=
  ((2 : ℚ) ^ 20 * 64) / (2 : ℚ) ^ 110 +
    3 / (2 : ℚ) ^ 128 + 1 / (2 : ℚ) ^ 120

/-- Sum of the four caller-supplied plane errors, the caller-supplied
residual, and the selected 482-root ProductClosure Q64 budget expression. -/
def c7Q357ConditionalTotalError
    (wError bError kvOldError kvNewError residualError : ℚ) : ℚ :=
  wError + bError + kvOldError + kvNewError + residualError +
    c7GemmaUseAxisProductClosureQ64Budget

/-- If all named external bounds hold, their exact rational sum is a
nonnegative quantity below `2^-78`.  This proves only the conditional
numerical screen. -/
theorem c7_q357_conditional_total_error_below_78_bits
    (wError bError kvOldError kvNewError residualError : ℚ)
    (hwNonneg : 0 ≤ wError)
    (hbNonneg : 0 ≤ bError)
    (hkvOldNonneg : 0 ≤ kvOldError)
    (hkvNewNonneg : 0 ≤ kvNewError)
    (hresidualNonneg : 0 ≤ residualError)
    (hw : wError ≤ c7Q357PlaneErrorCap)
    (hb : bError ≤ c7Q357PlaneErrorCap)
    (hkvOld : kvOldError ≤ c7Q357PlaneErrorCap)
    (hkvNew : kvNewError ≤ c7Q357PlaneErrorCap)
    (hresidual : residualError ≤ c7Q357ResidualErrorCap) :
    0 ≤ c7Q357ConditionalTotalError
          wError bError kvOldError kvNewError residualError ∧
      c7Q357ConditionalTotalError
          wError bError kvOldError kvNewError residualError <
        1 / (2 : ℚ) ^ 78 := by
  constructor
  · have hProductClosure : 0 ≤ c7GemmaUseAxisProductClosureQ64Budget := by
      norm_num [c7GemmaUseAxisProductClosureQ64Budget, c7QFSGlobal,
        c7GemmaUseAxisProductClosureRoots, c7GemmaBadProductChiRoots,
        c7GemmaProdSoundDeltaRoots, c7GemmaStackedUseProfile,
        C7StackedUseProfile.weightTerminals,
        C7StackedUseProfile.allTerminals, goldilocksP]
    unfold c7Q357ConditionalTotalError
    linarith
  · calc
      c7Q357ConditionalTotalError
            wError bError kvOldError kvNewError residualError ≤
          4 * c7Q357PlaneErrorCap + c7Q357ResidualErrorCap +
            c7GemmaUseAxisProductClosureQ64Budget := by
        unfold c7Q357ConditionalTotalError
        linarith
      _ < 1 / (2 : ℚ) ^ 78 := by
        norm_num [c7Q357PlaneErrorCap, c7Q357ResidualErrorCap,
          c7GemmaUseAxisProductClosureQ64Budget, c7QFSGlobal,
          c7GemmaUseAxisProductClosureRoots, c7GemmaBadProductChiRoots,
          c7GemmaProdSoundDeltaRoots, c7GemmaStackedUseProfile,
          C7StackedUseProfile.weightTerminals,
          C7StackedUseProfile.allTerminals, goldilocksP]

#print axioms c7_stacked_weight_use_compiler_complete
#print axioms c7_gemma_stacked_use_census
#print axioms c7_gemma_use_axis_prodBatch_sound_scalar
#print axioms c7_gemma_use_axis_product_closure_q64_budget_identity
#print axioms c7_q357_conditional_total_error_below_78_bits

end VoltaZk

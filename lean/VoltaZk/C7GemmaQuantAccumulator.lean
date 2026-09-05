import VoltaZk.C7GemmaTerminalManifest
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.Order.Ring.Abs
import Mathlib.Data.Fintype.Card
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.NormNum

/-!
# Gemma-31B signed-i16 dot-product accumulator bound

This file proves an integer range bound from explicit assumptions only.  It
does not claim that a quantizer, compiler, Rust kernel, or runtime satisfies
those assumptions.
-/

namespace VoltaZk

open Matrix

/-! ## Exact workload-row stacking

The older two-phase statements can use one already-stacked vector per phase.
The theorems below retain every workload row explicitly: 100 prompt rows and
50 response rows for matrices, 150 lookup/norm rows, 149 active final-norm
rows, and 50 selected logit rows. No random linear combination is used here.
-/

def C7AllRowsSharedVectorPerUseRelation
    {F Row I : Type*} [Mul F]
    (activation output : Row → I → F) (weight : I → F) : Prop :=
  ∀ row i, output row i = activation row i * weight i

def C7AllRowsSharedVectorBundleRelation
    {F Row I : Type*} [Semiring F] [Fintype I] [DecidableEq I]
    (activation output : Row → I → F) (weight : I → F) : Prop :=
  c7SharedDiagonalBundle activation *ᵥ weight =
    fun tagged => output tagged.1 tagged.2

/-- One diagonal bundle is equivalent to every explicitly indexed row of a
shared vector multiplication. -/
theorem c7_all_rows_shared_vector_bundle_iff_per_use
    {F Row I : Type*} [Semiring F] [Fintype I] [DecidableEq I]
    (activation output : Row → I → F) (weight : I → F) :
    C7AllRowsSharedVectorBundleRelation activation output weight ↔
      C7AllRowsSharedVectorPerUseRelation activation output weight := by
  constructor
  · intro h row i
    have hrow := congrFun h (row, i)
    simpa [c7_shared_diagonal_mulVec] using hrow.symm
  · intro h
    funext tagged
    rcases tagged with ⟨row, i⟩
    simpa [c7_shared_diagonal_mulVec] using (h row i).symm

def c7AllRowsRaggedNormUseDiagonal
    {F Row : Type*} [Zero F] {Use D : Fin 6 → Type*}
    [∀ role, DecidableEq (D role)]
    (activation : Row → ∀ role, Use role → D role → F) :
    Matrix (Row × Sigma fun role => Use role × D role) (Sigma D) F :=
  fun tagged physical =>
    if (⟨tagged.2.1, tagged.2.2.2⟩ : Sigma D) = physical then
      activation tagged.1 tagged.2.1 tagged.2.2.1 tagged.2.2.2
    else 0

theorem c7_all_rows_ragged_norm_use_diagonal_mulVec
    {F Row : Type*} [Semiring F] {Use D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation : Row → ∀ role, Use role → D role → F)
    (weight : ∀ role, D role → F)
    (row : Row) (role : Fin 6) (use : Use role) (d : D role) :
    (c7AllRowsRaggedNormUseDiagonal activation *ᵥ
      (fun rd => weight rd.1 rd.2)) (row, ⟨role, (use, d)⟩) =
        activation row role use d * weight role d := by
  classical
  simp [c7AllRowsRaggedNormUseDiagonal, Matrix.mulVec, dotProduct]

def C7AllRowsRaggedNormUsePerUseRelation
    {F Row : Type*} [Mul F] {Use D : Fin 6 → Type*}
    (activation output : Row → ∀ role, Use role → D role → F)
    (weight : ∀ role, D role → F) : Prop :=
  ∀ row role use d,
    output row role use d = activation row role use d * weight role d

def C7AllRowsRaggedNormUseBundleRelation
    {F Row : Type*} [Semiring F] {Use D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation output : Row → ∀ role, Use role → D role → F)
    (weight : ∀ role, D role → F) : Prop :=
  c7AllRowsRaggedNormUseDiagonal activation *ᵥ
      (fun rd => weight rd.1 rd.2) =
    fun tagged =>
      output tagged.1 tagged.2.1 tagged.2.2.1 tagged.2.2.2

/-- One bundle is equivalent to every row/role/head/coordinate equation. The
dependent `Use` axis retains all Q/K heads while the other roles use one copy. -/
theorem c7_all_rows_ragged_norm_use_bundle_iff_per_use
    {F Row : Type*} [Semiring F] {Use D : Fin 6 → Type*}
    [∀ role, Fintype (D role)] [∀ role, DecidableEq (D role)]
    (activation output : Row → ∀ role, Use role → D role → F)
    (weight : ∀ role, D role → F) :
    C7AllRowsRaggedNormUseBundleRelation activation output weight ↔
      C7AllRowsRaggedNormUsePerUseRelation activation output weight := by
  constructor
  · intro h row role use d
    have hrow := congrFun h (row, ⟨role, (use, d)⟩)
    rw [c7_all_rows_ragged_norm_use_diagonal_mulVec] at hrow
    exact hrow.symm
  · intro h
    funext tagged
    rcases tagged with ⟨row, ⟨role, use, d⟩⟩
    rw [c7_all_rows_ragged_norm_use_diagonal_mulVec]
    exact (h row role use d).symm

def c7TiedEmbeddingSeparateRowsDirectSum
    {F LookupRow LogitsRow V D : Type*}
    [Semiring F] [Fintype V] [Fintype D]
    (selection : Matrix LookupRow V F) (hidden : Matrix LogitsRow D F)
    (embedding : Matrix V D F) :
    (LookupRow × D) ⊕ (LogitsRow × V) → F
  | Sum.inl ld => (selection * embedding) ld.1 ld.2
  | Sum.inr lv => (hidden * embeddingᵀ) lv.1 lv.2

/-- Lookup and logits may have different row counts while using the same
physical embedding in opposite orientations. -/
theorem c7_tied_embedding_separate_rows_direct_sum
    {F LookupRow LogitsRow V D : Type*}
    [Semiring F] [Fintype V] [Fintype D]
    (selection : Matrix LookupRow V F) (hidden : Matrix LogitsRow D F)
    (embedding : Matrix V D F)
    (lookupOutput : Matrix LookupRow D F)
    (logitsOutput : Matrix LogitsRow V F) :
    c7TiedEmbeddingSeparateRowsDirectSum selection hidden embedding =
        Sum.elim (fun ld => lookupOutput ld.1 ld.2)
          (fun lv => logitsOutput lv.1 lv.2) ↔
      selection * embedding = lookupOutput ∧
        hidden * embeddingᵀ = logitsOutput := by
  constructor
  · intro h
    constructor
    · ext row d
      exact congrFun h (Sum.inl (row, d))
    · ext row v
      exact congrFun h (Sum.inr (row, v))
  · rintro ⟨hlookup, hlogits⟩
    funext tagged
    cases tagged with
    | inl ld => exact congrFun (congrFun hlookup ld.1) ld.2
    | inr lv => exact congrFun (congrFun hlogits lv.1) lv.2

abbrev C7GemmaPromptRow := Fin 100
abbrev C7GemmaResponseRow := Fin 50
abbrev C7GemmaAllTokenRow := Fin 150
abbrev C7GemmaDecisionRow := Fin 50
abbrev C7GemmaDecodeDecisionInputRow := Fin 49
abbrev C7GemmaFinalNormRow := C7GemmaPromptRow ⊕ C7GemmaDecodeDecisionInputRow

/-- Decision zero selects the last prefill row; decisions one through 49
select the corresponding singleton decode row. -/
def c7GemmaDecisionFinalNormRow : C7GemmaDecisionRow → C7GemmaFinalNormRow :=
  Fin.cases (Sum.inl ⟨99, by decide⟩) (fun row => Sum.inr row)

def c7GemmaSelectFinalNormDecisionRows
    {F D : Type*} (finalNorm : Matrix C7GemmaFinalNormRow D F) :
    Matrix C7GemmaDecisionRow D F :=
  fun decision d => finalNorm (c7GemmaDecisionFinalNormRow decision) d

theorem c7_gemma_decision_final_norm_row_zero :
    c7GemmaDecisionFinalNormRow (0 : C7GemmaDecisionRow) =
      Sum.inl (99 : C7GemmaPromptRow) := rfl

theorem c7_gemma_decision_final_norm_row_succ
    (row : C7GemmaDecodeDecisionInputRow) :
    c7GemmaDecisionFinalNormRow row.succ = Sum.inr row := rfl

def c7GemmaLocalNormUseCount (role : Fin 6) : Nat :=
  if role.val < 4 then 1 else if role.val = 4 then 16 else 32

def c7GemmaGlobalNormUseCount (role : Fin 6) : Nat :=
  if role.val < 4 then 1 else if role.val = 4 then 4 else 32

abbrev C7GemmaLocalNormUse (role : Fin 6) : Type :=
  Fin (c7GemmaLocalNormUseCount role)

abbrev C7GemmaGlobalNormUse (role : Fin 6) : Type :=
  Fin (c7GemmaGlobalNormUseCount role)

theorem c7_gemma_matrix_100_prompt_50_response_rows
    {F K O : Type*} [Semiring F] [Fintype K]
    (prompt : Matrix C7GemmaPromptRow K F)
    (response : Matrix C7GemmaResponseRow K F)
    (weight : Matrix K O F)
    (promptOutput : Matrix C7GemmaPromptRow O F)
    (responseOutput : Matrix C7GemmaResponseRow O F) :
    c7StackRows prompt response * weight =
        c7StackRows promptOutput responseOutput ↔
      prompt * weight = promptOutput ∧ response * weight = responseOutput :=
  c7_stack_rows_relation_iff prompt response weight promptOutput responseOutput

theorem c7_gemma_local_norm_all_150_rows_and_heads
    {F : Type*} [Semiring F]
    (activation output : C7GemmaAllTokenRow → ∀ role,
      C7GemmaLocalNormUse role → C7GemmaLocalNormCoordinate role → F)
    (weight : ∀ role, C7GemmaLocalNormCoordinate role → F) :
    C7AllRowsRaggedNormUseBundleRelation activation output weight ↔
      C7AllRowsRaggedNormUsePerUseRelation activation output weight :=
  c7_all_rows_ragged_norm_use_bundle_iff_per_use activation output weight

theorem c7_gemma_global_norm_all_150_rows_and_heads
    {F : Type*} [Semiring F]
    (activation output : C7GemmaAllTokenRow → ∀ role,
      C7GemmaGlobalNormUse role → C7GemmaGlobalNormCoordinate role → F)
    (weight : ∀ role, C7GemmaGlobalNormCoordinate role → F) :
    C7AllRowsRaggedNormUseBundleRelation activation output weight ↔
      C7AllRowsRaggedNormUsePerUseRelation activation output weight :=
  c7_all_rows_ragged_norm_use_bundle_iff_per_use activation output weight

theorem c7_gemma_norm_headed_per_token_census :
    (∑ role : Fin 6,
      c7GemmaLocalNormUseCount role * c7GemmaLocalNormDimension role) = 33792 ∧
    (∑ role : Fin 6,
      c7GemmaGlobalNormUseCount role * c7GemmaGlobalNormDimension role) = 39936 := by
  decide

theorem c7_gemma_norm_headed_workload_equation_census :
    50 * 150 * 33792 + 10 * 150 * 39936 = 313344000 := by
  norm_num

theorem c7_gemma_tied_embedding_150_lookup_selected_50_logits
    {F V D : Type*} [Semiring F] [Fintype V] [Fintype D]
    (selection : Matrix C7GemmaAllTokenRow V F)
    (finalNorm : Matrix C7GemmaFinalNormRow D F)
    (embedding : Matrix V D F)
    (lookupOutput : Matrix C7GemmaAllTokenRow D F)
    (logitsOutput : Matrix C7GemmaDecisionRow V F) :
    c7TiedEmbeddingSeparateRowsDirectSum selection
        (c7GemmaSelectFinalNormDecisionRows finalNorm) embedding =
        Sum.elim (fun ld => lookupOutput ld.1 ld.2)
          (fun lv => logitsOutput lv.1 lv.2) ↔
      selection * embedding = lookupOutput ∧
        c7GemmaSelectFinalNormDecisionRows finalNorm * embeddingᵀ =
          logitsOutput :=
  c7_tied_embedding_separate_rows_direct_sum
    selection (c7GemmaSelectFinalNormDecisionRows finalNorm) embedding
      lookupOutput logitsOutput

theorem c7_gemma_final_norm_all_149_active_rows
    {F D : Type*} [Semiring F] [Fintype D] [DecidableEq D]
    (activation output : C7GemmaFinalNormRow → D → F)
    (weight : D → F) :
    C7AllRowsSharedVectorBundleRelation activation output weight ↔
      C7AllRowsSharedVectorPerUseRelation activation output weight :=
  c7_all_rows_shared_vector_bundle_iff_per_use activation output weight

theorem c7_gemma_workload_row_census :
    Fintype.card C7GemmaPromptRow = 100 ∧
    Fintype.card C7GemmaResponseRow = 50 ∧
    Fintype.card C7GemmaAllTokenRow = 150 ∧
    Fintype.card C7GemmaDecisionRow = 50 ∧
    Fintype.card C7GemmaFinalNormRow = 149 := by
  norm_num [C7GemmaPromptRow, C7GemmaResponseRow,
    C7GemmaAllTokenRow, C7GemmaDecisionRow, C7GemmaFinalNormRow,
    C7GemmaDecodeDecisionInputRow]

/-- Largest magnitude admitted by the symmetric signed-i16 convention. -/
def c7GemmaI16Magnitude : ℤ := 32767

/-- Largest inner dimension in the pinned Gemma-31B text model. -/
def c7GemmaMaxDotWidth : ℕ := 21504

/-- `21504 * 32767²`, the largest absolute dot-product accumulator. -/
def c7GemmaMaxDotMagnitude : ℤ := 23088334918656

/-- Goldilocks prime `2^64 - 2^32 + 1`, restated locally so this arithmetic
lemma does not import a legacy protocol module. -/
def c7GemmaGoldilocksModulus : ℤ := 18446744069414584321

/-- A dot product whose two inputs use the symmetric signed-i16 range and
whose width is at most `21504` fits in the exact integer bound
`21504 * 32767²`.

The hypotheses are deliberately external: a runtime-refinement theorem must
separately show that concrete tensors and every concrete inner dimension
satisfy them. -/
theorem c7_gemma_i16_dot_accumulator_bound
    {k : ℕ} (hk : k ≤ c7GemmaMaxDotWidth)
    (a b : Fin k → ℤ)
    (ha : ∀ i, |a i| ≤ c7GemmaI16Magnitude)
    (hb : ∀ i, |b i| ≤ c7GemmaI16Magnitude) :
    |∑ i, a i * b i| ≤ c7GemmaMaxDotMagnitude := by
  calc
    |∑ i, a i * b i| ≤ ∑ i, |a i * b i| :=
      by simpa using Finset.abs_sum_le_sum_abs (fun i ↦ a i * b i) Finset.univ
    _ ≤ ∑ _i : Fin k, (1073676289 : ℤ) := by
      apply Finset.sum_le_sum
      intro i _hi
      rw [abs_mul]
      have hai : 0 ≤ |a i| := abs_nonneg (a i)
      have hbi : 0 ≤ |b i| := abs_nonneg (b i)
      norm_num [c7GemmaI16Magnitude] at ha hb
      nlinarith [ha i, hb i]
    _ = (k : ℤ) * 1073676289 := by simp
    _ ≤ c7GemmaMaxDotMagnitude := by
      have hk' : (k : ℤ) ≤ 21504 := by
        exact Int.ofNat_le.mpr (by simpa [c7GemmaMaxDotWidth] using hk)
      norm_num [c7GemmaMaxDotMagnitude]
      nlinarith

/-- The exact worst-case accumulator is strictly below half the Goldilocks
modulus (integer division rounds the positive odd modulus down). -/
theorem c7_gemma_i16_max_below_goldilocks_half :
    c7GemmaMaxDotMagnitude < c7GemmaGoldilocksModulus / 2 := by
  norm_num [c7GemmaMaxDotMagnitude, c7GemmaGoldilocksModulus]

/-- Consequently, every dot product covered by the explicit hypotheses lies
inside the centered Goldilocks representative interval. -/
theorem c7_gemma_i16_dot_in_centered_goldilocks_range
    {k : ℕ} (hk : k ≤ c7GemmaMaxDotWidth)
    (a b : Fin k → ℤ)
    (ha : ∀ i, |a i| ≤ c7GemmaI16Magnitude)
    (hb : ∀ i, |b i| ≤ c7GemmaI16Magnitude) :
    -(c7GemmaGoldilocksModulus / 2) < ∑ i, a i * b i ∧
      ∑ i, a i * b i < c7GemmaGoldilocksModulus / 2 := by
  have hbound := c7_gemma_i16_dot_accumulator_bound hk a b ha hb
  have hhalf := c7_gemma_i16_max_below_goldilocks_half
  rw [abs_le] at hbound
  exact ⟨(neg_lt_neg hhalf).trans_le hbound.1, hbound.2.trans_lt hhalf⟩

#print axioms c7_gemma_i16_dot_accumulator_bound
#print axioms c7_gemma_i16_max_below_goldilocks_half
#print axioms c7_gemma_i16_dot_in_centered_goldilocks_range
#print axioms c7_gemma_matrix_100_prompt_50_response_rows
#print axioms c7_gemma_local_norm_all_150_rows_and_heads
#print axioms c7_gemma_global_norm_all_150_rows_and_heads
#print axioms c7_gemma_norm_headed_per_token_census
#print axioms c7_gemma_norm_headed_workload_equation_census
#print axioms c7_gemma_decision_final_norm_row_zero
#print axioms c7_gemma_decision_final_norm_row_succ
#print axioms c7_gemma_tied_embedding_150_lookup_selected_50_logits
#print axioms c7_gemma_final_norm_all_149_active_rows

end VoltaZk

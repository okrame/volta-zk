import VoltaZk.BlindSumcheckSound

/-!
# Scalar batching of blind-sumcheck windows at one common challenge point

This file is the formal boundary for the P7 shared-round optimization.  A
`FixedSumcheckBatch` contains all member provers, public opening functionals,
and true semantics *before* the outer challenge `β` is sampled.  The only
post-`β` operation formalized here is the scalar-power linear combination
with weights `β^(k+1)`.

The construction deliberately uses one challenge vector `r` for every
member.  `HasCommonPoint` names the scheduler invariant needed when a concrete
implementation stores member-local point histories: algebraic batching does
not prove that an interleaving scheduler preserved that invariant.
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F]
variable {n K : ℕ} {d : ℕ → ℕ} {ι : Type*} [Fintype ι]

/-- Objects committed before the outer scalar batching challenge `β`.
Keeping `β` out of this structure is the formal fixed-before-challenge
boundary. -/
structure FixedSumcheckBatch (F : Type*) [Field F] (n K : ℕ)
    (d : ℕ → ℕ) (ι : Type*) [Fintype ι] where
  prover : Fin K → MaliciousProver F n d ι
  functional : Fin K → (Fin n → F) → ι → F
  truth : Fin K → TrueRounds F n d
  final_compatible : ∀ k, (truth k).finalEval = openEval (prover k) (functional k)

/-- Scalar-power weight used by Rust for the outer batch. -/
def batchWeight (β : F) (k : Fin K) : F := β ^ (k.val + 1)

/-- Linear combination of a fixed family of polynomials. -/
noncomputable def scalarBatchPoly (β : F) (p : Fin K → Polynomial F) : Polynomial F :=
  ∑ k, Polynomial.C (batchWeight β k) * p k

omit [Fintype ι] in
@[simp] theorem scalarBatchPoly_eval (β x : F) (p : Fin K → Polynomial F) :
    (scalarBatchPoly β p).eval x = ∑ k, batchWeight β k * (p k).eval x := by
  unfold scalarBatchPoly
  rw [Polynomial.eval_finsetSum]
  exact Finset.sum_congr rfl fun k _ => by simp

omit [Fintype ι] in
theorem scalarBatchPoly_natDegree_le (β : F) (p : Fin K → Polynomial F) {D : ℕ}
    (hp : ∀ k, (p k).natDegree ≤ D) : (scalarBatchPoly β p).natDegree ≤ D := by
  unfold scalarBatchPoly
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun k _ => ?_
  exact (Polynomial.natDegree_C_mul_le _ _).trans (hp k)

/-- Explicit scheduler invariant for member-local point histories. -/
def HasCommonPoint (points : Fin K → Fin n → F) (r : Fin n → F) : Prop :=
  ∀ k, points k = r

omit [Fintype ι] in
theorem trunc_eq_of_commonPoint (points : Fin K → Fin n → F) (r : Fin n → F)
    (hcommon : HasCommonPoint points r) (k : Fin K) (round : ℕ) :
    trunc (points k) round = trunc r round := by
  rw [hcommon k]

omit [Fintype ι] in
/-- Evaluation of a scalar batch is memberwise evaluation only when all
members are at the same point. -/
theorem scalarBatchPoly_eval_commonPoint (β : F) (p : Fin K → Polynomial F)
    (points : Fin K → Fin n → F) (r : Fin n → F) (i : Fin n)
    (hcommon : HasCommonPoint points r) :
    (scalarBatchPoly β p).eval (r i)
      = ∑ k, batchWeight β k * (p k).eval (points k i) := by
  rw [scalarBatchPoly_eval]
  refine Finset.sum_congr rfl fun k _ => ?_
  rw [hcommon k]

/-- Componentwise linear combination of authenticated value/tag pairs. -/
def scalarBatchPair (β : F) (z : Fin K → F × F) : F × F :=
  (∑ k, batchWeight β k * (z k).1, ∑ k, batchWeight β k * (z k).2)

/-- Aggregate malicious prover.  Member witness and coefficient schedules are
fixed in `B`; the final message may be adversarial after seeing `β`, `r`, and
the inner closing challenge, as in the M3 model. -/
noncomputable def scalarBatchProver (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F) (β : F) :
    MaliciousProver F n d (Fin K × ι) where
  wit ki := (B.prover ki.1).wit ki.2
  coeff i pre j := scalarBatchPair β fun k => (B.prover k).coeff i pre j
  σ₀ := ∑ k, batchWeight β k * (B.prover k).σ₀
  final := finalMsg β

/-- Opening functional matching the product-indexed aggregate witness. -/
def scalarBatchFunctional (B : FixedSumcheckBatch F n K d ι) (β : F)
    (r : Fin n → F) (ki : Fin K × ι) : F :=
  batchWeight β ki.1 * B.functional ki.1 r ki.2

/-- Honest semantics of the aggregate window. -/
noncomputable def scalarBatchTruth (B : FixedSumcheckBatch F n K d ι) (β : F) :
    TrueRounds F n d where
  g i pre := scalarBatchPoly β fun k => (B.truth k).g i pre
  total := ∑ k, batchWeight β k * (B.truth k).total
  finalEval r := ∑ k, batchWeight β k * (B.truth k).finalEval r
  deg_le i pre := scalarBatchPoly_natDegree_le β _ fun k => (B.truth k).deg_le i pre
  first r := by
    simp only [scalarBatchPoly_eval]
    rw [← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl fun k _ => by
      rw [← mul_add, (B.truth k).first r]
  step r i h := by
    simp only [scalarBatchPoly_eval]
    rw [← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl fun k _ => by
      rw [← mul_add, (B.truth k).step r i h]
  final r hn := by
    simp only [scalarBatchPoly_eval]
    exact Finset.sum_congr rfl fun k _ => by
      rw [(B.truth k).final r hn]

theorem openEval_scalarBatchProver (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F) (β : F) (r : Fin n → F) :
    openEval (scalarBatchProver B finalMsg β) (scalarBatchFunctional B β) r
      = ∑ k, batchWeight β k * openEval (B.prover k) (B.functional k) r := by
  unfold openEval scalarBatchFunctional scalarBatchProver
  rw [Fintype.sum_prod_type]
  refine Finset.sum_congr rfl fun k _ => ?_
  change (∑ x : ι, (batchWeight β k * B.functional k r x) * ((B.prover k).wit x).1)
    = batchWeight β k * ∑ x : ι, B.functional k r x * ((B.prover k).wit x).1
  rw [Finset.mul_sum]
  exact Finset.sum_congr rfl fun x _ => by ring

/-- The aggregate true final functional is exactly the plaintext of the
aggregate authenticated opening. -/
theorem scalarBatch_final_compatible (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F) (β : F) :
    (scalarBatchTruth B β).finalEval
      = openEval (scalarBatchProver B finalMsg β) (scalarBatchFunctional B β) := by
  funext r
  rw [openEval_scalarBatchProver]
  change (∑ k, batchWeight β k * (B.truth k).finalEval r)
    = ∑ k, batchWeight β k * openEval (B.prover k) (B.functional k) r
  exact Finset.sum_congr rfl fun k _ => by rw [B.final_compatible k]

/-- Difference between aggregate claimed and true totals.  This is the
univariate error polynomial to which `card_scalarRlc_zero_le` applies. -/
theorem scalarBatch_total_error (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F) (β : F) :
    (scalarBatchProver B finalMsg β).σ₀ - (scalarBatchTruth B β).total
      = ∑ k, batchWeight β k * ((B.prover k).σ₀ - (B.truth k).total) := by
  unfold scalarBatchProver scalarBatchTruth
  rw [← Finset.sum_sub_distrib]
  exact Finset.sum_congr rfl fun k _ => by ring

/-- Acceptance of the one-common-point aggregate.  The randomness is ordered
as `(β, Δ, r, χ)`: outer scalar batch, MAC key, shared sumcheck point,
and inner scalar `Π_ZeroBatch` challenge. -/
noncomputable def acceptsScalarBatch (hn : 0 < n) (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F)
    (Ω : F × (F × (Fin n → F) × F)) : Prop :=
  acceptsScalar hn (scalarBatchProver B finalMsg Ω.1)
    (scalarBatchFunctional B Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2

noncomputable instance acceptsScalarBatch.instDecidable [DecidableEq F] (hn : 0 < n)
    (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F) :
    DecidablePred (acceptsScalarBatch hn B finalMsg) := fun _ => by
  unfold acceptsScalarBatch
  infer_instance

/-- **Malicious-prover shared-round scalar batching soundness.**  The `K`
claimed and true totals are fixed before `β`.  For every `β`, however, `A β`
is an otherwise arbitrary malicious aggregate round strategy: in particular,
its coefficient and final-message schedules may depend on `β`.  Only the
aggregate initial total, true total, and final-opening compatibility are
constrained by `hσ`, `htrue`, and `hfin`.

If one fixed claim is false, acceptance occurs on at most

`(K + (Σ dᵢ + n + 2)) · |F|^(n+2)`

of the `|F|^(n+3)` tapes `(β, Δ, r, χ)`.  Thus the outer scalar-power
collapse contributes at most `K/|F|`, and the surviving aggregate is covered
by the existing scalar M3 bound `(Σ dᵢ+n+2)/|F|`.

The verifier supplies one `r` to the aggregate strategy; this is the
common-point boundary.  A concrete
interleaving scheduler must separately establish `HasCommonPoint`; this
theorem does not justify combining member transcripts with different point
histories. -/
theorem outer_scalar_batch_blind_sumcheck_sound [Fintype F] [DecidableEq F] (hn : 0 < n)
    (claimed trueTotal : Fin K → F)
    (A : F → MaliciousProver F n d ι)
    (L : F → (Fin n → F) → ι → F) (TR : F → TrueRounds F n d)
    (hσ : ∀ β, (A β).σ₀ = ∑ k, batchWeight β k * claimed k)
    (htrue : ∀ β, (TR β).total = ∑ k, batchWeight β k * trueTotal k)
    (hfin : ∀ β, (TR β).finalEval = openEval (A β) (L β))
    (k₀ : Fin K) (hbad : claimed k₀ ≠ trueTotal k₀) :
    (univ.filter fun Ω : F × (F × (Fin n → F) × F) =>
        acceptsScalar hn (A Ω.1) (L Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2).card
      ≤ (K + (Finset.sum (Finset.range n) d + (n + 2)))
          * Fintype.card F ^ (n + 2) := by
  let collapsed : F → Prop := fun β =>
    (A β).σ₀ = (TR β).total
  have collapsed_dec : DecidablePred collapsed := fun β => by
    unfold collapsed
    infer_instance
  let error : Fin K → F := fun k => claimed k - trueTotal k
  have herror : error k₀ ≠ 0 := by
    exact sub_ne_zero.mpr hbad
  have hcollapsed_root : (univ.filter collapsed).card ≤ K := by
    refine le_trans (Finset.card_le_card ?_) (card_scalarRlc_zero_le error herror)
    intro β hβ
    simp only [mem_filter, mem_univ, true_and] at hβ ⊢
    have hz : (A β).σ₀ - (TR β).total = 0 := sub_eq_zero.mpr hβ
    rw [hσ β, htrue β] at hz
    have hz' : ∑ k, batchWeight β k * (claimed k - trueTotal k) = 0 := by
      calc
        _ = (∑ k, batchWeight β k * claimed k)
              - ∑ k, batchWeight β k * trueTotal k := by
            rw [← Finset.sum_sub_distrib]
            exact Finset.sum_congr rfl fun k _ => by ring
        _ = 0 := hz
    simpa [batchWeight, error] using hz'
  have hsub : (univ.filter fun Ω : F × (F × (Fin n → F) × F) =>
        acceptsScalar hn (A Ω.1) (L Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2)
      ⊆ (univ.filter fun Ω : F × (F × (Fin n → F) × F) => collapsed Ω.1)
        ∪ (univ.filter fun Ω : F × (F × (Fin n → F) × F) =>
            ¬ collapsed Ω.1 ∧
              acceptsScalar hn (A Ω.1) (L Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2) := by
    intro Ω hΩ
    simp only [mem_filter, mem_univ, true_and, mem_union] at hΩ ⊢
    by_cases hc : collapsed Ω.1
    · exact Or.inl hc
    · exact Or.inr ⟨hc, hΩ⟩
  have hcollapse :
      (univ.filter fun Ω : F × (F × (Fin n → F) × F) => collapsed Ω.1).card
        ≤ K * Fintype.card (F × (Fin n → F) × F) := by
    refine card_filter_prod_le_left
      (fun Ω : F × (F × (Fin n → F) × F) => collapsed Ω.1) fun _ => ?_
    simpa using hcollapsed_root
  have hlive :
      (univ.filter fun Ω : F × (F × (Fin n → F) × F) =>
          ¬ collapsed Ω.1 ∧
            acceptsScalar hn (A Ω.1) (L Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2).card
        ≤ Fintype.card F *
          ((Finset.sum (Finset.range n) d + (n + 2)) * Fintype.card F ^ (n + 1)) := by
    refine card_filter_prod_le_right
      (fun Ω : F × (F × (Fin n → F) × F) =>
        ¬ collapsed Ω.1 ∧
          acceptsScalar hn (A Ω.1) (L Ω.1) Ω.2.1 Ω.2.2.1 Ω.2.2.2) fun β => ?_
    by_cases hc : collapsed β
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le _)
      refine Finset.filter_eq_empty_iff.mpr fun Δrχ _ h => ?_
      exact h.1 hc
    · refine le_trans (Finset.card_le_card ?_)
        (blind_sumcheck_sound_scalar hn (A β) (L β) (TR β) (hfin β) hc)
      intro Δrχ hΔrχ
      simp only [mem_filter, mem_univ, true_and] at hΔrχ ⊢
      exact hΔrχ.2
  refine le_trans (Finset.card_le_card hsub)
    (le_trans (Finset.card_union_le _ _) (le_trans (Nat.add_le_add hcollapse hlive) ?_))
  rw [Fintype.card_prod, Fintype.card_prod, Fintype.card_fun, Fintype.card_fin]
  have hinner : Fintype.card F * (Fintype.card F ^ n * Fintype.card F)
      = Fintype.card F ^ (n + 2) := by
    rw [show n + 2 = (n + 1) + 1 from by omega, pow_succ, pow_succ]
    ring
  have hlive_pow : Fintype.card F *
      ((Finset.sum (Finset.range n) d + (n + 2)) * Fintype.card F ^ (n + 1))
      = (Finset.sum (Finset.range n) d + (n + 2)) * Fintype.card F ^ (n + 2) := by
    rw [pow_succ]
    ring
  rw [hinner, hlive_pow, add_mul]
  apply Nat.le_of_eq
  ring

/-- The concrete fixed-member linear construction instantiates the malicious
outer-strategy theorem. -/
theorem scalar_batch_blind_sumcheck_sound [Fintype F] [DecidableEq F] (hn : 0 < n)
    (B : FixedSumcheckBatch F n K d ι)
    (finalMsg : F → (Fin n → F) → (Fin (n + 1) → F) → F)
    (k₀ : Fin K) (hbad : (B.prover k₀).σ₀ ≠ (B.truth k₀).total) :
    (univ.filter fun Ω : F × (F × (Fin n → F) × F) =>
        acceptsScalarBatch hn B finalMsg Ω).card
      ≤ (K + (Finset.sum (Finset.range n) d + (n + 2)))
          * Fintype.card F ^ (n + 2) := by
  simpa [acceptsScalarBatch] using
    (outer_scalar_batch_blind_sumcheck_sound (F := F) (n := n) (K := K) (d := d)
      (ι := Fin K × ι) hn
      (fun k => (B.prover k).σ₀) (fun k => (B.truth k).total)
      (scalarBatchProver B finalMsg) (scalarBatchFunctional B) (scalarBatchTruth B)
      (fun _ => rfl) (fun _ => rfl) (scalarBatch_final_compatible B finalMsg) k₀ hbad)

end VoltaZk

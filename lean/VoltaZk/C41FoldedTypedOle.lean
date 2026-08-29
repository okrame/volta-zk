import VoltaZk.Mac
import VoltaZk.Counting
import Mathlib.Algebra.Polynomial.BigOperators

/-!
# C4.1 folded-query high-degree typed OLE kill test

This file proves the Packed16 two-query identity, the degree-twelve bound,
and the fixed-before-challenge scalar batching used by the real bridge.
-/

namespace VoltaZk

open Finset Polynomial

variable {F ι : Type*} [Field F] [Fintype ι]

/-- Public linear opening used by the C4 boundary folds. -/
def c41LinearOpen (r x : ι → F) : F :=
  ∑ i, r i * x i

/-- The Packed16 correction commutes with every public linear opening and
therefore needs only openings of `a` and `b`. -/
theorem packed16_folded_opening
    (B H : F) (r a b d e x : ι → F)
    (hx : ∀ i, x i = a i + d i - H - B * (e i + (1 - 2 * e i) * b i)) :
    c41LinearOpen r x =
      c41LinearOpen r a
        + c41LinearOpen r (fun i => d i - H - B * e i)
        - B * c41LinearOpen (fun i => r i * (1 - 2 * e i)) b := by
  unfold c41LinearOpen
  calc
    (∑ i, r i * x i) =
        ∑ i, (r i * a i + r i * (d i - H - B * e i)
          - B * ((r i * (1 - 2 * e i)) * b i)) := by
      apply Finset.sum_congr rfl
      intro i _
      rw [hx i]
      ring
    _ = (∑ i, r i * a i) + (∑ i, r i * (d i - H - B * e i))
          - B * ∑ i, (r i * (1 - 2 * e i)) * b i := by
      rw [Finset.sum_sub_distrib, Finset.sum_add_distrib, Finset.mul_sum]

/-- Public folding of polynomial-in-`Delta` authentications. -/
noncomputable def c41PolynomialOpen (r : ι → F) (p : ι → Polynomial F) : Polynomial F :=
  ∑ i, Polynomial.C (r i) * p i

/-- Arbitrary public linear openings preserve the typed authentication
degree. -/
theorem c41_polynomial_open_degree_le {n : ℕ} (r : ι → F) (p : ι → Polynomial F)
    (hp : ∀ i, (p i).natDegree ≤ n) :
    (c41PolynomialOpen r p).natDegree ≤ n := by
  unfold c41PolynomialOpen
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun i _ => ?_
  exact (Polynomial.natDegree_C_mul_le _ _).trans (hp i)

/-- All bridge discrepancies are fixed before the single batching challenge.
The Rust response codec fixes this finite list through its correction vector
before `C41ProverResponseState.finish` samples `β`. -/
structure C41FixedBridgeBatch (F : Type*) [Field F] (K : ℕ) where
  error : Fin K → F

/-- Scalar-power bridge accumulator used by Rust. -/
def c41BridgeError {K : ℕ} (B : C41FixedBridgeBatch F K) (β : F) : F :=
  ∑ k, β ^ (k.val + 1) * B.error k

/-- If any fixed bridge is false, the final scalar batch can collapse for at
most `K` values of the post-correction challenge. -/
theorem c41_bridge_batch_sound [Fintype F] [DecidableEq F] {K : ℕ}
    (B : C41FixedBridgeBatch F K) {k₀ : Fin K} (hbad : B.error k₀ ≠ 0) :
    (univ.filter fun β : F => c41BridgeError B β = 0).card ≤ K := by
  simpa [c41BridgeError] using card_scalarRlc_zero_le B.error hbad

/-- Scalar batching preserves the degree-twelve authentication bound. -/
noncomputable def c41BridgePolynomial {K : ℕ} (β : F) (p : Fin K → Polynomial F) :
    Polynomial F :=
  ∑ k, Polynomial.C (β ^ (k.val + 1)) * p k

theorem c41_bridge_polynomial_degree_le_twelve {K : ℕ} (β : F)
    (p : Fin K → Polynomial F) (hp : ∀ k, (p k).natDegree ≤ 12) :
    (c41BridgePolynomial β p).natDegree ≤ 12 := by
  unfold c41BridgePolynomial
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun k _ => ?_
  exact (Polynomial.natDegree_C_mul_le _ _).trans (hp k)

/-- Once batching survives, a nonzero degree-twelve relation has at most
twelve accepting session-key points. -/
theorem c41_degree_twelve_close_root_bound [Fintype F] [DecidableEq F]
    (relation : Polynomial F) (hne : relation ≠ 0) (hdegree : relation.natDegree ≤ 12) :
    (univ.filter fun Δ : F => relation.eval Δ = 0).card ≤ 12 :=
  (card_eval_zero_le hne).trans hdegree

/-- Adding a public affine term cannot raise a degree-11 typed claim. -/
theorem c41_typed_affine_degree_le
    (typed affineTerm : Polynomial F)
    (htyped : typed.natDegree ≤ 11) (haffine : affineTerm.natDegree ≤ 0) :
    (typed + affineTerm).natDegree ≤ 11 :=
  (Polynomial.natDegree_add_le _ _).trans
    (max_le htyped (haffine.trans (Nat.zero_le 11)))

/-- The sole nonlinear eligible edge is typed degree 11 times ordinary
degree 1. -/
theorem c41_typed_ordinary_product_degree_le
    (typed ordinary : Polynomial F)
    (htyped : typed.natDegree ≤ 11) (hordinary : ordinary.natDegree ≤ 1) :
    (typed * ordinary).natDegree ≤ 12 :=
  Polynomial.natDegree_mul_le.trans (Nat.add_le_add htyped hordinary)

/-- Frozen source-audit classes for the post-T1 Packed16 census. -/
inductive C41EligibleConsumer
  | groupExit
  | groupEntry
  | cacheKey
  | cacheValue

/-- Group seams are affine; K/V close against one ordinary GEMM leg. -/
def C41EligibleConsumer.partnerDegree : C41EligibleConsumer → ℕ
  | .groupExit | .groupEntry => 0
  | .cacheKey | .cacheValue => 1

theorem c41_eligible_consumer_degree_le_twelve (consumer : C41EligibleConsumer) :
    11 + consumer.partnerDegree ≤ 12 := by
  cases consumer <;> decide

/-- A typed-by-typed edge would violate the registered degree-12 close. -/
theorem c41_typed_typed_rejected : ¬11 + 11 ≤ 12 := by
  decide

#print axioms VoltaZk.packed16_folded_opening
#print axioms VoltaZk.c41_polynomial_open_degree_le
#print axioms VoltaZk.c41_bridge_batch_sound
#print axioms VoltaZk.c41_bridge_polynomial_degree_le_twelve
#print axioms VoltaZk.c41_degree_twelve_close_root_bound
#print axioms VoltaZk.c41_typed_ordinary_product_degree_le
#print axioms VoltaZk.c41_eligible_consumer_degree_le_twelve
#print axioms VoltaZk.c41_typed_typed_rejected

end VoltaZk

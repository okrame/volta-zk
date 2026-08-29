import VoltaZk.Mac
import Mathlib.Algebra.Polynomial.BigOperators

/-!
# C4.1 folded-query high-degree typed OLE kill test

This file proves only the two facts that can reject FQ-HD-tOLE before an
implementation exists: Packed16 openings need two typed linear queries, and
the frozen C4 consumer census never needs degree above twelve.
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
#print axioms VoltaZk.c41_typed_ordinary_product_degree_le
#print axioms VoltaZk.c41_eligible_consumer_degree_le_twelve
#print axioms VoltaZk.c41_typed_typed_rejected

end VoltaZk

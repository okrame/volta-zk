import VoltaZk.ZeroBatchSound
import Mathlib.Tactic.LinearCombination

/-!
# Soundness of the batched QuickSilver product check (M8)

Dual game to `VoltaZk/Prod.lean` (M7, perfect ZK of the masked messages):
corrupt prover `P*`, honest verifier. Same value-level modeling as M3a/M4
(`VoltaZk/ZeroBatchSound.lean`): the adversary directly chooses plaintext/tag
pairs, keys are determined by `keyOf`, its view is independent of `Δ`, and
soundness is a cardinality bound over the verifier randomness `(Δ, χ)`.

The check. Each product claim is three adversary pairs `(a, b, c)` asserting
`c = a·b`. The verifier's key-side term expands as a polynomial in `Δ`
(`prodKey_expand`):

  `k_a·k_b − Δ·k_c = A₀ + A₁·Δ + (x_a·x_b − x_c)·Δ²`

— the `Δ²` coefficient *is* the falsity of the claim. `T` claims are batched
by `χ` and masked by one fresh correlation `r`; the prover sends `(M₀, M₁)`
(a function of the public `χ`, never of `Δ`) and the verifier accepts iff
`M₀ + M₁·Δ = ∑ χⱼ·(k_aⱼ·k_bⱼ − Δ·k_cⱼ) + k_r`. This is the opening that in
the protocol schedule closes the multiplicative claims alongside the
`Π_ZeroBatch` opening `m_Z`; higher fan-in products reduce to chained
degree-2 checks.

Soundness (`prodBatch_sound`): if some claim is false, then either `χ`
collapses the `Δ²`-coefficient linear form — at most `|F|^(T−1)` challenges,
`card_linearForm_zero_le` — or the acceptance equation is a nonzero quadratic
in `Δ` — at most two roots, `card_quadratic_solution_le_two`. Total: at most
`3·|F|^T` of the `|F|^(T+1)` verifier tapes, soundness error `≤ 3/|F|`
(`= (d+1)/|F|` for the degree-2 check). This discharges the former
`QuickSilverProdSound` assumption; with M7 the product check is now fully
proved (ZK + soundness).
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- **Quadratic forgery count.** A quadratic equation in `Δ` with nonzero
leading coefficient has at most two solutions: accepting a false product
claim requires the session key to hit a root of a nonzero degree-2
polynomial. -/
theorem card_quadratic_solution_le_two (c0 c1 c2 : F) (h2 : c2 ≠ 0) :
    (univ.filter fun Δ : F => c0 + c1 * Δ + c2 * (Δ * Δ) = 0).card ≤ 2 := by
  have hdeg : (C c2 * X ^ 2 + C c1 * X + C c0 : Polynomial F).natDegree = 2 :=
    Polynomial.natDegree_quadratic h2
  have hne : (C c2 * X ^ 2 + C c1 * X + C c0 : Polynomial F) ≠ 0 := by
    intro h
    rw [h] at hdeg
    simp at hdeg
  refine le_trans (le_of_eq (congrArg Finset.card (Finset.filter_congr fun Δ _ => ?_)))
    (le_trans (card_eval_zero_le hne) hdeg.le)
  simp only [Polynomial.eval_add, Polynomial.eval_mul, Polynomial.eval_pow,
    Polynomial.eval_C, Polynomial.eval_X]
  constructor <;> intro h <;> linear_combination h

/-- One product claim as committed through the corrupted-P branch of
`F_sVOLE`: three plaintext/tag pairs asserting `c = a·b`, with verifier keys
determined by `keyOf` (cf. `authedOfPair`). -/
structure ProdClaim (F : Type*) where
  /-- left factor, adversary pair -/
  a : F × F
  /-- right factor, adversary pair -/
  b : F × F
  /-- claimed product, adversary pair -/
  c : F × F

/-- The verifier's key-side term of one product check. -/
def prodKey (Δ : F) (p : ProdClaim F) : F :=
  keyOf Δ p.a * keyOf Δ p.b - Δ * keyOf Δ p.c

/-- Constant coefficient of the check polynomial (prover-known). -/
def prodA0 (p : ProdClaim F) : F := p.a.2 * p.b.2

/-- Linear coefficient of the check polynomial (prover-known). -/
def prodA1 (p : ProdClaim F) : F := p.a.1 * p.b.2 + p.b.1 * p.a.2 - p.c.2

/-- Quadratic coefficient of the check polynomial: the *falsity* of the
claim. Zero exactly when `c = a·b` on the plaintexts. -/
def prodQ (p : ProdClaim F) : F := p.a.1 * p.b.1 - p.c.1

omit [Fintype F] [DecidableEq F] in
/-- Key-side expansion of one product check as a polynomial in `Δ`. -/
theorem prodKey_expand (Δ : F) (p : ProdClaim F) :
    prodKey Δ p = prodA0 p + prodA1 p * Δ + prodQ p * (Δ * Δ) := by
  unfold prodKey prodA0 prodA1 prodQ keyOf
  ring

omit [Fintype F] [DecidableEq F] in
/-- Batched key-side expansion: the `χ`-combination of `T` product checks
plus the mask key is a polynomial in `Δ` whose quadratic coefficient is the
`χ`-combination of the claim falsities. -/
theorem prodKey_rlc_expand {T : ℕ} (z : Fin T → ProdClaim F) (r : F × F)
    (Δ : F) (χ : Fin T → F) :
    ∑ j, χ j * prodKey Δ (z j) + keyOf Δ r
      = ((∑ j, χ j * prodA0 (z j)) + r.2)
        + ((∑ j, χ j * prodA1 (z j)) + r.1) * Δ
        + (∑ j, χ j * prodQ (z j)) * (Δ * Δ) := by
  have h : ∀ j, χ j * prodKey Δ (z j)
      = χ j * prodA0 (z j) + χ j * prodA1 (z j) * Δ + χ j * prodQ (z j) * (Δ * Δ) := by
    intro j
    rw [prodKey_expand]
    ring
  rw [Finset.sum_congr rfl fun j _ => h j, Finset.sum_add_distrib, Finset.sum_add_distrib,
    ← Finset.sum_mul, ← Finset.sum_mul]
  unfold keyOf
  ring

/-- **Batched QuickSilver product-check soundness (M8).** If some claim in
the batched list is false (`c ≠ a·b` on the plaintexts), then for every
adversary message strategy `msg` (a function of the public `χ`, never of
`Δ`) and every mask pair `r`, the masked degree-2 opening verifies for at
most `3·|F|^T` of the `|F|^(T+1)` verifier random tapes `(Δ, χ)` — soundness
error `≤ 3/|F|`. -/
theorem prodBatch_sound {T : ℕ} (z : Fin T → ProdClaim F) {j₀ : Fin T}
    (hz : (z j₀).c.1 ≠ (z j₀).a.1 * (z j₀).b.1) (r : F × F)
    (msg : (Fin T → F) → F × F) :
    (univ.filter fun Δχ : F × (Fin T → F) =>
        (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
          = ∑ j, Δχ.2 j * prodKey Δχ.1 (z j) + keyOf Δχ.1 r).card
      ≤ 3 * Fintype.card F ^ T := by
  have hT : 0 < T := j₀.pos
  have hq0 : prodQ (z j₀) ≠ 0 := sub_ne_zero.mpr (Ne.symm hz)
  -- Split on whether the batching challenge collapsed the falsity RLC.
  have hsub : (univ.filter fun Δχ : F × (Fin T → F) =>
        (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
          = ∑ j, Δχ.2 j * prodKey Δχ.1 (z j) + keyOf Δχ.1 r)
      ⊆ (univ.filter fun Δχ : F × (Fin T → F) => ∑ j, Δχ.2 j * prodQ (z j) = 0)
        ∪ (univ.filter fun Δχ : F × (Fin T → F) =>
            (∑ j, Δχ.2 j * prodQ (z j) ≠ 0)
              ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
                  = ∑ j, Δχ.2 j * prodKey Δχ.1 (z j) + keyOf Δχ.1 r) := by
    intro Δχ h
    simp only [mem_filter, mem_univ, true_and, mem_union] at h ⊢
    by_cases hxz : ∑ j, Δχ.2 j * prodQ (z j) = 0
    · exact Or.inl hxz
    · exact Or.inr ⟨hxz, h⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  -- Collapse branch: for every Δ, at most |F|^(T-1) challenges kill the RLC.
  have h1 : (univ.filter fun Δχ : F × (Fin T → F) =>
        ∑ j, Δχ.2 j * prodQ (z j) = 0).card
      ≤ Fintype.card F * Fintype.card F ^ (T - 1) :=
    card_filter_prod_le_right (fun Δχ : F × (Fin T → F) => ∑ j, Δχ.2 j * prodQ (z j) = 0)
      fun _ => card_linearForm_zero_le (fun j => prodQ (z j)) hq0
  -- Quadratic branch: for every χ with live falsity, at most two Δ accept.
  have h2 : (univ.filter fun Δχ : F × (Fin T → F) =>
        (∑ j, Δχ.2 j * prodQ (z j) ≠ 0)
          ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
              = ∑ j, Δχ.2 j * prodKey Δχ.1 (z j) + keyOf Δχ.1 r).card
      ≤ 2 * Fintype.card F ^ T := by
    rw [show (2 : ℕ) * Fintype.card F ^ T = 2 * Fintype.card (Fin T → F) by
      rw [Fintype.card_fun, Fintype.card_fin]]
    refine card_filter_prod_le_left
      (fun Δχ : F × (Fin T → F) => (∑ j, Δχ.2 j * prodQ (z j) ≠ 0)
        ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
            = ∑ j, Δχ.2 j * prodKey Δχ.1 (z j) + keyOf Δχ.1 r) fun χ => ?_
    by_cases hxz : ∑ j, χ j * prodQ (z j) = 0
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le 2)
      exact Finset.filter_eq_empty_iff.mpr fun Δ _ h => h.1 hxz
    · refine le_trans (Finset.card_le_card fun Δ hΔ => ?_)
        (card_quadratic_solution_le_two
          ((∑ j, χ j * prodA0 (z j)) + r.2 - (msg χ).1)
          ((∑ j, χ j * prodA1 (z j)) + r.1 - (msg χ).2)
          (∑ j, χ j * prodQ (z j)) hxz)
      simp only [mem_filter, mem_univ, true_and] at hΔ ⊢
      have hacc := hΔ.2
      rw [prodKey_rlc_expand] at hacc
      linear_combination -hacc
  calc _ ≤ Fintype.card F * Fintype.card F ^ (T - 1) + 2 * Fintype.card F ^ T :=
        Nat.add_le_add h1 h2
    _ = 3 * Fintype.card F ^ T := by
        rw [← pow_succ', Nat.sub_add_cancel hT]
        ring

/-- **Scalar-power batched product soundness (implementation theorem).**
For the Rust weighting `χ^(j+1)`, a false list of length `T` accepts on at
most `(T+2)·|F|` of the `|F|²` verifier tapes `(Δ, χ)`: the falsity
polynomial collapses for at most `T` challenges, while a live quadratic has
at most two roots in the MAC key. -/
theorem prodBatch_sound_scalar {T : ℕ} (z : Fin T → ProdClaim F) {j₀ : Fin T}
    (hz : (z j₀).c.1 ≠ (z j₀).a.1 * (z j₀).b.1) (r : F × F)
    (msg : F → F × F) :
    (univ.filter fun Δχ : F × F =>
        (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
          = ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r).card
      ≤ (T + 2) * Fintype.card F := by
  have hq0 : prodQ (z j₀) ≠ 0 := sub_ne_zero.mpr (Ne.symm hz)
  have hsub : (univ.filter fun Δχ : F × F =>
        (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
          = ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r)
      ⊆ (univ.filter fun Δχ : F × F =>
            ∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) = 0)
        ∪ (univ.filter fun Δχ : F × F =>
            (∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) ≠ 0)
              ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
                  = ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r) := by
    intro Δχ h
    simp only [mem_filter, mem_univ, true_and, mem_union] at h ⊢
    by_cases hxz : ∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) = 0
    · exact Or.inl hxz
    · exact Or.inr ⟨hxz, h⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  have h1 : (univ.filter fun Δχ : F × F =>
        ∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) = 0).card
      ≤ Fintype.card F * T :=
    card_filter_prod_le_right
      (fun Δχ : F × F => ∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) = 0)
      fun _ => card_scalarRlc_zero_le (fun j => prodQ (z j)) hq0
  have h2 : (univ.filter fun Δχ : F × F =>
        (∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) ≠ 0)
          ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
              = ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r).card
      ≤ 2 * Fintype.card F := by
    refine card_filter_prod_le_left
      (fun Δχ : F × F =>
        (∑ j, Δχ.2 ^ (j.val + 1) * prodQ (z j) ≠ 0)
          ∧ (msg Δχ.2).1 + (msg Δχ.2).2 * Δχ.1
              = ∑ j, Δχ.2 ^ (j.val + 1) * prodKey Δχ.1 (z j) + keyOf Δχ.1 r) fun χ => ?_
    by_cases hxz : ∑ j, χ ^ (j.val + 1) * prodQ (z j) = 0
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le 2)
      exact Finset.filter_eq_empty_iff.mpr fun Δ _ h => h.1 hxz
    · refine le_trans (Finset.card_le_card fun Δ hΔ => ?_)
        (card_quadratic_solution_le_two
          ((∑ j, χ ^ (j.val + 1) * prodA0 (z j)) + r.2 - (msg χ).1)
          ((∑ j, χ ^ (j.val + 1) * prodA1 (z j)) + r.1 - (msg χ).2)
          (∑ j, χ ^ (j.val + 1) * prodQ (z j)) hxz)
      simp only [mem_filter, mem_univ, true_and] at hΔ ⊢
      have hacc := hΔ.2
      rw [prodKey_rlc_expand z r Δ (fun j => χ ^ (j.val + 1))] at hacc
      linear_combination -hacc
  calc
    _ ≤ Fintype.card F * T + 2 * Fintype.card F := Nat.add_le_add h1 h2
    _ = (T + 2) * Fintype.card F := by ring

end VoltaZk

import Mathlib.Algebra.Polynomial.Roots
import Mathlib.Data.Fintype.Pi
import Mathlib.Logic.Equiv.Prod

/-!
# Counting infrastructure for soundness bounds

The soundness milestones (M3, M4) are stated in *counting form*: the malicious
prover is a deterministic strategy (WLOG), so the only randomness in the game
is the honest verifier's — the session key `Δ`, the round challenges `r`, and
the batching challenge `χ` — and every "soundness error ≤ ε" statement becomes
a cardinality bound `#bad ≤ ε·|Ω|` over the finite product space `Ω` of
verifier randomness. This mirrors the counting formulation of the
Schwartz–Zippel lemma in Mathlib (`MvPolynomial.schwartz_zippel_sum_degreeOf`)
and avoids `ℝ≥0∞` plumbing in the probabilistic inductions.

This file provides the generic ingredients:

* `card_eval_zero_le` — a nonzero univariate polynomial has at most
  `natDegree` roots (Schwartz–Zippel, one-dimensional);
* `card_linear_solution_le_one` — a nontrivial linear equation in one unknown
  has at most one solution (the MAC-forgery count);
* `card_filter_prod_le_left` / `card_filter_prod_le_right` — slice-counting
  over product spaces (union of fibers);
* `card_filter_equiv` — transport of a filter count along an equivalence;
* `card_linearForm_zero_le` — a nonzero linear form vanishes on at most a
  `1/|F|` fraction of uniform vectors (RLC soundness count);
* `card_pi_root_slice` — for a per-prefix polynomial family independent of
  coordinate `i`, the event "coordinate `i` hits a root" has density `≤ d/|F|`
  (the per-round sumcheck count).
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- **One-dimensional Schwartz–Zippel.** A nonzero univariate polynomial of
degree `≤ d` has at most `d` roots in `F`. -/
theorem card_eval_zero_le {q : Polynomial F} (hq : q ≠ 0) :
    (univ.filter fun x : F => q.eval x = 0).card ≤ q.natDegree := by
  refine le_trans (Finset.card_le_card fun x hx => ?_)
    ((Multiset.toFinset_card_le _).trans q.card_roots')
  simp only [mem_filter, mem_univ, true_and] at hx
  rw [Multiset.mem_toFinset, Polynomial.mem_roots']
  exact ⟨hq, hx⟩

/-- **Forgery count.** A linear equation `b = a + Δ·x` with `x ≠ 0` has at
most one solution `Δ`: opening a nonzero authenticated claim requires guessing
the session key. -/
theorem card_linear_solution_le_one (a b x : F) (hx : x ≠ 0) :
    (univ.filter fun Δ : F => b = a + Δ * x).card ≤ 1 := by
  refine Finset.card_le_one.mpr fun Δ h Δ' h' => ?_
  simp only [mem_filter, mem_univ, true_and] at h h'
  exact mul_right_cancel₀ hx (add_left_cancel (h.symm.trans h'))

/-- Slice counting, first component: if for every `b` at most `d` values of
`a` satisfy `p (a, b)`, then at most `d·|B|` pairs satisfy `p`. -/
theorem card_filter_prod_le_left {A B : Type*} [Fintype A] [Fintype B]
    (p : A × B → Prop) [DecidablePred p] {d : ℕ}
    (h : ∀ b : B, (univ.filter fun a : A => p (a, b)).card ≤ d) :
    (univ.filter p).card ≤ d * Fintype.card B := by
  classical
  rw [Finset.card_eq_sum_card_fiberwise (f := Prod.snd) (t := univ) fun _ _ => mem_univ _]
  calc ∑ b ∈ univ, ((univ.filter p).filter fun ab => ab.2 = b).card
      ≤ ∑ b ∈ univ, d := by
        refine Finset.sum_le_sum fun b _ => ?_
        have hsub : ((univ.filter p).filter fun ab => ab.2 = b)
            ⊆ (univ.filter fun a : A => p (a, b)).image fun a => (a, b) := by
          intro ab hab
          simp only [mem_filter, mem_univ, true_and] at hab
          obtain ⟨hp, hb⟩ := hab
          have hab' : (ab.1, b) = ab := Prod.ext rfl hb.symm
          simp only [mem_image, mem_filter, mem_univ, true_and]
          exact ⟨ab.1, by rw [hab']; exact hp, hab'⟩
        exact le_trans (Finset.card_le_card hsub) (le_trans Finset.card_image_le (h b))
    _ = d * Fintype.card B := by rw [Finset.sum_const, card_univ, smul_eq_mul, mul_comm]

/-- Slice counting, second component: if for every `a` at most `d` values of
`b` satisfy `p (a, b)`, then at most `|A|·d` pairs satisfy `p`. -/
theorem card_filter_prod_le_right {A B : Type*} [Fintype A] [Fintype B]
    (p : A × B → Prop) [DecidablePred p] {d : ℕ}
    (h : ∀ a : A, (univ.filter fun b : B => p (a, b)).card ≤ d) :
    (univ.filter p).card ≤ Fintype.card A * d := by
  classical
  rw [Finset.card_eq_sum_card_fiberwise (f := Prod.fst) (t := univ) fun _ _ => mem_univ _]
  calc ∑ a ∈ univ, ((univ.filter p).filter fun ab => ab.1 = a).card
      ≤ ∑ a ∈ univ, d := by
        refine Finset.sum_le_sum fun a _ => ?_
        have hsub : ((univ.filter p).filter fun ab => ab.1 = a)
            ⊆ (univ.filter fun b : B => p (a, b)).image fun b => (a, b) := by
          intro ab hab
          simp only [mem_filter, mem_univ, true_and] at hab
          obtain ⟨hp, ha⟩ := hab
          have hab' : (a, ab.2) = ab := Prod.ext ha.symm rfl
          simp only [mem_image, mem_filter, mem_univ, true_and]
          exact ⟨ab.2, by rw [hab']; exact hp, hab'⟩
        exact le_trans (Finset.card_le_card hsub) (le_trans Finset.card_image_le (h a))
    _ = Fintype.card A * d := by rw [Finset.sum_const, card_univ, smul_eq_mul]

/-- Transport of a filter count along an equivalence. -/
theorem card_filter_equiv {α β : Type*} [Fintype α] [Fintype β] (e : α ≃ β) (p : α → Prop)
    [DecidablePred p] :
    (univ.filter fun b : β => p (e.symm b)).card = (univ.filter p).card := by
  refine Finset.card_bij (fun b _ => e.symm b) (fun b hb => ?_) (fun b hb b' hb' hbb' => ?_)
    fun a ha => ⟨e a, ?_, by simp⟩
  · simp only [mem_filter, mem_univ, true_and] at hb ⊢
    exact hb
  · exact e.symm.injective hbb'
  · simp only [mem_filter, mem_univ, true_and, Equiv.symm_apply_apply] at ha ⊢
    exact ha

/-- The subtype of coordinates different from a fixed one has one fewer
element. -/
theorem card_ne_index {ι : Type*} [Fintype ι] [DecidableEq ι] (i : ι) :
    Fintype.card {j : ι // j ≠ i} = Fintype.card ι - 1 := by
  rw [Fintype.card_subtype, Finset.filter_ne' univ i,
    Finset.card_erase_of_mem (mem_univ i), card_univ]

/-- **RLC soundness count.** A linear form with a nonzero coefficient vanishes
on at most `|F|^(T-1)` of the `|F|^T` challenge vectors: batching a list
containing a nonzero claim yields a nonzero combined claim except with
probability `1/|F|` over the batching challenge. -/
theorem card_linearForm_zero_le {T : ℕ} (z : Fin T → F) {j₀ : Fin T} (hz : z j₀ ≠ 0) :
    (univ.filter fun χ : Fin T → F => ∑ j, χ j * z j = 0).card
      ≤ Fintype.card F ^ (T - 1) := by
  rw [← card_filter_equiv (Equiv.funSplitAt j₀ F)]
  have hle := card_filter_prod_le_left
    (fun xw : F × ({j : Fin T // j ≠ j₀} → F) =>
      ∑ j, (Equiv.funSplitAt j₀ F).symm xw j * z j = 0)
    (d := 1) fun w => ?_
  · calc _ ≤ 1 * Fintype.card ({j : Fin T // j ≠ j₀} → F) := hle
      _ = Fintype.card F ^ (T - 1) := by
        rw [one_mul, Fintype.card_fun, card_ne_index, Fintype.card_fin]
  · refine Finset.card_le_one.mpr fun x hx x' hx' => ?_
    simp only [mem_filter, mem_univ, true_and] at hx hx'
    have hdiff : (x - x') * z j₀ = 0 := by
      have hsingle : ∑ j, ((Equiv.funSplitAt j₀ F).symm (x, w) j
          - (Equiv.funSplitAt j₀ F).symm (x', w) j) * z j = (x - x') * z j₀ := by
        rw [Finset.sum_eq_single j₀ (fun j _ hj => by simp [hj])
          fun h => absurd (mem_univ _) h]
        simp
      calc (x - x') * z j₀
          = ∑ j, ((Equiv.funSplitAt j₀ F).symm (x, w) j * z j
              - (Equiv.funSplitAt j₀ F).symm (x', w) j * z j) := by
            rw [← hsingle]
            exact Finset.sum_congr rfl fun j _ => sub_mul _ _ _
          _ = 0 := by rw [Finset.sum_sub_distrib, hx, hx', sub_self]
    rcases mul_eq_zero.mp hdiff with h | h
    · exact sub_eq_zero.mp h
    · exact absurd h hz

/-- **Per-round sumcheck count.** If `q r` is a polynomial family of degree
`≤ d` that does not depend on coordinate `i` of `r`, then the event
"`q r ≠ 0` and coordinate `i` of `r` is a root of `q r`" has at most
`d·|F|^(n-1)` elements: the verifier's fresh challenge hits a coincidence of
two distinct low-degree polynomials with probability `≤ d/|F|`. -/
theorem card_pi_root_slice {n : ℕ} (i : Fin n) (q : (Fin n → F) → Polynomial F) {d : ℕ}
    (hdeg : ∀ r, (q r).natDegree ≤ d)
    (hupd : ∀ r x, q (Function.update r i x) = q r) :
    (univ.filter fun r : Fin n → F => q r ≠ 0 ∧ (q r).eval (r i) = 0).card
      ≤ d * Fintype.card F ^ (n - 1) := by
  rw [← card_filter_equiv (Equiv.funSplitAt i F)]
  have key : ∀ (x : F) (w : {j : Fin n // j ≠ i} → F),
      q ((Equiv.funSplitAt i F).symm (x, w)) = q ((Equiv.funSplitAt i F).symm (0, w)) := by
    intro x w
    have hupdeq : (Equiv.funSplitAt i F).symm (x, w)
        = Function.update ((Equiv.funSplitAt i F).symm (0, w)) i x := by
      funext j
      by_cases hj : j = i
      · subst hj; simp [Equiv.funSplitAt_symm_apply]
      · simp [Equiv.funSplitAt_symm_apply, hj]
    rw [hupdeq, hupd]
  have hle := card_filter_prod_le_left
    (fun xw : F × ({j : Fin n // j ≠ i} → F) =>
      q ((Equiv.funSplitAt i F).symm xw) ≠ 0
        ∧ (q ((Equiv.funSplitAt i F).symm xw)).eval ((Equiv.funSplitAt i F).symm xw i) = 0)
    (d := d) fun w => ?_
  · calc _ ≤ d * Fintype.card ({j : Fin n // j ≠ i} → F) := hle
      _ = d * Fintype.card F ^ (n - 1) := by
        rw [Fintype.card_fun, card_ne_index, Fintype.card_fin]
  · by_cases hq : q ((Equiv.funSplitAt i F).symm (0, w)) = 0
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le d)
      refine Finset.filter_eq_empty_iff.mpr fun x _ => ?_
      rw [key x w]
      exact fun h => h.1 hq
    · refine le_trans (Finset.card_le_card fun x hx => ?_)
        (le_trans (card_eval_zero_le hq) (hdeg _))
      simp only [mem_filter, mem_univ, true_and] at hx ⊢
      obtain ⟨-, hx2⟩ := hx
      rw [key x w] at hx2
      simpa [Equiv.funSplitAt_symm_apply] using hx2

end VoltaZk

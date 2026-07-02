import VoltaZk.Counting

/-!
# Abstract soundness core of the clear sumcheck (M3b, probabilistic layer)

The classical sumcheck induction, stated against an *abstract* family of true
round polynomials, so that the probabilistic argument is independent of how
the summed function is represented (the `MvPolynomial` instantiation is in
`VoltaZk/SumcheckMv.lean`).

Model. A window has `n` rounds with public per-round degree bounds `d i`.
Challenges are a vector `r : Fin n → F`; adaptivity of the (deterministic)
malicious prover is captured *structurally*: every prover object at round `i`
is a function of the truncation `trunc r i`, which erases all coordinates
`≥ i` — so it cannot depend on the current or future challenges.

* `TrueRounds` packages the honest partial-sum polynomials `g i`, the true
  total `total`, and the final evaluation functional `finalEval`, with their
  defining consistency equations and degree bounds.
* `clearAccepts` is the clear-transcript verifier: round-0 check
  `p₀(0)+p₀(1) = σ₀`, chaining checks, and the final evaluation check.
* `exists_deviation` — if the transcript passes all checks but the claimed
  total is wrong, some round has `p_i ≠ g_i` *and* the fresh challenge landed
  on a coincidence `p_i(r_i) = g_i(r_i)` (a root of the nonzero difference).
* `card_deviation_le` — the union of those per-round coincidence events has
  density at most `(∑ d_i)/|F|` (one-dimensional Schwartz–Zippel per round).
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F]

/-- Truncation of a challenge vector below index `i`: coordinates `≥ i` are
erased. Feeding prover/true-round functions only truncated vectors is what
makes "depends only on the prefix" structural. -/
def trunc {n : ℕ} (r : Fin n → F) (i : ℕ) : Fin n → F :=
  fun j => if (j : ℕ) < i then r j else 0

theorem trunc_update {n : ℕ} (r : Fin n → F) (i : Fin n) (x : F) :
    trunc (Function.update r i x) i = trunc r i := by
  funext j
  unfold trunc
  by_cases hj : (j : ℕ) < (i : ℕ)
  · rw [if_pos hj, if_pos hj, Function.update_of_ne (Fin.ne_of_val_ne (Nat.ne_of_lt hj))]
  · rw [if_neg hj, if_neg hj]

/-- The honest ("true") side of a sumcheck window: the partial-sum round
polynomials `g i` (as functions of the challenge prefix), the true total, and
the final evaluation functional, together with their defining equations.

`g i` is only ever applied to `trunc r i`; the consistency fields quantify
over full vectors `r` and mention only truncated inputs, which is exactly the
shape the `MvPolynomial` partial sums satisfy. -/
structure TrueRounds (F : Type*) [Field F] (n : ℕ) (d : ℕ → ℕ) where
  /-- true round polynomial at round `i`, given the (truncated) challenge prefix -/
  g : ℕ → (Fin n → F) → Polynomial F
  /-- the true value of the sum being claimed -/
  total : F
  /-- the true evaluation functional checked at the end of the window
  (an authenticated MLE opening in the blind protocol) -/
  finalEval : (Fin n → F) → F
  /-- public degree bounds (enforced structurally by the message schedule) -/
  deg_le : ∀ i r, (g i r).natDegree ≤ d i
  /-- round 0: the true round polynomial sums to the true total -/
  first : ∀ r : Fin n → F, (g 0 (trunc r 0)).eval 0 + (g 0 (trunc r 0)).eval 1 = total
  /-- chaining: the round-`i+1` polynomial sums to the round-`i` polynomial
  evaluated at the fresh challenge -/
  step : ∀ (r : Fin n → F) (i : ℕ) (h : i + 1 < n),
    (g (i + 1) (trunc r (i + 1))).eval 0 + (g (i + 1) (trunc r (i + 1))).eval 1
      = (g i (trunc r i)).eval (r ⟨i, Nat.lt_of_succ_lt h⟩)
  /-- the last round polynomial evaluates to the final functional -/
  final : ∀ (r : Fin n → F) (h : 0 < n),
    (g (n - 1) (trunc r (n - 1))).eval (r ⟨n - 1, Nat.sub_lt h Nat.one_pos⟩) = finalEval r

/-- Clear-transcript verifier checks for an adversarial round-polynomial
schedule `p` (each `p i` reads only the truncated prefix), a claimed total
`σ₀`, and a final evaluation functional `fin`. -/
def clearAccepts {n : ℕ} (hn : 0 < n) (p : ℕ → (Fin n → F) → Polynomial F) (σ₀ : F)
    (fin : (Fin n → F) → F) (r : Fin n → F) : Prop :=
  ((p 0 (trunc r 0)).eval 0 + (p 0 (trunc r 0)).eval 1 = σ₀)
  ∧ (∀ i : Fin (n - 1),
      (p ((i : ℕ) + 1) (trunc r ((i : ℕ) + 1))).eval 0
          + (p ((i : ℕ) + 1) (trunc r ((i : ℕ) + 1))).eval 1
        = (p (i : ℕ) (trunc r (i : ℕ))).eval (r ⟨(i : ℕ), by omega⟩))
  ∧ (p (n - 1) (trunc r (n - 1))).eval (r ⟨n - 1, by omega⟩) = fin r

instance clearAccepts.instDecidablePred {n : ℕ} [DecidableEq F] (hn : 0 < n)
    (p : ℕ → (Fin n → F) → Polynomial F) (σ₀ : F) (fin : (Fin n → F) → F) :
    DecidablePred (clearAccepts hn p σ₀ fin) := fun r => by
  unfold clearAccepts; infer_instance

/-- **Deviation round.** If the clear transcript passes all checks but the
claimed total is wrong, there is a round where the adversarial polynomial
differs from the true one *and* the fresh challenge hit a point where they
agree. Deterministic chain argument: a deviation at round `i` whose
evaluations differ propagates to a deviation at round `i+1`; agreement at the
last round contradicts the final check. -/
theorem exists_deviation {n : ℕ} (hn : 0 < n) {d : ℕ → ℕ}
    (p : ℕ → (Fin n → F) → Polynomial F) (TR : TrueRounds F n d) {σ₀ : F} {r : Fin n → F}
    (hacc : clearAccepts hn p σ₀ TR.finalEval r) (hσ : σ₀ ≠ TR.total) :
    ∃ i : Fin n, p (i : ℕ) (trunc r (i : ℕ)) ≠ TR.g (i : ℕ) (trunc r (i : ℕ))
      ∧ (p (i : ℕ) (trunc r (i : ℕ))).eval (r i)
          = (TR.g (i : ℕ) (trunc r (i : ℕ))).eval (r i) := by
  by_contra hno
  push Not at hno
  have aux : ∀ (i : ℕ) (h : i < n), p i (trunc r i) ≠ TR.g i (trunc r i)
      ∧ (p i (trunc r i)).eval (r ⟨i, h⟩) ≠ (TR.g i (trunc r i)).eval (r ⟨i, h⟩) := by
    intro i
    induction i with
    | zero =>
      intro h
      have hne : p 0 (trunc r 0) ≠ TR.g 0 (trunc r 0) := by
        intro heq
        apply hσ
        rw [← hacc.1, heq]
        exact TR.first r
      exact ⟨hne, hno ⟨0, h⟩ hne⟩
    | succ i ih =>
      intro h
      have hprev := ih (Nat.lt_of_succ_lt h)
      have hne : p (i + 1) (trunc r (i + 1)) ≠ TR.g (i + 1) (trunc r (i + 1)) := by
        intro heq
        apply hprev.2
        have hstep := hacc.2.1 ⟨i, by omega⟩
        rw [← hstep, heq]
        exact TR.step r i h
      exact ⟨hne, hno ⟨i + 1, h⟩ hne⟩
  have hlast := aux (n - 1) (by omega)
  apply hlast.2
  rw [hacc.2.2]
  exact (TR.final r hn).symm

/-- **Per-round Schwartz–Zippel union bound.** The deviation event — some
round where the two prefix-determined polynomials differ yet agree at the
fresh challenge — has at most `(∑ d_i)·|F|^(n-1)` of the `|F|^n` challenge
vectors. -/
theorem card_deviation_le {F : Type*} [Field F] [Fintype F] [DecidableEq F] {n : ℕ}
    (p g : ℕ → (Fin n → F) → Polynomial F) {d : ℕ → ℕ}
    (hp : ∀ i r, (p i r).natDegree ≤ d i) (hg : ∀ i r, (g i r).natDegree ≤ d i) :
    (univ.filter fun r : Fin n → F => ∃ i : Fin n,
        p (i : ℕ) (trunc r (i : ℕ)) ≠ g (i : ℕ) (trunc r (i : ℕ))
          ∧ (p (i : ℕ) (trunc r (i : ℕ))).eval (r i)
              = (g (i : ℕ) (trunc r (i : ℕ))).eval (r i)).card
      ≤ (∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1) := by
  have hsub : (univ.filter fun r : Fin n → F => ∃ i : Fin n,
        p (i : ℕ) (trunc r (i : ℕ)) ≠ g (i : ℕ) (trunc r (i : ℕ))
          ∧ (p (i : ℕ) (trunc r (i : ℕ))).eval (r i)
              = (g (i : ℕ) (trunc r (i : ℕ))).eval (r i))
      ⊆ univ.biUnion fun i : Fin n => univ.filter fun r : Fin n → F =>
          p (i : ℕ) (trunc r (i : ℕ)) - g (i : ℕ) (trunc r (i : ℕ)) ≠ 0
            ∧ (p (i : ℕ) (trunc r (i : ℕ)) - g (i : ℕ) (trunc r (i : ℕ))).eval (r i) = 0 := by
    intro r hr
    simp only [mem_filter, mem_univ, true_and, mem_biUnion] at hr ⊢
    obtain ⟨i, hne, heval⟩ := hr
    exact ⟨i, sub_ne_zero.mpr hne, by rw [eval_sub, heval, sub_self]⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_biUnion_le) ?_)
  calc ∑ i : Fin n, (univ.filter fun r : Fin n → F =>
        p (i : ℕ) (trunc r (i : ℕ)) - g (i : ℕ) (trunc r (i : ℕ)) ≠ 0
          ∧ (p (i : ℕ) (trunc r (i : ℕ)) - g (i : ℕ) (trunc r (i : ℕ))).eval (r i) = 0).card
      ≤ ∑ i : Fin n, d (i : ℕ) * Fintype.card F ^ (n - 1) := by
        refine Finset.sum_le_sum fun i _ => ?_
        exact card_pi_root_slice i
          (fun r => p (i : ℕ) (trunc r (i : ℕ)) - g (i : ℕ) (trunc r (i : ℕ)))
          (fun r => le_trans (natDegree_sub_le _ _) (max_le (hp _ _) (hg _ _)))
          (fun r x => by rw [trunc_update])
    _ = (∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1) := by
        rw [← Finset.sum_mul, Fin.sum_univ_eq_sum_range]

end VoltaZk

import Mathlib.Algebra.MvPolynomial.Degrees
import Mathlib.Algebra.MvPolynomial.Eval
import VoltaZk.BlindSumcheckSound

/-!
# `MvPolynomial` semantics for the blind sumcheck (M3b, instantiation)

The abstract soundness core (`VoltaZk/SumcheckSound.lean`) is stated against
an arbitrary `TrueRounds` family. This file constructs that family for the
canonical sumcheck claim `∑_{b ∈ {0,1}^n} f(b) = σ₀` with
`f : MvPolynomial (Fin n) F`:

* `boolCube F n k` — the sub-cube of `{0,1}`-vectors whose first `k`
  coordinates are pinned to `0` (round `i` sums over `boolCube F n (i+1)`);
* `gMv f i pre` — the true round-`i` polynomial: substitute the challenge
  prefix `pre` for the first `i` variables, keep variable `i`, and sum the
  remaining variables over the Boolean sub-cube;
* `trueRoundsMv` — the `TrueRounds` package: degree bounds via
  `degreeOf`, and the three consistency equations via the sub-cube peeling
  lemma `sum_boolCube_peel`;
* `blind_sumcheck_sound_mv` — the end-to-end M3 statement: a malicious
  prover claiming a wrong value of `∑_{b} f(b)`, where the final
  authenticated opening computes `f(r)` (hypothesis `hopen` — MAC linearity
  for MLE openings), convinces the honest verifier with probability
  `≤ (∑ᵢ degreeOf i f + 2)/|F|`.
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F] [DecidableEq F]

/-! ### The Boolean sub-cube and its peeling -/

/-- Vectors whose coordinates `≥ k` range over `{0,1}` and whose coordinates
`< k` are pinned to `0`. `boolCube F n 0` is the full Boolean cube;
`boolCube F n n` is the single all-zero vector. -/
def boolCube (F : Type*) [Zero F] [One F] [DecidableEq F] (n k : ℕ) : Finset (Fin n → F) :=
  Fintype.piFinset fun j => if k ≤ (j : ℕ) then ({0, 1} : Finset F) else {0}

theorem mem_boolCube {n k : ℕ} {b : Fin n → F} :
    b ∈ boolCube F n k
      ↔ ∀ j : Fin n, b j ∈ (if k ≤ (j : ℕ) then ({0, 1} : Finset F) else {0}) :=
  Fintype.mem_piFinset

theorem boolCube_pinned {n k : ℕ} {b : Fin n → F} (hb : b ∈ boolCube F n k) (j : Fin n)
    (hj : (j : ℕ) < k) : b j = 0 := by
  have h := mem_boolCube.mp hb j
  rw [if_neg (by omega)] at h
  simpa using h

/-- Peeling coordinate `k` off the sub-cube: summing over `boolCube k` is
summing over `boolCube (k+1)` with coordinate `k` set to `0` and to `1`. -/
theorem sum_boolCube_peel {n k : ℕ} (hk : k < n) (G : (Fin n → F) → F) :
    ∑ b ∈ boolCube F n k, G b
      = ∑ b ∈ boolCube F n (k + 1),
          (G (Function.update b ⟨k, hk⟩ 0) + G (Function.update b ⟨k, hk⟩ 1)) := by
  have hstep : ∑ b ∈ boolCube F n k, G b
      = ∑ p ∈ (boolCube F n (k + 1)) ×ˢ ({0, 1} : Finset F),
          G (Function.update p.1 ⟨k, hk⟩ p.2) := by
    refine Finset.sum_nbij' (fun b => (Function.update b ⟨k, hk⟩ 0, b ⟨k, hk⟩))
      (fun p => Function.update p.1 ⟨k, hk⟩ p.2) ?_ ?_ ?_ ?_ ?_
    · intro b hb
      rw [Finset.mem_product]
      refine ⟨mem_boolCube.mpr fun j => ?_, ?_⟩
      · change Function.update b ⟨k, hk⟩ 0 j ∈ _
        by_cases hj : j = ⟨k, hk⟩
        · subst hj
          rw [Function.update_self, if_neg (by simp)]
          simp
        · rw [Function.update_of_ne hj]
          have h := mem_boolCube.mp hb j
          have hjk : (j : ℕ) ≠ k := fun hc => hj (Fin.ext hc)
          by_cases hlt : (j : ℕ) < k
          · rw [if_neg (by omega)] at h ⊢
            exact h
          · rw [if_pos (by omega)] at h
            rw [if_pos (by omega)]
            exact h
      · change b ⟨k, hk⟩ ∈ ({0, 1} : Finset F)
        have h := mem_boolCube.mp hb ⟨k, hk⟩
        rwa [if_pos (by simp)] at h
    · intro p hp
      rw [Finset.mem_product] at hp
      refine mem_boolCube.mpr fun j => ?_
      by_cases hj : j = ⟨k, hk⟩
      · subst hj
        rw [Function.update_self, if_pos (by simp)]
        exact hp.2
      · rw [Function.update_of_ne hj]
        have h := mem_boolCube.mp hp.1 j
        have hjk : (j : ℕ) ≠ k := fun hc => hj (Fin.ext hc)
        by_cases hlt : (j : ℕ) < k
        · rw [if_neg (by omega)] at h ⊢
          exact h
        · rw [if_pos (by omega)] at h
          rw [if_pos (by omega)]
          rcases Finset.mem_insert.mp h with h0 | h1
          · exact Finset.mem_insert.mpr (Or.inl h0)
          · exact Finset.mem_insert.mpr (Or.inr h1)
    · intro b _
      rw [Function.update_idem, Function.update_eq_self]
    · intro p hp
      rw [Finset.mem_product] at hp
      have hpk : p.1 ⟨k, hk⟩ = 0 := by
        have h := mem_boolCube.mp hp.1 ⟨k, hk⟩
        rw [if_neg (by simp)] at h
        simpa using h
      refine Prod.ext ?_ ?_
      · change Function.update (Function.update p.1 ⟨k, hk⟩ p.2) ⟨k, hk⟩ 0 = p.1
        rw [Function.update_idem, show (0 : F) = p.1 ⟨k, hk⟩ from hpk.symm,
          Function.update_eq_self]
      · change Function.update p.1 ⟨k, hk⟩ p.2 ⟨k, hk⟩ = p.2
        rw [Function.update_self]
    · intro b _
      rw [Function.update_idem, Function.update_eq_self]
  rw [hstep, Finset.sum_product]
  exact Finset.sum_congr rfl fun b _ => Finset.sum_pair zero_ne_one

/-- The top sub-cube is the single all-zero vector. -/
theorem boolCube_top {n : ℕ} : boolCube F n n = {fun _ => (0 : F)} := by
  unfold boolCube
  rw [show (fun j : Fin n => if n ≤ (j : ℕ) then ({0, 1} : Finset F) else {0})
      = fun j : Fin n => ({(0 : F)} : Finset F) from funext fun j => if_neg (by omega)]
  exact Fintype.piFinset_singleton fun _ => (0 : F)

/-! ### Partial substitution -/

/-- The substitution used for the round-`i` polynomial: challenge prefix for
variables `< i`, the polynomial variable `X` at `i`, cube values above. -/
noncomputable def subst {n : ℕ} (i : ℕ) (pre b : Fin n → F) : Fin n → Polynomial F :=
  fun j => if (j : ℕ) < i then Polynomial.C (pre j)
    else if (j : ℕ) = i then Polynomial.X else Polynomial.C (b j)

/-- Scalar counterpart of `subst` after evaluating the kept variable at `t`. -/
def assign {n : ℕ} (i : ℕ) (pre : Fin n → F) (t : F) (b : Fin n → F) : Fin n → F :=
  fun j => if (j : ℕ) < i then pre j else if (j : ℕ) = i then t else b j

omit [DecidableEq F] in
theorem natDegree_subst {n : ℕ} (i : ℕ) (pre b : Fin n → F) (j : Fin n) :
    (subst i pre b j).natDegree = if (j : ℕ) = i then 1 else 0 := by
  unfold subst
  split_ifs with h1 h2
  · exact absurd h2 (by omega)
  · exact Polynomial.natDegree_C _
  · exact Polynomial.natDegree_X
  · exact Polynomial.natDegree_C _

omit [DecidableEq F] in
/-- Evaluating the round polynomial at `t` is evaluating `f` at the
corresponding scalar assignment. -/
theorem eval_aeval_subst {n : ℕ} (f : MvPolynomial (Fin n) F) (i : ℕ) (pre b : Fin n → F)
    (t : F) :
    (MvPolynomial.aeval (subst i pre b) f).eval t = MvPolynomial.eval (assign i pre t b) f := by
  rw [MvPolynomial.aeval_def]
  have hcomp := MvPolynomial.eval₂_comp_left (Polynomial.evalRingHom t)
    (algebraMap F (Polynomial F)) (subst i pre b) f
  rw [show (Polynomial.evalRingHom t) (MvPolynomial.eval₂ (algebraMap F (Polynomial F))
      (subst i pre b) f) = (MvPolynomial.eval₂ (algebraMap F (Polynomial F))
      (subst i pre b) f).eval t from rfl] at hcomp
  rw [hcomp]
  have hring : (Polynomial.evalRingHom t).comp (algebraMap F (Polynomial F))
      = RingHom.id F := by
    ext a
    simp
  have hfun : (Polynomial.evalRingHom t) ∘ (subst i pre b) = assign i pre t b := by
    funext j
    simp only [Function.comp_apply]
    unfold subst assign
    split_ifs <;> simp
  rw [hring, hfun, MvPolynomial.eval₂_id]

omit [DecidableEq F] in
/-- Degree bound for the round polynomial: one substituted variable of degree
one, everything else constant. -/
theorem natDegree_aeval_subst_le {n : ℕ} (f : MvPolynomial (Fin n) F) (i : Fin n)
    (pre b : Fin n → F) :
    (MvPolynomial.aeval (subst (i : ℕ) pre b) f).natDegree ≤ f.degreeOf i := by
  classical
  rw [MvPolynomial.aeval_def, MvPolynomial.eval₂_eq']
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun u hu => ?_
  have halg : algebraMap F (Polynomial F) (f.coeff u) = Polynomial.C (f.coeff u) := rfl
  rw [halg]
  refine le_trans (Polynomial.natDegree_C_mul_le _ _) ?_
  refine le_trans (Polynomial.natDegree_prod_le _ _) ?_
  calc ∑ j, ((subst (i : ℕ) pre b j) ^ (u j)).natDegree
      ≤ ∑ j, u j * (subst (i : ℕ) pre b j).natDegree :=
        Finset.sum_le_sum fun j _ => Polynomial.natDegree_pow_le
    _ = ∑ j, (if j = i then u j else 0) := by
        refine Finset.sum_congr rfl fun j _ => ?_
        rw [natDegree_subst]
        by_cases hj : j = i
        · subst hj
          rw [if_pos rfl, if_pos rfl, mul_one]
        · rw [if_neg (fun hc => hj (Fin.ext hc)), if_neg hj, mul_zero]
    _ = u i := by
        rw [Finset.sum_ite_eq' Finset.univ i (fun j => u j)]
        simp
    _ ≤ f.degreeOf i := by
        rw [MvPolynomial.degreeOf_eq_sup]
        exact Finset.le_sup (f := fun m => m i) hu

/-! ### The true round polynomials -/

/-- True round-`i` polynomial of the sumcheck for `f`: substitute the prefix,
keep variable `i`, sum the tail over the Boolean sub-cube. -/
noncomputable def gMv {n : ℕ} (f : MvPolynomial (Fin n) F) (i : ℕ) (pre : Fin n → F) :
    Polynomial F :=
  ∑ b ∈ boolCube F n (i + 1), MvPolynomial.aeval (subst i pre b) f

theorem eval_gMv {n : ℕ} (f : MvPolynomial (Fin n) F) (i : ℕ) (pre : Fin n → F) (t : F) :
    (gMv f i pre).eval t
      = ∑ b ∈ boolCube F n (i + 1), MvPolynomial.eval (assign i pre t b) f := by
  unfold gMv
  rw [Polynomial.eval_finsetSum]
  exact Finset.sum_congr rfl fun b _ => eval_aeval_subst f i pre b t

omit [DecidableEq F] in
/-- Auxiliary congruence: the assignments appearing in the sumcheck chaining
step coincide. -/
theorem assign_update {n : ℕ} (r : Fin n → F) (i : ℕ) (h : i + 1 < n) (t : F)
    (b : Fin n → F) :
    assign i (trunc r i) (r ⟨i, by omega⟩) (Function.update b ⟨i + 1, h⟩ t)
      = assign (i + 1) (trunc r (i + 1)) t b := by
  funext j
  unfold assign trunc
  rw [Function.update_apply]
  by_cases h1 : (j : ℕ) < i
  · rw [if_pos h1, if_pos h1, if_pos (show (j : ℕ) < i + 1 by omega),
      if_pos (show (j : ℕ) < i + 1 by omega)]
  · by_cases h2 : (j : ℕ) = i
    · rw [if_neg h1, if_pos h2, if_pos (by omega : (j : ℕ) < i + 1), if_pos (by omega)]
      exact (congrArg r (Fin.ext h2)).symm
    · by_cases h3 : (j : ℕ) = i + 1
      · rw [if_neg h1, if_neg h2, if_pos (Fin.ext h3), if_neg (by omega), if_pos h3]
      · rw [if_neg h1, if_neg h2, if_neg (fun hc : j = ⟨i + 1, h⟩ => h3 (by
          have := congrArg Fin.val hc
          simpa using this)), if_neg (by omega), if_neg h3]

/-- Degree function of the sumcheck for `f`: `degreeOf i f` in range, `0`
outside (where the round polynomial is constant). -/
noncomputable def dMv {n : ℕ} (f : MvPolynomial (Fin n) F) (i : ℕ) : ℕ :=
  if h : i < n then f.degreeOf ⟨i, h⟩ else 0

theorem natDegree_gMv_le {n : ℕ} (f : MvPolynomial (Fin n) F) (i : ℕ) (pre : Fin n → F) :
    (gMv f i pre).natDegree ≤ dMv f i := by
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun b _ => ?_
  unfold dMv
  split
  · exact natDegree_aeval_subst_le f ⟨i, by assumption⟩ pre b
  · have hsubst : subst (n := n) i pre b = fun j => Polynomial.C (pre j) := by
      funext j
      unfold subst
      rw [if_pos (by omega)]
    rw [hsubst]
    have hconst : MvPolynomial.aeval (R := F) (fun j : Fin n => Polynomial.C (pre j)) f
        = Polynomial.C (MvPolynomial.eval pre f) := by
      rw [MvPolynomial.aeval_def, show (algebraMap F (Polynomial F)) = Polynomial.C from rfl]
      have h2 := MvPolynomial.eval₂_comp_left (Polynomial.C (R := F)) (RingHom.id F) pre f
      rw [MvPolynomial.eval₂_id, RingHom.comp_id] at h2
      exact h2.symm
    rw [hconst, Polynomial.natDegree_C]

/-- The `TrueRounds` package for the claim `∑_{b ∈ {0,1}^n} f(b) = σ₀`. -/
noncomputable def trueRoundsMv {n : ℕ} (hn : 0 < n) (f : MvPolynomial (Fin n) F)
    {d : ℕ → ℕ} (hd : ∀ i : Fin n, f.degreeOf i ≤ d (i : ℕ)) : TrueRounds F n d where
  g := gMv f
  total := ∑ b ∈ boolCube F n 0, MvPolynomial.eval b f
  finalEval := fun r => MvPolynomial.eval r f
  deg_le := fun i pre => by
    refine le_trans (natDegree_gMv_le f i pre) ?_
    unfold dMv
    split
    · exact hd ⟨i, by assumption⟩
    · exact Nat.zero_le _
  first := fun r => by
    rw [eval_gMv, eval_gMv, ← Finset.sum_add_distrib,
      sum_boolCube_peel hn (fun b => MvPolynomial.eval b f)]
    refine (Finset.sum_congr rfl fun b _ => ?_).symm
    have h0 : ∀ t : F, Function.update b ⟨0, hn⟩ t = assign 0 (trunc r 0) t b := by
      intro t
      funext j
      unfold assign
      rw [Function.update_apply]
      by_cases hj : (j : ℕ) = 0
      · rw [if_pos (Fin.ext hj), if_neg (by omega), if_pos hj]
      · rw [if_neg (fun hc : j = ⟨0, hn⟩ => hj (by
          have := congrArg Fin.val hc
          simpa using this)), if_neg (by omega), if_neg hj]
    rw [h0 0, h0 1]
  step := fun r i h => by
    rw [eval_gMv, eval_gMv, eval_gMv, ← Finset.sum_add_distrib,
      sum_boolCube_peel h (fun b => MvPolynomial.eval (assign i (trunc r i)
        (r ⟨i, Nat.lt_of_succ_lt h⟩) b) f)]
    refine Finset.sum_congr rfl fun b _ => ?_
    rw [assign_update r i h 0 b, assign_update r i h 1 b]
  final := fun r hn' => by
    rw [eval_gMv, show n - 1 + 1 = n from by omega, boolCube_top, Finset.sum_singleton]
    have hass : assign (n - 1) (trunc r (n - 1))
        (r ⟨n - 1, Nat.sub_lt hn' Nat.one_pos⟩) (fun _ => (0 : F)) = r := by
      funext j
      unfold assign trunc
      by_cases h1 : (j : ℕ) < n - 1
      · rw [if_pos h1, if_pos h1]
      · rw [if_neg h1, if_pos (show (j : ℕ) = n - 1 by omega)]
        exact (congrArg r (Fin.ext (show (j : ℕ) = n - 1 by omega))).symm
    rw [hass]

/-- **M3, end to end.** Soundness of the blind sumcheck for the canonical
claim `∑_{b ∈ {0,1}^n} f(b) = σ₀`, `f : MvPolynomial (Fin n) F` with
per-variable degrees bounded by the public schedule `d`: if the claimed
total is wrong and the final authenticated opening computes `f(r)`
(hypothesis `hopen` — MAC linearity of the MLE opening), the honest verifier
accepts on at most a `(∑ᵢ d i + 2)/|F|` fraction of its random tapes. -/
theorem blind_sumcheck_sound_mv [Fintype F] {n : ℕ} {d : ℕ → ℕ} {ι : Type*} [Fintype ι]
    (hn : 0 < n) (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F)
    (f : MvPolynomial (Fin n) F)
    (hd : ∀ i : Fin n, f.degreeOf i ≤ d (i : ℕ))
    (hopen : ∀ r, MvPolynomial.eval r f = openEval A L r)
    (hσ : A.σ₀ ≠ ∑ b ∈ boolCube F n 0, MvPolynomial.eval b f) :
    (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        accepts hn A L Ω.1 Ω.2.1 Ω.2.2).card
      ≤ (∑ i ∈ Finset.range n, d i + 2) * Fintype.card F ^ (n + (n + 1)) :=
  blind_sumcheck_sound hn A L (trueRoundsMv hn f hd) (funext hopen) hσ

end VoltaZk

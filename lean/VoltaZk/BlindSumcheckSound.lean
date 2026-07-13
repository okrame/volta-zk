import VoltaZk.ZeroBatchSound
import VoltaZk.SumcheckSound

/-!
# Soundness of the blind sumcheck `Π_BSC + Π_ZeroBatch` (M3, main theorem)

Corrupt prover `P*`, honest verifier, `F_sVOLE`-hybrid model.

Modeling notes (mirroring the deterministic-`V*` notes of the ZK theorem):

* **Value-level adversary (WLOG).** In the corrupted-P branch of `F_sVOLE`
  the adversary chooses each correlation `(u, m)` and the functionality sets
  `k = m + u·Δ`; the `Π_Auth` correction `δ` then commits it to the plaintext
  `x = u + δ` with tag `m`, key `k + Δ·δ = m + Δ·x`. Composing the two
  adversary-chosen maps, `P*` is modeled as directly choosing plaintext/tag
  pairs (`MaliciousProver.wit`, `MaliciousProver.coeff`). Its view is
  independent of `Δ`, so a deterministic `P*` is a family of messages indexed
  by the public challenges only; adaptivity is structural — round-`i` data
  reads the truncated challenge vector `trunc r i`.
* **The specific sumcheck claim schema.** Unlike the ZK theorem (which holds
  for *every* public-linear `ClaimSchema`), soundness is proved for the
  concrete schema of `Π_BSC`: claim `0` is the round-0 sum check, claim
  `0 < j < n` the chaining check, claim `n` the final-evaluation check
  against the authenticated MLE opening `⟨L r, wit⟩`. All are public-linear
  combinations of authenticated values, so the verifier's side of each claim
  is a local computation on its keys (`claimAt_valid`).
* **Semantics.** The true side is a `TrueRounds` family; the hypothesis
  `hfin` states that the final-check functional is the plaintext of the
  authenticated opening — for MLE openings this is exactly MAC linearity.
  The `MvPolynomial` instantiation is in `VoltaZk/SumcheckMv.lean`.

Main theorem `blind_sumcheck_sound`: if the claimed total is wrong, the
verifier accepts on at most `(∑ d_i + 2)·|F|^(2n+1)` of the `|F|^(2n+2)`
random tapes `(Δ, r, χ)` — soundness error `≤ (∑ d_i + 2)/|F|`, which is
`≤ (Σ degrees + T + 1)/|F|` for the `T = n+1` batched claims.
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F]

/-! ### Round polynomials from coefficient vectors -/

/-- The univariate polynomial with coefficient vector `c` (index `j` is the
coefficient of `X^j`) — the plaintext round polynomial behind a block of
authenticated coefficients. -/
noncomputable def polyOfCoeffs {m : ℕ} (c : Fin m → F) : Polynomial F :=
  ∑ j, Polynomial.C (c j) * Polynomial.X ^ (j : ℕ)

theorem natDegree_polyOfCoeffs_le {m : ℕ} (c : Fin m → F) :
    (polyOfCoeffs c).natDegree ≤ m - 1 := by
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ fun j _ => ?_
  refine le_trans (Polynomial.natDegree_C_mul_le _ _) ?_
  rw [Polynomial.natDegree_X_pow]
  omega

theorem eval_polyOfCoeffs {m : ℕ} (c : Fin m → F) (t : F) :
    (polyOfCoeffs c).eval t = ∑ j, c j * t ^ (j : ℕ) := by
  simp [polyOfCoeffs, Polynomial.eval_finsetSum]

/-! ### The malicious prover -/

/-- A deterministic malicious prover for one blind-sumcheck window (value
level, see the WLOG note in the file docstring). `wit` is the committed
witness (authenticated before the window opens), `coeff i` the authenticated
round-`i` coefficient block — a function of the truncated challenges only —
`σ₀` the claimed total, and `final` the batched `Π_ZeroBatch` opening
message, which may read all public challenges. -/
structure MaliciousProver (F : Type*) (n : ℕ) (d : ℕ → ℕ) (ι : Type*) where
  /-- committed witness: plaintext/tag pairs, fixed before any challenge -/
  wit : ι → F × F
  /-- round-`i` coefficient plaintext/tag pairs; reads only `trunc r i` -/
  coeff : (i : ℕ) → (Fin n → F) → Fin (d i + 1) → F × F
  /-- claimed value of the sum (public) -/
  σ₀ : F
  /-- final batched opening message; reads `(r, χ)` -/
  final : (Fin n → F) → (Fin (n + 1) → F) → F

variable {n : ℕ} {d : ℕ → ℕ} {ι : Type*} [Fintype ι]

omit [Fintype ι] in
/-- Plaintext round polynomial of the adversary at round `i` given the
(truncated) challenge prefix. -/
noncomputable def roundPoly (A : MaliciousProver F n d ι) (i : ℕ) (pre : Fin n → F) :
    Polynomial F :=
  polyOfCoeffs fun j => (A.coeff i pre j).1

omit [Fintype ι] in
theorem natDegree_roundPoly_le (A : MaliciousProver F n d ι) (i : ℕ) (pre : Fin n → F) :
    (roundPoly A i pre).natDegree ≤ d i :=
  le_trans (natDegree_polyOfCoeffs_le _) (by omega)

/-! ### Authenticated claim schema of the blind sumcheck -/

omit [Fintype ι] in
/-- The authenticated evaluation `⟦p_i(t)⟧` at a public point `t`: both
parties combine the authenticated coefficients with the public monomials
`t^j` locally (MAC linearity). -/
def evalAuthed (A : MaliciousProver F n d ι) (Δ : F) (i : ℕ) (pre : Fin n → F) (t : F) :
    Authed F :=
  ∑ j : Fin (d i + 1), t ^ (j : ℕ) • authedOfPair Δ (A.coeff i pre j)

omit [Fintype ι] in
theorem evalAuthed_valid (A : MaliciousProver F n d ι) (Δ : F) (i : ℕ) (pre : Fin n → F)
    (t : F) : (evalAuthed A Δ i pre t).Valid Δ := by
  unfold evalAuthed
  exact Authed.Valid.sum fun j _ => (authedOfPair_valid Δ _).smul _

omit [Fintype ι] in
@[simp] theorem evalAuthed_x (A : MaliciousProver F n d ι) (Δ : F) (i : ℕ) (pre : Fin n → F)
    (t : F) : (evalAuthed A Δ i pre t).x = (roundPoly A i pre).eval t := by
  unfold evalAuthed roundPoly
  rw [eval_polyOfCoeffs]
  simp only [Authed.sum_x, Authed.smul_x, authedOfPair_x]
  exact Finset.sum_congr rfl fun j _ => mul_comm _ _

omit [Fintype ι] in
@[simp] theorem evalAuthed_m (A : MaliciousProver F n d ι) (Δ : F) (i : ℕ) (pre : Fin n → F)
    (t : F) :
    (evalAuthed A Δ i pre t).m = ∑ j : Fin (d i + 1), t ^ (j : ℕ) * (A.coeff i pre j).2 := by
  simp [evalAuthed]

/-- Plaintext of the final opening functional: `⟨L r, wit⟩`. For MLE
openings, `L r = eq(r, ·)` and this is the multilinear extension of the
committed witness at `r`. -/
def openEval (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (r : Fin n → F) : F :=
  ∑ k, L r k * (A.wit k).1

/-- The authenticated final opening `⟦⟨L r, wit⟩⟧`: a public-linear
combination of the committed witness values (free for both parties). -/
def openingAuthed (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (Δ : F)
    (r : Fin n → F) : Authed F :=
  ∑ k, L r k • authedOfPair Δ (A.wit k)

theorem openingAuthed_valid (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (Δ : F)
    (r : Fin n → F) : (openingAuthed A L Δ r).Valid Δ :=
  Authed.Valid.sum fun _ _ => (authedOfPair_valid Δ _).smul _

@[simp] theorem openingAuthed_x (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F)
    (Δ : F) (r : Fin n → F) : (openingAuthed A L Δ r).x = openEval A L r := by
  simp [openingAuthed, openEval]

@[simp] theorem openingAuthed_m (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F)
    (Δ : F) (r : Fin n → F) :
    (openingAuthed A L Δ r).m = ∑ k, L r k * (A.wit k).2 := by
  simp [openingAuthed]

/-- The closed claim list of the blind sumcheck window (`T = n+1` claims):
claim `0` is `⟦p₀(0)+p₀(1)⟧ − σ₀`, claim `0 < j < n` is
`⟦p_j(0)+p_j(1)⟧ − ⟦p_{j-1}(r_{j-1})⟧`, claim `n` is
`⟦p_{n-1}(r_{n-1})⟧ − ⟦⟨L r, wit⟩⟧`. Each is a public-linear combination of
authenticated values, accumulated for one `Π_ZeroBatch`. -/
def claimAt (hn : 0 < n) (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (Δ : F)
    (r : Fin n → F) (j : ℕ) : Authed F :=
  if j = 0 then
    evalAuthed A Δ 0 (trunc r 0) 0 + evalAuthed A Δ 0 (trunc r 0) 1
      - Authed.ofPublic Δ A.σ₀
  else if h : j < n then
    evalAuthed A Δ j (trunc r j) 0 + evalAuthed A Δ j (trunc r j) 1
      - evalAuthed A Δ (j - 1) (trunc r (j - 1)) (r ⟨j - 1, by omega⟩)
  else
    evalAuthed A Δ (n - 1) (trunc r (n - 1)) (r ⟨n - 1, by omega⟩)
      - openingAuthed A L Δ r

theorem claimAt_valid (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) (j : ℕ) :
    (claimAt hn A L Δ r j).Valid Δ := by
  unfold claimAt
  split
  · exact ((evalAuthed_valid A Δ 0 (trunc r 0) 0).add
      (evalAuthed_valid A Δ 0 (trunc r 0) 1)).sub (Authed.ofPublic_valid Δ A.σ₀)
  split
  · exact ((evalAuthed_valid A Δ j (trunc r j) 0).add
      (evalAuthed_valid A Δ j (trunc r j) 1)).sub (evalAuthed_valid A Δ (j - 1) _ _)
  · exact (evalAuthed_valid A Δ (n - 1) _ _).sub (openingAuthed_valid A L Δ r)

/-! ### Plaintext formulas and Δ-independence -/

theorem claimAt_x_zero (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) :
    (claimAt hn A L Δ r 0).x
      = (roundPoly A 0 (trunc r 0)).eval 0 + (roundPoly A 0 (trunc r 0)).eval 1 - A.σ₀ := by
  unfold claimAt
  rw [if_pos rfl]
  simp

theorem claimAt_x_mid (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) {j : ℕ} (hj0 : j ≠ 0) (hjn : j < n) :
    (claimAt hn A L Δ r j).x
      = (roundPoly A j (trunc r j)).eval 0 + (roundPoly A j (trunc r j)).eval 1
          - (roundPoly A (j - 1) (trunc r (j - 1))).eval
              (r ⟨j - 1, by omega⟩) := by
  unfold claimAt
  rw [if_neg hj0, dif_pos hjn]
  simp

theorem claimAt_x_last (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) :
    (claimAt hn A L Δ r n).x
      = (roundPoly A (n - 1) (trunc r (n - 1))).eval (r ⟨n - 1, by omega⟩)
          - openEval A L r := by
  unfold claimAt
  rw [if_neg (by omega), dif_neg (by omega)]
  simp

/-- The claim plaintexts do not depend on the session key. -/
theorem claimAt_x_indep (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ Δ' : F) (r : Fin n → F) (j : ℕ) :
    (claimAt hn A L Δ r j).x = (claimAt hn A L Δ' r j).x := by
  unfold claimAt
  split
  · simp
  split <;> simp

/-- The claim tags do not depend on the session key. -/
theorem claimAt_m_indep (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ Δ' : F) (r : Fin n → F) (j : ℕ) :
    (claimAt hn A L Δ r j).m = (claimAt hn A L Δ' r j).m := by
  unfold claimAt
  split
  · simp
  split <;> simp

/-- The verifier's key side of claim `j` is the MAC of the (Δ-independent)
plaintext/tag pair — extracted at the fixed key `Δ = 0`. This is what lets
the honest verifier's batched check be analyzed by `zeroBatch_sound`. -/
theorem claimAt_k_eq_keyOf (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) (j : ℕ) :
    (claimAt hn A L Δ r j).k
      = keyOf Δ ((claimAt hn A L 0 r j).x, (claimAt hn A L 0 r j).m) := by
  have hv := claimAt_valid hn A L Δ r j
  unfold Authed.Valid at hv
  rw [hv, claimAt_x_indep hn A L Δ 0 r j, claimAt_m_indep hn A L Δ 0 r j]
  unfold keyOf
  ring

/-! ### The blind→clear reduction -/

/-- **Blind→clear.** If every claim in the closed list has zero plaintext,
then the plaintexts of the authenticated round coefficients form a clear
sumcheck transcript that passes all classical checks. -/
theorem clear_of_claims_zero (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (r : Fin n → F)
    (hz : ∀ j : Fin (n + 1), (claimAt hn A L 0 r (j : ℕ)).x = 0) :
    clearAccepts hn (roundPoly A) A.σ₀ (openEval A L) r := by
  refine ⟨?_, fun i => ?_, ?_⟩
  · have h0 := hz ⟨0, by omega⟩
    rw [claimAt_x_zero] at h0
    exact sub_eq_zero.mp h0
  · have hi := hz ⟨(i : ℕ) + 1, by omega⟩
    rw [show ((⟨(i : ℕ) + 1, by omega⟩ : Fin (n + 1)) : ℕ) = (i : ℕ) + 1 from rfl,
      claimAt_x_mid hn A L 0 r (Nat.succ_ne_zero _) (by omega)] at hi
    have hi' := sub_eq_zero.mp hi
    simpa using hi'
  · have hl := hz ⟨n, by omega⟩
    rw [show ((⟨n, by omega⟩ : Fin (n + 1)) : ℕ) = n from rfl, claimAt_x_last] at hl
    exact sub_eq_zero.mp hl

/-! ### The acceptance predicate and the main theorem -/

/-- The verifier's check at the end of the window: the adversary's batched
opening message must equal the χ-combination of the verifier's claim keys —
each computed locally from its `F_sVOLE` keys and the public transcript. -/
def accepts (hn : 0 < n) (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (Δ : F)
    (r : Fin n → F) (χ : Fin (n + 1) → F) : Prop :=
  A.final r χ = ∑ j : Fin (n + 1), χ j * (claimAt hn A L Δ r (j : ℕ)).k

instance accepts.instDecidable [DecidableEq F] (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) (χ : Fin (n + 1) → F) :
    Decidable (accepts hn A L Δ r χ) := by
  unfold accepts; infer_instance

/-- Implementation acceptance predicate: one scalar `χ` expands to the
power weights `χ^(j+1)` used by Rust's `zero_batch_*`. -/
def acceptsScalar (hn : 0 < n) (A : MaliciousProver F n d ι)
    (L : (Fin n → F) → ι → F) (Δ : F) (r : Fin n → F) (χ : F) : Prop :=
  A.final r (fun j => χ ^ (j.val + 1))
    = ∑ j : Fin (n + 1), χ ^ (j.val + 1) * (claimAt hn A L Δ r (j : ℕ)).k

instance acceptsScalar.instDecidable [DecidableEq F] (hn : 0 < n)
    (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F)
    (Δ : F) (r : Fin n → F) (χ : F) : Decidable (acceptsScalar hn A L Δ r χ) := by
  unfold acceptsScalar
  infer_instance

/-- Rotation of a triple product, used to slice the sample space along the
middle (challenge-vector) component. -/
def prodRotate (α β γ : Type*) : α × β × γ ≃ β × α × γ where
  toFun x := (x.2.1, x.1, x.2.2)
  invFun x := (x.2.1, x.1, x.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

@[simp] theorem prodRotate_symm_apply {α β γ : Type*} (x : β × α × γ) :
    (prodRotate α β γ).symm x = (x.2.1, x.1, x.2.2) := rfl

/-- **Soundness of the blind sumcheck (M3).** For every deterministic
malicious prover whose claimed total `σ₀` differs from the true total of the
`TrueRounds` semantics compatible with its committed witness (`hfin`: the
final functional is the plaintext of the authenticated opening), the honest
verifier accepts on at most `(∑ d_i + 2)·|F|^(2n+1)` of the `|F|^(2n+2)`
random tapes `(Δ, r, χ)`: soundness error `≤ (∑ d_i + 2)/|F|`. -/
theorem blind_sumcheck_sound [Fintype F] [DecidableEq F] (hn : 0 < n)
    (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (TR : TrueRounds F n d)
    (hfin : TR.finalEval = openEval A L) (hσ : A.σ₀ ≠ TR.total) :
    (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        accepts hn A L Ω.1 Ω.2.1 Ω.2.2).card
      ≤ (∑ i ∈ Finset.range n, d i + 2) * Fintype.card F ^ (n + (n + 1)) := by
  -- Split on whether all claim plaintexts vanish.
  have hsub : (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        accepts hn A L Ω.1 Ω.2.1 Ω.2.2)
      ⊆ (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
          ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0)
        ∪ (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
            (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
              ∧ accepts hn A L Ω.1 Ω.2.1 Ω.2.2) := by
    intro Ω hΩ
    simp only [mem_filter, mem_univ, true_and, mem_union] at hΩ ⊢
    by_cases hall : ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0
    · exact Or.inl hall
    · push Not at hall
      exact Or.inr ⟨hall, hΩ⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  -- All-zero branch: blind→clear reduction, then the deviation-round count.
  have hE2 : (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0).card
      ≤ Fintype.card F * ((∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1)
          * Fintype.card ((Fin (n + 1)) → F)) := by
    refine card_filter_prod_le_right
      (fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0) fun Δ => ?_
    refine card_filter_prod_le_left
      (fun rχ : (Fin n → F) × (Fin (n + 1) → F) =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 rχ.1 (j : ℕ)).x = 0) fun χ => ?_
    -- For each fixed χ: the all-zero event on r implies a deviation round.
    refine le_trans (Finset.card_le_card fun r hr => ?_)
      (card_deviation_le (roundPoly A) TR.g
        (fun i pre => natDegree_roundPoly_le A i pre) (fun i pre => TR.deg_le i pre))
    simp only [mem_filter, mem_univ, true_and] at hr ⊢
    have hacc : clearAccepts hn (roundPoly A) A.σ₀ TR.finalEval r := by
      rw [hfin]
      exact clear_of_claims_zero hn A L r hr
    exact exists_deviation hn (roundPoly A) TR hacc hσ
  -- Live-claim branch: rotate, then per-r reuse of the ZeroBatch soundness.
  have hE1 : (univ.filter fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
          ∧ accepts hn A L Ω.1 Ω.2.1 Ω.2.2).card
      ≤ Fintype.card (Fin n → F) * (2 * Fintype.card F ^ (n + 1)) := by
    rw [← card_filter_equiv (prodRotate F (Fin n → F) (Fin (n + 1) → F))
      (fun Ω : F × (Fin n → F) × (Fin (n + 1) → F) =>
        (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
          ∧ accepts hn A L Ω.1 Ω.2.1 Ω.2.2)]
    refine card_filter_prod_le_right
      (fun w : (Fin n → F) × F × (Fin (n + 1) → F) =>
        (∃ j : Fin (n + 1),
          (claimAt hn A L 0 ((prodRotate F (Fin n → F) (Fin (n + 1) → F)).symm w).2.1
            (j : ℕ)).x ≠ 0)
          ∧ accepts hn A L ((prodRotate F (Fin n → F) (Fin (n + 1) → F)).symm w).1
              ((prodRotate F (Fin n → F) (Fin (n + 1) → F)).symm w).2.1
              ((prodRotate F (Fin n → F) (Fin (n + 1) → F)).symm w).2.2) fun r => ?_
    by_cases hex : ∃ j : Fin (n + 1), (claimAt hn A L 0 r (j : ℕ)).x ≠ 0
    · obtain ⟨j₀, hj₀⟩ := hex
      refine le_trans (Finset.card_le_card fun Δχ hΔχ => ?_)
        (zeroBatch_sound
          (fun j : Fin (n + 1) =>
            ((claimAt hn A L 0 r (j : ℕ)).x, (claimAt hn A L 0 r (j : ℕ)).m))
          (j₀ := j₀) hj₀ (A.final r))
      simp only [mem_filter, mem_univ, true_and, prodRotate_symm_apply] at hΔχ ⊢
      have hacc := hΔχ.2
      unfold accepts at hacc
      rw [hacc]
      exact Finset.sum_congr rfl fun j _ => by rw [claimAt_k_eq_keyOf]
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le _)
      refine Finset.filter_eq_empty_iff.mpr fun Δχ _ h => ?_
      simp only [prodRotate_symm_apply] at h
      exact hex h.1
  -- Assemble and normalize the powers of |F|.
  refine le_trans (Nat.add_le_add hE2 hE1) ?_
  rw [Fintype.card_fun, Fintype.card_fun, Fintype.card_fin, Fintype.card_fin]
  have hpow1 : Fintype.card F * ((∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1)
      * Fintype.card F ^ (n + 1))
      = (∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n + (n + 1)) := by
    rw [show n + (n + 1) = 1 + ((n - 1) + (n + 1)) from by omega, pow_add, pow_add, pow_one]
    ring
  have hpow2 : Fintype.card F ^ n * (2 * Fintype.card F ^ (n + 1))
      = 2 * Fintype.card F ^ (n + (n + 1)) := by
    rw [pow_add]
    ring
  rw [hpow1, hpow2, add_mul]

/-- **Scalar-power blind-sumcheck soundness (Rust implementation).** The
one-scalar batching format trades the vector-RLC constant for the explicit
list-length term: the bad-tape count is
`(Σ dᵢ + n + 2)·|F|^(n+1)` out of `|F|^(n+2)`, hence error
`≤ (Σ dᵢ + n + 2)/|F|`. -/
theorem blind_sumcheck_sound_scalar [Fintype F] [DecidableEq F] (hn : 0 < n)
    (A : MaliciousProver F n d ι) (L : (Fin n → F) → ι → F) (TR : TrueRounds F n d)
    (hfin : TR.finalEval = openEval A L) (hσ : A.σ₀ ≠ TR.total) :
    (univ.filter fun Ω : F × (Fin n → F) × F =>
        acceptsScalar hn A L Ω.1 Ω.2.1 Ω.2.2).card
      ≤ (Finset.sum (Finset.range n) d + (n + 2)) * Fintype.card F ^ (n + 1) := by
  have hsub : (univ.filter fun Ω : F × (Fin n → F) × F =>
        acceptsScalar hn A L Ω.1 Ω.2.1 Ω.2.2)
      ⊆ (univ.filter fun Ω : F × (Fin n → F) × F =>
          ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0)
        ∪ (univ.filter fun Ω : F × (Fin n → F) × F =>
            (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
              ∧ acceptsScalar hn A L Ω.1 Ω.2.1 Ω.2.2) := by
    intro Ω hΩ
    simp only [mem_filter, mem_univ, true_and, mem_union] at hΩ ⊢
    by_cases hall : ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0
    · exact Or.inl hall
    · push Not at hall
      exact Or.inr ⟨hall, hΩ⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  have hE2 : (univ.filter fun Ω : F × (Fin n → F) × F =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0).card
      ≤ Fintype.card F *
          ((∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1) * Fintype.card F) := by
    refine card_filter_prod_le_right
      (fun Ω : F × (Fin n → F) × F =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x = 0) fun Δ => ?_
    refine card_filter_prod_le_left
      (fun rχ : (Fin n → F) × F =>
        ∀ j : Fin (n + 1), (claimAt hn A L 0 rχ.1 (j : ℕ)).x = 0) fun χ => ?_
    refine le_trans (Finset.card_le_card fun r hr => ?_)
      (card_deviation_le (roundPoly A) TR.g
        (fun i pre => natDegree_roundPoly_le A i pre) (fun i pre => TR.deg_le i pre))
    simp only [mem_filter, mem_univ, true_and] at hr ⊢
    have hacc : clearAccepts hn (roundPoly A) A.σ₀ TR.finalEval r := by
      rw [hfin]
      exact clear_of_claims_zero hn A L r hr
    exact exists_deviation hn (roundPoly A) TR hacc hσ
  have hE1 : (univ.filter fun Ω : F × (Fin n → F) × F =>
        (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
          ∧ acceptsScalar hn A L Ω.1 Ω.2.1 Ω.2.2).card
      ≤ Fintype.card (Fin n → F) * ((n + 2) * Fintype.card F) := by
    rw [← card_filter_equiv (prodRotate F (Fin n → F) F)
      (fun Ω : F × (Fin n → F) × F =>
        (∃ j : Fin (n + 1), (claimAt hn A L 0 Ω.2.1 (j : ℕ)).x ≠ 0)
          ∧ acceptsScalar hn A L Ω.1 Ω.2.1 Ω.2.2)]
    refine card_filter_prod_le_right
      (fun w : (Fin n → F) × F × F =>
        (∃ j : Fin (n + 1),
          (claimAt hn A L 0 ((prodRotate F (Fin n → F) F).symm w).2.1 (j : ℕ)).x ≠ 0)
          ∧ acceptsScalar hn A L ((prodRotate F (Fin n → F) F).symm w).1
              ((prodRotate F (Fin n → F) F).symm w).2.1
              ((prodRotate F (Fin n → F) F).symm w).2.2) fun r => ?_
    by_cases hex : ∃ j : Fin (n + 1), (claimAt hn A L 0 r (j : ℕ)).x ≠ 0
    · obtain ⟨j₀, hj₀⟩ := hex
      refine le_trans (Finset.card_le_card
        (t := univ.filter fun Δχ : F × F =>
          A.final r (fun j => Δχ.2 ^ (j.val + 1))
            = ∑ j : Fin (n + 1), Δχ.2 ^ (j.val + 1) *
                keyOf Δχ.1
                  ((claimAt hn A L 0 r (j : ℕ)).x, (claimAt hn A L 0 r (j : ℕ)).m))
        fun Δχ hΔχ => ?_) ?_
      · simp only [mem_filter, mem_univ, true_and, prodRotate_symm_apply] at hΔχ ⊢
        have hacc := hΔχ.2
        unfold acceptsScalar at hacc
        rw [hacc]
        exact Finset.sum_congr rfl fun j _ => by rw [claimAt_k_eq_keyOf]
      · simpa [Nat.add_assoc] using
          (zeroBatch_sound_scalar
            (fun j : Fin (n + 1) =>
              ((claimAt hn A L 0 r (j : ℕ)).x, (claimAt hn A L 0 r (j : ℕ)).m))
            (j₀ := j₀) hj₀ (fun χ => A.final r (fun j => χ ^ (j.val + 1))))
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le _)
      refine Finset.filter_eq_empty_iff.mpr fun Δχ _ h => ?_
      simp only [prodRotate_symm_apply] at h
      exact hex h.1
  refine le_trans (Nat.add_le_add hE2 hE1) ?_
  rw [Fintype.card_fun, Fintype.card_fin]
  have hpow1 : Fintype.card F *
      ((∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n - 1) * Fintype.card F)
      = (∑ i ∈ Finset.range n, d i) * Fintype.card F ^ (n + 1) := by
    rw [show n + 1 = 1 + ((n - 1) + 1) from by omega, pow_add, pow_add, pow_one]
    ring
  have hpow2 : Fintype.card F ^ n * ((n + 2) * Fintype.card F)
      = (n + 2) * Fintype.card F ^ (n + 1) := by
    rw [pow_succ]
    ring
  rw [hpow1, hpow2]
  conv_rhs => rw [add_mul]

end VoltaZk

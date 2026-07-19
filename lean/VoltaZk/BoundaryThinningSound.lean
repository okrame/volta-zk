import VoltaZk.BlindSumcheckSound
import Mathlib.Tactic

/-!
# Late-claim reductions for boundary thinning (M11)

This file closes the formal gap created when a sumcheck terminal value is
authenticated only after its challenge point is known.  The types enforce the
challenge order used by T1: compressed round wires are prefix-adaptive;
terminal pairs may depend on the outer scalar `eta` and the complete point
`rho`; neither can depend on the MAC key or on any later verifier coin.

The round-wire model is the concrete one used by Rust.  A quadratic round
sends values at `0,2`; a cubic round sends values at `0,2,3`; in both cases
the verifier derives the value at `1` from the current live claim.  We prove
the authenticated-key mirror pointwise, rather than postulating an opening
key.  The counting theorems are clear-level statements and use only the
existing M2/M3 counting infrastructure.
-/

namespace VoltaZk

open Finset Polynomial

variable {F : Type*} [Field F]

/-! ## Exact compressed round wires -/

/-- The two wire formats used by the implementation.  Every component is a
prover plaintext/tag pair fixed without access to the MAC key. -/
inductive LateRoundWire (F : Type*) where
  | quadratic (g0 g2 : F × F)
  | cubic (g0 g2 g3 : F × F)

namespace LateRoundWire

/-- Public degree represented by a compressed wire. -/
def degree : LateRoundWire F → ℕ
  | quadratic .. => 2
  | cubic .. => 3

/-- Plaintext at node zero. -/
def x0 : LateRoundWire F → F
  | quadratic g0 _ => g0.1
  | cubic g0 _ _ => g0.1

/-- Tag at node zero. -/
def m0 : LateRoundWire F → F
  | quadratic g0 _ => g0.2
  | cubic g0 _ _ => g0.2

end LateRoundWire

/-- Small fixed vectors without relying on matrix-notation reduction. -/
def vec2 {α : Type*} (a b : α) : Fin 2 → α :=
  Fin.cases a (fun _ => b)

@[simp] theorem vec2_zero {α : Type*} (a b : α) : vec2 a b 0 = a := rfl
@[simp] theorem vec2_one {α : Type*} (a b : α) : vec2 a b 1 = b := rfl

def vec3 {α : Type*} (a b c : α) : Fin 3 → α :=
  Fin.cases a (Fin.cases b (fun _ => c))

/-- Four-element companion of `vec3`. -/
def vec4 {α : Type*} (a b c d : α) : Fin 4 → α :=
  Fin.cases a (Fin.cases b (Fin.cases c (fun _ => d)))

@[simp] theorem vec3_zero {α : Type*} (a b c : α) : vec3 a b c 0 = a := rfl
@[simp] theorem vec3_one {α : Type*} (a b c : α) : vec3 a b c 1 = b := rfl
@[simp] theorem vec3_two {α : Type*} (a b c : α) : vec3 a b c 2 = c := rfl

@[simp] theorem vec4_zero {α : Type*} (a b c d : α) : vec4 a b c d 0 = a := rfl
@[simp] theorem vec4_one {α : Type*} (a b c d : α) : vec4 a b c d 1 = b := rfl
@[simp] theorem vec4_two {α : Type*} (a b c d : α) : vec4 a b c d 2 = c := rfl
@[simp] theorem vec4_three {α : Type*} (a b c d : α) : vec4 a b c d 3 = d := rfl

/-- Coefficients of the quadratic through values at nodes `0,1,2`.
The formula is deliberately written in Newton form.  Its values at `0` and
`1` are exact over every field; matching node `2` additionally uses that
`2 != 0`, which holds for the production field and is audited separately. -/
noncomputable def quadraticCoeffs (y0 y1 y2 : F) : Fin 3 → F :=
  let c2 := (2 : F)⁻¹ * (y2 - 2 * y1 + y0)
  vec3 y0 (y1 - y0 - c2) c2

/-- Coefficients of the cubic through nodes `0,1,2,3`. -/
noncomputable def cubicCoeffs (y0 y1 y2 y3 : F) : Fin 4 → F :=
  let q := polyOfCoeffs (quadraticCoeffs y0 y1 y2)
  let c3 := (6 : F)⁻¹ * (y3 - q.eval 3)
  let qc := quadraticCoeffs y0 y1 y2
  vec4 (qc 0) (qc 1 + 2 * c3) (qc 2 - 3 * c3) c3

/-- Polynomial reconstructed from the exact Rust wire.  The missing value at
node one is `live-g0`, as in `round3`/`lagrange4`. -/
noncomputable def compressedRoundPoly (live : F) : LateRoundWire F → Polynomial F
  | .quadratic g0 g2 => polyOfCoeffs (quadraticCoeffs g0.1 (live - g0.1) g2.1)
  | .cubic g0 g2 g3 => polyOfCoeffs (cubicCoeffs g0.1 (live - g0.1) g2.1 g3.1)

theorem compressedRoundPoly_natDegree_le (live : F) (w : LateRoundWire F) :
    (compressedRoundPoly live w).natDegree ≤ w.degree := by
  cases w with
  | quadratic =>
      exact (natDegree_polyOfCoeffs_le _).trans (by simp [LateRoundWire.degree])
  | cubic =>
      exact (natDegree_polyOfCoeffs_le _).trans (by simp [LateRoundWire.degree])

@[simp] theorem quadraticCoeffs_zero (y0 y1 y2 : F) :
    (polyOfCoeffs (quadraticCoeffs y0 y1 y2)).eval 0 = y0 := by
  simp [eval_polyOfCoeffs, quadraticCoeffs, Fin.sum_univ_succ]

@[simp] theorem quadraticCoeffs_one (y0 y1 y2 : F) :
    (polyOfCoeffs (quadraticCoeffs y0 y1 y2)).eval 1 = y1 := by
  simp [eval_polyOfCoeffs, quadraticCoeffs, Fin.sum_univ_succ]

@[simp] theorem cubicCoeffs_zero (y0 y1 y2 y3 : F) :
    (polyOfCoeffs (cubicCoeffs y0 y1 y2 y3)).eval 0 = y0 := by
  simp [eval_polyOfCoeffs, cubicCoeffs, quadraticCoeffs, Fin.sum_univ_succ]

@[simp] theorem cubicCoeffs_one (y0 y1 y2 y3 : F) :
    (polyOfCoeffs (cubicCoeffs y0 y1 y2 y3)).eval 1 = y1 := by
  simp [eval_polyOfCoeffs, cubicCoeffs, quadraticCoeffs, Fin.sum_univ_succ]
  ring

@[simp] theorem compressedRoundPoly_eval_zero (live : F) (w : LateRoundWire F) :
    (compressedRoundPoly live w).eval 0 = w.x0 := by
  cases w <;> simp [compressedRoundPoly, LateRoundWire.x0]

@[simp] theorem compressedRoundPoly_eval_one (live : F) (w : LateRoundWire F) :
    (compressedRoundPoly live w).eval 1 = live - w.x0 := by
  cases w <;> simp [compressedRoundPoly, LateRoundWire.x0]

@[simp] theorem compressedRoundPoly_sum01 (live : F) (w : LateRoundWire F) :
    (compressedRoundPoly live w).eval 0 + (compressedRoundPoly live w).eval 1 = live := by
  simp

/-! The next two lemmas audit that the remaining sent nodes are also matched
in the production characteristic.  M11a itself only needs the unconditional
`0/1` identities above. -/

theorem quadraticCoeffs_two (y0 y1 y2 : F) (h2 : (2 : F) ≠ 0) :
    (polyOfCoeffs (quadraticCoeffs y0 y1 y2)).eval 2 = y2 := by
  simp [eval_polyOfCoeffs, quadraticCoeffs, Fin.sum_univ_succ]
  field_simp
  ring

theorem cubicCoeffs_two_three (y0 y1 y2 y3 : F) (h2 : (2 : F) ≠ 0)
    (h3 : (3 : F) ≠ 0) :
    (polyOfCoeffs (cubicCoeffs y0 y1 y2 y3)).eval 2 = y2 ∧
      (polyOfCoeffs (cubicCoeffs y0 y1 y2 y3)).eval 3 = y3 := by
  have h6 : (6 : F) ≠ 0 := by
    rw [show (6 : F) = 2 * 3 by norm_num]
    exact mul_ne_zero h2 h3
  constructor
  · simp [eval_polyOfCoeffs, cubicCoeffs, quadraticCoeffs, Fin.sum_univ_succ,
      quadraticCoeffs_two y0 y1 y2 h2]
    field_simp [h2, h3, h6]
    ring
  · simp [eval_polyOfCoeffs, cubicCoeffs, quadraticCoeffs, Fin.sum_univ_succ,
      quadraticCoeffs_two y0 y1 y2 h2]
    field_simp [h2, h3, h6]
    ring

/-! ## Authenticated reconstruction and the late-row prover -/

/-- Evaluate authenticated coefficient values at a public scalar. -/
def evalAuthedCoeffs {m : ℕ} (c : Fin m → Authed F) (t : F) : Authed F :=
  ∑ j : Fin m, t ^ (j : ℕ) • c j

theorem evalAuthedCoeffs_valid {m : ℕ} (c : Fin m → Authed F) (t Δ : F)
    (hc : ∀ j, (c j).Valid Δ) : (evalAuthedCoeffs c t).Valid Δ := by
  unfold evalAuthedCoeffs
  exact Authed.Valid.sum fun j _ => (hc j).smul _

@[simp] theorem evalAuthedCoeffs_x {m : ℕ} (c : Fin m → Authed F) (t : F) :
    (evalAuthedCoeffs c t).x = (polyOfCoeffs fun j => (c j).x).eval t := by
  rw [eval_polyOfCoeffs]
  simp only [evalAuthedCoeffs, Authed.sum_x, Authed.smul_x]
  exact Finset.sum_congr rfl fun j _ => mul_comm _ _

@[simp] theorem evalAuthedCoeffs_m {m : ℕ} (c : Fin m → Authed F) (t : F) :
    (evalAuthedCoeffs c t).m = ∑ j : Fin m, t ^ (j : ℕ) * (c j).m := by
  simp [evalAuthedCoeffs]

@[simp] theorem evalAuthedCoeffs_k {m : ℕ} (c : Fin m → Authed F) (t : F) :
    (evalAuthedCoeffs c t).k = ∑ j : Fin m, t ^ (j : ℕ) * (c j).k := by
  simp [evalAuthedCoeffs]

theorem evalAuthedCoeffs_k_poly {m : ℕ} (c : Fin m → Authed F) (t : F) :
    (evalAuthedCoeffs c t).k = (polyOfCoeffs fun j => (c j).k).eval t := by
  rw [evalAuthedCoeffs_k, eval_polyOfCoeffs]
  exact Finset.sum_congr rfl fun j _ => mul_comm _ _

/-- Authenticated quadratic coefficients, using only public linear
operations on the live value and sent node correlations. -/
noncomputable def quadraticAuthedCoeffs (y0 y1 y2 : Authed F) : Fin 3 → Authed F :=
  let c2 := (2 : F)⁻¹ • (y2 - (2 : F) • y1 + y0)
  vec3 y0 (y1 - y0 - c2) c2

/-- Authenticated cubic coefficients in the same node order as Rust. -/
noncomputable def cubicAuthedCoeffs (y0 y1 y2 y3 : Authed F) : Fin 4 → Authed F :=
  let qc := quadraticAuthedCoeffs y0 y1 y2
  let q3 := evalAuthedCoeffs qc 3
  let c3 := (6 : F)⁻¹ • (y3 - q3)
  vec4 (qc 0) (qc 1 + (2 : F) • c3) (qc 2 - (3 : F) • c3) c3

/-- Exact authenticated evaluation reconstructed from a compressed wire. -/
noncomputable def compressedEvalAuthed (Δ : F) (live : Authed F)
    (w : LateRoundWire F) (t : F) : Authed F :=
  match w with
  | .quadratic g0 g2 =>
      evalAuthedCoeffs
        (quadraticAuthedCoeffs (authedOfPair Δ g0) (live - authedOfPair Δ g0)
          (authedOfPair Δ g2)) t
  | .cubic g0 g2 g3 =>
      evalAuthedCoeffs
        (cubicAuthedCoeffs (authedOfPair Δ g0) (live - authedOfPair Δ g0)
          (authedOfPair Δ g2) (authedOfPair Δ g3)) t

theorem quadraticAuthedCoeffs_valid (Δ : F) {y0 y1 y2 : Authed F}
    (h0 : y0.Valid Δ) (h1 : y1.Valid Δ) (h2 : y2.Valid Δ) :
    ∀ j, (quadraticAuthedCoeffs y0 y1 y2 j).Valid Δ := by
  have hc2 : ((2 : F)⁻¹ • (y2 - (2 : F) • y1 + y0)).Valid Δ :=
    ((h2.sub (h1.smul 2)).add h0).smul _
  intro j
  fin_cases j
  · simpa [quadraticAuthedCoeffs]
  · simpa [quadraticAuthedCoeffs] using (h1.sub h0).sub hc2
  · simpa [quadraticAuthedCoeffs] using hc2

theorem cubicAuthedCoeffs_valid (Δ : F) {y0 y1 y2 y3 : Authed F}
    (h0 : y0.Valid Δ) (h1 : y1.Valid Δ) (h2 : y2.Valid Δ) (h3 : y3.Valid Δ) :
    ∀ j, (cubicAuthedCoeffs y0 y1 y2 y3 j).Valid Δ := by
  have hq : ∀ j, (quadraticAuthedCoeffs y0 y1 y2 j).Valid Δ :=
    quadraticAuthedCoeffs_valid Δ h0 h1 h2
  have hq3 : (evalAuthedCoeffs (quadraticAuthedCoeffs y0 y1 y2) 3).Valid Δ :=
    evalAuthedCoeffs_valid _ _ _ hq
  have hc3 : ((6 : F)⁻¹ •
      (y3 - evalAuthedCoeffs (quadraticAuthedCoeffs y0 y1 y2) 3)).Valid Δ :=
    (h3.sub hq3).smul _
  intro j
  fin_cases j
  · simpa [cubicAuthedCoeffs]
  · simpa [cubicAuthedCoeffs] using (hq 1).add (hc3.smul 2)
  · simpa [cubicAuthedCoeffs] using (hq 2).sub (hc3.smul 3)
  · simpa [cubicAuthedCoeffs] using hc3

theorem compressedEvalAuthed_valid (Δ : F) {live : Authed F} (hlive : live.Valid Δ)
    (w : LateRoundWire F) (t : F) : (compressedEvalAuthed Δ live w t).Valid Δ := by
  cases w with
  | quadratic g0 g2 =>
      apply evalAuthedCoeffs_valid
      apply quadraticAuthedCoeffs_valid Δ
      · exact authedOfPair_valid Δ g0
      · exact hlive.sub (authedOfPair_valid Δ g0)
      · exact authedOfPair_valid Δ g2
  | cubic g0 g2 g3 =>
      apply evalAuthedCoeffs_valid
      apply cubicAuthedCoeffs_valid Δ
      · exact authedOfPair_valid Δ g0
      · exact hlive.sub (authedOfPair_valid Δ g0)
      · exact authedOfPair_valid Δ g2
      · exact authedOfPair_valid Δ g3

@[simp] theorem quadraticAuthedCoeffs_x (y0 y1 y2 : Authed F) (j : Fin 3) :
    (quadraticAuthedCoeffs y0 y1 y2 j).x =
      quadraticCoeffs y0.x y1.x y2.x j := by
  fin_cases j <;> simp [quadraticAuthedCoeffs, quadraticCoeffs, vec3]

@[simp] theorem cubicAuthedCoeffs_x (y0 y1 y2 y3 : Authed F) (j : Fin 4) :
    (cubicAuthedCoeffs y0 y1 y2 y3 j).x =
      cubicCoeffs y0.x y1.x y2.x y3.x j := by
  fin_cases j <;>
    simp [cubicAuthedCoeffs, cubicCoeffs, quadraticAuthedCoeffs_x,
      evalAuthedCoeffs_x, vec4]

@[simp] theorem compressedEvalAuthed_x (Δ : F) (live : Authed F)
    (w : LateRoundWire F) (t : F) :
    (compressedEvalAuthed Δ live w t).x = (compressedRoundPoly live.x w).eval t := by
  cases w <;> simp [compressedEvalAuthed, compressedRoundPoly]

/-- Prefix-adaptive compressed prover.  The type excludes `Delta` and every
coin sampled after the terminal vector. -/
structure LateRowProver (F : Type*) [Field F] (n : ℕ) (d : ℕ → ℕ) (J : ℕ) where
  sigma : F → F
  wire : F → (i : ℕ) → (Fin n → F) → LateRoundWire F
  wire_degree_le : ∀ eta i pre, (wire eta i pre).degree ≤ d i
  late : F → (Fin n → F) → Fin J → F × F
  coeff : F → (Fin n → F) → Fin J → F

variable {n J : ℕ} {d : ℕ → ℕ}

/-- Recursive clear polynomial schedule.  At round `i+1`, the live value is
the preceding reconstructed polynomial evaluated at challenge `pre[i]`.
Thus `g(1)` is not sent and cannot be chosen independently. -/
noncomputable def lateRoundPoly (P : LateRowProver F n d J) (eta : F) :
    (i : ℕ) → (Fin n → F) → Polynomial F
  | 0, pre => compressedRoundPoly (P.sigma eta) (P.wire eta 0 pre)
  | i + 1, pre =>
      let live := if h : i < n then
        (lateRoundPoly P eta i (trunc pre i)).eval (pre ⟨i, h⟩)
      else 0
      compressedRoundPoly live (P.wire eta (i + 1) pre)

theorem lateRoundPoly_natDegree_le (P : LateRowProver F n d J) (eta : F)
    (i : ℕ) (pre : Fin n → F) : (lateRoundPoly P eta i pre).natDegree ≤ d i := by
  cases i with
  | zero =>
      exact (compressedRoundPoly_natDegree_le _ _).trans (P.wire_degree_le eta 0 pre)
  | succ i =>
      exact (compressedRoundPoly_natDegree_le _ _).trans (P.wire_degree_le eta (i + 1) pre)

theorem trunc_trunc_succ (r : Fin n → F) (i : ℕ) :
    trunc (trunc r (i + 1)) i = trunc r i := by
  funext j
  unfold trunc
  by_cases hj : (j : ℕ) < i
  · simp [hj, Nat.lt.step hj]
  · simp [hj]

theorem trunc_succ_apply_self (r : Fin n → F) (i : ℕ) (hi : i < n) :
    trunc r (i + 1) ⟨i, hi⟩ = r ⟨i, hi⟩ := by
  simp [trunc]

/-- The missing node-one value makes the first sumcheck identity
definitionally true. -/
theorem lateRoundPoly_first (P : LateRowProver F n d J) (eta : F)
    (r : Fin n → F) :
    (lateRoundPoly P eta 0 (trunc r 0)).eval 0 +
      (lateRoundPoly P eta 0 (trunc r 0)).eval 1 = P.sigma eta := by
  simp [lateRoundPoly]

/-- Every subsequent reconstructed round sums to the preceding live claim.
This is the exact compressed-wire recursion used by `clearAccepts`. -/
theorem lateRoundPoly_step (P : LateRowProver F n d J) (eta : F)
    (r : Fin n → F) (i : ℕ) (hi : i + 1 < n) :
    (lateRoundPoly P eta (i + 1) (trunc r (i + 1))).eval 0 +
        (lateRoundPoly P eta (i + 1) (trunc r (i + 1))).eval 1 =
      (lateRoundPoly P eta i (trunc r i)).eval
        (r ⟨i, Nat.lt_of_succ_lt hi⟩) := by
  simp [lateRoundPoly, Nat.lt_of_succ_lt hi, trunc_trunc_succ,
    trunc_succ_apply_self]

/-- Recursive authenticated schedule mirroring `lateRoundPoly`. -/
noncomputable def lateEvalAuthed (P : LateRowProver F n d J) (Δ eta : F) :
    (i : ℕ) → (Fin n → F) → F → Authed F
  | 0, pre, t =>
      compressedEvalAuthed Δ (Authed.ofPublic Δ (P.sigma eta)) (P.wire eta 0 pre) t
  | i + 1, pre, t =>
      let live := if h : i < n then
        lateEvalAuthed P Δ eta i (trunc pre i) (pre ⟨i, h⟩)
      else Authed.ofPublic Δ 0
      compressedEvalAuthed Δ live (P.wire eta (i + 1) pre) t

theorem lateEvalAuthed_valid (P : LateRowProver F n d J) (Δ eta : F)
    (i : ℕ) (pre : Fin n → F) (t : F) :
    (lateEvalAuthed P Δ eta i pre t).Valid Δ := by
  induction i generalizing pre t with
  | zero =>
      exact compressedEvalAuthed_valid Δ (Authed.ofPublic_valid Δ _) _ _
  | succ i ih =>
      unfold lateEvalAuthed
      split
      · exact compressedEvalAuthed_valid Δ (ih _ _) _ _
      · exact compressedEvalAuthed_valid Δ (Authed.ofPublic_valid Δ 0) _ _

@[simp] theorem lateEvalAuthed_x (P : LateRowProver F n d J) (Δ eta : F)
    (i : ℕ) (pre : Fin n → F) (t : F) :
    (lateEvalAuthed P Δ eta i pre t).x = (lateRoundPoly P eta i pre).eval t := by
  induction i generalizing pre t with
  | zero => simp [lateEvalAuthed, lateRoundPoly]
  | succ i ih =>
      unfold lateEvalAuthed lateRoundPoly
      split <;> simp [ih]

/-- Public-linear authenticated late terminal. -/
def lateOpeningAuthed (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) : Authed F :=
  ∑ j, P.coeff eta rho j • authedOfPair Δ (P.late eta rho j)

theorem lateOpeningAuthed_valid (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) : (lateOpeningAuthed P Δ eta rho).Valid Δ := by
  unfold lateOpeningAuthed
  exact Authed.Valid.sum fun j _ => (authedOfPair_valid Δ _).smul _

@[simp] theorem lateOpeningAuthed_x (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) :
    (lateOpeningAuthed P Δ eta rho).x =
      ∑ j, P.coeff eta rho j * (P.late eta rho j).1 := by
  simp [lateOpeningAuthed]

/-- The exact `n+1` authenticated row schema for a post-point terminal. -/
noncomputable def lateClaimAt (hn : 0 < n) (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) (j : ℕ) : Authed F :=
  if j = 0 then
    lateEvalAuthed P Δ eta 0 (trunc rho 0) 0 +
      lateEvalAuthed P Δ eta 0 (trunc rho 0) 1 -
      Authed.ofPublic Δ (P.sigma eta)
  else if h : j < n then
    lateEvalAuthed P Δ eta j (trunc rho j) 0 +
      lateEvalAuthed P Δ eta j (trunc rho j) 1 -
      lateEvalAuthed P Δ eta (j - 1) (trunc rho (j - 1))
        (rho ⟨j - 1, by omega⟩)
  else
    lateEvalAuthed P Δ eta (n - 1) (trunc rho (n - 1))
        (rho ⟨n - 1, by omega⟩) -
      lateOpeningAuthed P Δ eta rho

/-- M11a/M1 premise: every late row is a valid MAC, by construction. -/
theorem lateClaimAt_valid (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) (j : Fin (n + 1)) :
    (lateClaimAt hn P Δ eta rho (j : ℕ)).Valid Δ := by
  unfold lateClaimAt
  split
  · exact ((lateEvalAuthed_valid P Δ eta 0 _ 0).add
      (lateEvalAuthed_valid P Δ eta 0 _ 1)).sub (Authed.ofPublic_valid Δ _)
  split
  · exact ((lateEvalAuthed_valid P Δ eta _ _ 0).add
      (lateEvalAuthed_valid P Δ eta _ _ 1)).sub (lateEvalAuthed_valid P Δ eta _ _ _)
  · exact (lateEvalAuthed_valid P Δ eta _ _ _).sub
      (lateOpeningAuthed_valid P Δ eta rho)

/-! ### Pointwise verifier-key reconstruction -/

/-- Key-side quadratic coefficients.  These are computed solely from the
verifier's correlation keys and public scalars. -/
noncomputable def quadraticKeyCoeffs (k0 k1 k2 : F) : Fin 3 → F :=
  quadraticCoeffs k0 k1 k2

/-- Key-side cubic coefficients. -/
noncomputable def cubicKeyCoeffs (k0 k1 k2 k3 : F) : Fin 4 → F :=
  cubicCoeffs k0 k1 k2 k3

@[simp] theorem quadraticAuthedCoeffs_k (y0 y1 y2 : Authed F) (j : Fin 3) :
    (quadraticAuthedCoeffs y0 y1 y2 j).k =
      quadraticKeyCoeffs y0.k y1.k y2.k j := by
  fin_cases j <;>
    simp [quadraticAuthedCoeffs, quadraticKeyCoeffs, quadraticCoeffs, vec3]

@[simp] theorem cubicAuthedCoeffs_k (y0 y1 y2 y3 : Authed F) (j : Fin 4) :
    (cubicAuthedCoeffs y0 y1 y2 y3 j).k =
      cubicKeyCoeffs y0.k y1.k y2.k y3.k j := by
  have hEval :
      (∑ x : Fin 3, (3 : F) ^ (x : ℕ) * quadraticCoeffs y0.k y1.k y2.k x) =
        (polyOfCoeffs (quadraticCoeffs y0.k y1.k y2.k)).eval 3 := by
    rw [eval_polyOfCoeffs]
    exact Finset.sum_congr rfl fun x _ => mul_comm _ _
  fin_cases j <;>
    simp [cubicAuthedCoeffs, cubicKeyCoeffs, cubicCoeffs,
      quadraticAuthedCoeffs_k, quadraticKeyCoeffs, evalAuthedCoeffs_k_poly, hEval]

/-- Public-linear evaluation of one compressed round on verifier keys. -/
noncomputable def compressedEvalKey (Δ liveKey : F) (w : LateRoundWire F) (t : F) : F :=
  match w with
  | .quadratic g0 g2 =>
      (polyOfCoeffs (quadraticKeyCoeffs (keyOf Δ g0) (liveKey - keyOf Δ g0)
        (keyOf Δ g2))).eval t
  | .cubic g0 g2 g3 =>
      (polyOfCoeffs (cubicKeyCoeffs (keyOf Δ g0) (liveKey - keyOf Δ g0)
        (keyOf Δ g2) (keyOf Δ g3))).eval t

theorem compressedEvalAuthed_k_eq_key (Δ : F) (live : Authed F)
    (w : LateRoundWire F) (t : F) :
    (compressedEvalAuthed Δ live w t).k = compressedEvalKey Δ live.k w t := by
  cases w with
  | quadratic g0 g2 =>
      simp only [compressedEvalAuthed, compressedEvalKey, evalAuthedCoeffs_k,
        eval_polyOfCoeffs, quadraticAuthedCoeffs_k, authedOfPair_k,
        Authed.sub_k]
      exact Finset.sum_congr rfl fun j _ => mul_comm _ _
  | cubic g0 g2 g3 =>
      simp only [compressedEvalAuthed, compressedEvalKey, evalAuthedCoeffs_k,
        eval_polyOfCoeffs, cubicAuthedCoeffs_k, authedOfPair_k,
        Authed.sub_k]
      exact Finset.sum_congr rfl fun j _ => mul_comm _ _

/-- Verifier key for one recursively reconstructed evaluation.  Inputs are
exactly the public challenge/scalars and `keyOf Delta` applied to the same
correlation pairs present in `P.wire`. -/
noncomputable def lateEvalVerifierKey (P : LateRowProver F n d J) (Δ eta : F) :
    (i : ℕ) → (Fin n → F) → F → F
  | 0, pre, t =>
      compressedEvalKey Δ (Δ * P.sigma eta) (P.wire eta 0 pre) t
  | i + 1, pre, t =>
      let liveKey := if h : i < n then
        lateEvalVerifierKey P Δ eta i (trunc pre i) (pre ⟨i, h⟩)
      else 0
      compressedEvalKey Δ liveKey (P.wire eta (i + 1) pre) t

/-- The recursive authenticated evaluation's key is reconstructed pointwise
by the verifier expression above. -/
theorem lateEvalAuthed_k_eq_verifier (P : LateRowProver F n d J) (Δ eta : F)
    (i : ℕ) (pre : Fin n → F) (t : F) :
    (lateEvalAuthed P Δ eta i pre t).k = lateEvalVerifierKey P Δ eta i pre t := by
  induction i generalizing pre t with
  | zero =>
      simp [lateEvalAuthed, lateEvalVerifierKey, compressedEvalAuthed_k_eq_key]
  | succ i ih =>
      unfold lateEvalAuthed lateEvalVerifierKey
      split
      · rw [compressedEvalAuthed_k_eq_key, ih]
      · rw [compressedEvalAuthed_k_eq_key]
        simp

/-- Public-linear verifier reconstruction for a late terminal. -/
def lateOpeningVerifierKey (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) : F :=
  ∑ j, P.coeff eta rho j * keyOf Δ (P.late eta rho j)

theorem lateOpeningAuthed_k_eq_verifier (P : LateRowProver F n d J) (Δ eta : F)
    (rho : Fin n → F) :
    (lateOpeningAuthed P Δ eta rho).k = lateOpeningVerifierKey P Δ eta rho := by
  simp [lateOpeningAuthed, lateOpeningVerifierKey, authedOfPair, keyOf]

/-- Pointwise verifier reconstruction of one closing row. -/
noncomputable def lateClaimVerifierKey (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) (j : ℕ) : F :=
  if j = 0 then
    lateEvalVerifierKey P Δ eta 0 (trunc rho 0) 0 +
      lateEvalVerifierKey P Δ eta 0 (trunc rho 0) 1 - Δ * P.sigma eta
  else if h : j < n then
    lateEvalVerifierKey P Δ eta j (trunc rho j) 0 +
      lateEvalVerifierKey P Δ eta j (trunc rho j) 1 -
      lateEvalVerifierKey P Δ eta (j - 1) (trunc rho (j - 1))
        (rho ⟨j - 1, by omega⟩)
  else
    lateEvalVerifierKey P Δ eta (n - 1) (trunc rho (n - 1))
        (rho ⟨n - 1, by omega⟩) - lateOpeningVerifierKey P Δ eta rho

/-- M11a's required pointwise verifier-key mirror.  It takes no supplied key
and no `Delta`-dependent prover pair as a hypothesis. -/
theorem lateClaimAt_k_eq_verifier (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) (j : Fin (n + 1)) :
    (lateClaimAt hn P Δ eta rho (j : ℕ)).k =
      lateClaimVerifierKey hn P Δ eta rho (j : ℕ) := by
  unfold lateClaimAt lateClaimVerifierKey
  split
  · simp [lateEvalAuthed_k_eq_verifier]
  split
  · simp [lateEvalAuthed_k_eq_verifier]
  · simp [lateEvalAuthed_k_eq_verifier, lateOpeningAuthed_k_eq_verifier]

/-! ### Plaintext rows and the blind-to-clear bridge -/

theorem lateClaimAt_x_zero (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) :
    (lateClaimAt hn P Δ eta rho 0).x =
      (lateRoundPoly P eta 0 (trunc rho 0)).eval 0 +
        (lateRoundPoly P eta 0 (trunc rho 0)).eval 1 - P.sigma eta := by
  simp [lateClaimAt]

theorem lateClaimAt_x_mid (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) {j : ℕ} (hj0 : j ≠ 0) (hjn : j < n) :
    (lateClaimAt hn P Δ eta rho j).x =
      (lateRoundPoly P eta j (trunc rho j)).eval 0 +
        (lateRoundPoly P eta j (trunc rho j)).eval 1 -
        (lateRoundPoly P eta (j - 1) (trunc rho (j - 1))).eval
          (rho ⟨j - 1, by omega⟩) := by
  unfold lateClaimAt
  rw [if_neg hj0, dif_pos hjn]
  simp

theorem lateClaimAt_x_last (hn : 0 < n) (P : LateRowProver F n d J)
    (Δ eta : F) (rho : Fin n → F) :
    (lateClaimAt hn P Δ eta rho n).x =
      (lateRoundPoly P eta (n - 1) (trunc rho (n - 1))).eval
          (rho ⟨n - 1, by omega⟩) -
        ∑ j, P.coeff eta rho j * (P.late eta rho j).1 := by
  unfold lateClaimAt
  rw [if_neg (by omega), dif_neg (by omega)]
  simp

/-- M11a: zero plaintexts of the exact authenticated late-row schema imply
the existing clear verifier with the post-`rho` terminal functional. -/
theorem clear_of_late_claims_zero
    (hn : 0 < n) (P : LateRowProver F n d J)
    (eta : F) (rho : Fin n → F)
    (hz : ∀ j : Fin (n + 1),
      (lateClaimAt hn P 0 eta rho (j : ℕ)).x = 0) :
    clearAccepts hn (lateRoundPoly P eta) (P.sigma eta)
      (fun r => ∑ j : Fin J, P.coeff eta r j * (P.late eta r j).1) rho := by
  refine ⟨?_, fun i => ?_, ?_⟩
  · have h0 := hz ⟨0, by omega⟩
    rw [lateClaimAt_x_zero] at h0
    exact sub_eq_zero.mp h0
  · have hi := hz ⟨(i : ℕ) + 1, by omega⟩
    rw [show ((⟨(i : ℕ) + 1, by omega⟩ : Fin (n + 1)) : ℕ) = (i : ℕ) + 1 from rfl,
      lateClaimAt_x_mid hn P 0 eta rho (Nat.succ_ne_zero _) (by omega)] at hi
    simpa using sub_eq_zero.mp hi
  · have hl := hz ⟨n, by omega⟩
    rw [show ((⟨n, by omega⟩ : Fin (n + 1)) : ℕ) = n from rfl,
      lateClaimAt_x_last] at hl
    exact sub_eq_zero.mp hl

/-! ## Clear-level late-claim counting -/

/-- Affine collapse of a two-component claim, with the constant component at
index zero. -/
def affinePair (v : Fin 2 → F) (eta : F) : F := v 0 + eta * v 1

/-- A false two-component vector can agree with the true affine claim at at
most one outer challenge. -/
theorem affinePair_collision_card_le_one [Fintype F] [DecidableEq F]
    (claimed truth : Fin 2 → F) (hfalse : claimed ≠ truth) :
    (univ.filter fun eta : F => affinePair claimed eta = affinePair truth eta).card ≤ 1 := by
  classical
  by_cases h1 : claimed 1 = truth 1
  · have h0 : claimed 0 ≠ truth 0 := by
      intro h0
      apply hfalse
      funext i
      fin_cases i
      · exact h0
      · exact h1
    rw [Finset.card_eq_zero.mpr]
    · exact Nat.zero_le 1
    · refine Finset.filter_eq_empty_iff.mpr fun eta _ heta => ?_
      apply h0
      unfold affinePair at heta
      calc
        claimed 0 = claimed 0 + eta * claimed 1 - eta * claimed 1 := by ring
        _ = truth 0 + eta * truth 1 - eta * claimed 1 := by rw [heta]
        _ = truth 0 := by rw [h1]; ring
  · refine Finset.card_le_one.mpr fun eta heta eta' heta' => ?_
    simp only [mem_filter, mem_univ, true_and] at heta heta'
    have hz : (eta - eta') * (claimed 1 - truth 1) = 0 := by
      calc
        _ = (affinePair claimed eta - affinePair truth eta) -
            (affinePair claimed eta' - affinePair truth eta') := by
              simp only [affinePair]
              ring
        _ = 0 := by rw [heta, heta']; ring
    rcases mul_eq_zero.mp hz with h | h
    · exact sub_eq_zero.mp h
    · exact (h1 (sub_eq_zero.mp h)).elim

/-- M11b: an affine outer challenge compresses a fixed two-component claim
to a post-`rho` terminal vector, after which an arbitrary later sound chain
is composed by slice counting.  No independence between the sumcheck and the
later chain is assumed. -/
theorem affine_late_atoms_then_chain_sound
    [Fintype F] [DecidableEq F]
    {n m J Bup : ℕ} {d : ℕ → ℕ}
    (hn : 0 < n) (hm : 0 < m)
    (claimed truth : Fin 2 → F)
    (hfalse : claimed ≠ truth)
    (roundPoly : F → ℕ → (Fin n → F) → Polynomial F)
    (TR : F → TrueRounds F n d)
    (atom atomTrue coeff : F → (Fin n → F) → Fin J → F)
    (upAccept : F → (Fin n → F) → Finset (Fin m → F))
    (hdeg : ∀ eta i pre, (roundPoly eta i pre).natDegree ≤ d i)
    (htotal : ∀ eta, (TR eta).total = truth 0 + eta * truth 1)
    (hfinal : ∀ eta r,
      (TR eta).finalEval r =
        ∑ j : Fin J, coeff eta r j * atomTrue eta r j)
    (hup : ∀ eta r,
      atom eta r ≠ atomTrue eta r →
        (upAccept eta r).card ≤ Bup * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega :
        F × ((Fin n → F) × (Fin m → F)) =>
      clearAccepts hn (roundPoly Omega.1)
        (claimed 0 + Omega.1 * claimed 1)
        (fun r => ∑ j : Fin J,
          coeff Omega.1 r j * atom Omega.1 r j)
        Omega.2.1 ∧
      Omega.2.2 ∈ upAccept Omega.1 Omega.2.1)).card ≤
      (1 + (Finset.range n).sum d + Bup) *
        Fintype.card F ^ (n + m) := by
  classical
  let collapsed : F → Prop := fun eta => affinePair claimed eta = affinePair truth eta
  let atomsEqual : F → (Fin n → F) → Prop :=
    fun eta r => atom eta r = atomTrue eta r
  let accepts : F → (Fin n → F) → Prop := fun eta r =>
    clearAccepts hn (roundPoly eta) (affinePair claimed eta)
      (fun rr => ∑ j : Fin J, coeff eta rr j * atom eta rr j) r
  have hcollapsed : (univ.filter collapsed).card ≤ 1 :=
    affinePair_collision_card_le_one claimed truth hfalse
  have hsub :
      (univ.filter (fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        accepts Omega.1 Omega.2.1 ∧
          Omega.2.2 ∈ upAccept Omega.1 Omega.2.1)) ⊆
        (univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
          collapsed Omega.1) ∪
        ((univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
          ¬ collapsed Omega.1 ∧ atomsEqual Omega.1 Omega.2.1 ∧
            accepts Omega.1 Omega.2.1 ∧
            Omega.2.2 ∈ upAccept Omega.1 Omega.2.1) ∪
         (univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
          ¬ collapsed Omega.1 ∧ ¬ atomsEqual Omega.1 Omega.2.1 ∧
            Omega.2.2 ∈ upAccept Omega.1 Omega.2.1)) := by
    intro Omega hOmega
    simp only [mem_filter, mem_univ, true_and, mem_union] at hOmega ⊢
    by_cases hc : collapsed Omega.1
    · exact Or.inl hc
    · by_cases ha : atomsEqual Omega.1 Omega.2.1
      · exact Or.inr (Or.inl ⟨hc, ha, hOmega.1, hOmega.2⟩)
      · exact Or.inr (Or.inr ⟨hc, ha, hOmega.2⟩)
  have hcollapseTape :
      (univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        collapsed Omega.1).card ≤
        Fintype.card ((Fin n → F) × (Fin m → F)) := by
    have hle := card_filter_prod_le_left
      (fun Omega : F × ((Fin n → F) × (Fin m → F)) => collapsed Omega.1)
      (d := 1) fun _ => by simpa using hcollapsed
    simpa using hle
  have hroundTape :
      (univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        ¬ collapsed Omega.1 ∧ atomsEqual Omega.1 Omega.2.1 ∧
          accepts Omega.1 Omega.2.1 ∧
          Omega.2.2 ∈ upAccept Omega.1 Omega.2.1).card ≤
        Fintype.card F *
          (((Finset.range n).sum d * Fintype.card F ^ (n - 1)) *
            Fintype.card (Fin m → F)) := by
    refine card_filter_prod_le_right
      (fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        ¬ collapsed Omega.1 ∧ atomsEqual Omega.1 Omega.2.1 ∧
          accepts Omega.1 Omega.2.1 ∧
          Omega.2.2 ∈ upAccept Omega.1 Omega.2.1) fun eta => ?_
    refine card_filter_prod_le_left
      (fun rOmega : (Fin n → F) × (Fin m → F) =>
        ¬ collapsed eta ∧ atomsEqual eta rOmega.1 ∧ accepts eta rOmega.1 ∧
          rOmega.2 ∈ upAccept eta rOmega.1) fun omega => ?_
    refine le_trans (Finset.card_le_card ?_)
      (card_deviation_le (roundPoly eta) (TR eta).g (hdeg eta) (TR eta).deg_le)
    intro r hr
    simp only [mem_filter, mem_univ, true_and] at hr ⊢
    obtain ⟨hnc, hatom, hacc, _⟩ := hr
    have hacc' : clearAccepts hn (roundPoly eta) (affinePair claimed eta)
        (TR eta).finalEval r := by
      refine ⟨hacc.1, hacc.2.1, ?_⟩
      calc
        (roundPoly eta (n - 1) (trunc r (n - 1))).eval
            (r ⟨n - 1, by omega⟩) =
            ∑ j : Fin J, coeff eta r j * atom eta r j := hacc.2.2
        _ = ∑ j : Fin J, coeff eta r j * atomTrue eta r j := by rw [hatom]
        _ = (TR eta).finalEval r := (hfinal eta r).symm
    have hwrong : affinePair claimed eta ≠ (TR eta).total := by
      intro heq
      apply hnc
      unfold collapsed affinePair
      rw [← htotal eta]
      exact heq
    exact exists_deviation hn (roundPoly eta) (TR eta) hacc' hwrong
  have hupTape :
      (univ.filter fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        ¬ collapsed Omega.1 ∧ ¬ atomsEqual Omega.1 Omega.2.1 ∧
          Omega.2.2 ∈ upAccept Omega.1 Omega.2.1).card ≤
        Fintype.card F *
          (Fintype.card (Fin n → F) *
            (Bup * Fintype.card F ^ (m - 1))) := by
    refine card_filter_prod_le_right
      (fun Omega : F × ((Fin n → F) × (Fin m → F)) =>
        ¬ collapsed Omega.1 ∧ ¬ atomsEqual Omega.1 Omega.2.1 ∧
          Omega.2.2 ∈ upAccept Omega.1 Omega.2.1) fun eta => ?_
    refine card_filter_prod_le_right
      (fun rOmega : (Fin n → F) × (Fin m → F) =>
        ¬ collapsed eta ∧ ¬ atomsEqual eta rOmega.1 ∧
          rOmega.2 ∈ upAccept eta rOmega.1) fun r => ?_
    by_cases ha : atomsEqual eta r
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le _)
      exact Finset.filter_eq_empty_iff.mpr fun omega _ h => h.2.1 ha
    · refine le_trans (Finset.card_le_card ?_) (hup eta r ha)
      intro omega homega
      simp only [mem_filter, mem_univ, true_and] at homega ⊢
      exact homega.2.2
  have hcardR : Fintype.card (Fin n → F) = Fintype.card F ^ n := by
    rw [Fintype.card_fun, Fintype.card_fin]
  have hcardOmega : Fintype.card (Fin m → F) = Fintype.card F ^ m := by
    rw [Fintype.card_fun, Fintype.card_fin]
  have hcardProduct : Fintype.card ((Fin n → F) × (Fin m → F)) =
      Fintype.card F ^ (n + m) := by
    rw [Fintype.card_prod, hcardR, hcardOmega, pow_add]
  have hnPow : Fintype.card F * Fintype.card F ^ (n - 1) =
      Fintype.card F ^ n := by
    calc
      _ = Fintype.card F ^ (n - 1) * Fintype.card F := by ring
      _ = Fintype.card F ^ ((n - 1) + 1) := by rw [pow_succ]
      _ = Fintype.card F ^ n := by rw [Nat.sub_add_cancel (by omega)]
  have hmPow : Fintype.card F * Fintype.card F ^ (m - 1) =
      Fintype.card F ^ m := by
    calc
      _ = Fintype.card F ^ (m - 1) * Fintype.card F := by ring
      _ = Fintype.card F ^ ((m - 1) + 1) := by rw [pow_succ]
      _ = Fintype.card F ^ m := by rw [Nat.sub_add_cancel (by omega)]
  have hroundNorm : Fintype.card F *
      (((Finset.range n).sum d * Fintype.card F ^ (n - 1)) *
        Fintype.card (Fin m → F)) =
      (Finset.range n).sum d * Fintype.card F ^ (n + m) := by
    rw [hcardOmega]
    calc
      _ = (Finset.range n).sum d *
          (Fintype.card F * Fintype.card F ^ (n - 1)) *
            Fintype.card F ^ m := by ring
      _ = (Finset.range n).sum d * Fintype.card F ^ n *
            Fintype.card F ^ m := by rw [hnPow]
      _ = _ := by rw [pow_add]; ring
  have hupNorm : Fintype.card F *
      (Fintype.card (Fin n → F) *
        (Bup * Fintype.card F ^ (m - 1))) =
      Bup * Fintype.card F ^ (n + m) := by
    rw [hcardR]
    calc
      _ = Bup * Fintype.card F ^ n *
          (Fintype.card F * Fintype.card F ^ (m - 1)) := by ring
      _ = Bup * Fintype.card F ^ n * Fintype.card F ^ m := by rw [hmPow]
      _ = _ := by rw [pow_add]; ring
  refine le_trans (Finset.card_le_card hsub)
    (le_trans (Finset.card_union_le _ _)
      (le_trans (Nat.add_le_add hcollapseTape
        (Finset.card_union_le _ _)) ?_))
  refine le_trans (Nat.add_le_add (Nat.le_of_eq hcardProduct)
      (Nat.add_le_add hroundTape hupTape)) ?_
  rw [hroundNorm, hupNorm, add_mul]
  apply Nat.le_of_eq
  ring

/-- M11c: one shared fresh `t` collapses every fixed child pair at once.  If
the full vector is false, the equality event has one root irrespective of
`C`; off that root the supplied later-chain bound applies. -/
theorem shared_pair_collapse_then_chain_sound
    [Fintype F] [DecidableEq F]
    {C m B_after : ℕ} (hm : 0 < m)
    (pair pairTrue : Fin C → Fin 2 → F)
    (hfalse : pair ≠ pairTrue)
    (after : F → Finset (Fin m → F))
    (hafter : ∀ t,
      (fun c => pair c 0 + (pair c 1 - pair c 0) * t) ≠
        (fun c => pairTrue c 0 + (pairTrue c 1 - pairTrue c 0) * t) →
      (after t).card ≤ B_after * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega : F × (Fin m → F) =>
      Omega.2 ∈ after Omega.1)).card ≤
      (1 + B_after) * Fintype.card F ^ m := by
  classical
  let collapse : (Fin C → Fin 2 → F) → F → Fin C → F :=
    fun p t c => p c 0 + (p c 1 - p c 0) * t
  let collided : F → Prop := fun t => collapse pair t = collapse pairTrue t
  have hcollided : (univ.filter collided).card ≤ 1 := by
    obtain ⟨c, hc⟩ := Function.ne_iff.mp hfalse
    have hpair : pair c ≠ pairTrue c := hc
    let affineCoeffs : (Fin 2 → F) → Fin 2 → F :=
      fun p => vec2 (p 0) (p 1 - p 0)
    have hacfalse : affineCoeffs (pair c) ≠ affineCoeffs (pairTrue c) := by
      intro heq
      apply hpair
      funext b
      fin_cases b
      · exact congrFun heq 0
      · have hslope := congrFun heq 1
        have hbase := congrFun heq 0
        simp only [affineCoeffs, vec2_zero] at hbase
        simp only [affineCoeffs, vec2_one] at hslope
        calc
          pair c 1 = (pair c 1 - pair c 0) + pair c 0 := by ring
          _ = (pairTrue c 1 - pairTrue c 0) + pairTrue c 0 := by rw [hslope, hbase]
          _ = pairTrue c 1 := by ring
    have hle := affinePair_collision_card_le_one
      (affineCoeffs (pair c)) (affineCoeffs (pairTrue c)) hacfalse
    refine le_trans (Finset.card_le_card ?_) hle
    intro t ht
    simp only [mem_filter, mem_univ, true_and] at ht ⊢
    have hcEq := congrFun ht c
    unfold collapse at hcEq
    unfold affinePair affineCoeffs
    simpa [mul_comm] using hcEq
  have hsub :
      (univ.filter fun Omega : F × (Fin m → F) => Omega.2 ∈ after Omega.1) ⊆
        (univ.filter fun Omega : F × (Fin m → F) => collided Omega.1) ∪
          (univ.filter fun Omega : F × (Fin m → F) =>
            ¬ collided Omega.1 ∧ Omega.2 ∈ after Omega.1) := by
    intro Omega hOmega
    simp only [mem_filter, mem_univ, true_and, mem_union] at hOmega ⊢
    by_cases hc : collided Omega.1
    · exact Or.inl hc
    · exact Or.inr ⟨hc, hOmega⟩
  have hcollisionTape :
      (univ.filter fun Omega : F × (Fin m → F) => collided Omega.1).card ≤
        Fintype.card (Fin m → F) := by
    have hle := card_filter_prod_le_left
      (fun Omega : F × (Fin m → F) => collided Omega.1) (d := 1) fun _ => by
        simpa using hcollided
    simpa using hle
  have hlive :
      (univ.filter fun Omega : F × (Fin m → F) =>
          ¬ collided Omega.1 ∧ Omega.2 ∈ after Omega.1).card ≤
        Fintype.card F * (B_after * Fintype.card F ^ (m - 1)) := by
    refine card_filter_prod_le_right
      (fun Omega : F × (Fin m → F) =>
        ¬ collided Omega.1 ∧ Omega.2 ∈ after Omega.1) fun t => ?_
    by_cases hc : collided t
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le _)
      exact Finset.filter_eq_empty_iff.mpr fun omega _ h => h.1 hc
    · refine le_trans (Finset.card_le_card ?_) (hafter t ?_)
      · intro omega homega
        simp only [mem_filter, mem_univ, true_and] at homega ⊢
        exact homega.2
      · exact hc
  refine le_trans (Finset.card_le_card hsub)
    (le_trans (Finset.card_union_le _ _)
      (le_trans (Nat.add_le_add hcollisionTape hlive) ?_))
  have hcardFun : Fintype.card (Fin m → F) = Fintype.card F ^ m := by
    rw [Fintype.card_fun, Fintype.card_fin]
  have hpow : Fintype.card F * (B_after * Fintype.card F ^ (m - 1)) =
      B_after * Fintype.card F ^ m := by
    calc
      _ = B_after * (Fintype.card F ^ (m - 1) * Fintype.card F) := by ring
      _ = B_after * Fintype.card F ^ ((m - 1) + 1) := by rw [pow_succ]
      _ = B_after * Fintype.card F ^ m := by rw [Nat.sub_add_cancel (by omega)]
  rw [hcardFun, hpow, add_mul]
  apply Nat.le_of_eq
  ring

/-! ## Concrete `layer_leaf_ones_aux` full-vector instantiation -/

/-- The complete pre-`t` child vector returned by the Rust leaf: first the
`p` pair, then the `q` pair, then every auxiliary column pair. -/
structure FullLeafPairs (F : Type*) (nCols : ℕ) where
  p : Fin 2 → F
  q : Fin 2 → F
  col : Fin nCols → Fin 2 → F

/-- Exact flattening order with `C = 2 + nCols`. -/
def fullLeafPair {nCols : ℕ} (s : FullLeafPairs F nCols) :
    Fin (2 + nCols) → Fin 2 → F :=
  fun c b =>
    if h0 : c.val = 0 then s.p b
    else if h1 : c.val = 1 then s.q b
    else s.col ⟨c.val - 2, by omega⟩ b

@[simp] theorem fullLeafPair_p {nCols : ℕ} (s : FullLeafPairs F nCols) :
    fullLeafPair s 0 = s.p := by
  funext b
  simp [fullLeafPair]

@[simp] theorem fullLeafPair_q {nCols : ℕ} (s : FullLeafPairs F nCols) :
    fullLeafPair s ⟨1, by omega⟩ = s.q := by
  funext b
  simp [fullLeafPair]

@[simp] theorem fullLeafPair_col {nCols : ℕ} (s : FullLeafPairs F nCols)
    (ci : Fin nCols) :
    fullLeafPair s ⟨ci.val + 2, by omega⟩ = s.col ci := by
  funext b
  simp [fullLeafPair, Fin.ext_iff]

theorem fullLeafPair_card {nCols : ℕ} :
    Fintype.card (Fin (2 + nCols)) = 2 + nCols := Fintype.card_fin _

/-- LSB-first equality polynomial used by `mle::eq_points`. -/
def eqPoint {l : ℕ} (point rho : Fin l → F) : F :=
  ∏ i, (point i * rho i + point i * rho i - point i - rho i + 1)

/-- One low-variable fold, exactly `lo + t*(hi-lo)`. -/
def pairFold (pair : Fin 2 → F) (t : F) : F :=
  pair 0 + (pair 1 - pair 0) * t

/-- Recursive multilinear evaluation with coordinate zero folded first.  The
cube index and challenge index share that LSB-first order. -/
noncomputable def lsbMle : {l : ℕ} →
    ((Fin l → Fin 2) → F) → (Fin l → F) → F
  | 0, values, _ => values (fun i => Fin.elim0 i)
  | l + 1, values, point =>
      let tail : Fin l → F := fun i => point i.succ
      let half0 : (Fin l → Fin 2) → F :=
        fun bits => values (Fin.cases 0 bits)
      let half1 : (Fin l → Fin 2) → F :=
        fun bits => values (Fin.cases 1 bits)
      (1 - point 0) * lsbMle half0 tail + point 0 * lsbMle half1 tail

/-- The two tail evaluations produced before folding the new LSB. -/
noncomputable def lsbMlePair {l : ℕ}
    (values : (Fin (l + 1) → Fin 2) → F) (rho : Fin l → F) : Fin 2 → F :=
  fun b => lsbMle (fun bits => values (Fin.cases b bits)) rho

/-- The Rust child equation is exactly the LSB-first MLE at `(t,rho)`. -/
theorem lsbMle_cons {l : ℕ} (values : (Fin (l + 1) → Fin 2) → F)
    (t : F) (rho : Fin l → F) :
    lsbMle values (Fin.cases t rho) = pairFold (lsbMlePair values rho) t := by
  simp [lsbMle, lsbMlePair, pairFold]
  ring

/-- Fixed-before-`mu` data for the concrete auxiliary leaf.  `baseClaim` and
`externalClaim` are malicious/live claims; `baseTotal` and `columnMle` are
their distinct true semantics. -/
structure LayerLeafOnesAuxInput (F : Type*) (nCols : ℕ) where
  baseClaim : F
  externalClaim : F
  baseTotal : F
  columnMle : F
  point0 : F
  cpref : F
  lambda : F
  z0 : F
  z1 : F
  z2 : F
  pairs : FullLeafPairs F nCols

/-- Algebraic outputs of the concrete Rust leaf boundary. -/
structure LayerLeafOnesAuxModel (F : Type*) (nCols : ℕ) where
  sigma : F
  total : F
  terminal : F
  children : Fin (2 + nCols) → Fin 2 → F

/-- Lean mirror of `logup.rs::layer_leaf_ones_aux` at its layer boundary.
All `p/q/column` pairs remain separate until the later shared `t`. -/
def layerLeafOnesAux {nCols l : ℕ} (input : LayerLeafOnesAuxInput F nCols)
    (mu : F) (ci : Fin nCols) (pointTail rho : Fin l → F) :
    LayerLeafOnesAuxModel F nCols where
  sigma := input.baseClaim + mu * input.externalClaim
  total := input.baseTotal + mu * input.columnMle
  terminal :=
    input.cpref * (input.lambda * (input.z0 + input.z1) + input.z2) +
      eqPoint pointTail rho *
        (mu * (1 - input.point0) * input.pairs.col ci 0 +
          mu * input.point0 * input.pairs.col ci 1)
  children := fullLeafPair input.pairs

@[simp] theorem layerLeafOnesAux_sigma {nCols l : ℕ}
    (input : LayerLeafOnesAuxInput F nCols) (mu : F) (ci : Fin nCols)
    (pointTail rho : Fin l → F) :
    (layerLeafOnesAux input mu ci pointTail rho).sigma =
      input.baseClaim + mu * input.externalClaim := rfl

@[simp] theorem layerLeafOnesAux_total {nCols l : ℕ}
    (input : LayerLeafOnesAuxInput F nCols) (mu : F) (ci : Fin nCols)
    (pointTail rho : Fin l → F) :
    (layerLeafOnesAux input mu ci pointTail rho).total =
      input.baseTotal + mu * input.columnMle := rfl

/-- Exact terminal formula, including the selected column's two distinct
halves and the tail equality factor. -/
@[simp] theorem layerLeafOnesAux_terminal {nCols l : ℕ}
    (input : LayerLeafOnesAuxInput F nCols) (mu : F) (ci : Fin nCols)
    (pointTail rho : Fin l → F) :
    (layerLeafOnesAux input mu ci pointTail rho).terminal =
      input.cpref * (input.lambda * (input.z0 + input.z1) + input.z2) +
        eqPoint pointTail rho *
          (mu * (1 - input.point0) * input.pairs.col ci 0 +
            mu * input.point0 * input.pairs.col ci 1) := rfl

@[simp] theorem layerLeafOnesAux_children {nCols l : ℕ}
    (input : LayerLeafOnesAuxInput F nCols) (mu : F) (ci : Fin nCols)
    (pointTail rho : Fin l → F) :
    (layerLeafOnesAux input mu ci pointTail rho).children =
      fullLeafPair input.pairs := rfl

/-- Child folding keeps all `C=2+nCols` pairs and samples `t` only after that
vector is fixed. -/
def layerLeafChildrenAt {nCols : ℕ} (s : FullLeafPairs F nCols) (t : F) :
    Fin (2 + nCols) → F :=
  fun c => pairFold (fullLeafPair s c) t

@[simp] theorem layerLeafChildrenAt_apply {nCols : ℕ}
    (s : FullLeafPairs F nCols) (t : F) (c : Fin (2 + nCols)) :
    layerLeafChildrenAt s t c =
      fullLeafPair s c 0 + t * (fullLeafPair s c 1 - fullLeafPair s c 0) := by
  simp [layerLeafChildrenAt, pairFold, mul_comm]

/-- Falsity of the external claim makes the affine vectors unequal even if
the malicious base claim is also wrong; no base-claim equality is assumed. -/
theorem layerLeaf_claim_pair_ne_of_external
    {nCols : ℕ} (input : LayerLeafOnesAuxInput F nCols)
    (hExternal : input.externalClaim ≠ input.columnMle) :
    vec2 input.baseClaim input.externalClaim ≠
      vec2 input.baseTotal input.columnMle := by
  intro h
  apply hExternal
  simpa using congrFun h 1

/-- Concrete M11c instantiation at exactly `C=2+nCols`. -/
theorem layer_leaf_ones_aux_full_vector_collapse_sound
    [Fintype F] [DecidableEq F]
    {nCols m B_after : ℕ} (hm : 0 < m)
    (pair pairTrue : FullLeafPairs F nCols)
    (hfalse : fullLeafPair pair ≠ fullLeafPair pairTrue)
    (after : F → Finset (Fin m → F))
    (hafter : ∀ t,
      layerLeafChildrenAt pair t ≠ layerLeafChildrenAt pairTrue t →
        (after t).card ≤ B_after * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega : F × (Fin m → F) =>
      Omega.2 ∈ after Omega.1)).card ≤
      (1 + B_after) * Fintype.card F ^ m := by
  apply shared_pair_collapse_then_chain_sound hm
    (fullLeafPair pair) (fullLeafPair pairTrue) hfalse after
  intro t ht
  apply hafter t
  intro heq
  apply ht
  funext c
  have hc := congrFun heq c
  simpa [layerLeafChildrenAt, pairFold, mul_comm] using hc

/-! ### Exact cubic wire specialization -/

/-- Data sent by every degree-three auxiliary leaf round. -/
structure LayerLeafAuxWireProver (F : Type*) (n J : ℕ) where
  inputSigma : F → F
  g0 : F → ℕ → (Fin n → F) → F × F
  g2 : F → ℕ → (Fin n → F) → F × F
  g3 : F → ℕ → (Fin n → F) → F × F
  late : F → (Fin n → F) → Fin J → F × F
  coeff : F → (Fin n → F) → Fin J → F

/-- Concrete constructor tying the live initial claim to the two fixed leaf
claims before `mu` is sampled. -/
def layerLeafAuxWireProverOfInput {nCols n J : ℕ}
    (input : LayerLeafOnesAuxInput F nCols)
    (g0 g2 g3 : F → ℕ → (Fin n → F) → F × F)
    (late : F → (Fin n → F) → Fin J → F × F)
    (coeff : F → (Fin n → F) → Fin J → F) :
    LayerLeafAuxWireProver F n J where
  inputSigma mu := input.baseClaim + mu * input.externalClaim
  g0 := g0
  g2 := g2
  g3 := g3
  late := late
  coeff := coeff

@[simp] theorem layerLeafAuxWireProverOfInput_sigma {nCols n J : ℕ}
    (input : LayerLeafOnesAuxInput F nCols)
    (g0 g2 g3 : F → ℕ → (Fin n → F) → F × F)
    (late : F → (Fin n → F) → Fin J → F × F)
    (coeff : F → (Fin n → F) → Fin J → F) (mu : F) :
    (layerLeafAuxWireProverOfInput input g0 g2 g3 late coeff).inputSigma mu =
      input.baseClaim + mu * input.externalClaim := rfl

/-- Embed the exact cubic wire into M11a's late-row model. -/
def LayerLeafAuxWireProver.toLate {n J : ℕ}
    (P : LayerLeafAuxWireProver F n J) :
    LateRowProver F n (fun _ => 3) J where
  sigma := P.inputSigma
  wire eta i pre := .cubic (P.g0 eta i pre) (P.g2 eta i pre) (P.g3 eta i pre)
  wire_degree_le := by intros; simp [LateRoundWire.degree]
  late := P.late
  coeff := P.coeff

/-- Unfolding the concrete auxiliary wire yields degree at most three in
every round. -/
theorem layer_leaf_ones_aux_round_degree_le_three {n J : ℕ}
    (P : LayerLeafAuxWireProver F n J) (mu : F) (i : ℕ) (pre : Fin n → F) :
    (lateRoundPoly P.toLate mu i pre).natDegree ≤ 3 :=
  lateRoundPoly_natDegree_le P.toLate mu i pre

/-- Once the exact compressed `0/2/3` wires are reconstructed, all first and
middle verifier equations are the `clearAccepts` recursion; only the concrete
late-terminal equation remains. -/
theorem layer_leaf_ones_aux_clearAccepts_iff_terminal
    {n J : ℕ} (hn : 0 < n) (P : LayerLeafAuxWireProver F n J)
    (mu : F) (rho : Fin n → F) :
    clearAccepts hn (lateRoundPoly P.toLate mu) (P.inputSigma mu)
      (fun r => ∑ j : Fin J, P.coeff mu r j * (P.late mu r j).1) rho ↔
      (lateRoundPoly P.toLate mu (n - 1) (trunc rho (n - 1))).eval
          (rho ⟨n - 1, by omega⟩) =
        ∑ j : Fin J, P.coeff mu rho j * (P.late mu rho j).1 := by
  constructor
  · exact fun h => h.2.2
  · intro hlast
    refine ⟨lateRoundPoly_first P.toLate mu rho, ?_, hlast⟩
    intro i
    exact lateRoundPoly_step P.toLate mu rho i (by omega)

/-- Concrete M11b instantiation for the leaf's malicious/live claim pair and
its distinct true pair.  The premise `hExternal` alone supplies falsity; the
base claims remain unrestricted. -/
theorem layer_leaf_ones_aux_affine_then_chain_sound
    [Fintype F] [DecidableEq F]
    {nCols n m J Bup : ℕ} {d : ℕ → ℕ}
    (hn : 0 < n) (hm : 0 < m)
    (input : LayerLeafOnesAuxInput F nCols)
    (hExternal : input.externalClaim ≠ input.columnMle)
    (roundPoly : F → ℕ → (Fin n → F) → Polynomial F)
    (TR : F → TrueRounds F n d)
    (atom atomTrue coeff : F → (Fin n → F) → Fin J → F)
    (upAccept : F → (Fin n → F) → Finset (Fin m → F))
    (hdeg : ∀ mu i pre, (roundPoly mu i pre).natDegree ≤ d i)
    (htotal : ∀ mu,
      (TR mu).total = input.baseTotal + mu * input.columnMle)
    (hfinal : ∀ mu r,
      (TR mu).finalEval r =
        ∑ j : Fin J, coeff mu r j * atomTrue mu r j)
    (hup : ∀ mu r,
      atom mu r ≠ atomTrue mu r →
        (upAccept mu r).card ≤ Bup * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega :
        F × ((Fin n → F) × (Fin m → F)) =>
      clearAccepts hn (roundPoly Omega.1)
        (input.baseClaim + Omega.1 * input.externalClaim)
        (fun r => ∑ j : Fin J,
          coeff Omega.1 r j * atom Omega.1 r j)
        Omega.2.1 ∧
      Omega.2.2 ∈ upAccept Omega.1 Omega.2.1)).card ≤
      (1 + (Finset.range n).sum d + Bup) *
        Fintype.card F ^ (n + m) := by
  exact affine_late_atoms_then_chain_sound hn hm
    (vec2 input.baseClaim input.externalClaim)
    (vec2 input.baseTotal input.columnMle)
    (layerLeaf_claim_pair_ne_of_external input hExternal)
    roundPoly TR atom atomTrue coeff upAccept hdeg
    (by simpa using htotal) hfinal hup

end VoltaZk

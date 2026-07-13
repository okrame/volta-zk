import VoltaZk.Mac
import VoltaZk.Counting

/-!
# Soundness of `Π_ZeroOpen` / `Π_ZeroBatch` (M3a)

Dual game to `VoltaZk/ZeroBatch.lean`: corrupt prover `P*`, honest verifier.

Modeling (mirror of the deterministic-`V*` notes for the ZK theorem). In the
corrupted-prover branch of `F_sVOLE` the adversary chooses each correlation
pair `(u, m)` and the functionality sets `k = m + u·Δ`; after the `Π_Auth`
correction `δ` the adversary is committed, for every authenticated value, to
a plaintext `x = u + δ` and tag `m` it knows, with verifier key
`k = m + Δ·x`. WLOG we therefore model the adversary as *directly* choosing
`(x, m)` pairs. Its view contains no information about `Δ` (it sees only its
own `(u, m)` choices and public challenges), so a deterministic `P*` is a
family of messages indexed by the public challenges only; the honest
verifier's randomness — `Δ` and the batching challenge `χ` — is the sample
space, and soundness statements are cardinality bounds over it.

Sub-lemmas of the M3 target proved here:

* `zeroOpen_sound` — **MAC unforgeability**: opening a claim with nonzero
  plaintext requires guessing `Δ` (at most one key accepts a forged message);
* `zeroBatch_sound` — **RLC + opening soundness**: if the closed claim list
  contains a nonzero plaintext, the batched opening verifies on at most a
  `2/|F|` fraction of the verifier randomness `(Δ, χ)` — one `1/|F|` for the
  batching challenge collapsing the list (Schwartz–Zippel), one for the
  forged opening.
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- Verifier key of an adversarially authenticated value: the corrupted-P
branch of `F_sVOLE` determines `k = m + Δ·x` from the adversary's chosen
plaintext/tag pair `(x, m)`. -/
def keyOf (Δ : F) (vm : F × F) : F := vm.2 + Δ * vm.1

/-- The authenticated value induced by an adversary pair. -/
def authedOfPair (Δ : F) (vm : F × F) : Authed F := ⟨vm.1, vm.2, keyOf Δ vm⟩

omit [Fintype F] [DecidableEq F] in
theorem authedOfPair_valid (Δ : F) (vm : F × F) : (authedOfPair Δ vm).Valid Δ := rfl

omit [Fintype F] [DecidableEq F] in
@[simp] theorem authedOfPair_x (Δ : F) (vm : F × F) : (authedOfPair Δ vm).x = vm.1 := rfl

omit [Fintype F] [DecidableEq F] in
@[simp] theorem authedOfPair_m (Δ : F) (vm : F × F) : (authedOfPair Δ vm).m = vm.2 := rfl

omit [Fintype F] [DecidableEq F] in
@[simp] theorem authedOfPair_k (Δ : F) (vm : F × F) : (authedOfPair Δ vm).k = keyOf Δ vm := rfl

/-- **`Π_ZeroOpen` unforgeability.** For an authenticated value with nonzero
plaintext and any forged opening message (chosen without seeing `Δ`), at most
one session key accepts: soundness error `1/|F|`. -/
theorem zeroOpen_sound (vm : F × F) (hx : vm.1 ≠ 0) (msg : F) :
    (univ.filter fun Δ : F => msg = keyOf Δ vm).card ≤ 1 :=
  card_linear_solution_le_one vm.2 msg vm.1 hx

omit [Fintype F] [DecidableEq F] in
/-- Bilinearity of the batched key: `k_Z = m_Z + Δ·x_Z` where `m_Z, x_Z` are
the χ-combinations of the adversary's tags and plaintexts. -/
theorem keyOf_rlc_expand {T : ℕ} (z : Fin T → F × F) (Δ : F) (χ : Fin T → F) :
    ∑ j, χ j * keyOf Δ (z j)
      = (∑ j, χ j * (z j).2) + Δ * ∑ j, χ j * (z j).1 := by
  rw [Finset.mul_sum, ← Finset.sum_add_distrib]
  exact Finset.sum_congr rfl fun j _ => by unfold keyOf; ring

/-- **`Π_ZeroBatch` soundness (M3a).** If some claim in the closed list has a
nonzero plaintext, then for every adversary opening strategy `msg` (a function
of the public `χ`, never of `Δ`), the batched zero-opening verifies for at
most `2·|F|^T` of the `|F|^(T+1)` verifier random tapes `(Δ, χ)` — soundness
error `≤ 2/|F|`. -/
theorem zeroBatch_sound {T : ℕ} (z : Fin T → F × F) {j₀ : Fin T} (hz : (z j₀).1 ≠ 0)
    (msg : (Fin T → F) → F) :
    (univ.filter fun Δχ : F × (Fin T → F) =>
        msg Δχ.2 = ∑ j, Δχ.2 j * keyOf Δχ.1 (z j)).card
      ≤ 2 * Fintype.card F ^ T := by
  have hT : 0 < T := j₀.pos
  -- Split on whether the batching challenge collapsed the plaintext RLC.
  have hsub : (univ.filter fun Δχ : F × (Fin T → F) =>
        msg Δχ.2 = ∑ j, Δχ.2 j * keyOf Δχ.1 (z j))
      ⊆ (univ.filter fun Δχ : F × (Fin T → F) => ∑ j, Δχ.2 j * (z j).1 = 0)
        ∪ (univ.filter fun Δχ : F × (Fin T → F) =>
            (∑ j, Δχ.2 j * (z j).1 ≠ 0)
              ∧ msg Δχ.2 = ∑ j, Δχ.2 j * keyOf Δχ.1 (z j)) := by
    intro Δχ h
    simp only [mem_filter, mem_univ, true_and, mem_union] at h ⊢
    by_cases hxz : ∑ j, Δχ.2 j * (z j).1 = 0
    · exact Or.inl hxz
    · exact Or.inr ⟨hxz, h⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  -- RLC branch: for every Δ, at most |F|^(T-1) challenges χ kill the RLC.
  have h1 : (univ.filter fun Δχ : F × (Fin T → F) => ∑ j, Δχ.2 j * (z j).1 = 0).card
      ≤ Fintype.card F * Fintype.card F ^ (T - 1) :=
    card_filter_prod_le_right (fun Δχ : F × (Fin T → F) => ∑ j, Δχ.2 j * (z j).1 = 0)
      fun _ => card_linearForm_zero_le (fun j => (z j).1) hz
  -- Forgery branch: for every χ with live RLC, at most one Δ accepts.
  have h2 : (univ.filter fun Δχ : F × (Fin T → F) =>
        (∑ j, Δχ.2 j * (z j).1 ≠ 0)
          ∧ msg Δχ.2 = ∑ j, Δχ.2 j * keyOf Δχ.1 (z j)).card
      ≤ 1 * Fintype.card F ^ T := by
    rw [show (1 : ℕ) * Fintype.card F ^ T = 1 * Fintype.card (Fin T → F) by
      rw [Fintype.card_fun, Fintype.card_fin]]
    refine card_filter_prod_le_left
      (fun Δχ : F × (Fin T → F) => (∑ j, Δχ.2 j * (z j).1 ≠ 0)
        ∧ msg Δχ.2 = ∑ j, Δχ.2 j * keyOf Δχ.1 (z j)) fun χ => ?_
    by_cases hxz : ∑ j, χ j * (z j).1 = 0
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le 1)
      exact Finset.filter_eq_empty_iff.mpr fun Δ _ h => h.1 hxz
    · refine le_trans (Finset.card_le_card fun Δ hΔ => ?_)
        (card_linear_solution_le_one (∑ j, χ j * (z j).2) (msg χ)
          (∑ j, χ j * (z j).1) hxz)
      simp only [mem_filter, mem_univ, true_and] at hΔ ⊢
      rw [← keyOf_rlc_expand]
      exact hΔ.2
  calc _ ≤ Fintype.card F * Fintype.card F ^ (T - 1) + 1 * Fintype.card F ^ T :=
        Nat.add_le_add h1 h2
    _ = 2 * Fintype.card F ^ T := by
        rw [one_mul, ← pow_succ', Nat.sub_add_cancel hT, two_mul]

/-- **Scalar-power `Π_ZeroBatch` soundness (implementation theorem).**
The Rust wire format derives all list weights as `χ^(j+1)` from one field
challenge. If a closed list of length `T` contains a nonzero plaintext, at
most `(T+1)·|F|` of the `|F|²` verifier tapes `(Δ, χ)` accept: at most
`T·|F|` tapes collapse the nonzero RLC polynomial and at most `|F|` tapes
forge the surviving MAC opening. -/
theorem zeroBatch_sound_scalar {T : ℕ} (z : Fin T → F × F) {j₀ : Fin T}
    (hz : (z j₀).1 ≠ 0) (msg : F → F) :
    (univ.filter fun Δχ : F × F =>
        msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) * keyOf Δχ.1 (z j)).card
      ≤ (T + 1) * Fintype.card F := by
  have hsub : (univ.filter fun Δχ : F × F =>
        msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) * keyOf Δχ.1 (z j))
      ⊆ (univ.filter fun Δχ : F × F =>
            ∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 = 0)
        ∪ (univ.filter fun Δχ : F × F =>
            (∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 ≠ 0)
              ∧ msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) * keyOf Δχ.1 (z j)) := by
    intro Δχ h
    simp only [mem_filter, mem_univ, true_and, mem_union] at h ⊢
    by_cases hxz : ∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 = 0
    · exact Or.inl hxz
    · exact Or.inr ⟨hxz, h⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _) ?_)
  have h1 : (univ.filter fun Δχ : F × F =>
        ∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 = 0).card
      ≤ Fintype.card F * T :=
    card_filter_prod_le_right
      (fun Δχ : F × F => ∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 = 0)
      fun _ => card_scalarRlc_zero_le (fun j => (z j).1) hz
  have h2 : (univ.filter fun Δχ : F × F =>
        (∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 ≠ 0)
          ∧ msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) * keyOf Δχ.1 (z j)).card
      ≤ 1 * Fintype.card F := by
    refine card_filter_prod_le_left
      (fun Δχ : F × F =>
        (∑ j, Δχ.2 ^ (j.val + 1) * (z j).1 ≠ 0)
          ∧ msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) * keyOf Δχ.1 (z j)) fun χ => ?_
    by_cases hxz : ∑ j, χ ^ (j.val + 1) * (z j).1 = 0
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le 1)
      exact Finset.filter_eq_empty_iff.mpr fun Δ _ h => h.1 hxz
    · refine le_trans (Finset.card_le_card fun Δ hΔ => ?_)
        (card_linear_solution_le_one
          (∑ j, χ ^ (j.val + 1) * (z j).2) (msg χ)
          (∑ j, χ ^ (j.val + 1) * (z j).1) hxz)
      simp only [mem_filter, mem_univ, true_and] at hΔ ⊢
      rw [← keyOf_rlc_expand z Δ (fun j => χ ^ (j.val + 1))]
      exact hΔ.2
  calc
    _ ≤ Fintype.card F * T + 1 * Fintype.card F := Nat.add_le_add h1 h2
    _ = (T + 1) * Fintype.card F := by ring

end VoltaZk

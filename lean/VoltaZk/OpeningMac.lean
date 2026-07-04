import VoltaZk.ZeroBatchSound
import VoltaZk.BlindSumcheckSound

/-!
# M9 — PCS opening-into-MAC interface

`docs/private-weights-pcs.md` (decision 2026-07-04): with private weights, the
blind sumcheck's final weight evaluation `W̃(r)` is not computed by the
verifier but *transferred* as a MAC-authenticated value whose consistency with
the static commitment `C_W` is certified by a (ZK) PCS opening.

This file gives the interface lemma composing that transfer with the M3 chain:

* the PCS itself is **abstract** — `PCSOpening` records only its accept bit,
  the authenticated output pair, and the committed polynomial's true
  evaluation at the (fixed, public) challenge point;
* PCS binding is an **explicit hypothesis** (`BindsIntoMac`, in the same
  counting form as M3a: at most `εΩ` of the `|Ω|` opening tapes are accepted
  with a wrong plaintext), NOT the global placeholder axiom
  `Ideal.WeightPCSBinding` — so `#print axioms` on everything here stays at
  the standard three;
* `opening_mac_sound` — if the sumcheck-side opening pair disagrees with the
  committed evaluation, then "PCS accepts AND the difference zero-opens"
  survives on at most `εΩ·|F| + |Ω|` of the `|Ω|·|F|` tapes `(ω, Δ)`:
  soundness error `≤ εΩ/|Ω| + 1/|F|`, which union-bounds with M3's
  `(Σ dᵢ + 2)/|F|` (`blind_sumcheck_sound`);
* `transfers_eval` — the completeness-side glue: on good tapes an accepted
  opening plus an honest difference zero-opening yields exactly
  `openEval A L r = eval C_W r`, i.e. the `hfin` hypothesis of
  `blind_sumcheck_sound` for the weight leg.

The concrete PCS (Ligero/Brakedown/Basefold family over Goldilocks) is
instantiated in P3.5's paper analysis; its code-based IOP soundness supplies
`BindsIntoMac` and is assumed there, declared as such.
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]
variable {Ω : Type*} [Fintype Ω]

/-- Abstract view of one PCS opening session at a fixed public point: on
opening tape `ω` the verifier either rejects or accepts an authenticated
output pair `out ω = (x, m)` (the verifier ends up holding `keyOf Δ (out ω)`
through the VOLE transfer); `eval` is the committed polynomial's true
evaluation at the point. -/
structure PCSOpening (F : Type*) (Ω : Type*) where
  /-- Verifier's accept bit for the opening proper, as a function of the
  opening tape (challenges, queried columns, …). -/
  accept : Ω → Bool
  /-- The authenticated output pair `(plaintext, tag)` produced by the
  (possibly malicious) prover on tape `ω`. -/
  out : Ω → F × F
  /-- True evaluation of the committed polynomial at the public point. -/
  eval : F

namespace PCSOpening

/-- **Binding-into-MAC hypothesis** (counting form): at most `εΩ` opening
tapes are accepted while carrying a wrong plaintext. Supplied by the concrete
PCS's soundness analysis; `Ideal.WeightPCSBinding` names the deferred global
version. -/
def BindsIntoMac (P : PCSOpening F Ω) (εΩ : ℕ) : Prop :=
  (univ.filter fun ω : Ω => P.accept ω ∧ (P.out ω).1 ≠ P.eval).card ≤ εΩ

/-- The authenticated value the verifier holds after an accepted transfer. -/
def pcsAuthed (P : PCSOpening F Ω) (Δ : F) (ω : Ω) : Authed F :=
  authedOfPair Δ (P.out ω)

omit [Fintype F] [DecidableEq F] [Fintype Ω] in
theorem pcsAuthed_valid (P : PCSOpening F Ω) (Δ : F) (ω : Ω) :
    (P.pcsAuthed Δ ω).Valid Δ :=
  authedOfPair_valid Δ (P.out ω)

/-- **M9 soundness.** Let `σm` be the sumcheck-side opening pair (for the
weight leg: plaintext `openEval A L r`, tag its `L`-combination — see
`openingAuthed`). If its plaintext disagrees with the committed evaluation,
then for every forgery strategy `msg` (a function of the opening tape, never
of `Δ`), the combined check "PCS accepts and `σm − out` zero-opens" passes on
at most `εΩ·|F| + |Ω|` of the `(ω, Δ)` tapes: error `≤ εΩ/|Ω| + 1/|F|`. -/
theorem opening_mac_sound (P : PCSOpening F Ω) {εΩ : ℕ} (hbind : P.BindsIntoMac εΩ)
    (σm : F × F) (hσ : σm.1 ≠ P.eval) (msg : Ω → F) :
    (univ.filter fun p : Ω × F =>
        P.accept p.1 ∧ msg p.1 = keyOf p.2 (σm - P.out p.1)).card
      ≤ εΩ * Fintype.card F + Fintype.card Ω := by
  classical
  -- Split on whether the PCS transferred the right plaintext on tape ω.
  have hsub : (univ.filter fun p : Ω × F =>
        P.accept p.1 ∧ msg p.1 = keyOf p.2 (σm - P.out p.1))
      ⊆ ((univ.filter fun ω : Ω => P.accept ω ∧ (P.out ω).1 ≠ P.eval) ×ˢ (univ : Finset F))
        ∪ (univ.filter fun p : Ω × F =>
            ((P.out p.1).1 = P.eval) ∧ msg p.1 = keyOf p.2 (σm - P.out p.1)) := by
    intro p hp
    simp only [mem_filter, mem_univ, true_and, and_true, mem_union, mem_product] at hp ⊢
    by_cases hout : (P.out p.1).1 = P.eval
    · exact Or.inr ⟨hout, hp.2⟩
    · exact Or.inl ⟨hp.1, hout⟩
  refine le_trans (Finset.card_le_card hsub) (le_trans (Finset.card_union_le _ _)
    (Nat.add_le_add ?_ ?_))
  · -- Wrong-plaintext branch: bad tapes × all keys.
    rw [Finset.card_product, card_univ]
    exact Nat.mul_le_mul_right _ hbind
  · -- Right-plaintext branch: the difference has nonzero plaintext, so
    -- `zeroOpen_sound` leaves at most one accepting Δ per tape.
    rw [← Nat.mul_one (Fintype.card Ω)]
    refine card_filter_prod_le_right _ fun ω => ?_
    by_cases hout : (P.out ω).1 = P.eval
    · refine le_trans (Finset.card_le_card fun Δ hΔ => ?_)
        (zeroOpen_sound (σm - P.out ω) ?_ (msg ω))
      · simp only [mem_filter, mem_univ, true_and] at hΔ ⊢
        exact hΔ.2
      · simpa [Prod.fst_sub, sub_ne_zero, hout] using hσ
    · refine le_trans (le_of_eq (Finset.card_eq_zero.mpr ?_)) (Nat.zero_le 1)
      exact Finset.filter_eq_empty_iff.mpr fun Δ _ h => hout h.1

omit [Fintype F] [DecidableEq F] [Fintype Ω] in
/-- **M9 completeness glue.** On a good tape (accepted openings carry the
right plaintext), an accepted opening plus an honestly zero-opened difference
pin the sumcheck-side plaintext to the committed evaluation — exactly the
`hfin : TR.finalEval = openEval A L` hypothesis `blind_sumcheck_sound` needs
for the weight leg. -/
theorem transfers_eval (P : PCSOpening F Ω) {ω : Ω}
    (hgood : P.accept ω → (P.out ω).1 = P.eval) (hacc : P.accept ω)
    {σm : F × F} (hzero : (σm - P.out ω).1 = 0) : σm.1 = P.eval := by
  have h := sub_eq_zero.mp (by simpa [Prod.fst_sub] using hzero)
  rw [h, hgood hacc]

end PCSOpening

end VoltaZk

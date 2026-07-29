import VoltaZk.Connection
import VoltaZk.ZeroBatchSound

/-!
# C6 Δ-residual compression

C6 removes the direct authentication-correction vector from the response
wire.  The verifier's key program is linear, so after all public challenges
are fixed its leaves can be reverse-accumulated into one affine equation.

For each base correlation the corrupted prover knows `(a,m)`, while the
designated verifier holds `keyOf Δ (a,m) = m + Δ*a`.  Authenticating `x`
uses the hidden correction `d=x-a`.  This file proves:

* `correctedKey` is exactly the base key plus `Δ*d`;
* a response-wide linear combination decomposes into the verifier-only base
  key aggregate plus `Δ` times the hidden correction aggregate;
* if the resulting plaintext residual is nonzero, at most one `Δ` accepts;
* the ordinary 17-certificate union bound does not weaken any individual
  certificate premise.

The wrapper/PCS binding that certifies the hidden dot product is deliberately
an explicit protocol premise outside these algebraic identities.
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F]

/-- Apply one hidden authentication correction to a prover-chosen base
correlation pair.  The tag is unchanged. -/
def correctedPair (base : F × F) (correction : F) : F × F :=
  (base.1 + correction, base.2)

/-- Verifier-only linear combination of the uncorrected base keys. -/
def c6BaseKeyAggregate {T : ℕ} (Δ : F) (coeff : Fin T → F)
    (base : Fin T → F × F) : F :=
  ∑ i, coeff i * keyOf Δ (base i)

/-- Prover-side dot product of the hidden corrections with the same public
coefficient schedule. -/
def c6CorrectionAggregate {T : ℕ} (coeff : Fin T → F)
    (correction : Fin T → F) : F :=
  ∑ i, coeff i * correction i

/-- The response-wide plaintext residual after applying every correction. -/
def c6PlaintextAggregate {T : ℕ} (coeff : Fin T → F)
    (base : Fin T → F × F) (correction : Fin T → F) : F :=
  ∑ i, coeff i * ((base i).1 + correction i)

/-- Matching response-wide prover tag. -/
def c6TagAggregate {T : ℕ} (coeff : Fin T → F)
    (base : Fin T → F × F) : F :=
  ∑ i, coeff i * (base i).2

theorem correctedPair_fst (base : F × F) (correction : F) :
    (correctedPair base correction).1 = base.1 + correction := rfl

theorem correctedPair_snd (base : F × F) (correction : F) :
    (correctedPair base correction).2 = base.2 := rfl

/-- One correction updates a verifier key by exactly `Δ*d`. -/
theorem correctedKey (Δ : F) (base : F × F) (correction : F) :
    keyOf Δ (correctedPair base correction)
      = keyOf Δ base + Δ * correction := by
  unfold keyOf correctedPair
  ring

/-- **C6 affine residual identity.**  The expanded old verifier key
combination equals the compact base-key aggregate plus `Δ` times the one
hidden-correction dot product certified by the wrapper. -/
theorem c6_delta_residual_decompose {T : ℕ} (Δ : F) (coeff : Fin T → F)
    (base : Fin T → F × F) (correction : Fin T → F) :
    (∑ i, coeff i * keyOf Δ (correctedPair (base i) (correction i)))
      = c6BaseKeyAggregate Δ coeff base
        + Δ * c6CorrectionAggregate coeff correction := by
  unfold c6BaseKeyAggregate c6CorrectionAggregate
  rw [Finset.mul_sum, ← Finset.sum_add_distrib]
  exact Finset.sum_congr rfl fun i _ => by
    rw [correctedKey]
    ring

/-- The same expanded old-verifier expression is a single ordinary
`keyOf` whose plaintext/tag coordinates are the accumulated response
residual. -/
theorem c6_delta_residual_keyOf {T : ℕ} (Δ : F) (coeff : Fin T → F)
    (base : Fin T → F × F) (correction : Fin T → F) :
    c6BaseKeyAggregate Δ coeff base
        + Δ * c6CorrectionAggregate coeff correction
      = keyOf Δ
          (c6PlaintextAggregate coeff base correction,
            c6TagAggregate coeff base) := by
  rw [← c6_delta_residual_decompose]
  rw [keyOf_rlc_expand]
  unfold c6PlaintextAggregate c6TagAggregate correctedPair
  congr 1

/-- Completeness of the compact client check: when the accumulated
plaintext residual is zero, the base-key aggregate plus `Δ*D_corr` equals
the accumulated prover tag for every designated-verifier secret. -/
theorem c6_delta_residual_complete {T : ℕ} (Δ : F) (coeff : Fin T → F)
    (base : Fin T → F × F) (correction : Fin T → F)
    (hzero : c6PlaintextAggregate coeff base correction = 0) :
    c6BaseKeyAggregate Δ coeff base
        + Δ * c6CorrectionAggregate coeff correction
      = c6TagAggregate coeff base := by
  rw [c6_delta_residual_keyOf, keyOf, hzero]
  ring

variable [Fintype F] [DecidableEq F]

/-- **C6 designated-verifier residual soundness.**  If the response-wide
plaintext residual is nonzero, any provider message fixed independently of
`Δ` is accepted by at most one designated-verifier key.  This is the same
`1/|F|` event as an ordinary zero opening, not a revelation of `Δ`. -/
theorem c6_delta_residual_sound {T : ℕ} (coeff : Fin T → F)
    (base : Fin T → F × F) (correction : Fin T → F)
    (hbad : c6PlaintextAggregate coeff base correction ≠ 0) (msg : F) :
    (univ.filter fun Δ : F =>
        msg = c6BaseKeyAggregate Δ coeff base
          + Δ * c6CorrectionAggregate coeff correction).card ≤ 1 := by
  refine le_trans
    (le_of_eq (congrArg Finset.card (Finset.filter_congr fun Δ _ => ?_)))
    (zeroOpen_sound
      (c6PlaintextAggregate coeff base correction,
        c6TagAggregate coeff base) hbad msg)
  rw [c6_delta_residual_keyOf]

/-- The session composition is an ordinary union bound over 17 distinct
certificate events.  Each local slice premise remains `≤ B`; it is not
replaced by `≤ 17*B`.  No independence between certificates is assumed. -/
theorem c6_seventeen_certificate_union_bound {Delta Xi : Type*}
    [Fintype Delta] [Fintype Xi] [DecidableEq Delta] [DecidableEq Xi]
    {B : ℕ}
    (bad : Fin 17 → Finset (Delta × (Fin 17 → Xi)))
    (hslice : ∀ r (rest : Fin 16 → Xi),
      (univ.filter fun dxi : Delta × Xi =>
        responseTapeEquiv r (dxi, rest) ∈ bad r).card ≤ B) :
    (univ.biUnion bad).card ≤ 17 * B * Fintype.card Xi ^ 16 := by
  simpa using
    (connection_soundness_union_bound (n := 16) (B := B) bad hslice)

end VoltaZk

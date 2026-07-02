import VoltaZk.Mac

/-!
# `Π_ZeroOpen` and `Π_ZeroBatch`

`docs/protocol-sketch.md` § "Zero Opening".

To prove that an authenticated `y` equals zero, the prover sends `m_y` and the
verifier accepts iff `k_y = m_y`. Batching: the verifier sends `χ` *after the
claim list is closed*, both parties form the random linear combination, and a
single opening covers all claims.

The perfect-ZK content is deterministic: for *true* zero claims the prover's
message `m_Z` **equals** `k_Z`, a value the simulator computes from the
verifier's keys alone. (Soundness — a cheating prover must guess `Δ` — is the
separate statement, error `≤ (T+1)/|F|`; deferred to the next milestone.)
-/

namespace VoltaZk

variable {F : Type*} [Field F]

/-- `Π_ZeroOpen`, perfect simulation: on a valid zero claim the prover's only
message is exactly the verifier's key, so the simulator outputs `k_y`. -/
theorem Authed.Valid.msg_eq_key {Δ : F} {y : Authed F}
    (h : y.Valid Δ) (hx : y.x = 0) : y.m = y.k := by
  unfold Authed.Valid at h
  rw [hx, mul_zero, add_zero] at h
  exact h.symm

/-- Random linear combination of a *closed* claim list under the verifier's
batching challenge `χ`. Both parties compute their share locally. -/
def rlc {T : ℕ} (χ : Fin T → F) (z : Fin T → Authed F) : Authed F :=
  ∑ j, χ j • z j

/-- The simulator's message for `Π_ZeroBatch`: computed from the verifier's
keys and the public challenge only — no witness, no tags. -/
def simZeroBatchMsg {T : ℕ} (χ : Fin T → F) (key : Fin T → F) : F :=
  ∑ j, χ j * key j

theorem rlc_valid {T : ℕ} {Δ : F} (χ : Fin T → F) {z : Fin T → Authed F}
    (hval : ∀ j, (z j).Valid Δ) : (rlc χ z).Valid Δ := by
  unfold rlc
  exact Authed.Valid.sum fun j _ => (hval j).smul (χ j)

/-- **Perfect simulation of `Π_ZeroBatch`** (for any adversarially chosen `χ`):
on valid, true zero claims the prover's batched opening `m_Z` coincides with
the value the simulator derives from the verifier's keys. Since `χ` is chosen
by `V*` as a function of an already-fixed transcript prefix, and every other
component of the exchange is deterministic given `χ`, the real and simulated
transcript distributions of `Π_ZeroBatch` are identical. -/
theorem zeroBatch_perfect_sim {T : ℕ} {Δ : F} (χ : Fin T → F)
    (z : Fin T → Authed F)
    (hval : ∀ j, (z j).Valid Δ) (hzero : ∀ j, (z j).x = 0) :
    (rlc χ z).m = simZeroBatchMsg χ fun j => (z j).k := by
  have hx : (rlc χ z).x = 0 := by
    simp [rlc, hzero]
  have hm : (rlc χ z).m = (rlc χ z).k :=
    (rlc_valid χ hval).msg_eq_key hx
  rw [hm]
  simp [rlc, simZeroBatchMsg]

end VoltaZk

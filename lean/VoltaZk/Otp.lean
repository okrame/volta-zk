import Mathlib.Probability.Distributions.Uniform
import Mathlib.Algebra.Group.Units.Equiv

/-!
# One-time-pad lemma

The correction `δ = x − r` sent by the prover in `Π_Auth` is masked by the
fresh uniform VOLE value `r`, hence is itself uniform — independently of `x`.
This is the entire reason the blind-transcript messages of `Π_BSC` are
simulatable: every prover message is either such a correction or an opening
the simulator can compute from the verifier's keys.
-/

namespace VoltaZk

open PMF

variable {G : Type*} [Fintype G] [Nonempty G]

/-- Pushing the uniform distribution through any permutation yields the
uniform distribution. -/
theorem map_equiv_uniform (e : G ≃ G) :
    (uniformOfFintype G).map ⇑e = uniformOfFintype G := by
  classical
  ext b
  have hsum : (∑' a, if b = e a then uniformOfFintype G a else 0)
      = (if b = e (e.symm b) then uniformOfFintype G (e.symm b) else 0) :=
    tsum_eq_single (e.symm b) fun a ha =>
      if_neg fun hba => ha (by rw [hba, Equiv.symm_apply_apply])
  rw [map_apply, hsum]
  simp

/-- **One-time pad.** For uniform `r`, the correction `x − r` is uniform,
for every fixed `x`. -/
theorem sub_left_uniform {G : Type*} [AddGroup G] [Fintype G]
    (x : G) :
    (uniformOfFintype G).map (fun r => x - r) = uniformOfFintype G :=
  map_equiv_uniform (Equiv.subLeft x)

/-- Congruence for pushforwards: functions that agree on the support of `p`
induce the same distribution. Used to replace the prover's final opening with
the simulator's value on the support of the real execution. -/
theorem map_congr_support {α β : Type*} {p : PMF α} {f g : α → β}
    (h : ∀ a ∈ p.support, f a = g a) : p.map f = p.map g := by
  classical
  ext b
  rw [map_apply, map_apply]
  refine tsum_congr fun a => ?_
  by_cases ha : a ∈ p.support
  · rw [h a ha]
  · rw [PMF.mem_support_iff, not_not] at ha
    simp [ha]

end VoltaZk

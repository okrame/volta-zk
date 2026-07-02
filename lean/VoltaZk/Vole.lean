import VoltaZk.Mac
import VoltaZk.Otp

/-!
# Ideal `F_sVOLE`, corrupted-verifier branch, and `Π_Auth`

We model only what the ZK simulator needs: the `Extend` command of the ideal
(subfield-)VOLE functionality when the verifier is corrupted. The adversary
(malicious `V*`) freely chooses the session key `Δ` and the correlation key
`k`; the functionality samples the mask `u` uniformly and *determines* the
prover tag as `m := k − Δ·u`, so the MAC invariant holds by construction.

Domain separation / one-time use of correlations is abstracted by indexing:
each fresh correlation is consumed at a distinct index (see
`VoltaZk.BlindSumcheck`, where index = position in the message schedule).

The realization of this functionality by an actual PCG/Ferret-style protocol
is deliberately an assumption — see `VoltaZk.Ideal`.
-/

namespace VoltaZk

open PMF

variable {F : Type*} [Field F] [Fintype F]

/-- One fresh correlation from ideal `F_sVOLE` with a corrupted verifier:
`Δ` and `k` are adversarial, `u` is uniform, `m := k − Δ·u`. -/
noncomputable def freshCorr (Δ k : F) : PMF (Authed F) :=
  (uniformOfFintype F).map fun u => ⟨u, k - Δ * u, k⟩

/-- Every correlation delivered by the ideal functionality satisfies the MAC
invariant, whatever `Δ, k` the adversary chose. -/
theorem freshCorr_valid (Δ k : F) {a : Authed F}
    (ha : a ∈ (freshCorr Δ k).support) : a.Valid Δ := by
  rw [freshCorr, support_map] at ha
  obtain ⟨u, -, rfl⟩ := ha
  simp only [Authed.Valid]
  ring

/-- The prover-side mask of a fresh correlation is uniform (this is what the
adversary cannot bias, even though it chose `Δ` and `k`). -/
theorem freshCorr_x_uniform (Δ k : F) :
    (freshCorr Δ k).map Authed.x = uniformOfFintype F := by
  rw [freshCorr, map_comp]
  exact map_id (uniformOfFintype F)

/-- **Simulatability of `Π_Auth` corrections.** When the prover authenticates
a plaintext `x` from a fresh correlation, the correction it sends is
`δ = x − u`: uniform, independent of `x`. A simulator that samples `δ`
uniformly produces exactly the real distribution. -/
theorem auth_correction_uniform (Δ k x : F) :
    (freshCorr Δ k).map (fun a => x - a.x) = uniformOfFintype F := by
  rw [freshCorr, map_comp]
  exact sub_left_uniform x

/-- Both parties' local update in `Π_Auth`: after the correction
`δ = x − r.x`, the prover keeps tag `m_r` and the verifier moves its key to
`k_r + Δ·δ`. The result authenticates `x`. -/
def Authed.correct (r : Authed F) (Δ x : F) : Authed F :=
  ⟨x, r.m, r.k + Δ * (x - r.x)⟩

omit [Fintype F] in
theorem Authed.correct_valid {Δ : F} {r : Authed F} (h : r.Valid Δ) (x : F) :
    (r.correct Δ x).Valid Δ := by
  unfold Authed.Valid Authed.correct at *
  rw [h]
  ring

end VoltaZk

import VoltaZk.Connection
import VoltaZk.C61PublicCompression

/-!
# C6.3 joint correction privacy

C6.3 exposes hashes, openings and algebraic checks derived from the correction
state `D = X - R`.  This file isolates the exact outer privacy argument.  One
fresh uniform mask is allocated to every live `(cell, version)` slot, so the
whole correction vector is uniform.  Any later transcript generated only from
that vector, public data, verifier state and fresh coins is therefore
independent of the model/cache plaintext.

The theorem deliberately does not claim that WHIR hides its opened initial
oracle.  C6.3 does not need that stronger statement: the opened oracle must be
a post-processing of the already one-time-padded correction vector.  The two
final lemmas record why mask reuse and serialization of a prover MAC tag are
forbidden.
-/

namespace VoltaZk

open PMF

variable {F : Type*} [Field F]

section JointCorrection

variable [Fintype F]

/-- The complete correction vector for one connection lifecycle.  The index
must distinguish every cell version, including values retained across accepted
responses and fresh successor values. -/
def c63Corrections {I : Type*} (x r : I → F) : I → F :=
  fun i => x i - r i

/-- Real C6.3 verifier view after corrections.  `downstream` may include
adaptive challenges, roots, opened rows, WHIR messages and the designated
terminal simulator.  Its only secret-dependent input is the masked vector.
-/
noncomputable def c63CorrectionView {I View : Type*} [Fintype I] [DecidableEq I]
    (x : I → F) (downstream : (I → F) → PMF View) : PMF View :=
  ((uniformOfFintype (I → F)).map (c63Corrections x)).bind downstream

/-- The straight-line simulator samples the public correction vector directly
and then runs the same downstream transcript generator. -/
noncomputable def c63CorrectionSimulator {I View : Type*} [Fintype I]
    [DecidableEq I]
    (downstream : (I → F) → PMF View) : PMF View :=
  (uniformOfFintype (I → F)).bind downstream

/-- **C6.3 joint perfect hiding.** For fixed verifier state, the complete
tagless transcript has exactly the simulator's distribution.  Since `I`
covers all response versions at once, this includes persistent predecessor
roots and adaptive successor transcripts without remasking an accepted value.
-/
theorem c63_joint_correction_view_perfect_zk
    {I View : Type*} [Fintype I] [DecidableEq I]
    (x : I → F) (downstream : (I → F) → PMF View) :
    c63CorrectionView x downstream = c63CorrectionSimulator downstream := by
  unfold c63CorrectionView c63CorrectionSimulator c63Corrections
  rw [connection_corrections_uniform]

/-- Consequently, two arbitrary model/cache plaintext vectors induce the same
complete verifier-view distribution. -/
theorem c63_joint_correction_view_independent
    {I View : Type*} [Fintype I] [DecidableEq I]
    (x₀ x₁ : I → F) (downstream : (I → F) → PMF View) :
    c63CorrectionView x₀ downstream = c63CorrectionView x₁ downstream := by
  rw [c63_joint_correction_view_perfect_zk,
    c63_joint_correction_view_perfect_zk]

end JointCorrection

/-- C6.3 reuses C6.1's designated terminal simulator unchanged.  The emitted
zero-opening tag is safe because it is computable from the verifier keys and
public closure; it is not the raw prover tag attached to a cache mask. -/
theorem c63_designated_terminal_tag_eq_honest_tag
    (Delta gamma combined maskedClaim : F) (target mask : Authed F)
    (htarget : target.Valid Delta) (hmask : mask.Valid Delta)
    (hbase : combined = maskedClaim + gamma * target.x) :
    Delta * (combined - (maskedClaim + mask.x))
        - gamma * target.k + mask.k
      = (c61AuthenticatedTargetResidual Delta gamma combined maskedClaim
          target mask).m := by
  exact c61_designated_simulator_tag_eq_honest_tag Delta gamma combined
    maskedClaim target mask htarget hmask hbase

/-- Reusing one mask for two plaintext versions exposes their difference.
This is why the lifecycle index contains the version and aborts burn their
allocated range. -/
theorem c63_reused_mask_reveals_difference (x₀ x₁ r : F) :
    (x₀ - r) - (x₁ - r) = x₀ - x₁ := by
  ring

/-- If the verifier receives the prover MAC tag beside its key and correction,
it reconstructs the plaintext.  Production framing must therefore expose only
the verifier-computable terminal value, never the prover tag itself. -/
theorem c63_exposed_prover_tag_recovers_plaintext
    (Delta x r proverTag verifierKey correction : F)
    (hDelta : Delta ≠ 0)
    (hkey : verifierKey = proverTag + Delta * r)
    (hcorrection : correction = x - r) :
    correction + (verifierKey - proverTag) / Delta = x := by
  rw [hkey, hcorrection]
  field_simp [hDelta]
  ring

end VoltaZk

import VoltaZk.Vole
import VoltaZk.ZeroBatchSound

/-!
# Subfield corrections: `F_p ⊆ E` (M5)

`docs/protocol-sketch.md` § "Next Formal Targets" item 3: 16-bit corrections
in `F_p ⊆ E` preserve both ZK (uniformity in the subdomain) and the bandwidth
claim.

In the real protocol quantized values live in the base field `F_p` (16-bit
encodable) while MAC tags, keys and the session key `Δ` live in the extension
`E` (`= F_p²`, statistical soundness `1/|E|`). Subfield VOLE samples the mask
`u` of a fresh correlation in `F_p`, so the `Π_Auth` correction `δ = x − u` is
an element of `F_p`:

* **bandwidth** — the correction message is *typed* in `F_p`
  (`SubAuthed.correction : … → Fp`), so its encoding costs `log₂ |F_p|` bits
  per authenticated value, not `log₂ |E|`; this is structural, not a lemma;
* **ZK in the subdomain** — for `x ∈ F_p` and `u` uniform on `F_p`, the
  correction is uniform on `F_p` (`sub_correction_uniform`): the simulator
  samples `δ ← F_p` and matches the real distribution exactly. Masking with
  `u ← E` instead would also be uniform but push `δ` out of `F_p` (bandwidth
  lost); masking a subdomain plaintext with a subdomain mask loses nothing;
* **soundness unchanged** — `Δ ∈ E`, so opening a forged subfield claim still
  requires guessing `Δ` in `E`: the embedding `SubAuthed.toAuthed` maps valid
  subfield values to valid `E`-values with the *same* tag and key, plaintext
  nonzero iff nonzero in `F_p` (`algebraMap` is injective), and the M3a/M4
  lemmas (`zeroOpen_sound`, `zeroBatch_sound`, `kv_cache_sound`) apply
  verbatim to the embedded values (`sub_zeroOpen_sound` below spells out the
  single-opening case, error `1/|E|`).

Corrupted-verifier branch of subfield `F_sVOLE`: the adversary still chooses
`Δ` and the correlation key `k` freely in `E`; only the mask is constrained
to (and uniform on) the subdomain — mirror of `VoltaZk.freshCorr`.
-/

namespace VoltaZk

open PMF

variable {Fp E : Type*} [Field Fp] [Field E] [Algebra Fp E]

/-- An authenticated value whose plaintext is constrained to the subfield:
the prover holds `(x, m)` with `x : Fp`, the verifier holds `k : E`, and the
MAC invariant lives in `E` through the embedding. -/
@[ext]
structure SubAuthed (Fp E : Type*) where
  /-- plaintext value, in the subfield (prover side) -/
  x : Fp
  /-- MAC tag, in the extension (prover side) -/
  m : E
  /-- MAC key, in the extension (verifier side) -/
  k : E

namespace SubAuthed

/-- The MAC invariant `k = m + Δ·ι(x)` for session key `Δ : E`. -/
def Valid (Δ : E) (a : SubAuthed Fp E) : Prop :=
  a.k = a.m + Δ * algebraMap Fp E a.x

/-- Embedding into plain authenticated values over `E`: same tag, same key,
plaintext pushed through `algebraMap`. All `E`-level lemmas (linearity,
zero-opening soundness, cache soundness) apply to the image. -/
def toAuthed (a : SubAuthed Fp E) : Authed E :=
  ⟨algebraMap Fp E a.x, a.m, a.k⟩

theorem toAuthed_valid {Δ : E} {a : SubAuthed Fp E} (h : a.Valid Δ) :
    a.toAuthed.Valid Δ := h

/-- The embedded plaintext vanishes iff the subfield plaintext does: forging
a subfield claim is forging an `E`-claim. -/
@[simp] theorem toAuthed_x_eq_zero_iff (a : SubAuthed Fp E) :
    a.toAuthed.x = 0 ↔ a.x = 0 :=
  map_eq_zero_iff _ (algebraMap Fp E).injective

/-- The `Π_Auth` correction message for plaintext `x` from mask `r`: an
element of `F_p`. Its type *is* the bandwidth claim: `log₂ |F_p|` bits per
authenticated value. -/
def correction (r : SubAuthed Fp E) (x : Fp) : Fp := x - r.x

/-- Both parties' local update in subfield `Π_Auth`: the prover keeps tag
`m_r`, the verifier moves its key by `Δ·ι(δ)`. -/
def correct (r : SubAuthed Fp E) (Δ : E) (x : Fp) : SubAuthed Fp E :=
  ⟨x, r.m, r.k + Δ * algebraMap Fp E (r.correction x)⟩

theorem correct_valid {Δ : E} {r : SubAuthed Fp E} (h : r.Valid Δ) (x : Fp) :
    (r.correct Δ x).Valid Δ := by
  unfold Valid correct correction at *
  rw [map_sub, h]
  ring

/-- The subfield update commutes with the embedding: subfield `Π_Auth` *is*
`Π_Auth` over `E` restricted to subdomain corrections. -/
theorem toAuthed_correct (r : SubAuthed Fp E) (Δ : E) (x : Fp) :
    (r.correct Δ x).toAuthed = r.toAuthed.correct Δ (algebraMap Fp E x) := by
  unfold correct correction toAuthed Authed.correct
  simp [map_sub]

end SubAuthed

section Distributions

variable [Fintype Fp]

/-- One fresh correlation from ideal subfield `F_sVOLE` with a corrupted
verifier: `Δ` and `k` are adversarial in `E`, the mask `u` is uniform on the
subdomain `F_p`, and `m := k − Δ·ι(u)`. -/
noncomputable def subFreshCorr (Δ k : E) : PMF (SubAuthed Fp E) :=
  (uniformOfFintype Fp).map fun u => ⟨u, k - Δ * algebraMap Fp E u, k⟩

/-- Every subfield correlation satisfies the MAC invariant, whatever `Δ, k`
the adversary chose. -/
theorem subFreshCorr_valid (Δ k : E) {a : SubAuthed Fp E}
    (ha : a ∈ (subFreshCorr (Fp := Fp) Δ k).support) : a.Valid Δ := by
  rw [subFreshCorr, support_map] at ha
  obtain ⟨u, -, rfl⟩ := ha
  simp only [SubAuthed.Valid]
  ring

/-- The subdomain mask of a fresh subfield correlation is uniform on `F_p`. -/
theorem subFreshCorr_x_uniform (Δ k : E) :
    (subFreshCorr (Fp := Fp) Δ k).map SubAuthed.x = uniformOfFintype Fp := by
  rw [subFreshCorr, map_comp]
  exact map_id (uniformOfFintype Fp)

/-- **Subfield correction lemma (M5), ZK half.** When the prover authenticates
a quantized plaintext `x : F_p` from a fresh subfield correlation, the
correction it sends is uniform on `F_p` — independently of `x` and of the
adversarial `Δ, k`. A simulator sampling `δ ← F_p` produces exactly the real
distribution, and the message stays in the subdomain: ZK and bandwidth hold
simultaneously. -/
theorem sub_correction_uniform (Δ k : E) (x : Fp) :
    (subFreshCorr (Fp := Fp) Δ k).map (fun a => a.correction x)
      = uniformOfFintype Fp := by
  rw [subFreshCorr, map_comp]
  exact sub_left_uniform x

end Distributions

section Soundness

variable [Fintype E] [DecidableEq E]

/-- **Subfield soundness is `E`-soundness.** Opening a subfield claim with
nonzero plaintext still requires guessing `Δ` in the *extension*: at most one
session key accepts a forged message, error `1/|E|`. Direct reuse of
`zeroOpen_sound` through the embedding; the batched and cache variants
(`zeroBatch_sound`, `kv_cache_sound`) transfer the same way. -/
theorem sub_zeroOpen_sound (x : Fp) (m : E) (hx : x ≠ 0) (msg : E) :
    (Finset.univ.filter fun Δ : E => msg = keyOf Δ (algebraMap Fp E x, m)).card ≤ 1 :=
  zeroOpen_sound _ (fun h => hx (map_eq_zero_iff _ (algebraMap Fp E).injective |>.mp h)) msg

end Soundness

end VoltaZk

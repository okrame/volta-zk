import VoltaZk.Vole

/-!
# `Π_Prod`: perfect ZK of the masked QuickSilver product check (M7)

`docs/protocol-sketch.md` § "Next Formal Targets" item 5: the masked degree-2
check messages are uniform (same OTP pattern as the corrections); soundness
stays assumed (`VoltaZk.Ideal.QuickSilverProdSound`).

The check. For a product claim `⟦c⟧ = ⟦a⟧·⟦b⟧` over valid values, expanding
the MAC invariant gives the degree-2 key identity

  `k_a·k_b − Δ·k_c = A₀ + A₁·Δ`,   `A₀ = m_a·m_b`,  `A₁ = a·m_b + b·m_a − m_c`

(the `Δ²` terms cancel exactly when `c = a·b`). The prover knows `A₀, A₁`,
the verifier knows the left-hand side; a fresh correlation `⟦r⟧` masks the
prover's message: P sends `(A₀ + m_r, A₁ + r)`, V accepts iff

  `k_a·k_b − Δ·k_c + k_r = (A₀ + m_r) + (A₁ + r)·Δ`   (`qs_check_complete`).

ZK. The second component is one-time-padded by the uniform mask `r`; the
first is then *determined* by the second and the verifier's keys: on true
claims `A₀ + m_r = k_a·k_b − Δ·k_c + k_r − s·Δ` where `s = A₁ + r`
(`qsMsg_eq_sim`). So the simulator samples `s ← F` and computes the first
component from `V*`'s state alone — the exact pattern of
`zeroBatch_perfect_sim` (message = function of the keys) combined with
`auth_correction_uniform` (OTP). `prod_perfect_sim` states the resulting
distributional equality against adversarial `Δ` and correlation key `k`.

Composition note: the `Π_Prod` message has the shape
`(key-computable ∘ uniform-component, uniform-component)` — the same shape
consumed by the round induction `realView_map_publicView`, so it slots into
the blind transcript without new theory; in the protocol the check is
RLC-batched into the same closing `Π_ZeroBatch` list.
-/

namespace VoltaZk

open PMF

variable {F : Type*} [Field F] [Fintype F]

/-- Constant coefficient of the prover's degree-2 check polynomial. -/
def qsA0 (a b : Authed F) : F := a.m * b.m

/-- Linear coefficient of the prover's degree-2 check polynomial. -/
def qsA1 (a b c : Authed F) : F := a.x * b.m + b.x * a.m - c.m

/-- The prover's masked `Π_Prod` message for claim `c = a·b`, masked by the
fresh correlation `r`: `(A₀ + m_r, A₁ + r)`. -/
def qsMsg (a b c r : Authed F) : F × F :=
  (qsA0 a b + r.m, qsA1 a b c + r.x)

/-- The simulator's `Π_Prod` message: second component sampled uniformly,
first computed from the verifier's keys and `Δ` only. -/
def simQsMsg (Δ ka kb kc kr s : F) : F × F :=
  (ka * kb - Δ * kc + kr - s * Δ, s)

omit [Fintype F] in
/-- **Completeness.** On valid values with `c = a·b`, the verifier's degree-2
key-side check accepts the masked message. -/
theorem qs_check_complete {Δ : F} {a b c r : Authed F}
    (ha : a.Valid Δ) (hb : b.Valid Δ) (hc : c.Valid Δ) (hr : r.Valid Δ)
    (hx : c.x = a.x * b.x) :
    a.k * b.k - Δ * c.k + r.k = (qsMsg a b c r).1 + (qsMsg a b c r).2 * Δ := by
  unfold Authed.Valid at ha hb hc hr
  unfold qsMsg qsA0 qsA1
  rw [ha, hb, hc, hr, hx]
  ring

omit [Fintype F] in
/-- **Pointwise simulation** (the `msg_eq_key` analogue): on a true product
claim the honest masked message coincides with the simulator's output at
`s = A₁ + r` — a value of the *uniform* second component. -/
theorem qsMsg_eq_sim {Δ : F} {a b c r : Authed F}
    (ha : a.Valid Δ) (hb : b.Valid Δ) (hc : c.Valid Δ) (hr : r.Valid Δ)
    (hx : c.x = a.x * b.x) :
    qsMsg a b c r = simQsMsg Δ a.k b.k c.k r.k (qsA1 a b c + r.x) := by
  unfold Authed.Valid at ha hb hc hr
  unfold qsMsg simQsMsg qsA0 qsA1
  rw [Prod.mk.injEq]
  refine ⟨?_, rfl⟩
  rw [ha, hb, hc, hr, hx]
  ring

/-- **`Π_Prod` perfect ZK (M7).** Over a fresh correlation from the
corrupted-verifier branch of `F_sVOLE` — adversarial `Δ` and correlation key
`k` — the prover's masked degree-2 check message for a true product claim is
distributed exactly as the simulator's, which uses only `V*`'s state
(`Δ`, the keys `k_a, k_b, k_c, k`) and a uniform sample. -/
theorem prod_perfect_sim (Δ k : F) {a b c : Authed F}
    (ha : a.Valid Δ) (hb : b.Valid Δ) (hc : c.Valid Δ)
    (hx : c.x = a.x * b.x) :
    (freshCorr Δ k).map (qsMsg a b c)
      = (uniformOfFintype F).map (simQsMsg Δ a.k b.k c.k k) := by
  rw [freshCorr, map_comp]
  have hfun : (qsMsg a b c ∘ fun u => (⟨u, k - Δ * u, k⟩ : Authed F))
      = simQsMsg Δ a.k b.k c.k k ∘ fun u => qsA1 a b c + u := by
    funext u
    have hr : (⟨u, k - Δ * u, k⟩ : Authed F).Valid Δ := by
      simp only [Authed.Valid]
      ring
    exact qsMsg_eq_sim ha hb hc hr hx
  rw [hfun, ← map_comp,
    show (uniformOfFintype F).map (fun u => qsA1 a b c + u) = uniformOfFintype F from
      map_equiv_uniform (Equiv.addLeft (qsA1 a b c))]

end VoltaZk

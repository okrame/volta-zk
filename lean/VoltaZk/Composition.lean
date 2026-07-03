import VoltaZk.BlindSumcheck

/-!
# Sequential composition of `Π_BSC` windows (M6)

`docs/protocol-sketch.md` § "Next Formal Targets" item 4: multiple
`Π_BSC + Π_ZeroBatch` windows under one session key `Δ`, with fresh
correlation indices per window, against a single malicious verifier that is
adaptive *across* windows — perfect ZK composes.

Model. A `Window` is one blind-sumcheck instance: a coefficient schedule, a
claim schema, and a round count. Windows run sequentially; window `w` ends
with its own batched zero-opening, and that opening *enters the transcript*:
the challenges, keys and batching challenge of every later window may depend
on it. `V*` is one global adversary; the per-window adversary is the residual
strategy `wrapV V pre off` that prepends the flat public prefix `pre`
(everything sent or received so far, openings included) to its strategies and
shifts its correlation keys by `off` — the offset *is* the freshness of the
VOLE indices across windows, the same move as the M4 domain separation.

The hybrid argument is degenerate because the per-window equalities are
perfect. Formally the proof is an induction over the window list:

* rounds — `realView_map_publicView` applied to the wrapped adversary (it is
  already stated for arbitrary adversaries and accumulators);
* opening — on the support the prover's opening equals a deterministic
  function of the public window transcript and `V*`'s state
  (`finalMsg_eq_sim` + `simFinalMsg_eq_of_publicView_eq`), so it composes
  into the next window's prefix exactly like a public challenge;
* the continuation factors through the public projection (`simCont`), and the
  inductive hypothesis swaps `realMulti` for `simMulti` under the bind.

The zero-claims hypothesis is quantified over *every* prefix and offset, not
just reachable ones — stronger than needed, but faithful for an honest
prover, whose per-window claim identities hold for every challenge sequence
(same convention as the WLOG notes of M2: `V*` deterministic, `Δ` and keys
fixed upfront).
-/

namespace VoltaZk

open PMF

variable {F : Type*} [Field F] [Fintype F]

/-- Congruence for binds: kernels that agree on the support of `p` induce the
same distribution (bind analogue of `map_congr_support`). -/
theorem bind_congr_support {α β : Type*} {p : PMF α} {f g : α → PMF β}
    (h : ∀ a ∈ p.support, f a = g a) : p.bind f = p.bind g := by
  classical
  ext b
  rw [bind_apply, bind_apply]
  refine tsum_congr fun a => ?_
  by_cases ha : a ∈ p.support
  · rw [h a ha]
  · rw [PMF.mem_support_iff, not_not] at ha
    simp [ha]

/-- One `Π_BSC + Π_ZeroBatch` window: an honest coefficient schedule, the
public-linear schema of its closed claim list, and its round count. -/
structure Window (F : Type*) where
  /-- honest-prover coefficient schedule of this window -/
  P : RoundCoeffs F
  /-- claim schema closed by this window's `Π_ZeroBatch` -/
  S : ClaimSchema F
  /-- number of rounds -/
  n : ℕ

/-- What the simulator knows about a window: the public shape of the schedule
(coefficient counts — public protocol data), the schema, the round count. -/
structure SimWindow (F : Type*) where
  /-- number of coefficients per round, from the challenge history -/
  shape : List F → ℕ
  /-- claim schema closed by this window's `Π_ZeroBatch` -/
  S : ClaimSchema F
  /-- number of rounds -/
  n : ℕ

/-- The public shape of a window — all the simulator needs. -/
def Window.publicShape (w : Window F) : SimWindow F :=
  ⟨fun chals => (w.P chals).length, w.S, w.n⟩

/-- The residual adversary for one window: the global `V*` with the flat
public prefix `pre` (previous windows' corrections, challenges and openings)
baked into its strategies, and its correlation keys shifted to the fresh
index range starting at `off`. Same `Δ`: one session key for all windows. -/
def wrapV (V : MaliciousV F) (pre : List F) (off : ℕ) : MaliciousV F where
  Δ := V.Δ
  key := fun i => V.key (off + i)
  challenge := fun t => V.challenge (pre ++ t)
  chi := fun t => V.chi (pre ++ t)

omit [Field F] [Fintype F] in
/-- The number of correlations a window consumes is public: it is determined
by the public projection of the view. -/
theorem opensOf_length_public (v : List (RoundView F)) :
    (opensOf v).length = ((publicView v).flatMap Prod.fst).length := by
  rw [← opensOf_map_fst, List.length_map]

/-- Real multi-window execution, returning the *public* transcript: per
window, the public round data and the batched opening. The opening extends
the prefix (later windows depend on it) and the consumed correlations extend
the index offset (freshness). -/
noncomputable def realMulti (V : MaliciousV F) :
    List (Window F) → List F → ℕ → PMF (List (List (List F × F) × F))
  | [], _, _ => PMF.pure []
  | w :: ws, pre, off =>
    (realView w.P (wrapV V pre off) w.n []).bind fun view =>
      (realMulti V ws
          (pre ++ pubFlat (publicView view) ++ [realFinalMsg (wrapV V pre off) w.S view])
          (off + (opensOf view).length)).map
        fun rest => (publicView view, realFinalMsg (wrapV V pre off) w.S view) :: rest

/-- Simulated multi-window execution: corrections sampled uniformly per
window (`simView`), openings computed from `V*`'s keys (`simFinalMsg`) —
public shapes and verifier state only. -/
noncomputable def simMulti (V : MaliciousV F) :
    List (SimWindow F) → List F → ℕ → PMF (List (List (List F × F) × F))
  | [], _, _ => PMF.pure []
  | sw :: sws, pre, off =>
    (simView sw.shape (wrapV V pre off) sw.n []).bind fun view =>
      (simMulti V sws
          (pre ++ pubFlat (publicView view) ++ [simFinalMsg (wrapV V pre off) sw.S view])
          (off + (opensOf view).length)).map
        fun rest => (publicView view, simFinalMsg (wrapV V pre off) sw.S view) :: rest

/-- Continuation of the simulated execution after one window with public
transcript `pub`: a function of *public data and verifier state only*. Both
the real and the simulated window continuations collapse onto it. -/
noncomputable def simCont (V : MaliciousV F) (sws : List (SimWindow F))
    (S : ClaimSchema F) (pre : List F) (off : ℕ)
    (pub : List (List F × F)) : PMF (List (List (List F × F) × F)) :=
  (simMulti V sws
      (pre ++ pubFlat pub ++ [simFinalMsg (wrapV V pre off) S (viewOfPub pub)])
      (off + (pub.flatMap Prod.fst).length)).map
    fun rest => (pub, simFinalMsg (wrapV V pre off) S (viewOfPub pub)) :: rest

/-- **Sequential composition of perfect ZK (M6).** Any number of
`Π_BSC + Π_ZeroBatch` windows under one session key `Δ`, with fresh
correlation indices, against a single malicious verifier that adapts across
windows: if every window's closed claim list is identically zero on the
support (honest prover), the real public multi-transcript — openings
included — equals the simulated one *as a distribution*, for every prefix
and index offset. The simulator is straight-line and uses only the public
window shapes and `V*`'s state. -/
theorem sequential_composition_perfect_zk (V : MaliciousV F) (ws : List (Window F))
    (hzero : ∀ (pre : List F) (off : ℕ), ∀ w ∈ ws,
      ∀ view ∈ (realView w.P (wrapV V pre off) w.n []).support,
        ∀ j < w.S.T, (claimOf (wrapV V pre off) w.S view j).x = 0) :
    ∀ (pre : List F) (off : ℕ),
      realMulti V ws pre off = simMulti V (ws.map Window.publicShape) pre off := by
  induction ws with
  | nil => intro pre off; rfl
  | cons w ws ih =>
    intro pre off
    have ih' := ih fun pre off w' hw' => hzero pre off w' (List.mem_cons_of_mem w hw')
    simp only [realMulti, simMulti, List.map_cons, Window.publicShape]
    -- The real window continuation factors through the public projection,
    -- onto the all-public continuation `simCont`.
    have hreal : ∀ view ∈ (realView w.P (wrapV V pre off) w.n []).support,
        ((realMulti V ws
            (pre ++ pubFlat (publicView view)
              ++ [realFinalMsg (wrapV V pre off) w.S view])
            (off + (opensOf view).length)).map
          fun rest => (publicView view, realFinalMsg (wrapV V pre off) w.S view) :: rest)
        = simCont V (ws.map Window.publicShape) w.S pre off (publicView view) := by
      intro view hview
      have hmsg : realFinalMsg (wrapV V pre off) w.S view
          = simFinalMsg (wrapV V pre off) w.S (viewOfPub (publicView view)) :=
        (finalMsg_eq_sim (wrapV V pre off) w.S view
            (hzero pre off w List.mem_cons_self view hview)).trans
          (simFinalMsg_eq_of_publicView_eq (wrapV V pre off) w.S
            (publicView_viewOfPub (publicView view)).symm)
      rw [simCont, hmsg, opensOf_length_public, ih']
    -- The simulated window continuation factors the same way, pointwise.
    have hsim : ∀ view : List (RoundView F),
        ((simMulti V (ws.map Window.publicShape)
            (pre ++ pubFlat (publicView view)
              ++ [simFinalMsg (wrapV V pre off) w.S view])
            (off + (opensOf view).length)).map
          fun rest => (publicView view, simFinalMsg (wrapV V pre off) w.S view) :: rest)
        = simCont V (ws.map Window.publicShape) w.S pre off (publicView view) := by
      intro view
      have hmsg : simFinalMsg (wrapV V pre off) w.S view
          = simFinalMsg (wrapV V pre off) w.S (viewOfPub (publicView view)) :=
        simFinalMsg_eq_of_publicView_eq (wrapV V pre off) w.S
          (publicView_viewOfPub (publicView view)).symm
      rw [simCont, hmsg, opensOf_length_public]
    calc _ = (realView w.P (wrapV V pre off) w.n []).bind
            (fun view => simCont V (ws.map Window.publicShape) w.S pre off (publicView view)) :=
          bind_congr_support hreal
      _ = ((realView w.P (wrapV V pre off) w.n []).map publicView).bind
            (simCont V (ws.map Window.publicShape) w.S pre off) :=
          (bind_map (realView w.P (wrapV V pre off) w.n []) publicView
            (simCont V (ws.map Window.publicShape) w.S pre off)).symm
      _ = ((simView (fun chals => (w.P chals).length) (wrapV V pre off) w.n []).map
            publicView).bind (simCont V (ws.map Window.publicShape) w.S pre off) := by
          rw [realView_map_publicView w.P (wrapV V pre off) w.n [] [] rfl]
      _ = (simView (fun chals => (w.P chals).length) (wrapV V pre off) w.n []).bind
            (fun view => simCont V (ws.map Window.publicShape) w.S pre off (publicView view)) :=
          bind_map (simView (fun chals => (w.P chals).length) (wrapV V pre off) w.n [])
            publicView (simCont V (ws.map Window.publicShape) w.S pre off)
      _ = _ := (congrArg _ (funext hsim)).symm

end VoltaZk

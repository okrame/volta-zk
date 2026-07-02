import VoltaZk.Vole
import VoltaZk.ZeroBatch

/-!
# `Π_BSC`: blind sumcheck against a malicious designated verifier

`docs/protocol-sketch.md` § "Blind GKR Target".

Model. The prover never opens anything in the clear: per round it
authenticates the coefficients of the round polynomial via `Π_Auth`
(messages = uniform corrections), the verifier answers with a *public*
challenge chosen adaptively by an arbitrary strategy, and all linear
consistency relations (`p_i(0) + p_i(1) = σ_{i−1}`, LogUp rows, MLE openings)
are accumulated as zero-claims over the authenticated coefficients, closed at
the end of the window and discharged by one `Π_ZeroBatch`.

The *commit-then-challenge, deferred testing* principle is structural here:

* a challenge is a function of the transcript prefix, which already contains
  the corrections for every value the corresponding relation touches;
* the claim schema (`ClaimSchema`) reads only the **public** transcript —
  it cannot depend on masks or plaintexts;
* the batching challenge `χ` is a function of the full public transcript,
  i.e. of the closed claim list.

The malicious verifier `V*` chooses `Δ`, all VOLE keys (corrupted-V branch of
`F_sVOLE`), every round challenge, and `χ`.
-/

namespace VoltaZk

open PMF

variable {F : Type*} [Field F] [Fintype F]

/-! ### Parties -/

/-- A malicious designated verifier for `Π_BSC + Π_ZeroBatch` in the
`F_sVOLE`-hybrid model. It fixes the session key `Δ` and the key of every
fresh correlation upfront (the ideal functionality lets a corrupted verifier
choose them), and picks each public challenge and the batching challenge `χ`
adaptively from the public transcript so far. -/
structure MaliciousV (F : Type*) where
  /-- session MAC key, adversarially chosen -/
  Δ : F
  /-- adversarial key of the `i`-th fresh VOLE correlation -/
  key : ℕ → F
  /-- next public round challenge, given the flat public transcript so far -/
  challenge : List F → F
  /-- batching challenge for `Π_ZeroBatch`, given the full public transcript
  (the claim list is closed at that point) -/
  chi : List F → ℕ → F

/-- Honest-prover message schedule: the plaintext coefficients of the next
round polynomial, as a function of the public challenges issued so far
(they are derived from the witness and the wiring; we keep them abstract). -/
def RoundCoeffs (F : Type*) := List F → List F

/-! ### Views and transcripts -/

/-- One round as seen jointly: for each authenticated coefficient the pair
`(δ, u)` — correction `δ` is public, mask `u` is prover-private — followed by
the public challenge. -/
abbrev RoundView (F : Type*) := List (F × F) × F

/-- Public projection of one round: corrections and challenge. -/
def publicRound (rv : RoundView F) : List F × F :=
  ((rv.1.map Prod.fst : List F), rv.2)

/-- Public projection of a view. -/
def publicView (view : List (RoundView F)) : List (List F × F) :=
  view.map publicRound

/-- Flattening of a public transcript, fed to `V*`'s strategies. -/
def pubFlat (pub : List (List F × F)) : List F :=
  pub.flatMap fun rc => rc.1 ++ [rc.2]

/-- All `(δ, u)` pairs of a view, in correlation-index order. -/
def opensOf (view : List (RoundView F)) : List (F × F) :=
  view.flatMap Prod.fst

omit [Field F] [Fintype F] in
/-- The public corrections of a view are recoverable from its public
projection: the simulator loses nothing by seeing only public data. -/
theorem opensOf_map_fst (v : List (RoundView F)) :
    (opensOf v).map Prod.fst = (publicView v).flatMap Prod.fst := by
  simp [opensOf, publicView, publicRound, List.map_flatMap, List.flatMap_map]

omit [Field F] [Fintype F] in
theorem publicView_append (v w : List (RoundView F)) :
    publicView (v ++ w) = publicView v ++ publicView w :=
  List.map_append ..

omit [Field F] [Fintype F] in
/-- The challenge history is public: both parties derive the prover's next
input from the public projection alone. -/
theorem publicView_map_snd (v : List (RoundView F)) :
    (publicView v).map Prod.snd = v.map Prod.snd := by
  simp only [publicView, List.map_map]
  rfl

/-- Canonical view reconstructed from a public transcript (dummy masks `0`) —
what the simulator materializes. Its public projection is the identity. -/
def viewOfPub (pub : List (List F × F)) : List (RoundView F) :=
  pub.map fun rc => (rc.1.map fun d => (d, (0 : F)), rc.2)

omit [Fintype F] in
theorem publicView_viewOfPub (pub : List (List F × F)) :
    publicView (viewOfPub pub) = pub := by
  simp [publicView, viewOfPub, publicRound, List.map_map, Function.comp_def]

/-- Uniform distribution on length-`m` vectors over `F` (fresh masks or
simulated corrections for one round). -/
noncomputable def uniformVec (F : Type*) [Fintype F] [Nonempty F]
    (m : ℕ) : PMF (List F) :=
  (uniformOfFintype (Fin m → F)).map List.ofFn

omit [Fintype F] in
theorem zipWith_sub_ofFn :
    ∀ (cs : List F) (v : Fin cs.length → F),
      List.zipWith (fun c u => c - u) cs (List.ofFn v)
        = List.ofFn fun i => cs.get i - v i
  | [], _ => rfl
  | c :: cs, v => by
    rw [List.ofFn_succ, List.zipWith_cons_cons,
      zipWith_sub_ofFn cs fun i => v i.succ, List.ofFn_succ]
    rfl

/-- **Vector one-time pad.** Componentwise correction of a uniform mask vector
by any fixed coefficient vector is again uniform: the corrections the honest
prover sends in one round carry no information about the coefficients. -/
theorem uniformVec_zipWith_sub (cs : List F) :
    (uniformVec F cs.length).map (fun us => List.zipWith (fun c u => c - u) cs us)
      = uniformVec F cs.length := by
  unfold uniformVec
  rw [map_comp]
  have hfun : ((fun us => List.zipWith (fun c u => c - u) cs us) ∘ List.ofFn)
      = (List.ofFn ∘ fun (v : Fin cs.length → F) i => cs.get i - v i) :=
    funext fun v => zipWith_sub_ofFn cs v
  rw [hfun, ← map_comp,
    show (uniformOfFintype (Fin cs.length → F)).map
          (fun (v : Fin cs.length → F) i => cs.get i - v i)
        = uniformOfFintype (Fin cs.length → F) from
      map_equiv_uniform (Equiv.piCongrRight fun i => Equiv.subLeft (cs.get i))]

/-! ### Real and simulated executions -/

/-- Real execution of the `Π_BSC` message schedule for `n` rounds: per round
the prover authenticates its coefficients (fresh uniform masks `u`, public
corrections `δ = c − u`), then `V*` emits its public challenge. -/
noncomputable def realView (P : RoundCoeffs F) (V : MaliciousV F) :
    ℕ → List (RoundView F) → PMF (List (RoundView F))
  | 0, acc => PMF.pure acc
  | n + 1, acc =>
    (uniformVec F (P (acc.map Prod.snd)).length).bind fun us =>
      let pairs := List.zipWith (fun c u => (c - u, u)) (P (acc.map Prod.snd)) us
      let chal := V.challenge (pubFlat (publicView acc) ++ pairs.map Prod.fst)
      realView P V n (acc ++ [(pairs, chal)])

/-- Simulated execution: the simulator knows only the public shape of the
schedule (number of coefficients per round — public protocol data) and `V*`'s
state. It samples the corrections uniformly — justified by
`auth_correction_uniform` — and stores a dummy mask `0`. -/
noncomputable def simView (shape : List F → ℕ) (V : MaliciousV F) :
    ℕ → List (RoundView F) → PMF (List (RoundView F))
  | 0, acc => PMF.pure acc
  | n + 1, acc =>
    (uniformVec F (shape (acc.map Prod.snd))).bind fun ds =>
      let pairs := ds.map fun d => (d, (0 : F))
      let chal := V.challenge (pubFlat (publicView acc) ++ ds)
      simView shape V n (acc ++ [(pairs, chal)])

/-! ### Authenticated coefficients and the closed claim list -/

/-- The authenticated value produced by the `i`-th correction of the schedule:
plaintext `δ + u`, prover tag `key i − Δ·u` (ideal `F_sVOLE`), verifier key
`key i + Δ·δ` (local update of `Π_Auth`). -/
def authedAt (V : MaliciousV F) (opens : List (F × F)) (i : ℕ) : Authed F :=
  ⟨(opens.getD i (0, 0)).1 + (opens.getD i (0, 0)).2,
    V.key i - V.Δ * (opens.getD i (0, 0)).2,
    V.key i + V.Δ * (opens.getD i (0, 0)).1⟩

omit [Fintype F] in
theorem authedAt_valid (V : MaliciousV F) (opens : List (F × F)) (i : ℕ) :
    (authedAt V opens i).Valid V.Δ := by
  unfold Authed.Valid authedAt
  ring

/-- The closed list of zero-claims produced by `Π_BSC`: claim `j` is a
public-coefficient linear combination of the authenticated coefficients plus
a public constant. Coefficients and constants are functions of the **public**
transcript only — this is the formal content of *commit-then-challenge*: the
schema is fixed by data the verifier already saw, and can never read masks or
plaintexts. -/
structure ClaimSchema (F : Type*) where
  /-- number of claims in the closed list -/
  T : ℕ
  /-- public transcript ↦ claim index ↦ correlation index ↦ coefficient -/
  coeff : List (List F × F) → ℕ → ℕ → F
  /-- public transcript ↦ claim index ↦ additive public constant -/
  const : List (List F × F) → ℕ → F

/-- Claim `j` as an authenticated value, over a (real) view. -/
def claimOf (V : MaliciousV F) (S : ClaimSchema F)
    (view : List (RoundView F)) (j : ℕ) : Authed F :=
  (∑ i ∈ Finset.range (opensOf view).length,
      S.coeff (publicView view) j i • authedAt V (opensOf view) i)
    + Authed.ofPublic V.Δ (S.const (publicView view) j)

omit [Fintype F] in
theorem claimOf_valid (V : MaliciousV F) (S : ClaimSchema F)
    (view : List (RoundView F)) (j : ℕ) :
    (claimOf V S view j).Valid V.Δ :=
  Authed.Valid.add
    (Authed.Valid.sum fun i _ => (authedAt_valid V _ i).smul _)
    (Authed.ofPublic_valid _ _)

/-! ### Final openings -/

/-- The prover's final `Π_ZeroBatch` message: the `m`-side of the χ-combination
of the closed claim list. -/
def realFinalMsg (V : MaliciousV F) (S : ClaimSchema F)
    (view : List (RoundView F)) : F :=
  ∑ j ∈ Finset.range S.T,
    V.chi (pubFlat (publicView view)) j * (claimOf V S view j).m

/-- The simulator's final message: the `k`-side of the same combination.
`authedAt … .k = key i + Δ·δ_i` and `ofPublic … .k = Δ·const` read only the
public corrections, `V*`'s keys and `Δ` — verifier-state data
(`claimOf_k_public` below makes this formal). -/
def simFinalMsg (V : MaliciousV F) (S : ClaimSchema F)
    (view : List (RoundView F)) : F :=
  ∑ j ∈ Finset.range S.T,
    V.chi (pubFlat (publicView view)) j * (claimOf V S view j).k

omit [Field F] [Fintype F] in
/-- First component of an indexed lookup commutes with the `Prod.fst`
projection of the list. -/
theorem getD_fst {α : Type*} [Zero α] (l : List (α × α)) (i : ℕ) :
    (l.getD i (0, 0)).1 = (l.map Prod.fst).getD i 0 := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases l[i]? <;> rfl

omit [Fintype F] in
/-- The `k`-side of a claim depends only on the public projection of the view
(the simulator never needs masks or plaintexts). -/
theorem claimOf_k_public (V : MaliciousV F) (S : ClaimSchema F)
    {v₁ v₂ : List (RoundView F)} (h : publicView v₁ = publicView v₂) (j : ℕ) :
    (claimOf V S v₁ j).k = (claimOf V S v₂ j).k := by
  have hopens : (opensOf v₁).map Prod.fst = (opensOf v₂).map Prod.fst := by
    rw [opensOf_map_fst, opensOf_map_fst, h]
  have hlen : (opensOf v₁).length = (opensOf v₂).length := by
    have := congrArg List.length hopens
    simpa using this
  have hk : ∀ i, (authedAt V (opensOf v₁) i).k = (authedAt V (opensOf v₂) i).k := by
    intro i
    have hδ : ((opensOf v₁).getD i (0, 0)).1 = ((opensOf v₂).getD i (0, 0)).1 := by
      rw [getD_fst, getD_fst, hopens]
    change V.key i + V.Δ * ((opensOf v₁).getD i (0, 0)).1
        = V.key i + V.Δ * ((opensOf v₂).getD i (0, 0)).1
    rw [hδ]
  simp only [claimOf, Authed.add_k, Authed.sum_k, Authed.smul_k,
    Authed.ofPublic_k, hlen, h]
  refine congrArg₂ (· + ·) (Finset.sum_congr rfl fun i _ => ?_) rfl
  rw [hk i]

omit [Fintype F] in
/-- **ZeroBatch half of the composition, pointwise.** On any view whose closed
claim list consists of *true* zero claims (honest prover), the prover's final
opening equals the value the simulator computes from `V*`'s state and the
public transcript alone. -/
theorem finalMsg_eq_sim (V : MaliciousV F) (S : ClaimSchema F)
    (view : List (RoundView F))
    (hzero : ∀ j < S.T, (claimOf V S view j).x = 0) :
    realFinalMsg V S view = simFinalMsg V S view := by
  unfold realFinalMsg simFinalMsg
  refine Finset.sum_congr rfl fun j hj => ?_
  rw [(claimOf_valid V S view j).msg_eq_key (hzero j (Finset.mem_range.mp hj))]

omit [Fintype F] in
/-- `simFinalMsg` factors through the public projection: views with the same
public transcript get the same simulated final message. -/
theorem simFinalMsg_eq_of_publicView_eq (V : MaliciousV F) (S : ClaimSchema F)
    {v₁ v₂ : List (RoundView F)} (h : publicView v₁ = publicView v₂) :
    simFinalMsg V S v₁ = simFinalMsg V S v₂ := by
  unfold simFinalMsg
  rw [h]
  refine Finset.sum_congr rfl fun j _ => ?_
  rw [claimOf_k_public V S h j]

/-! ### Transcripts and the main theorem -/

/-- **Core distributional equality.** The public transcript of the real
execution is distributed exactly as the simulated one, for any pair of
accumulators with equal public projections. Per round: the prover's
corrections are one-time padded (`uniformVec_zipWith_sub`), and the
challenge is a deterministic function of the public prefix — identical in
both worlds. Induction over the remaining rounds. -/
theorem realView_map_publicView (P : RoundCoeffs F) (V : MaliciousV F) :
    ∀ (n : ℕ) (accR accS : List (RoundView F)),
      publicView accR = publicView accS →
      (realView P V n accR).map publicView
        = (simView (fun chals => (P chals).length) V n accS).map publicView := by
  intro n
  induction n with
  | zero =>
    intro accR accS h
    simp only [realView, simView, pure_map, h]
  | succ n ih =>
    intro accR accS h
    have hsnd : accS.map Prod.snd = accR.map Prod.snd := by
      rw [← publicView_map_snd, ← h, publicView_map_snd]
    simp only [realView, simView, map_bind, hsnd]
    set cs := P (accR.map Prod.snd) with hcs
    set B : List F → PMF (List (List F × F)) := fun d =>
      (simView (fun chals => (P chals).length) V n
        (accS ++ [(d.map fun x => (x, (0 : F)),
          V.challenge (pubFlat (publicView accS) ++ d))])).map publicView with hB
    have h1 : ∀ us : List F,
        (realView P V n (accR ++ [(List.zipWith (fun c u => (c - u, u)) cs us,
            V.challenge (pubFlat (publicView accR)
              ++ (List.zipWith (fun c u => (c - u, u)) cs us).map Prod.fst))])).map
            publicView
          = B (List.zipWith (fun c u => c - u) cs us) := by
      intro us
      refine ih _ _ ?_
      have h' : List.map publicRound accR = List.map publicRound accS := h
      simp [publicView, publicRound, List.map_zipWith, h']
    calc _ = (uniformVec F cs.length).bind
            (fun us => B (List.zipWith (fun c u => c - u) cs us)) :=
          congrArg _ (funext h1)
      _ = ((uniformVec F cs.length).map
            (fun us => List.zipWith (fun c u => c - u) cs us)).bind B :=
          (bind_map (uniformVec F cs.length)
            (fun us => List.zipWith (fun c u => c - u) cs us) B).symm
      _ = (uniformVec F cs.length).bind B := by rw [uniformVec_zipWith_sub]

/-- Full public transcript of `Π_BSC + Π_ZeroBatch`: per-round public data
plus the final batched opening. -/
noncomputable def realTranscript (P : RoundCoeffs F) (V : MaliciousV F)
    (S : ClaimSchema F) (n : ℕ) : PMF (List (List F × F) × F) :=
  (realView P V n []).map fun view => (publicView view, realFinalMsg V S view)

/-- Simulated transcript: same shape, corrections sampled uniformly, final
message computed from `V*`'s state (`simFinalMsg` reads only public data,
by `claimOf_k_public`). -/
noncomputable def simTranscript (shape : List F → ℕ) (V : MaliciousV F)
    (S : ClaimSchema F) (n : ℕ) : PMF (List (List F × F) × F) :=
  (simView shape V n []).map fun view => (publicView view, simFinalMsg V S view)

/-- **Main formal target (milestone 2 — proof pending).**

Perfect zero-knowledge of `Π_BSC + Π_ZeroBatch` against a malicious designated
verifier in the `F_sVOLE`-hybrid model: for every honest prover schedule `P`
whose closed claim list is identically zero on the support of the real
execution, and every `V*`, the simulated transcript — produced from the public
shape of the schedule and `V*`'s state only — is *equal as a distribution* to
the real transcript.

Proof plan: induction over rounds. Each block of corrections is uniform and
independent of the coefficients (`auth_correction_uniform` /
`sub_left_uniform`, one-time pad), challenges are deterministic functions of
the public prefix (same in both worlds), and the final openings agree
pointwise on the support by `finalMsg_eq_sim`. No prover message distribution
depends on the witness conditionally on the challenges, so no rewinding or
masking is needed — the simulator is straight-line. -/
theorem bsc_zeroBatch_perfect_zk (P : RoundCoeffs F) (V : MaliciousV F)
    (S : ClaimSchema F) (n : ℕ)
    (hzero : ∀ view ∈ (realView P V n []).support,
      ∀ j < S.T, (claimOf V S view j).x = 0) :
    realTranscript P V S n
      = simTranscript (fun chals => (P chals).length) V S n := by
  unfold realTranscript simTranscript
  have hreal : (realView P V n []).map
      (fun view => (publicView view, realFinalMsg V S view))
      = (realView P V n []).map
        ((fun pub => (pub, simFinalMsg V S (viewOfPub pub))) ∘ publicView) := by
    refine map_congr_support fun v hv => ?_
    have h1 := finalMsg_eq_sim V S v (hzero v hv)
    have h2 := simFinalMsg_eq_of_publicView_eq V S
      (publicView_viewOfPub (publicView v)).symm
    change (publicView v, realFinalMsg V S v)
      = (publicView v, simFinalMsg V S (viewOfPub (publicView v)))
    rw [h1, h2]
  have hsim : (simView (fun chals => (P chals).length) V n []).map
      (fun view => (publicView view, simFinalMsg V S view))
      = (simView (fun chals => (P chals).length) V n []).map
        ((fun pub => (pub, simFinalMsg V S (viewOfPub pub))) ∘ publicView) := by
    refine map_congr_support fun v _ => ?_
    have h2 := simFinalMsg_eq_of_publicView_eq V S
      (publicView_viewOfPub (publicView v)).symm
    change (publicView v, simFinalMsg V S v)
      = (publicView v, simFinalMsg V S (viewOfPub (publicView v)))
    rw [h2]
  rw [hreal, hsim, ← map_comp, ← map_comp,
    realView_map_publicView P V n [] [] rfl]

end VoltaZk

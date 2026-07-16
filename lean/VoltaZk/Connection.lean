import VoltaZk.Composition
import VoltaZk.KvCache
import VoltaZk.Subfield
import Mathlib.Data.Fin.Tuple.Finset

/-!
# Connection-scoped shared-Delta composition (M10)

Fase D keeps one verifier MAC key `Delta` for several responses on one
connection.  This file records the minimal extension of M2--M6 needed for
that lifecycle:

* the full correlation domain contains both the connection identity and the
  single-use response nonce, so domains belonging to distinct responses do
  not collide;
* M4's cache theorem applies unchanged to the enlarged domain.  On the common
  tape `Delta x (Fin R -> Xi)`, fixing every other response coin leaves one
  local M4 slice; lifting its bound costs exactly `|Xi|^(R-1)`, and the final
  union bound loses at most one further factor `R`;
* a vector of corrections made with fresh masks is jointly uniform, and M6's
  sequential simulator applies to all windows of all responses with one
  `Delta` and one monotonically increasing correlation offset.

The durable store is responsible for the injectivity of response nonces and
for terminal connection burn.  The ideal-sVOLE model is responsible for fresh
correlations at distinct offsets.  These theorems do not realize ideal sVOLE
with the concrete PCG, prove the AES-MMO assumption, or model filesystem
durability and abort/restart behavior.
-/

namespace VoltaZk

open Finset PMF

/-- Full fase-D allocation domain.  The first two fields separate connections
and responses; the remaining fields retain the M4 intra-response domain. -/
structure ConnectionDomain where
  /-- durable connection identity -/
  connectionId : Nat
  /-- durable single-use response authorization nonce -/
  responseNonce : Nat
  /-- transformer layer -/
  layer : Nat
  /-- attention head -/
  head : Nat
  /-- token position -/
  position : Nat
  /-- tensor-role discriminator -/
  tensorTag : Nat
deriving DecidableEq

/-- **M10 domain separation.** If response nonces are injective, then every
domain belonging to response `r` differs from every domain belonging to a
different response `s`, regardless of their intra-response coordinates. -/
theorem response_domains_noncolliding {R : Nat} (connectionId : Nat)
    (nonce : Fin R → Nat) (hnonce : Function.Injective nonce)
    {r s : Fin R} (hrs : r ≠ s)
    (layerR headR positionR tensorTagR layerS headS positionS tensorTagS : Nat) :
    ConnectionDomain.mk connectionId (nonce r) layerR headR positionR tensorTagR ≠
      ConnectionDomain.mk connectionId (nonce s) layerS headS positionS tensorTagS := by
  intro h
  apply hrs
  apply hnonce
  exact congrArg ConnectionDomain.responseNonce h

/-- **M10 per-response M4 statement.** Enlarging the cache/allocation index
to `ConnectionDomain` does not change Rust's scalar-power M4 bound.  A forged
read in one response is accepted on at most `(T+1)*|F|` tapes `(Delta, chi)`.
-/
theorem connection_response_sound_scalar {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    (L : WriteLog ConnectionDomain F) {T : Nat}
    (idx : Fin T → ConnectionDomain) (stored : Fin T → F × F)
    (hstored : ∀ j, (idx j, stored j) ∈ L.entries)
    (claim : Fin T → F × F) {j₀ : Fin T} {w₀ : F × F}
    (hw : (idx j₀, w₀) ∈ L.entries) (hforge : (claim j₀).1 ≠ w₀.1)
    (msg : F → F) :
    (univ.filter fun Δχ : F × F =>
        msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) *
          (keyOf Δχ.1 (claim j) - keyOf Δχ.1 (stored j))).card
      ≤ (T + 1) * Fintype.card F :=
  kv_cache_sound_scalar L idx stored hstored claim hw hforge msg

/-- Split one common connection tape into the local tape `(Delta, xi_r)` for
response `r` and the `n` other responses' coins.  The inverse is the canonical
lift that inserts the local coin at coordinate `r`. -/
def responseTapeEquiv {Delta Xi : Type*} {n : Nat} (r : Fin (n + 1)) :
    ((Delta × Xi) × (Fin n → Xi)) ≃ Delta × (Fin (n + 1) → Xi) :=
  (Equiv.prodAssoc Delta Xi (Fin n → Xi)).trans
    (Equiv.prodCongr (Equiv.refl Delta)
      (Fin.insertNthEquiv (fun _ : Fin (n + 1) => Xi) r))

/-- Projection of a common tape onto the shared `Delta` and response `r`'s
local verifier coin. -/
def responseTapeProject {Delta Xi : Type*} {R : Nat} (r : Fin R)
    (tape : Delta × (Fin R → Xi)) : Delta × Xi :=
  (tape.1, tape.2 r)

@[simp]
theorem responseTapeEquiv_apply_fst {Delta Xi : Type*} {n : Nat}
    (r : Fin (n + 1)) (dxi : Delta × Xi) (rest : Fin n → Xi) :
    (responseTapeEquiv r (dxi, rest)).1 = dxi.1 := rfl

@[simp]
theorem responseTapeEquiv_apply_at {Delta Xi : Type*} {n : Nat}
    (r : Fin (n + 1)) (dxi : Delta × Xi) (rest : Fin n → Xi) :
    (responseTapeEquiv r (dxi, rest)).2 r = dxi.2 := by
  simp [responseTapeEquiv]

@[simp]
theorem responseTapeProject_lift {Delta Xi : Type*} {n : Nat}
    (r : Fin (n + 1)) (dxi : Delta × Xi) (rest : Fin n → Xi) :
    responseTapeProject r (responseTapeEquiv r (dxi, rest)) = dxi := by
  ext <;> simp [responseTapeProject]

/-- **Exact lift cost for one adaptive response event.** `bad` is a set on
the complete connection tape and may depend arbitrarily on the coins of all
other responses.  If, after fixing those coins, every local `(Delta, xi_r)`
slice has at most `B` bad elements, then lifting the local statement costs
exactly the number `|Xi|^n` of assignments to the other coordinates. -/
theorem response_bad_card_le {Delta Xi : Type*}
    [Fintype Delta] [Fintype Xi] [DecidableEq Delta] [DecidableEq Xi]
    {n B : Nat} (r : Fin (n + 1))
    (bad : Finset (Delta × (Fin (n + 1) → Xi)))
    (hslice : ∀ rest : Fin n → Xi,
      (univ.filter fun dxi : Delta × Xi =>
        responseTapeEquiv r (dxi, rest) ∈ bad).card ≤ B) :
    bad.card ≤ B * Fintype.card Xi ^ n := by
  classical
  let e : ((Delta × Xi) × (Fin n → Xi)) ≃ Delta × (Fin (n + 1) → Xi) :=
    responseTapeEquiv r
  let p : ((Delta × Xi) × (Fin n → Xi)) → Prop := fun z => e z ∈ bad
  have htransport : bad.card = (univ.filter p).card := by
    rw [← card_filter_equiv e p]
    simp [p, e]
  rw [htransport]
  simpa only [Fintype.card_fun, Fintype.card_fin] using
    card_filter_prod_le_left p hslice

/-- **M10 shared-Delta union bound.** For `n+1` adaptive response events on
one common tape, a local slice bound `B` gives the exact other-coordinate
factor `|Xi|^n`, followed by the ordinary `(n+1)`-event union bound.  No
independence between responses is assumed. -/
theorem connection_soundness_union_bound {Delta Xi : Type*}
    [Fintype Delta] [Fintype Xi] [DecidableEq Delta] [DecidableEq Xi]
    {n B : Nat}
    (bad : Fin (n + 1) → Finset (Delta × (Fin (n + 1) → Xi)))
    (hslice : ∀ r (rest : Fin n → Xi),
      (univ.filter fun dxi : Delta × Xi =>
        responseTapeEquiv r (dxi, rest) ∈ bad r).card ≤ B) :
    (univ.biUnion bad).card ≤ (n + 1) * B * Fintype.card Xi ^ n := by
  calc
    (univ.biUnion bad).card
        ≤ (n + 1) * (B * Fintype.card Xi ^ n) := by
          simpa using Finset.card_biUnion_le_card_mul univ bad
            (B * Fintype.card Xi ^ n)
            (fun r _ => response_bad_card_le r (bad r) (hslice r))
    _ = (n + 1) * B * Fintype.card Xi ^ n := by simp [Nat.mul_assoc]

/-- **M10 instantiated with Rust's scalar-power M4 bound.** For `n+1`
responses, each fixed-rest slice contributes at most `(T+1)*|F|` bad local
tapes by `connection_response_sound_scalar`.  Hence the any-response bad set
has numerator at most `(n+1)*(T+1)*|F|^(n+1)`. -/
theorem connection_m4_soundness_union_bound {F : Type*}
    [Field F] [Fintype F] [DecidableEq F]
    {n T : Nat}
    (bad : Fin (n + 1) → Finset (F × (Fin (n + 1) → F)))
    (hslice : ∀ r (rest : Fin n → F),
      (univ.filter fun dxi : F × F =>
        responseTapeEquiv r (dxi, rest) ∈ bad r).card
        ≤ (T + 1) * Fintype.card F) :
    (univ.biUnion bad).card
      ≤ (n + 1) * (T + 1) * Fintype.card F ^ (n + 1) := by
  have h := connection_soundness_union_bound bad hslice
  simpa [pow_succ, Nat.mul_assoc, Nat.mul_left_comm, Nat.mul_comm] using h

/-- The common scalar-M4 connection tape has denominator `|F|^(n+2)`:
one shared `Delta` and `n+1` independently sampled response challenges. -/
theorem connection_m4_tape_card {F : Type*} [Fintype F] {n : Nat} :
    Fintype.card (F × (Fin (n + 1) → F)) = Fintype.card F ^ (n + 2) := by
  simp [pow_succ, Nat.mul_comm]

variable {F : Type*} [Field F] [Fintype F]

/-- **M10 joint correction hiding.** For any finite coordinate type `I`,
fresh masks make the entire correction function uniform and independent of
the plaintext function.  Instantiate `I` with all `(response, local slot)`
coordinates and `F` with M5's correction field `Fp`; tags, keys and the shared
`Delta` remain in the extension field and do not enter the correction. -/
theorem connection_corrections_uniform {I : Type*} [Fintype I] [DecidableEq I]
    (x : I → F) :
    (uniformOfFintype (I → F)).map (fun u i => x i - u i)
      = uniformOfFintype (I → F) := by
  exact map_equiv_uniform (Equiv.piCongrRight fun r => Equiv.subLeft (x r))

/-- **M10 shared-Delta blindness.** Flattening the windows of every response
and applying M6 gives perfect simulation against a verifier adaptive across
responses.  `V.Delta` is shared by construction, while `realMulti` advances
one global correlation offset after each window, so every consumed
correlation remains one-time. -/
theorem connection_responses_perfect_zk (V : MaliciousV F)
    (responses : List (List (Window F)))
    (hzero : ∀ (pre : List F) (off : Nat), ∀ w ∈ responses.flatten,
      ∀ view ∈ (realView w.P (wrapV V pre off) w.n []).support,
        ∀ j < w.S.T, (claimOf (wrapV V pre off) w.S view j).x = 0) :
    ∀ (pre : List F) (off : Nat),
      realMulti V responses.flatten pre off =
        simMulti V (responses.flatten.map Window.publicShape) pre off :=
  sequential_composition_perfect_zk V responses.flatten hzero

end VoltaZk

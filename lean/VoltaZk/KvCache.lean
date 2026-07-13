import VoltaZk.ZeroBatchSound

/-!
# KV-cache anti-replay and append-only cache soundness (M4)

`docs/protocol-sketch.md` § "Next Formal Targets" item 2: index domain
separation ⇒ replay or mix-and-match across
`(session, query, layer, head, position)` indices is a MAC forgery;
append-only cache soundness for the stateful decoding functionality `F_VDec`.

Modeling (same conventions as M3, see `VoltaZk/ZeroBatchSound.lean`): the
malicious prover is deterministic and value-level — for every authenticated
cache entry it chooses a plaintext/tag pair `(x, m)` and the corrupted-P
branch of `F_sVOLE` determines the verifier key `k = m + Δ·x = keyOf Δ (x, m)`.
The verifier's cache state is an append-only write log binding each *full*
index tuple to the pair authenticated at write time; **domain separation** is
the freshness condition that the index projection of the log is duplicate-free
(`WriteLog.fresh`), so each index binds a unique entry
(`WriteLog.read_eq_of_mem`) and appending never rebinds an old index
(`WriteLog.append_read_stable`).

A cache read at index `i` re-enters the transcript as a fresh authenticated
pair `claim` together with the zero-opening of `claim - stored i`, whose
verifier key `keyOf Δ claim - keyOf Δ (stored i)` the verifier computes from
its stored key alone. Soundness then reduces directly to the M3a
unforgeability lemmas:

* `cache_open_forge` — a single forged read (claimed plaintext ≠ written
  plaintext) is accepted by at most one session key `Δ`: reuse of
  `zeroOpen_sound` through linearity of `keyOf` (error `1/|F|`);
* `cache_read_sound` / `cache_mix_sound` — the log-aware forms: substituting
  the entry written at any other `(session, query, layer, head, position)`
  index forges unless the plaintexts coincide (replay and mix-and-match);
* `kv_cache_sound` — **M4 main theorem**: `T` batched cache reads checked by
  `Π_ZeroBatch`; if any read claim differs from the unique logged write at its
  index, the batched opening verifies on at most `2·|F|^T` of the `|F|^(T+1)`
  verifier tapes `(Δ, χ)` — soundness error `≤ 2/|F|`, via `zeroBatch_sound`.
* `kv_cache_sound_scalar` — the implementation-facing scalar-power format:
  one `χ`, weights `χ^(j+1)`, and at most `(T+1)·|F|` accepting tapes
  out of `|F|²` (soundness error upper bound `(T+1)/|F|`).

Multi-session note: the session identifier is part of the index tuple, so
cross-session replay *under one `Δ`* is covered by domain separation; sessions
with independent keys are independent games and need no lemma.
-/

namespace VoltaZk

open Finset

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/-- Full cache-entry index: everything a decoding step must pin down before
an authenticated K/V value may be re-used. Domain separation of the MAC keys
is duplicate-freeness of these tuples in the write log. -/
structure CacheIndex where
  /-- verification session -/
  session : ℕ
  /-- query (decoding request) within the session -/
  query : ℕ
  /-- transformer layer -/
  layer : ℕ
  /-- attention head -/
  head : ℕ
  /-- token position -/
  pos : ℕ
deriving DecidableEq

omit [Fintype F] [DecidableEq F] in
/-- Linearity of the verifier key in the adversary pair: keys of differences
are differences of keys, so consistency checks between authenticated values
are themselves zero-openings of authenticated values. -/
theorem keyOf_sub (Δ : F) (a b : F × F) :
    keyOf Δ (a - b) = keyOf Δ a - keyOf Δ b := by
  simp only [keyOf, Prod.fst_sub, Prod.snd_sub]
  ring

/-- Append-only authenticated cache: a write log of adversary pairs keyed by
full indices, with **domain separation** — no index is ever written twice. -/
structure WriteLog (I F : Type*) where
  /-- the (index, plaintext/tag pair) write events, in order -/
  entries : List (I × (F × F))
  /-- domain separation / freshness: full index tuples never repeat -/
  fresh : (entries.map Prod.fst).Nodup

namespace WriteLog

variable {I : Type*}

omit [Field F] [Fintype F] [DecidableEq F] in
/-- **Statefulness.** Domain separation makes the cache a partial function:
each index binds a unique written pair, so "the stored value at `i`" is
well-defined and the verifier's stored key is canonical. -/
theorem read_eq_of_mem (L : WriteLog I F) {i : I} {vm vm' : F × F}
    (h : (i, vm) ∈ L.entries) (h' : (i, vm') ∈ L.entries) : vm = vm' :=
  congrArg Prod.snd (List.inj_on_of_nodup_map L.fresh h h' rfl)

/-- Appending a batch of writes at fresh indices (one decoding step of
`F_VDec`): the extended log is again domain-separated. -/
def append (L : WriteLog I F) (new : List (I × (F × F)))
    (hnew : (new.map Prod.fst).Nodup)
    (hdisj : ∀ i ∈ new.map Prod.fst, i ∉ L.entries.map Prod.fst) :
    WriteLog I F where
  entries := L.entries ++ new
  fresh := by
    rw [List.map_append]
    exact L.fresh.append hnew fun i hi hi' => hdisj i hi' hi

omit [Field F] [Fintype F] [DecidableEq F] in
/-- Old writes survive an append. -/
theorem mem_append_left (L : WriteLog I F) {new : List (I × (F × F))}
    {hnew : (new.map Prod.fst).Nodup}
    {hdisj : ∀ i ∈ new.map Prod.fst, i ∉ L.entries.map Prod.fst}
    {i : I} {vm : F × F} (h : (i, vm) ∈ L.entries) :
    (i, vm) ∈ (L.append new hnew hdisj).entries :=
  List.mem_append_left new h

omit [Field F] [Fintype F] [DecidableEq F] in
/-- **Append-only soundness of the cache state.** A read from the extended
log at an old index still returns the original write: appending can only add
bindings at fresh indices, never rebind an existing one. -/
theorem append_read_stable (L : WriteLog I F) {new : List (I × (F × F))}
    {hnew : (new.map Prod.fst).Nodup}
    {hdisj : ∀ i ∈ new.map Prod.fst, i ∉ L.entries.map Prod.fst}
    {i : I} {vm vm' : F × F} (hold : (i, vm) ∈ L.entries)
    (hread : (i, vm') ∈ (L.append new hnew hdisj).entries) : vm' = vm :=
  (L.append new hnew hdisj).read_eq_of_mem hread (L.mem_append_left hold)

end WriteLog

/-- **Forged cache read, single opening.** If the claimed plaintext differs
from the stored one, the zero-opening of `claim - stored` is accepted by at
most one session key `Δ` — a MAC forgery, error `1/|F|`. Direct reuse of
`zeroOpen_sound` through `keyOf_sub`. -/
theorem cache_open_forge (stored claim : F × F) (hforge : claim.1 ≠ stored.1)
    (msg : F) :
    (univ.filter fun Δ : F => msg = keyOf Δ claim - keyOf Δ stored).card ≤ 1 := by
  simp only [← keyOf_sub]
  exact zeroOpen_sound (claim - stored)
    (by rw [Prod.fst_sub]; exact sub_ne_zero.mpr hforge) msg

/-- **Anti-replay, log-aware form.** Against a domain-separated write log,
answering a read of index `i` with any pair whose plaintext differs from the
(unique) value written at `i` forges: at most one `Δ` accepts the opening.
The freshness of the log is what makes `stored` — the verifier's key-side
snapshot — agree with the witnessed write `w₀`. -/
theorem cache_read_sound {I : Type*} (L : WriteLog I F) {i : I}
    {stored w₀ : F × F} (hstored : (i, stored) ∈ L.entries)
    (hw : (i, w₀) ∈ L.entries) (claim : F × F) (hforge : claim.1 ≠ w₀.1)
    (msg : F) :
    (univ.filter fun Δ : F => msg = keyOf Δ claim - keyOf Δ stored).card ≤ 1 :=
  cache_open_forge stored claim
    (by rw [L.read_eq_of_mem hstored hw]; exact hforge) msg

/-- **Mix-and-match.** Substituting the entry written at a *different*
`(session, query, layer, head, position)` index — replay across sessions,
positions, heads, … under one `Δ` — is the special case `claim := vm'` of a
forged read, and fails on all but at most one key whenever the plaintexts
differ. -/
theorem cache_mix_sound {I : Type*} (L : WriteLog I F) {i i' : I}
    {stored vm' : F × F} (hstored : (i, stored) ∈ L.entries)
    (_hw : (i', vm') ∈ L.entries) (hne : vm'.1 ≠ stored.1) (msg : F) :
    (univ.filter fun Δ : F => msg = keyOf Δ vm' - keyOf Δ stored).card ≤ 1 :=
  cache_read_sound L hstored hstored vm' hne msg

/-- **M4: append-only KV-cache soundness.** `T` cache reads are checked by
batching the zero-openings of `claim j - stored j` with the `Π_ZeroBatch`
challenge `χ`, where `stored j` is the verifier's key-side snapshot of the
write log at index `idx j`. If at least one read claims a plaintext different
from the value actually written at its index (replay, substitution, or
mix-and-match — domain separation makes that write unique), then for every
adversary opening strategy `msg` (a function of the public `χ` only) the
batched check verifies on at most `2·|F|^T` of the `|F|^(T+1)` verifier tapes
`(Δ, χ)`: soundness error `≤ 2/|F|`. Direct reuse of `zeroBatch_sound`. -/
theorem kv_cache_sound {I : Type*} (L : WriteLog I F) {T : ℕ}
    (idx : Fin T → I) (stored : Fin T → F × F)
    (hstored : ∀ j, (idx j, stored j) ∈ L.entries)
    (claim : Fin T → F × F) {j₀ : Fin T} {w₀ : F × F}
    (hw : (idx j₀, w₀) ∈ L.entries) (hforge : (claim j₀).1 ≠ w₀.1)
    (msg : (Fin T → F) → F) :
    (univ.filter fun Δχ : F × (Fin T → F) =>
        msg Δχ.2 = ∑ j, Δχ.2 j *
          (keyOf Δχ.1 (claim j) - keyOf Δχ.1 (stored j))).card
      ≤ 2 * Fintype.card F ^ T := by
  have hz : (claim j₀ - stored j₀).1 ≠ 0 := by
    rw [Prod.fst_sub, L.read_eq_of_mem (hstored j₀) hw]
    exact sub_ne_zero.mpr hforge
  simp only [← keyOf_sub]
  exact zeroBatch_sound (fun j => claim j - stored j) hz msg

/-- **M4 in Rust's scalar-power wire format.** This is the cache analogue of
`kv_cache_sound`, with one verifier challenge `χ` and list weight
`χ^(j+1)`. If one read differs from its unique logged write, at most
`(T+1)·|F|` of the `|F|²` verifier tapes `(Δ, χ)` accept. Thus the
soundness error is upper-bounded by `(T+1)/|F|`; the statement does not claim
that every adversary attains this bound. -/
theorem kv_cache_sound_scalar {I : Type*} (L : WriteLog I F) {T : ℕ}
    (idx : Fin T → I) (stored : Fin T → F × F)
    (hstored : ∀ j, (idx j, stored j) ∈ L.entries)
    (claim : Fin T → F × F) {j₀ : Fin T} {w₀ : F × F}
    (hw : (idx j₀, w₀) ∈ L.entries) (hforge : (claim j₀).1 ≠ w₀.1)
    (msg : F → F) :
    (univ.filter fun Δχ : F × F =>
        msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) *
          (keyOf Δχ.1 (claim j) - keyOf Δχ.1 (stored j))).card
      ≤ (T + 1) * Fintype.card F := by
  have hz : (claim j₀ - stored j₀).1 ≠ 0 := by
    rw [Prod.fst_sub, L.read_eq_of_mem (hstored j₀) hw]
    exact sub_ne_zero.mpr hforge
  simp only [← keyOf_sub]
  exact zeroBatch_sound_scalar (fun j => claim j - stored j) hz msg

/-- **M4 at the concrete index type** — the statement deferred as
`Ideal.AuthenticatedCacheSound`: replay or mix-and-match across
`(session, query, layer, head, position)` indices of the authenticated
KV-cache is a MAC forgery, and the batched cache check has soundness error
`≤ 2/|F|`. -/
theorem authenticated_cache_sound (L : WriteLog CacheIndex F) {T : ℕ}
    (idx : Fin T → CacheIndex) (stored : Fin T → F × F)
    (hstored : ∀ j, (idx j, stored j) ∈ L.entries)
    (claim : Fin T → F × F) {j₀ : Fin T} {w₀ : F × F}
    (hw : (idx j₀, w₀) ∈ L.entries) (hforge : (claim j₀).1 ≠ w₀.1)
    (msg : (Fin T → F) → F) :
    (univ.filter fun Δχ : F × (Fin T → F) =>
        msg Δχ.2 = ∑ j, Δχ.2 j *
          (keyOf Δχ.1 (claim j) - keyOf Δχ.1 (stored j))).card
      ≤ 2 * Fintype.card F ^ T :=
  kv_cache_sound L idx stored hstored claim hw hforge msg

/-- **M4 scalar-power implementation theorem at the concrete cache index.**
Replay or mix-and-match is checked with Rust's single-`χ` closure and has
soundness error upper bound `(T+1)/|F|`. -/
theorem authenticated_cache_sound_scalar (L : WriteLog CacheIndex F) {T : ℕ}
    (idx : Fin T → CacheIndex) (stored : Fin T → F × F)
    (hstored : ∀ j, (idx j, stored j) ∈ L.entries)
    (claim : Fin T → F × F) {j₀ : Fin T} {w₀ : F × F}
    (hw : (idx j₀, w₀) ∈ L.entries) (hforge : (claim j₀).1 ≠ w₀.1)
    (msg : F → F) :
    (univ.filter fun Δχ : F × F =>
        msg Δχ.2 = ∑ j, Δχ.2 ^ (j.val + 1) *
          (keyOf Δχ.1 (claim j) - keyOf Δχ.1 (stored j))).card
      ≤ (T + 1) * Fintype.card F :=
  kv_cache_sound_scalar L idx stored hstored claim hw hforge msg

end VoltaZk

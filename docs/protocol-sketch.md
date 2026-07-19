# Protocol Sketch

This file tracks the formal objects that need to be written before prototype
work becomes meaningful.

## Minimal Authenticated Value Interface

Let `F` be the base field and `E` be an extension field for statistical
soundness. The designated verifier samples a session MAC key `Delta in E`.

For an authenticated value `x`, the prover holds `(x, m_x)` and the verifier
holds `k_x` such that:

```text
k_x = m_x + Delta * x
```

Fresh correlations are expanded from a silent-VOLE/PCG seed and consumed once.

## Authentication

To authenticate `x`, start from a fresh random authenticated mask `r`.

```text
P sends delta = x - r
P keeps m_x = m_r
V computes k_x = k_r + Delta * delta
```

The correction is masked by `r`, so it should be simulatable as a random field
element under the VOLE idealization.

## Zero Opening

To prove that authenticated `y` equals zero:

```text
P sends m_y
V accepts iff k_y == m_y
```

Any nonzero error requires guessing `Delta` and should fail except with
probability about `1 / |E|`.

## MLE Functional Check

For a tensor `x` and point `r`, define:

```text
z = <eq(r, .), x>
```

The prover computes `z` and the corresponding MAC functional. The verifier
streams its keys:

```text
k_z = <eq(r, .), k_x>
```

The equality relation is then checked through the authenticated-value interface.

Open question: in the blind transcript version, avoid revealing `z` itself and
keep all derived claims authenticated.

## Blind GKR Target

Formalize a GKR/sumcheck transcript where:

- round polynomial coefficients are authenticated values;
- verifier challenges remain public;
- linear consistency checks are accumulated into one random linear combination;
- final low-degree products are discharged by a QuickSilver-like multiplication
  check;
- no activation MLE value is opened in the clear.

## Security Proof Tasks

- malicious-verifier zero-knowledge simulator;
- soundness of blind sumcheck under authenticated claims;
- composition with LogUp-style lookup checks;
- one-time use and domain separation of VOLE correlations;
- multi-session and append-only cache soundness.

## Formalization Status

Lean 4 project in `lean/` (Mathlib-based). Perfect indistinguishability is
stated as equality of `PMF` transcript distributions.

| Protocol object | Lean location | Status |
| --- | --- | --- |
| MAC invariant `k = m + Δ·x`, linearity | `VoltaZk/Mac.lean` (`Authed`, `Valid`) | proved |
| One-time pad (corrections uniform) | `VoltaZk/Otp.lean` (`sub_left_uniform`) | proved |
| Ideal `F_sVOLE`, corrupted-V branch | `VoltaZk/Vole.lean` (`freshCorr`) | modeled |
| `Π_Auth` correction simulatability | `VoltaZk/Vole.lean` (`auth_correction_uniform`) | proved |
| `Π_ZeroOpen` / `Π_ZeroBatch` perfect simulator | `VoltaZk/ZeroBatch.lean` (`zeroBatch_perfect_sim`) | proved |
| Claim `k`-side computable from public data | `VoltaZk/BlindSumcheck.lean` (`claimOf_k_public`) | proved |
| Final opening = simulator's value (pointwise) | `VoltaZk/BlindSumcheck.lean` (`finalMsg_eq_sim`) | proved |
| Vector one-time pad for per-round corrections | `VoltaZk/BlindSumcheck.lean` (`uniformVec_zipWith_sub`) | proved |
| Public transcript distributional equality (round induction) | `VoltaZk/BlindSumcheck.lean` (`realView_map_publicView`) | proved |
| **`Π_BSC + Π_ZeroBatch` perfect ZK vs malicious V\*** | `VoltaZk/BlindSumcheck.lean` (`bsc_zeroBatch_perfect_zk`) | **proved** |
| Counting toolkit (1-dim Schwartz–Zippel, forgery count, vector-RLC and scalar-power-RLC root counts, slice bounds) | `VoltaZk/Counting.lean` (`card_linearForm_zero_le`, `card_scalarRlc_zero_le`) | proved |
| `Π_ZeroOpen` unforgeability (forge ⇒ guess `Δ`, error `1/|F|`) | `VoltaZk/ZeroBatchSound.lean` (`zeroOpen_sound`) | proved |
| Generic vector-RLC `Π_ZeroBatch` soundness, independent `χ : Fin T → F`, error `≤ 2/|F|` | `VoltaZk/ZeroBatchSound.lean` (`zeroBatch_sound`) | proved |
| **Rust scalar-power `Π_ZeroBatch` soundness**, weights `χ^(j+1)`, error `≤ (T+1)/|F|` | `VoltaZk/ZeroBatchSound.lean` (`zeroBatch_sound_scalar`) | **proved** |
| Clear-sumcheck core: deviation round + per-round SZ union bound | `VoltaZk/SumcheckSound.lean` (`exists_deviation`, `card_deviation_le`) | proved |
| Blind→clear transcript reduction (specific sumcheck claim schema) | `VoltaZk/BlindSumcheckSound.lean` (`clear_of_claims_zero`) | proved |
| Generic vector-RLC **blind sumcheck soundness vs malicious P\* (M3)**, error `≤ (Σ dᵢ + 2)/|F|` | `VoltaZk/BlindSumcheckSound.lean` (`blind_sumcheck_sound`) | **proved** |
| **Rust scalar-power blind sumcheck soundness**, `n+1` closing claims weighted by `χ^(j+1)`, error `≤ (Σ dᵢ + n + 2)/|F|` | `VoltaZk/BlindSumcheckSound.lean` (`blind_sumcheck_sound_scalar`) | **proved** |
| **P7 shared-round outer scalar batch**, `K` homogeneous claims fixed before `β`, one common point, error `≤ (K + Σ dᵢ + n + 2)/|F|` | `VoltaZk/BatchSumcheckSound.lean` (`outer_scalar_batch_blind_sumcheck_sound`, `scalar_batch_blind_sumcheck_sound`) | **proved; scheduler obligations below** |
| `MvPolynomial` semantics: `Σ_{b∈{0,1}ⁿ} f(b) = σ₀` end-to-end (M3b) | `VoltaZk/SumcheckMv.lean` (`blind_sumcheck_sound_mv`) | **proved** |
| Domain-separated append-only write log: unique binding per index, appends never rebind | `VoltaZk/KvCache.lean` (`WriteLog`, `read_eq_of_mem`, `append_read_stable`) | proved |
| Cache replay / mix-and-match ⇒ MAC forgery (single opening, error `1/|F|`) | `VoltaZk/KvCache.lean` (`cache_open_forge`, `cache_read_sound`, `cache_mix_sound`) | proved |
| **KV-cache anti-replay soundness (M4)**, batched reads, error `≤ 2/|F|` | `VoltaZk/KvCache.lean` (`kv_cache_sound`, `authenticated_cache_sound`) | **proved** |
| **Rust scalar-power KV-cache anti-replay soundness**, weights `χ^(j+1)`, error `≤ (T+1)/|F|` | `VoltaZk/KvCache.lean` (`kv_cache_sound_scalar`, `authenticated_cache_sound_scalar`) | **proved** |
| **Subfield corrections `F_p ⊆ E` (M5)**: ZK in the subdomain, `F_p`-typed bandwidth, soundness `1/|E|` via embedding | `VoltaZk/Subfield.lean` (`sub_correction_uniform`, `sub_zeroOpen_sound`) | **proved** |
| **Sequential composition of `Π_BSC` windows under one `Δ` (M6)**, cross-window adaptive `V*`, perfect ZK | `VoltaZk/Composition.lean` (`sequential_composition_perfect_zk`) | **proved** |
| **`Π_Prod` (QuickSilver) masked degree-2 check, perfect ZK (M7)** | `VoltaZk/Prod.lean` (`prod_perfect_sim`, `qs_check_complete`) | **proved** |
| Generic vector-RLC **`Π_Prod` batched soundness (M8)**, `T` claims + fresh mask, error `≤ 3/|F|` | `VoltaZk/ProdSound.lean` (`prodBatch_sound`) | **proved** |
| **Rust scalar-power `Π_Prod` soundness**, weights `χ^(j+1)`, error `≤ (T+2)/|F|` | `VoltaZk/ProdSound.lean` (`prodBatch_sound_scalar`) | **proved** |
| **PCS opening-into-MAC interface (M9)**: accepted opening + difference zero-open ⇒ authenticated plaintext = committed evaluation, error `≤ εΩ/|Ω| + 1/|F|`; composes with M3 by discharging `hfin` for the weight leg; binding taken as explicit hypothesis (`BindsIntoMac`), not an axiom | `VoltaZk/OpeningMac.lean` (`opening_mac_sound`, `transfers_eval`) | **proved** |
| **Connection-scoped shared-`Δ` composition (M10)**: injective response nonces make `(connection, response, layer, head, position, tensor)` domains disjoint; an explicit tape equivalence lifts scalar M4 from each fixed-other-response slice, giving numerator `R·(T+1)·|F|^R` over the common `|F|^(R+1)` tape and hence at most `R` times the per-response error without independence; fresh masks make every finite response/correction vector jointly uniform, and M6 gives perfect multi-response simulation with one monotonically increasing correlation offset | `VoltaZk/Connection.lean` (`response_domains_noncolliding`, `connection_response_sound_scalar`, `response_bad_card_le`, `connection_m4_soundness_union_bound`, `connection_corrections_uniform`, `connection_responses_perfect_zk`) | **proved** |
| **Late-point authenticated claim bridge (M11a)**: exact compressed quadratic `[g(0),g(2)]` and cubic `[g(0),g(2),g(3)]` wires derive `g(1)` from the live claim; every custom `n+1` row is MAC-valid, its verifier key is reconstructed pointwise from the same correlation keys, and zero plaintext rows imply the existing `clearAccepts` transcript with a post-`rho` terminal vector | `VoltaZk/BoundaryThinningSound.lean` (`lateClaimAt_valid`, `lateClaimAt_k_eq_verifier`, `clear_of_late_claims_zero`) | **proved** |
| **Affine late atoms followed by a sound chain (M11b)**: a false fixed pair collapsed by post-commit `eta`, degree-bounded clear sumcheck, and arbitrary later chain has bad-tape numerator `1 + Σd_i + B_up`; the proof uses fixed-slice counts and assumes no independence | `VoltaZk/BoundaryThinningSound.lean` (`affine_late_atoms_then_chain_sound`) | **proved** |
| **Shared full-vector pair collapse (M11c)**: one fresh `t` collapses every fixed pair simultaneously with one root independent of vector length, then composes with a later bound `B_after` | `VoltaZk/BoundaryThinningSound.lean` (`shared_pair_collapse_then_chain_sound`) | **proved** |
| **Concrete `layer_leaf_ones_aux` M11 instantiation**: `C=2+n_cols` enumerates `[p0,p1]`, `[q0,q1]`, then every column half-pair; the model unfolds the affine live/true totals and exact terminal formula, proves degree-three `0/2/3` reconstruction and clear recursion, and proves the child fold is the LSB-first MLE at `(t,rho)` | `VoltaZk/BoundaryThinningSound.lean` (`layerLeafOnesAux_terminal`, `lsbMle_cons`, `layer_leaf_ones_aux_full_vector_collapse_sound`, `layer_leaf_ones_aux_clearAccepts_iff_terminal`, `layer_leaf_ones_aux_affine_then_chain_sound`) | **proved** |
| PCG/Ferret realization, PCS, LogUp, UC | `VoltaZk/Ideal.lean` | assumed (named axioms) |

Axiom audit: every audited lemma — including the main ZK theorem, the generic
vector-RLC soundness theorems and the scalar-power theorems mapped to Rust —
depends only on `propext`,
`Classical.choice`, `Quot.sound` (checked with `#print axioms` /
`lean_verify`). No `sorry` remains in the development; none of the named
axioms in `VoltaZk/Ideal.lean` is used by any proof. M9 (2026-07-04) is
conditional on the `BindsIntoMac` hypothesis, to be instantiated by the
concrete code-based PCS chosen in P3.5 (`docs/private-weights-pcs.md`);
`Ideal.WeightPCSBinding` remains as the named global placeholder it subsumes. The former
`BlindSumcheckSound` (M3), `AuthenticatedCacheSound` (M4),
`SubfieldCorrection` (M5) and `QuickSilverProdCheck`/`QuickSilverProdSound`
(M7 ZK + M8 soundness) axioms have all been removed: they are now theorems.

Modeling notes (to keep honest in the writeup): the malicious verifier is an
arbitrary *deterministic* adaptive strategy (perfect ZK against all
deterministic V* extends to randomized V* by averaging); `Δ` and the VOLE keys
are fixed upfront, WLOG in the ideal corrupted-V functionality; the round
polynomials are abstracted as an arbitrary coefficient schedule, and the claim
schema is an arbitrary public-linear schema — the ZK theorem is therefore
*stronger* than needed (holds for every schema), while the soundness theorem
targets the specific sumcheck schema.

Batching-format map: the vector theorems are generic results for an
independently uniform coefficient vector `χ⃗`. The concrete Rust functions
`zero_batch_{prover,verify}` and `prod_batch_*` instead draw one `χ ∈ E` and
use `χ^(j+1)`. For a nonzero list of length `T`, `card_scalarRlc_zero_le`
proves that this univariate polynomial collapses at no more than `T` field
points. Consequently `zeroBatch_sound_scalar` has bad-tape count
`(T+1)·|E|` out of `|E|²`, while `prodBatch_sound_scalar` has
`(T+2)·|E|` out of `|E|²`. These scalar bounds, not the stronger vector
constants, are the theorems mapped to the current Rust wire format. Lean's
generic field `F` is instantiated by Rust's extension field `E = F_p²` here.

Modeling notes for M3 (soundness): dual WLOG to the ZK side — the malicious
prover is *deterministic*, and it is modeled at *value level*: in the
corrupted-P branch of `F_sVOLE` the adversary chooses `(u, m)` and the
functionality sets `k = m + u·Δ`, so composing with the `Π_Auth` correction
the adversary directly picks plaintext/tag pairs, with keys determined and
its view independent of `Δ`. Adaptivity is structural: round-`i` data reads
the truncated challenge vector `trunc r i` only. Soundness statements are in
*counting form* — `#bad ≤ ε·|Ω|` over verifier randomness — matching
Mathlib's Schwartz–Zippel style and avoiding `ℝ≥0∞` plumbing. The generic
vector theorem uses `Ω = (Δ, r, χ⃗)` and proves
`(∑ dᵢ + 2)/|F|`. Rust instead sends one scalar `χ` and assigns closing
claim `j` the weight `χ^(j+1)`. For that exact implementation,
`blind_sumcheck_sound_scalar` counts at most
`(∑ dᵢ + n + 2)·|F|^(n+1)` bad tapes out of `|F|^(n+2)`, hence error
`≤ (∑ dᵢ + n + 2)/|F|` (`T = n+1` closing claims). The extra `n`
is the root bound for the nonzero scalar-RLC polynomial, not a vector-RLC
`1/|F|` collapse. The final evaluation check is scoped to *public-linear*
authenticated openings (`hopen`: the opening computes `f(r)` — MAC linearity
for MLE openings); its degree-2 terminal products are covered by M7/M8.

P7's shared-round theorem adds an independent outer scalar `β`. The `K`
claimed totals and their true totals are fixed before `β`; weights are exactly
`β^(k+1)`. If any member is false, the aggregate total collapses for at
most `K` values of `β`. Conditional on no collapse, the aggregate prover is
covered by `blind_sumcheck_sound_scalar` even if all of its round coefficients
and final message depend adversarially on `β`. The resulting count is
`(K + ∑ dᵢ + n + 2)·|F|^(n+2)` out of `|F|^(n+3)` tapes
`(β, Δ, r, χ)`.

This theorem is deliberately narrower than a scheduler proof. One cohort
must have a fixed `K`, the same round count `n`, the same public degree vector
`d`, and exactly one challenge history `r`; `HasCommonPoint` and
`trunc_eq_of_commonPoint` name that invariant. It is unsound to combine
member-local transcripts at different points, to select cohort membership
after seeing `β`, or to reuse the inner `χ` as `β`. A concrete interactive
schedule therefore needs a fresh, domain-separated verifier challenge `β`
and must account for that field element in communication. The Lean theorem
does not yet prove the Rust interleaving state machine, LogUp layer-end
alignment, correlation-counter discipline, or an across-cohort/session union
bound; those remain implementation and differential-test gates rather than
implicit consequences of linearity.

Modeling notes for M4 (KV-cache): the cache is a `WriteLog` — an append-only
list of (full index, adversary pair) write events whose index projection is
duplicate-free; that freshness condition *is* domain separation, and it makes
the verifier's stored key per `(session, query, layer, head, position)` tuple
canonical (`read_eq_of_mem`) and stable under appends (`append_read_stable`,
the `F_VDec` statefulness lemma). A cache read re-enters the transcript as a
claimed pair plus the zero-opening of claimed − stored, whose verifier key is
computable from the stored key alone (`keyOf_sub`); replay, substitution, and
cross-index mix-and-match all make the difference plaintext nonzero, so
soundness is a direct reuse of the M3a unforgeability lemmas: `1/|F|` per
single opening (`zeroOpen_sound`). The abstract vector-RLC cache theorem uses
`zeroBatch_sound` and has error `≤ 2/|F|`; Rust's one-scalar closure is
covered by the explicit wrappers `kv_cache_sound_scalar` /
`authenticated_cache_sound_scalar`, which reuse `zeroBatch_sound_scalar` and
give the upper bound `≤ (T+1)/|F|` for a list of length `T` (not a claim
that this bound is attained). Multi-session: the session id is part of
the index tuple, so cross-session replay under one `Δ` is covered; sessions
with independent keys are independent games.

Modeling notes for M5 (subfield): quantized plaintexts live in `F_p`, tags,
keys and `Δ` in the extension `E`; subfield `F_sVOLE` samples the mask in the
subdomain, so the `Π_Auth` correction is *typed* `F_p` — the `log₂|F_p|`-bit
bandwidth claim is structural — and uniform on `F_p` for adversarial `Δ, k`
(`sub_correction_uniform`): the simulator samples in the subdomain and
matches exactly. Soundness is unchanged at `1/|E|`: the embedding
`SubAuthed.toAuthed` preserves validity and nonzeroness of plaintexts, so the
M3a/M4 opening lemmas apply verbatim to embedded subfield values.

Modeling notes for M6 (composition): windows run sequentially under one `Δ`;
each window's batched opening enters the transcript, and later windows'
challenges, keys and `χ` may depend on it. The per-window adversary is the
residual strategy `wrapV` (global `V*` with the flat public prefix baked in,
correlation keys shifted by an offset — the offset *is* index freshness,
mirroring the M4 domain separation). The hybrid argument is degenerate
because the per-window equalities are perfect: the proof is an induction over
the window list where openings collapse to public functions of the prefix
(`finalMsg_eq_sim`) and continuations factor through the public projection.
The zero-claims hypothesis is quantified over all prefixes/offsets, not just
reachable ones — stronger than needed, faithful for an honest prover.

Modeling notes for M10 (connection-scoped `Δ`): response non-collision is
conditional on injectivity of the authorization nonces; the durable store is
the implementation mechanism establishing that hypothesis. For `R=n+1`,
`responseTapeEquiv` splits the common tape `F × (Fin R → F)` into the local
`(Δ,χ_r)` tape and the other `n` response coins. `response_bad_card_le`
formally lifts the scalar-M4 bound after each fixed assignment of those other
coins, including strategies that depend adaptively on them. The exact
numerator is `R·(T+1)·|F|^R` and `connection_m4_tape_card` gives denominator
`|F|^(R+1)`, hence error `≤ R·(T+1)/|F|`; no independence assumption is used.
For hiding, `connection_corrections_uniform` is the vector OTP over an
arbitrary finite index (instantiated by every response/local correction
coordinate) in M5's correction field, while
`connection_responses_perfect_zk` flattens all response windows and invokes
M6 with one global offset, so correlations are never re-used. This formal
boundary is the ideal-sVOLE protocol: it does not prove the concrete
AES-128-MMO/GKWY assumption or PCG realization, nonce-store durability,
terminal abort/restart burn, or the Rust connection state machine.

Modeling notes for M7 (`Π_Prod` ZK): for a true product claim `c = a·b` the
degree-2 key identity `k_a·k_b − Δ·k_c = A₀ + A₁·Δ` holds (the `Δ²` terms
cancel); the prover's message `(A₀ + m_r, A₁ + r)` masked by a fresh
correlation has a uniform second component (OTP) whose value *determines* the
first given `V*`'s keys — the same two ingredients as the `Π_ZeroBatch`
simulator, so simulation is perfect against adversarial `Δ` and correlation
key (`prod_perfect_sim`).

Modeling notes for M8 (`Π_Prod` soundness): dual game, same value-level
corrupted-P conventions as M3a/M4. The key-side term of one check expands as
a polynomial in `Δ` whose `Δ²` coefficient `x_a·x_b − x_c` *is* the falsity
of the claim; batching `T` checks under one fresh mask, a false claim survives
only if the batching coefficients collapse the falsity RLC or `Δ` hits a
root of a live quadratic. For an independently uniform vector,
`prodBatch_sound` gives `1/|F| + 2/|F| = 3/|F|`. Rust uses the scalar powers
`χ^(j+1)`; `card_scalarRlc_zero_le` bounds the nonzero degree-`T`
polynomial by `T` roots, and `prodBatch_sound_scalar` therefore counts at
most `(T+2)·|F|` bad tapes out of `|F|²`, i.e. error
`≤ (T+2)/|F|`. The adversary's message `(M₀,M₁)` may depend on `χ`,
never on `Δ`. Higher fan-in products reduce to chained
degree-2 checks. In the protocol schedule this opening closes the
multiplicative claims alongside the `Π_ZeroBatch` opening `m_Z`
(union bound at the protocol level).

## Next Formal Targets (before implementation)

1. ~~**Soundness of the blind sumcheck (M3)**~~ — **done** (see table):
   `blind_sumcheck_sound` (generic vector-RLC schema),
   `blind_sumcheck_sound_scalar` (Rust scalar-power schema), and
   `blind_sumcheck_sound_mv` (`MvPolynomial` semantics). Their respective
   batching bounds are `≤ (∑ dᵢ + 2)/|F|` and
   `≤ (∑ dᵢ + n + 2)/|F|`.
2. ~~**KV-cache / statefulness lemma (M4)**~~ — **done** (see table):
   `kv_cache_sound` / `authenticated_cache_sound` and their implementation
   wrappers `kv_cache_sound_scalar` / `authenticated_cache_sound_scalar` in
   `VoltaZk/KvCache.lean`; replay/mix-and-match is a MAC forgery. The generic
   vector bound is `≤ 2/|F|`; Rust's scalar closure has upper bound
   `≤ (T+1)/|F|`. Append-only statefulness is
   `WriteLog.append_read_stable`.
3. ~~**Subfield correction lemma (M5)**~~ — **done** (see table):
   `sub_correction_uniform` / `sub_zeroOpen_sound` in `VoltaZk/Subfield.lean`,
   ZK in the subdomain + `F_p`-typed bandwidth, soundness `1/|E|` preserved.
4. ~~**Sequential composition (M6)**~~ — **done** (see table):
   `sequential_composition_perfect_zk` in `VoltaZk/Composition.lean`,
   degenerate hybrid over windows, one `Δ`, fresh indices by key offset.
5. ~~**`Π_Prod` (QuickSilver) ZK extension (M7)**~~ — **done** (see table):
   `prod_perfect_sim` in `VoltaZk/Prod.lean`.
6. ~~**`Π_Prod` batched soundness (M8)**~~ — **done** (see table):
   `prodBatch_sound` for generic vector coefficients, error `≤ 3/|F|`, and
   `prodBatch_sound_scalar` for Rust's scalar powers, error
   `≤ (T+2)/|F|`; the latter is the implementation theorem.
7. ~~**P7 shared-round scalar batch boundary**~~ — **abstract theorem done**:
   `outer_scalar_batch_blind_sumcheck_sound` permits a fully malicious
   `β`-adaptive aggregate prover and composes the `K/|F|` outer-collapse
   count with scalar M3; `scalar_batch_blind_sumcheck_sound` instantiates it
   for the fixed-member linear construction. Enabling either result in Rust
   remains conditional on the homogeneous-cohort, fresh-`β`, common-point,
   transcript, and counter obligations stated above.
8. ~~**Connection-scoped shared-`Δ` composition (M10)**~~ — **done**:
   `response_domains_noncolliding` separates distinct response nonces,
   `connection_response_sound_scalar` transfers M4 to the full fase-D domain,
   `response_bad_card_le` performs the fixed-rest local-to-common-tape lift,
   `connection_m4_soundness_union_bound` loses exactly the union-bound factor
   `R` relative to M4 without assuming independent response events, and
   `connection_responses_perfect_zk` composes fresh response windows under one
   `Δ`; the concrete lifecycle obligations remain outside Lean as stated
   above.

**The formal exit gate to the implementation phase is closed**: every
security claim of the paper draft, including the scalar-power batching used
by Rust, is either a Lean theorem (M1–M10) or a
named, isolated assumption in `VoltaZk/Ideal.lean` (PCG/Ferret realization,
weight-PCS binding, LogUp-GKR soundness, full UC composition — all
established-literature or modular/swappable components, none in the
per-token critical path). Next phase: CUDA/CPU prototype and the ρ benchmark
protocol; LogUp composition gets a paper proof once the prototype freezes
the fused-block circuit structure.

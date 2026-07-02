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
| Counting toolkit (1-dim Schwartz–Zippel, forgery count, RLC count, slice bounds) | `VoltaZk/Counting.lean` | proved |
| `Π_ZeroOpen` unforgeability (forge ⇒ guess `Δ`, error `1/|F|`) | `VoltaZk/ZeroBatchSound.lean` (`zeroOpen_sound`) | proved |
| `Π_ZeroBatch` soundness (RLC + opening, error `≤ 2/|F|`) | `VoltaZk/ZeroBatchSound.lean` (`zeroBatch_sound`) | proved |
| Clear-sumcheck core: deviation round + per-round SZ union bound | `VoltaZk/SumcheckSound.lean` (`exists_deviation`, `card_deviation_le`) | proved |
| Blind→clear transcript reduction (specific sumcheck claim schema) | `VoltaZk/BlindSumcheckSound.lean` (`clear_of_claims_zero`) | proved |
| **Blind sumcheck soundness vs malicious P\* (M3)**, error `≤ (Σ dᵢ + 2)/|F|` | `VoltaZk/BlindSumcheckSound.lean` (`blind_sumcheck_sound`) | **proved** |
| `MvPolynomial` semantics: `Σ_{b∈{0,1}ⁿ} f(b) = σ₀` end-to-end (M3b) | `VoltaZk/SumcheckMv.lean` (`blind_sumcheck_sound_mv`) | **proved** |
| Domain-separated append-only write log: unique binding per index, appends never rebind | `VoltaZk/KvCache.lean` (`WriteLog`, `read_eq_of_mem`, `append_read_stable`) | proved |
| Cache replay / mix-and-match ⇒ MAC forgery (single opening, error `1/|F|`) | `VoltaZk/KvCache.lean` (`cache_open_forge`, `cache_read_sound`, `cache_mix_sound`) | proved |
| **KV-cache anti-replay soundness (M4)**, batched reads, error `≤ 2/|F|` | `VoltaZk/KvCache.lean` (`kv_cache_sound`, `authenticated_cache_sound`) | **proved** |
| PCG/Ferret realization, QuickSilver `Π_Prod`, PCS, LogUp, UC, subfield corrections | `VoltaZk/Ideal.lean` | assumed (named axioms) |

Axiom audit: every proved lemma — including the main ZK theorem and the
M3/M4 soundness theorems — depends only on `propext`, `Classical.choice`,
`Quot.sound` (checked with `#print axioms` / `lean_verify`). No `sorry`
remains in the development; none of the named axioms in `VoltaZk/Ideal.lean`
is used by any proof. The former `BlindSumcheckSound` (M3) and
`AuthenticatedCacheSound` (M4) axioms have been removed: they are now
theorems.

Modeling notes (to keep honest in the writeup): the malicious verifier is an
arbitrary *deterministic* adaptive strategy (perfect ZK against all
deterministic V* extends to randomized V* by averaging); `Δ` and the VOLE keys
are fixed upfront, WLOG in the ideal corrupted-V functionality; the round
polynomials are abstracted as an arbitrary coefficient schedule, and the claim
schema is an arbitrary public-linear schema — the ZK theorem is therefore
*stronger* than needed (holds for every schema), while the soundness theorem
targets the specific sumcheck schema.

Modeling notes for M3 (soundness): dual WLOG to the ZK side — the malicious
prover is *deterministic*, and it is modeled at *value level*: in the
corrupted-P branch of `F_sVOLE` the adversary chooses `(u, m)` and the
functionality sets `k = m + u·Δ`, so composing with the `Π_Auth` correction
the adversary directly picks plaintext/tag pairs, with keys determined and
its view independent of `Δ`. Adaptivity is structural: round-`i` data reads
the truncated challenge vector `trunc r i` only. Soundness statements are in
*counting form* — `#bad ≤ ε·|Ω|` over the verifier randomness
`Ω = (Δ, r, χ)` — matching Mathlib's Schwartz–Zippel style and avoiding
`ℝ≥0∞` plumbing. The proved bound is `(∑ dᵢ + 2)/|F|`, tighter than the
`(Σ degrees + T + 1)/|F|` target (`T = n+1` batched claims). The final
evaluation check is scoped to *public-linear* authenticated openings
(`hopen`: the opening computes `f(r)` — MAC linearity for MLE openings);
degree-2 product claims remain behind the `QuickSilverProdCheck` axiom.

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
single opening (`zeroOpen_sound`), `≤ 2/|F|` for `T` reads batched through
`Π_ZeroBatch` (`zeroBatch_sound`). Multi-session: the session id is part of
the index tuple, so cross-session replay under one `Δ` is covered; sessions
with independent keys are independent games.

## Next Formal Targets (before implementation)

1. ~~**Soundness of the blind sumcheck (M3)**~~ — **done** (see table):
   `blind_sumcheck_sound` (abstract schema) and `blind_sumcheck_sound_mv`
   (`MvPolynomial` semantics), error `≤ (∑ dᵢ + 2)/|F|`.
2. ~~**KV-cache / statefulness lemma (M4)**~~ — **done** (see table):
   `kv_cache_sound` / `authenticated_cache_sound` in `VoltaZk/KvCache.lean`,
   replay/mix-and-match is a MAC forgery, batched error `≤ 2/|F|`;
   append-only statefulness via `WriteLog.append_read_stable`.
3. **Subfield correction lemma (M5)**: 16-bit corrections in `F_p ⊆ E`
   preserve both ZK (uniformity in the subdomain) and bandwidth claims.
4. **Sequential composition**: multiple `Π_BSC` windows under one `Δ` with
   fresh indices — perfect ZK composes; short hybrid argument.
5. **`Π_Prod` (QuickSilver) ZK extension**: masked degree-2 check messages
   are uniform (same OTP pattern); soundness may remain assumed.

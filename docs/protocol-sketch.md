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
| PCG/Ferret realization, QuickSilver `Π_Prod`, PCS, LogUp, UC, subfield corrections, KV-cache soundness | `VoltaZk/Ideal.lean` | assumed (named axioms) |

Axiom audit: every proved lemma — including the main ZK theorem — depends only
on `propext`, `Classical.choice`, `Quot.sound` (checked with `#print axioms`).
No `sorry` remains in the development; none of the named axioms in
`VoltaZk/Ideal.lean` is used by any proof.

Modeling notes (to keep honest in the writeup): the malicious verifier is an
arbitrary *deterministic* adaptive strategy (perfect ZK against all
deterministic V* extends to randomized V* by averaging); `Δ` and the VOLE keys
are fixed upfront, WLOG in the ideal corrupted-V functionality; the round
polynomials are abstracted as an arbitrary coefficient schedule, and the claim
schema is an arbitrary public-linear schema — the ZK theorem is therefore
*stronger* than needed (holds for every schema), while the upcoming soundness
theorem will target the specific sumcheck schema.

## Next Formal Targets (before implementation)

1. **Soundness of the blind sumcheck (M3)**: corrupt `P*`, honest `V`;
   error `≤ (Σ degrees + T + 1)/|F|`. Sub-lemmas: MAC unforgeability
   (opening a nonzero claim requires guessing `Δ`), RLC soundness under
   uniform `χ`, and the blind→clear transcript reduction.
2. **KV-cache / statefulness lemma (M4)**: index domain separation ⇒
   replay/mix-and-match across (session, query, layer, head, position) is a
   MAC forgery; append-only cache soundness for `F_VDec`.
3. **Subfield correction lemma (M5)**: 16-bit corrections in `F_p ⊆ E`
   preserve both ZK (uniformity in the subdomain) and bandwidth claims.
4. **Sequential composition**: multiple `Π_BSC` windows under one `Δ` with
   fresh indices — perfect ZK composes; short hybrid argument.
5. **`Π_Prod` (QuickSilver) ZK extension**: masked degree-2 check messages
   are uniform (same OTP pattern); soundness may remain assumed.

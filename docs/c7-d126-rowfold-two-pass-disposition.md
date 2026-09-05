# C7 D126 two-pass ROWFOLD intake and screen

**Status:** the owner-named `ROWFOLD` carrier is `BLOCKED` at intake. The local
design GO is already present; this is a construction gap, not a missing GO
or an H100 measurement. No
versioned report, digest, relation, pseudocode or compiler with that name is
present in the repository, its Git refs, or the materials supplied by the
owner. The numerical standard-WHIR analysis below is an analytic
assertion screen, not a derivation of the missing carrier. It gives a
conditional `NO-GO` only when its named assumptions hold. It earns no
protocol, complexity or implementation credit.

## Frozen boundary

The proof subsystem may read packed `W` exactly twice and may use one total
ROWFOLD arena of at most `6,442,450,944` bytes, including simultaneous input
and output.  It may not retain a full codeword, spill it, make another weight
copy, or perform `qN`, `N log q`, or `N log N` work.  Its required bound is

```text
C(N,q,h) = c_source*N + P(q,h),
```

where `c_source` is independent of both `N` and `q`.

The required offline Fiat--Shamir order is sequential. Any submitted carrier
must identify its exact retained objects and prove a relation at least as
strong as the following shape. Writing `O_r` for a distance-bearing oracle and
`C_r` for its root, it must bind

```text
O0 = Encode(W)                    ; C0 = Commit(O0)
F0 = Fold(rho0, O0)              ; O1 = Extend(F0); C1 = Commit(O1)
F1 = Fold(rho1, O1)              ; O2 = Extend(F1); C2 = Commit(O2)
...
EvalLink(tail, W, authenticated terminal)
```

`CheckExtend` must prove that each next oracle is the encoding of the folded
message; Merkle paths alone do not prove that relation.  The tail must remain
linked to the same authenticated evaluation of `W`, never to a cleartext
weight evaluation.  Consequently the transcript prefix is

```text
pass 1 over W -> C0 -> rho0 -> pass 2 over W -> C1 -> rho1 -> C2 -> ...
-> tail -> query tape -> openings -> settlement
```

Thus `C1` must bind the state before `rho1` is known.  After `rho1`, the prover
must construct `C2` and answer arbitrary valid verifier queries without
reading `W` again.  Producing every challenge before `C1` would change this
required relation and remove adaptive binding; offline operation does not
authorize that change. The present checker freezes this required symbolic
order only. It does not parse or verify a carrier transcript.

## Conditional standard-WHIR screen

This screen assumes a standard-WHIR realization with a `2^36`-cell initial
oracle, a first fold of arity 16, and a materialized `O1` (or equivalent
distance-bearing state) of `2^32` Goldilocks cells after `C1`. These values are
controls from the existing WHIR geometry; they are not yet derived from the
missing ROWFOLD report. Under those assumptions, retaining that state costs

```text
2^32 * 8 = 34,359,738,368 bytes
arena cap =  6,442,450,944 bytes
excess    = 27,917,287,424 bytes
```

The following four concrete choices each fail a frozen condition under their
stated assumption. They are rejection controls, not a proof that the list
exhausts every possible algorithm:

| Concrete choice after `rho1` | Assumption and consequence | Conditional verdict |
| --- | --- | --- |
| Retain `O1` or equivalent state | Materializes `2^32` cells: 34,359,738,368 bytes, exceeding the arena | `NO-GO` |
| Recompute from packed W | Requires at least a third source sweep; the available complete transform costs `N log N` | `NO-GO` |
| Compute only selected answers | Uses direct `qN` evaluation or an `N log q` selector | `NO-GO` |
| Keep only a local streaming code | Has no proved global relative-distance statement for adaptive openings | `NO-GO` |

The last row is not a small security loss. Under the additional control
assumption that each of `q` independent samples chooses uniformly among `R`
local regions, the changed region is visited with probability
`1-(1-1/R)^q <= q/R` (approximately `q/R` only when `q` is much smaller than
`R`). Detection can only be lower and additionally depends on the local
distance. This illustrative control is not a bound for the missing carrier.
Such a carrier cannot support a 78-bit lifetime statement without a proved
adaptive global-rank or distance theorem.

Merkle path pruning changes authentication bytes, not the encoder work or the
global-distance obligation.  Offline Fiat--Shamir removes online challenge
transport, not the order `C0 -> rho0 -> C1 -> rho1`.

## Exact verdict and unblock

- `ROWFOLD_CARRIER = BLOCKED` because its identified source and concrete
  relation are absent.
- `STANDARD_WHIR_2^32_STATE_SCREEN = NO-GO_IF_ASSUMPTIONS_HOLD`; this is not
  transferred to the unnamed carrier.
- `COMPLEXITY_BOUND = BLOCKED` globally.
- `TWO_HBM_SWEEPS = BLOCKED` globally.

The gates may be reopened by the identified ROWFOLD report, or by a new or
revised PCS, only if it provides all of:

1. a precise relation and a proved global-distance/soundness statement;
2. the same offline-FS commitment order, including the second challenge;
3. an implemented prover using at most two source sweeps and at most the one
   arena, without a full codeword or spill; and
4. a proved and measured
   `C(N,q,h)=c_source*N+P(q,h)` bound with `c_source` independent of `N,q`.

The deterministic ROWFOLD intake procedure is: obtain the complete report;
record title, authors, version/date, canonical URL and SHA-256; archive the
immutable source; transcribe its relation and full pseudocode; derive every
oracle length/rate and retained state from that source; prove the candidate
list exhaustive or add the missing algorithms; implement the checker/compiler;
then rerun this screen. Changing the setup, transcript, trust model, field, or
interactive relation is a new protocol decision and receives no credit here.

## 2026-09-05: concrete construction checks

### Selected q357 dense-fold control

The new W reservation compiler also derives a rejection control from the
actual selected profile, rather than the older favorable eight-byte screen.
There are 30,697,345,280 packed scalars; power-of-two padding gives `2^35`
message cells. After the first four-variable fold, the straightforward dense
message has `2^31` Fp3 coefficients:

```text
dense first-fold message: 2^31 * 24 = 51,539,607,552 bytes
one total arena:                       6,442,450,944 bytes
```

This materialization alone is eight times the arena, before simultaneous
input or scratch. Materializing the selected next encoded oracle would be
still larger: `2^(31+4)*24 = 824,633,720,832` bytes. Both figures are computed
symbolically; neither allocation was attempted. They reject the concrete
**dense materialization** strategy, not every compressed/streaming algorithm.

### Primary-source candidate: Hobbit

Christodoulos Pappas and Dimitrios Papadopoulos, *Hobbit: Space-Efficient
zkSNARK with Optimal Prover Time*, ePrint 2025/1214, approved 2025-07-07,
[full paper](https://eprint.iacr.org/2025/1214). The PDF and AnyDoc Markdown
are archived as `2025-1214-hobbit.{pdf,md}` under the owner's research archive.
PDF SHA-256 is
`1fad6172a3299c31c4bc589e0bb3ce03751dbe6ec07dc2f1d97eb19ebfec4972`;
Markdown SHA-256 is
`f5754080284f8a5311a195954f9e4f973add4d27663e596460258febfa66870e`.
No external implementation was executed or adopted.

Construction 4 and Theorem 2 explicitly require:

1. one source pass for `Commit`, retaining column hashes;
2. one source pass for the two aggregate rows, then their commitment;
3. only after that commitment, sample column indices and make another source
   pass to recover the selected encoded columns.

This is **three passes for commitment plus opening**, not two. The sumcheck
in its Theorem 1 does use two passes, but is not the complete PCS. Applying
Construction 4 directly to the current two-pass commitment/opening order is
`NO-GO`.

Precommitting the original oracle in offline setup would leave two *opening*
passes per attempt. This is a distinct candidate, not a proof that the paper
is globally unusable. It changes the current carrier relation/setup schedule
and requires new accounting: the retained column hashes and refresh work,
tensor-code distance and Q64 query count, all inner PCS/GKR proofs, masked
authenticated openings and the lifetime leakage theorem. Its original clear
column disclosures cannot simply replace VOLE-authenticated openings. It is
`BLOCKED_NOT_SELECTED`, with no transfer of q357 or 79.481814-bit arithmetic.

Writing `b` for the paper's chunk length (not our B plane), its actual
expressions include `q*N/b` disclosed field elements and `b*log(b)` inner
PCS work. These terms must be bounded explicitly when selecting `b` as a
function of the source length and arena budget. The paper's `O(N)` with a
fixed security parameter does not by itself establish our stronger
`c_source*N + P(q,h)` condition. No claim about output-pruned repository
code or an exact 6.44-GB peak follows from the paper's `O(b)` space statement.

### Constructive rejection of the early-query shortcut

There is a simple exact counterexample to a proposed way to avoid the last
read: sample the comparison points **before** committing the folded word,
then check source-to-fold equality only at those points. Let the true folded
polynomial be zero, let the distinct early samples be `x_1,...,x_q`, and let
`z` be a different claim point. If the allowed message dimension is at least
`q+1`, set

```text
h(X) = product_j (X-x_j) / product_j (z-x_j).
```

All denominators are nonzero in the field. This is a valid polynomial of
degree q with `h(x_j)=0` for every checked point, but `h(z)=1`, whereas the
true value is zero. The malicious prover can commit to the actual encoding
of h; even a perfect low-degree test and valid original-word Merkle paths do
not repair the missing equality. No hash collision is needed.

The executable fixture uses the **unchanged Goldilocks field**, samples
`1..357`, and `z=358`. It constructs all 358 coefficients and checks the
equalities with an independent polynomial evaluator. This refutes the
restricted early-query equality test, not the correctly ordered frozen
PCS: any independent authenticated source-evaluation check would have to be
analysed separately. Consequently we do not move queries early to claim two
passes, and we do not count this rejection test as a new PCS implementation.

### Why a small folded summary is not automatically enough

A useful conditional lower bound is elementary. Assume an injective encoding
of arbitrary N packed i16 values, and a retained state from which **every**
original-oracle coordinate can be recovered exactly, with no further source
reads or external source-dependent storage. Fix the encoder's randomness.
If two distinct sources produced the same retained state, the answering
algorithm would return the same full codeword for both, contradicting
injectivity. Thus the state needs at least `16*N` bits. Include every retained
source-dependent root, transcript and auxiliary value in that state.

For the current private-weight length this is 61,394,690,560 bytes, not
6,442,450,944. This rules out that **universal exact-recovery summary** claim.
It is not a universal impossibility proof: a protocol might avoid arbitrary
coordinate recovery, use a different relation, or exploit source restrictions
that invalidate the premise. We do not transfer this conditional bound to
all offline Fiat--Shamir algorithms or to a single hard-coded checkpoint.

### Result

No complete permitted two-pass carrier was constructed by these checks.
`COMPLEXITY_BOUND`, `TWO_HBM_SWEEPS` and the full certificate remain
`BLOCKED`. The explicit standard-WHIR memory choice, direct three-pass
Hobbit schedule and early-query shortcut each receive only their scoped
`NO-GO`. Complete cryptographic construction remains a pre-pod task; an H100
run cannot supply its missing relation or soundness proof.

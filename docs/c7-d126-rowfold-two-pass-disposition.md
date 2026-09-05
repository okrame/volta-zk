# C7 D126 two-pass ROWFOLD intake and screen

**Status:** the owner-named `ROWFOLD` carrier is `BLOCKED` at intake. No
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

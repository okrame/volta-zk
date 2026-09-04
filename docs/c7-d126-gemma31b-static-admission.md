# C7 D126 Gemma-31B stacked static admission

**Status:** active design; the known static slice is implemented and checked;
full admission remains `BLOCKED`.

This document is the only active D126 path.  Historical designs and ledger
entries remain append-only evidence, not active parameter sources.

## 1. Frozen scope

- Model: `google/gemma-4-31B`, revision
  `5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89`.
- Operational context cap: 4,096 tokens.
- Field: Goldilocks `p=2^64-2^32+1`; challenges and MACs use
  `Fp3=Fp[u]/(u^3-2)`.  An Fp3 value is 24 bytes and a base-field correction
  is 8 bytes.
- Offline classical-ROM Fiat--Shamir with one global
  `Q_FS_global<=2^64`.  This includes every local query, concurrent session,
  abort, retry and the complete `2^20` response-attempt lifetime.
- First query count 357, with Gemma vector
  `[357,163,152,149,149,149,149,149]`.
- One weight use per physical segment: 472 W terminals, eight B/KV identity
  terminals, 480 total terminals and zero use reducers.
- Mask geometry: 4,096 `ResponseAttempt` reservations per root, including
  success, failure, abort and retry, plus 512 attempt-equivalent lifecycle/load
  reserve cells; 256 root epochs and one shared KV arena.
- One 80,000,000,000-byte H100; one storage acquisition; exactly two packed-W
  HBM sweeps; no spill, full codeword, second W copy, `qN`, `N log q` or
  `N log N` work.
- The 6,442,450,944-byte ROWFOLD allowance is one total temporary arena.  It
  must contain its input and output together.

`N` remains the source length and `q` remains a query count.  Neither is
treated as a fixed profile constant.  The 4,096-token cap does not hide work
or memory that depends on `N`.

## 2. Stacked relation and exact census

`lean/VoltaZk/C7StackedWeightUse.lean` proves:

1. right multiplication by one physical matrix commutes with stacking prompt
   and response rows;
2. one tagged direct sum for the six norm roles is equivalent to the twelve
   old phase/role equations and has no cross-role terms;
3. tied lookup and logits keep their two matrix orientations;
4. the final norm is shared across the two phases; and
5. the combined relation is equivalent to the per-use algebraic relation.

The main theorem is
`VoltaZk.c7_stacked_weight_use_compiler_complete`.  It proves the algebraic
relation, not that the Rust compiler emitted it.  The missing implementation
refinement is named `C7CompilerMatchesStackedWeightUse`; admission requires a
concrete proof or checked refinement for that predicate.

The frozen target census is:

```text
50*(7 matrix groups + 1 norm group)
+ 10*(6 matrix groups + 1 norm group)
+ 1 tied embedding
+ 1 final norm
= 472 W terminals

472 + 4 B + 2 KV-old + 2 KV-new = 480 total terminals
UseEta events = 0
use-reducer instances = 0
```

Lean derives the last two zeros from an explicit vector of 480 use-axis
lengths, all equal to one; they are not literal zero-returning definitions.
This proves the frozen-profile arithmetic.  It does not prove that the future
compiler emits that vector; that remains part of the named refinement.

The tested Rust helper rejects every tuple other than
`context/W/all/reducer = 4096/472/480/0`.  It is not yet connected to the
runtime compiler.

## 3. Proved fixed-prefix numerator; concrete Q64 bridge open

For `T=480`, the existing scalar ProductClosure theorem has two bad branches:

```text
BadProductChi: at most T = 480 roots in chi
ProdSound:     at most 2 roots in the secret MAC key Delta
total:         482 roots in the abstract finite field
```

The theorem assumes a false claim and a prover message that may depend on
`chi`, but not on `Delta`.  The use-axis reducer contributes zero roots.  This
proves the fixed-prefix numerator `482`.

For the intended C7 field and global ROM scope, the reserved budget expression
is

```text
epsilon_stacked_product
  = (2^64+1) * 482 / p^3
  = about 2^-119.087110662762.
```

Lean proves the abstract `480+2=482` root bound and normalizes this rational
budget expression.  It does not yet prove that concrete C7 Fp3 has the required
cardinality and field bridge, that the concrete verifier refines
`prodBatch_sound_scalar`, that the C7 transcript fixes the message before `chi`
while keeping it independent of `Delta`, or that one classical-ROM Q64 factor
covers all sessions and attempts.  Therefore the 119.087-bit value is
conditional and its C7/Q64 instantiation remains `BLOCKED`.

This is not the base GKR of the transformer.  Base-GKR rounds, degrees, common
points and final PCS links still have to be emitted by the compiler.  The 480
triples already include the eight B/KV identity terminals; upstream B/KV
query and PCS terms remain separate.

## 4. 78-bit admission contract

For one q357 plane, the static calculator uses

```text
miss(ell) = (1+2^-ell)/2
ell       = [1,4,6,8,10,13,16,19]

epsilon_query
  = (2^64+1) * sum_i miss(ell_i)^q_i

epsilon_gap
  = (2^64+1) * sum_i k_i*2^(36-i)/p^3

epsilon_mask
  = 5,656,563,154,944/2^128
    + exact six-draw rejection failure.
```

Their exact rational sum is emitted by
`scripts/budget_c7_d126_gemma_static.py`.  It is
`2^-81.546189488918`, hence strictly below the simple admission cap
`2^-81`.

Until the B and KV layouts are compiled, the admission rule is conservative:
each of W, B, KV-old and KV-new must be no worse than that same q357 plane
envelope.  This is a required upper bound, not a claim that their layouts are
identical.

The remaining response-local registry has at most 64 slots per attempt, each
already required to include any applicable global-FS loss before meeting its
`2^-110` cap:

| Class | Maximum slots |
| --- | ---: |
| operator and compute, including base GKR | 16 |
| boundary commitments | 8 |
| predecessor/successor state | 8 |
| PCS binding and privacy | 16 |
| extension-field terminal and MAC | 8 |
| sampling and range | 4 |
| serialization and order | 4 |
| **Total** | **64** |

The complete conditional allocation is

```text
epsilon_total_cap
  = 4*epsilon_plane_q357
  + (2^64+1)*482/p^3
  + 2^20*64*2^-110
  + 2^-128 hash
  + 2^-128 production PCG
  + 2^-120 state/replay
  + 2^-128 codec/transcript
  = about 2^-79.481814299560
  < 2^-78.
```

The stronger exact-envelope row uses 35.803826821% of the allowed 78-bit
error and leaves 64.196173179%, or 1.481814300 security bits.  The simpler
Lean contract permits each plane to reach `2^-81`; its worst case is
78.955605881 bits and still leaves 48.437499999% of the error budget.
Cumulative exact-envelope margins are:

| After adding | Effective bits | 78-bit budget left |
| --- | ---: | ---: |
| W | 81.546189489 | 91.439668295% |
| B envelope | 80.546189489 | 82.879336590% |
| KV-old envelope | 79.961226988 | 74.319004884% |
| KV-new envelope | 79.546189489 | 65.758673179% |
| conditional stacked ProductClosure budget | 79.546189489 | 65.758673179% |
| all 64 response slots | 79.481814300 | 64.196173179% |
| hash, PCG, state/replay and codec | 79.481814300 | 64.196173179% |

Lean separately proves that the simpler four-plane caps, the selected
482-root Q64 budget expression and the residual allocation are below
`2^-78`.  The executable static test proves that the exact q357 W calculation
fits its `2^-81` cap.  Both are admission arithmetic, not the missing C7/ROM
bridge.

This contract ensures that an admitted profile cannot fall below 78 bits.
It does not admit the current implementation: B/KV schedules, base GKR, the
global ROM composition, the keyed-BLAKE3 multi-session control, production
PCG/MAC, hash, replay, abort/timing and codec reductions remain missing.
Those missing values are never treated as zero.

## 5. Static Gemma checks

The focused static report and test are:

```text
scripts/budget_c7_d126_gemma_static.py
tests/test_budget_c7_d126_gemma_static.py
```

They fail closed on any model revision, context, q vector, terminal count or
reducer count that differs from the frozen Gemma profile.  They check:

- the 472/480/0 census and 481 known Fp3 correlations;
- q357 W query, leaf, symbol, sibling, hash and byte counts;
- the abstract 482-root numerator, its conditional Q64 budget and 78-bit
  allocation;
- Alternative-1 mask capacity, setup and refresh counts;
- the conditional H100 subtotal and uncensused live allocations;
- the exact two-sweep and source-linear complexity requirements; and
- fail-closed `BLOCKED` status for every uncompiled full-chain quantity.

The Rust Phase-A unit test exercises the exact-tuple helper field by field and
checks a synthetic vector of 480 one-use axes has no reducer depth.  Neither
check is wired into the runtime compiler yet.

## 6. Current static resource row

### Wire and certificate

```text
q_open/U/S/H                         1,417 / 2,834 / 399,594 / 52,361
W offline-FS floor                   4,976,700 B
W partial certificate with framing  4,977,268 B
W 105% target / margin               5,496,695 / 519,995 B
W exact 125% cap                     6,543,685 B
W remaining bytes                    1,566,985 B
W 150% outer band / margin           7,852,422 / 2,875,722 B
four-plane planning proxy           25,482,394 B
```

The known slice fits the 100 MB Gemma ceiling and the frozen 3x growth gate.
The 125% W cap is the only preregistered cap; 150% is diagnostic only and is
not an automatic fallback.
The full certificate remains `BLOCKED` because B/KV, base-GKR, PCS and final
receipt records do not exist.  The planning value remains about 30 MB; it is
not certificate credit.

### Masks

```text
visible Fp per attempt       399,594
ResponseAttempt/root         4,096 (all outcomes)
lifecycle/load reserve       512 attempt-equivalent
mask cells/root              1,841,329,152
RootMask dimension           2,741,852,160
unused cells                 900,523,008
epochs / refreshes           256 / 255
one-slot setup               92,587,558,592 B
generator traffic/root       176,767,598,592 B
```

This closes the W geometry only.  B/KV charges and the adaptive multi-session
PRG theorem are still required, so `MASK_LIFETIME` remains `BLOCKED`.

### H100

```text
packed W                     61,394,690,560 B
one KV arena                  3,690,987,520 B
ROWFOLD total arena cap       6,442,450,944 B
staging                         256,000,000 B
ProductClosure terminal scalars     11,520 B
conditional subtotal          71,784,140,544 B
conditional headroom           8,215,859,456 B
```

The subtotal is valid only if the selected KV and ROWFOLD arena caps hold.
With the optional 2,000,000,000-byte speculative-generation allowance, its
conditional headroom becomes 6,215,859,456 bytes.  The exact `v` allocation
and liveness, B, commitment chains, base GKR, activations, CUDA/runtime
modules, allocator reserve/fragmentation and each selected kernel workspace
remain uncensused.  Therefore the strict
`peak_allocated < 80,000,000,000` test remains `BLOCKED`.

## 7. Complexity and realistic planning values

Admission still requires

```text
C(N,q,h) = c_source*N + P(q,h),
```

with `c_source` independent of `N` and `q`, exactly two packed-W HBM sweeps,
and no hidden complete transform or output-pruned claim without code.  The
repository does not yet contain the ROWFOLD relation/compiler, so both this
bound and the two-sweep gate remain `BLOCKED`.

For a warm resident Gemma-31B model, current low-confidence planning is:

| Quantity | Realistic planning estimate |
| --- | ---: |
| prover time | 45--50 s |
| complete proof size | about 30 MB |
| verifier time, 4 cores | 6.4--8.2 s |

The 19.186-second storage acquisition is charged once to model onboarding,
not to each response.  The static report freezes these bands and fails if they
drift, but cannot validate runtime performance.  These estimates receive no
measurement credit.  The prover estimate is controlled mainly by the real
fixed-point 16-bit H100 kernel rate.

## 8. Authorization and deterministic resume

Authorized now, without hardware or generated model bodies:

1. full local Lean, Rust-workspace and Python static/KAT execution;
2. repository implementation of the exact 480-terminal manifest and the
   `C7CompilerMatchesStackedWeightUse` refinement;
3. deterministic B/KV layout compilation and the complete event-registry
   schema using tiny synthetic fixtures; and
4. a static H100 liveness-map generator that rejects every unnamed byte.

Still blocked:

1. generated Gemma weights/LUTs/goldens/roots until `GemmaQuantV1`, workload
   tokens and pinned shard hashes are supplied;
2. ROWFOLD implementation until its exact report, relation and two-pass
   algorithm are present;
3. any full-chain security, proof-size, two-sweep, complexity or H100 PASS;
4. GPU/H100 measurement, production work and every pod action.

The next admission run must, in order:

1. compile all 480 terminal records and prove the Rust-to-Lean refinement;
2. emit B/KV `q,U,S,H`, mask loads and every base-GKR
   `K,sum(degree),n,hfin` row;
3. populate every event with numerator, denominator, FS factor, lifetime and
   abort/retry scope;
4. serialize the maximal certificate and check all byte caps;
5. emit the complete H100 allocation timeline and prove the peak is strictly
   below 80,000,000,000 bytes; and
6. only then request a separate hardware-measurement authorization.

## 9. Gate status

| Gate | Status |
| --- | --- |
| stacked Lean relation | `PASS` |
| fixed-prefix ProductClosure numerator | `PASS` for abstract `T+2=482` |
| concrete Fp3/transcript/Q64 ProductClosure bridge | `BLOCKED` |
| `SECURITY_78` | conditional arithmetic `PASS`; realized security `BLOCKED` |
| `SECURITY_84` at q357 | `NO-GO` |
| `FS_Q64` | `BLOCKED` |
| `MASK_LIFETIME` | `BLOCKED` |
| `COMPLEXITY_BOUND` | `BLOCKED` |
| `TWO_HBM_SWEEPS` | `BLOCKED` |
| `EXACT_WIRE_CENSUS` | `BLOCKED` |
| `FULL_CERTIFICATE` | `BLOCKED` |
| `H100_STATIC_FIT` | `BLOCKED` |
| `D126` | `BLOCKED` |

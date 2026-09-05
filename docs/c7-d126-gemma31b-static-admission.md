# C7 D126 Gemma-31B stacked static admission

**Status:** active design; the terminal declaration, pinned metadata/workload,
public scalar values, isolated static frontend, ragged-norm algebra and
conditional heterogeneous-GKR envelope are implemented and checked; full
admission remains `BLOCKED`.

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

`lean/VoltaZk/C7StackedWeightUse.lean` proves the generic matrix, tied-
embedding and final-norm stacking laws.  Its older six-role norm statement has
one uniform coordinate type `D`; that is not an exact Gemma instantiation and
is no longer presented as one.

`lean/VoltaZk/C7GemmaTerminalManifest.lean` adds the required Gemma-specific
ragged statement.  Together the two files prove:

1. right multiplication by one physical matrix commutes with stacking prompt
   and response rows;
2. one sigma-indexed direct sum for the six differently sized norm roles is
   equivalent to the twelve phase/role equations and has no cross-role terms;
3. tied lookup and logits keep their two matrix orientations;
4. the final norm is shared across the two phases; and
5. the exact local/global norm cardinalities are respectively
   `4*5376+2*256=22,016` and `4*5376+2*512=22,528`.

The exact ragged equivalence is
`VoltaZk.c7_gemma_ragged_norm_bundle_iff_per_use`; local and global
specializations and the no-cross-term theorem are kernel-checked.  The generic
combined theorem `VoltaZk.c7_stacked_weight_use_compiler_complete` remains
useful algebra, but its uniform norm type is not the Gemma runtime refinement.

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

The canonical terminal declaration is
`manifests/c7-d126-gemma31b-terminals-v1.csv`, with BLAKE3
`c90c41afaaac0c8da4a3c6e4781cd95dab026477999d6e20f565580db82bda25`.
It contains 480 ordered records and is consumed by both Rust and Lean.  The
Rust compiler rejects any header, order, owner, source-key or use-axis drift.
Lean's build-time `#guard` checks the same CSV against its declaration, and
the theorem `c7_gemma_declared_terminal_manifest_refines_stacked_profile`
proves its order/census conditions.  The pinned text-only source inventory is
exactly 772 private learned tensors plus 60 public `layer_scalar` dependencies;
all 356 vision/bridge tensors are excluded.  Packed private W is exactly
30,697,345,280 scalars or 61,394,690,560 i16 bytes. The two pinned
safetensors headers and the 120 public-scalar bytes were acquired without
downloading either complete shard. Their exact ordered BF16 patterns are in
`c7-d126-gemma31b-layer-scalars-v1.csv`; they are not all one.

Lean derives the last two zeros from an explicit vector of 480 use-axis
lengths, all equal to one; they are not literal zero-returning definitions.
This proves the frozen static declaration. `C7GemmaGKR.lean` additionally
checks the scalar CSV byte for byte and proves its ordered association with
the public keys in the terminal manifest. The conditional theorem
`c7_gemma_bound_runtime_manifest_refines_stacked_profile` shows what follows
if a runtime output equals both canonical lists; it does not construct that
runtime equality.

The isolated `c7_gemma_frontend.rs` validates the metadata, workload,
reference-semantics and quantization-requirements digests. It compiles 472 W
descriptors: 410 matrices, 60 ragged norm bundles, tied embedding and final
norm, covering all 772 private source descriptors and 60 ordered public
scalars. Every descriptor has `runtime_value_bound=false`. The frontend emits
zero B/KV layout rows and zero base-GKR cohort rows rather than filling missing
values with synthetic defaults. Thus the static frontend census passes while
checkpoint-value-to-relation refinement remains `BLOCKED`.

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

The strongest currently justified base-GKR statement is therefore symbolic.
`C7GemmaGKR.lean` defines heterogeneous cohort shapes and specializes the
existing malicious-prover theorem for each shape `c`:

```text
R_c = K_c + sum_i d_c[i] + n_c + 2
epsilon_GKR <= (2^64+1) * sum_c R_c / p^3.
```

This theorem is deliberately shape-only. It does not invent member-point
histories or claim that the runtime scheduler used one common point. The
actual histories, their `HasCommonPoint` proof, the final PCS relation `hfin`
and the concrete Fp3 verifier refinement remain required inputs.

A separate finite counting lemma places all supplied cohort bad sets under
one `2^64+1` axis. Its premise must already hold for every local query,
concurrent session, abort and retry; it is a union bound, not the missing ROM
reduction. Thus the global factor is applied once and there is no additional
`2^20` factor for this lifetime-global event.

Exact arithmetic permits at most `R=262,143` in one `2^-110` slot, or
`sum R=4,398,046,508,032` only if the entire `operator_compute` class
(`2^-86`) is assigned to GKR. Other compute events must be subtracted. The
current total already includes that reserve and leaves an additional absolute
headroom of 722,784,653,514,375 roots before the strict 78-bit boundary; the
next root fails. Spending that diagnostic headroom would leave about
`1.01e-16` of the 78-bit error budget and is not the active allocation. No
current artifact supplies Gemma values for `K`, `d`, `n`, common points or
final links, so none of these ceilings is a concrete GKR term.

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

The focused static reports and tests are:

```text
scripts/c7_d126_gemma_metadata.py
tests/test_c7_d126_gemma_metadata.py
tests/test_c7_d126_gemma_workload.py
scripts/c7_d126_gemma_quant_contract.py
tests/test_c7_d126_gemma_quant_contract.py
scripts/budget_c7_d126_gemma_static.py
tests/test_budget_c7_d126_gemma_static.py
scripts/c7_d126_gemma_h100_liveness.py
tests/test_c7_d126_gemma_h100_liveness.py
rust/volta-pcs/src/c7_gemma_frontend.rs
rust/volta-pcs/tests/gemma31b_frontend.rs
lean/VoltaZk/C7GemmaGKR.lean
```

They fail closed on any model revision, context, q vector, terminal count or
reducer count that differs from the frozen Gemma profile.  They check:

- the 472/480/0 census and 481 known Fp3 correlations;
- q357 W query, leaf, symbol, sibling, hash and byte counts;
- the abstract 482-root ProductClosure numerator, symbolic heterogeneous GKR
  numerator, conditional Q64 budgets and 78-bit allocation;
- Alternative-1 mask capacity, setup and refresh counts;
- the conditional H100 subtotal and uncensused live allocations;
- the exact two-sweep and source-linear complexity requirements; and
- fail-closed `BLOCKED` status for every uncompiled full-chain quantity.

The source manifest was also compared independently with the pinned
checkpoint index: all and only the 832 language keys are covered. Focused
Python, Rust and Lean counts are recorded in the active ledger checkpoint.
These are static/KAT results, not model execution or security credit.

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

The synthetic B/KV compiler now records the full query tape, tree size,
`q/U/S/H`, mask loads, terminal IDs, root multiplicity and event scope.  Its
stress fixture deliberately uses the q357 caps and one synthetic root for each
of B, KV-old and KV-new.  For each such root it derives 256 epochs, 255
refreshes, 419,004,678,144 service loads, 52,375,584,768 lifecycle-reserve
loads and 471,380,262,912 provisioned lifetime loads.  It explicitly covers
local queries, concurrent sessions, aborts and retries, and rejects applying
`2^20` again to a global-Q64 event.

Those numbers are fixture checks, not real B/KV geometry, semantics, physical
root counts, setup or leakage bounds. The caller also supplies its own event-ID
inventory, and an event row does not yet say whether its numerator is per root
or already aggregated across roots. W is the only real compiled query geometry,
so `MASK_LIFETIME` remains `BLOCKED`.

### H100

```text
packed W                     61,394,690,560 B
one KV arena, capacity        3,690,987,520 B
KV live payload                 135,168,000 B
unused KV capacity            3,555,819,520 B
ROWFOLD total arena cap       6,442,450,944 B
staging                         256,000,000 B
ProductClosure terminal scalars     11,520 B
conditional subtotal          71,784,140,544 B
conditional headroom           8,215,859,456 B
```

The subtotal charges the complete 4,096-token KV capacity, not only the 150
live workload tokens, and is valid only if the selected KV and ROWFOLD arena
caps hold.
With the optional 2,000,000,000-byte speculative-generation allowance, its
conditional headroom becomes 6,215,859,456 bytes.  The exact `v` allocation
and liveness, B, commitment chains, base GKR, activations, CUDA/runtime
modules, allocator reserve/fragmentation and each selected kernel workspace
remain uncensused.  Therefore the strict
`peak_allocated < 80,000,000,000` test remains `BLOCKED`.

The H100 checker requires a caller-supplied row for packed W, one KV arena,
the unique 11,520-byte `v`, staging, ROWFOLD, B, masks, public constants,
commitment chains, ProductClosure, base GKR, activations, workspaces,
CUDA/runtime and allocator reserve. Every row separates useful payload,
temporary device-lane padding, logical bytes and physical allocation, with
`logical = payload + padding`; the peak sums physical allocation bytes. It
checks declared liveness/aliasing, two W sweeps, every forbidden allocation,
batch size one, at most one GPU response at a time, the frozen 100+50 live
workload and the 4,096-token capacity. Its 16-allocation synthetic KAT has a
structural peak of
71,986,689,600 bytes, but returns top-level `BLOCKED`, not `PASS`; the inventory
is self-declared and its unknown-buffer sizes may be incomplete or too small.
Only a compiler-owned inventory, CUDA completion fences for alias handoffs and
an allocator trace can prove every byte and receive memory credit.

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

The owner GO of 2026-09-05 authorizes three implementation scopes:

1. define a new Gemma-only `GemmaQuantV1` arithmetic specification and compile
   the complete text-model operator DAG;
2. use the two pinned private weight bodies after their complete SHA-256
   verification; and
3. design the ROWFOLD relation and two-pass algorithm from first principles.

This GO does not permit importing historical model arithmetic or treating an
old transform as ROWFOLD. It also does not override the separate provider and
hardware hard stop.

The workstation has about 66 GB free. The two source shards consume
62,546,338,248 bytes and the packed i16 output consumes 61,394,690,560 bytes,
or 123,941,028,808 bytes together before any build, LUT, golden or temporary
artifact. Therefore complete local shard acquisition/packing is `NO-GO` under
the owner's no-saturation rule. Specifications, metadata-only compilers and
tiny fixtures stay local. A future pod must have an H100 80 GB, at least 400
GB usable storage, at least 256 GiB host RAM until the exporter is proved
streaming, and a provider-side stop/termination deadline. Contacting the
provider still requires the literal `GO-RUNPOD`.

Completed under the current local authorization, without hardware or
complete private model bodies:

1. focused Lean, Rust and Python static/KAT execution;
2. repository implementation of the exact 480-terminal static manifest and
   its Rust/Lean declaration refinement;
3. pinned tensor metadata, 60 public scalar values, tokenizer/workload and an
   explicitly uninstantiated `GemmaQuantV1` requirements contract;
4. an isolated static Gemma frontend compiling all 472 W descriptors while
   emitting zero unearned B/KV or GKR rows;
5. shape-only heterogeneous-GKR numerator and one-axis union lemmas;
6. a B/KV/event schema exercised only on tiny synthetic fixtures; and
7. an internal-consistency checker for a caller-supplied static H100 map.

Still blocked:

1. completion and review of the now-authorized Gemma-only arithmetic
   specification, followed by execution against the authorized pinned shard
   bodies, LUTs and bit-exact goldens;
2. runtime binding of those values to the 472 relations, the 50 decode IDs,
   real B/KV roots/layouts and concrete base-GKR cohorts;
3. scheduler common-point, PCS, Fp3 and global-ROM refinements;
4. ROWFOLD implementation until its exact report, relation and two-pass
   algorithm are present;
5. any full-chain security, proof-size, two-sweep, complexity or H100 PASS;
6. provider contact, every pod action, GPU/H100 measurement and production
   work until the separate `GO-RUNPOD` is recorded.

The next admission run must, in order:

1. approve a Gemma-only arithmetic specification containing every currently
   null `GemmaQuantV1` field;
2. separately authorize or supply the two pinned private shard bodies;
3. instantiate quantization, LUTs, goldens and Rust/Python bit equality;
4. bind runtime values and the 50 decode IDs to the 472 relations and compile
   the complete operator DAG;
5. emit real B/KV `q,U,S,H`, physical roots and lifetime mask loads;
6. emit every GKR `K,d[],sum_d,n,common-point,hfin,PCS,transcript` row and the
   complete security-event registry, then close the Fp3/ROM refinements;
7. serialize the maximal certificate and compiler-owned H100 allocation
   timeline, including CUDA fences and allocator trace, and close every static
   gate; and
8. only then request a separate hardware-measurement authorization.

## 9. Gate status

| Gate | Status |
| --- | --- |
| matrix/tied/final stacking algebra | `PASS` |
| exact ragged six-norm algebra | `PASS` |
| exact static 480-terminal declaration/census | `PASS` |
| pinned metadata and 60 scalar values | `PASS`, static only |
| frozen 100+50 workload | prompt `PASS`; decode/runtime `BLOCKED` |
| isolated 472-W descriptor frontend | `PASS`, static only |
| `GemmaQuantV1` | `BLOCKED`, 13 fields missing |
| runtime checkpoint-to-472-relations refinement | `BLOCKED` |
| synthetic B/KV/event compiler structure | `PASS`, no protocol credit |
| real B/KV layout/events | `BLOCKED` |
| fixed-prefix ProductClosure numerator | `PASS` for abstract `T+2=482` |
| generic base-GKR shape formula | `PASS`; runtime common-point and Gemma rows `BLOCKED` |
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
| local full-weight ingest | `NO-GO`, insufficient safe disk headroom |
| RunPod/provider execution | `BLOCKED`, requires literal `GO-RUNPOD` |
| `D126` | `BLOCKED` |

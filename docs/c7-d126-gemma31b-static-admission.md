# C7 D126 Gemma-31B stacked static admission

Historical design as of 2026-09-05. The owner opened C7.1 in
[`c7.1-gemma31b-design.md`](c7.1-history/c7.1-gemma31b-design.md); the original D126 status
and requirements below are preserved as history, not current authority.

**Status:** active design; the terminal declaration, pinned metadata/workload,
public scalar values, row-complete weight-use algebra, logical tensor shapes,
source-once reference ingest, native tensor packing and conditional
heterogeneous-GKR envelope are implemented and checked; full admission remains
`BLOCKED`.

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

### Service flow and finite setup

The owner-confirmed target flow is:

```text
offline: DVConnectionSetup -> CapacitySetup(finite attempts) -> one-time slots
user    -> prompt + attempt_id/nonce + connection/capacity/predecessor binding
provider-> generated text, pending verification
provider-> complete proof of the declared quantized Gemma inference
user    -> local verification with secret Delta/keys -> durable verdict
user    -> optional ACK now, or acknowledgment carried by the next prompt
```

This is the required interface; the complete executable protocol remains
blocked. Fiat--Shamir challenges are derived in the frozen commitment order,
with no verifier challenge during proving. Delta and verifier keys remain
local. The user request is bound to the model revision, quantization profile,
capacity/slot, prompt and predecessor state; the certificate also binds the
generated token IDs and successor state. A nonce is replay binding, not a
substitute for the global-Q64 security proof.

Slots and correlation ranges are reserved durably before disclosure and are
never returned on failure, retry or missing ACK. Verification and committing
the accepted state do not depend on sending an ACK. A subsequent prompt must
name the accepted predecessor; absent or conflicting acknowledgment must not
cause a fresh proof, a second spend or acceptance of an unverified state.
Crash/replay and concurrent-session refinements remain required before credit.

"Once" means once per connection and purchased finite capacity, not unlimited
reuse of masks. The current lifetime has 256 root epochs, at most 4,096
attempts per root and 255 refreshes; those refreshes, all setup traffic and
their retained state must be charged even when provisioned ahead of time.
These costs are separate from the 19.186-second model-resident storage load.
The timing profile remains the frozen 100-prompt/50-generated-token workload;
the 4,096-token capacity does not assert that every context length has the same
cost.

## 2. Stacked relation and exact census

`lean/VoltaZk/C7StackedWeightUse.lean` proves the generic matrix, tied-
embedding and final-norm stacking laws.  Its older six-role norm statement has
one uniform coordinate type `D`; that is not an exact Gemma instantiation and
is no longer presented as one.

`lean/VoltaZk/C7GemmaTerminalManifest.lean` adds the Gemma-specific ragged
coordinate statement. `lean/VoltaZk/C7GemmaQuantAccumulator.lean` then adds
the workload-row refinement that the older phase-indexed statement lacked.
Together these files prove:

1. right multiplication by one physical matrix commutes with stacking all 100
   prompt rows and all 50 response rows;
2. one sigma-indexed direct sum for the six differently sized norm roles is
   equivalent to every role/head/coordinate equation on all 150 token rows:
   Q uses 32 heads, while K uses 16 local or 4 global heads;
3. tied lookup over 150 rows and logits over 50 rows keep their two matrix
   orientations while sharing one physical embedding;
4. the unpruned final norm covers its 100 prefill rows plus 49 decode rows,
   while `last_row_select` leaves exactly 50 LM-head/logit rows;
5. the physical local/global norm-weight cardinalities remain respectively
   `4*5376+2*256=22,016` and `4*5376+2*512=22,528`; and
6. the logical norm equations are 33,792 per token/local layer and 39,936 per
   token/global layer, hence exactly 313,344,000 for 150 tokens over 50 local
   and 10 global layers.

The phase-level ragged helper remains
`VoltaZk.c7_gemma_ragged_norm_bundle_iff_per_use`. The row-complete statements
are `c7_gemma_matrix_100_prompt_50_response_rows`,
`c7_gemma_local_norm_all_150_rows_and_heads`,
`c7_gemma_global_norm_all_150_rows_and_heads`,
`c7_gemma_tied_embedding_150_lookup_selected_50_logits` and
`c7_gemma_final_norm_all_149_active_rows`. They use explicit row and dependent
head-use indices, not an unchecked random linear combination, so they
introduce no additional RLC error term. They are algebraic statements:
equality between the Rust-emitted runtime rows and these Lean inputs is still
a separate blocked refinement. The logits theorem uses an explicit selector:
decision zero reads prefill row 99, and decisions one through 49 read the 49
singleton decode rows; it does not accept an unrelated hidden matrix.
The generic combined theorem
`VoltaZk.c7_stacked_weight_use_compiler_complete` remains useful algebra, but
its uniform norm type and two phase representatives are not that runtime
refinement.

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

The new Gemma-only QSPEC manifest and Python/Rust compilers expand the frozen
51-execution schedule into exactly 79,963 high-level operator-invocation
records and 101,322 tensor-output dependency edges. They count 20,910 learned
matrix invocations inside layers and 20,960 including the 50 one-row LM-head
applications. An explicit `last_row_select` and
`logits_to_keep_per_decision=1` prevent charging a full prompt logit matrix.
The 472 compiled W owner names equal the canonical terminal-manifest owner set,
and the prompt IDs, positions, attention masks, embedding scale and 60 layer
scalars are named public inputs. No output-pruned implementation or theorem is
claimed.

The original artifact remains a declared high-level operator invocation DAG.
`scripts/c7_d126_gemma_shapes.py` now refines every node to logical output
ports, exact shapes, private weight keys, input ports, views, direct consumers
and matrix contraction widths. Its canonical JSONL stream has SHA-256
`35c6716f0b8ca5ffc1e089c592af647dcf3c094ed692d7398bff8fbb5561e7d3`.
It contains 83,023 output ports and 104,322 input-port edges: each cache node
has separate K and V outputs, so these are not the older tensor-node edge
counts. All and only 772 private tensor keys are checked against their exact
source shapes. Rewiring a same-sized graph is rejected.

The logical plan contains 610 aliases and 6,120 cache views. Global V aliases
the raw K projection, before learned K normalization. GQA uses the indexed
mapping `kv_head=floor(query_head/(query_heads/kv_heads))`; materializing a
repeated cache is not assumed. The final-row view retains the exact prefill
row 99 and subsequent singleton-row selectors. Attention has 21,744,000
allowed cells and 9,504,000 masked cells; all 31,248,000 rectangular cells
remain charged. The shape-derived dense/QK/PV MAC counts independently equal
the earlier census, and the maximum dot width is 21,504.

Concrete integer dtypes/scales, internal nonlinear and requantization rows,
GKR-domain and device-lane padding, proof-retention lifetimes and runtime source
dependency closure remain open. The logical shape compiler is not a full
semantic DAG, exact integer-wire census, base-GKR circuit or physical allocator
trace. In particular, a direct-consumer index does not authorize releasing an
aliased value or a witness needed by later proving.

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
`prodBatch_sound_scalar`, that the C7 transcript fixes the claims/triples
before `chi` while allowing the response message to depend on `chi` but never
on secret `Delta`, or that one classical-ROM Q64 factor covers all sessions
and attempts. Therefore the 119.087-bit value is
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

The new Lean theorem `c7_gemma_i16_dot_accumulator_bound` proves from explicit
hypotheses that any signed-i16 dot product of width at most 21,504 has absolute
value at most 23,088,334,918,656. A companion theorem proves this is strictly
below half the Goldilocks modulus, so no centered-field wrap occurs for such a
dot product. This closes one arithmetic lemma only. The QSPEC compiler has not
yet proved that every runtime operand, requantization point and non-dot
operation satisfies the hypotheses, and the operator DAG has not been lowered
to base-GKR rows. Consequently there is still no concrete new Gemma GKR error
term to add or credit.

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
manifests/c7-d126-gemma31b-qspec-dag-v1.json
scripts/c7_d126_gemma_qspec_dag.py
tests/test_c7_d126_gemma_qspec_dag.py
scripts/c7_d126_gemma_shapes.py
tests/test_c7_d126_gemma_shapes.py
tests/test_c7_d126_gemma_native_bf16.py
scripts/c7_d126_gemma_weight_ingest.py
tests/test_c7_d126_gemma_weight_ingest.py
docs/c7-d126-rowfold-two-pass-disposition.md
scripts/c7_d126_rowfold_two_pass.py
tests/test_c7_d126_rowfold_two_pass.py
scripts/budget_c7_d126_gemma_static.py
tests/test_budget_c7_d126_gemma_static.py
scripts/c7_d126_gemma_h100_liveness.py
tests/test_c7_d126_gemma_h100_liveness.py
rust/volta-pcs/src/c7_gemma_frontend.rs
rust/volta-pcs/tests/gemma31b_frontend.rs
rust/volta-pcs/src/gemma31b_qspec_dag.rs
rust/volta-pcs/src/gemma31b_bf16.rs
rust/volta-pcs/examples/gemma31b_bf16_fixture.rs
rust/volta-pcs/tests/gemma31b_qspec_dag.rs
lean/VoltaZk/C7GemmaGKR.lean
lean/VoltaZk/C7GemmaQuantAccumulator.lean
```

They fail closed on any model revision, context, q vector, terminal count or
reducer count that differs from the frozen Gemma profile.  They check:

- the exact static 472 W / 480 total / zero-reducer declaration and 481 known
  Fp3 correlations; runtime emission of all 480 remains unproved;
- the 79,963 high-level operator invocation and 101,322 tensor-edge census,
  including one-row logits and all named public inputs;
- source-layout, terminal-order, BF16 RNE, minimum-exponent, source-once hash
  and fail-closed publication behavior on tiny weight fixtures;
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

This is a **subcodec reservation**, not a complete serialized certificate.
The report now derives each round's oracle/leaf count, opened-leaf reservation,
masked payload, salts, exact compact-tree frontier and framing from the active
Gemma geometry. It imports no historical budget implementation. Independent
exhaustive small-tree tests check the frontier formula. Separate reservation
maxima need not be jointly attainable in a single Fiat--Shamir transcript.

The partial slice fits the 100 MB ceiling and its **partial-slice** growth
comparison. Full-certificate growth cannot use the 3,466,188-byte partial
historical slice as its denominator: the complete reference is still missing.
The 125% W cap is the only preregistered cap; 150% is diagnostic only and is
not an automatic fallback.
The full certificate remains `BLOCKED` because B/KV, base-GKR, PCS and final
receipt records do not exist. The 30 MB value is an **owner target, not a
prediction or a proved bound**.

The 25,482,394-byte proxy is not a known partial certificate awaiting only
additional positive records. It already contains uncompiled substitutes:

| Proxy component | Bytes | Evidence |
| --- | ---: | --- |
| W subcodec plus fixed W records | 4,976,700 | partial reservation only |
| three hypothetical D31 B/KV streams | 11,050,776 | layouts not selected |
| illustrative compute/base-GKR | 9,379,670 | no Gemma record compiler |
| illustrative MAC/framing | 75,248 | not a complete final codec |
| **Proxy** | **25,482,394** | **neither lower nor upper bound** |

In particular, `30,000,000 - 25,482,394 = 4,517,606` bytes is **not** certified
remaining headroom. If the present W reservation and 568 bytes of known
all-plane/container allowance are retained without overlap, the correct
unfilled *target budget* is `30,000,000 - 4,977,268 = 25,022,732` bytes. It
must cover all additional W PCS records, all B/KV streams, complete GKR,
mask/base-case messages, output/receipts and remaining framing exactly once.
The missing W portion must also fit its separate 1,566,985-byte allowance.
Neither allowance asserts that the missing construction will fit.

**Pre-pod completion procedure.** Lower the integer DAG and compile GKR
cohorts/rounds first; select B/KV oracle and mask layouts; construct the actual
PCS relations and their ordered messages; assign every serialized record to
one owner (no duplicate framing); derive lengths and padding from those
records; then serialize bounded synthetic witnesses and compare actual
lengths with the compiled reservation, including rejection tests. An H100 is
not needed to establish these deterministic byte counts. The current blocker
is absent protocol/codec construction, not absent GPU measurements. Missing
records stay `None`, never zero or historical estimates.

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

The logical-shape compiler counts 1,841,924,224 owned real-valued output
elements, excluding the explicitly aliased/cache-view outputs. If all those
outputs are retained simultaneously beside the conditional subtotal above:

| Representation assumption | Output bytes | Conditional subtotal plus outputs | Screen |
| --- | ---: | ---: | --- |
| i16 throughout | 3,683,848,448 | 75,467,988,992 | `BLOCKED`, 4,532,011,008 bytes before missing classes |
| every output expanded to Fp | 14,735,393,792 | 86,519,534,336 | `NO-GO_IF_SIMULTANEOUS` |
| every output expanded to Fp3 | 44,206,181,376 | 115,990,321,920 | `NO-GO_IF_SIMULTANEOUS` |

These are representation screens, not allocation or datatype claims. Integer
lowering temporaries, B, masks, chains, GKR scratch, CUDA/runtime and allocator
reserve remain additional. The i16 case cannot pass the memory gate until
their sizes and exact lifetimes are compiled.

## 7. Complexity and realistic planning values

Admission still requires

```text
C(N,q,h) = c_source*N + P(q,h),
```

with `c_source` independent of `N` and `q`, exactly two packed-W HBM sweeps,
and no hidden complete transform or output-pruned claim without code.
The owner has now identified the previously uninspected ROWFOLD report;
its immutable source, digest and [controlling review](c7-d126-rowfold-v2-review.md)
replace the prior “report absent” diagnosis. V2 has a proposed relation and
two-pass interactive schedule, but is `NO-GO` as written: it uses `N log q`,
at least 10,737,418,240 bytes for v plus its separate NTT buffer, and online
challenges. Its heterogeneous-row EvalLink and interactive mask-lifetime
arguments also fail the local algebraic checks. No repaired offline-Q64
implementation is present or admitted. The old standard-WHIR sweep mapping
is a control, not a derivation of v2, whose initial oracle is precommitted
in setup.
Under separately named standard-WHIR controls, a materialized `2^32`-cell
post-first-fold state would occupy 34,359,738,368 bytes and exceed the one
6,442,450,944-byte arena by 27,917,287,424 bytes. That is a conditional
rejection control, not a derivation or universal impossibility result for the
missing carrier. Both the complexity and two-sweep gates remain `BLOCKED`.

For a warm resident Gemma-31B model, the owner's targets remain:

| Quantity | Target, not a supported prediction |
| --- | ---: |
| prover time | 45--50 s |
| complete proof size | about 30 MB |
| verifier time, 4 cores | 6.4--8.2 s |

The 19.186-second storage acquisition is charged once to model onboarding,
not to each response.  The static report freezes these bands and fails if they
drift, but cannot validate runtime performance. There is no complete
cryptographic execution path from which to estimate its arithmetic, HBM
traffic or critical path. The previous description as mainly a kernel-rate
problem was too strong: **both the cryptographic construction and kernel
engineering remain open**. No confidence interval or 50-second upper bound
is supported. The four-core verifier estimate is likewise not derived from
a complete Gemma verifier workload.

The report now records the timing boundaries explicitly. Prover time starts
at warm request admission and includes inference, response-local correlation
work and complete certificate encoding. Verifier time includes its correlation
preparation, full parsing/hash/algebra and durable verdict on four cores; ACK
may follow. Proof bytes include every certificate record and frame. Network
transfer, connection/capacity setup, quantization and root refresh are reported
separately; they are not covered by the 19.186-second storage acquisition.
The remaining PCS/ROWFOLD construction is also necessary to substantiate the
planning times; kernel engineering alone does not close that protocol gate.

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
7. an internal-consistency checker for a caller-supplied static H100 map;
8. a Gemma-only high-level operator-invocation DAG with exact declared counts,
   canonical W-owner equality and no base-GKR credit;
9. row/head-complete Lean norm batching, 149-row final-norm algebra and the
   conditional signed-i16 dot accumulator bound; and
10. a tiny-fixture source-once reference weight packer and a fail-closed
    ROWFOLD intake/conditional standard-WHIR screen.

The new native BF16 tensor component uses integer arithmetic for RNE and the
minimum per-tensor exponent. For a nonzero magnitude `x`, it derives
`e=floor(log2(x))-14`; BF16 has at most eight significant bits, so scaling
gives an exact integer in `[16384,32640]`, while `e-1` overflows symmetric
i16. All-zero tensors use zero. Tests compare all 65,536 BF16 patterns at all
264 exponents from -149 through 114 with an independent dyadic reference,
check minimality for every positive finite BF16 magnitude, and compare packed
bytes with Python. Nonfinite/truncated tensors produce no output; insufficient
scratch rejects before reading the source.

The component reads one tensor into caller-budgeted scratch, scans and converts
that same buffer, then writes it. The largest private tensor requires
2,818,572,288 host bytes, derived from the metadata. This is not a second full
weight copy or an HBM allocation. The fixture executable caps input at 1 MiB
and is test-only. Integration with complete shard hashing, canonical tensor
placement, locking and atomic model publication remains blocked; the existing
scalar whole-model reference is still the only such integrated path. No native
full-ingest or H100 throughput is claimed.

Still blocked:

1. instantiation of every open GemmaQuantV1 exponent, requantization, finite
   mask and nonlinear-table field, followed by execution against the pinned
   shard bodies, LUTs and bit-exact goldens;
2. runtime binding of those values to the 472 relations, the 50 decode IDs,
   real B/KV roots/layouts and concrete base-GKR cohorts;
3. scheduler common-point, PCS, Fp3 and global-ROM refinements;
4. repair the identified ROWFOLD relation, mask proof, offline-Q64 transcript,
   total arena and source-linear work, then implement the admitted algorithm;
5. any full-chain security, proof-size, two-sweep, complexity or H100 PASS;
6. provider contact, every pod action, GPU/H100 measurement and production
   work until the separate `GO-RUNPOD` is recorded.

The reference packer accepts exactly one canonical packed filename inside the
pinned shard directory:
`gemma-4-31b-5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89.packed.i16`. It acquires
that path's exclusive lock before creating a large temporary and blocks if it
finds a crash orphan. Thus two compliant jobs cannot choose different output
names and create parallel 61.4-GB copies.
It assumes this directory is controlled by the operator and is not writable by
an untrusted same-host process. After a crash, the deterministic recovery is:
verify that no pack process owns the recorded PID; confirm that no final output
was published; record the exact lock and unique partial path/size; remove only
those inspected paths; rerun preflight. No automatic orphan deletion is
allowed.

The owner GO recorded at `ba9d4c5` already authorizes a Gemma-only ROWFOLD
relation and two-pass algorithm designed from first principles. No duplicate
ROWFOLD-design GO is required while the frozen field, offline transcript
order, two source sweeps, one 6,442,450,944-byte arena, underlying PCS and
trust model remain unchanged. Replacing the underlying PCS or changing any of
those boundaries requires a new owner decision.

Before requesting `GO-RUNPOD`, local work must, in order:

1. close and pin the small public runtime-source dependency closure;
2. attach exact shapes, dtype, active views, aliasing, padding and liveness to
   the complete operator DAG;
3. freeze a shape-stable integer lowering, emit every primitive row and derive
   the exact wire census without using checkpoint values as topology;
4. emit real B/KV geometry and every GKR
   `K,d[],sum_d,n,common-point,hfin,PCS,transcript` row;
5. prove the common-point scheduler, final authenticated PCS link, Fp3/global
   Q64 composition, two-sweep property and
   `C(N,q,h)=c_source*N+P(q,h)` bound;
6. implement and test the prover/verifier, codec and source-read guard on small
   fixtures, including rejection of any third packed-W sweep;
7. serialize the maximal synthetic certificate, recompute every security and
   mask event, and compile the complete static H100 allocation timeline; and
8. provide a fail-fast runbook plus a native source-once exponent scanner and
   packer whose small-fixture output equals the scalar Python reference bit for
   bit.

Only after all applicable local gates are green may the owner be asked for the
literal `GO-RUNPOD`. That future bounded run may then:

1. acquire and verify the two private shard bodies on eligible storage;
2. derive the 772 weight exponents, packed digest, activation calibration,
   full goldens and Rust/Python runtime-value equality;
3. bind those values and the 50 decode IDs to the already compiled relations;
4. confirm CUDA liveness and allocator fences; and
5. measure HBM traffic, kernel throughput, peak allocation, prover time,
   serialized proof bytes and verifier time.

A second billed-run authorization is needed only for a retry or a materially
expanded scope after a failed run; it is not part of the normal successful
path. No provider contact or pod action is authorized yet.

## 9. Gate status

| Gate | Status |
| --- | --- |
| 100+50 matrix and 150-row lookup algebra | `PASS`, algebra only |
| norm head/use census: 313,344,000 logical equations | `PASS`, algebra only |
| 149-row final norm and 50-row logits algebra | `PASS`, algebra only |
| exact ragged six-norm algebra | `PASS` |
| exact static 480-terminal declaration/census | `PASS` |
| pinned metadata and 60 scalar values | `PASS`, static only |
| frozen 100+50 workload | prompt `PASS`; decode/runtime `BLOCKED` |
| isolated 472-W descriptor frontend | `PASS`, static only |
| declared high-level operator-invocation DAG census | `PASS`, static only |
| exact logical tensor shapes and input/output ports | `PASS`, static only |
| full semantic/operator-shape DAG | `BLOCKED` |
| signed-i16 dot accumulator bound | `PASS` from explicit hypotheses; runtime refinement `BLOCKED` |
| `GemmaQuantV1` | `BLOCKED`, 13 fields missing |
| source-once reference weight packer | `PASS` on tiny fixtures; full bodies and throughput uncredited |
| native source-once BF16 tensor packing | `PASS` on exhaustive arithmetic/tiny tensor tests; whole-model integration `BLOCKED` |
| runtime checkpoint-to-472-relations refinement | `BLOCKED` |
| synthetic B/KV/event compiler structure | `PASS`, no protocol credit |
| real B/KV layout/events | `BLOCKED` |
| fixed-prefix ProductClosure numerator | `PASS` for abstract `T+2=482` |
| generic base-GKR shape formula | `PASS`; runtime common-point and Gemma rows `BLOCKED` |
| concrete Fp3/transcript/Q64 ProductClosure bridge | `BLOCKED` |
| owner-named ROWFOLD source | identified and digest-checked; proposed v2 `NO-GO` as written; repaired carrier `BLOCKED` |
| standard-WHIR `2^32` retained-state control | conditional `NO-GO` under named assumptions |
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

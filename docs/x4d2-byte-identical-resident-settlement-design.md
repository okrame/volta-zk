# X4d.2 byte-identical GPU-resident settlement

**Status (2026-07-26): Phase 1 local implementation and identity proof
complete. HARD STOP before pod contact pending explicit owner GO. No
production measurement or gate verdict.**

This descendant is subordinate to `AGENTS.md`,
`docs/p7-handoff-spec.md`, `docs/prototype-status.md` and
`docs/x4d-deferred-settlement-design.md`. It changes only evaluation strategy,
residency and instrumentation. It changes no protocol, transcript ordering,
challenge schedule, proof grammar, codec, proof byte, soundness expression,
Lean theorem, query distribution, response hot path or gate ceiling.

## 1. Immutable history and owner disposition

X4d.1 remains an immutable preregistered **FAIL**. Its same-host A100
settlement walls are **333.456712047 s** at `k=1` and **878.973897598 s** at
`k=16`, hence **2.635946033901128x > 1.30x**. Its physical-symbol counters
pass: both records read **4,809,293,824** initial encoded symbols, produce
**1,159,200,768** combined-codeword symbols, perform one encoded-oracle pass
and one query gather, and materialize 102 physical terms. The k=16 record
retains 1,632 protocol relations and reports 1,530 fused terms.

The owner appends a one-time waiver for only the historical k=1
`0.154283455 s > 0.150 s` G1 synchronization observation. The waiver accepts
the already-delivered response hot path for the product decision. It does not
rewrite either raw record, authorize a selective retry, apply to X4d.2, or
relax the 0.150-s ceiling for any later record. Component classification is:

- physical fusion: **PASS**;
- hot path: **accepted under the one-time historical waiver**;
- amortization/flatness: **FAIL**.

The binding X4d.2 performance gate remains same-host
`settlement_wall(k=16) <= 1.30 * settlement_wall(k=1)` plus equality of all
inherited physical-symbol counters. No gate is relaxed.

## 2. Correction of record: ClaimReduce has rank-m, not rank-1

The earlier proposed general multi-point factorization with cost
`O(N + m*mu)` is **refuted for the current ClaimReduce relation**. Each
`eq(z_i,x)` is rank-1, but a weighted sum of independently pointed equality
tensors generally has rank up to `m`. At round `j`, each claim needs a
distinct suffix evaluation of the currently folded source polynomial. A
per-claim prefix scalar cannot reproduce the unchanged round polynomial.

The P4 Gruen split is not a counterexample. It removes one shared public
equality factor. It does not reduce a sum of independently pointed equality
tensors.

Therefore X4d.2 makes no asymptotic-flatness claim in `k`. It does not call
`blind_prove_batch` or use any round-synchronous schedule. The warning in
`rust/volta-proto/src/sumcheck_blind.rs:171-178` is binding: that schedule
assigns the interactive challenge tape differently. X4d.2 retains all
`51*k` ClaimReduce instances in their existing sequential order, including
each message append and host challenge draw. This algebraic correction is an
analytic protocol fact, not a performance measurement.

## 3. Disjoint attribution schema

The former claim-preparation bucket is replaced by the following disjoint
walls. All walls are steady-clock instrumentation and enter neither
transcript nor proof:

1. settlement-fixed preprocessing: padded i16 source construction and unique
   source-table census;
2. response-local ClaimReduce: prover and verifier walls separated, with
   prover F construction, W embedding, product-round message evaluation, F/W
   folds, and masks/transcript/orchestration; rows are grouped by `mu`;
3. auxiliary MLE evaluation;
4. authenticated-output link preparation: coefficient/challenge preparation,
   combined link-equality generation/accumulation, source clone/copy,
   delayed-link round evaluation, source/equality folds, and
   terminal/group/orchestration;
5. explicit unattributed residual.

The children plus residual reconcile exactly to the existing
`claim_coefficient_preparation_wall`. The record reports the residual as wall
and percentage and explains it as manifest/frame construction, inventory
lookups, allocation bookkeeping and timer/caller overhead not owned by a
named arithmetic child. Verifier work is never folded into prover work.

Traffic and residency are separately counted even when zero: unique host and
device bytes, H2D/D2H/D2D, kernel calls, protocol-scalar D2H, live/peak
scratch, allocation requests and pool reuse. Raw evaluation tables are not
called X4c encoded-oracle buffers and no pointer/content reuse is credited
without an exact identity and lifetime check.

### 3.1 Exact operation census

GPT-2 has 51 ClaimReduce calls and 102 frozen claims per response:

| `mu` | blocks/calls per response | claims per response | source symbols/call |
|---:|---:|---:|---:|
| 26 | 2 | 4 | 67,108,864 |
| 22 | 36 | 72 | 4,194,304 |
| 20 | 13 | 26 | 1,048,576 |
| **total** | **51** | **102** | **298,844,160 unique padded symbols** |

Thus the implemented sequential schedule performs 1,104 product rounds,
1,104 F folds and 1,104 W folds per response. Product-round evaluation reads
**1,195,376,436 Fp2 symbols/response**; each fold family reads
**597,688,218 Fp2 symbols/response**. These are operation and traffic counts,
not walls. At `k=16`, every count is exactly sixteen times the per-response
count.

The k-linear loops of record are:

- `rust/volta-bench/src/x4d_gpt2.rs:1178-1289`: response × 51-block
  ClaimReduce caller, exactly `51*k` calls and `102*k` claims;
- `rust/volta-pcs/src/batch.rs:809-906`: CPU-reference per-call F
  construction and repeated
  W i16→Fp2 embedding;
- `rust/volta-pcs/src/batch.rs:728-806`: CPU-reference per-round product
  evaluation and F/W
  folds;
- `rust/volta-bench/src/x4d_gpt2.rs:1475-1496`: response × block auxiliary
  MLE evaluation;
- `rust/volta-pcs/src/x4/authenticated_output_v4.rs:676-769`: one equality
  contribution per response-local relation before physical accumulation and
  CPU-reference materialization;
- `rust/volta-pcs/src/x4/authenticated_output_v4.rs:796-877`: delayed-link
  product rounds and folds over the 102 materialized physical terms;
- `rust/volta-pcs/src/x4/authenticated_output_v4.rs:1486-1778`: validation,
  coefficient construction, physical grouping and terminal group
  construction.

The first four loops are response-proportional. Source/onboarding construction
and the one encoded-oracle combine are physical-table-proportional. Manifest,
query and settlement-envelope work is fixed settlement overhead.

| attributed cost | scaling classification | operation/traffic interpretation |
|---|---|---|
| padded i16 construction and canonical W embedding | physical-table-proportional, paid once per settlement | 51 source builds/embeddings; bytes scale with the unique source census, not `k` |
| ClaimReduce F generation, product rounds and F/W folds | response-proportional | exactly `51*k` calls, `102*k` claims and the round/symbol counts above |
| ClaimReduce masks/transcript and verifier replay | response-proportional | logical scalar work; protocol bytes and correlation use remain unchanged |
| auxiliary MLE evaluation | response-proportional after one physical-table upload | 51 resident calls per response; call count and symbols read are separate from H2D |
| link coefficient and equality accumulation | response-proportional arithmetic over a physical source set | independently pointed contributions accumulate into 102 physical equality tables; no rank collapse |
| delayed-link rounds/folds | physical-table-proportional after equality accumulation | one global sequential sumcheck over 102 physical source/equality pairs |
| encoded-oracle combine and fold/Merkle | physical-table-proportional | one encoded-oracle pass and one fold chain for both k values |
| manifest, query, envelope and caller residual | fixed settlement overhead | reported explicitly rather than assigned to a convenient arithmetic child |

### 3.2 Historical A100 postdiction

The immutable coarse walls satisfy the descriptive affine fit

```text
claim_preparation ~= 131.279843649 s
                  + 0.358678416 s * frozen_claim
```

to displayed-record precision:

| record | fixed/intercept | response-local term | fitted total | observed |
|---|---:|---:|---:|---:|
| k=1, 102 claims | 131.279843649 s | 36.585198432 s | 167.865042081 s | 167.865042048 s |
| k=16, 1,632 claims | 131.279843649 s | 585.363174912 s | 716.643018561 s | 716.643018039 s |

The 33-ns and 522-ns differences are rounding in the displayed fit. This
postdicts the entire observed **167.865042048 s** and **716.643018039 s**
coarse buckets as a fixed/link/preprocessing intercept plus response-local
ClaimReduce/auxiliary-MLE slope. The permanent fine-grained instrumentation
will measure the named children in X4d.2 records. It is not valid to pretend
the X4d.1 JSONs measured those children, and the affine fit alone does not
prove that any single loop owns the slope.

## 4. Selected resident architecture and exact kernel contracts

### 4.1 ClaimReduce

At settlement entry, the 51 padded i16 sources contain exactly
**298,844,160 symbols / 597,688,320 B**. Each is embedded once into an
immutable canonical Fp2 device table:
**4,781,506,560 B**. This is distinct from the complete 102-table
authenticated-output evaluation tier of **601,161,728 Fp2 symbols /
9,618,587,648 B**.

Reused operations:

- `base_broadcast_fp2_kernel` with `kind=i16, repeat=1`: exact canonical
  i16→Fp2 embedding, once per source;
- `fp2_product_round_terms` plus `reduce_product_round`, exposed by
  `fp2_product_round_device`: returns only `[g(0),g(2)]`;
- `fp2_fold_rows_device`: non-destructive F or W fold into caller-owned D2D
  ping-pong storage;
- `reserve_fp2_product_round_workspace`: preallocates private reduction
  scratch before the first sequential instance;
- resident allocation/upload/download and segment-download primitives.

New operations:

- `claim_reduce_eq_seed`: seeds one scaled equality expansion;
- `claim_reduce_eq_expand`: expands one equality level in reverse point order;
- `claim_reduce_add`: accumulates the second scaled equality into the first;
- `volta_cuda_claim_reduce_f_two_into_device`: orchestrates
  `F=lambda*eq(z0)+lambda^2*eq(z1)` with one output plus reusable scratch and
  no host equality table.

One maximum-geometry four-buffer Fp2 pool is reused by every instance. The
canonical W input is never mutated. Round zero reads canonical W and writes a
W fold scratch; later rounds ping-pong. F uses a separate ping-pong pair.
Instances remain sequential. After `[g(0),g(2)]` returns, Rust applies the
unchanged masks, appends the unchanged 32-byte correction frame, draws the
next host challenge, then launches the two folds. At terminal, only the two
Fp2 scalars are returned for equality checking. Any CUDA load, allocation,
kernel, transfer, terminal or ownership error aborts; production does not
fall back to CPU.

`BackendKind::Cpu` implements the same source-hoist, immutable-source,
geometry-keyed scratch-pool and sequential transcript contract using host
vectors. It is the local full-orchestration differential oracle, not a
performance substitute.

### 4.2 Residual link and auxiliary work

Auxiliary MLE evaluation uses one resident canonical auxiliary table and the
existing `equality_weights_device`, `matrix_fold_device`/`fp2_dot_device`
contract; only the result scalar returns.

Combined link equality reuses the new `claim_reduce_eq_seed` and
`claim_reduce_eq_expand` kernels, then calls the new
`x4d_link_eq_accumulate_kernel` through
`volta_cuda_x4d_link_eq_accumulate_device`. They generate each independently
pointed, scaled rank-1 contribution and initialize or accumulate it into the
one physical-term equality buffer. This is exact `O(k*N)` work and makes no
rank-1 factorization claim.

Delayed-link execution reuses `fp2_product_round_terms`,
`reduce_product_round`, `fp2_fold_rows` and the workspace reserved by
`volta_cuda_reserve_fp2_product_round_workspace`. Virtual leading rounds use
the new `x4d_scaled_dot_pair_kernel` through
`volta_cuda_fp2_dot_scaled_pair_into_device`. The new
`volta_cuda_fp2_pair_sum_device` reuses `reduce_product_round` to reduce all
resident per-term pairs to the single protocol `[g(0),g(2)]`. Source and
equality vectors have separate non-destructive ping-pong storage. Rust
retains the one existing global round transcript/challenge schedule.
Terminal group construction is host-side and unchanged.

The complete 601,161,728-symbol evaluation tier is canonical and immutable.
It is not the encoded X4c oracle. Pointer, length, descriptor/cohort/slot,
content digest and lifetime must all match before reuse is credited.

## 5. GPT-2 resource envelope

Exact durable/onboarding history remains **9,618,587,808 B**. X4d.1's
**317,413,392,384 B** was the pre-fusion Phase-1 relation payload.
X4d.1 fusion reduced the relation-table CPU payload to
**28,855,762,944 B**. Neither number is rewritten.

X4d.2 resident components are:

- padded i16 ClaimReduce sources: 597,688,320 B host;
- immutable ClaimReduce Fp2 W tier: 4,781,506,560 B device;
- immutable authenticated-output source tier: 9,618,587,648 B host and
  device while the delayed link is active;
- largest `mu=26` four-buffer ClaimReduce pool:
  4,294,967,296 B device plus 864 B public point/scalar row;
- pre-reserved ClaimReduce product-reduction workspace:
  1,610,612,736 B device;
- delayed-link device-generated equality tier: 9,618,587,648 B;
- delayed-link per-term fold scratch: 14,427,881,472 B;
- two maximum-geometry (`mu=27`) link-equality generation buffers:
  4,294,967,296 B;
- existing X4c measured peak: 47,256,774,900 B device.

The phase lifetimes are disjoint and fail-closed: ClaimReduce releases its
canonical W and four-buffer pool before auxiliary MLE; auxiliary MLE releases
its resident tables before the delayed link; the delayed link releases its
source/equality/fold pools before X4c arena allocation. ClaimReduce is
therefore approximately **10,687,087,456 B** including reserved private
product workspace. The delayed-link live set is approximately
**37,960,027,776 B** including its 3,712-B point/mailbox row. Both remain
below the existing measured **47,256,774,900-B** X4c device peak, so the
projected settlement device peak remains **47,256,774,900 B** plus allocator
rounding and any backend-private state already included differently by the
native census. Phase 2 must preflight the measured rather than projected live
set against the admitted A100. Host admission remains **>=256 GiB** because
the complete live set still includes the durable coefficient/root tier, the
28,855,762,944-B fused relation-table CPU payload, source/onboarding tables,
response/model state, auxiliary material, CUDA pinned pools, codec/proof
state and allocator headroom—not merely one isolated tier.

## 6. Recomputed engineering scenarios (not gates)

From the immutable pair, k=1 minus the fitted one-response marginal gives a
descriptive current base
`B ~= 333.456712047 - 36.585198432 = 296.871513615 s`.
Flatness requires `M <= B/49`; at this base that is about **6.06
s/response**. The stronger scenario `M<=4 s` satisfies flatness for every
`B>=196 s`.

The informative 288–307-s band implies both:

- response-local marginal at or below about 4 s/response (about 9x below the
  present 36.585198432 s/response segment); and
- about 20–55 s removed from the current k-independent base, principally
  fixed preprocessing/link preparation and the approximately 125-s encoded
  oracle combine.

These are decomposition-derived scenarios only. They are not results,
preregistered wall projections or gate verdicts. In particular, the
historical ~290-s and ~160-s projections are not preregistered.

The local CPU-backend decomposition is an identity and operation-count
measurement, not an A100 wall forecast. It confirms that the selected path
removes repeated W embedding/allocation from the `51*k` loop and leaves the
remaining response-local work in GPU-suitable equality generation,
product-round and fold operations. That is sufficient to retain the
byte-identical Phase-2 experiment; it does not trigger the protocol-visible
contingency.

## 7. gpt-oss-20b sizing appendix (informative only)

The existing analytic point is 41.8 GB of committed i16 weights, at most
1,660 physical blocks and 3,320 claims. It has a **5.3504-TB** logical first
oracle at rate 1/8. No exporter, artifact, download, implementation or X5
authorization is implied.

Applying the X4d.2 representation ratios:

- canonical ClaimReduce Fp2 W: `8 * 41.8 GB = 334.4 GB`;
- weight-extension evaluation tables before auxiliary padding:
  `16 * 41.8 GB = 668.8 GB`;
- largest `mu=29` four-buffer pool: `4 * 2^29 * 16 =
  34,359,738,368 B`;
- one `mu=25` optional transport shard remains 8 GiB of raw first oracle,
  but sharding changes peak, not the 5.3504-TB logical volume.

The single-A100 fully resident policy is therefore not a viable 20B
deployment. X5 would require deterministic multi-device/source sharding,
streamed canonical-table residency, a central transcript coordinator and
counted NVLink/NCCL/NVMe traffic. The X4d.2 APIs remain keyed by
cohort/slot/source and use a maximum-geometry reusable pool rather than one
monolithic model allocation, so they do not algebraically foreclose that
path. Treating “all canonical tables on one device” as a permanent invariant
would foreclose it and is explicitly not an X5 decision.

Claim-cap pressure is binding: the analytic 3,318.06 expected claims and
3,320 maximum nearly consume the complete cap in one response. The GPT-2
`k=16` settlement policy cannot be projected onto 20B; absent a separately
preregistered X5 profile, settlement is effectively per response.

## 8. Phase-2 gate preregistration (verbatim)

1. FLATNESS: settlement_wall(k=16) <= 1.30 * settlement_wall(k=1), same
   admitted host, unchanged build.
2. PHYSICAL COUNTERS: k=1 and k=16 equal in initial_encoded_symbols_read,
   combined_codeword_symbols, unique physical evaluation/source symbols,
   encoded-oracle pass count, query-gather count. Do NOT require
   equality of response-local ClaimReduce calls or logical work: those
   remain exactly 51*k and must be reported.
3. BYTE IDENTITY: as tested in section 2, permanent.
4. HOT PATH: rerun the existing G1, exact 41,270,464-B response,
   synchronization and interference validators unchanged, with their
   registered predicates verbatim. The historical sync waiver does not
   apply to X4d.2.
5. RESOURCE ADMISSION: fail-closed RAM >=256 GiB, volume >=150 GB,
   admitted A100 profile, device-memory preflight for the measured live
   set. Correct the memory history: 317,413,392,384 B was the pre-fusion
   Phase-1 relation payload; fused X4d.1 reports 28,855,762,944 B
   relation-table CPU payload. Report new total host and device peaks
   (durable bases plus scratch) and rejustify the unchanged 256-GiB
   floor from the complete live set.
6. PROTOCOL REGRESSIONS: all existing suites unchanged.

## 9. Out-of-scope contingency

Only if the completed local decomposition and CPU-backend microbenchmarks
show that the byte-identical path cannot plausibly reach flatness will Phase 1
prepare decision material for a protocol-visible batched reduction: changed
challenge schedule, messages/transcript/codec, correlation domains,
soundness/M12/Lean impact, new tests/gates and projected bytes/walls. It is
not X4d.2 Phase 2 and will not be implemented without a new explicit owner GO
and separately preregistered amendment.

## 10. Phase-1 stop condition

Phase 1 may close only after instrumentation, resident implementation,
append-only deterministic local records, permanent byte-identity and
physical-counter tests, full workspace green, ledger update and resource
appendices. No pod is contacted and no production gate verdict is claimed.
Then: **HARD STOP pending explicit owner GO**.

## 11. Permanent local identity evidence

The Phase-1 local record is
`benchmarks/results/x4d2-phase1-local-identity-2026-07-26-d298370.json`.
It is explicitly non-production (`pod_contacted=false`,
`proof_or_gate_verdict=false`) and binds the immutable X4d.1 input checksums.

Permanent tests cover:

- legacy CPU ClaimReduce versus resident CPU ClaimReduce at `mu=6,9,12`,
  including every round correction, terminal point/value, correlation
  ledger and transcript ledger;
- the exact 51-block production multiplicity scaled to locally practical
  `mu=8,6,4`, sequentially at deterministic `k=1` and `k=16`, including the
  next transcript challenge and physical-census equality;
- resident auxiliary MLE reuse over 16 response iterations;
- fused physical-counter equality at k=1/k=16, source-alias rejection,
  the real two-response authenticated-output fixture, codec round trips,
  tamper/freshness/abort/cap suites and X4c byte-identity suites;
- CUDA differentials for
  `volta_cuda_claim_reduce_f_two_into_device`,
  `volta_cuda_x4d_link_eq_accumulate_device`,
  `volta_cuda_fp2_dot_scaled_pair_into_device` and
  `volta_cuda_fp2_pair_sum_device`.

On this non-CUDA local host, the Rust CUDA feature and dynamic ABI compile
green, the CUDA differential is permanently present but self-skips because
`libvolta_cuda_backend.so` is unavailable, and all CPU-backend resident
orchestration executes. `nvcc` is not installed, so no claim is made that the
new `.cu` translation unit was compiled or executed locally. Phase 2 must run
the same permanent differential with `VOLTA_REQUIRE_CUDA=1` before accepting
any record.

Local verification on 2026-07-26: `cargo test --workspace` green,
`pytest -q tests/test_report.py` green (**22 passed**), CUDA-feature Rust
check green, formatting and `git diff --check` green. The workspace's
pre-existing Clippy warning baseline prevents `-D warnings`; ordinary
Clippy completes successfully. No Lean file or protocol statement changed.
No pod was provisioned or contacted.

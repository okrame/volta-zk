# X4c I/O-lifecycle redesign — Phase 1 record and Phase 2 override

**Status:** Phase 1 is closed at checkpoint
`c7e104324fca41c2192a2e1a16bb58a8153d1ff6`. The product owner has authorized
the direct-fold, GPU-resident-tree, RAM-oracle, gather and arena implementation
locally under the frozen `runpod-a100-x4c-v1` contract. **HARD STOP before any
pod request or contact; pod work requires a separate provisioning approval
after the clean local checkpoint.** The original pre-measurement artifact is
preserved at commit
`61bf1fb0acf6ea693f24b049c6d31393845c7d95`, SHA-256
`7d4f8254b066b91fea9ee52fbef0f0008632adccceef1513d3d3478eeea3a52a`.
Its Section 2.3 incorrectly predeclared the hypothesis as confirmed. The
`c7e1043` revision is the explicit Phase-1 interpretation correction; it
changed no experiment geometry, sampling plan, engineering design, profile,
protocol or gate.
The corrected Phase-1 artifact is preserved at checkpoint `c7e1043`, SHA-256
`1a744625078e3ffe5772b040c24854e9510dcedebc906416279cf3a7c29bf191`;
the present override does not mutate either append-only Phase-1 JSON.

**Phase-2 diagnostic correction (2026-07-23):** after checkpoint `185b177`
failed closed on the final output domains of lengths 32, 16 and 8, the product
owner corrected the production parity control to
`min(64, output_len)` unique coordinates per round.  The exact total is
`24*64 + 32 + 16 + 8 = 1,592` comparisons.  This is exclusively a
diagnostic control, receives zero soundness credit and changes no protocol
parameter, format, root, reference/proof byte or gate.  Local implementation
resumes from `185b177`; the HARD STOP before any pod request or contact
remains.

This package follows the immutable X4 and X4b closures. X4 remains
**G4 commit FAIL / overall FAIL** and X4b remains **official FAIL on isolated
commit and persisted open**. X4c is a new implementation profile, not a
reinterpretation of either verdict.

The implemented protocol remains `x4-zkdeepfold-ud-e29-v4`, rate `1/8`,
`s=111`, response-wide claim union at most 3,320 and one schema-4 packed
opening. No proof field, frame order, N4 preimage, context, Merkle root,
reference byte, correlation count, Lean statement or soundness parameter
changes. The complete PCS remains exactly **2,683,236 B** and the response
exactly **43,953,700 B**. The response-wide bound remains

```text
3320 * (9/16)^111
  + 28,522,064,267,253 / 340282366762482138490186164457219031041
= 80.25537016399041 bits.
```

The only Phase-1 Rust change is out-of-band lifecycle instrumentation. It
does not change a proof or transcript.

## 1. X4b I/O byte reconciliation

### 1.1 Exact `Wext-mu26` counter identity

The selected X4b isolated candidate is
`persisted_response.measured[0]`'s companion isolated run:
**254.861527720 s**. Its own `metrics`, `process_io` and accelerator counters
give the following decimal-byte inventory.

| Category | Bytes | Decimal GB | Direction / role |
| --- | ---: | ---: | --- |
| coefficients | 4,294,967,296 | 4.294967296 | host write; E-NTT input |
| persisted oracle | 34,359,738,368 | 34.359738368 | host write |
| persisted oracle read for N4 | 34,359,738,368 | 34.359738368 | host read |
| staging write | 68,719,476,704 | 68.719476704 | host write |
| staging read | 68,719,476,672 | 68.719476672 | host read |
| root | 32 | 0.000000032 | host write |
| **modeled host reads** | **103,079,215,040** | **103.079215040** | oracle + staging |
| **modeled host writes** | **107,374,182,400** | **107.374182400** | coefficients + oracle + staging + root |
| **modeled physical I/O** | **210,453,397,440** | **210.453397440** | read + write |
| observed `process_io.read_bytes` | 103,079,235,584 | 103.079235584 | kernel counter |
| observed `process_io.write_bytes` | 107,374,211,072 | 107.374211072 | kernel counter |
| **observed physical I/O** | **210,453,446,656** | **210.453446656** | kernel read + write |

The modeled and observed inventories differ by exactly **49,216 B**. No cause
is assigned to those unmodeled bytes. The recorded aggregate rate is
**825,756,043.051 B/s = 0.825756043 GB/s**, but it is itself
`210,453,446,656 B / 254.861527720 s`. Applying that rate to the modeled
inventory reconstructs **254.861468119 s**, only **0.000059601 s** below the
measured wall.

The accelerator layer moved essentially the same amount again:
**107,374,217,152 B H2D** and **103,079,215,072 B D2H**, or
**210,453,432,224 B** of PCIe traffic. PCIe bytes are reported separately
and are not added to the physical-host-I/O denominator because the two layers
carry overlapping payloads.

This is an exact and valuable byte reconciliation, not an independent causal
timing model. The **0.000059601-s** residual is the algebraic identity
`254.861527720 s * 49,216 / 210,453,446,656`, because the rate was derived
from the same wall. No per-category coefficient or intercept was optimized,
but the reconstruction is not evidence that all wall time was I/O. Causal
attribution requires independent phase timers plus storage and ownership
anchors.

### 1.2 The seven redundant response-fold steps

For every one of the 27 response fold rounds, the current production path is:

1. **Re-copy coefficients.**
   `rust/volta-pcs/src/x4/folding_v4.rs:453-459` clones
   `current_coefficients` into a one-slot `Vec`, after which
   `rust/volta-pcs/src/x4/cuda_v4.rs:373` serializes it to a coefficient file.
2. **Run a redundant E-NTT.**
   `rust/volta-pcs/src/x4/cuda_v4.rs:374` calls `x4b_ntt_fp2` even though the
   caller already holds the corresponding folded codeword.
3. **Write coefficients and the complete oracle.**
   `rust/volta-pcs/src/x4/cuda_v4.rs:373-375,414-426` writes, flushes,
   `sync_data`s and applies `FADV_DONTNEED` to both files.
4. **Build Merkle through staging files.**
   `rust/volta-pcs/src/x4/cuda_v4.rs:438-538` rereads oracle tiles and writes
   level zero; `rust/volta-pcs/src/x4/cuda_v4.rs:540-631` reads and writes
   every outer level through temporary files.
5. **Reread and compare the full oracle.**
   `rust/volta-pcs/src/x4/folding_v4.rs:467-469` invokes
   `verify_persisted_oracle_matches_v4`; its full chunked comparison is
   `rust/volta-pcs/src/x4/cuda_v4.rs:269-330`.
6. **Copy the result back into CPU-owned structures.**
   `rust/volta-pcs/src/x4/folding_v4.rs:470-474` transfers ownership of the
   outer cache and clones the already-known codeword into `CohortTreeV4`.
7. **Clean up response-local files.**
   Staging levels are removed at
   `rust/volta-pcs/src/x4/cuda_v4.rs:626,631`; coefficients, oracle and root
   are removed at `rust/volta-pcs/src/x4/folding_v4.rs:475-481` during seal.
   Residual response directories are removed by the recorder only after open
   and verification.

Across all 27 rounds, the X4b record counts:

| Response-fold category | Bytes |
| --- | ---: |
| coefficient files | 2,147,483,632 |
| oracle files | 17,179,869,056 |
| full-oracle comparison reads | 17,179,869,056 |
| staging reads | 68,719,474,496 |
| staging writes | 68,719,475,360 |
| H2D | 88,046,836,500 |
| D2H | 85,899,344,416 |

The staging files alone therefore impose
**137,438,949,856 B = 137.438949856 GB per response** of avoidable host I/O.

### 1.3 `current_codeword` is already available

The claim is confirmed directly. The fold loop computes
`current_codeword = fold_codeword(...)` at
`rust/volta-pcs/src/x4/folding_v4.rs:696-697`, adds any newly activated
same-domain codeword at lines 699-706, and passes the finished slice to
`commit_round` at line 734. The X4b committer does not use this slice to build
the commitment; it constructs the oracle from the coefficient clone and uses
`codeword` only for the later full comparison and CPU clone. Direct folding
therefore removes redundant work rather than introducing a new algebraic
path.

### 1.4 Storage-incident consequence

The two `mfs` attempts each failed with EIO after the exact
**4,294,967,296-B coefficient + 34,359,738,368-B oracle** positions, despite
the first incident's smaller 4-GiB probe succeeding. The required
38,654,705,664-B `fdatasync` probe later passed only after moving to local
overlay storage. A subsequent complete run was invalidated by a missing
companion binary after more than 5,299 s and 86,567,288,992 B had been
materialized. X4c consequently has no response-path staging or overlay
oracle. The exact **9,618,587,808-B** coefficient-plus-five-root durable tier
stays on the provider **PERSISTENT** volume; separate local non-`mfs` storage
is reserved for scratch, RAM-spill and append-only records. The harness fails
closed on all companions before onboarding.

## 2. Opening lifecycle decomposition

### 2.1 Four timers and exact boundaries

`SealedGlobalChainV4::issue_queries` now records host monotonic wall
nanoseconds for:

1. `query_gather`: exact-draw validation and construction of the canonical
   verifier-owned opening schedule;
2. `hashing_path_assembly`: every source/tree opening call, including queried
   symbol and cached-digest reads, inner-tree rebuild/hashing, and ordered
   sibling-path assembly;
3. `encode_serialize`: opening-schedule digest, packed-opening structural
   validation and one canonical packed-frame encode; and
4. `teardown`: explicit destruction of all residual sealed round trees,
   prover groups, common point, fold challenges and the query schedule before
   `issue_queries` returns.

It also records the total call wall, exact sealed fold-codeword/cache bytes,
tree count and retained outer-level-vector count. These are metrics only.

### 2.2 X4b production counter decomposition

The opening record's `persisted_oracle_bytes_read` is cumulative across seal
and issue. The issue-only delta is exact:

```text
76,949,425,792
  - (4,809,293,824 initial_encoded_symbols_read * 16 B)
= 724,608 B.
```

The issue additionally reads **507,008 B** of outer cache and rebuilds
**2,220** small inner trees. In contrast, the consumed sealed state owns:

```text
fold codewords       17,179,869,056 B
fold outer cache   + 34,359,737,248 B
                    ----------------
sealed state         51,539,606,304 B
```

Because `issue_queries(self, ...)` consumes `self`, Rust destroys those
round-tree allocations before returning to the recorder's `open_wall_s`
timer. The sealed `CohortTreeV4` owns ordinary CPU `Vec` codewords and
`DenseOuterNodeCacheV4`; it does not own the CUDA backend.
`backend.finish_measurement` completes before the recorder starts
`open_wall_s`. Response-fold files have already been removed during seal, and
residual directories are removed only after open and verification.

The pre-existing same-pod-host exact-geometry full-cache preflight, which
performs more query work but owns no production sealed state, selected
**0.109631491 s**. Subtracting that conservative anchor from
**6.683486611 s** leaves a **6.573855120-s**, or **98.359666%**,
lifecycle-associated gap. The subtraction does not identify its cause.

Pinned-host deregistration and opening-window unlink/writeback are
**RETRACTED AS PROPOSED CULPRITS**. Phase-2 instrumentation retains
pinned/device/file ownership and unlink/writeback as zero-expected controls;
absence is recorded as exact zero, while a nonzero observation is evidence.
The production-host cause is **OPEN**, and no redesign element may depend on a
specific diagnosis.

### 2.3 Local synthetic result and pod-scale projection

The clean Phase-1 record runs one warm-up plus five measured candidates at
outer-domain logs 16, 18, 20 and 22. Each candidate builds the real CPU
schema-4 fold chain, emits and verifies the real 111-query packed opening,
uses the production one-shot ownership boundary and records allocator
counters. The exact state formula is:

```text
codeword bytes = (2^mu - 8) * 16
cache bytes    = (2^mu - 8 - (mu - 3)) * 32.
```

The analytic projection takes the largest synthetic scale's selected
teardown nanoseconds per exact sealed-state byte and multiplies by
**51,539,606,304 B**. It uses no regression and no fitted intercept:

```text
projected teardown
  = upper_median(local mu22 teardown)
      * 51,539,606,304 / exact_local_mu22_sealed_bytes.
```

Candidate timers, upper medians, allocator counts, the direct projection and
its min/max-candidate sensitivity interval land only in an append-only clean
Phase-1 JSON and the ledger. No regression, fitted intercept, rate chosen
after measurement or pod result is permitted.

The first local JSON from source `61bf1fb0acf6ea693f24b049c6d31393845c7d95`
is retained append-only, but is ineligible for Phase-1 closure because its
generator copied the predeclared `CONFIRMED` conclusion into the record before
examining the projection. The corrected rerun keeps every experimental input
unchanged and applies this explicit rule:

- “dominant” means more than 50% of the **6.573855120-s** implied lifecycle
  debt;
- `REFUTED` when even the largest of the five direct byte-scaled `mu22`
  teardown candidates is below that threshold;
- `CONFIRMED` when even the smallest candidate is above it; and
- `INCONCLUSIVE` otherwise.

The conclusion applies only to the stated local synthetic evidence plus the
analytic byte projection. Even a refutation of ordinary container-drop
dominance does not erase the measured same-host lifecycle gap or identify its
cause. Phase 2 must report independent production-host phase timers, process
I/O and storage anchors, faults/RSS/smaps/NUMA/allocator state,
pinned/device/ordinary-host ownership, outstanding synchronization and
sealed-state files/mappings rather than promote the projection. Missing or
inconsistent ownership is a validator failure.

## 3. Byte-identical X4c redesign

### 3.1 Direct fold of the existing codeword

The production fold committer accepts the already-computed
`current_codeword`. It performs **zero response-round E-NTTs**, creates
**zero response-round coefficient files**, and performs **zero full-oracle
comparison reads**. `current_coefficients` remains available for the frozen
claim-line calculation, but it is never serialized as a response artifact.
The existing `fold_codeword` formula, challenge order, activation schedule,
N4 frames and root construction remain unchanged.

Correctness no longer depends on a full production reread:

- Permanent full CPU/GPU direct-fold tests cover lengths
  `2^3, 2^8, 2^12, 2^16, 2^20` and challenges
  `0`, `1`, `Fp2(3,11)` and `Fp2(p-1,p-2)`. Every output symbol must be
  bit-identical.
- Each production response checks **`min(64, output_len)` unique output
  coordinates in each of 27 rounds**: indices `0` and `output_len-1` when
  distinct, plus unique indices up to the round target from BLAKE3 XOF context
  `volta-zk/x4c/direct-fold-parity/v1`. The XOF absorbs the X4c design SHA,
  clean source SHA, response ordinal, round number, fold challenge and fixed
  round root. Power-of-two masking is exact; duplicates are redrawn.
- The CPU recomputes each selected output from its two input symbols and the
  frozen `fold_codeword` equation. All **1,592** comparisons must match.
  The record includes the seed material, ordered-index digest, comparison
  count and zero mismatch count. Sampling affects no transcript and receives
  no soundness credit.
- The production diagnostic traffic is accounted separately from proof
  opening traffic: exactly **53 gathers**, **4,648 Fp2 symbols**,
  **37,184 B index H2D** and **74,368 B value D2H**. These bytes are
  out-of-band parity observations, never proof bytes and never soundness
  evidence; `noncanonical_opening_d2h_bytes` remains hard zero.

A mismatch fails closed before query gathering. Synthetic full comparisons
and production samples supplement, rather than replace, the existing
CPU/GPU root gates.

### 3.2 GPU-resident fold trees, no staging

All response-local fold codewords and retained outer nodes live in one GPU
arena through root fixation and query gathering. Merkle construction is
in-place and writes no staging file. The bottom outer-internal level is
omitted and rebuilt in the batched query kernel from resident codewords, the
already validated byte-identical policy used by X4b's one-level cache mode.

The exact retained payload is:

```text
all fold codewords                         17,179,869,056 B
one-level-omitted fold outer cache       + 17,179,868,192 B
                                            ----------------
retained GPU payload                       34,359,737,248 B
allowed in-place NTT/Merkle/query scratch +  9,126,808,800 B
                                            ----------------
preregistered live anchor                  43,486,546,048 B
```

The **43,486,546,048-B** anchor is the measured X4b device peak. An A100
80-GiB device exposes 85,899,345,920 B, leaving 42,412,799,872 B beyond that
anchor. Phase 2 nevertheless measures actual peak live arena plus runtime
allocations and fails closed on capacity; nominal fit is not a measured X4c
result.

The hard response gate is:

```text
staging files created == 0
staging bytes read == 0
staging bytes written == 0.
```

No disk fallback, paging, hidden CPU tree copy or late full-oracle comparison
is record-eligible.

### 3.3 Host-RAM-resident initial oracle and restart semantics

The initial padded oracle (**76,948,701,184 B**) and derived initial outer
cache (**37,094,424,416 B**) are rebuildable host-RAM session caches.
Coefficients plus five roots are the complete durable tier:
**9,618,587,808 B**. The durable tier contains no oracle or derived node
file and resides on the provider **PERSISTENT** volume.

Onboarding streams pinned host tiles to the GPU, produces the initial oracle
and tree, and retains the oracle/cache in RAM. The response path performs no
overlay reread and no `FADV_DONTNEED` on these caches. Pinned transfer buffers
are registered into a reusable pool and reused across responses; they are
never registered or deregistered per response. Every H2D tile, pool
registration/deregistration and ownership transition is counted. This pooling
is prospective X4c lifecycle engineering, not a claimed explanation of the
old X4b opening gap.

The concrete pool has four allocations: a two-entry transfer ring, one
canonical-opening mailbox and one canonical-gather operation table. Its exact
requested ownership is **1,090,741,982 B**. Every transfer-ring slot carries
an independent completion event and cannot be rewritten while its preceding
H2D is outstanding. At the explicit session boundary all four buffers are
awaited and returned together; the allocator census must return exactly to
the pre-pool active-allocation and active-byte baseline.

Restart is fail-closed:

1. validate durable coefficient/root file count, length, binding and digest;
2. rebuild the RAM oracle and initial outer cache from coefficients only;
3. compare all five reconstructed roots byte-for-byte with the durable roots;
4. run the registered fixed challenge/query equivalence fixture once from
   the warm materialization and once after a fresh-process durable-only
   rebuild; roots, fold frames and the canonical packed opening must be
   byte-identical; and
5. admit no live response until the rebuild-equivalence gate passes.

An interrupted rebuild discards only partial RAM state and restarts from the
unchanged durable tier. A root or opening mismatch refuses service. Onboarding
wall and all bytes are offline counters, never hidden in an online response.

The named **REBUILD-EQUIVALENCE** gate requires five equal roots, identical
canonical fold/opening bytes, the unchanged codec digest, exact
**2,683,236-B PCS / 43,953,700-B response**, and zero durable-oracle bytes.

### 3.4 One batched GPU query gather

Only after all 27 roots are fixed does one kernel batch gather all 111
projected query paths from resident fold trees. Missing bottom-level nodes
are rebuilt in that batch. Initial queried symbols and outer nodes come from
host RAM through counted pinned transfers, never storage. Only the final
approximately 2.6-MB canonical opening crosses from device to host. The
record reports logical symbols/digests, H2D/D2H, kernel launches,
synchronizations and allocator bytes separately.

### 3.5 Single arena and accounted teardown

The sealed response state uses one explicitly sized arena instead of
distributed per-round `Vec`/`BTreeSet` ownership. The final opening is copied
to its host proof buffer, establishing `proof_ready_wall`; arena reset,
zeroing and return of the already-registered pinned buffers to their reusable
pool occur afterward. Pool deregistration is not a per-response operation.

Both walls are mandatory:

- `proof_ready_wall`: first post-line verifier challenge through complete
  canonical proof bytes available to the caller;
- `session_reusable_wall`: the same start through all teardown and allocator
  state restored for another response.

The record includes arena reserved/committed/peak bytes, allocation,
reallocation, deallocation, reset, zeroed-byte and outstanding-allocation
counters at both boundaries. `proof_ready_wall` may exclude teardown;
`session_reusable_wall` may not. Thousands of distributed vector/set drops
are a named anti-pattern and a failing allocation-census condition, not an
acceptable way to make proof-ready latency look smaller.

Reset covers and reports the complete **43,486,546,048-B** arena, including
the registered scratch/workspace region, and is synchronized before the
session-reusable boundary. A partial payload-only zero, a hidden outstanding
operation or failure to restore the single cached arena ownership is a hard
validator failure.

## 4. Gate restructure: strictness moved, not relaxed

This is one owner-approved reclassification and is recorded as
**strictness MOVED, not relaxed**.

### 4.1 Offline model onboarding

Initial commitment is **OFFLINE MODEL ONBOARDING**, following the existing
precedent that the static Ligero weight commitment was outside per-response
comparisons. On the first `runpod-a100-x4c-v1` tier run, these are informative
baselines with complete counters:

- isolated `Wext-mu26` onboarding wall and throughput;
- complete five-cohort full-pass wall and aggregate oracle B/s;
- durable bytes, RAM-cache bytes, H2D/D2H, RSS, VRAM, page-cache and scratch;
- CPU/GPU roots, durable-only rebuild equivalence and exact bytes.

There is no v1 onboarding wall ceiling. Correctness and capacity remain hard:
root equality, rebuild equivalence, exact durable/communication bytes, zero
staging on the response path and hardware preflight.

### 4.2 Online PCS block

The new online block is **seal + issue-queries + final serialization** and
reports both lifecycle walls. `runpod-a100-x4c-v1` establishes an informative
first-tier baseline; the hard ceiling is pinned in
`runpod-a100-x4c-v2` only after the measured v1 values land, matching the
fase-D baseline-then-pin precedent.

The issue/open suboperation remains hard at **<=1.50 s**, and verification
remains hard at **<=0.25 s**. Exact PCS/response bytes and all correctness
gates remain hard. Thus no failed X4/X4b ceiling is relabeled or silently
discarded: response strictness moves to the complete online lifecycle, while
the already-online open/verify ceilings stay in force.

### 4.3 Projections, never results

The first-tier planning envelope is:

| Projection | Derivation | Planning range |
| --- | --- | ---: |
| isolated `mu26` onboarding | 34.36 GB direct encode/tree at 6–8 GB/s, with no 210.45-GB host-I/O cycle | about 5 s |
| complete onboarding pass | 76.95 GB / 0.855–1.282 GB/s effective full-pass throughput | about 60–90 s |
| response seal | 51.54 GB logical fold payload processed at 8.6–17.2 GB/s | about 3–6 s |
| issue/open | 0.1096-s same-host no-teardown anchor plus batched GPU gather/2.6-MB copy envelope | about 0.1–0.5 s |
| reusable response session | about 5 s non-PCS response work + seal/open/teardown envelope | about 9–11 s |

These ranges select provisioning and test duration only. They are not gate
verdicts, speedup claims or substitutes for the v1 record.

## 5. Historical rate decision material — inactive in Phase 2

The implemented path remains exactly rate `1/8`, `s=111`. No rate
contingency, alternate codec/reference, Lean constant or profile is authorized
in Phase 2. The unchanged table below is retained as historical Phase-1
decision material only.

Under the same strict unique-decoding analysis, 3,320-response union and
unchanged aggregate ClaimReduce/LinkBad/ZeroBatch term
`28,522,064,267,253 / |E|`, the decision table is:

| Rate | Query count | Exact expression | Bits | Slack above 78.809294874 | Preliminary resource/bytes |
| --- | ---: | --- | ---: | ---: | --- |
| `1/4` | 136 | `3320*(5/8)^136 + C/|E|` | **80.32497833580102** | **1.51568346180102** | about one-half the `1/8` oracle; PCS about 3.2–3.3 MB |
| `1/2` | 219 | `3320*(3/4)^219 + C/|E|` | **79.11483983122474** | **0.30554495722474** | **REJECTED** by the soundness-slack rule |
| `1/2` | 224 | `3320*(3/4)^224 + C/|E|` | **80.95573450952145** | **2.14643963552145** | about one-quarter the `1/8` oracle; response about 46–47 MB, +5–7% |

Here `C=28,522,064,267,253`; it retains the existing LinkBad ownership.
The byte ranges are preliminary until an exact codec preflight accounts for
query-index deduplication and changed path depths.

The table receives no implementation, codec-preflight, projection-gate or
fallback credit in this phase. Any future activation requires a separately
authorized phase and product-owner **GO**, logged as a deliberate exception to
the 2026-07-06 cost-trade convention because it buys prover/storage resources
with response bytes. It would then require new Lean constant discharge, exact
codec preflight, full CPU/GPU correctness, leakage and tamper reruns, and a
complete clean rebaseline.

Padding/re-binning, Merkle arity/leaf grouping, MXFP4-direct commitment and
multi-mask batteries remain exclusively in the X5 oracle-scale addendum.

## 6. Frozen `runpod-a100-x4c-v1`

Hardware and execution profile:

- exactly an **A100-SXM4 80 GB** selected backend;
- actual `/proc/meminfo` host RAM
  **>=256 GiB = 274,877,906,944 B**, checked before allocation and failed
  closed if undersized;
- a provider **PERSISTENT** volume holding the exact **9,618,587,808-B**
  coefficient-plus-five-root durable tier;
- separate local non-`mfs` storage **>=150,000,000,000 B** for scratch,
  RAM-spill and append-only records;
- wall-only timing plus complete counters; no CUDA-event gate timing;
- proving path `RAYON_NUM_THREADS=8` for historical comparability;
- commit/onboarding, seal and open paths use their own unpinned worker policy,
  reported with actual worker count and affinity; no hidden inheritance of
  the proving-path cap; and
- R1b NOTE-6 `c3_weights_two_weight_set_leakage_smoke` is the first
  production-size execution.

Record order:

1. clean source/reference/design pins and companion fail-closure;
2. RAM/GPU/volume/local-filesystem preflight;
3. NOTE-6 first;
4. permanent synthetic direct-fold and CPU/GPU N4/root gates;
5. offline onboarding baselines and all five root checks;
6. durable-only fresh-process rebuild-equivalence;
7. online PCS candidates with direct-fold samples, zero staging, exact
   communication, both lifecycle walls and allocator census;
8. persisted issue/open hard gate and verify hard gate; and
9. append-only record validation and verbatim verdicts.

The first tier records one warm-up and at least three measured candidates for
each wall block. Candidate selection is upper median. No omitted counter,
unavailable timer, staging byte, RAM/profile shortfall or mismatch is rounded
into a pass.

R1c scope is extended to the direct-fold CPU/GPU parity boundary,
one-level-omitted GPU tree reconstruction, GPU arena ownership and teardown,
pinned RAM-oracle lifecycle, durable-only restart equivalence, batched query
gather and every new traffic/allocator counter, in addition to the already
pinned v3/v4 seam, draw-before-validation episode and X4b CPU/CUDA/persistence
surface.

## HARD STOP

Phase 2 is authorized locally for the causal instrumentation and Sections
3.1–3.5 at fixed rate `1/8`, `s=111`. Do not activate any rate contingency or
begin X5/R1c. After format/check, full workspace and validator tests,
direct-fold/root/rebuild byte identity, unchanged tamper coverage, exact
communication, ledger update and a clean checkpoint, stop and request
separate provisioning approval. Do not request or contact an existing or new
pod before that local hard stop; do not contact a pod until provisioning is
separately approved. The owner correction at the top resolves only the
diagnostic sampling geometry and resumes local implementation; it does not
clear this pre-pod stop or authorize provisioning.

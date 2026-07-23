# X4c Phase-1 closure — exact I/O bytes and lifecycle gap

**Verdict:** Phase 1 completed at checkpoint
`c7e104324fca41c2192a2e1a16bb58a8153d1ff6` and was hard-stopped before the
X4c production implementation or any pod access. The later product-owner
ruling authorizes Phase-2 implementation locally only, with a second hard stop
before any pod request or contact. The modeled and observed I/O inventories
reconcile to an exact **49,216-B** difference. The reconstructed
**0.000059601-s** wall residual is not independent causal evidence because its
aggregate rate is derived from the same measured wall; it does not prove that
all wall time was I/O. The local synthetic experiment narrowly
**refutes ordinary sealed-state container destruction as the dominant cause
under the registered local direct projection**. The production-host cause of
the **6.573855120-s** lifecycle-associated gap remains **OPEN**.

The eligible append-only record is
`benchmarks/results/x4c-phase1-open-decomposition-2026-07-23-f772013.json`,
SHA-256
`ca9841ffce22f731dd45ba616e482a4528ae9ce934856965b0782ed3e052ebcf`.
It was generated from clean source
`f77201398c6093afff6dd12124b43d0641e694fd`, has `git_dirty:false` and
`pod_contacted:false`, and passes
`scripts/report.py --validate-x4c-phase1`.

The earlier clean schema-1 record is retained unchanged as diagnostic
evidence. Its predeclared `CONFIRMED` field makes it ineligible; the incident
and correction are recorded in the ledger. The Phase-1 corrected design
artifact at checkpoint `c7e1043` is `docs/x4c-io-lifecycle-design.md`,
SHA-256
`1a744625078e3ffe5772b040c24854e9510dcedebc906416279cf3a7c29bf191`.
The current document adds the approved Phase-2 terminology, ownership and
profile override; it does not mutate either raw record. The original
pre-measurement artifact remains recoverable at commit
`61bf1fb0acf6ea693f24b049c6d31393845c7d95`.

## 1. Frozen protocol surface

Nothing in Phase 1 changes the implemented schema-4 proof, field order, N4
preimage/context, root, reference bytes, rate, query count, claim union,
correlations, Lean statements or soundness expression. The profile remains
`x4-zkdeepfold-ud-e29-v4`, rate `1/8`, `s=111`, with:

- PCS: exactly **2,683,236 B**;
- response: exactly **43,953,700 B**; and
- response soundness:
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`
  = **80.25537016399041 bits**.

The only implemented Phase-1 change is out-of-band timing, sealed-state and
allocator instrumentation around `issue_queries`.

## 2. Exact I/O byte reconciliation

The selected X4b `Wext-mu26` wall is **254.861527720 s**. Its own counters
give:

| Category | Bytes |
| --- | ---: |
| coefficient write | 4,294,967,296 |
| oracle write | 34,359,738,368 |
| oracle reread for N4 | 34,359,738,368 |
| staging read | 68,719,476,672 |
| staging write | 68,719,476,704 |
| root write | 32 |
| **modeled host read** | **103,079,215,040** |
| **modeled host write** | **107,374,182,400** |
| **modeled physical host I/O** | **210,453,397,440** |
| observed process read | 103,079,235,584 |
| observed process write | 107,374,211,072 |
| **observed physical host I/O** | **210,453,446,656** |

The modeled/observed difference is exactly **49,216 B**. The recorded
aggregate rate is **825,756,043.051 B/s = 0.825756043 GB/s**, but that rate is
itself `210,453,446,656 B / 254.861527720 s`. Applying it to the modeled byte
inventory yields **254.861468119 s**, and the **0.000059601-s** residual is
therefore the algebraic identity
`254.861527720 s * 49,216 / 210,453,446,656`. It is not an independent phase
timer, causal model or proof that the complete wall was I/O. The useful result
is the exact byte reconciliation; causal attribution requires independent
phase walls and storage/ownership anchors. No category coefficient or
intercept was fitted.

The overlapping accelerator transport layer reports
**107,374,217,152 B H2D** and **103,079,215,072 B D2H**. It is reported
separately rather than double-counted into physical host I/O.

The complete-pass per-cohort G6 byte counters were also checked. Coefficient
read equals coefficient persistence, oracle persistence equals the N4 oracle
reread, and every cohort has a 32-B root:

| Cohort | Coefficients | Oracle / N4 reread | Staging read / write | H2D / D2H | Retained cache | Persistent artifacts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `Wext-mu26` | 4,294,967,296 | 34,359,738,368 | 68,719,476,672 / 68,719,476,704 | 107,374,217,152 / 103,079,215,072 | 34,359,738,336 | 38,654,705,696 |
| `Wext-mu22` | 4,831,838,208 | 38,654,705,664 | 4,294,967,232 / 4,294,967,264 | 47,782,625,216 / 42,949,672,928 | 2,147,483,616 | 43,486,543,904 |
| `Wext-mu20` | 436,207,616 | 3,489,660,928 | 1,073,741,760 / 1,073,741,792 | 4,999,627,712 / 4,563,402,720 | 536,870,880 | 3,925,868,576 |
| `auxiliary-ell17` | 4,194,304 | 33,554,432 | 67,108,800 / 67,108,832 | 104,857,604 / 100,663,264 | 33,554,400 | 37,748,768 |
| `auxiliary-ell16` | 51,380,224 | 411,041,792 | 33,554,368 / 33,554,400 | 495,985,088 / 444,596,192 | 16,777,184 | 462,422,048 |
| **total** | **9,618,587,648** | **76,948,701,184** | **74,188,848,832 / 74,188,848,992** | **160,757,312,772 / 151,137,550,176** | **37,094,424,416** | **86,567,288,992** |

The remaining per-cohort G6 counters also reconcile:

| Cohort | Peak staging | Device-zeroed | Maximum N4 tile | `DONTNEED` bytes / calls | NTT / inner / outer calls |
| --- | ---: | ---: | ---: | ---: | ---: |
| `Wext-mu26` | 51,539,607,552 | 30,064,771,072 | 402,653,312 | 141,733,920,768 / 35 | 2 / 512 / 277 |
| `Wext-mu22` | 3,221,225,472 | 33,822,867,456 | 482,347,264 | 86,436,216,832 / 31 | 36 / 512 / 37 |
| `Wext-mu20` | 805,306,368 | 3,053,453,312 | 528,482,976 | 8,489,271,296 / 29 | 13 / 32 / 25 |
| `auxiliary-ell17` | 50,331,648 | 29,360,128 | 167,772,356 | 138,412,032 / 25 | 2 / 1 / 20 |
| `auxiliary-ell16` | 25,165,824 | 359,661,568 | 509,610,240 | 907,018,240 / 24 | 49 / 4 / 19 |
| **total / max** | **51,539,607,552** | **67,330,113,536** | **528,482,976** | **237,704,839,168 / 144** | **102 / 1,061 / 378** |

The seven redundant steps and their current file/line owners are pinned in
the design: coefficient recopy, redundant per-round E-NTT, coefficient and
oracle persistence, staging-file Merkle construction, full-oracle comparison,
copy-back into CPU structures and temporary cleanup. Across all 27 folds,
staging alone is **68,719,474,496 B read + 68,719,475,360 B written =
137,438,949,856 B** of avoidable response I/O.

`fold_codeword` already produces `current_codeword` at
`rust/volta-pcs/src/x4/folding_v4.rs:696-697`, applies same-domain activation
at lines 699-706, and passes it to `commit_round` at line 734. The current
committer nevertheless rebuilds the codeword from copied coefficients and
uses the available slice only for comparison and a CPU clone.

## 3. Opening decomposition

The X4b record's cumulative oracle reads minus its seal reads leave only
**724,608 B** read by `issue_queries`. It also reads **507,008 B** from the
outer cache and rebuilds **2,220** small inner trees. The consumed sealed
state is much larger:

| Sealed state | Bytes |
| --- | ---: |
| fold codewords | 17,179,869,056 |
| fold outer cache | 34,359,737,248 |
| **total** | **51,539,606,304** |

The same X4b pod host's exact-geometry, no-production-sealed-state preflight
was **0.109631491 s**. The difference from **6.683486611 s** is
**6.573855120 s**, or **98.359666%**, so a large lifecycle-associated gap is
real. That subtraction alone does not identify its cause.

Code-level ownership and timing retract two earlier proposed culprits:

- `backend.finish_measurement` completes before the recorder starts
  `open_wall_s`;
- the sealed `CohortTreeV4` owns ordinary CPU `Vec` codewords and
  `DenseOuterNodeCacheV4`, not the CUDA backend;
- response-fold coefficient, oracle and root files are removed during seal;
  and
- residual response directories are removed only after open and verification.

Pinned-host deregistration and opening-window unlink/writeback are therefore
**RETRACTED AS PROPOSED CULPRITS**. Phase-2 instrumentation retains them as
zero-expected ownership/timing controls and must record exact zero when they
are absent. A nonzero counter is evidence, not a permitted assumption. The
production-host cause remains **OPEN**, and no X4c design element depends on a
particular diagnosis.

## 3.1 Phase-2 diagnostic correction

Checkpoint `185b177` failed closed when the then-written 64-per-round
diagnostic reached production fold outputs of lengths 32, 16 and 8.  The
product owner corrected the control to **`min(64, output_len)` unique
coordinates per round**, giving exactly **1,592** comparisons.  The
correction is exclusively diagnostic, receives zero soundness credit and
changes no protocol parameter, format, root, byte or gate.  It does not
reinterpret the Phase-1 record or alter its narrow
`REFUTED_LOCAL_SYNTHETIC_DIRECT_PROJECTION` disposition.  Local Phase-2 work
resumes from `185b177`; no pod was requested or contacted.

The corrected clean local run used a real schema-4 fold chain, one warm-up
and five measured candidates at each scale, 111 queries, canonical encoding
and full verification. Upper-median walls were:

| Domain | Exact sealed state | Query gather | Hash/path | Encode/serialize | Teardown | Total |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `mu16` | 3,144,928 B | 0.000667 ms | 1.959272 ms | 0.729217 ms | 0.004750 ms | 2.709197 ms |
| `mu18` | 12,582,048 B | 0.001084 ms | 2.988284 ms | 0.973303 ms | 0.006375 ms | 3.980963 ms |
| `mu20` | 50,330,720 B | 0.001500 ms | 4.531635 ms | 1.298015 ms | 0.009875 ms | 5.828608 ms |
| `mu22` | 201,325,600 B | 0.001584 ms | 6.110778 ms | 1.610060 ms | 0.150377 ms | 7.861006 ms |

At `mu22`, each candidate accounted for **17,604 allocations, 332
reallocations, 17,877 deallocations and 209,494,985 cumulative deallocated
bytes**. Every opening verified and exact state accounting passed.

The preregistered direct byte scale is
`51,539,606,304 / 201,325,600 = 256.00125520053086`. It gives:

- selected teardown projection: **0.03849670075329023 s**;
- five-candidate interval:
  **0.0035200172590072994–0.06874760107657137 s**;
- selected share of the 6.573855120-s gap: **0.585603121%**; and
- high-end share of that gap: **1.045772987%**.

Even the high endpoint is far below the explicit
**3.286927560-s** dominance threshold. The Phase-1 disposition is therefore:

> **REFUTED_LOCAL_SYNTHETIC_DIRECT_PROJECTION**

This refutes the proposed ordinary `Vec`/tree container-drop explanation
under the required local experiment and no-fit byte projection. It does not
turn the projection into an A100-host result or identify the production cause.
Phase 2 must independently time and anchor NUMA placement, faults, page
reclaim, allocator mappings, pinned/device/ordinary-host ownership,
outstanding synchronization and sealed-state files/mappings. File-backed and
pinned-memory controls are expected to be zero at the opening boundary under
the ownership analysis above; discovery otherwise is measured evidence.

## 4. Byte-identical redesign preregistration

The explicit Phase-2 ruling now authorizes this implementation locally, under
the second hard stop before pod provisioning or contact:

1. Fold the already-encoded codeword directly. The response path performs
   zero per-round E-NTTs, writes zero coefficient files and performs zero
   full-oracle comparisons. Permanent CPU/GPU parity tests are full at
   synthetic scale. Production checks exactly `min(64, output_len)` unique
   coordinates in each of 27 rounds, **1,592 comparisons**, under domain
   `volta-zk/x4c/direct-fold-parity/v1`; they receive no soundness credit.
2. Keep fold trees in one GPU arena with one outer level omitted and
   reconstructed in place. Retained codewords plus cache are
   **34,359,737,248 B**; with the registered **9,126,808,800-B** workspace,
   the envelope is the already observed **43,486,546,048-B** device peak,
   within an A100 80-GB device. Response coefficient files, oracle files,
   staging files, reads and writes are hard-zero counters. There is no CPU
   tree clone; exact root equality, arena capacity and all scratch/runtime
   allocations are counted.
3. Keep the initial **76,948,701,184-B** oracle and
   **37,094,424,416-B** outer cache in host RAM. Durable storage remains only
   coefficients plus five roots, **9,618,587,808 B**, on the provider
   **PERSISTENT** volume. A fresh process must rebuild from that tier,
   reproduce all five roots and emit the registered byte-identical opening
   before serving a response. Response-path overlay rereads and
   `FADV_DONTNEED` are forbidden. Pinned transfer buffers are registered as a
   reusable pool and reused across responses, never registered/deregistered
   per response. Pooling is prospective X4c lifecycle engineering, not an
   explanation of the old X4b gap.
4. After all roots are fixed, gather all 111 query paths in one GPU batch.
   Only the final approximately 2.6-MB canonical opening crosses to host.
5. Replace distributed sealed-state ownership with a single arena. Report
   both `proof_ready_wall` and teardown-inclusive `session_reusable_wall`,
   plus allocator state at each boundary. Teardown may move off proof-ready
   latency, but never out of accounting.

## 5. Gate restructure and projections

The recorded owner decision moves strictness; it does not relax it:

- initial commit becomes **OFFLINE MODEL ONBOARDING**, following the static
  Ligero precedent;
- v1 onboarding/full-pass throughput and storage walls are informative, but
  CPU/GPU root equality, rebuild equivalence, exact bytes, zero staging and
  hardware capacity remain hard;
- the new online PCS block is seal + issue-queries + serialization and
  reports both walls; v1 establishes the informative baseline and profile v2
  pins its ceiling from those measurements; and
- persisted issue/open **<=1.50 s**, verify **<=0.25 s**, exact PCS/response
  bytes and all correctness gates remain hard.

Provisioning projections—not results or gate verdicts—are:

| Item | Derivation | Projection |
| --- | --- | ---: |
| `mu26` onboarding | 34.36 GB at 6–8 GB/s | about 5 s |
| full onboarding pass | 76.95 GB at 0.855–1.282 GB/s | 60–90 s |
| seal | 51.54 GB at 8.6–17.2 GB/s | 3–6 s |
| issue/open | 0.1096-s anchor plus batched gather/copy envelope | 0.1–0.5 s |
| reusable session | about 5 s non-PCS work plus seal/open/teardown | 9–11 s |

## 6. Historical rate decision material — inactive in Phase 2

Rate remains exactly `1/8` and `s=111`. No rate contingency, alternate codec
or reference is authorized in Phase 2. The unchanged table below is retained
only as historical Phase-1 decision material; nothing in this package
implements or activates a rate change.

| Rate | `s` | Exact soundness | Slack over registered floor | Disposition |
| --- | ---: | ---: | ---: | --- |
| `1/4` | 136 | 80.32497833580102 bits | 1.51568346180102 bits | preregistered option; about half the oracle; preliminary 3.2–3.3-MB PCS |
| `1/2` | 219 | 79.11483983122474 bits | 0.30554495722474 bits | **REJECTED** by the soundness-slack rule |
| `1/2` | 224 | 80.95573450952145 bits | 2.14643963552145 bits | preregistered option; about one-quarter the oracle; preliminary 46–47-MB response, +5–7% |

All use the same UD analysis and `LinkBad` aggregate term. They receive no
implementation, codec-preflight or gate credit in this phase. Any future
activation would require a separately authorized phase, a recorded exception
to the 2026-07-06 cost-trade convention, new Lean constant discharge and full
rebaseline. Padding, arity, MXFP4 and multi-mask remain in the X5 addendum.

## 7. Frozen Phase-2 profile and hard stop

`runpod-a100-x4c-v1` requires:

- one A100-SXM4 80 GB;
- actual host RAM **>=274,877,906,944 B (256 GiB)**, fail closed;
- a provider **PERSISTENT** volume holding the exact **9,618,587,808-B**
  coefficient-plus-five-root durable tier; and, separately,
- local non-`mfs` storage **>=150,000,000,000 B** for scratch, RAM-spill and
  append-only records;
- wall-only timing plus traffic/allocator counters;
- proving-path `RAYON_NUM_THREADS=8`; onboarding/seal/open unpinned with
  actual worker policy reported; and
- NOTE-6 `c3_weights` first.

R1c scope is extended to direct-fold parity, device trees and arena,
RAM-cache/restart semantics, batched gather and all new accounting
boundaries. At Phase-1 closure no Phase-2 implementation, pod request or pod
contact had occurred. Phase 2 is now authorized locally; after all local gates
and the clean checkpoint land, work hard-stops to request separate pod
provisioning approval. The diagnostic correction in Section 3.1 resumes local
implementation but does not clear this stop. No existing or new pod may be
contacted before the local checkpoint and later provisioning approval.

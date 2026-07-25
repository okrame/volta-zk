# X4c real-weight GPT-2 E2E — live handoff

## Current boundary

The historical schema-2 same-source onboarding and CPU fresh rebuild remain
valid evidence in the append-only ledger. The most recent online attempt
reached CUDA warm-up and stopped fail-closed at the reusable-arena census;
the lifecycle-accounting correction is locally green. It did not emit an
online verdict and cannot be resumed from released in-memory state.

The next milestone is
`X4c-GPT2-real-weight-online-accelerated`, still schema 2 but discriminated
from the historical `X4c-GPT2-real-weight-online` milestone. Its dedicated
validator requires every accelerated rebuild counter. Local tests and
projections grant no production gate. No new pod has been contacted for this
milestone.

Local implementation checkpoint
`065e75c78bd1427329dddbd37be7beb472927b8a` is green: workspace
**376 passed / 0 failed / 4 preexisting ignored**, Python validators
**41 passed**, the tamper filter **44 passed**, and the host CUDA reference
plus all six immutable-input SHA-256 checks pass. This is local preparation,
not a hardware or production verdict; R1c review remains pending.

The live implementation adds:

- `online-accelerated` in `x4c_gpt2_e2e_record`;
- a shared accelerated-rebuild record contract in
  `volta-bench::x4c_rebuild_record`;
- an explicit CUDA RAM-first rebuild in
  `volta-pcs::x4::rebuild_cohort_ram_v4`;
- the manual `x4c_rebuild_preflight` binary;
- fail-closed online and preflight validators in `scripts/report.py`.

Historical incident and checkpoint chronology lives only in
`docs/prototype-status.md` and the append-only raw records.

## Frozen boundary

The accelerated rebuild is an implementation substitution only. It does not
change:

- protocol, ABI, codec, frame or proof format;
- rate `1/8`, `s=111`, query schedule or challenge availability;
- coefficients, roots or canonical proof bytes;
- PCS **2,683,236 B** or response **43,953,700 B**;
- correlation accounting, Lean or soundness;
- the durable tier.

The durable X4c tier remains exactly five coefficient files plus five roots:
no oracle, outer cache or hidden auxiliary file. Immutable model artifacts
are separate inputs, hash-checked before use, and are not X4c durable state.

Any need for a new cryptographic primitive, hash construction, coefficient
transform, transcript field or protocol-visible encoding is a HARD STOP to
report before implementation.

## Rebuild diagnosis

The historical fresh rebuild has these ordered boundaries:

1. exact durable-directory census and SHA-256 verification;
2. five coefficient/root reads;
3. clone plus inverse multilinear transform for evaluation tables;
4. rate-1/8 E-NTT for every present slot;
5. N4 inner leaf construction;
6. full N4 outer-cache construction and root;
7. exact five-root comparison and durable re-census;
8. pre-response ownership admission.

The coefficient/root reads and CPU cohort rebuilds used five outer Rayon
tasks. Evaluation-table reconstruction completes before those tasks; each
inverse multilinear transform uses Rayon internally. In the CPU cohort
rebuild, E-NTT is serial inside each outer task, while N4 inner and N4 outer
use Rayon internally. The measured design therefore combines five
memory-bandwidth-heavy cohort tasks with nested Rayon in N4. “Five tasks”
does not imply five useful independent compute lanes.

The resident byte geometry is:

| Cohort | Coefficients | Host oracle | Full outer cache | Final resident | Conservative build peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| mu26 | 4,294,967,296 | 34,359,738,368 | 34,359,738,336 | 73,014,444,000 | 90,194,313,216 |
| mu22 | 4,831,838,208 | 38,654,705,664 | 2,147,483,616 | 45,634,027,488 | 46,707,769,344 |
| mu20 | 436,207,616 | 3,489,660,928 | 536,870,880 | 4,462,739,424 | 4,731,174,912 |
| auxiliary ell17 | 4,194,304 | 33,554,432 | 33,554,400 | 71,303,136 | 88,080,384 |
| auxiliary ell16 | 51,380,224 | 411,041,792 | 16,777,184 | 479,199,200 | 487,587,840 |
| **Total final** | **9,618,587,648** | **76,948,701,184** | **37,094,424,416** | **123,661,713,248** | — |

The evaluation tables add exactly **9,618,587,648 B**, for a required final
host payload of **133,280,300,896 B** before ordinary runtime overhead.
During CPU N4 construction, outer leaves and their first parent level can
coexist. The per-cohort conservative transient formula used by the preflight
is:

`coefficient bytes + oracle bytes + outer_len × 48`.

If all five historical outer tasks reach that boundary together, their
transients plus evaluation tables total **151,827,513,344 B** before allocator,
thread-stack and model overhead. This is a geometry reconciliation, not a
causal timing claim. The measured earlier critical path remains mu26; only a
new hardware record can attribute accelerated wall time.

With the accelerated serial order, already completed sources, remaining
coefficient buffers and all evaluation tables are retained. The corresponding
largest theoretical host payload is **133,297,078,144 B**, reached while
building auxiliary ell17, again before allocator and runtime overhead.

The existing X4b NTT kernel documents a one-slot device budget of two full
Fp2 buffers plus `n/2` Fp2 twiddles, exactly `40 × outer_len` bytes:
**42,949,672,960 B** at mu26, **2,684,354,560 B** at mu22 and
**671,088,640 B** at mu20. Auxiliary ell16/ell17 use the **512 MiB** N4 tile
ceiling as their conservative device estimate. These are preflight
working-set estimates, not observed VRAM peaks; native live/peak counters
remain mandatory.

Dependencies are strict within a cohort: coefficients precede E-NTT, all
codewords precede N4 inner, inner leaves precede outer levels, and the exact
root precedes admission. Evaluation-table reconstruction is independent of
oracle/N4 construction after the coefficient read, but it is intentionally
completed first to avoid unmeasured overlap. Cohorts are independent until
the five-root admission gate, but the accelerated production schedule is
deterministic and serial (`mu26`, `mu22`, `mu20`, `ell16`, `ell17`) so mu26
and mu22 never overlap.

## Accelerated architecture

The RAM-first path reuses only the already qualified, byte-identical CUDA
primitives:

- `x4b_ntt_fp2`;
- `x4b_n4_inner_tile`;
- `x4b_n4_outer_nodes`.

It does not call the file-oriented committer and creates no scratch. Each
cohort is rebuilt into the normal online ownership:

- coefficients in ordinary host RAM;
- complete oracle in ordinary host RAM;
- full outer cache in ordinary host RAM;
- no file, mapping or file handle;
- no active rebuild device or pinned allocation beyond the backend's
  explicitly censused reusable workspace/cache;
- idle CUDA stream and zero outstanding operation before the next cohort.

The expected root is supplied independently from the durable root file and
must match exactly. Native H2D/D2H counters must equal the byte formula.
Missing counters, traffic mismatch, dirty entry state, root mismatch,
unfinished CUDA work or incomplete cleanup fail closed. A CUDA error performs
idempotent measurement cleanup and returns an error; it never selects the CPU
path. `CpuExplicit` remains a separate opt-in strategy for diagnostics.

The reusable E-NTT workspace is not mislabeled as zero: after the final
cohort, the record captures both workspace bytes and total live device bytes.
The rebuild backend is then dropped before response authorization, its
context-cleanup wall is recorded, and online work receives a newly
constructed backend. Admission requires that fresh context to report zero
workspace/resident/cache bytes, an idle stream, zero outstanding operations
and no active or cached device/pinned allocation. These lifecycle counters
are mandatory in the accelerated schema-2 validator.

There are no duplicated reads or transforms in the accelerated cohort path:
one verified coefficient load feeds one E-NTT, whose returned host codewords
feed tiled N4 inner and N4 outer directly. Evaluation-table reconstruction is
still a separate necessary clone/inverse transform for claim reduction.

## Manual progressive preflight

`x4c_rebuild_preflight` executes exactly one requested stage and never starts
the next. Every executable stage builds a deterministic fixture, constructs
a CPU reference, performs the CUDA RAM-first rebuild, compares the exact root
and records:

- total and per-phase wall;
- logical throughput;
- CPU/CUDA root equality;
- native H2D/D2H;
- process RSS/HWM and device live/peak counters;
- scratch reads/writes/files (required zero);
- cleanup wall and final CUDA control state;
- durable structural census before/after.

The manual order is:

1. `synthetic-small`;
2. `aux-ell16`;
3. `aux-ell17`;
4. `mu20`;
5. `project`, supplied exactly the accepted ell16, ell17 and mu20 records.

The projection uses the slowest observed logical throughput to estimate mu22
and mu26. It is decision-only: no threshold, automatic go/no-go, production
gate or larger geometry execution is attached to it.

Abort after any stage on root mismatch, backend error, insufficient reported
RAM/VRAM, noncompetitive economics, scratch activity, durable-census drift,
ownership inconsistency or missing/contradictory counters. Throughput
economics are reviewed between invocations; the tool cannot auto-advance.

Successful records validate with:

```text
python3 scripts/report.py \
  --validate-x4c-rebuild-preflight RECORD.json
```

The final real-weight chain validates with:

```text
python3 scripts/report.py \
  --validate-x4c-gpt2-accelerated-online ONLINE.json \
  --x4c-gpt2-onboarding ONBOARDING.json
```

## Next-pod runbook

HARD STOP locally until implementation, workspace tests, validator tests,
tamper suite, ledger and this runbook are green.

On a newly supplied endpoint, execute in this order:

1. verify configuration, NOTE-6, one idle physical A100 by UUID, host RAM and
   distinct local/PERSISTENT storage;
2. run the append-only 4-GiB PERSISTENT `write + fdatasync` health probe;
3. run CUDA regressors and immutable input SHA-256 checks;
4. run each preflight stage manually in the order above, validating every
   record before deciding whether to continue;
5. make an explicit economic go/no-go from counters and the diagnostic
   projection;
6. run exactly one same-source onboarding on fresh paths;
7. start a fresh process and run exactly one `online-accelerated` rebuild;
8. only after digest/root/ownership, rebuild-context destruction and
   fresh-online-context admission, run one warm-up and three measured online
   candidates;
9. validate the schema-2 onboarding/accelerated-online chain and copy raw
   records append-only.

Do not reuse a failed authorization store, connection, epoch, scratch path,
durable output path or record path. Do not describe pre-response scratch as
“zero staging”; this implementation currently uses zero scratch at all, and
the response window independently retains exact zero I/O.

## Endpoint requirements

The next host must satisfy the registered `runpod-a100-x4c-v1` profile,
including one idle **A100 80GB** with enough free VRAM for the reported
working set, at least 256 GiB host RAM, reliable local scratch, and a distinct
durable volume that passes the 4-GiB synchronized-write probe. CUDA/driver
identity, GPU UUID, CPU, RAM and storage counters must be recorded by NOTE-6.
No endpoint is requested until the local checkpoint is clean.

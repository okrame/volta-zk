# C4 — Ligero inline rate reduction

**Status (2026-07-27): Phase 1 implemented and locally verified; Phase 2
owner GO received for pod preflight; no producer workload, A100 performance
record or gate verdict yet.**

C4 returns the product path to the accepted T1 Ligero opening and compares
two inline profiles on one unchanged build:

- anchor: the immutable T1 geometry at nominal rate `1/4`, `Q=120`;
- candidate: the same two commitment layouts at nominal rate `1/8`,
  `Q=97`.

X4/X4d is operationally suspended. Its source, formal statements, records,
raw failures, waivers and comparison history remain immutable. C4 does not
delete or reinterpret that work and does not use deferred settlement.

## 1. Scope and invariants

Every response remains weight-certified before acceptance through one
batched Ligero opening for the consolidated weight tree and one for the
exact-block embedding tree. C4 changes only the Ligero code length and fresh
query count. It does not change:

- GPT-2 quantization, witness generation or golden output;
- T1 boundary thinning, the private-logit argument or public output;
- the two commitment messages, their row/column split or tensor placement;
- the `96 + 6` distinct opening claims;
- query timing: every response draws a fresh set after prover messages seal;
- VOLE/MAC equations, real/AES PCG, connection lifecycle or one-time use;
- proof grammar, field encoding, Merkle hash or authenticated output;
- M1--M11 statements or the M9 PCS-binding interface.

Verifier-cached columns and linear merging of independently pointed claims
remain forbidden by the 2026-07-15 ledger correction. No response may enter
`WEIGHT_PENDING`; no production record may fall back to CPU or another PCS.

## 2. Frozen profiles

The anchor continues to use the immutable `C3_WEIGHTS` and `C3_EMBED`
constants. C4 adds new constants rather than mutating them:

| field | anchor weights | C4 weights | anchor embed | C4 embed |
|---|---:|---:|---:|---:|
| rows | 24,576 | 24,576 | 2,080 | 2,080 |
| cols | 8,192 | 8,192 | 32,768 | 32,768 |
| pad | 512 | 512 | 512 | 512 |
| message length | 8,704 | 8,704 | 33,280 | 33,280 |
| code length | 32,768 | 65,536 | 131,072 | 262,144 |
| queries | 120 | 97 | 120 | 97 |
| effective rate | 0.265625 | 0.1328125 | 0.25390625 | 0.126953125 |

`--t1-record` remains frozen at the anchor. C4 uses a distinct record mode
and namespace; no historical validator or JSON is re-baselined.

## 3. Exact communication and soundness

The existing `MultiOpenProof::byte_breakdown()` formula gives:

```text
anchor PCS             = 43,273,888 B
C4 PCS                 = 38,296,040 B
non-PCS T1 transcript  = 41,270,464 B
anchor response        = 84,544,352 B
C4 response            = 79,566,504 B
response saving        =  4,977,848 B
fase-D setup           = 38,371,465 B
anchor first exchange  = 122,915,817 B
C4 first exchange      = 117,937,969 B
```

At five accepted responses in one already-supported connection:

```text
anchor amortized = 84,544,352 + 38,371,465/5 = 92,218,645 B
C4 amortized     = 79,566,504 + 38,371,465/5 = 87,240,797 B
```

The response-wide statistical union bound uses the same conservative C3
formula:

```text
epsilon_tree =
    (1 - (1-rate)/2)^Q
  + (rows + claims + 1)/|Fp2|
epsilon_response = epsilon_weights + epsilon_embed
```

The anchor is `78.80929487391641` bits. The C4 candidate is
`78.866516497` bits by the existing analytic sweep and must be recomputed
from the actual constants. Acceptance requires candidate bits greater than
or equal to the exact anchor value. Query-index modulo bias remains the
declared modeling boundary; C4 does not credit it as soundness.

## 4. Local implementation and permanent tests

Phase 1 lands:

1. `C4_WEIGHTS` and `C4_EMBED`, with layout validation and exact byte tests.
2. A separate `--c4-record --c4-profile anchor|rate8` report mode. Both
   profiles are emitted by one binary and one SHA.
3. Additive C4 report fields for profile, expected/observed PCS and response
   bytes, exact saving, soundness floor, setup/first-exchange and projected
   device/storage envelopes. Historical T1 fields remain unchanged.
4. A fail-closed Python validator and negative mutations for profile,
   geometry, `Q`, rate, bytes, saving, soundness, query freshness, claims,
   PCG setup, hardware and performance pairing.
5. Permanent tests for both profiles on practical local geometries,
   including commit/open/verify, response-fresh query tapes, mask/root/path
   tampering, counter/ledger parity and unchanged non-PCS transcript.
6. Full workspace, report-validator, formatting, diff-hygiene and
   CUDA-feature all-target compilation.

The implementation uses schema 11 and CUDA ABI 33. `--c4-record` requires
exactly one `--c4-profile anchor|rate8`, a clean full-geometry run, real
AES-PCG, one warmup plus at least three measured repetitions, and either CPU
or fail-closed `cuda-resident`; production validation accepts only the latter.
`--pcs-q` cannot override a C4 profile. The report records both geometries,
formula and observed bytes, exact non-PCS residue, soundness, codeword tier,
maximum measured device live set and whether the 40-GB ceiling is met.
Before loading weights, an A100 record also resolves exactly one
`CUDA_VISIBLE_DEVICES` selector and fails closed unless free VRAM is at least
40,000,000,000 B, host RAM is at least 64 GiB, the repository filesystem is
non-FUSE/non-network with at least 80,000,000,000 B free, at least 13 effective
CPUs are visible and Rayon is exactly eight. Every observation and floor is
serialized and rechecked by the validator.

RunPod exposes its local container disk as `overlayfs`, while its separately
provisioned `/workspace` volume is network FUSE. The first authorized Phase-2
preflight therefore stopped before checkout, build, weights, PCG stores or
any producer workload: the original filesystem allowlist admitted only the
backing ext4/XFS spelling and rejected the provider's local overlay view.
The admission correction keeps the 80,000,000,000-B floor and still rejects
all FUSE/network storage. `overlayfs` is accepted only when `findmnt -T`
reports source exactly `overlay`, filesystem exactly `overlay`, and mount
options contain both Docker-local `upperdir=/var/lib/docker/` and
`workdir=/var/lib/docker/`; the repository path, mount source, filesystem,
mount options and boolean evidence are serialized and revalidated. Plain
ext4 (`stat` spelling `ext2/ext3`) and XFS remain admitted without overlay
evidence. No generic `overlayfs` or capacity waiver is introduced.

### Owner Amendment 1 — effective-CPU floor

The original C4 floor of 16 logical CPUs was conservative headroom, not a
measured requirement of the eight-worker inline Ligero path. The clean
historical T1 A100 record
`t1-a100-realpcg-v4-2026-07-19-b14577e.json` (SHA-256
`1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`)
reports `detected_logical_cpu_cores=13`, `pcg_setup_rayon_threads=8`, a
38.845157077-s real-PCG setup, a 5.289037812-s response session and green T1
gates. It is therefore direct production evidence that the workload and PCG
setup do not require 16 effective CPUs.

The owner amends only the C4 resource floor from 16 to **13 effective CPUs**.
The producer continues to use cgroup-aware
`std::thread::available_parallelism`, so a fractional quota such as 13.6 is
counted conservatively as 13. Rayon remains exactly eight, leaving five
admitted effective CPUs outside the scheduled pool. A host reporting 12 is
rejected. The anchor and candidate must still use the same detected CPU
count, build, host and GPU; the anchor must pass every absolute T1 gate before
the candidate may start, and both paired timing ratios remain `<=1.05x`.
Thus the amendment cannot convert CPU contention into a passing performance
result. It changes no protocol, proof byte, soundness expression, rate,
query count, CUDA operation, PCG lifecycle or communication gate.

The failed 16-CPU admission attempt and its teardown records remain immutable
and are not retried. This amendment is local preregistration only; a new pod
contact or replacement pair still requires a new explicit owner GO and fresh
authorization/connection stores.

`scripts/report.py --validate-c4-official RECORD` validates each raw A100
profile. The paired selector requires an anchor and candidate on the same
full Git SHA, instance, GPU, ABI and eight-worker configuration, distinct
connection channel ledgers, equal non-PCS ledgers/correlation counters, and
both 1.05 timing ratios. It can create the final record append-only:

```text
python3 scripts/report.py \
  --validate-c4-pair ANCHOR.json RATE8.json \
  --write-c4-pair benchmarks/results/c4-ligero-paired-a100-DATE-SHA.json
```

The permanent scaled differential uses identical message geometry and a
doubled code length, proves both multi-openings, and rejects a tampered Merkle
path and authenticated correction. The exact production formulas are tested
without materializing the 17.25-GB candidate codeword tier locally.

The local 11-GiB host is not required to materialize the 17.25-GB production
candidate tier. Production-size execution belongs to Phase 2; local tests
must use exact formulas plus scaled cryptographic differentials and may not
claim an A100 result.

The append-only local record is
`benchmarks/results/c4-ligero-local-2026-07-27-7bb4428.json`. It states
`pod_contacted=false`, `production_pair_started=false` and
`gate_verdict=false`. `cargo test --workspace`, all 23 report-validator
tests, CUDA-feature all-target compilation, formatting and diff hygiene are
green. This is local correctness/formula evidence only; no production-size
candidate or performance workload ran.

## 5. Phase-2 A100 profile and order

Phase 2 begins only after a clean local checkpoint and a new explicit owner
GO. The admitted profile is:

- one selected NVIDIA A100-SXM4 80 GB (`sm_80`), even on a multi-GPU host;
- at least 40 GB free device memory;
- at least 64 GiB host RAM;
- at least 80 GB free local non-FUSE ext4/XFS storage, either directly
  mounted or exposed through the exact Docker-local overlay contract above;
- at least 13 effective CPUs, with proving and PCG Rayon fixed at exactly 8;
- CUDA toolchain and `nvcc` capable of building the current fail-closed ABI.

The measured T1 anchors are 8.164 GiB peak RSS, a 4,584,443,640-B
correlation spool and about 19.36 GB live device state including reusable
cache. Candidate codewords are 17,246,978,048 B versus 8,623,489,024 B for
the anchor, projecting about 28 GB live device state. The 40-GB free-device,
64-GiB RAM and 80-GB local-volume floors include build, both codeword tiers,
spool and bounded scratch headroom.

The binding order is:

1. clean-source and hardware/resource preflight;
2. real-CUDA differentials and production leakage smokes;
3. one build, unchanged thereafter;
4. anchor: one warmup plus at least three measured repetitions;
5. only if the anchor is green, candidate: one warmup plus at least three
   measured repetitions;
6. paired validator, document/ledger closure and control-plane teardown.

Each profile uses fresh authorization and connection stores. No selective
retry is allowed. An anchor obstruction prevents candidate execution.

The two producer commands are identical except for the profile and fresh
store paths:

```text
CUDA_VISIBLE_DEVICES=0 RAYON_NUM_THREADS=8 VOLTA_REQUIRE_CUDA=1 \
cargo run --release -p volta-bench --bin p6_report -- \
  --c4-record --c4-profile anchor \
  --accelerator cuda-resident --resident-timing wall-only-counters \
  --pcg-backend real --ggm-prg aes128-mmo \
  --pcg-authorization-store ANCHOR_AUTH \
  --pcg-connection-store ANCHOR_CONNECTION

CUDA_VISIBLE_DEVICES=0 RAYON_NUM_THREADS=8 VOLTA_REQUIRE_CUDA=1 \
cargo run --release -p volta-bench --bin p6_report -- \
  --c4-record --c4-profile rate8 \
  --accelerator cuda-resident --resident-timing wall-only-counters \
  --pcg-backend real --ggm-prg aes128-mmo \
  --pcg-authorization-store RATE8_AUTH \
  --pcg-connection-store RATE8_CONNECTION
```

The candidate command is forbidden until the anchor raw record passes
`--validate-c4-official`. Both output paths are selected with create-new
semantics; the pair writer also refuses overwrite.

## 6. Binding gates

### Anchor

- PCS `43,273,888 B`, response `84,544,352 B`, setup `38,371,465 B`;
- auth corrections `38,348,720 B`, two trees and `96 + 6` claims;
- prefill `<=10 s`, decode marginal `<=4 s`;
- H2D `<=100,000,000 B`, maximum sync wall `<=0.150 s`;
- flat-cost last/first `<=1.5`;
- golden, normal/chunked acceptance, leakage and all protocol regressions
  green.

### Candidate

All predicates are conjunctive:

1. PCS exactly `38,296,040 B`.
2. Response exactly `79,566,504 B`.
3. Saving exactly `4,977,848 B`.
4. Soundness bits at least `78.80929487391641`.
5. Prove-response upper median `<=1.05 *` anchor.
6. Complete response-session upper median `<=1.05 *` anchor.
7. The anchor absolute prefill/decode/H2D/sync/flat ceilings unchanged.
8. Peak device live bytes `<40,000,000,000`.
9. Setup traffic exactly `38,371,465 B`; no repeated base OT or OT extension
   after the first accepted response.
10. Non-PCS transcript, authentication bytes, claim census, correlation
    counts, output and all non-PCS ledgers equal to the anchor.
11. Every protocol and report-validator regression green.

Commit/open/verify, storage and mask work are reported separately and may not
hide a failure of either total-wall predicate.

## 7. Records, comparison and stop condition

Production records are append-only:

```text
c4-ligero-t1-anchor-a100-<date>-<gitsha>.json
c4-ligero-rate8-a100-<date>-<gitsha>.json
c4-ligero-paired-a100-<date>-<gitsha>.json
c4-control-plane-teardown-<date>-<gitsha>.json
```

After the pair lands, `docs/gpt2-comparison-WIP.md` must contain the current
same-build anchor, the C4 candidate, first-exchange and two/five-response
amortization, cost/resource deltas, exact record hashes and the immutable X4
history. Only then may its stale-build warning be removed.

The local hard stop was lifted by the owner's explicit Phase-2 GO. No
producer workload may start until the storage-admission correction is a
clean committed build and the complete preflight passes.

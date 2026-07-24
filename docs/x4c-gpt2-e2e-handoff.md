# X4c to real-weight GPT-2 small E2E handoff

## Status and boundary

X4c Phase 2 / v1 is complete and PASS on the new pod.  The qualifying online
record is
`benchmarks/results/11-x4c-online-2026-07-24-603d5a7.json`, SHA-256
`aa1aafc5c956444c4d2fb2b8e921c9be7e2c6566d856f57569cfb3cf13a03f98`.
It uses exact production GPT-2 cohort and opening geometry, but it is not an
inference E2E with real model weights.  No real-weight X4c E2E verdict is
claimed by this handoff.

The 2026-07-24 R1c remediation checkpoint supersedes the record-harness
requirements for the next run without changing the historical records.
Schema-1 onboarding/online JSON remains append-only evidence, but it does not
carry the new measured response-window I/O, native census, durable-directory
census or explicit onboarding-SHA fields and therefore is not accepted by the
new schema-2 validators.

The existing `scripts/run_prefill.sh` and `scripts/run_decode.sh` remain the
historical P5/P6 real-weight baselines.  At source `603d5a7` they do not route
their PCS through the new X4c onboarding, rebuild, direct-fold arena and
batched-gather driver.  Running either script alone must not be labeled an
X4c E2E result.

The clean local driver checkpoint is
`7e8e957977fc51ca5d5deedd0c75371dc438118a`.  It adds
`x4c_gpt2_e2e_record` with `preflight`, `onboard` and `online` modes plus
schema-2 fail-closed report validation.  Local verification is green; no pod
was contacted by that checkpoint and no real-weight hardware verdict is
claimed.

The first migrated-pod NOTE-6 invocation exposed a stale pre-R1c design
digest pin and stopped before its production-size child test.  The corrected
local checkpoint is `1facd7e0880cc614888a1176f547a222dcdf0831`: remediated
schema-2 evidence now pins design SHA-256
`9a3c64a65902046ba0a2b1891ff8fce03690d870773a346f7128b9f75f7a1164`
in the shared X4c runtime, NOTE-6, onboarding/online records and validators.
Historical `57d0c0...` records remain unchanged and are not reused as
post-R1c evidence.

The first real-weight onboarding attempt from clean `092dda1` then stopped
before durable-tier creation because the new driver incorrectly treated the
canonical `golden-p6.bin` as header plus tokens only.  The frozen artifact is
unchanged and exact: **616 B**, SHA-256 `e102783a...`, with its documented
50-token plus 50-checksum payload.  Clean checkpoint
`1bbeb28a72f4270f884d16553e3bd9b89e273171` corrects the fail-closed parser to
require that full 616-B geometry and exact `T=100` / `N=50` header.  The
failed invocation wrote no onboarding record and carries no gate verdict.

The next clean `4c97ebb` attempt passed that input gate and then stopped
before coefficient materialization because the driver compared the two model
transcripts before their product and zero-batch MAC closures.  Clean
checkpoint `79b0142106fc27ca3db2daf2ee99e6527b3d5c10` now executes and verifies
both closures, compares byte counts and ledgers at the correct post-closure
boundary, and preserves the pre-closure correlation census used by the
explicit `+2` budget.  This corrects only prepass control flow; it changes no
protocol transcript or parameter.  The failed attempt also wrote no
onboarding record and carries no gate verdict.

## Frozen real-weight inputs

The following repo-local generated artifacts are present and match
`benchmarks/weights/SHA256SUMS`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `gpt2s-q.bin` | 249,403,904 | `bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a` |
| `gpt2s-q.json` | 18,322 | `98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c` |
| `gpt2s-q.params` | 704 | `264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac` |
| `golden-p5.bin` | 402,280 | `4ac774f208a414bf7fb591a29bd455968ce2d89846255fe8239eabd9b5c92f45` |
| `golden-p6.bin` | 616 | `e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862` |
| `model.safetensors` | 548,105,171 | `248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707` |

These input artifacts may live on PERSISTENT as immutable, hash-checked model
inputs.  They are not X4c response staging and do not alter the X4c durable
PCS tier: the latter remains exactly coefficient files plus five roots, with
zero durable oracle files.

For the current pod session, the manifest and all six files have been copied
to the fresh PERSISTENT path
`/workspace/x4c-gpt2-small-input-2026-07-24`.  An on-pod reread with
`sha256sum -c` returned `OK` for all six entries.  The directory contains
exactly those six artifacts plus `SHA256SUMS`; its files and directory are
read-only.  This is input preparation, not an E2E execution record.

## Implemented local driver

The clean descendant driver connects the existing real GPT-2
T=100+50 witness/proof orchestration to the already qualified X4c APIs.  It
derives the five X4c cohort coefficient streams from the actual frozen model
artifact, rather than from the production-geometry fixture, and retains the
existing real/AES PCG connection and one-time response authorization
lifecycle.

Before any transcript challenge or correlation becomes available, the driver
calls `ProductionFaseDConnection::begin_x4_response` with the actual
`model_root`, nonzero epoch, digest of the verifier challenge seed and the
real-PCG authorization nonce. It passes the resulting persisted freshness
receipt to `X4OpeningRegistryV4::authorize_after_persistent_freshness`.
The three burn indexes survive success, retry, abort and process restart;
legacy per-instance authorization is not record-eligible for this E2E.

This integration adds orchestration and record fields only.  It does not
change rate `1/8`, `s=111`, query availability/order, the
selected tape, protocol frames, codec, roots as derived from the same inputs,
proof bytes, correlations, Lean statements, soundness accounting or any
gate.  The complete PCS and response must remain exactly
**2,683,236 / 43,953,700 B**.

The driver records both identities in one clean record:

1. Real inference identity: exact input-artifact hashes, T=100 prefill,
   50 greedy decode tokens, CPU/Rust golden equality, CPU/CUDA witness
   equality, accepted model proof and real-PCG lifecycle/counters.
2. X4c PCS identity: real-weight coefficient hashes and roots, same-source
   onboarding/rebuild equality, direct-fold diagnostics, one 111-query
   gather, canonical opening bytes, zero response staging and reconciled
   teardown ownership.

Local completion at this checkpoint includes format/check, the full Rust
workspace, the Python/report-validator suite, tamper tests, exact input SHA
checks, the host reference and the driver preflight.  Production-size
onboarding/rebuild and real CUDA equality intentionally wait for the pod.

## Ordered execution after the new pod endpoint is supplied

1. Verify the new pod configuration, NOTE-6 and distinct local/PERSISTENT
   storage, then run the append-only 4-GiB PERSISTENT `write + fdatasync`
   health probe before expensive onboarding.
2. Check out the exact clean closure and rerun format/check, the CUDA
   regressors and every SHA-256 before loading model data.
3. Select exactly one idle physical A100 by UUID on the new host.  Do not
   reuse the previous pod's physical GPU number or UUID as a selection
   assumption. Keep code, target, scratch, RAM spill and append-only records
   on fresh local non-MFS paths; keep immutable model inputs and the
   coefficient-plus-five-root durable tier on PERSISTENT.
4. Run the real-weight CPU/Rust golden and CPU/CUDA witness differential
   before the first full X4c onboarding.
5. Run same-source real-weight onboarding on a fresh durable path, then a
   fresh-process five-cohort parallel rebuild.  Admit no response until all
   coefficient hashes, byte censuses and five roots agree.
6. Run one warm-up plus three measured E2E candidates with the composite
   persistent epoch/challenge/real-PCG freshness burn described above.
   Preserve exact phase timers, `proof_ready_wall`,
   teardown-inclusive `session_reusable_wall`, complete-session wall and all
   ownership/traffic counters.
7. Validate onboarding and online/E2E records with the schema-2 fail-closed
   validators, including their exact onboarding-SHA chain, before making any
   verdict or copying an append-only record back.

The X4c PCS gates remain open **<=1.50 s**, verify **<=0.25 s**, exact
communication, staging zero and ownership fully reconciled.  Golden,
CPU/CUDA equality, root/rebuild equality, verifier acceptance and one-time
correlation accounting are conjunctive.  The complete E2E wall is informative
until a separate ceiling is preregistered; the X4c v1 measurement does not
create a v2 ceiling.

HARD STOP on `EIO`, any golden/witness/root/reference/proof-byte mismatch,
nonzero response staging, missing counter, inconsistent ownership, leaked or
distributed per-round allocations, RAM/VRAM overflow, correlation reuse, or
need for a protocol/rate/Lean/soundness change.

# C7 R0.4 — CPU-first fail-closed prover and pod handoff

**State:** `C7_R04_CPU_SEARCH_ACTIVE_NOT_READY`.

This handoff prepares the order, evidence and stop rules for later C7 work.
It authorizes only the tiny CPU `BatchOpenBlocks` search/reference described
below, not a large prover/E2E, optimized SIMT kernel, provider contact or pod
run.  The protocol authority remains
`docs/c7-stateful-authenticated-lfc-design.md` and the active capsule in
`docs/prototype-status.md`.

## 1. Authorization boundary

- Local work is design/theorem/census, transparent tiny/scaled screening and
  the authorized CPU `BatchOpenBlocks` reference only.
- No optimized SIMT kernel or GPU scaffold is authorized before the ledger
  records `C7_CPU_REFERENCE_PASS`.
- A complete GPT-2 E2E is never local.  It remains pod-only.
- Pod contact requires both a prior ledger transition to `C7_POD_READY` and a
  later explicit owner GO naming the concrete run.  Readiness is not GO.
- No full-model component benchmark can substitute for the first complete
  serialized case or receive E2E credit.
- Production/provider synchronization uses a clean GitHub HTTPS push/pull and
  exact SHA only.  No `gh`, SSH Git, SCP/rsync, repository archive or exported
  credential is admitted.  Generated weights/setup remain pod-local.

## 2. Gates to `C7_LOCAL_READY`

Every row is fail-closed and currently **open**.

| Gate | Required evidence |
| --- | --- |
| concrete crypto | selected domain-separated `LeafCom` and tree hash; fresh honest-DV `rho/beta/gamma` are serialized with `Q_FS=0`; adaptive hiding/binding, authenticated-checker soundness or PoK, real PCG/VOLE and complete connection bound |
| canonical compiler | exact response relation, serialized schedule, one terminal point per physical segment and reject-before-correlation on any multiplicity/count mismatch |
| opening schedule | CPU reference with derived `c_source*N+poly(q,log N)`, `c_source` independent of `q`, exactly one monotone packed scan, bounded memory, no N-scale scratch or expanded Fp/Fp2/code/tag plane |
| setup | logical `g=141`; manifest with persistent, temporary, read/write, refresh, peak host/device and wall counts; `A_setup<=2.00` target or explicit tolerance at `<=2.10` |
| certificate | exact five-counter query census, serialized interactive challenge frames and six-component reconciliation; `B_weight_ALFC<=target` or explicit tolerance at `<=105%`; complete 30/100-MB and 3x gates |
| security | theorem/hypothesis registry with scope, repetition and exact error for every event; analytic `Q_leaf<=2^64`, selected `Q_FS=0`, and connection arithmetic remains at least 78 bits |
| SIMT, if used | only after CPU pass; bit-exact leaves/root/multiproof/MAC/transcript/certificate/journal plus reconciled disk, H2D/D2H/D2D, RSS/VRAM, padding, launch and synchronization counters |
| lifecycle | two incremental responses, accepted predecessor/successor K/V, real finite PCG using only consumed profiles, abort burn and atomic promotion |
| verifier | canonical serialization, reload and full ordinary-CPU verification; mutation, replay, fork, truncation, reordered-prefix and configured-count-plus-one failures |

The smallest valid local case must execute the whole lifecycle twice.  A
mock-PCG, component-only, analytic or public-WHIR result remains
`credit:false` and cannot establish `C7_LOCAL_READY`.  The authorized CPU
reference precedes that case and by itself earns no lifecycle/E2E credit.

## 3. CPU-first ladder and SIMT contract

1. Prove the generator/structure screen analytically; `nnz(G)>=kd` already
   rejects direct sparse-output accumulation for uniform queries in expectation
   and for the heaviest queried leaves in the worst case.
2. Implement only the smallest CPU reference for a surviving structured
   algorithm and tiny canonical fixtures.
3. Record `C7_CPU_REFERENCE_PASS` only if code-derived
   `c_source*N+poly(q,log N)` and exact counters agree.
4. Only then implement the admitted SIMT stages and prove byte-exact
   CPU/SIMT equivalence.
5. Only then run scaled local integration; no complete GPT-2 locally.

The CPU report must assert one source open/pass, monotonically increasing
offsets, exactly `2*N` packed bytes, no reopen/backward seek, no full codeword,
expanded weights or model-linear scratch, and live memory bounded by
`chunk+140 symbols+poly(q,log N)`.  It separately reports source/query
operations, Fp/Fp2/hash/AES/VOLE/MAC/leaf/reduction work, host disk traffic,
scratch and syncs, RSS/`VmHWM`, output/certificate/transcript bytes.  `N,q`
fixtures reconcile the formula; timing trends alone do not pass.

After the CPU pass, reports add per-phase H2D/D2H/explicit-D2D,
device-generated/zeroed bytes, VRAM/pinned peaks, allocation/launch counts,
and synchronizations by reason and wall.  Logical `g=141` is immutable.  Any
wider device tile is temporary zero padding with zero persistent,
`LeafCom`-input, certificate and transcript bytes; its work and peak are
measured.  CPU and SIMT must match leaves, digests/root/multiproof,
provider-internal salts, exact finite-fixture PCG/VOLE values and consumption,
handles/corrections, correlation schedule, every transcript frame/challenge,
both Fp2 limbs, certificate, CPU-verifier result and journal transition.
Production records store only secret-free digests/counters for internal values.

Any second scan, `qN`, full codeword, model-sized scratch, unassigned transfer,
unclassified barrier or transcript/correlation-order change fails.  Reuse the
existing transcript, correlation-audit, backend-stat and RSS measurement seams;
do not reuse an X4/C6 oracle/backend or add an empty C7 scaffold.

## 4. Required create-new evidence

Do not create empty schema scaffolding.  Once a concrete compiler exists, its
single run-of-record directory must contain create-new artifacts covering:

```text
compiler manifest       layouts, segment IDs, points, roots and transcript order
setup manifest          persistent/temp/refresh bytes and build resource counters
query census            q_open, U_leaf, P_secret, Q_leaf screen and Q_FS=0
certificate census      six B_* components with every byte assigned once
security registry       named theorem/hypothesis, scope, repetitions and epsilon
resource report         passes, bytes read/written, peak RSS/device and wall phases
lifecycle journal       reservation, burn, accept, promotion, replay/fork decisions
verifier/mutation log   reload result and every negative test
checksums                inputs, setup, certificate, journal and reports
```

Each report records `git_sha`, `git_dirty:false`, protocol/compiler version,
field/hash/PCG identifiers, workload, challenge mode and machine identity.
Analytic screens use a different namespace and cannot be promoted later.

## 5. Promotion to `C7_POD_READY`

`C7_POD_READY` is a same-checkpoint ledger/capsule transition only after:

1. every Section 2 gate passes on the complete two-response tiny/scaled case;
2. the exact GPT-2 pod command, immutable inputs, output directory and abort
   policy are preregistered;
3. the run fails closed on a dirty tree, SHA mismatch, existing output,
   missing real PCG, unrecognized hardware, insufficient disk/memory, setup or
   certificate cap, and any verifier/mutation failure;
4. a source-tree checksum before/after proves the run did not modify tracked
   inputs;
5. no automatic/selective retry exists.

There is intentionally no C7 pod runner yet: no concrete compiler, prover or
certificate interface exists.  A placeholder runner would conceal these
gates rather than prepare them.

## 6. Pod order after later owner GO

1. Create a new pod-local run directory and HTTPS-pull the preregistered clean
   SHA; verify it before any setup.
2. Record CPU/GPU/RAM/disk/driver/runtime identity and perform only read-only
   capacity checks.
3. Run the smallest complete serialized production-equivalent case first,
   including reload, CPU verifier, mutations, abort burn and promotion.
4. Stop and record the first failure.  Do not retry or enlarge the case.
5. Only if that complete case passes and the GO explicitly includes it, run
   the full GPT-2 E2E once in a new directory.
6. Persist create-new reports/checksums and append the ledger disposition.
   Large generated weights/setup stay pod-local.

Current blockers are the concrete leaf commitment, authenticated soundness
bridge, CPU-pass locally openable code, compiler/query
census and all downstream complete-chain evidence.  Therefore no pod action
is presently valid.

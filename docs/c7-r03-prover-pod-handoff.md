# C7 R0.3 — fail-closed prover and pod handoff

**State:** `C7_R03_NOT_READY`.

This handoff prepares the order, evidence and stop rules for later C7 work.  It
does not authorize prover implementation/execution, provider contact or a pod
run.  The protocol authority remains
`docs/c7-stateful-authenticated-lfc-design.md` and the active capsule in
`docs/prototype-status.md`.

## 1. Authorization boundary

- Local work before a later owner decision is design, theorem/census and
  transparent tiny/scaled screening only.
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
| concrete crypto | selected domain-separated `LeafCom`, tree hash and challenge mode; adaptive hiding/binding, authenticated-checker soundness or PoK, real PCG/VOLE and complete connection bound |
| canonical compiler | exact response relation, serialized schedule, one terminal point per physical segment and reject-before-correlation on any multiplicity/count mismatch |
| opening schedule | executable `BatchOpenBlocks=O(N+poly(q,log N))`, one packed sequential scan, bounded memory, no N-scale scratch or expanded Fp/Fp2/code/tag plane |
| setup | manifest with persistent, temporary, read/write, refresh, peak host/device and wall counts; `A_setup<=2.00` target or explicit tolerance at `<=2.10` |
| certificate | exact five-counter query census and six-component reconciliation; `B_weight_ALFC<=target` or explicit tolerance at `<=105%`; complete 30/100-MB and 3x gates |
| security | theorem/hypothesis registry with scope, repetition and exact error for every event; `Q_leaf` and `Q_FS` are separate and connection arithmetic remains at least 78 bits |
| lifecycle | two incremental responses, accepted predecessor/successor K/V, real finite PCG using only consumed profiles, abort burn and atomic promotion |
| verifier | canonical serialization, reload and full ordinary-CPU verification; mutation, replay, fork, truncation, reordered-prefix and configured-count-plus-one failures |

The smallest valid local case must execute the whole lifecycle twice.  A
mock-PCG, component-only, analytic or public-WHIR result remains
`credit:false` and cannot establish `C7_LOCAL_READY`.

## 3. Required create-new evidence

Do not create empty schema scaffolding.  Once a concrete compiler exists, its
single run-of-record directory must contain create-new artifacts covering:

```text
compiler manifest       layouts, segment IDs, points, roots and transcript order
setup manifest          persistent/temp/refresh bytes and build resource counters
query census            q_open, U_leaf, P_secret, Q_leaf policy and Q_FS policy
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

## 4. Promotion to `C7_POD_READY`

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

## 5. Pod order after later owner GO

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

Current blockers are the concrete leaf commitment, challenge choice,
authenticated soundness bridge, locally openable one-pass code, compiler/query
census and all downstream complete-chain evidence.  Therefore no pod action
is presently valid.

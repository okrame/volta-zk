# C7 R0.6 — policy-2 root-wide bounded-query handoff

**State:** `C7_R06_POLICY2_ACTIVE_DESIGN_ONLY`.

This handoff prepares the order, evidence and stop rules for later C7 work.
Policy 3 remains terminally rejected under its registered gates; R0.6 activates
policy 2, in which only masked PCS answers within a cryptographically enforced
root-wide horizon may be public and the terminal evaluation remains
VOLE-authenticated.  No backend, concrete query counts or root capacity are
selected yet.  This document authorizes no PCS prover, SIMT kernel, provider
contact or pod run.  The protocol authority remains
`docs/c7-stateful-authenticated-lfc-design.md` and the active capsule in
`docs/prototype-status.md`.

## 1. Authorization boundary

- Local work is limited to the policy-2 design, theorem and executable analytic
  census plus tiny counter/hash/codec fixtures.  Selecting a backend and its
  exact counts requires a recorded design checkpoint before prover work.
- Before the first attempt-local provider response byte whose distribution
  depends on `W` or its oracle epoch, the model-owner/provider's authoritative
  global allocator for the complete ordered `omega` root set must
  durably reserve the fixed plane-charge vector and its declared census
  profile.  Its authenticated reservation/assignment receipts, profile and root-set digest enter the
  canonical transcript.  The already-public root is a baseline view element whose
  cross-world replacement is charged to the root-hiding theorem.
  Accept, abort, crash,
  timeout and retry all consume the complete reservation; no suffix is
  refunded or reused.
- The root-wide allocator aggregates every connection, identity, failed
  attempt and colluding designated verifier.  Per-user quotas and rate limits
  may mitigate exhaustion attacks but never replace this counter.
- Each authenticated receipt binds a receipt-free request containing the
  complete connection/nonce/MAC-domain/charge context; appending the receipt
  derives the session binding.  Before emitting receipt/seed commitment the
  provider CASes `Reserved -> InFlight` and caches that first reply.  Replica
  duplicates may return only the cached byte-identical reply for the exact
  transcript state; divergent challenges fail before new witness-dependent
  bytes.
- Exhaustion seals the root; it does not automatically reset the budget.  A
  later rotation needs fresh independent masks/salts, a same-weights bridge,
  a bounded root-epoch/lifetime composition and one atomic activation.  Only
  the weight-epoch counter rotates; the separate state-plane ledger and every
  K/V high-water survive byte-identically.
- Before the first accepted predecessor root is disclosed, `InitKVState(s0)`
  must create and charge its durable map entry.  A carried predecessor without
  that authenticated live entry rejects before a new response.
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
| concrete crypto | a domain-separated public salted-Merkle construction such as BLAKE3 is eligible because masked leaves may be shown and checked in public; distinct `Q_CR/Q_hide/Q_PRF` bounds, collision binding, adaptive root/path hiding, mask PRF, joint t-query ZK, multi-user VOLE/MAC composition, real PCG/VOLE and the authenticated terminal theorem remain named missing premises; Poseidon2 private-leaf checking is not required by policy 2 |
| canonical compiler | exact causal sampling prelude, response relation and serialized schedule; complete ordered `omega` descriptor, profile/root-budget IDs and authenticated reservation receipt fixed in the prefix; every allowed clear answer is typed as a masked symbol of a declared ZK alphabet, while the terminal evaluation has no clear codec; one terminal point per physical segment and reject-before-correlation on every mismatch |
| root budget | exact plane-tagged `q_attempt`/`q_response` vectors and fixed `(u_W,u_B,u_KV_old,u_KV_new)` charges; weight-epoch `Q_root`/`R_root`, per-attempt `Q_B[a]` and per-created-K/V-root `Q_KV[s]`; `InitKVState(s0)` before first disclosure; durable weight ledger separated from boundary/KV state ledger; every proposed successor is charged, then sealed on abort or keeps the same counter after acceptance; receipt-free request binding plus single-session receipt state machine reserves all components before the first reply, and a no-extension assignment CAS binds pre-burned slots to new roots before disclosure; no refund, global aggregation across connections/colluding verifiers and stop-admit rotation carrying state maps byte-identically plus a private same-weights bridge |
| opening schedule | backend and counts are unselected; logical PCS samples, ZK-alphabet atoms, unique leaves and visible Fp occurrences must each stay within 1.05 from GPT-2 to 31B absent a proved codec equivalence; standard public leaf/path verification, one fused packed-weight scan, `O(N+poly(q,log N))` CPU work and bounded memory remain mandatory; the R0.5 one-stage RA screen remains rejected for distance and ordered-root setup, so `C7_CPU_REFERENCE_PASS=false` |
| setup | logical `g=141`; exact static randomized oracle, salted tree, counter and same-weights rotation costs; persistent, temporary, read/write, refresh, peak host/device and wall counts; `A_setup<=2.00` target or explicit tolerance at `<=2.10`, with no X4d-style expanded setup hidden in rotation |
| certificate | separate logical PCS samples, ZK-alphabet query atoms, visible masked Fp/Fp2 limbs, unique leaves, exact multiproof siblings/paths and attempt counts; serialized `omega`/profile/receipt authentication and interactive challenge frames with six-component reconciliation; `B_weight_ALFC<=target` or explicit tolerance at `<=105%`; complete 30/100-MB and 3x gates |
| security | one paired-history model/root-lifetime adaptive malicious-DV game covering all connections/MAC domains, collusion, concurrency, selective abort and every byte prefix; equality applies only to the witness-independent base frame while a named reduction covers all branch-derived IDs/receipts/heads; theorem scopes separate local MAC error, multi-user composition, honest-allocator privacy integrity and dishonest-prover receipt unforgeability; `Q_FS=0`; connection soundness/state and the separate composed model-lifetime privacy advantage each remain at least 78 bits without treating rate limits as cryptographic evidence |
| SIMT, if used | only after CPU pass; bit-exact leaves/root/multiproof/MAC/transcript/certificate/journal plus reconciled disk, H2D/D2H/D2D, RSS/VRAM, padding, launch and synchronization counters |
| lifecycle | two incremental responses, accepted predecessor/successor K/V, real finite PCG using only consumed profiles, abort burn and atomic promotion; rotation seals admission, resolves/burns all outstanding receipts, privately proves same-`W`, then atomically cuts over |
| verifier | canonical serialization, reload and full ordinary-CPU verification; mutation, replay, fork, truncation, reordered-prefix and configured-count-plus-one failures |

The four original query quantities are deliberately not one minimum.
`q_attempt[p]` is the fixed maximum census vector for each W/B/KV plane;
`q_response[p]` is the census
actually serialized by an accepted response; `Q_root` is the total charge
covered by the root-wide privacy theorem; and `R_root` counts every durable
attempt reservation, including failures and selective aborts.  With one fixed
profile,

```text
u_attempt = (u_W,u_B,u_KV_old,u_KV_new)
spent_root = attempts_reserved * u_W <= Q_root
q_response[p] <= q_attempt[p]                     # componentwise
R_root <= floor(Q_root / u_W).
```

The formula requires `0 < u_W <= Q_root`; every nonzero other component must
fit its separate `Q_B/Q_KV` horizon. A profile that cannot reserve one full
attempt is invalid, and the selected operational service floor must retain
positive privacy headroom.

The compiler defines a query atom in the exact ZK alphabet.  Opening a
141-scalar leaf for one sample charges 141 atoms unless the cited theorem
treats that complete block as one alphabet symbol.  Merkle siblings charge no
query atoms but do charge path/hash bytes.  Every attempt therefore records a
vector—not a scalar substitute—of logical PCS samples, visible masked
symbols/limbs, unique leaves, exact multiproof sibling nodes and attempt
reservations, both per transcript and as a per-plane union.  Proof size limits
the per-attempt vector, privacy limits `Q_root/Q_B/Q_KV`, setup limits root
construction/rotation, and online resource gates limit work; their units and
tolerances are not transferable.

The smallest valid local case must execute the whole lifecycle twice.  A
mock-PCG, component-only, analytic or public-WHIR result remains
`credit:false` and cannot establish `C7_LOCAL_READY`.  The future CPU reference
precedes that case and by itself earns no lifecycle/E2E credit.

## 3. CPU-first ladder and SIMT contract

1. Select a policy-2 PCS only after compiling its exact root-wide privacy unit,
   query counts, public salted-Merkle wire bytes, soundness floor, setup and
   rotation schedule.  A query answer count that grows materially with `N`
   fails even if its prover is fast.
2. Implement only the smallest CPU reference for a surviving structured
   algorithm and tiny canonical fixtures.
3. Record `C7_CPU_REFERENCE_PASS` only if code-derived
   `c_source*N+poly(q,log N)` and exact counters agree.
4. Only then implement the admitted SIMT stages and prove byte-exact
   CPU/SIMT equivalence.
5. Only then run scaled local integration; no complete GPT-2 locally.

R0.5 executed the earlier structure screen and a CPU fixture for the one-stage
RA dense exception.  Its counters
and tiny differential test pass the online algorithm shape, but its code
distance and streaming ordered-root gates fail.  Therefore step 3 did not
occur and steps 4--5 remain blocked.  A working component is not a passing PCS.
Its source is a borrowed `&[i16]`, so the one-pass/`2N` values are logical
access counts, not filesystem, RSS or `VmHWM` measurements.

The policy-2 CPU report must additionally prove that every query answer was
fixed by the canonical interactive schedule, came from the committed masked
oracle and was charged before disclosure to the root reservation.  It must
assert one source open/pass, monotonically increasing
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
measured.  CPU and SIMT must match masked leaf payloads, opened public salts,
digests/root/multiproof, exact finite-fixture PCG/VOLE values and consumption,
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
root budget manifest    complete omega/root-set and profile digests, authenticated
                        receipt-free request binding plus single-session
                        receipt lifecycle/cache schema, privacy
                        unit, plane charge vector, q_attempt, q_response,
                        Q_root, R_root, per-plane Q_B/Q_KV horizons including
                        aborted successors, budget-map high-waters, assignment
                        receipt, InitKVState and rotation carry-forward heads,
                        D_model and K_model
query census            plane-tagged logical samples, masked symbols/limbs, unique leaves,
                        exact sibling/path nodes, q_exposed and attempts; Q_FS=0
certificate census      six B_* components with every byte assigned once
security registry       named theorem/hypothesis, scope, repetitions and epsilon
resource report         passes, bytes read/written, peak RSS/device and wall phases
lifecycle journal       global omega reservation/receipt/high-water mark,
                        Reserved/InFlight/Burned/Accepted CAS and cached replies,
                        W/B/KV maps, pre-burned slot assignment before root
                        disclosure, InitKVState before genesis disclosure, full
                        burn, outstanding-at-seal resolution, private same-W
                        bridge, byte-identical state-map carry at cutover,
                        promotion and replay/fork decisions
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

Policy 2 removes the need to verify Poseidon2 privately: a public salted
BLAKE3 leaf/tree is eligible, with every opened payload, salt and path charged
to the certificate.  It does not yet supply collision binding, adaptive
root/path hiding or the joint root-wide t-query theorem.  Current blockers are
backend selection, exact plane/root/round query counts, transcript-bound
single-session receipts, branch-derived-view closure, response/K/V privacy
horizons and durable no-extension plane maps, distinct hash-work bounds, the cryptographic global counter,
genesis state-map initialization, rotation carry-forward, multi-user VOLE/MAC
composition and private stop-admit rotation bridge,
authenticated soundness/terminal privacy,
`C7_CPU_REFERENCE_PASS`, the compiled certificate census and all downstream
complete-chain evidence.  No prover, SIMT, provider or pod action is presently
valid.  A complete GPT-2 E2E remains pod-only after `C7_POD_READY` and a later
run-specific owner GO.

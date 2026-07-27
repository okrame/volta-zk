# VOLTA-ZK R1c — hostile security review report (X4/X4b/X4c implementation)

Adversarial, read-only review. No fixes implemented, no repository content or
ledger edited, no pod contacted. Passing tests and benchmark records were not
treated as security evidence by themselves; every load-bearing claim below was
re-derived from code and frozen specifications.

This review continues and completes the work begun under the original R1c
plan (an earlier review session stopped after the mandatory-reading and
chain-mapping phase; this report re-verified all of its intermediate
conclusions independently and completed the audit).

## 1. Reviewed baseline, target, clean-tree status

- Previous reviewed R1b baseline: `9b1ef2dc54f28113f86f00adaca9410251ede05e`
- Target (final HEAD): `aca34c2b4ba413eec2a83953c4770a52bf7636eb`
- X4c measurement source: `603d5a7b670ae9730a504ac39c6cf0bf7d4a8273`
- Review worktree: `/home/okrame/projects/volta-zk-r1c-review`, created with
  `git worktree add --detach` at exactly `aca34c2b4ba413eec2a83953c4770a52bf7636eb`;
  `git status --porcelain | wc -l` = **0** (clean) before beginning. The
  historical detached worktrees `volta-zk-r1-review` (`f05d727`) and
  `volta-zk-r1b-review` (`9b1ef2d`) were not modified.
- Review range: 76 commits, 110 files, +90,872/−50
  (`git diff --stat 9b1ef2d..aca34c2`).

Artifact locations and hashes were verified, not assumed (all match the
ledger pins at `docs/prototype-status.md:331-334,640-642`):

| artifact | SHA-256 (verified) | ledger pin |
|---|---|---|
| `benchmarks/results/x4b-a100-production-2026-07-22-6c6907a.json` | `63f4a97b…cfe6e0` | ✓ |
| `benchmarks/results/x4c-phase1-open-decomposition-2026-07-23-f772013.json` | `ca9841ff…52ebcf` | ✓ |
| `benchmarks/results/09-exact-size-lifecycle-probe-2026-07-24-603d5a7.json` | `148330b9…f4216` | ✓ |
| `benchmarks/results/10-x4c-onboarding-2026-07-24-603d5a7.json` | `401852b1…f18428` | ✓ |
| `benchmarks/results/11-x4c-online-2026-07-24-603d5a7.json` | `aa1aafc5…a03f98` | ✓ |
| `benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json` | `ba877223…ce56499` | ✓ (code-pinned at `x4c_pod_record.rs:50-52`) |

## 2. Files/commits reviewed and methodology

Mandatory reading completed: `CLAUDE.md`, `AGENTS.md`,
`docs/prototype-status.md` (full ledger incl. R1/R1b dispositions and the
2026-07-23 selected-tape correction at lines 626-688),
the then-current P7b contract now retained in that ledger,
`docs/x4-folding-pcs-design.md`,
`docs/x4c-io-lifecycle-design.md`, `docs/x4c-phase1-results.md`,
`docs/x4c-gpt2-e2e-handoff.md`, `docs/r1-kimi3-report.md`,
`docs/r1b-kimi3-report.md`, `docs/r1b-delta-handoff.md`, the immutable X4b
production record, and the three X4c records of record (09/10/11).

Commit groups in range (all cross-checked against the ledger): X4 first-oracle
mitigation addendum; R1b-amended folding-PCS design freeze; Amendments 3/4/5
Lean discharge (Lean files touched **only** by the five preregistered
amendment commits `fc05f10, 8383d42, 8578bfd, 3ca2a05, d5227f2` — no X4c
commit touches `lean/`); v4 schema/codec; X4 v4 CPU/pod records; X4b Phase
1/2; X4c Phase-1 postdiction; X4c canonical-byte diagnostic; selected-tape +
PCS-label correction; parallel rebuild authorization; X4c implementation and
records 09/10/11; ledger closure checkpoint.

Methodology: the lead reviewer personally traced the primary binding chain
(challenge timing → schedule digest → gather plan → CUDA runtime → canonical
bytes → verifier reconstruction/acceptance) end-to-end in
`rust/volta-pcs/src/x4/{x4c_v4,folding_v4,frame_v4,merkle_v4,accounting}.rs`,
`rust/volta-mac/src/transcript.rs`, `rust/volta-accel/src/lib.rs`,
`cuda/volta_cuda_backend.cu`, `cuda/volta_x4b.cuh`, and
`rust/volta-bench/src/bin/x4c_pod_record.rs`. Four parallel read-only
sub-audits covered: (A) direct-fold equivalence + LinkBad/ZeroBatch seam;
(B) CUDA kernels/FFI/unsafe inventory; (C) Merkle build side + fresh rebuild
+ durable source; (D) arena/pinned lifecycle + instrumentation/validator.
Every sub-audit finding cited below was re-examined by the lead reviewer;
load-bearing rejection boundaries (C-ABI op validator, Merkle reconstruction,
schedule digest, census/reset synchronization) were additionally spot-verified
firsthand. Bounded tests were run locally (§8); no production-size or pod
workloads were run.

## 3. Executive verdict

| severity | count |
|---|---|
| CRITICAL | **0** |
| MAJOR | **0** |
| MINOR | **7** (R1C-M1…M7) |
| NOTE | **12** (R1C-N1…N12) |

The primary security question — whether prover-controlled, stale, reordered,
truncated, duplicated, aliased or asynchronously updated state can make the
GPU gather return bytes for coordinates other than those dictated by the
verifier transcript while still passing canonical decoding and root checks —
was answered in the negative. The chain fixed-roots → verifier-owned draws →
schedule digest → gather indices → gathered bytes → canonical serialization →
verifier reconstruction holds at every seam audited, with exact rejection
boundaries enumerated in §6.

One preliminary suspicion carried over from the earlier session — that the
runner "loads the public Amendment-5 draw fixture before root sealing and
passes known draws into the non-interactive query API" constitutes a
challenge-ownership break — did **not** survive verification. It is the
preregistered, ledger-documented correction of the 2026-07-23 deviation
(`docs/prototype-status.md:639-649`), not a new defect: the frozen byte
budgets are tape-dependent, so any record of record must replay the selected
tape; the tape is BLAKE3-pinned and cross-checked against two independent
records; the draft exposes no query method; the sealed type (all fields
private, `x4c_v4.rs:1393-1407`) is consumed by `issue_queries_x4c`
(`x4c_v4.rs:1840`); verification uses the same tape
(`x4c_pod_record.rs:1611-1621`) and the harness cross-checks it
(`selected_query_tape_exact`, `x4c_pod_record.rs:1675`). What the recorded
execution is — and is not — is stated precisely in R1C-N1.

## 4. Architecture / binding diagram of the reviewed X4c path

```
 durable tier (5 coefficient files + 5 roots, nothing else)
   │  SHA-256 + length + canonical-limb checks (x4c_pod_record.rs:1128-1139,
   │  persisted_v4.rs:335-369)        [TOCTOU note R1C-N9]
   ▼
 fresh-process parallel rebuild (5 rayon tasks, indexed collect)
   │  NTT extend rate 1/8 → full N4 + outer cache in host RAM;
   │  per-cohort rebuilt root == durable root (x4c_v4.rs:3123-3136);
   │  any task failure ⇒ rebuild.accepted=false ⇒ hard gate (:1876-1879)
   ▼
 GlobalChainDraftV4 ──seal_interactive_x4c (x4c_v4.rs:1412)──► one device arena
   │  per round r=1..27: append line(32B) → draw fold challenge (verifier
   │  stream, transcript.rs:37) → direct fold of resident codeword (no E-NTT)
   │  + delayed-cohort activation → one-slot N4 root (frame r) → append rest
   │  diagnostic: min(64,out_len) samples/round, 1,592 total, ZERO soundness
   │  credit (x4c_v4.rs:2067); mismatch aborts seal (x4c_v4.rs:1638-1640)
   ▼
 SealedGlobalChainX4cV4  (roots fixed; query methods exist ONLY here)
   │  SelectedQueryTapeV4::release_after_roots (x4c_pod_record.rs:303)
   │  tape = pinned e29-r3-s111 draws (BLAKE3 3654af24…d299)
   ▼
 packed_schedule_from_verifier (folding_v4.rs:1617) ──► schedule digest
   binds profile|model_root|epoch|(cohort_id,root)×5|frames|draws|width
   (frame_v4.rs:810-834, OPENING_SCHEDULE_HASH_CONTEXT_V4)
   ▼
 X4cCanonicalGatherPlanV4::build (x4c_v4.rs:620)
   projected_query_indices(draws) → sorted-unique ±pairs per round
   (accounting.rs:36) → 53,898 ops; destinations tile the canonical template
   exactly (cursor end == len, :756; uniqueness+overlap :778-791,851-862)
   ▼
 C-ABI validator (volta_cuda_backend.cu:5953-6114): per-op geometry,
   per-class exact source derivation, monotonic non-overlapping in-mailbox
   destinations, round anchors (cohort/descriptor/offsets memcmp), intra-round
   ordering (volta_x4b.cuh:76-86) — then ONE DMA of 4,743,024 B op table
   ▼
 ONE batched kernel (gather_canonical_operations, volta_x4b.cuh:735-769):
   symbol copy 16B | cached digest 32B | rebuilt (level≤1) digest recomputed
   on-device with v4-domain-separated BLAKE3
   ▼
 synchronized D2H of exactly 2,615,414 B → decode → validate_against_schedule
   (frame_v4.rs:1452) → re-encode == bytes (x4c_v4.rs:1898-1905)
   ▼
 verifier (verify_global_folding_v4, folding_v4.rs:1484):
   schedule digest recomputed from VERIFIER draws == proof digest (:1502-1509)
   ∧ Merkle reconstruction of every opening vs fixed roots
     (merkle_v4.rs:628-830, per-node bound to cohort/role/kind/round/
      outer_index/level/node_index, exact cursor consumption :1134-1195)
   ∧ per-draw fold relation, 111 draws × 27 rounds (:1854-1926)
   ∧ final-constant check (:1553-1570)
   ▼
 reset_arena (full-capacity memset + real cudaStreamSynchronize boundary)
   → release_arena → census reconciliation (x4c_v4.rs:2745-2795)
```

## 5. Findings (ordered by severity)

No CRITICAL. No MAJOR.

---

### R1C-M1 — MINOR — The two X4c records of record (onboarding, online) have no fail-closed record validator

- **Where:** `scripts/report.py:5068-5080, 5170-5193` — only
  `validate_x4c_phase1_result`, `validate_x4c_legacy_causal_result` and
  `validate_x4c_lifecycle_probe_result` are dispatched. No
  `validate_x4c_onboarding_result` / `validate_x4c_online_result` exists;
  `tests/test_report.py` covers phase1/legacy-causal/lifecycle-probe only.
  Sub-points: the record's `ArenaRow` drops 18 of 32 census fields
  (`x4c_pod_record.rs:1351-1387`), so boundary identities (baselines,
  in-flight pinned, cached bytes) are not externally re-checkable; several
  zero-expected counters (`pinned_alloc_requests == 0`,
  `allocation_calls == 0`, `resident_reuse_hits == 1`, …) are recorded but not
  gated in `traffic_exact` (`x4c_pod_record.rs:1666-1671`).
- **Violated invariant:** review area 8 — "missing fields must reject, not
  default to zero; contradicting required fields must reject" — holds for the
  probe record (validated: §8) but is vacuous for records 10/11, whose gate
  verdicts (`overall_pass`) currently rest on the runner's own conjunctive
  computation plus the out-of-band ledger SHA-256 pins (verified intact, §1).
- **Attack/failure trace:** an auditor consuming `11-x4c-online-….json` cannot
  re-derive `overall_pass`; a malformed, mislabeled, re-ordered, or
  field-stripped record of this class passes every automated check that
  exists. No proof-acceptance path is affected: runtime enforcement (Rust
  census validators, runner conjuncts, session abort) is independent and was
  audited sound. Direction is fail-closed — nothing is falsely accepted — but
  the project's own evidence convention (every record of record has a
  fail-closed validator; ledger row: "Validated record …") is not met for the
  two records that ground the X4c PASS.
- **Tests:** do not catch it — the gap is invisible to CI (13/13
  `test_report.py` tests pass without any online/onboarding coverage).
- **Minimum remediation:** add `_x4c_online_result_valid` /
  `_x4c_onboarding_result_valid` mirroring the probe validator
  (ordinal/epoch binding, census cross-field identities, `query_gather_calls
  == 1`, `noncanonical_opening_d2h_bytes == 0`, hard-zero response I/O,
  `accepted == ∧ components`, GPU-UUID presence, onboarding→online pin chain);
  serialize the full census; extend `traffic_exact`. Apply the same discipline
  to the forthcoming real-weight E2E record **before** claiming it.

### R1C-M2 — MINOR — Zero-response-staging library counters are compile-time constants; the record gate is vacuous at library level

- **Where:** `x4c_v4.rs:2006-2007` —
  `let io = X4cResponseIoCountersV4::default(); io.validate_hard_zero()?;`
  The counters are never incremented anywhere in the library (only the struct
  definition `x4c_v4.rs:336-360` and test mutations `:3653-3665` exist), so
  `zero_response_staging = (metrics.io == default())`
  (`x4c_pod_record.rs:1672`) always passes by construction.
- **Violated invariant (intent):** "zero response coefficient/oracle/staging
  files or I/O" should be *measured* accounting, not a constant assertion.
- **Attack/failure trace:** a future regression adding an unreported file
  read/overlay reread inside `X4cRamModelGlobalCohortV4::open_initial_source`
  (one that forgets to populate `persisted_oracle_bytes_read`) keeps every
  record gate green. Current protection is real but lives elsewhere: RAM
  cohorts hold no `File` (`x4c_v4.rs:3081-3090`) and any reported persisted
  traffic fails closed (`x4c_v4.rs:1879-1886, 1748-1753`). Notably the runner
  already measures a `/proc/self/io` delta per response
  (`x4c_pod_record.rs:1552, 1731`) but never gates `accepted` on it.
- **Tests:** `response_io_hard_zero_rejects_every_legacy_artifact_class` only
  exercises the validator on hand-mutated structs.
- **Minimum remediation:** gate `accepted` on the measured process-I/O delta
  (expected-zero response-window read bytes), or delete the constant counter
  in favor of the measured snapshot.

### R1C-M3 — MINOR — One-shot correlation/challenge/epoch freshness is enforced only within live instances; cross-instance retry safety is caller discipline

- **Where:** challenge stream is seed-deterministic
  (`rust/volta-mac/src/transcript.rs:20-44`); mock-PCG domain re-open panics
  (`rust/volta-mac/src/corr.rs:230-233`); opening registry is per-instance
  (`authenticated_output_v4.rs:237-247`). In-repo callers create fresh
  instances per response with per-ordinal seeds/epochs
  (`x4c_pod_record.rs:1537, 1550`; `x4_v4_report.rs:292-296,343,390-391,424`).
- **Violated invariant (if misdeployed):** "retries cannot reuse challenges
  or one-time correlations."
- **Attack trace (out-of-tree deployment only):** a verifier that abandons a
  failed response and retries the same `(model_root, epoch)` with **fresh**
  instances but the **same** seeds replays the identical challenge tape
  (appends only charge bytes) and re-expands identical mock correlations; a
  prover that observed attempt 1 can then deterministically survive attempt
  2's terminal zero-open. Intra-instance reuse is impossible (ledger panic).
- **Tests:** all one-shot tests are intra-instance; no cross-instance reuse
  test exists. In-repo harnesses are safe by construction.
- **Minimum remediation:** the real-weight E2E runner must derive
  per-response seeds/domains (e.g. `ConnectionCorrelationScope`) and persist
  `X4OpeningRegistryV4` across retries of the same model; document (or
  type-encode) that fresh-instance-plus-seed-reuse is forbidden.

### R1C-M4 — MINOR — Arena census `zeroed_bytes`/`committed`/`peak` are asserted from layout constants, not cross-read from native counters

- **Where:** `x4c_v4.rs:2411-2421` (`zeroed_bytes: if proof_ready { 0 } else
  { layout.capacity_bytes }`, committed/peak = capacity).
- **Violated invariant:** census as *measured* ownership evidence.
- **Failure trace:** a native regression that reports reset success without
  zeroing would still yield `zeroed_bytes == capacity` and pass
  `validate_session_reusable`. Mitigant today: `reset_arena` propagates
  native failure (`x4c_v4.rs:2768-2773`) and the runner independently
  requires `stats.x4c_arena_reset_bytes == stats.device_zeroed_bytes ==
  X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4` in `traffic_exact`
  (`x4c_pod_record.rs:1666-1671`) — so no live discrepancy; latent
  single-point-of-truth weakness.
- **Tests:** CPU census tests use `accelerator_available: false` semantics;
  nothing forces census/native agreement.
- **Minimum remediation:** have `census()` cross-read `backend.stats()` and
  require equality instead of fabricating the fields.

### R1C-M5 — MINOR — Leak-on-double-failure: no `Drop` for device/pinned buffers; reset-then-release cleanup can strand 43.5 GB and poison the runtime

- **Where:** `cleanup_failed_x4c_arena_v4` (`x4c_v4.rs:2074-2090`);
  `release_arena` rejects when `!arena.reset` (`x4c_v4.rs:2785-2791`);
  `X4cCudaArenaV4`/`DeviceBuffer`/`PinnedHostBuffer` have no `Drop`.
- **Violated invariant:** "cleanup behavior after every partially successful
  native operation" / "check all failure paths".
- **Failure trace:** CUDA fault during seal/gather → reset's memset/boundary
  fails → `arena.reset` stays false → cleanup's `release_arena` rejects →
  buffer dropped unfreed; native `active_device_allocations` stays +1,
  `arena_live` stays true; combined error is honestly returned but the runtime
  is unrecoverable short of process exit (`allocate_arena` and
  `begin_response_measurement` reject). Same shape if `free_device` itself
  fails after `take()`. Mid-session abort also skips `release_pinned_pool`
  (`x4c_pod_record.rs:1987-1995`), stranding the ~1.09-GB pinned pool until
  context destroy. Fail-closed, availability-only; no stale data reaches any
  future response.
- **Tests:** no double-failure injection test.
- **Minimum remediation:** best-effort force-free on error/Drop that bypasses
  the reset precondition.

### R1C-M6 — MINOR — Kernel discards device-side rebuild failure and writes a zero digest

- **Where:** `cuda/volta_x4b.cuh:759-763` —
  `(void)rebuild_one_slot_outer_digest(...)`; on failure the kernel writes
  `Hash32{}` (32 zero bytes) into the template destination.
- **Violated invariant:** a failed gather op must not produce output.
- **Attack/failure trace:** the device predicate (`level > 1 || index >=
  outer_len >> level`, `cuh:504-506`) exactly duplicates the host validator
  (`volta_cuda_backend.cu:6062-6065`) over the same bytes, so the branch is
  dead-by-construction; it could fire only if the pinned op table changed
  between validation and DMA (prevented by in-flight pinned events,
  `volta_cuda_backend.cu:6126, 5933-5936, 3510-3511`). If it ever fired, the
  zero sibling digest passes all prover-side checks (structure-only, R1C-N6)
  and is rejected at verification — prover liveness, never soundness.
- **Tests:** positive-path gather/N4 differentials exist
  (`x4c_v4.rs:3531, 3687`); the swallowed branch has no negative test.
- **Minimum remediation:** trap or bump a device error counter the host reads
  after the D2H sync; at minimum document the deliberate duplication.

### R1C-M7 — MINOR — Durable-tier exactness is audited only for expected filenames; no directory census

- **Where:** onboarding reports `durable_*_file_count` as literals
  (`x4c_pod_record.rs:1050-1052`) and `durable_tier_exact` sums only the 10
  expected paths (`:1029`); online probes only `cohort/oracle.bin` by name
  (`:1171`).
- **Violated invariant (literal):** "the durable tier must contain only five
  coefficient files plus five roots."
- **Attack/failure trace:** a stray file under any other name
  (`oracle.bin.bak`, `fold-*-oracle.bin`, a `staging/` dir) inside the durable
  root is never detected by either side. No protocol consequence today:
  onboarding creates fresh directories and writes oracle only to scratch
  (`:954-955, 762-771`), and the response path never re-reads the tier
  (RAM cohorts; R1C-M2's structural protection).
- **Tests:** none cover stray files.
- **Minimum remediation:** online-side directory census (exactly five cohort
  dirs × exactly `{coefficients.bin, root.bin}`) folded into
  `rebuild.accepted`.

---

### R1C-N1 — NOTE — Recorded runs replay a public fixture tape and a fixed challenge seed: the record is a cost/correctness measurement, not a soundness experiment

- **Where:** tape loaded at process start from a public record
  (`x4c_pod_record.rs:48-54, 232-306`), released only against a sealed state
  (`:303`, called `:1572`); verifier seed `[0x70+ordinal; 32]` (`:1550`).
- **Facts:** the frozen byte budgets are tape-dependent (multiproof frontier
  sharing), so the selected `e29-r3-s111` tape must be replayed for any
  byte-exact record — this is the preregistered correction of the 2026-07-23
  deviation (`docs/prototype-status.md:639-649`). The tape being publicly
  known before sealing means the recorded run cannot instantiate the
  query-unpredictability soundness game; soundness rests on the Lean
  discharge + design analysis + the verifier code's actual binding to
  verifier-owned draws (all verified, §6). This is the same declared modeling
  boundary class as R1's N5 (single-process two-role harness; seeded-stream
  DV challenges, `docs/r1-kimi3-report.md:143-153`). The ledger's language is
  consistently careful ("no soundness change"; gates are
  byte/root/ownership/timing) — keep it that way for the real-weight E2E
  record: it must not be cited as soundness evidence.

### R1C-N2 — NOTE — `release_after_roots` binds the tape to the sealed state only at the type level

- **Where:** `x4c_pod_record.rs:300-305` (`_sealed` unused).
- Structurally sound (a sealed value can only be obtained via the seal path;
  fields are private), and the tape is BLAKE3-pinned; but the same tape would
  be released against *any* sealed state (wrong model/epoch would not be
  resisted at this seam — the schedule digest binds model_root/epoch at
  verification, so acceptance is unaffected). Optional hardening: assert
  sealed `model_root`/`epoch` against expected values inside
  `release_after_roots`.

### R1C-N3 — NOTE — CPU↔CUDA direct-fold differential samples lengths; outputs 32/16/8 are covered only indirectly

- **Where:** `x4c_v4.rs:3350, 3386-3399`;
  `scripts/check_x4c_cuda_host_reference.sh` — differential lengths log2 ∈
  {3, 8, 12, 16, 20}. Production inputs 2^4…2^7 (outputs 32/16/8) and
  2^21…2^30 are not in the CPU↔CUDA differential; the last four rounds get
  100%-coordinate on-pod parity (`x4c_v4.rs:1100`) and the small-chain CPU e2e
  exercises real verification (`x4c_v4.rs:3906-4036`). The kernel is
  length-generic (`volta_x4b.cuh:642-669`) and acceptance never rests on the
  differential. Cheap hardening: extend the differential to log2 ∈ {4,5,6,7}.

### R1C-N4 — NOTE — The parity diagnostic is a per-round local differential, not a track-to-track binding

- **Where:** `x4c_v4.rs:1586-1640` — for rounds ≥ 1 both sides of the
  comparison are gathered from the device; only round 0 ties device output to
  host input. A device fault at an unsampled coordinate propagates
  self-consistently; it is caught only by the verifier's queried fold
  relation (priced in the frozen soundness expression) — never by the
  diagnostic. This is as designed (zero soundness credit,
  `x4c_v4.rs:2067, 1389-1390`; record gate `:1686-1689`); document the
  locality in the diagnostic's doc comment so "byte-identity oracle"
  (`:1237-1239`) is not over-read.

### R1C-N5 — NOTE — Cross-family correlation-domain disjointness is unvalidated; collision fails by uncaught panic

- **Where:** only the 2·round_count link domains are validated
  (`authenticated_output_v4.rs:526-534`); M9 domains (`:106-148`) and the
  zero-batch mask domain (`:1092-1165`) are caller-supplied and unchecked
  against each other. Collision → ledger panic (`corr.rs:230-233`) —
  fail-closed but a panic on configuration-controlled input (server DoS
  hygiene). Validate disjointness in `validate_prefix_common_v4` or return
  errors.

### R1C-N6 — NOTE — Prover-side canonical checks bind structure, not payload values

- **Where:** `x4c_v4.rs:1898-1905` + `frame_v4.rs:1452-1516` — decode,
  schedule-digest/count equality, re-encode byte-compare. Structurally valid
  but value-wrong device output (permutation, zeros) passes all three and is
  caught only by the verifier's root recomputation — by design
  (`materialize_x4c_gather_plan_cpu_v4` is "not the production path",
  `x4c_v4.rs:956-957`). Consequence class is prover liveness only. Related:
  `BoundAuxEval*` values carry no `(model_root, epoch)` tag
  (`authenticated_output_v4.rs:72-104`); in-repo callers scope them per
  response (`x4_v4_report.rs:435-448`).

### R1C-N7 — NOTE — `verify_global_folding_v4` is geometry-generic; the final output_log2 = 3 is pinned by callers, not the verifier

- **Where:** frame chain checks `folding_v4.rs:1540-1549` enforce
  input/output consistency but not the terminal length; production geometry
  is pinned prover-side (`x4c_v4.rs:2008`, seal config
  `folding_v4.rs:948`) and by the envelope statement
  (`frame_v4.rs:1921-1942`). A chain ending above 2^3 still verifies and
  remains binding; integration must keep pinning the profile geometry (as
  the record and the E2E envelope do).

### R1C-N8 — NOTE — Gather kernels perform no device-side bounds re-check

- **Where:** `cuda/volta_x4b.cuh:721-730, 735-769` — raw arena base + op
  offsets; only `operation_index >= operation_count` early-returns (cannot
  skip a valid op). The host C-ABI validator bounds everything and the
  validated bytes are the DMA'd bytes (in-flight event discipline); mailbox
  vs codeword/cache/scratch disjointness is validated
  (`volta_cuda_backend.cu:6001-6014`). Defense-in-depth only: optionally pass
  capacity/mailbox range as kernel arguments with an error flag.

### R1C-N9 — NOTE — Durable-source TOCTOU windows, all cryptographically fail-closed

- **Where:** coefficient digest check (`sha256sum` subprocess,
  `x4c_pod_record.rs:132-138, 1129-1132`) precedes the independent re-read
  (`persisted_v4.rs:335-369`) — a same-inode swap between the two yields
  bytes never digest-checked, but the consumed bytes must Merkleize to the
  durable root (`x4c_v4.rs:3123-3136`), itself pinned twice
  (`x4c_pod_record.rs:1128, 1133-1136`); non-canonical limbs/trailing bytes
  fail earlier (`persisted_v4.rs:92-96, 364-367`). Spec↔record pairing is
  positional (`:1213-1218`) with `recorded["cohort_id"]` never asserted —
  permuted records fail closed at root equality and cohort-id-bound hashing.
  No uid/mode verification of the durable tier; the online path pins the
  onboarding record SHA only out-of-band (ledger) while the diagnostic path
  pins it in-code (`:1854-1857`). Optional: single-pass read-and-hash;
  per-task cohort_id assertion; `--expect-onboarding-sha256` for online.

### R1C-N10 — NOTE — Exactly-one-GPU is enforced at the harness level, not the library

- **Where:** `volta_cuda_backend.cu:2996-3021` uses the runtime current
  device and checks no UUID; the record harness pins a single-entry
  `CUDA_VISIBLE_DEVICES` resolved via `nvidia-smi --id=` with name check and
  UUID record (`x4c_pod_record.rs:425-454`; ledger-pinned
  `GPU-3286abe4-…-7f6059`). With one visible device, logical 0 ≡ that
  physical GPU. A non-record multi-GPU caller would silently land on device
  0; optional: record `cudaGetDevice`/UUID at create and expose it in the
  control state.

### R1C-N11 — NOTE — Spec constants are duplicated across device and host hash implementations

- **Where:** device BLAKE3 flags/magic/context strings/`PRIMITIVE_ROOT_2_33`
  (`volta_x4b.cuh:22-23, 233-237, 371-377, 535-538`) vs host
  (`frame_v4.rs:20-59, 403-405`; root by deterministic search
  `ntt.rs:24-44`). Compared field-by-field (field order, LE encodings, flags,
  context strings, key usage, tree-role/kind tags, u64::MAX binding) — no
  divergence; `φ²=7` matches `volta-field`; c0‖c1 u64 LE matches
  `#[repr(C)] Fp2Repr` (`volta-accel/src/lib.rs:393-398`). A same-direction
  typo on both sides would stay self-consistent; only the byte count is
  Lean-pinned (`lean/VoltaZk/X4FoldingPCSV4.lean:951`), the strings are not.
  One-line spec anchor would close the residue.

### R1C-N12 — NOTE — Test-coverage and hygiene residues (no current security consequence)

- Thin negative coverage at the C-ABI validator: one positive FFI gather test
  (`volta-accel/src/lib.rs:6464-6540`); rejection paths are covered only
  off-device (`scripts/check_x4c_cuda_host_reference.sh:235-262`).
- Non-production `x4c_batch_gather_bytes`: O(n²) destination-overlap loop and
  implicit `size_t`→grid narrowing (`volta_cuda_backend.cu:5862-5891`);
  bounded in practice (≤ ~1.7e9 requests), unused by production X4c.
- Gather plan hardcodes the omitted-level cutoff `level <= 1`
  (`x4c_v4.rs:717`) rather than deriving it from
  `OuterCachePolicyV4::RAM_DEGADED_ONE_LEVEL` — consistent with the fold
  layout (retains levels 2..=depth, `:236-253`) but a latent coupling.
- Proof-ready stream idleness is inherited from the D2H's synchronizing side
  effect; it is genuinely *verified* (`cudaStreamQuery`,
  `volta_cuda_backend.cu:3354-3365`) and fail-closed
  (`x4c_v4.rs:443-444`) — flag for future refactors that might make the
  download non-synchronizing.

## 6. Attempted attacks that appear correctly rejected (exact boundaries)

Adversarial families from the review mandate, each traced to its rejection
boundary:

1. **Selected tape changed after roots are fixed** — verifier recomputes the
   schedule digest from its own draws and compares to the proof's
   (`frame_v4.rs:1458`); the digest covers the ordered draws, roots, epoch,
   model root (`frame_v4.rs:810-834`). Record-level cross-check:
   `selected_query_tape_exact` (`x4c_pod_record.rs:1675`).
2. **Query order permutation with the same multiset** — digest is over the
   ordered tape; openings are consumed in sorted projected order at
   reconstruction (`merkle_v4.rs:691-731, 792-815`); per-draw chain iterates
   the verifier's ordered tape (`folding_v4.rs:1875`).
3. **Duplicate query substituted for a distinct query** — tape uniqueness is
   not assumed (replacement=true); the projected set dedups
   (`accounting.rs:46-52`) while the digest binds the full ordered multiset;
   a substituted tape ≠ verifier digest → reject (`frame_v4.rs:1458`).
4. **One gather index shifted across a frontier-class boundary** — per-class
   exact source derivation at the C-ABI validator
   (`volta_cuda_backend.cu:6017-6065`), plan-side source bounds
   (`x4c_v4.rs:792-849`), and the coordinate is bound inside the leaf hash
   (`outer_index` in `frame_v4.rs:599, 703`), so wrong-coordinate bytes fail
   root reconstruction.
5. **Correct symbol with wrong inner path** — inner nodes bind
   `outer_index/level/node_index/TreeRole::Inner`
   (`frame_v4.rs:682-713`); tamper tests
   (`merkle_v4.rs:1262-1298`).
6. **Correct inner path with wrong omitted outer node** — omitted levels are
   `None` and error on cached read (`merkle_v4.rs:169-181, 225-227`); level
   ≤ 1 digests are rebuilt with byte-identical hashing
   (`merkle_v4.rs:590-623`); root equality under both policies tested
   (`merkle_v4.rs:1374-1418`); device rebuilt digest verified against CPU
   oracle (`x4c_v4.rs:3531-3590`).
7. **Correct bytes returned in noncanonical order** — destinations strictly
   monotonic non-overlapping (`volta_cuda_backend.cu:6074-6083`;
   `x4c_v4.rs:851-862`); decode + re-encode equality
   (`x4c_v4.rs:1903-1905`); canonical order per round
   (`volta_x4b.cuh:76-86`).
8. **Stale arena contents from the preceding response** — release requires a
   completed reset (`x4c_v4.rs:2785`); reset = full-capacity
   `cudaMemsetAsync` + `cudaStreamSynchronize`
   (`volta_cuda_backend.cu:6167, 6174-6183`); every proof-read byte is
   rewritten this response (full template H2D `x4c_v4.rs:2648-2654`;
   codewords folded; N4 cache fully written `:2591-2595`); all arena ops
   reject post-reset (`:2488, 2525, 2548, 2582, 2615, 2635`).
9. **Gather launched before reset/synchronization completes** — single
   stream ordering; census requires `outstanding == 0` **and**
   `cudaStreamQuery == Idle` (`x4c_v4.rs:443-444, 2409-2410`); reset
   boundary is a real sync; `stats.synchronization_reason_total ==
   synchronizations` cross-check (`volta_cuda_backend.cu:3245`).
10. **One rebuild cohort result substituted for another** — rayon indexed
    collect + ordinal assertion (`x4c_pod_record.rs:1224-1230`); canonical
    cohort-order and duplicate re-validation
    (`folding_v4.rs:1684-1697`); cohort-id-bound hashing
    (`frame_v4.rs:599, 703`).
11. **Coefficient file changed after digest validation** — rebuilt root must
    equal the durable root (`x4c_v4.rs:3123-3136`); canonical-limb and exact
    length checks (`persisted_v4.rs:92-96, 335-369`); zero root rejected
    (`x4c_v4.rs:3128`).
12. **One task fails after four rebuild tasks succeed** — first error aborts
    (`result?`, `x4c_pod_record.rs:1224`); any non-accepted row ⇒
    `rebuild.accepted = false` ⇒ hard gate before CUDA work
    (`:1245-1263, 1876-1879`).
13. **Pinned buffer contains a longer previous response tail** — H2D window
    == D2H window == `template.len()` (`x4c_v4.rs:2647-2653, 2736-2741`);
    writes bounds-checked against `logical_bytes`
    (`volta_cuda_backend.cu:538-548`); in-flight overwrite rejected twice
    (Rust `wait_pinned_host_ready` + native ready check
    `:3508-3511, 5933-5936`); generational ids (`:296-309, 523-536`).
14. **CUDA kernel reports success after partial output** — launch errors
    checked (`cudaPeekAtLastError` after every launch sequence); async
    faults surface at the mandatory synchronized D2H
    (`volta_cuda_backend.cu:1236-1258, 1154-1181, 843`); nonzero rc maps to
    `AccelError::Cuda` with `last_error` (`cuda.rs:1366-1373`); any
    unfilled payload byte remains template-zero and fails verification
    (Merkle/fold relation), never acceptance.
15. **Missing counter encoded as zero** — where validators exist, missing
    key ⇒ fail (`report.py:1255-1261`, tested); zero-with-unavailability
    requires explicit `{available: false, reason}` and forces obstruction
    semantics (`report.py:1263-1270, 1873-1890`). **Exception: R1C-M1** for
    the two record classes without validators.
16. **Response staging file created and deleted between snapshots** — X4c
    response path performs zero protocol file I/O by construction (RAM
    cohorts, `x4c_v4.rs:3081-3090`); persisted-traffic assertions fail closed
    (`x4c_v4.rs:1879-1886, 1748-1753`); probe validator reconciles
    create/delete ledgers at every boundary
    (`report.py:1486-1498, 2059-2064`). Residual counter vacuousness:
    **R1C-M2**.
17. **Diagnostic samples all pass while an unsampled fold coordinate is
    wrong** — acceptance never references the diagnostic: it is a seal-abort
    differential only (`x4c_v4.rs:1638-1640`),
    `sampling_soundness_credit_bits == 0` hard-coded (`x4c_v4.rs:2067`) and
    gated in the record (`x4c_pod_record.rs:1689`); a wrong committed
    coordinate is caught exactly when queried (fold relation
    `folding_v4.rs:1917-1921`) and otherwise priced in the frozen soundness
    expression.
18. **LinkBad/ZeroBatch ordering or challenge replay** — bound values are
    constructible only after the terminal zero-open
    (`authenticated_output_v4.rs:1078-1089`; sole constructor sites
    `:953, :1085`; pending types expose no accessors); mask correction is
    appended before χ is drawn (`:1117-1120` vs `:1155-1159`); one opening
    per `(model_root, epoch)` (`:237-247`, `EpochAlreadyOpened`);
    beta-collision/delta-shift are permanent negative artifacts
    (`:1556-1590`); the four response-wide event owners remain exactly
    Fold/ClaimReduce/LinkBad/ZeroBatch inside the closed 17-family inventory
    (`security_v4.rs:8-26, 151-166`). Cross-instance retry: **R1C-M3**.
19. **Correlation authorization reused after retry or abort** — intra-instance
    reuse panics (`corr.rs:230-233`); drawn correlations survive reservation
    abort (`corr.rs:779-782`); consumption counted and reconciled both sides
    (`authenticated_output_v4.rs:305-319, 1449-1450`). Cross-instance:
    **R1C-M3**.

Additionally re-verified firsthand: challenge timing — query methods exist
only on the sealed type (`x4c_v4.rs:1819-1840`), whose fields are all
private and whose only constructor is the seal path (`x4c_v4.rs:1429`);
`issue_queries_x4c` consumes `self` (no double-tape reuse of one sealing);
the draft rejects pre-seal queries (`folding_v4.rs:715-717`
`EarlyQueryRejected`); no query-dependent upload occurs during seal
(diagnostic indices derive from design/source SHA + ordinal + round +
challenge + root — `x4c_v4.rs:1082-1140` — never from the tape).

## 7. Frozen-invariant table

| invariant | status | evidence |
|---|---|---|
| protocol profile `x4-zkdeepfold-ud-e29-v4` | unchanged | `PROTOCOL_PROFILE` (`x4c_pod_record.rs:316`); migration reference field checks (`:314-330`) |
| rate exactly 1/8 | unchanged | `X4C_RATE_V4` (`x4c_v4.rs:40`); fixture row `rate: "1/8"` verified |
| query count s = 111 | unchanged | `X4C_QUERY_COUNT_V4` (`x4c_v4.rs:41`); fixture has exactly 111 draws, all unique, max 1,070,288,806 < 2^30 (verified) |
| complete PCS = 2,683,236 B | unchanged | `X4C_COMPLETE_PCS_BYTES_V4` (`x4c_v4.rs:84`); identity `2,615,414 + 67,822` holds (`:79-80`) |
| packed opening = 2,615,414 B | unchanged | `x4c_v4.rs:79`; Lean-pinned (`X4FoldingPCSV4.lean:951`) |
| complete response = 43,953,700 B | unchanged | `x4c_v4.rs:85`; asserted in `accepted` (`x4c_pod_record.rs:1684`) |
| query draws unavailable until every root is fixed | preserved (typestate) | private-field sealed struct (`x4c_v4.rs:1393-1407`); single construction site (`:1429`); consuming query method (`:1840`); Lean seal-before-query theorem (ledger row 326) |
| exactly one batched GPU gather | unchanged | `query_gather_calls: 1` (`x4c_v4.rs:1991`); single `x4c_batch_gather_canonical_operations` call per response (`:2727`) |
| zero response coefficient/oracle/staging files or I/O | preserved structurally; see R1C-M2 | RAM cohorts hold no `File` (`x4c_v4.rs:3081-3090`); persisted-traffic rejections (`:1879-1886, 1748-1753`) |
| direct fold of the already-encoded codeword; zero response-round E-NTTs | unchanged | fold≡coefficient-fold+re-encode identity tested (`ntt.rs:256-263`); `ntt_calls` counted only at onboarding; seal uses direct folds only (`x4c_v4.rs:2481-2539`) |
| one reusable arena | unchanged | one device allocation per response from the cached arena (`x4c_v4.rs:2456-2479`); reset+release reconcile |
| proof_ready_wall and teardown-inclusive session_reusable_wall both counted | unchanged | `x4c_v4.rs:1927, 1958-1962`; lifecycle probe validator requires both (`report.py:2027, 2074, 2101, 2121`) |
| no protocol/codec/proof-format/root-semantics/Lean/soundness change | unchanged | `lean/` touched only by the five preregistered amendment commits; soundness expression fixed at 80.25537016399041 bits (ledger); codec/schema constants frozen (`frame_v4.rs`) |
| diagnostic parity = zero soundness credit | unchanged | hard-coded 0 (`x4c_v4.rs:2067`); gated (`x4c_pod_record.rs:1689`) |
| `min(64, output_len)` unique diagnostic coordinates/round | unchanged | `x4c_v4.rs:1100`; uniqueness via `seen` set (`:1102-1125`) |
| exact production diagnostic total = 1,592 | unchanged | `x4c_v4.rs:48-49`; test (`:3645`); gated (`x4c_pod_record.rs:1686-1688`) |
| historical X4 and X4b FAIL verdicts immutable | untouched | no ledger edit by this review; records verified byte-identical (§1) |
| old X4b 6.57-s production-host cause remains OPEN | untouched | no timing claim made or relied upon in this review |
| gather ops = 53,898 / op-H2D = 4,743,024 B / canonical D2H = 2,615,414 B / noncanonical D2H = 0 | unchanged | `53,898 × 88 = 4,743,024` (op size asserted `volta-accel/src/lib.rs:434`); counters `x4c_v4.rs:1992-2003`; record 11 fields |

## 8. Test and static-analysis commands run (exact results)

No production-size or pod workloads were run.

- `git worktree add --detach /home/okrame/projects/volta-zk-r1c-review aca34c2…`; `git rev-parse HEAD` → `aca34c2b…7636eb`; `git status --porcelain | wc -l` → **0**.
- `sha256sum` on the six mandatory artifacts → all match ledger/code pins (§1).
- `git diff --stat 9b1ef2d..aca34c2` → 110 files, +90,872/−50; `git log --oneline 9b1ef2d..aca34c2 | wc -l` → **76**.
- `git log --oneline 9b1ef2d..aca34c2 -- lean/` → exactly the five preregistered amendment commits (`fc05f10, 8383d42, 8578bfd, 3ca2a05, d5227f2`).
- `python3 scripts/report.py --validate-x4c-lifecycle-probe benchmarks/results/09-…-603d5a7.json` → **valid, rc=0**.
- `python3 scripts/report.py --validate-x4c-phase1 benchmarks/results/x4c-phase1-…-f772013.json` → **valid, rc=0**.
- `pytest tests/` (main repo, has generated `.venv`/weights) → **36/36 pass**. In the fresh review worktree → 32 pass, 4 fail; all four are missing *generated* artifacts (`benchmarks/weights/gpt2s-q.bin`, `.venv/bin/python`), reproduced as environmental by running the same suite in the R1b worktree (28 pass/1 pre-existing environment failure) and in the main repo (36/36). **No code regression.**
- `pytest tests/test_report.py` (main repo) → **13/13 pass** (matches the ledger's "13 report-validator tests"; none cover online/onboarding — R1C-M1).
- `cargo test --workspace` (review worktree) → **all suites ok, 326 passed / 0 failed / 4 ignored, exit 0**; no `#[ignore]` attributes exist in the X4/X4c/volta-accel modules (ignored tests are pre-existing ignores in earlier-milestone harnesses).
- Fixture interrogation (node): Amendment-5 row `e29-r3-s111` → rate `1/8`, 111 draws, draw_width 30, replacement true, `ordered_draws_blake3 = 3654af24…d299`, all draws unique, max draw 1,070,288,806 < 2^30.
- Unsafe/FFI inventory: `unsafe` count 0 in `rust/volta-accel/src/lib.rs`; 358 in `rust/volta-accel/src/cuda.rs` (dlopen loading + thin checked FFI wrappers, audited); the only `unsafe` in volta-pcs are two range-checked `posix_fadvise` calls (`cuda_v4.rs:1097-1113`, `persisted_v4.rs:39-60`); 98 added lines in range contain `unsafe` (the FFI wrapper layer).
- Constant spot-checks: op struct 88 B (`lib.rs:434` static assert); `X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4 = 2,615,414/16 = 163,463 ≥ 53,898` (`x4c_v4.rs:89-90`); pinned pool = ring 2 + template + operations = 4 buffers (`x4c_v4.rs:88`; census requires `X4C_PINNED_TRANSFER_RING_V4 + 2` at `:439`); durable tier = 9,618,587,648 + 160 = 9,618,587,808 B (`:74-77`).

## 9. Residual risk

- **Cryptographic reasoning.** The prototype models interactive DV challenges
  as a seeded stream (`transcript.rs:1-8`); any Fiat–Shamir deployment needs
  new analysis (R1-N5, unchanged). Recorded executions replay a public tape
  and fixed seed: they are cost/correctness measurements and must never be
  cited as soundness evidence (R1C-N1). The mock-PCG and the GKWY
  correlation-robustness assumption remain as registered in earlier reviews.
  Cross-instance retry safety is deployment discipline (R1C-M3).
- **CUDA/unsafe implementation.** Device/host hash equivalence is enforced
  by differentials that sample lengths (R1C-N3) and by duplicated constants
  (R1C-N11); the device has no independent bounds re-check (R1C-N8) and one
  dead-by-construction swallowed error (R1C-M6). Kernel fault consequences
  are liveness-only because value binding lives at the verifier (R1C-N6) —
  this asymmetry is load-bearing and should survive future refactors.
- **Lifecycle/accounting.** The two records of record lack validators
  (R1C-M1); some census fields are asserted rather than measured (R1C-M4);
  the zero-staging counter is vacuous at library level (R1C-M2);
  double-failure cleanup strands resources (R1C-M5); durable-tier exactness
  is filename-scoped (R1C-M7). None create an acceptance path, but each
  weakens the evidence trail the ledger relies on.
- **AI-review limitations.** The review audited code at the pinned SHAs, not
  the pod executions; record contents were hash-verified and
  validator-checked where validators exist, but the online/onboarding gate
  arithmetic was re-derived from runner code, not re-executed at production
  scale. Sub-audit decomposition could miss cross-area interactions; the
  lead reviewer mitigated by personally tracing the primary seam end-to-end
  and spot-verifying every load-bearing boundary cited. Lean theorems were
  treated as frozen inputs (their audit history is in the ledger), not
  re-proved.

## 10. Final recommendation

**CONDITIONAL GO AFTER LISTED DISPOSITIONS**

No CRITICAL or MAJOR finding: the post-R1b X4/X4b/X4c implementation
preserves the frozen protocol and soundness arguments, and the complete
binding chain from fixed roots through the GPU gather to verifier acceptance
is intact. Proceeding to the separately recorded real-weight GPT-2 small E2E
integration is safe **after** these dispositions, each bounded and none
requiring protocol, codec, root, Lean or soundness changes:

1. **D1 (R1C-M1):** implement fail-closed `scripts/report.py` validators for
   the X4c onboarding and online record classes (with the full census
   serialized), and apply the same validation discipline to the forthcoming
   real-weight E2E record before claiming it.
2. **D2 (R1C-M3):** codify in the E2E runner: per-response seed/epoch
   derivation and a persistent `X4OpeningRegistryV4` across retries; document
   that fresh-instance-plus-seed-reuse is forbidden.
3. **D3 (R1C-M2):** make the zero-staging gate real — gate `accepted` on the
   measured per-response process-I/O delta — or remove the vacuous counter.
4. **D4 (R1C-M4…M7, R1C-N1…N12):** record these in the ledger deviations log
   as accepted hardening backlog; R1C-N1's claims-hygiene rule (records are
   not soundness experiments) must accompany any E2E record announcement.

Historical X4/X4b FAIL verdicts and the OPEN X4b 6.57-s cause are untouched
by this review.

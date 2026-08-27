# C6.4 — projected residual PCS recovery

**Status:** R3 first pod attempt failed before proof at setup-bundle dispatch;
shared repair tested; one create-new second attempt owner-authorized.

**Branch:** `agent/c64-joint-residual-sketch`.

## 0. Objective and authorization

C6.4 is isolated from C7. It targets two complete GPT-2 certificates,
`0 -> 150` and `150 -> 200`, with response prover time below `20.000 s` on
one A100 and complete certificate size at most `35,000,000 B`.
`30,000,000 B` is diagnostic only.

Local design, implementation and bounded tests are authorized. Provider or
pod contact is forbidden until this document and `prototype-status.md` record
`C64_POD_READY`; the actual campaign additionally needs a later run-specific
owner GO.

## 1. R2 invalidation

R2's D23x16 private joint table and 27-round terminal callback are not a
sound production link. The callback supplied an authenticated value for an
arbitrary D27 opening but did not prove that this opening was determined by
the four D23 projected WHIR messages. A pre-challenge projection of sixteen
columns cannot later answer an arbitrary opening of the full private table.
R2 tests established local algebra and codec behavior only. Their recorded
protocol-pass interpretation is withdrawn; they give no gate credit.

The R2 table, terminal-link proof, extra D23-to-D20 sparse matrix and its
setup are historical diagnostics and must not enter the R3 certificate.

## 2. Selected R3 construction

The existing C6.3 cache replacement remains unchanged: its D22 systematic
message and D19 BOLT sketch continue to bind the persistent cache. R3 replaces
only the inherited residual wrapper.

After both residual-sumcheck statements and their 48 terminal descriptors are
fixed, the verifier draws a three-coordinate column point for the seven leaf
columns plus compact closure, and a four-coordinate point for the sixteen
auxiliary lanes. The leaf weights are split so correction columns 3 and 6
remain linkable to the cache commitment. This produces three polynomials:

| family | rows | live inputs | padded wrapper |
| --- | ---: | ---: | ---: |
| other leaf plus closure | `2^23` | 6 compact columns | none |
| two concatenated correction leaves | `2^24` | columns 3 and 6 | none |
| auxiliary | `2^15` | 16 compact lanes | none |

Each polynomial is split into two base-field limbs. Each limb is committed
once and opened by native WHIR at both residual-sumcheck repetition points.
The suffix therefore has six WHIR bodies. The first opening weight
is one; the second is transcript-derived. The expected authenticated target
is the same weighted combination of the exact pending claims.

WHIR hiding values are shared across the two authentication tapes, but the
tapes do not share correlations. Each tape consumes its own six full-field
correlations. Canonical corrections translate tape-local random values to the
common hiding values and are transcript-bound before the six terminal checks.

The existing native/compiler relation derives the provider correction from
the exact paired source cursor and reconstructs its base key by counter-neutral
verifier replay. Its completion receipt may be released only after the
projected residual checks accept. The correction polynomial is additionally
opened at the sparse-cache terminal point and matched to the two existing
source functionals. The old wrapper output link is removed, not retained.

## 3. Required identities

Production admission requires all of the following in one typed lifecycle:

1. All 48 pending descriptors occur in canonical order: eight leaf and sixteen
   auxiliary tables for each of two repetitions.
2. Column challenges are drawn only after the descriptors and public statement
   are fixed.
3. Compact leaf, closure and auxiliary owners are the same production owners
   consumed by the residual relation and exact finite allocation.
4. All three polynomials open at both exact sumcheck points; the correction
   polynomial also opens at the cache terminal point. No caller-selected
   point or clear opening is accepted.
5. Both verifier tapes derive the same plaintext relation from independent
   keys and correction-bound common masks.
6. The native/compiler tail is released only after all six WHIR artifacts and
   six terminal checks accept under the same outer statement.
7. Codec decode, disk reload and verification reconstruct every challenge,
   weight, correlation domain and byte count; trailing or reordered data
   rejects.

Materializing the old residual wrapper, a D23x16 private table, a second sparse
matrix or a new persistent response oracle is a NO-GO.

## 4. Analytic screens (`credit:false`)

The executable R3 screen currently reports:

- six 107-bit WHIR bodies: `6,861,312 B`;
- projected complete certificate: `32,903,995 B`, including a `4,096-B`
  new-codec reserve;
- 30-MB diagnostic miss: `2,903,995 B`;
- 35-MB hard-limit headroom: `2,096,005 B`;
- complete analytic soundness: `78.001993132250...` bits;
- no new sparse setup and inherited D22 finite-distance lower bound: 188 bits;
- resident projected output: `403,177,472 B`;
- complete suffix: exactly `661` full correlations per tape;
- forbidden dense residual wrapper: exactly `0 B`.

The byte estimate replaces the exact `2,672,044-B` old output-link frame with
the six bodies and reserves `4,096 B` for new framing and corrections.
Only a complete serialized and reloaded certificate receives size credit.

## 5. Gates

| Gate | Requirement |
| --- | ---: |
| projected complete prover before pod | `<=17.000 s` |
| complete A100 prover | `<20.000 s` |
| complete certificate | diagnostic `<=30,000,000 B`; hard `<=35,000,000 B` |
| complete `pi_final` payload | `<=8,500,000 B` |
| four-thread CPU verifier | `<5.000 s` |
| verifier additional RSS | `<=8,000,000,000 B` |
| A100 device high-water | `<=45,818,576,864 B` |
| response-local dense encoded oracle | exactly `0 B` |
| complete soundness | `>=78.00 bits` |

Target misses may be recorded, but protocol, session, finite-correlation,
resource-integrity and verification failures stop the attempt.

## 6. Two-profile campaign

The installed setup bundle contains exactly profiles `[0,150]`. The session
runs exactly proof `0 -> 150`, then—only after serialization, reload, complete
verification and atomic promotion—proof `150 -> 200`. There is no automatic or
selective retry. A third profile is out of scope.

The registered entrypoint is `scripts/run_c64_pod_e2e.sh`. It refuses to run
without the exact clean SHA and run-specific owner GO, one idle 80-GB A100,
96 GiB available RAM and 208 GiB free on the shared persistent filesystem.
Before paid setup it builds ABI45 and runs the whole projected-residual CUDA
differential, including output equality and allocation cleanup. It either
copies only contexts 0 and 150 from `C64_SETUP_SOURCE` or invokes the existing
setup compiler with `--stop-after 150`; it can never generate the other 15
profiles. Compilation completes before the measured process starts.

The measured process has a default 600-second emergency timebox, adjustable
through `C64_SESSION_TIMEOUT_S`, plus the registered disk, cgroup-memory and
device-memory hard stops. The 20- and 150-second marks are diagnostic only.
Every second is recorded with process memory/I/O, device memory, compute and
memory utilization, power, clocks, temperature, free disk and cgroup use;
stdout, stderr, build/setup logs, artifact hashes and failure file censuses
remain outside the repository. A target miss keeps both proofs for diagnosis
but makes `credit:false`.

On a new pod, source and small tracked evidence move only through GitHub HTTPS.
Generated setup, weights and large run artifacts remain pod-local. Every raw
run is create-new and records the clean SHA.

## 7. Exact resume condition

`C64_POD_READY` records the following completed local gates:

- projected-pending algebra and mutation checks;
- shared-mask two-tape authentication and finite counters for six bodies;
- CUDA projection ownership compiles through the Rust production boundary,
  cleans up on every error and has a differential runnable on the pod;
- production coordinator no longer calls the residual wrapper/output-link;
- strict certificate codec/reload and two-response lifecycle pass;
- complete local byte/correlation diagnostics agree with this design;
- the full workspace, feature-enabled C6.4 suite, budget self-check and strict
  two-profile driver tests pass;
- `rust/target` and ignored nested build caches are removed after checkpoint.

The first clean pod attempt at `ba09091` passed native CUDA differential and
setup, then failed before proof because response construction parsed C64MP1 as
C62MP1. Its burned authorizations and diagnostics remain immutable. A shared
selector repair passes its focused regression. The owner authorized one fresh
attempt with new directories and authorizations, reusing only setup contexts 0
and 150. It may run the two ordered proofs once; no third or selective retry is
authorized.

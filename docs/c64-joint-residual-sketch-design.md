# C6.4 — projected residual PCS recovery

**Status:** R7 A100 FAIL. Response construction remained `65.524719047 s` and
the first retained-device native opening rejected with `C6SPR11`. HARD STOP:
no pod or parameter-only retry before the local identity and timing repairs
below are complete.

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

The executable R5 screen currently reports:

- six 107-bit WHIR bodies: `6,861,312 B`;
- projected complete certificate: `32,903,963 B`, including a `4,096-B`
  new-codec reserve;
- 30-MB diagnostic miss: `2,903,963 B`;
- 35-MB hard-limit headroom: `2,096,037 B`;
- complete analytic soundness: `78.001993132250...` bits;
- no new sparse setup and inherited D22 finite-distance lower bound: 188 bits;
- resident projected output: `403,177,472 B`;
- complete suffix: exactly `661` full correlations per tape;
- forbidden dense residual wrapper: exactly `0 B`.

The byte estimate replaces the exact `2,672,044-B` old output-link frame with
the six bodies, reserves `4,096 B` for new framing and corrections, and applies
the exact `793 -> 761 B` outer-framing reduction.
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
profiles. Compilation completes before the measured process starts. R4
compiles for the pod's native CPU and refuses admission unless the compiler
exposes AVX2, NEON or SVE vector instructions. Rayon uses the allocated vCPU
count rather than the guest-wide processor census. The compiler features, CPU
topology and thread count are retained beside the run.

The measured process has a default 300-second emergency timebox, adjustable
through `C64_SESSION_TIMEOUT_S`, plus the registered disk, cgroup-memory and
device-memory hard stops. The 20- and 150-second marks are diagnostic only.
Every second is recorded with process memory/I/O, device memory, compute and
memory utilization, power, clocks, temperature, free disk and cgroup use;
stdout, stderr, build/setup logs, artifact hashes and failure file censuses
remain outside the repository. `C64PH1` markers delimit response, projected
roots, native chains, projected proof and seal. `C64GPU1` markers record live
device bytes after each projected root and opening. A target miss keeps both
proofs for diagnosis but makes `credit:false`.

On a new pod, source and small tracked evidence move only through GitHub HTTPS.
Generated setup, weights and large run artifacts remain pod-local. Every raw
run is create-new and records the clean SHA.

## 7. R7 GPU/SIMD repair and exact resume condition

R7 keeps the R6 protocol and certificate bytes unchanged and repairs the
executed implementation at the three measured CPU fallbacks:

1. The C6.4 response alone selects the existing CUDA-hybrid proving backend;
   historical C6.2/C6.3 entry points remain CPU-identical. The backend is
   dropped after the response so its allocations cannot overlap the six-root
   phase.
2. Each of the four native WHIR lanes remains sequential for device-memory
   safety, but its opening evaluation now reads the pending device-resident
   message instead of scanning the full message on the CPU. SIMT is used for
   the dense commitment, opening and proof kernels; transcript and loading
   stay on the CPU.
3. The direct residual prover now obtains each statement and first sumcheck
   message from one replay, not two. Regular zero tails are skipped in the
   first message and their folded coefficients are generated in bounded Rayon
   chunks. SIMD/Rayon is retained here because these short independent ranges
   already live in host memory; a new GPU-resident residual engine is deferred
   unless the phase exceeds its `3.000 s` admission budget.

The executable non-credit R7 projection is `16.800812093 s`: conservative
rounded response anchor `4.180000000`, measured C6.4 roots `5.710866424`, the
sum of matching C62GW4 provider-cached D28/D27 lanes `3.409945669`, residual
budget `3.000000000`, and seal budget `0.500000000`. Headroom below the local
`17.000 s` admission gate is `0.199187907 s`. This is engineering admission,
not A100 timing credit.

The runner records `C64OPT1` timings for response provider/seal/replay, each
native lane, both residual first messages and every folded-coefficient build.
It extracts those together with `C64PH1` and `C64GPU1` into a checksummed file
on success or failure. The default emergency timebox is reduced from 600 to
300 seconds; setup remains exactly contexts `[0,150]`, and the second proof is
attempted only after the first proof is serialized, reloaded and verified.

R7 is `C64_POD_READY` only for that registered two-proof campaign. It still
requires a fresh clean SHA, the new A100 endpoint and explicit run-specific
owner GO. A response above its anchor or residual above `3.000 s` is diagnostic
evidence for the already identified next step: retain coefficients and compact
witness tables on device and reuse the existing equality, product, triple-
product and fold kernels. It does not authorize a parameter-only retry.

### R7 A100 disposition

Clean `41b4e07` invalidates the `16.800812093-s` projection. The response
component took `65.524719047 s`, split into `58.727182131 s` provider,
`1.266567169 s` seal and `5.433695015 s` verifier replay. Selecting the
CUDA-hybrid backend therefore did not move the dominant provider work; this is
not cold-start attribution because it followed `142.781160265 s` of measured
pre-campaign preparation. The residual owner took `11.547041744 s` and the six
projected roots `5.903876539 s`.

The first native chain then failed closed: `C6SPR11 retained authenticated
target differs from its committed polynomial opening`. The focused CUDA
differential had passed, so it did not cover the production retained-message
identity across the exact representation, limb/order mapping and transcript
evaluation point. No certificate or verifier result exists, and all gates
remain `credit:false`.

Resume is local only. First add one production-path identity check that compares
the retained-device opening with the committed polynomial at the exact sampled
point and repair the root cause. Separately trace `response_provider` and move
or remove its CPU-dominant operations; backend dispatch by itself is not a
repair. Re-establish a complete `<=17.000 s` projection from matching measured
components before requesting another pod and run-specific owner GO.

### R6 disposition

R6 is not `C64_POD_READY`. Clean `813dd22` passed the complete CUDA
differential and campaign checks, and the migrated six-root lifecycle stayed
below the device guard: `40,053 MiB` peak with `3,643 MiB` headroom. The first
certificate nevertheless exceeded the 600-second session timebox. From the
first provider marker, response construction took `66.014 s`, residual-owner
construction `12.292 s`, projected roots `5.711 s`, and native four-chain
proving `227.870 s`; the residual-blind suffix was still incomplete after a
further `92.784 s`. No proof envelope, certificate or verifier replay exists,
so no complete protocol, size or timing claim follows.

The root/certificate migration should be retained as the measured memory
repair, but moving one more object into the same compact representation cannot
by itself reach 20 seconds: the response path alone already exceeds the gate,
and two later CPU-dominated paths are larger. Native AVX2 and 16 Rayon threads
were enabled; GPU execution appeared only in short bursts. Resume requires a
code-level plan that moves or removes work in all three dominant paths,
demonstrates a projected complete prover at most `17.000 s` locally, passes the
clean registered checks, and receives a new run-specific owner GO. A longer
timebox or parameter-only retry is not an unblock.

R5 is `C64_POD_READY`. C6.4 now precommits the six projected roots directly,
fixes a distinct projected-root typestate, and only then binds the residual
relation. The verifier decodes and replays those same six roots before drawing
or checking the dependent relation challenges. The v4 certificate binds the
statement, the digest of all six roots and the source schedule; its profile is
six projected bodies, not the C6.3 86-query wrapper profile. A v4 certificate
carrying legacy roots, a legacy profile, reordered/mutated projected roots or
cross-version bytes rejects. C6.3 v3 behavior is unchanged.

The C6.4 branch no longer creates the wrapper directory or calls the legacy
root materializer. The former `c6010003`/`c6010006` cohorts are therefore
unreachable from the C6.4 campaign path. Full workspace tests, 18 focused
C6.4/certificate checks, the budget self-check, campaign discipline and runner
syntax pass locally. This is structural evidence only; device high-water,
complete prover time, serialized certificate size and verifier gates remain
unmeasured. Resume requires a new clean pod endpoint and explicit run-specific
owner GO; the registered run remains exactly profiles `[0,150]` and two proofs
with no retry.

R4 keeps only six roots and six private replay seeds after projected
precommit. Each committed lane is released immediately, rebuilt from the same
seed after its opening points exist, and rejected if the rebuilt root is not
byte-identical. Thus at most one prepared projected lane is owned instead of
six, and released allocations are reusable by later lanes; the allocator may
still cache freed blocks. This is the selected SIMT memory repair for the
measured 422,576,128-byte overrun. Native CPU code continues to use the
repository's `target-cpu=native` SIMD path.

The R3 `C64_POD_READY` claim is withdrawn. Source audit after the failed run
found that C6.4 still unconditionally calls
`bind_c63_campaign_live_residual_roots`, which materializes cohorts
`c6010003` and `c6010006` before the compact six-root proof. Their retained
bytes are 19,629,342,720, dominated by the 17,179,869,184-byte residual
oracle. The raw failure record mislabeled this as an inherited weight oracle;
the append-only attribution amendment corrects it. The inherited certificate
codec also still carries these two roots. Therefore the earlier statements
that the old residual wrapper was absent and that the response-local dense
oracle was 0 B do not describe the executed implementation.

R4 required all previous local gates plus a sound C6.4 root
typestate and certificate binding that removes the two legacy cohorts without
substituting projected roots into the old wrapper type. The first clean pod
attempt at `ba09091` failed at dispatch; `31aae24` crossed that boundary but
reached `44,099 MiB` against the `43,696-MiB` guard. No state was promoted.
At R4 the simultaneous-buffer condition had a local repair but was not
measured on an A100, and a target-bearing retry remained blocked until the
legacy wrapper was removed. The stopped historical pod retained setup and
hashed diagnostics.

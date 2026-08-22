# C6.2 WHIR Fiat--Shamir Design

Status: **C62GW4 GENESIS TIMING HARD STOP / NO POD**

This document is the active design for C6.2. It has precedence over the
interactive C6.1 sections in `c6-delta-residual-inline-design.md`. Frozen C6
and C6.1 records remain historical evidence. C6.2 cannot use a historical
acceptance path as a substitute for a proved relation.

## 0. Authority and objective

On 2026-08-16, the owner selected a fully non-interactive Fiat--Shamir path.
The provider sends one proof. The verifier sends no proof challenges. The
verifier remains designated because VOLE-MAC verification still requires the
connection secret `Delta`.

The owner authorizes selection of the exact typed WHIR relation without a
second decision point. This authority covers design, additive Lean proof,
Rust implementation, adversarial mutations, exact budgets, and local
end-to-end preflight. It does not authorize pod contact.

The work stops at `C62_POD_READY`. An intermediate failed candidate causes a
redesign. It is not a terminal stop. A terminal stop is permitted only for a
proved security contradiction or a numerical gate that remains impossible
after the registered design search and the tolerance in Section 0.1.

## 0.1 Binding gates and tolerance

The original gate remains the target. The owner permits a five-percent
tolerance for a numerical product gate. The tolerance does not weaken a
cryptographic soundness claim or a protocol invariant.

| Gate | Target | Terminal threshold |
|---|---:|---:|
| setup plus first proof | `150,000,000 B` | `157,500,000 B` |
| final certificate | `21,999,999 B` | `23,099,998 B` |
| `pi_final` | `4,500,000 B` | `4,725,000 B` |
| one A100 prover wall | `<15.000 s` | `<15.750 s` |
| official four-thread verifier wall | `<5.000 s` | `<5.250 s` |
| accepted baseline proofs | `17` | `17` |
| separately accounted burned attempts | `4` | `4` |
| per-certificate soundness | `>=78.80929487391641 bits` | exact |

The certificate remains independent of cache length and accepted-proof count.
The protocol adds no per-token proof instance and no per-token PCS claim.
Every correlation remains connection-scoped, one-time, and domain-separated.

The current C6.1 screen is not a C6.2 result. Its setup plus first proof is
`165,818,049 B`. This value exceeds the terminal threshold by `8,318,049 B`.
C6.2 must remove at least this amount before pod admission.

## 0.2 Preserved evidence and open obligations

C6.2 preserves the four-root C6.1 owner graph, the ordered 96+6 response claim
schedule, C6NBR2, the 56+1 authenticated link, the six-component envelope,
the exact response-to-seal runner, and the disk cache and terminal typestates.
These items are component evidence only.

C6.2 inherits two open proof obligations.

1. The verifier must prove equality between the response-bound values and the
   compiler-bound values for distinct primary and secondary commitments.
2. The Fiat--Shamir transform must be sound for the complete composed
   protocol against an adversarial provider.

The first obligation is the historical
`C6ICT5_SECONDARY_RESPONSE_VALUE_BINDING_OBSTRUCTED` condition. C6.2 treats it
as a mandatory relation input. It does not bypass it.

## 0.3 WHIR design search

The design search compares three typed constructions.

1. A joint authenticated random linear combination proves both
   `secondary = response` and `secondary = compiler` after all three values
   are fixed.
2. A constrained-WHIR secondary statement installs both authenticated target
   functionals and batches them inside one constrained code relation.
3. A shared interleaved WHIR statement commits both MAC coordinates and the
   compiler functional under one root and one claim schedule.

Each candidate must use the same ordered 96+6 points. Each candidate must
accept independent commitment roots. Each candidate must reject divergent
values for those roots. No candidate can expose a clear target, a verifier
key, `Delta`, or a provider-selected functional digest.

The selection order is security, exact bytes, provider memory, provider time,
and verifier time. A design with an unproved equality is rejected before any
performance comparison.

## 0.4 Fiat--Shamir transcript

C6.2 uses one versioned transcript named `C62FS1`. It absorbs canonical bytes,
not byte lengths. Its initial state binds the following items:

- protocol version and security profile;
- setup and parameter digests;
- connection-safe public attempt binding;
- workload and all three statement digests;
- predecessor and proposed successor heads;
- all four commitment roots and the source binding; and
- the exact ordered component and lane census.

Every challenge has a unique domain with the component, lane, repetition,
round, challenge kind, and field type. The transcript absorbs the exact
preceding provider move before it derives that challenge. Field sampling is
canonical and unbiased. A missing, repeated, reordered, truncated, or
noncanonical move changes all later challenges and fails verification.

Provider-private hiding seeds remain independent OS entropy. They are not
Fiat--Shamir challenges. They do not enter a provider-facing statement field.
The final designated verification still checks VOLE-authenticated values with
private verifier keys.

Pure Fiat--Shamir removes the eight verifier-private challenge tapes and all
challenge traffic. This removal receives no byte or time credit until the
strict live and disk paths produce and verify the same proof bytes.

## 0.5 Fiat--Shamir proof obligation

A simple `q_RO * epsilon_interactive` estimate is a screen only. It is not the
C6.2 security theorem. The selected construction must state a
state-restoration soundness assumption for each functional commitment and
each interactive oracle component. It must then prove composition for the
complete WHIR, MAC, C6NBR2, blind-link, and ZeroOpen statement.

The exact security report must include the random-oracle query model,
commitment binding, BLAKE3 collision terms, field-sampling terms, all WHIR
events, the joint value relation, and the 17-certificate union. It must not
use the four burned slots as a bound on private hash trials.

## 0.6 Adversarial-input requirements

The strict verifier derives every statement from installed setup, canonical
public input, decoded proof data, and private verifier keys. The provider
cannot supply a claim schedule, target vector, relation weight, correction,
root role, transcript seed, or statement digest.

Mandatory mutations change one item at a time. They cover every input token,
cache head field, operation-plan identity, claim point, claim value,
commitment root, component role, repetition, correction, transcript move,
challenge domain, proof field, and trailing byte. A dedicated mutation uses
distinct primary and secondary roots with divergent values.

## 0.7 Ordered execution

1. Complete the source and theorem audit for the three relation candidates.
2. Select one typed relation and freeze its challenge order and codec.
3. Add the Lean relation and Fiat--Shamir composition modules.
4. Implement the canonical transcript and selected relation in Rust.
5. Replace the production broker endpoints and private challenge tapes.
6. Assemble strict live and disk verification through one proof object.
7. Run mutations, differentials, exact budgets, Lean, and the Rust workspace.
8. Run the local hardware-neutral readiness checks and write the pod-only
   production preflight and run commands.

No provider or pod is contacted before `C62_POD_READY` is recorded in the
ledger.

## 0.8 Research basis

The design audit uses the WHIR paper, ePrint 2024/1586; the constrained-code
HVZK extension, ePrint 2026/391; and the state-restoration Fiat--Shamir work,
ePrint 2025/902. Paper statements are not implementation credit. The exact
repository relation and measured gates remain controlling.

## 0.9 Relation selection

The source audit selects candidate 1. Its protocol name is `C62JVR1`.

The existing secondary WHIR body already computes the authenticated weighted
opening. The C6.1 path discards the response target because
`into_joint_term` requires `aggregate_key = None`. This restriction caused
the missing equality. It is not required by WHIR.

The live response owner already carries the 96+6 tape-1 `ProverAuthed`
targets. The strict disk response replay already carries the matching 96+6
`VerifierKey` targets. The WHIR body already derives the exact claim weights.
Therefore, C6.2 can retain one aggregate target per cohort. It does not retain
a second target vector.

Candidate 2 is not selected. Installing both constraints inside the WHIR fork
still requires the same authenticated tail relation. It changes more fork
code and gives no smaller proof.

Candidate 3 is not selected. A shared interleaved commitment changes the
registered roots and setup. It also removes the required independent-root
negative case.

## 0.10 Exact `C62JVR1` relation

Let `a[j,i]` be the claim weight produced by secondary WHIR for claim `i` in
cohort `j`. Let `w[j] = zeta^j` be the fixed cohort weight.

Define the following authenticated values on tape 1:

```text
N = sum_j w[j] * normalized_secondary_opening[j]
R = sum_j w[j] * sum_i a[j,i] * response_target[j,i]
C = compiler_base_fold + compiler_correction
```

`N` comes only from the verified secondary WHIR bodies. `R` comes only from
the response owner on the provider side and the replay-owned response keys on
the verifier side. `C` comes only from the installed compiler functional and
C6NBR2 bridge.

After `N`, `R`, and `C` are fixed, `C62FS1` derives a fresh `eta` in `Fp2`.
The existing joint ZeroOpen carrier proves one authenticated equation:

```text
(N - R) + eta * (N - C) = 0
```

For fixed unequal values, this degree-one equation has at most one accepting
`eta`. The new algebraic batching error is at most `1 / |Fp2|`. This term is
added to the exact soundness report.

The provider term retains the raw aggregate response target that already
exists before its affine WHIR transformation. The verifier term retains the
matching aggregate response key. Both are one scalar per cohort. Neither is
serialized.

## 0.11 Exact challenge order

The following items are fixed before `zeta`:

1. the full C6.2 public context;
2. the primary proof digests;
3. every secondary typed statement;
4. every secondary tagless WHIR body; and
5. the ordered 96+6 claim schedule digest.

`C62FS1` then derives `zeta`. The prover and verifier derive the same claim
and cohort weights.

The following items are fixed after `zeta` and before `eta`:

1. the response aggregate binding;
2. the installed compiler-functional digest;
3. the C6NBR2 statement digest;
4. the four-root and source-binding digests; and
5. the canonical 16-byte compiler correction.

`C62FS1` then derives `eta`. The joint residual becomes fixed. The C6NBR2
link must verify before the final joint ZeroOpen tag is accepted.

No challenge is derived from a byte count. No provider value can change after
the challenge that binds it.

## 0.12 Typed ownership and codecs

The C6.2 production graph adds these non-clonable owners:

- `C62SecondaryResponseProverTerm` owns one WHIR term and one aggregate
  response target;
- `C62SecondaryResponseVerifierTerm` owns one WHIR term and one aggregate
  response key;
- `C62ResponseCompilerRelationFixed` owns `N`, `R`, `C`, `zeta`, `eta`, and
  their complete transcript binding; and
- `C62ResponseCompilerLinkPending` releases the ZeroOpen tail only after the
  matching C6NBR2 receipt.

The provider API accepts none of these values as detached inputs. It derives
them from the response, secondary bodies, installed functional, and fixed
roots. The disk verifier reconstructs them from the strict proof, installed
setup, public instance, response replay, and private verifier keys.

C6.2 uses new semantic versions. `C62AWP1` replaces the secondary joint body.
`C62PA1` replaces the joint public argument. `C62PIF1` replaces the proof
envelope. `C62NFC1` replaces the final certificate. Historical C6.1 decoders
must reject these versions. C6.2 decoders must reject all C6.1 versions.

The 32-byte secondary carrier remains one 16-byte correction and one 16-byte
ZeroOpen tag. `zeta` and `eta` are Fiat--Shamir outputs. They add no wire
bytes. This is an analytic expectation until the strict codecs confirm it.

## 0.13 Lean obligations

`C62ResponseCompilerRelation.lean` must prove the following facts:

1. the typed response fold uses the same 96+6 points and weights as the
   secondary WHIR fold;
2. the compiler fold uses the same weights through the installed reverse DAG;
3. acceptance of `C62JVR1` implies both required equalities outside the one
   degree-one `eta` event; and
4. distinct roots and divergent values cannot satisfy the deterministic
   relation for all `eta`.

`C62FiatShamirComposition.lean` must compose the relation with explicit
state-restoration hypotheses for WHIR, functional commitments, C6NBR2, the
blind authenticated link, and ZeroOpen. BLAKE3 random-oracle behavior and
collision resistance remain explicit hypotheses. The module must add no new
axiom beyond the existing permitted Lean kernel set.

## 0.14 Total stable-softmax gap relation

The local 1,024-row profile found the first undefined P5 softmax input at
position 495, layer 4, head 11. The row maximum was `9,420`. The row minimum
was `-23,431`. Their gap was `32,851`. The signed exp input limit was
`32,768`.

C6.2 uses the typed relation `C62SGE1`. It does not change an output that was
defined by the frozen P5 rule. It gives a unique output to the previously
undefined lower tail.

For each causal score `s` and proved row maximum `c`, define the unsigned
16-bit value `g = c - s`. The exp table is indexed by `g`. For
`g <= 32,768`, its output is the frozen value `exp[-g]`. For `g > 32,768`,
its output is zero. The frozen table output at `-32,768` is zero. Therefore,
the extension is monotone and exact after integer rounding.

The existing score-requant lookup retains `s`. The existing row table retains
`c`. The exp lookup retains `g`. At the exp lookup point, the score lookup is
opened against `c - g`. This proves `g = c - s`. Table membership proves
`0 <= g <= 65,535`. The existing one-hot maximum relation changes from
`is_max * (s - c) = 0` to `is_max * g = 0`. Its row sum remains one.
Consequently, `c` is the exact row maximum.

`C62SGE1` replaces the signed exp content with one gap-exp content. It adds no
lookup instance, proof column, correction, challenge, or wire byte. The CUDA
proof workspace adds one internal rectangular column. C6.2 uses a new table
key and the existing C6.2 semantic versions. Historical C6 and C6.1 codecs do
not reinterpret this relation.

The Rust witness, CUDA witness, Python reference, live verifier, disk
verifier, mutations, and additive Lean relation must use the same gap rule.
Golden inputs inside the old domain must remain bit-for-bit unchanged.

## 0.15 Registered setup profiles

C6.2 uses one canonical `C62MP1` profile bundle inside `C62CP1`.
The bundle contains 17 ordered `C62SP1` objects. The profile identifiers are
the exact old contexts `0`, `150`, `200`, and every multiple of 50 from `250`
through `900`.

Each accepted workload uses the profile matching its exact old context. These
17 setup profiles fall into four correlation-capacity classes: genesis,
continuation-256 for contexts `150` and `200`, continuation-512 for contexts
`250` through `450`, and continuation-1024 for contexts `500` through `900`.
All continuation steps are 50 tokens. No other context has a registered
profile.

Each profile has an independent source manifest and extraction plan.
Each profile has an independent operation-plan topology identity.
All profiles share one canonical verifier model and quantization digest.
The bundle binds the profile order and each complete profile digest.
The outer envelope binds the uncompressed and compressed bundle digests.
Canonical re-compression is mandatory.

The setup directory contains exactly 17 physical directories named
`context-000`, `context-150`, and `context-NNN` for every registered context
through `context-900`.
Extra entries and symbolic links fail verification.
The local generator runs independent provider and verifier traces.
It requires exact equality for plans, native targets, cache traces, fixed
frames, and transcript ledgers.
The generator uses a fresh child process for every context, so profile memory
is released between contexts. For recovery, `--resume-from` verifies the
complete existing prefix and `--stop-after` bounds the requested range. These
flags do not resume a proof or a production session.

The current analytic setup cap is `141,882,261 B`.
The client-parameter envelope cap is `65,139,022 B`.
The terminal setup-plus-certificate limit is `157,500,000 B`.
These values are not measured credit.

## 0.16 Exact continuation session

The production record uses one live pair of real/AES PCG connections.
It accepts 17 certificates in one ordered session.
The first certificate changes context `0` to context `150`.
Each later certificate adds 50 tokens.
The final accepted context is `950`.

Four aborted attempts occur after the first certificate is verified and
accepted.
Each aborted attempt reserves the context `150` continuation profile.
Each abort consumes its complete reserved range.
Each abort keeps the two connections live.
An abort cannot read proof correlations before it closes.

The accepted correlation-capacity distribution is `1, 2, 5, 9`.
The distribution follows genesis, continuation-256, continuation-512, and
continuation-1024 order. The four burns add four continuation-256
reservations.
The exact session use is `49,383,784` raw correlations per tape.
The terminal capacity is `110,918,718` raw correlations per tape.

Each certificate is written to a new artifact directory.
The four-thread disk verifier loads that artifact.
The client accepts the head only after disk verification succeeds.
The provider slot receives acknowledgement after client acceptance.
The session closes both connections after the final accepted certificate.

## 0.17 Local readiness boundary

Additive Lean modules state `C62JVR1`, `C62FS1`, and `C62SGE1`.
The frozen Lean modules are unchanged.
Local checks must include the complete Lean build and `Audit.lean`.

Local Rust checks must cover codecs, typed ownership, transcript domains,
the gap relation, profile selection, response aborts, disk order, mutations,
and the complete workspace.
The exact setup compression must be measured from generated profiles.
The local session cannot claim A100 time or CUDA execution credit.

The production `preflight` mode requires one visible A100 and the CUDA
backend. It is therefore the first pod-only stage in the registered e2e
script, after the local hardware-neutral package is complete. Local readiness
does not claim that hardware check.

`C62_POD_READY` is valid only after all local checks pass.
That ledger entry must give exact create-new pod commands.
No pod contact is permitted before that entry.

## 0.18 First A100 attempt disposition

The owner authorized one fresh execution of the recorded command on
2026-08-17. Clean source `126dbe3` and hash-verified generated weights were
installed on one NVIDIA A100-SXM4-80GB with CUDA 12.8. The runner built the
`sm_80` backend and then failed its mandatory `volta-accel` gate at **37
passed / 2 failed**.

The attention proof-wire and protocol field-algebra CUDA results differed
from their CPU references. The fail-closed runner stopped before setup
generation. No setup or session root was created, and no certificate,
provider time, verifier time, byte result, or product gate receives credit.
No retry was performed.

Resume requires code-level root-cause fixes for both exactness failures,
complete local and A100 exactness checks at a new clean checkpoint, a ledger
update, and a new explicit owner GO. This disposition changes no protocol
parameter and does not authorize selective retry of the failed attempt.

## 0.19 CUDA exactness repair and renewed pod readiness

Clean repair checkpoint `3d70c5bd5b06a97bedd0d40d230e1de0f7b5edcd`
closes both first-attempt failures. The attention CUDA kernel was correct, but
its bit-exact test supplied invalid zero softmax weights. The fixture now
derives the required rounded weights and residuals. The affine Fp2 CUDA FFI
passed two 128-bit structs by value, which the x86-64 boundary decoded
incorrectly. It now passes four explicit `u64` limbs and reconstructs the two
Fp2 values in C++. The CUDA ABI advances from 36 to 37.

The two focused A100 regressions pass **1/1** each. The complete A100
`volta-accel --features cuda` gate passes **39/39**. The full local workspace,
the C6.2 library target (**55/55**), and the runner target (**3/3**) pass. This
repair changes no statement, relation, protocol parameter, certificate byte,
correlation count, or security calculation.

The owner explicitly authorizes one new fresh E2E run. It must use the exact
create-new command and roots recorded in the active ledger capsule. The failed
`126dbe3` roots remain burned. A failed new session is terminal and requires
another explicit owner GO; selective retry remains forbidden.

The pod upload authorization covers only the three repaired source files. A
clean side checkpoint `ec1607d655d7beac5684c8cdde76673fb1429a5a` therefore
applies exactly those files to the original `126dbe3` pod-ready parent. It has
the same protocol and executable sources as `3d70c5b`; only the local
incident/docs ancestry is absent. The registered production command uses this
side checkpoint in a separate clean pod worktree.

## 0.20 Second A100 attempt disposition

The renewed one-run owner GO was consumed on 2026-08-17. Clean pod source
`ec1607d655d7beac5684c8cdde76673fb1429a5a` passed the complete repaired CUDA
gate (**39/39**), generated all 17 fresh setup profiles, and passed the full
hardware and capacity preflight. Exact setup bytes were **101,197,448**.

The real session failed before the first cache wrapper was materialized with
`C6.2 cache precommit setup, workload, or root mismatch`. No certificate or
artifact was sealed, so provider time, verifier time, proof bytes, mutation,
session, hardware, and comparison-table gates are unevaluated and receive no
credit. No retry was attempted.

Resume requires isolating and fixing the first cache-precommit owner guard,
focused and complete local/A100 validation, a new clean checkpoint with new
create-new roots, a ledger update, and another explicit owner GO. Neither
failed session may be selectively retried.

## 0.21 Cache-precommit context fix and renewed readiness

The combined precommit guard incorrectly applied continuation growth to
genesis. Genesis starts at context 0 and adds 100 prompt plus 50 decode tokens,
so its new context is 150. Continuations add 50 decoded tokens to the old
context. The guard now uses these separate exact rules and reports each input
mismatch independently before CUDA or PCG allocation.

The real production-input validation passes locally and on the RunPod using
the existing validated weights and 17-profile setup. Relevant local tests pass
56/56 plus 3/3. CUDA code is unchanged and retains the same-pod 39/39 result.
The fix changes no protocol or quantitative parameter.

Clean pod checkpoint `27a0f1d11da301a581eae6833076ac85abf2fe80`
contains only the two repaired runner/campaign files over `ec1607d`. The owner
authorizes one fresh E2E run using the exact new paths in the active ledger.

## 0.22 Third A100 attempt disposition and correlation-census repair

The third one-run GO was consumed by clean pod source
`27a0f1d11da301a581eae6833076ac85abf2fe80`. All 17 setup profiles and the
A100 preflight passed. The first real proof then failed before artifact
sealing with `pooled sub correlation underflow`; exit was 101. Both connection
authorizations are burned. No retry, product timing, proof-size result,
consumer verification, mutation result, or comparison-table credit exists.

The cause is an exact profile error, not a CUDA or cache-precommit failure.
Every C6.2 profile allocated 98,600 too few sub correlations. Exact mock
prover and verifier schedules give these `(sub, full)` profiles:

- genesis: `(4,892,214, 226,917)`;
- continuation-256: `(1,795,150, 197,762)`;
- continuation-512: `(1,795,150, 202,562)`;
- continuation-1024: `(1,795,150, 207,554)`.

The corrected 17-accept session total is 49,383,784 raw correlations per tape,
within the unchanged 110,918,718 terminal capacity. Setup generation now
compares its live prover and verifier counters with the production constants,
so this mismatch fails before any PCG allocation. Local production-PCG tests
pass 4/4, runner tests pass 3/3, and the corrected genesis setup census passes.

The failed roots are immutable. A fresh provider session requires a clean
repair checkpoint, narrow pod census/readiness checks, new create-new paths,
an updated ledger, and another explicit owner GO.

## 0.23 Optimized renewed authorization

The owner explicitly authorizes one fresh run at clean checkpoint
`e2d0e9ee4e820ba45d262d56d56d9968322ad1b4`, the clean pod-side equivalent of
local checkpoint `d4fbae5de106dbcc822284b68c5e8d98d2e2ca5b`. The optimized runner retains the
unchanged same-pod CUDA 39/39 result and the post-fix local production-PCG 4/4
and runner 3/3 results. This avoids repeating test suites, but it does not skip
any measured E2E stage: CUDA is rebuilt, all 17 setup profiles are created
fresh with the new exact census guard, and setup measurement, preflight,
complete proving, mutation, and checksums all run normally.

The run must use the create-new paths and exact command in the active ledger.
Any failure consumes this authorization and is terminal for that session.

## 0.24 Optimized launch guard disposition

The authorized optimized command exited 2 at the source-clean guard before
setup, preflight, PCG allocation, or response authorization. A cache reuse
copy created the unexpected nested path `benchmarks/weights/weights`. It was
removed and clean pod checkpoint `e2d0e9e` is restored. The failed work path
and log are preserved; no product or component credit was produced.

The one-run GO is consumed. A replacement launch needs new create-new paths,
an updated ledger, and another explicit owner GO.

## 0.25 Standing create-new replacement authorization

The owner authorizes replacement `r01` and gives standing GO for future fresh
create-new C6.2 replacements until the real E2E and consumer measurement
complete. This authorization never permits reuse or selective retry of a
failed path. Each failure remains immutable and must be diagnosed and recorded
before a new replacement path is used.

Replacement `r01` keeps clean pod source `e2d0e9e`, fixes only the cache-copy
layout, retains the validated test gates, and executes every measured E2E
stage normally.

## 0.26 r01 spill preflight and r02 setup reuse

Replacement r01 regenerated all 17 profiles and every exact correlation guard
passed. Setup measurement passed. A100 preflight stopped before PCG allocation
only because local spill availability was 122,538,557,440 B, below 128 GiB.

The 74-GiB temporary wrapper `run/` data from the earlier no-certificate
failure was removed under owner cleanup authorization; burned state and
records remain. Local availability is now 200,921,718,784 B. Standing GO
authorizes r02. The deterministic, fully guarded r01 setup is copied to a new
r02 path and verified, avoiding a third generation pass. Measurement,
preflight, complete proving, mutation and checksums still execute normally on
new r02 work/session paths.

## 0.27 r02 causal-challenge disposition

r02 passed setup measurement and A100 preflight, then passed the earlier
correlation-underflow point. The first certificate proof stopped before
artifact sealing at `causal mask MLE vanished at r`. Exit was 101, both
authorizations are burned, and no proof-size, timing, verifier, session or
comparison-table credit exists.

The padded causal selector evaluates to zero when every sumcheck coordinate
is the transcript's fixed fail-closed fallback value. The old panic did not
show whether an earlier canonical-transcript error caused that state. One
diagnostic setup mode therefore runs the exact genesis model proof with mock
correlations and public C62FS1 challenges, then requires a valid canonical
binding. It performs no production PCG allocation and changes no protocol
parameter. A fresh r03 may start under standing owner GO only after this
diagnostic identifies and the code fixes the cause. r02 paths remain burned.

## 0.28 Exact challenge census and bound correction

The mock-correlation compiler ran the complete fixed model-proof schedule for
the four registered capacity classes with a counting challenge channel. The
exact per-role counts are **94,864** for genesis, **81,875** for
continuation-256, **84,107** for continuation-512, and **86,435** for
continuation-1024. Prover and verifier counts match in every class. A separate
bounded C62FS1 genesis run reproduces r02 and reports
`challenge census exceeds its proof bound`.

The old **65,536** bound was therefore stale. The fail-closed bound is
corrected to **131,072**, with **1,048,576** worst-case random-oracle limb
queries. This does not add or remove a challenge, proof round, proof byte,
correlation, relation, query parameter, or certificate field: it admits the
already-fixed **94,864**-challenge maximum and makes the security calculation
cover it. The exact budget remains above the binding soundness gate. A fresh
r03 still requires one bounded genesis replay on the pod before production.

The bounded replay passed at clean pod checkpoint `e9300f8`. Both roles used
the exact genesis correlation census and registered topology, and C62FS1
completed without an error. Standing owner GO now authorizes fresh r03 paths
with a verified copy of the existing deterministic 17-profile setup.

## 0.29 Exact ProductClosure census level

r03 passed the corrected Fiat--Shamir bound and then stopped at the next
strict provider census check. r04 stopped before preflight because a narrow
diagnostic rebuild omitted the registered production features; it consumed no
authorization. The corrected r05 feature build exposed the exact values:
**28,948** triples in the final live product batch, **29,620** triples across
the complete installed plan, and **673** installed closures. All closure,
zero-root and 96/6 native-claim counts match.

The installed total contains 672 earlier one-triple closures plus the final
28,948-triple batch. The old live check incorrectly compared that final batch
with the all-closure total. The provider and disk verifier must instead compare
the final live batch with the final installed closure. They continue to check
the complete closure count, while installed-plan decoding continues to bind
and validate all **29,620** triples. This is an accounting-level repair. It
does not change the proof, operation plan, setup, transcript, correlation
schedule, certificate format, byte gates, or protocol statement.

## 0.30 C6.2 retained-response codec selection

r06 passed the repaired census and reached the live-to-disk response byte
boundary. That shared boundary still called the historical C6.1 retained
codec, which correctly rejects model proofs carrying C62SRE1 extensions. The
C6.2 codec and strict extension checks already exist and are used by later
C6.2 wrapper and certificate framing.

At this earlier byte boundary, a model with the registered stable-softmax row
shift must use `encode_c62_parts` followed by `decode_c62`. A historical model
without that relation continues to use `encode_parts` followed by `decode`.
There is no error fallback between codecs. This makes the boundary use the
already-registered framing and changes no proof payload, allocation, setup,
correlation schedule, certificate format or gate.

## 0.31 C6.2-only retained-response frame

r07 passed strict codec selection and reached the complete C62SRE1 response.
The encoder then failed closed because C6.2 had inherited the historical
**2,921,744-byte** fixed frame even though its versioned codec adds the
mandatory C62SRE1 trailer. The earlier analytic budget counted the old frame
and was not complete evidence for the new codec.

C6.2 therefore uses a separate fixed **4,500,000-byte** response frame.
Historical C6 and C6.1 keep the original frame byte-for-byte. The C6.2
certificate maximum remains **21,999,999 bytes**, and the corrected complete
component ceiling is **17,195,995 bytes**. With the already measured immutable
setup bundle, setup plus this ceiling is **118,393,443 bytes**, below the
**150,000,000-byte** target. The frame remains canonical, zero padded,
digest-bound and strict on truncation, trailing bytes and C62SRE1 census.

This is a codec allocation repair. It changes no proof relation, query count,
soundness term, setup content, correlation schedule, model parameter or
certificate maximum. r07 is immutable. Standing create-new GO permits r08 on
new roots after the two focused codec/certificate checks and the narrow
registered-feature binary rebuild; no full suite or setup regeneration is
required.

## 0.32 r08 full retained-proof byte obstruction

r08 proved that Section 0.31 corrected an allocation without measuring the
object being allocated. The strict production encoder requires **42,820,093
bytes** before padding and its final digest. A deterministic genesis replay
through the same canonical writer decomposes this into a **42,115,273-byte**
model proof, **704,736 bytes** of 24 C62SRE1 extensions, a **32-byte** product,
and framing. Of the model proof, layer-boundary vectors alone occupy
**25,805,280 bytes**. This is larger than the complete **21,999,999-byte**
certificate target before adding the public argument or proof envelope.

The former **17,195,995-byte** ceiling incorrectly treated the historical
`other_non_pcs_bytes = 2,921,744` projection as a complete serializable model
proof. It is withdrawn. Raising the response frame cannot pass the gate and is
not authorized. r08 is immutable and has no product credit.

Resume requires a typed redesign that removes duplicate serialization only
where the existing authenticated PCS relation supplies equivalent verifier
inputs. It must not omit a correction needed by independent response replay,
expose a value, or replace the designated verification relation. The exact
genesis mock codec and a complete locally sealed/decoded certificate must fit
the binding byte gates before any r09 pod checkpoint or launch.

## 0.33 r09 compact retained-response checkpoint

The C6.2-only `C62RRP2` grammar no longer serializes the raw value of each
`Vec<u64>` correction already represented by the grand-residual PCS relation.
It serializes the canonical logical length and a 32-byte BLAKE3 digest instead.
The strict decoder reconstructs zero placeholders, limits both each collection
and the cumulative logical correction census, and retains an ordered digest
manifest. Historical C6/C6.1 codecs are unchanged.

During independent replay, the manifest binds the original correction digest
and logical byte count at the same transcript move, so the public
Fiat--Shamir challenges are byte-for-byte identical to the full response. The
verifier reserves the same one-time correlation schedule and emits the same C6
source trace. It does not numerically re-apply omitted corrections: their
authenticated values, ProductClosure operands and response-wide ZeroBatch are
checked by the already-bound grand-residual PCS relation. The direct response
ProductClosure call is retained to reproduce its exact trace; only its local
numeric result is deferred on the compact path. Full-field opening corrections
remain explicit. Missing, zero, reordered, unused, replayed or mutated digest
entries fail closed through the manifest, transcript census or outer frame
digest.

The digest entry is not treated as an algebraic PCS opening. The four wrapper
roots and source-binding digest are already in the initial `C62FS1` state
before these moves, and the PCS relation supplies the value binding. The
compact digest preserves the ordered provider move and its logical length;
provider attempts to vary that move are ordinary random-oracle queries covered
by the registered `q_RO` bound, not a new correction commitment assumption.

The exact genesis writer measured **42,115,273 B** under the full model grammar
and **2,992,409 B** under `C62RRP2`. The removed raw correction payload is
**39,137,712 B** across **464** vectors. Including the C62SRE1 trailer and
product, the canonical body is **3,697,229 B**, or **3,697,261 B** with its
final digest: **802,739 B** below the fixed **4,500,000-B** frame. Independent
compact replay also matched the production correlation census and complete
operation-plan/native-target topology for the genesis profile.

The local VM cannot safely replay a high-context full profile: the context-900
diagnostic exhausted RAM/swap and produced no record. By owner direction this
is not evidence and was removed. Local readiness is therefore limited to the
strict codec/transcript/certificate tests and both record-binary checks. The
first complete 17-profile seal, byte measurement and four mutations move to
the paused A100 pod. No product gate receives credit until that clean r09 run
finishes.

## 0.34 r09 disposition and r10 topology-registry repair

r09 passed the reused **101,197,448-B** setup measurement, A100 preflight,
real/AES connection preparation and the former retained-response obstruction.
After materializing and consuming the first wrapper spill it stopped before
sealing with `C6RLM1 production manifest does not have a registered C6.2
geometry`. No certificate or mutation exists and no product gate receives
credit. The spill was removed automatically.

The setup operation-plan headers identify four exact topology classes:

- genesis: `(5,119,131, 17,894,474, 2,093, 6,458,502, 673, 29,620, 10,909)`;
- continuation-256: `(1,992,912, 7,082,024, 2,093, 2,599,883, 673, 27,073, 10,060)`;
- continuation-512: `(1,997,712, 7,104,920, 2,093, 2,611,091, 673, 27,361, 10,156)`;
- continuation-1024: `(2,002,704, 7,128,872, 2,093, 2,622,875, 673, 27,649, 10,252)`.

Tuple order is source, canonical nodes, public inputs, scalar inputs,
ProductClosures, product triples and zero roots. The production whitelist had
retained four obsolete pre-repair tuples even though setup generation,
artifact digests and strict plan decoding already bind the current values.
The r10 repair replaces only that whitelist and adds an exact four-class
regression. It changes no operation plan, setup byte, transcript, relation,
correlation, proof or gate. Standing create-new GO authorizes r10 with new
roots after the narrow registry test and clean checkpoint.

## 0.35 r10 disposition and r11 retained-boundary repair

r10 passed setup, A100 preflight, real/AES connection preparation, compact
encoding and the corrected topology registry. After the first wrapper spill it
failed before sealing with `C6.2 retained response prefix has the wrong
length`; no certificate or mutation exists and the spill was removed.

The C6.2 binding constructor decoded `C62RRP2` but first compared its bytes to
the historical C6.1 frame constant. r11 changes that single boundary check to
`C62_RETAINED_NON_PCS_RESPONSE_BYTES` and adds a regression using the strict
C6.2 test frame. It changes no bytes, setup, relation, transcript, correlation,
proof or gate. Standing create-new GO authorizes r11 with fresh roots after the
narrow test and clean checkpoint.

## 0.36 r11 disposition and r12 terminal-tag binding

r11 passed setup, A100 preflight, retained-response framing and the production
topology registry, then failed after the first wrapper spill because one
compiler-chain transcript event was length-only. No certificate or mutation
exists and temporary spill was removed.

The shared C6AWH1 terminal helper charged its known 16-byte ZeroOpen tag with
the historical accounting-only API. r12 binds the exact `Fp2` tag whenever the
transcript is a C62FS1 Fiat--Shamir lane; interactive and seeded C6.1 accounting
remain unchanged. A role-parity regression requires equal canonical digests.
No wire bytes, setup, relation, correlation, proof or gate changes. Standing
create-new GO authorizes r12 with fresh roots after the narrow test and clean
checkpoint.

## 0.37 r12 disposition and r13 wrapper-root binding

r12 repeated the one-event canonical-transcript failure after setup, preflight
and the first wrapper spill. This disproves the §0.36 attribution: the exact
ZeroOpen binding is valid but occurs later and was not the failing event.

The failure is at response-transcript closure immediately after the four
wrapper commitments are fixed. The root fixer owns all four ordered 32-byte
roots but used the historical 128-byte accounting-only event. r13 absorbs the
exact root bytes for Fiat--Shamir transcripts and preserves historical seeded
and interactive behavior. The error now reports the first noncanonical label,
and regressions cover both the four-root boundary and a complete scaled
compiler transcript. No wire bytes, setup, relation, correlation, proof or gate
changes. Standing create-new GO authorizes r13 with fresh roots.

## 0.38 r13 disposition and r14 per-closure challenge binding

r13 passed setup, A100 preflight, canonical response closure and the first
full wrapper spill, then failed before sealing because residual coordinate zero
did not reproduce the retained `ProductClosure` messages. No certificate or
mutation exists and temporary spill was removed.

The residual compiler supplied the final response `chi` to every installed
closure. The real transcript derives a distinct `chi` at each closure; the
single-closure fixtures could not expose this mismatch. r14 captures the exact
ordered `(chi,M0,M1)` tuple at the existing prover and verifier closure sites,
checks role equality, and supplies that challenge vector to both live and disk
residual compilation. Challenges remain transcript-derived and add no wire,
setup, relation, correlation or certificate bytes. A trace regression covers
distinct ordered challenges. Standing create-new GO authorizes r14 with fresh
roots after the narrow checks and clean checkpoint.

## 0.39 r14 disposition and r15 live-primary target join

r14 passed setup, A100 preflight, per-closure challenge binding and the first
full wrapper spill, then failed before sealing because the native join required
the installed evaluator's coordinate-zero MAC share to equal the already-live
response MAC share. No certificate or mutation exists and temporary spill was
removed.

The two owners have distinct jobs. Tape zero is the authentication already
emitted and checked by the response; the installed evaluator proves that its
plaintext is the same target plaintext on both coordinates and supplies the
independent tape-one authentication. r15 therefore requires exact target
census and per-target plaintext equality, retains the live tape-zero target,
and joins it to evaluated tape one. This is the existing C6FT1/C6PS1
two-stage target link, not fresh reauthentication or a provider-selected
correction. A duplicate fail-fast join now runs before wrapper spill. Wire,
setup, relation, correlation and certificate byte counts are unchanged.
Standing create-new GO authorizes r15 with fresh roots after the focused test
and feature compilation pass.

## 0.40 r15 disposition and r16 post-source correlation phase

r15 passed setup, A100 preflight, the repaired native target join and the full
wrapper spill, then panicked on the first ordinary full-field draw in the
native suffix. The response source sidecars were correctly frozen, but their
closed flag also prohibited later correlations from the same one-time
connection allocation. No certificate or mutation exists and spill was
removed.

r16 adds one typed transition at verifier-replay transfer, which is already
guarded by successful paired-source sealing. It keeps both source sidecars
immutable and non-reopenable, ends response provenance-token assignment, and
admits later wrapper/compiler draws outside the frozen response source
schedule. The disk verifier ends its response provenance at the matching
trace boundary. A lifecycle regression checks that draws fail before the
transition, succeed after it, and cannot mutate either sidecar. Allocation,
correlation census, setup, relation and certificate framing are unchanged.
Standing create-new GO authorizes r16 after that regression and the feature
compilation pass.

## 0.41 r16 disposition and r17 complete correlation geometry

r16 passed setup, A100 preflight, the live-target join, the full wrapper spill
and the post-source lifecycle transition. It then failed closed at the first
suffix draw because the production allocation still reserved only the compact
response schedule. No certificate or mutation exists and temporary spill was
removed.

The executable suffix census is **24 subfield + 765 full-field correlations per
tape**: compiler chain `24 + 305`, two remaining authenticated-WHIR target
masks, residual blind `254`, persistent-cache blind `104`, and authenticated
output link `100`. r17 adds this suffix once to every registered response
profile. The resulting raw counts are **5,347,602** (genesis), **2,192,228**
(continuation-256), **2,201,828** (continuation-512), and **2,211,812**
(continuation-1024); the complete 17-accept plus four-abort session uses
**49,416,418** raw correlations per tape. Preflight and prove both check the
suffix formula before allocation or spill. This changes reservation geometry
only: setup relation, transcript, certificate framing and wire bytes are
unchanged. Standing create-new GO authorizes r17 with fresh roots after the
narrow checks and clean checkpoint.

## 0.42 r17 disposition and r18 C6.2 suffix binding boundary

r17 passed setup, A100 preflight, correlation allocation, the complete wrapper
and all four persisted native chains. It observed about **197 GiB** of live
temporary spill, then failed closed before sealing because the C62JVR1
functional's response-binding digest re-encoded the live response with the
historical C6.1 codec. The strict codec correctly rejected its C62SRE1
extensions. No certificate or mutation exists; the runner removed all spill.

r18 selects `encoded_c62_retained_response()` at that typed C6.2-only binding
site, matching both the earlier wrapper binding and the later C62NFC1 seal. It
also records exact per-certificate persisted bytes, raises the C6.2 preflight
spill floor to **208 GiB**, and removes each certificate's temporary spill only
after seal, artifact creation, independent internal verification, acceptance
and the required abort-slot exercise. Artifact and performance records remain;
only recomputable oracle files are removed. Relation, transcript contents,
certificate framing, correlations and setup are unchanged. Standing
create-new GO authorizes r18 with fresh roots after narrow checks and a clean
checkpoint.

## 0.43 r18 pre-session disposition and r19 split correlation censuses

After the container-disk resize removed the reusable setup, r18 rebuilt the
official setup generator and failed closed on profile zero before emitting any
setup or starting a production session. The measured response census remained
`(4,892,214, 226,917)`, while the generator incorrectly compared it with the
new response-plus-suffix allocation `(4,892,238, 227,682)`.

r19 names the response-only subfield/full-field constants separately for all
four profiles. Setup generation checks those response constants; production
allocation and client ranges retain the larger response-plus-suffix constants.
A regression checks that every allocation equals its response census plus the
fixed `(24, 765)` suffix. This changes no bytes, correlations, relation,
transcript or setup content. The r18 authorization was not consumed; standing
create-new GO authorizes r19 with fresh roots after the narrow checks and clean
checkpoint.

## 0.44 r19 setup completion and performance-eligibility hard stop

Clean `e107db2` generated all 17 setup profiles without entering setup
measurement, PCG allocation or a production session. The copied setup contains
85 files / 197,278,943 bytes and matches its source byte-for-byte; the SHA-256
of its canonical per-file manifest is
`9990a3dbbeaf30405e3cabdbd947d9e03003a6fca50ebe361783d52c6e036821`.
It is retained on the persistent volume for `C62_SETUP_SOURCE`. No attempt,
certificate, mutation or product metric exists, and standing create-new r19 GO
is unconsumed. The pod was stopped after removing temporary builds and logs.

The pre-session audit found that every selected committed or compiler WHIR
chain explicitly sets `gpu_performance_credit=false`. This is consistent with
r17's roughly 197-GiB persisted spill and tens-of-minutes first-proof path, but
the session runner would still apply the `<15.750 s` A100-prover wall gate.
Container disk capacity makes that executor functional; it does not make it a
performance-eligible A100 prover. Relabeling partial CUDA counters as wall time,
loosening the gate, or moving 197 GiB into the 117-GiB tmpfs is forbidden.

The active hard stop is
`C62_GPU_PERFORMANCE_ELIGIBLE_EXECUTOR_REQUIRED`. Resume requires an exact,
byte-identical GPU-resident or bounded-streaming WHIR executor, a positive typed
performance-eligibility signal checked before authorization, and the narrow
CUDA/codec/replay regressions at a clean checkpoint. Only then may r19 reuse the
saved setup and start its one create-new 17-accept plus four-abort session.

## 0.45 Performance-eligible executor authorization and local decision tree

The owner authorizes a C6.2-specific bounded-resident executor. Historical
Ligero/X4 code may supply independently tested CUDA primitives only; its
protocol, transcript, codec and measurements are not C6.2 evidence. The
executor must reproduce the current `C62FS1`/`C62JVR1` roots, proof bytes,
96+6 schedule, compiler relation, certificate and verifier replay exactly.
Primary and secondary roots remain independent; eliminating or interleaving
them requires a new explicit owner authorization.

The first implementation tier changes lifecycle, not protocol:

1. replace persisted coefficient/oracle/MMCS files with preallocated device
   arenas and a bounded host staging buffer;
2. retain compact upper Merkle frontiers and reconstruct query-local lower
   subtrees after Fiat--Shamir sampling;
3. execute D28/D27 WHIR lanes sequentially, using fused CUDA folds, NTT,
   equality-weight, sumcheck, Merkle and gather kernels;
4. share only algebraically identical base work between repetitions; each
   repetition retains independent mask randomness, root and transcript;
5. expose positive performance eligibility only after scaled byte-for-byte
   differentials and production-geometry resource guards pass.

A provider-only cache may contain the fixed model and embedding base
encodings. Its key binds the model digest, protocol/parameter digests, field,
dimensions, encoder version and content digest. Cache construction and preload
occur before the per-certificate timer and are never transmitted as setup.
Their wall time, bytes, RSS and VRAM are reported separately. Workload/cache
states, PCG material, masks, challenges, roots and query-dependent data may not
enter this cache. A miss or binding mismatch fails before authorization; it
may not silently rebuild inside or outside the measured attempt.

The local D14 differential now executes both commit paths with identical
witness, fresh-randomness stream, challenges and PCG state. The cached path
produces the exact ordinary commitment, complete strict proof payload,
interaction census, transcript ledger and correlation count. This is
functional cache evidence only; it gives no production-size or A100 credit.

The registered engineering admission is a conservative projected wall below
`12.500 s`, leaving `3.250 s` before the terminal gate. If the exact
root-preserving executor projects above `12.500 s`, a local WHIR folding study
starts automatically. It may change folding factors only while preserving the
independent-root relation, soundness floor, communication ceilings and all
typed transcript bindings. It receives no protocol or timing credit until a
new proof, codec budget and exact differential exist.

Local work uses scaled C6.2 fixtures plus analytic D28/D27 resource censuses;
it does not attempt a full VM proof. The eventual pod admission runs a
non-session geometry calibration first, then at most one genesis
`context-000` certificate. The measured attempt includes cache precommit, PCG
allocation, response, proof and seal, as in the current runner; only setup,
inference and the separately reported provider-cache preload are excluded.
Phase events record wall/CUDA time, I/O, RSS, VRAM and bytes, and the attempt
aborts at the first phase budget violation or absolute `15.750 s` deadline.
Until that executor exists, the production record adapter reports the
`C6SPR11-persisted-functional-only` profile as ineligible and rejects both
preflight and prove mode before the clean-tree check; prove therefore cannot
reach state creation, reservation or PCG use.

The proposed bounded-output `Fp2`-VOLE is deliberately not part of this
executor decision tree. It is a separately named C5 cryptographic research
construction governed by `c5-packed16-rate8-design.md` section 5.5.

### 0.45.1 Local seam audit and implementation order

The local audit rejects an MMCS-only optimization. The active fork currently
materializes `zk_padded_matrix`, runs `dft_batch` into a host
`RowMajorMatrix`, and only then calls the MMCS. `C61PersistedMmcs` first lets
the ordinary CPU MMCS construct the complete resident tree and spills it
afterward. Replacing its files with RAM or a faster filesystem would preserve
the dominant host DFT/tree construction and cannot become performance
eligible.

The required narrow fork boundary is a GPU-native claimless-WHIR prover which
accepts the same message, randomness, configuration and challenger moves but
returns the existing commitment and proof types. For each independent lane it
must:

1. form or restore the exact padded coefficients on device;
2. encode with the Goldilocks/Fp2 DFT convention used by the current fork;
3. hash the same serialized leaves and binary nodes, retaining only the
   bounded opening frontier;
4. execute sumcheck, code switching, fold, gather and query-local subtree
   reconstruction without a full host matrix;
5. release the lane arena only after its strict proof bytes are fixed.

The compiler D28/D27 pair remains transcript-coupled. It may alternate device
work within each shared round, but it may not merge commitments or reorder a
challenge across the two independent roots. Model and embedding repetitions
may reuse their fixed cached base encoding; masks, roots, equality weights and
proof state remain distinct.

Optimization order is fixed to avoid tuning an ineligible path: cached fixed
base plus fresh mask; reusable twiddle/DFT plans; preallocated arenas; batched
same-shape slot transforms; fused serialization/leaf hashing and compact
frontiers; asynchronous pinned-host staging; CUDA graph capture only after
byte identity. Folding-factor changes are evaluated last and only under the
`12.500 s` trigger. Every tier first passes a scaled root/proof/transcript
differential against the current C6.2 fork.

## 0.46 C62GW1 local GPU-native boundary checkpoint

The staged executor is `C62GW1-bounded-binary-frontier`, CUDA ABI 39. The
Plonky3 forks now expose typed commitment and residual-sumcheck boundaries;
mask sampling, transcript observations, PoW, challenges, proof assembly and
the strict C6.2 codec remain in the reviewed common path. The native side
implements exact base/Fp2 padding and NTT, resident prefix product-sumcheck,
fold and scale, binary BLAKE3 tile frontiers, query-local subtree rebuild and
the existing pruned-multiproof order. It returns the unchanged commitment,
opening and proof types.

The authorized provider cache contains only `Enc(fixed_base, 0)`. Its key
binds model, protocol, parameters, field, geometry, encoder version and content
digest; each online commitment adds a newly encoded mask. Workload state,
masks, challenges, roots, queries and PCG material remain excluded. The D28
cache-on resource admission projects a conservative peak of
`40 GiB + 64 MiB - 32 B` including a 4-GiB reserve, and rejects a 40-GiB
device. Allocation and geometry error paths release owned device buffers.

Local checks establish only executable seam evidence: the ordinary and cached
D14 CPU paths produce the same complete strict payload, interaction census,
transcript ledger and correlation count; the fork and CUDA-feature Rust graph
compile; the resource/cache/frontier tests pass. This VM has no CUDA compiler
or device, so neither the ABI nor any kernel, root, opening or full native
payload has hardware credit. In particular the prefix round is registered as
`[h(0), h(inf)]`, not the historical adjacent-pair `[h(0), h(2)]` interface.

The production runner therefore remains fail-closed under
`C6SPR11-persisted-functional-only` and must not be relabelled. Resume order is
fixed: clean checkpoint; A100 ABI build; scaled base/Fp2 root-row-multiproof
and fresh/cache full-payload differentials; D28/D27 non-session memory and
phase calibration; only then production adapter wiring and one genesis
`context-000` attempt. Any projected wall above `12.500 s` triggers the
authorized independent-root folding analysis. Any phase budget violation or
absolute `15.750 s` wall overrun aborts before another certificate.

The registered first pod command is
`scripts/check_c62_gpu_native_boundary.sh`. It is non-session and refuses a
dirty tree or missing CUDA device/toolchain; it builds ABI 39 and runs only the
narrow kernel, root/opening and full-payload differentials with hard timeouts.

## 0.47 First A100 boundary disposition and exactness repair

The first clean ABI-39 boundary run on an 80-GiB A100 passed the dedicated
padding/cache-add test. Its main suite passed four of six tests and stopped on
the cached initial root and the resident initial sumcheck claim. It did not run
D28/D27 calibration, setup, PCG, a certificate or a session.

The cached path encoded the fresh randomness with an empty message slice. This
placed its first row at zero, whereas the reviewed split requires
`Enc(0_message, randomness)` with randomness beginning after the fixed message
rows. The repair uses the existing resident zero and strided-copy operations to
place those rows before the unchanged NTT and cached addition. It does not
upload or allocate a full zero message.

The resident equality kernel also mapped point coordinate zero to the
least-significant row bit. P3 dense equality tables use big-endian row order.
The shared kernel now maps coordinate zero to the most-significant row bit; its
low-level regression uses the same order. This also repairs the existing
resident output-link caller rather than adding a WHIR-only workaround.

CUDA ABI 39, cache contents/key, commitment and proof types, transcript,
relation, codec, bytes and resource admission remain unchanged. Resume requires
a clean pushed checkpoint, the two focused A100 regressions, and the complete
registered boundary script. D28/D27 non-session calibration remains forbidden
until all pass.

## 0.48 A100 exactness boundary pass and calibration seam

Clean checkpoint `cc0e2e1` passed both formerly failing focused A100 tests.
The registered boundary script then passed the padding/cache-add test and all
six root, opening, frontier, resource and complete-payload tests. This closes
the scaled CUDA exactness boundary for ABI 39. It grants no production-size,
memory, timing, certificate or session credit.

The source audit finds no production-geometry calibration executable. The
existing `scripts/budget_c62_gpu_executor.py` is an analytic screen and
deliberately contains no measured phase times. It cannot be filled from the
scaled test wall or historical CUDA data.

The next checkpoint must add one fail-closed non-session calibrator for the
exact current D28/D27 folding geometry. It measures device peak and the
registered phase walls, creates no setup, PCG state, transcript, proof or
certificate, and emits no product record. The result must identify cache-on
and fresh lanes separately. Any geometry mismatch or allocation failure stops
without a timing decision. A projected wall above `12.500 s` starts the
authorized independent-root folding study; calibration cannot wire the
production adapter itself.

## 0.49 Exact-fold correction and decision-first A100 calibration

The resource test in §0.46 used a fold-8 candidate. The selected authenticated
profile actually fixes initial fold 1, starting inverse-rate log 1, and initial
heights `2^28` and `2^27`. The stale D28
`40 GiB + 64 MiB - 32 B` statement is withdrawn. With a 4-GiB reserve and
tile log 20, exact D28 checked peak is `26 GiB + 80 MiB - 32 B` with its own
fixed base, or `28 GiB + 80 MiB - 32 B` when the D28 and D27 provider bases
coexist at 6 GiB. The runnable resource check freezes both values.

The first production-size run is the registered non-session script
`scripts/check_c62_gpu_native_calibration.sh`. It constructs both fixed bases,
then measures exact initial commit, spread multi-opening and every initial
sumcheck fold for the four production lane shapes: cached D28 model with 96
claims, fresh D28 compiler response with 16, cached D27 embedding with 6, and
fresh D27 compiler plan with 3. Twice their sum is a strict lower bound for the
two repetitions. The run creates no transcript, proof, PCG state, certificate
or session and writes one create-new non-credit JSON record.

This is decision-first calibration: after each lane, a measured lower bound
above `12.500 s` is already sufficient to start the authorized root-preserving
folding study, so remaining expensive lanes are skipped. A lower completed
initial census is not an admission pass; later WHIR rounds must then be added
and measured before production wiring. The current pod has no historical setup
after the owner-requested cleanup. Independent roots and provider-only cache
contents remain unchanged.

## 0.50 Calibration r1 resource mismatch and narrow repair

Clean `93fe6fb` measured fixed-base preload at `19.403972640 s`. The first
cached D28 lane with 96 claims measured `21.800127087 s`, which the harness
reported as a two-repetition lower bound of `43.600254174 s`. That timing does
not receive a decision: device peak was `31,138,513,544 B`, exceeding the
exact `30,148,657,120-B` resource guard by `989,856,424 B`.

The fixed-base phase had logically freed its NTT and upload buffers, but the
resident allocator retained their physical storage for reuse. Provider preload
is a separately reported pre-attempt phase, so the online calibration boundary
must physically trim those inactive buffers. R1 is an invalid resource run,
not a folding verdict. Its non-credit disposition record is
`benchmarks/results/c62-a100-initial-lower-bound-failure-2026-08-19-93fe6fb-r1.json`.

The only repair is a post-preload device-cache trim. Before the first timed
lane the calibrator requires exactly 6 GiB of active provider bases and zero
inactive resident bytes; after every lane it rejects a measured peak above the
guard. Resume requires a clean checkpoint and one create-new run of the same
registered script. No protocol, root, cache content, transcript, proof or
production stage changes.

## 0.51 Calibration r2 and exact product-reduction workspace

Clean `b280958` passed the new post-preload checks: exactly 6 GiB of active
provider bases and zero inactive resident-arena bytes. The first cached D28
lane still exceeded the old guard and the assertion stopped before record
creation or timing disposition.

The remaining undercount is in the shared guard, not the trim. Each initial
sumcheck round uses two CUDA product-reduction workspaces. At the largest round
their exact capacities are `pairs * 32 B` and `ceil(pairs/2) * 32 B`, with
`pairs = 2^(D-1)`: together this is 24 B per source element, exactly 6 GiB at
D28 and 3 GiB at D27. The shared guard now charges that term explicitly.
Current D28 checked peak is therefore `32 GiB + 80 MiB - 32 B` with its own
base cache and `34 GiB + 80 MiB - 32 B` with both provider bases resident.

Resume is one clean create-new run of the unchanged registered script. Its
actual peak must fit the corrected guard before the measured lower bound can
trigger folding. R2 created no setup, PCG state, proof, certificate or session.

## 0.52 Calibration r3 schedule mismatch and exact non-final rerun

Clean `ca02e2f` passed the post-preload checks and the corrected resource
guard. The cached D28 lane peaked at `31,205,625,168 B`, below its
`36,591,108,064-B` admission, and reported a two-repetition projection of
`43.597385326 s`. That projection receives no decision because the calibration
loop reduced all 28 variables. The production prover performs only the
configured non-final folds: 23 rounds for this profile, leaving five variables
to its final case. The non-credit disposition is
`benchmarks/results/c62-a100-initial-lower-bound-failure-2026-08-19-ca02e2f-r3.json`.

The calibrator now derives the non-final count as the initial variable count
minus the configured final-case variable count, performs exactly that many
rounds, and rejects any different remainder. This is the only code change.
Fold 1, roots, provider-only cache contents, opening geometry, claim counts and
resource admission remain unchanged.

Resume is one clean create-new run of the registered non-session script. A
resource-valid two-repetition lower bound above `12.500 s` starts the
root-preserving folding study; otherwise later WHIR phases remain required.
No setup, correlation state, transcript, proof, certificate or session may be
created by this rerun.

## 0.53 Exact r4 lower bound and folding trigger

Clean `31aba7b` ran the registered non-session calibration with exactly 23
non-final sumcheck rounds and five final variables untouched. The fixed-base
preload took `19.169216006 s`. After trim, active provider bases were exactly
`6,442,450,944 B`, the reusable workspace was `1,073,741,824 B`, and inactive
resident storage was zero.

The first cached D28 lane, with 96 claims and 175 queries, took
`21.735754390 s` and peaked at `31,205,625,168 B`, below the corrected
`36,591,108,064-B` guard. The two independent roots therefore have a strict
initial lower bound of `43.471508780 s`, above the `12.500-s` engineering
admission. The decision-first script correctly skipped the other three lanes.
This starts the folding study; it is not product timing or session credit. Raw
evidence is
`benchmarks/results/c62-a100-initial-lower-bound-2026-08-19-31aba7b-r4.json`;
the pod file SHA-256 is
`3e07d7e2920b8ac94b02f80c359f215be901cc0c9b99fe273ba06a78fe0f2866`.

## 0.54 Folding-invariant initialization floor

The source boundary for initial claim-weight construction accepts only the
message, claims, coefficients and target. It receives no folding factor or
round schedule. Each independent root invokes it once with its independently
bound coefficients. Changing initial or later folding therefore cannot remove
either invocation or reduce its D28 96-claim kernel work.

Before building any folding candidate, the registered non-session script
`scripts/check_c62_gpu_native_folding_floor.sh` measures only this initialization
on the A100. Twice its device-kernel time is a strict folding-invariant lower
bound; host work and transfers are excluded. If that floor exceeds `12.500 s`,
folding-factor changes are insufficient and no candidate is implemented. If it
does not, candidates remain ordered as later-fold-only, then initial-and-later
fold, with exact soundness, byte and differential checks before timing credit.

The script creates one append-only record outside the repository. It creates
no setup, correlation state, transcript, proof, certificate or session and
does not consume the standing production authorization.

## 0.55 Folding disposition and executor redesign boundary

Clean `d29ad85` measured the folding-independent D28 initialization for all 96
model targets. Its wall was `14.722157134 s`; device kernels alone used
`14.169145760 s`. The strict two-root device-kernel floor is therefore
`28.338291520 s`. Peak device memory was `17,179,869,184 B`, below the
`30,148,657,120-B` guard. The raw record SHA-256 is
`9fa224622ed377e2c0c768acf472d09394c77caabac1fc60ee17dd9fc29da8d6`.

The floor exceeds both the `12.500-s` engineering admission and the
`15.750-s` terminal product threshold. Initial claim-weight construction
receives no folding factor, and independent roots require separate coefficient
bindings. Increasing later folding or initial-plus-later folding cannot rescue
the current executor. The decision-first study therefore implements no folding
candidate and grants no protocol, product or session credit.

This is not a proof that the protocol is impossible. The obstruction is the
current executor's 96 whole-domain claim-weight passes. Resume requires a local
exact redesign of that construction, preserving the same weighted polynomial
and independent roots, followed by scaled CPU/device differentials, an updated
resource bound, a clean checkpoint and explicit owner GO for another pod
measurement. Until then, no setup, correlation state, context, proof,
certificate or production session may start.

## 0.56 C62GW2 batched-weight and folding redesign

The owner replaces the Section 0.1 product allocation for this continuation.
The complete inline genesis prover includes every proof chain and certificate
serialization, but excludes one-time setup and provider-only fixed-work cache.
Its target is `<=10 s` and its binding gate is `<12 s`. Setup is
`<150,000,000 B`, setup plus the first certificate is `<172,000,000 B`, every
certificate is `<22,000,000 B`, the four-thread CPU verifier is `<5 s`, and the
campaign still requires at least 17 accepted certificates. These gates do not
authorize exchanging more traffic for prover time: a folding candidate must
also be non-increasing against the selected C6.2 chain and certificate byte
ceilings.

The redesign is ordered and fail-closed.

1. **Exact batched weights.** Replace the 96 serial whole-domain CUDA passes by
   one device construction of the same
   `W(x) = sum_i coefficient[i] * eq(point[i], x)`. Reuse the pinned Plonky3
   batched/split equality recurrence. The provider-only cache may retain fixed
   message data, but never a Fiat--Shamir point, coefficient, weight table or
   proof-dependent value. Fold-in the target dot product only if the returned
   value remains bit-exact.
2. **Local executor gates.** Differentially compare the new path with the CPU
   reference and the old path at scaled dimensions, including nonzero points,
   coefficients and targets. Recompute peak device storage and all transfers.
   This phase changes no root, transcript, proof, codec, setup or Lean statement.
3. **Bounded folding screen.** Use the already-pinned
   `FoldingFactor::PerRound`; enumerate only registered factors `2..=8` and
   retain the Pareto frontier for exact soundness, non-increasing wire, prover
   work, verifier work and device memory. At most one schedule is implemented.
   A selected schedule receives a new parameter/proof version and fresh setup
   digests; independent roots remain mandatory.
4. **SVO trigger.** If the conservative full-chain projection after steps 1--3
   exceeds `9 s`, integrate the pinned sumcheck SVO for the initial folding
   rounds and materialize only the exact residual weight polynomial. The proof
   messages and verifier equations must remain byte-for-byte equivalent. A
   projective-basis sumcheck, a new PCS and the C5 typed-PCG research branch are
   outside this milestone. SVO is not built before the A100 measurement: on the
   exact dense path it can reintroduce claim-linear partial evaluations, so the
   measured trigger must justify that extra boundary.
5. **A100 admission.** A clean checkpoint must contain the exact screen, scaled
   differentials, resource guard and one fail-fast all-lane non-session runner.
   The owner authorizes one such calibration on a new A100. It must record phase
   wall/kernel time, H2D/D2H, RSS, VRAM, query/round counts and encoded sizes,
   and stop as soon as the conservative complete-inline projection reaches
   `12 s`. It creates no setup, PCG, context, retained proof or certificate; a
   proof exists only transiently to measure the real serializer. Only a pass
   authorizes the one genesis `context-000` session.

The local checkpoint implements the minimum executor change. Balanced equality
half-tables replace the 96 whole-domain passes. Fixed codewords, fixed Fp2
evaluations and NTT twiddles are provider-only; Fiat--Shamir points,
coefficients and weights remain per proof. Optional resident hooks keep the
folded source, OOD evaluation and STIR/OOD covector accumulation on device while
the reference prover retains its original host fallback. Transcript events,
roots, verifier equations and certificate framing are unchanged.

The exact screen selects only calibration candidates: D27 uses
`[3,4,2,2,2,8]`, `717,524 B` per chain and analytic FFT work
`18,639,737,856`; D28 uses `[3,3,2,2,2,2,8]`, `793,240 B` and
`39,846,157,312`. Both are below their historical wire and FFT-work baselines.
No production proof version or setup digest is minted before measurement. The
conservative D28 all-lane guard with both provider bases is
`42 GiB + 688 MiB - 32 B`, including the 12-GiB fixed cache, twiddles, round
covectors and a 4-GiB reserve.

`check_c62_gpu_native_calibration.sh` first runs one scaled full-payload CUDA
differential, then measures the four genesis lane classes twice: model and
response at D28, embedding and plan at D27. It warms provider-only state before
timing, records real WHIR serialization and all required counters, reserves
`3 s` for non-WHIR inline work, and stops after the first atomic lane that makes
the projection reach `12 s`. Complete WHIR must remain below `9 s` to admit the
genesis run; otherwise the record directs the next local SVO analysis.

## 0.57 C62GW2 A100 disposition and SVO trigger

Clean `7f973b5` passed the scaled fresh/cached CUDA full-payload differential.
The registered all-lane run then stopped after seven of eight lanes, exactly at
its first terminal projection. Partial WHIR wall time was `9.742663280 s`; with
the fixed `3 s` non-WHIR reserve, the strict incomplete lower bound was
`12.742663280 s`. This already exceeds the `<12 s` binding gate, while the
missing second D27 fresh-plan lane prevents any complete-WHIR timing claim.

Provider preload was `18.852973902 s` and is excluded as authorized fixed work.
Peak VRAM was `39,146,362,732 B`, below the `45,818,576,864-B` guard; high-water
RSS was `2,277,711,872 B`. Ephemeral encoded lanes ranged from `664,852 B` to
`736,280 B`. The two D28 cached model lanes used `1.752730811 s` and
`1.744888393 s`; the two D28 fresh response lanes used `2.048391817 s` and
`2.059932086 s`; the D27 cached embedding lanes used `0.591341159 s` and
`0.597534060 s`; the first D27 fresh plan lane used `0.947844954 s`.

The measured kernel profile moves the obstruction beyond equality batching:
NTT dominates every lane, with resident row construction second on the cached
model roots; fresh D28 additionally transfers `4,296,117,104 B` per lane. The
Section 0.56 SVO trigger is therefore active. Resume is local only: integrate
the pinned initial-round SVO without changing proof messages, verifier
equations, roots or wire, and rerun scaled exactness/resource checks before any
new A100 authorization. No setup, PCG, context, genesis proof or certificate is
authorized by this failure record.

## 0.58 C62GW3 exact SVO and A100-local execution plan

The active continuation keeps the C6.2 statement, independent roots, proof
messages, verifier equations and wire unchanged. Its engineering target is now
complete WHIR `<7 s`, leaving the registered `3 s` for the rest of the inline
genesis path and therefore targeting `<=10 s`; `<12 s` remains the binding
product gate. The setup, first-exchange, per-certificate, verifier and
17-certificate gates in Section 0.56 are unchanged.

The minimum executor change has three parts.

1. The first folding batch uses exact batched SVO. One GPU pass compresses each
   opening against the non-SVO equality suffix. The reviewed host driver emits
   the same quadratic round coefficients; only after all initial challenges
   are known does it fold the source and materialize the exact residual batched
   equality polynomial. All SVO partials, challenges and residual work are
   created and consumed inside the timed proof. Nothing enters the provider
   cache.
2. A fresh lane uploads its initial message once. The same pointer-bound,
   device-resident evaluations serve the initial commitment and sumcheck, then
   are consumed by that proof. The runner rejects a fresh H2D census above one
   message plus 16 MiB of framing and small protocol inputs. This is transient
   online working memory, not a response cache and not cross-certificate state.
3. The exact radix-2 NTT keeps the same Goldilocks twiddles and butterflies but
   fuses bit reversal with the first ten stages in shared memory, then fuses
   each pair of remaining stages as one radix-4 global sweep. For a `2^26`
   transform the analytic global-sweep count falls from 27 to 9; arithmetic,
   roots and serialization do not change. This is a work screen, not timing
   credit.

The anti-X4d.1 boundary is explicit. Timing starts before commitment and ends
after real proof serialization. It includes fresh upload, SVO compression and
residual materialization, every NTT and Merkle operation, all independent roots
and all eight model/response/embedding/plan lanes. Each lane must report
`online_debt_items=0`; the record fixes `deferred_settlement=false`. No pending
opening, weight, partial or settlement may survive certificate closure, and no
work is amortized across certificates. A partial lane census cannot pass.

Local Rust checks cover SVO round/residual equivalence and compile the CUDA
feature boundary. The existing scaled full-payload CUDA differential is the
mandatory first pod test and catches NTT, fresh-reuse, root, transcript and wire
divergence. The pod run remains non-session and fail-fast: it creates no setup,
PCG state, context or retained certificate. Only a complete `<7 s` WHIR result,
with projected inline `<=10 s`, can request the one `context-000` genesis run.
Any SVO regression, H2D duplication, nonzero debt, root mismatch, resource
failure or projection `>=12 s` stops the line.

## 0.59 C62GW3 A100 disposition

Clean `97ccdb3` passed the scaled fresh/cached full-payload CUDA differential.
The registered calibration then completed all eight serialized lanes in
`8.835343613 s` WHIR and projected `11.835343613 s` inline after the fixed
`3 s` reserve. This satisfies the binding `<12 s` screen but misses the `<7 s`
redesign target, so it does not authorize genesis or any product credit.

The anti-X4d.1 checks passed: every lane closed with zero online debt,
`deferred_settlement=false`, and fresh H2D stayed within one message plus its
small protocol inputs. Peak VRAM was `34,300,209,352 B` under the
`45,818,576,864-B` guard; RSS high-water was `2,281,512,960 B`. No setup, PCG,
context, retained proof or certificate was created.

The eight lanes used `6.696867206 s` of device kernels and `2.138476407 s` of
remaining wall time. `pcs_rows` accounts for `3.968810458 s`, NTT for
`2.024905595 s`, and Merkle work for `0.605490107 s`. The exact fused NTT is no
longer the first obstruction. Resume locally on only two counted boundaries:

1. reduce the claim-linear `pcs_rows` work for the 96-opening cached lanes
   without changing points, targets, transcript, roots or wire;
2. stage each fresh message through pinned or already-produced resident memory,
   while keeping source construction and transfer inside the complete online
   accounting.

No further folding search, provider cache expansion or deferred settlement is
admitted. Another A100 calibration requires an exact scaled differential, a
clean checkpoint and a new owner GO. Raw evidence is
`c62-gw3-a100-calibration-2026-08-19-97ccdb3-r1.json`, SHA-256
`30881afd15b7c2ab23a6dd5a709d496fc13d5813f3572ce8e65e4d05f6372356`.

## 0.60 C62GW4 single row/H2D cycle

The owner authorizes one local C62GW4 cycle with no folding, parameter,
transcript, root, verifier, proof-message or wire change. The target range is
`6.5..7.5 s` complete WHIR and `9.5..10.5 s` projected inline; `<12 s` remains
the product gate. The owner's option to accept GW3 below `<12 s` is recorded
but not exercised because the local screen clears its required `1.5 s` saving.

GW3 measured `3.968810458 s` in `pcs_rows`. The same-A100 GW2 dense batched
reducer used at most `1.864715958 s` after doubling the slower measurement in
each lane class and conservatively duplicating the sole D27 fresh sample. The
registered screen therefore credits only `2.104094500 s`, projects
`6.731249113 s` WHIR, and assigns zero credit to H2D. This comparison is valid
because GW4 reuses that exact reducer; GW3's fused NTT and schedule are
unchanged.

The implementation is deliberately small. Initial sumcheck selects the
existing dense batched equality weights instead of SVO, while retaining GW3's
single resident fresh-message ownership. Large Goldilocks messages are
canonicalized into one reusable pinned buffer and enqueued as one H2D copy.
The pinned allocation/write and copy all remain inside measured wall time; the
runner records pinned bytes, allocation/reuse counts and peak pinned memory.
Nothing transcript-dependent enters the provider cache.

The anti-X4d.1 boundary is unchanged: timing starts before commitment, ends
after real serialization, covers all eight independent lanes, and requires
zero online debt and no deferred settlement. The scaled full-payload CUDA
differential exercises both dense reduction and pinned staging before one
fail-fast A100 calibration. It creates no setup, PCG, context or retained
certificate. Any exactness, resource, one-upload or pinned-byte failure stops;
genesis requires a later authority update even if GW4 meets its target.

## 0.61 C62GW4 A100 disposition

Clean `8edc302` passed the full-payload fresh/cached CUDA differential and the
single authorized eight-lane calibration. Complete WHIR wall time was
`7.359403833 s`; the unchanged `3 s` reserve projects `10.359403833 s` inline.
Both the `6.5..7.5 s` WHIR target and `9.5..10.5 s` inline target pass, as does
the `<12 s` terminal admission screen.

The eight lanes used `4.887398788 s` of device kernels: `pcs_rows`
`1.873687318 s`, NTT `2.025247798 s`, and Merkle `0.605375271 s`. Peak VRAM was
`39,146,362,732 B` below the `45,818,576,864-B` guard; RSS high-water was
`4,423,577,600 B`, peak pinned storage `2,147,483,648 B`, and maximum serialized
lane size `736,280 B`. Every fresh lane recorded exactly one pinned allocation
request, one reuse hit and one message-sized pinned write. All lanes recorded
zero online debt and no deferred settlement.

This is non-session component evidence: no setup, PCG, context, retained proof
or certificate was created, so no product, byte, 17-certificate or CPU-verifier
gate receives credit. The cycle is closed at owner review; genesis and any
further pod run require a new explicit owner GO. Raw evidence is
`c62-gw4-a100-calibration-2026-08-19-8edc302-r1.json`, SHA-256
`036eb4d3aac185bc15387d1fc303c7021548e70cf39a30968aed7cb8310f0312`.

## 0.62 C62GW4 genesis integration

The owner GO authorizes promotion of the measured GW4 boundary into the real
C6.2 path and one clean `context-000` genesis attempt. It does not authorize a
17-certificate session or a retry. The promotion must use the selected D28
`[3,3,2,2,2,2,8]` and D27 `[3,4,2,2,2,8]` schedules under a new C6.2 parameter
and proof version; historical C6.1 configuration and artifacts stay unchanged.

One provider-only GPU owner may preload the fixed model and embedding bases.
The response and plan messages remain fresh per certificate. All eight roots
must use the GW4 dense-weight, fused-NTT and single pinned-H2D path, with the
same independent commitments, Fiat--Shamir order, verifier equations and
certificate framing measured in §0.61. No online work or settlement may enter
the cache.

Before pod execution, the scaled full-payload CUDA differential, C6.2 codec
round trip, production runner checks and current gate constants must pass. The
single genesis run measures setup, complete provider wall, backend counters,
I/O, RSS/VRAM, certificate bytes and the independent four-thread verifier.
Binding admission is setup `<150,000,000 B`, setup plus first certificate
`<172,000,000 B`, certificate `<22,000,000 B`, provider `<12 s` and verifier
`<5 s`. Any exactness, resource, byte or timing miss stops before mutation or a
continuation. A passing genesis may run the four registered negative mutations
and seal one copyable artifact, but a full session still requires a later
explicit owner GO.

## 0.63 C62GW4 genesis timing disposition

Clean `299050d` passed the CUDA boundary and runner tests, generated all 17
setup profiles, measured setup at `101,197,617 B`, and passed the real A100
preflight. The sole authorized genesis did not reach a certificate. A wrapper
directory modified after the complete-inline timer began was present at
`2026-08-19T16:06:13.611756856Z`; the live pod clock at
`2026-08-19T16:07:31.034046358Z` therefore establishes the conservative
`77.422289502-s` lower bound. This alone exceeds both `<12 s` and the terminal
`15.75 s` stop.

The process was interrupted once. The exit cleanup removed the partial run and
provider cache; no certificate, artifact, CPU verification or mutation exists.
Two real/AES connection files were opened, but the slot store stayed empty, so
no accepted attempt was allocated. Maximum observed RSS and VRAM were
`23,948,939,264 B` and `25,066,209,280 B`; persisted spill was zero.

The `7.359403833-s` GW4 component calibration remains valid only as component
evidence: its fixed `3-s` reserve did not include the real fresh-precommit
cost and receives no product credit. C62GW4 pod work is closed. Resume is local
only: identify that cost without moving fresh work into provider cache, bind a
phase watchdog to the same complete-inline timer, and pass an exact full-payload
screen before requesting a new owner GO. The raw disposition is
`c62-gw4-genesis-timing-hard-stop-2026-08-19-299050d-r1.json`, SHA-256
`93903ee770e5b8e729d0643519172488746cd2a3a543a290790a66a299bfb515`.

## 0.64 Cache-precommit root-cause audit and one-shot probe

The failed genesis reached neither WHIR nor PCG. The complete provider timer
started immediately before `prepare_c62_campaign_cache_precommit`; slot
reservation and `C6ProductionPairedPcgAttempt::allocate` occur only after that
function returns. The stopped record has zero reserved slots. The probability
that the `77.422289502-s` lower bound belongs almost entirely to this cache
precommit is assessed at **>=99%**. The probability that the precommit is the
dominant or co-dominant C6.2 prover bottleneck is assessed at **98%**.

GW4 does not execute this work. GW4 owns the later eight authenticated-WHIR
lanes and measured `7.359403833 s`; the cache roots use a second backend and
the legacy persisted X4b wrapper. Replacing only those eight lanes with a new
PCS would therefore leave this path unchanged.

### Exact static census

Each predecessor or successor root takes eight D24 witness tables, generates
eight independent D24 mask tables, concatenates witness and mask, applies
eight CPU D25 multilinear transforms, performs eight rate-eight D25-to-D28
NTTs, persists the codewords, rereads them, and builds a disk-backed Merkle
tree. The exact two-root totals are:

| Item | Two-root total |
|---|---:|
| durable semantic cache + coefficients + codewords + metadata | `78,383,153,576 B` (about 73 GiB) |
| peak live files while building the second tree | `91,268,055,252 B` (about 85 GiB) |
| cumulative writes | `112,742,891,880 B` (about 105 GiB) |
| cumulative reads | `103,079,214,976 B` (about 96 GiB) |
| accounted H2D / D2H | `111,669,428,096 / 103,079,215,040 B` |
| NTT / initial-hash tiles / outer-hash tiles | `16 / 1,024 / 170` |
| storage durability barriers | `70` |
| retained upper Merkle cache | `67,108,800 B` |

Before that I/O, two 2-GiB cache states are zero-filled and validated during
materialization, then validated again by the precommit. This visits
`536,870,912` cells; every visit currently recomputes checked layout indexing.
Mask generation produces `268,435,456 Fp2` values. The 16 D25 transforms
perform about 6.71 billion `Fp2` pair updates, or 13.42 billion base-field
subtractions, with a conservative 300-GiB lower bound on host-memory traffic.
Only the successor's K/V tables contain live genesis data: 14 of the 16
witness slots across both roots are wholly zero, yet all receive a mask,
transform, rate-eight encoding and tree.

The existing record cannot distinguish validation, masking, transform and
storage. Their relative share is deliberately left unclaimed. Current
confidence that CPU scans/masking/transforms account for a majority of the
first observed 77 seconds is **75%**; confidence that persisted codeword/tree
work becomes the next blocker even after CPU cleanup is **>99%**.

### Single diagnostic run

Runner mode `precommit` is the only admitted diagnostic. It uses the installed
17-profile setup, real GPT-2 weights and exact genesis workload. It builds and
retains the same 12-GiB `C62ProductionGpuWhir` fixed cache as the product path,
but starts no WHIR lane. It then measures the exact two-root
`prepare_c62_campaign_cache_precommit`, writes a create-new JSON record with
wall time, backend counters, process I/O, RSS, durable bytes and both roots,
and exits before opening a slot store, reserving a slot, allocating PCG,
constructing a proof or invoking a verifier. The record is always
`credit:false`.

The fresh authorized pod retained no setup. One deterministic 17-profile
generation is therefore admitted as unmeasured preparation only if its
canonical per-file manifest SHA-256 matches the registered
`9990a3dbbeaf30405e3cabdbd947d9e03003a6fca50ebe361783d52c6e036821`;
a mismatch stops before the probe. No historical GW2--GW4 calibration,
workspace suite, certificate, mutation or continuation is repeated. The
lightweight `scripts/watch_c62_precommit.sh` launches the release binary
directly and samples `/proc/<pid>/io`, RSS/CPU and file sizes under
`certificate-00/wrapper` once per second into a create-new timeline outside
the run root. Setting `C62_PRECOMMIT_PERF_DATA` also attaches a 49-Hz `perf`
call sampler when permitted by the host; failure of that optional sampler does
not authorize a retry. File transitions identify the useful split:
semantic cache, coefficient transform gap, coefficient/codeword write, oracle
reread and initial hash, outer Merkle levels, root and manifest. `perf` call
sampling may be added if the pod permits it. The heavier `CausalObserverV1` is
not wired for this first run because its per-boundary `/proc`, allocator,
smaps and NUMA probes would alter the measurement and require three new API
layers.

The owner granted GO on 2026-08-22 for exactly one clean single-A100 run of
this diagnostic. Completion of both distinct roots is diagnostic success, not
a timing pass. If runtime is operationally excessive, the predecessor
manifest plus the external timeline is sufficient to stop manually; no
watcher is allowed to advance into PCG and no retry is authorized.

### Inputs that C6.3 must carry forward

This section does not open or specify C6.3. It records four constraints for a
later Authenticated Sketched PCS design:

1. Bolt adaptation must replace or avoid predecessor and successor cache
   commitment work, and should include the D23 delta-residual cohort; replacing
   only the eight WHIR lanes cannot solve the provider bottleneck.
2. Genesis zero structure and the two live K/V slots must remain sparse through
   commitment rather than expanding 14 empty slots into dense masked D28
   codewords.
3. A verified successor owner must be promoted as the next predecessor. The
   current continuation instead samples a new mask and then demands equality
   with the old successor root; that equality has negligible probability and
   is a latent functional defect, not a performance optimization.
4. For the first GPT-2/single-A100 experiment, total proof-of-inference size
   may be at most `30,000,000 B`. The analytic Bolt-min estimate near
   `23.56 MB` is therefore admissible as a design screen, with roughly 6.44 MB
   of headroom, but has no proof-size or security credit until encoded and
   verified end to end.

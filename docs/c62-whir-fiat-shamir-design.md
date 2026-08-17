# C6.2 WHIR Fiat--Shamir Design

Status: **A100 PREFLIGHT CUDA BIT-EXACT FAIL / NO SESSION / NO RETRY**

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
The exact session use is `47,356,708` raw correlations per tape.
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

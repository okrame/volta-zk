# C7 — stateful authenticated linear-functional commitment

**Status:** C7 R0 design checkpoint; design and small formal/analytic seams
only.  This document is the task-specific authority named by
`prototype-status.md`.

**Branch:** `agent/c7-stateful-alfc`.

**Registered workload:** an accepted 100-token predecessor, followed by one
50-token response and a 150-token successor, for both GPT-2 and the declared
Gemma-class 31B screening envelope.

## 0. Decision, authority and hard stops

C7 changes the statement, not just the PCS.  It proves one response-wide
recurrence over the real incremental fixed-point decode:

```text
accepted hidden predecessor
  -> DecodeStep_q[0]
  -> ...
  -> DecodeStep_q[49]
  -> append-only hidden successor
```

This is one proof with one terminal settlement.  There is no per-token PCS
claim, per-token folding instance, or deferred cross-response settlement.
DeepProve and zkAgent are evidence for response-wide operator batching, but
their teacher-forced full-forward statements are not the C7 relation.

R0 makes the following decisions.

1. The immutable model, response trace and persistent cache are separate
   commitment planes.  "One opening" means one transcript-bound
   multi-commitment ALFC invocation, not one literal Merkle root.
2. Every physical packed segment has **exactly one** operator-reduced terminal
   point before the ALFC batching challenge.  This is the only admitted
   resolution of the `O(KN)` packed-functional hard stop.
3. Static-weight privacy uses policy 3: no PCS symbol or evaluation is ever
   revealed in clear; accepted terminal values enter the connection VOLE-MAC
   directly.  Reuse of the static weight root is conditional on the named
   malicious-DV multi-session privacy theorem in Section 4.  It is not
   inferred from HVZK.
4. Backend A (packed Ligerito/ERA-style code, constrained-code masking and a
   new VOLE-MAC adapter) remains the architectural candidate, but is
   **NO-GO for R1 implementation** at this checkpoint.  Strict
   unique-decoding WHIR is **GO as a local executable control only**, using
   this exact packed relation and never the C6.3 eight-body topology.

The following are terminal R0 hard stops.  Until all are discharged there is
no large prover implementation, production equivalence claim, provider/pod
contact, or proof/time/memory credit:

- a concrete compiler census must show one terminal point per physical
  segment; any segment with multiplicity `K_i > 1` reopens the `sum K_i N_i`
  stop;
- the selected code must have a proved, executable one-pass bounded-memory
  schedule, with exact read/write traffic and no expanded resident Fp/Fp2
  weight wrapper;
- the Fp2-to-two-Fp-limb authenticated terminal adapter must be proved and
  exercised without exposing an evaluation;
- the malicious designated-verifier, adaptive, stateful privacy theorem must
  cover the full connection horizon, rejection feedback, retries and
  selective aborts;
- certificate constants, setup/oracle storage and refresh must be obtained
  from the composed protocol.  The R0 budget is an exact target-envelope
  calculation, `credit:false`, not a measurement or construction theorem.

No C6.3 measurement, component test or analytic certificate is transferred as
C7 credit.

## 1. Scope and fixed conventions

### 1.1 In scope

- the exact public/session state, witness and acceptance relation;
- one canonical response-wide claim schedule;
- the algebra and construction cost of one packed linear functional;
- candidate/control selection and explicit dead ends;
- symbolic and executable proof, setup, storage, I/O, memory and security
  budgets for the same GPT-2/31B workload;
- small additive Lean lemmas.  Concrete binding, hash/PCG assumptions and
  malicious-DV privacy remain named hypotheses.

### 1.2 Out of scope

- changes to `quantization-spec.md`, the Rust fixed-point witness generator,
  `scripts/gpt2_fixed.py`, or frozen M1--M12 Lean statements;
- a new transformer frontend, full prover, production run or pod experiment;
- a claim that preprocessing removes a fresh arbitrary linear evaluation;
- changing certificate bytes into setup bytes, or hiding prover work in an
  unaccounted persistent data structure.

All fixed-point values use the frozen canonical i16 representation and the
existing i64 accumulator/requantization semantics.  Corrections remain
8-byte `F_p` values.  Challenges that need the registered response security
use `F_{p^2}` and are carried through both base-field limbs.

### 1.3 Threat and leakage model

The provider/prover owns private weights and hidden K/V state.  The client is
the designated verifier and may choose protocol messages adaptively, abort,
retry, and use accept/reject feedback.  The connection shares one MAC key
`Delta`; raw correlations, masks, nonces and attempt slots are one-time and
domain-separated.

The intended public leakage is:

- model identifier, architecture, quantization/layout digest and static
  weight commitment root;
- input/output token transcript, response length and sampling policy;
- predecessor/successor epochs and cache lengths, but not K/V contents;
- commitment roots, certificate length, public challenge/query metadata,
  accept/reject and durable journal state.

Privacy is only required between weight/cache witnesses inducing the same
declared public leakage.  Availability and suppression of a sampled response
are not hidden.  C7 proves that a published token follows the committed
sampling coins; it does not promise unbiased service after a provider chooses
to abort.  Every such attempt still consumes the connection horizon and burns
its masks/correlations.

## 2. Exact response relation

Let `e` be the accepted epoch, `k` the predecessor cache length, `T` the
response length, and `tau_0,...,tau_T` the public token boundary and response.
For the registered workload, `k = 100` and `T = 50`.

### 2.1 Public and durable session state

The public instance `x_e` contains, in canonical byte order:

1. protocol/version and all domain-separation labels;
2. `connection_id`, model/layout/quantization digests and the immutable root
   `C_W`;
3. accepted `epoch = e`, predecessor certificate digest, `C_KV,e`, and
   `kv_len = k`;
4. attempt slot, single-use response nonce, reserved correlation ranges and
   their already-durable high-water marks;
5. public input/output tokens, `T`, maximum context/capacity and the exact
   sampler policy;
6. a prover sampling-seed commitment, client entropy, and the transcript rule
   deriving per-step sampling coins;
7. fresh response root `C_B,e`, successor root `C_KV,e+1`, successor length
   `k + T`, and the canonical claim-schedule digest;
8. hash/code/field parameter identifiers and the complete certificate framing
   lengths.

The accepted client state is the tuple

```text
(connection_id, e, k, C_W, C_KV,e,
 predecessor_certificate, accepted_transcript_head,
 correlation_high_water, attempt_high_water).
```

The client persists a reservation before exposing its nonce, entropy or raw
correlations.  `C_W` cannot change within the connection.

### 2.2 Private witness

The witness `w_e` contains:

- the canonical packed i16 model weights `W` and commitment opening data for
  `C_W`;
- the complete accepted predecessor K/V values `KV_0` and opening data for
  `C_KV,e`;
- the response trace `B_e`: every real incremental `DecodeStep_q` activation,
  i64 accumulator, requantization/range/LUT witness, logits, selection witness
  and sampling coins;
- the canonical K/V tail written by the `T` steps, intermediate logical cache
  views, and successor opening data;
- commitment randomness for the fresh trace/successor planes;
- operator-reduction messages, the canonical terminal schedule, private
  terminal values, two-limb authenticated shares/tags, and the exact one-time
  VOLE correlations/masks consumed by this attempt.

The response trace commitment is fresh even when the same public prompt is
retried.  No trace cell or K/V cell is required to be directly transmitted as
a MAC correction.

### 2.3 Incremental semantics

Define the deterministic fixed-point transition

```text
DecodeStep_q(W, tau_0..tau_t, KV_t, sampler_coin_t)
  = (tau_(t+1), KV_write_t, trace_t).
```

`DecodeStep_q` is the Rust witness generator, bit-for-bit aligned with the
frozen Python reference.  It executes exactly one incremental token step.  It
does not recompute a teacher-forced `0..t` prefix.

Starting from `KV_0`, define

```text
KV_(t+1) = KV_t || KV_write_t,
coin_t   = H(domain, connection_id, nonce, e, t,
             prover_seed, client_entropy, transcript_prefix).
```

The prover seed is committed before client entropy.  Its opening is proved in
the response relation; a mismatch rejects.  Greedy decoding is the degenerate
sampler with no random branch.

For every `t < T`, the relation constrains:

- all fixed quantization, GEMM, attention, normalization, lookup,
  requantization, token-selection and sampling operations;
- every K/V address to be below `k + t + 1` and to resolve either to the
  accepted prefix or to an earlier response-local write;
- exactly the canonical K and V cells for token `k + t`, with no duplicate or
  out-of-range write;
- the public token `tau_(t+1)` to equal the selected/sampled result.

### 2.4 Acceptance predicate

`AcceptC7(x_e, w_e, pi_e)` holds iff all of the following hold.

1. **Plane binding.** `C_W`, `C_B,e`, `C_KV,e` and `C_KV,e+1` bind their
   canonical layouts under the named concrete binding hypotheses.  `C_W`
   binds the same weight cells at every layer and step.
2. **Accepted predecessor.** The old K/V commitment, length, epoch and
   predecessor certificate exactly equal the durable accepted head.
3. **All real steps.** The recurrence in Section 2.3 holds for every
   `t = 0,...,T-1`, including the fixed token tie rule and sampler coins.
4. **Append-only successor.** `KV_T = KV_0 || canonical_tail`, the prefix is
   unchanged, the length is `k + T`, all written addresses are canonical and
   no other cell changes.
5. **Response-wide stacking.** Operator, weight, boundary and K/V claims cover
   all `T` steps in one protocol execution.  There is no per-token proof or
   later debt.
6. **Canonical schedule.** Serialization parses uniquely; ordinals, segment
   bounds, padding, roots and query-vector derivations match the public layout;
   every physical segment appears exactly once.  Commitments, schedule,
   query vectors and authenticated claimed values are fixed before `beta`.
7. **ALFC.** The one logical multi-commitment opening accepts and transfers
   every claimed linear result directly into the shared VOLE-MAC.  No clear
   `W~(r)`, K/V evaluation, code symbol or affine fold is exposed.
8. **Terminal settlement.** One post-ALFC challenge settles all two-limb MAC
   residuals to zero, and every reserved correlation/mask is consumed exactly
   once.
9. **Atomic state change.** A durable compare-and-swap on the predecessor head,
   nonce and slot promotes `(e,k,C_KV,e)` to `(e+1,k+T,C_KV,e+1)` together with
   the certificate/transcript journal.  The ACK is sent only after this commit.

Concrete PCS binding/knowledge soundness, code distance, collision resistance,
Fiat--Shamir/ROM, real-PCG security and malicious-DV privacy are explicit
hypotheses.  Component lemmas do not imply this complete predicate.

## 3. Authenticated linear-functional commitment

### 3.1 Interface and commitment planes

C7 requires the designated-verifier primitive

```text
Commit(domain, layout_digest, x; randomness) -> (C, prover_state)

OpenLinearIntoMac(
  [(plane_j, C_j, q_j, authenticated(v_j))]_j,
  transcript
) -> proof

where v_j = <x_j, q_j>.
```

`authenticated(v_j)` is a handle to prover/verifier VOLE-MAC shares, not wire
serialization of `v_j`.  The verifier never receives `v_j` or a PCS symbol
from which it can derive it.

A raw prover MAC tag is also forbidden.  If the verifier knows nonzero
`Delta` and its key share `K`, exposing a tag `M` with the convention
`M = K - Delta*v` reveals `v = (K-M)/Delta`.  Only the typed authenticated
handle and a simulator-computable terminal opening of a residual constrained
to zero may cross the wire.

The minimum planes are:

| Plane | Lifecycle | Contents |
| --- | --- | --- |
| `W` | immutable connection/model setup | canonical packed private i16 model weights |
| `B,e` | fresh, burned after this attempt | response-wide incremental boundary/trace data |
| `KV,e` | accepted predecessor | canonical hidden K/V prefix |
| `KV,e+1` | proposed successor | predecessor plus canonical response tail |

All four roots are included in certificate framing.  The old K/V and weight
roots may already be in durable state, but omitting their bytes from the
certificate budget would hide framing dependence.

For `F_{p^2} = F_p[u]/f(u)`, write `v = v_0 + u v_1`.  The terminal adapter
authenticates both `F_p` limbs using separately domain-separated one-time raw
correlations.  Linearity must hold for the value, MAC and verifier-key share
on both limbs.  One 8-byte correction per consumed limb is counted; direct
per-cell corrections are forbidden.

### 3.2 Canonical schedule

A schedule entry has the fixed serialization

```text
(version, ordinal, plane_tag, root_id,
 segment_id, source_offset, source_len, padded_len,
 local_dimension, query_derivation_digest,
 authenticated_value_handle, operator_claim_digest).
```

Entries are sorted lexicographically by `(plane_tag, segment_id)`, have
consecutive ordinals, and cover the registered segment table exactly once.
Padding is a layout property and always has coefficient zero.  Query vectors
are derived from the committed operator transcript; they are not arbitrary
prover metadata.

For a weight tensor used at many tokens, the response-wide operator protocol
first stacks the use axis and reduces all uses to one terminal MLE point for
that tensor.  The physical weight segment therefore has terminal
multiplicity exactly one.  This work belongs to the operator proof: the ALFC
does not reconstruct `K` equality tables for `K` uses.

The concrete schedule compiler must emit a census

```text
segment_id -> (physical_len, terminal_count = 1, point, claim_digest)
```

and the verifier must recompute it.  A missing, duplicated or reordered entry
rejects before `beta`.

The R0 layout allocates eight physical weight segments per layer, two global
weight segments, four response-boundary segments, two predecessor K/V
segments and two successor K/V segments.  Thus the screen has 106 terminal
claims for GPT-2 and 378 for the 31B envelope.  The codec hard-caps a schedule
at `J_max = 512` logical terminal claims.  The concrete compiler must fit this
census or stop and rederive the proof/privacy/PCG budgets.  Over one
connection this bounds logical authenticated handles by
`t_max = R_max * J_max = 2^29`, and two-limb transfers by `2^30`.

### 3.3 Packed-functional identity and its cost

Let public disjoint segments `S_i` partition the non-padding packed indices.
Let `local_i(j)` be the canonical local coordinate of `j in S_i`, and let the
one terminal point be `r_i`.  After all entries are fixed, sample
`beta_i` in `F_{p^2}` and define

```text
L(j) = beta_i * eq(r_i, local_i(j))   when j in S_i,
       0                              on padding.
```

Then, by finite-sum reindexing,

```text
<W,L>
  = sum_j W[j] L(j)
  = sum_i beta_i * sum_(j in S_i) W[j] eq(r_i, local_i(j))
  = sum_i beta_i * MLE(W_i, r_i).
```

`VoltaZk.packed_functional_eq` proves the abstract identity with a canonical
`owner : J -> Option I`; `none` is padding and makes disjointness structural.

The construction algorithm, not just the identity, is registered:

1. traverse segments once in physical order;
2. generate the complete `eq(r_i, .)` table for the sole point in `O(N_i)`
   field operations (or stream the equivalent recurrence);
3. stream each packed i16 weight once, lift it canonically, and accumulate
   `W[j] * beta_i * eq(...)` into the two Fp limbs;
4. never materialize `L` or an expanded Fp/Fp2 copy of `W`.

This costs `sum_i O(N_i) = O(N)`, reads exactly `2N` packed source bytes in
the R0 budget and writes zero `L` bytes.  A code backend may add oracle I/O;
that traffic must be separately derived before R1.

Treating a fresh arbitrary linear form as requiring `Omega(N)` source reads
is the prudent C7 engineering presumption, not a formal unconditional lower
bound.  Success means making that pass bandwidth-optimal; zero scans are not
credited to preprocessing.

If one segment retains unrelated points `r_i,1,...,r_i,K`, coefficient
generation becomes

```text
L_i(j) = sum_h beta_i,h * eq(r_i,h, local_i(j))
```

and costs `Theta(K_i N_i)` absent another structured algorithm.  No paper in
the tournament removes this cost for arbitrary points.  Thus
`terminal_count = 1` is a protocol invariant and hard stop, not an
optimization note.

### 3.4 Transcript phase diagram

```text
Client durable journal             Provider / prover
----------------------             -----------------
reserve slot, nonce, two-limb
correlation ranges; persist
high-water marks
        |  authorization + client entropy
        |------------------------------------------->
        |                 commit seed, C_B,e, C_KV,e+1
        |<-------------------------------------------|
bind public state, C_W, C_KV,e, all four roots and sampler metadata
        |  operator/GKR/code challenges
        |------------------------------------------->
        |                 response-wide operator messages
        |<-------------------------------------------|
fix complete canonical schedule, every q_j and every authenticated(v_j)
        |  beta = H(transcript_through_fixed_schedule)
        |------------------------------------------->
        |                 one multi-plane ALFC proof
        |<-------------------------------------------|
        |  gamma = H(transcript_through_ALFC)
        |------------------------------------------->
        |                 one two-limb MAC settlement
        |<-------------------------------------------|
verify complete relation and CAS old head -> new head
persist certificate + transcript + consumed ranges
        |  durable ACK
        |------------------------------------------->
```

An abort at any point after reservation burns the slot, nonce, seed
commitment, masks and both correlation ranges.  It leaves the accepted head
unchanged.  A retry begins strictly after the burned high-water marks and has
a fresh response root and transcript.

## 4. Stateful privacy and connection security

### 4.1 Selected static-weight policy

C7 selects policy 3:

> PCS symbols and linear evaluations are never revealed; they are delivered
> only as one-time, connection-domain-separated VOLE-authenticated shares,
> under a new malicious-DV multi-session privacy theorem.

This policy permits a static `C_W` only if the theorem below is discharged.
It does not permit reuse merely because an underlying code/PCS is hiding or
HVZK.  If the theorem fails, C7 must stop and select/rebudget fresh roots, a
proved finite query budget, or a finite consumable pool.  There is no silent
fallback.

R0 scopes a static `C_W` to one connection.  Reusing the same root across
connections or colluding designated verifiers is unauthorized until either a
multi-user theorem supplies a root-wide attempt/query bound or a durable
root-wide counter accounts the sum of every attempt.  A per-connection union
bound cannot justify global root reuse.

### 4.2 Why a reusable affine mask is insufficient

If two accepted or selectively observed folds reuse a mask `R`,

```text
X1 = a W + b R
X2 = c W + d R,
```

then for `a*d - b*c != 0`,

```text
W = (d*X1 - b*X2) / (a*d - b*c).
```

The Lean theorem `reused_affine_mask_extract` proves this field identity.
It applies equally to partial code symbols or terminal folds.  Therefore C7
never places either `X1` or `X2` on the wire, and every authentication mask is
attempt-local and burned on abort.

### 4.3 Named privacy theorem still required

`C7-ALFC-MDV-STATEFUL-PRIV` must state the following game.

- A malicious designated verifier holds `Delta`, verification state and all
  client shares and chooses messages adaptively.
- It interacts for at most `R_max` authorized attempts, including accepted
  responses, failures, retries and selective aborts, with persistent `C_W`
  and accepted K/V roots.
- It sees at most `J_max = 512` logical authenticated terminal handles per
  attempt, including every partial attempt, and the theorem composes over the
  resulting `t_max = 2^29` adaptive functionals.
- It may observe all roots, queries, authenticated handles, proof bytes,
  timing classes admitted by the leakage policy, accept/reject, crash/replay
  recovery and the durable journal.
- For any two weight/cache witness sequences with identical declared public
  leakage and valid recurrence outputs, the real views are simulatable or
  computationally indistinguishable within the registered privacy error.
- The simulator handles adaptive queries and rejection feedback; masks,
  nonces and raw correlations are unique even for aborted transcripts; no
  clear symbol/evaluation is an oracle output.

Required hypotheses must be named individually: concrete commitment hiding
and binding, code query leakage, Fiat--Shamir/ROM, hash collision resistance,
real/AES PCG security, VOLE security with shared `Delta`, journal durability,
replay/fork exclusion and the exact public leakage function.  The t-query
CFW/constrained-code HVZK theorem used by 2026/391 has a non-adaptive,
query-bounded simulator; it does not discharge this game.

### 4.4 Horizon and union bound

Set

```text
R_max = 2^20 attempts.
```

An attempt is counted when its durable nonce/correlation reservation is
created, whether it later accepts, fails, crashes, retries or is selectively
aborted.  The connection closes before a `2^20 + 1`-st reservation.

R0 allocates at most 64 response-local bad events, each at most `2^-110`:

| Class | Maximum events |
| --- | ---: |
| operator/compute reductions | 16 |
| boundary commitments | 8 |
| predecessor/successor state | 8 |
| code/ALFC binding, proximity and privacy | 16 |
| two-limb terminal MAC | 8 |
| sampling/range rules | 4 |
| serialization/order | 4 |
| **Total** | **64** |

Each concrete event must still prove its degree, list-size, query and grinding
numerator fits this allocation; the table is not a generic "110-bit" label.
The connection budget is

```text
epsilon_response <= 64 * 2^-110 = 2^-104

epsilon_connection
  <= 2^20 * epsilon_response
   + 2^-128              hash
   + 2^-128              real/AES PCG
   + 2^-120              state/replay/collision
   + 2^-128              framing/transcript
  = 2^-84 + 2^-120 + 3*2^-128
  < 2^-83.99.
```

The executable budget computes the non-rounded bit value.  This retains
almost six bits of reserve above the 78-bit connection target.  The shared
`Delta` does not justify independence: the formal wrapper reuses M10's
fixed-other-coins slice and ordinary union bound.

The strict whole-bit label is 83 bits, five whole bits above 78; the effective
value is approximately 83.99999999998 bits.  The sum is slightly larger than
`2^-84`, so it is not labeled as a strict 84-bit result.

### 4.5 Atomic promotion, replay and forks

Verification and state promotion are one journal transaction keyed by
`(connection_id, epoch, old_root, predecessor_certificate, slot, nonce)`.
Recovery observes either the complete old record or the complete new record.
It never observes a promoted root without the matching certificate and
consumption high-water marks.

- A byte-identical produced certificate may be retransmitted after ACK
  ambiguity; no different certificate may occupy that slot.
- Once one certificate advances epoch `e`, neither it nor a sibling fork from
  the same old head is admissible against epoch `e+1`.
- Abort/reject marks the attempt burned and cannot promote K/V state.
- No retry may reuse the burned nonce, sampler seed commitment, PCS mask/root
  for the response-local planes, or either base-limb correlation range.

The C7 Lean module reuses the existing C6 durable-state definitions only as
an already proved abstract state-machine seam; it does not reuse the C6 proof
backend or certificate topology.

## 5. Backend tournament

Labels mean: **Evidence** is a proved/published component fact;
**Assumption** is required but not supplied for C7; **Dead end** is excluded
from the selected line.

### 5.1 A — packed Ligerito/ERA code plus constrained-code masking

**Evidence**

- Ligerito has strict unique-decoding soundness and
  `~log^2(N)/loglog(N)` communication; its measured 100-bit proofs grow from
  145 KiB at `2^20` to 420 KiB at `2^30`.
- ERA gives a field-agnostic, linear-time encoder construction and a
  query-efficient code-switch IOPP whose Merkle-compiled proof law is
  `O(lambda log^2 N)`.
- 2026/391 gives t-query HVZK constrained-code/code-switch components and an
  explicit masking construction for a public target.
- Jagged gives the canonical heterogeneous packing map and an `O(N_i)` method
  to enumerate one equality table.

**Assumptions / missing composition**

- 2026/391 proves HVZK for a query-bounded non-adaptive distinguisher, not the
  C7 malicious-DV connection game.
- No paper supplies the no-clear two-limb VOLE-MAC terminal adapter.
- ERA's query-efficient `2^32` proof is an estimate, not a prover/memory
  measurement; its random permutations/multipliers and indexer oracles are
  linear setup objects.
- Neither Ligerito nor ERA supplies the required one-sequential-scan,
  bounded-memory composed schedule at 31B.

**R0 recommendation:** architectural front-runner, **NO-GO for R1** until all
Section 0 hard stops are discharged.

### 5.2 B — SwitchFold/QAFold challenger

**Evidence:** SwitchFold claims an `O(N)` prover and
`O(lambda log^2 N)` proof/verifier for suitable truly linear-time encodable
geometric code sequences.  It finalizes accumulated generator claims with a
decider, so it could in principle settle inside one response.

**Assumption:** QAFold uses `O(N log N)` WHT additions, its `2^30` benchmark
used 377 GiB host memory, and no bounded-memory schedule, hiding theorem,
authenticated terminal or stateful privacy theorem is supplied.  Its
published evaluation is clear.

**Dead end as implemented:** `T` arbitrary openings cost `O(TN)`; the special
generator-matrix accumulator does not batch arbitrary weight functionals.

**R0 recommendation:** retain as an analytic challenger, **NO-GO**.

### 5.3 C — strict unique-decoding WHIR control

**Evidence:** WHIR-UD is the most mature executable code control in the
tournament.  Published 128-bit, rate-1/2 proofs are 621 KiB at `2^24` and
770 KiB at `2^28`; prover evidence reaches 62 seconds at `2^28` on a large
host.  Staying inside unique decoding avoids WHIR's correlated-agreement
list-decoding conjecture.

**Assumption:** WHIR supplies no hiding/stateful privacy theorem, authenticated
terminal, or bounded-memory result.  A `2^30` low-rate case ran out of memory
on a 768-GiB host.

**R0 recommendation:** **GO as a local executable control only** after the
packed schedule exists.  Use one packed oracle and one logical C7 ALFC
invocation.  The C6.3 eight-body WHIR+Bolt topology is forbidden.  Control
results remain component evidence and cannot promote C7 state or grant E2E
credit.

### 5.4 Layout/reference-only and quarantined lines

| Item | Label | C7 disposition |
| --- | --- | --- |
| Jagged | Evidence/layout | canonical public heterogeneous layout; do not pay its generic ~5N adapter |
| TensorSwitch | Dead end | proof `N^(1/2+o(1))`, about 15.77x at the registered ratio |
| WARP | Dead end | arbitrary off-hypercube points retain `KN`; cross-response settlement forbidden |
| ITC batch evaluation | Dead end | univariate compiler; authors do not obtain linear-time multilinear batching |
| polynomial preprocessing 2025/238 | Evidence/warning | evaluation binding only; strong binding/knowledge requires proving DS correctness |
| LigeSIS | Quarantine | expanded RS/subset-sum/secondary PCS, no hiding theorem, distributed rather than one-pass target |
| DeepProve / zkAgent | Evidence only | response-wide batching/prefix equivalence, but teacher-forced rather than incremental KV recurrence |
| dynamic DV zk-SNARKs | Dead end | update locality is Hamming distance of the whole witness, not a free transformer update |
| one-group-element DV SNARG | Dead end/evidence | group-heavy linear circuit work; useful warning about rejection-feedback reuse |
| Mac'n'Cheese | Evidence/dead end | VOLE-MAC linearity and streaming pattern only; full transformer circuit is linear communication |

Also excluded are dense 8-byte boundary/K/V corrections; Ligero/Brakedown
sqrt-size certificates; TensorSwitch/Titan proof laws above the scaling
exponent; KZG/IPA/group backends with a full large-field online MSM; dynamic
SNARK replacement of the transformer computation; Twist/Shout without an
accepted-predecessor bridge; reusable secret Freivalds sketches; any clear
weight evaluation; unbounded root/mask reuse; HVZK promoted to malicious-DV
privacy; hidden list-decoding/conjectural assumptions; and withdrawn LiLAC,
HyperWolf or similar bases.

## 6. Registered analytic budgets

The executable authority is `scripts/budget_c7_stateful_alfc.py`.  Every
output carries `credit:false`.  Constants describe a target envelope and
storage consequence of the selected candidate components; they are not
measured C7 proof bytes or time.

### 6.1 Models and common workload

| Field | GPT-2 | Gemma-class 31B envelope |
| --- | ---: | ---: |
| packed weight scalars | 124,000,000 | 30,826,400,000 |
| ratio to GPT-2 | 1 | 248.6 |
| layers | 12 | 46 |
| hidden width | 768 | 4,608 |
| query / K/V heads | 12 / 12 | 32 / 16 |
| head dimension | 64 | 128 |
| accepted / response / successor tokens | 100 / 50 / 150 | 100 / 50 / 150 |

The 31B point is an explicit screening envelope, not a claim about a named
published checkpoint.  A real target must replace this configuration and
rerun the script before it can receive credit.

For `R = 248.6`, any proof term `N^a` satisfying at most 3x growth obeys

```text
a <= log(3) / log(248.6) = 0.199...
```

The optional 6x ceiling gives `a <= log(6)/log(248.6)`; it is reported but is
not active without later owner approval.

The following law table and component numbers are reproduced by the script;
the symbolic definitions are authoritative:

```text
B_certificate
  = B_compute
  + B_boundary_commitments
  + B_state
  + B_weight_ALFC
  + B_MAC
  + B_framing.

B_weight_ALFC(N)
  = 4,014,000 B
    * (110/100)
    * (log2(N)/32)^2.
```

The weight term is conservatively calibrated to ERA's published 4.014-MB
`2^32`, 100-bit estimate and uses the larger `log^2 N` law.  The other exact
formula constants in the script are **allocations** sized to expose layer,
token, K/V length, terminal-segment and root dependence.  Changing them is a
ledger deviation, not a free fit after measurement.

### 6.2 Certificate target table

| Certificate component | GPT-2 (B) | 31B envelope (B) | Classification |
| --- | ---: | ---: | --- |
| `B_compute` | 6,000,000 | 9,379,670 | target allocation |
| `B_boundary_commitments` | 1,200,000 | 1,846,426 | target allocation |
| `B_state` | 2,000,000 | 2,676,008 | target allocation |
| `B_weight_ALFC` | 3,116,843 | 5,234,948 | ERA-calibrated transposition |
| `B_MAC` | 2,208 | 6,560 | target allocation; both Fp limbs |
| `B_framing` | 66,512 | 68,688 | target allocation; all four roots |
| **Complete target envelope** | **12,385,563** | **19,212,300** | **`credit:false`** |

The large/GPT-2 ratio is `1.55118503697x`.  All three Tier-A allocation
checks pass (`12.39 MB <= 30 MB`, `19.21 MB <= 100 MB`, ratio `<= 3x`), but
none is protocol or measurement credit.  In particular, the table cannot be
used as a certificate claim until every target allocation is replaced by an
exact compiled byte census.

The preferred gates are GPT-2 approximately at or below 30 MB, the 31B point
at or below 100 MB, and large/GPT-2 growth at or below 3x.  Tier B's 200-MB
large-model ceiling is inactive and requires explicit owner approval.

### 6.3 Scaling-law screen

| Weight-law term | 31B/GPT-2 growth | Within 3x? | Within optional 6x? |
| --- | ---: | :---: | :---: |
| `log N` | 1.295981257x | yes | yes |
| `log^2 N / log log N` | 1.556932990x | yes | yes |
| `log^2 N` | 1.679567419x | yes | yes |
| `N^(1/4)` | 3.970775020x | no | yes |
| `sqrt(N)` | 15.767054259x | no | no |
| `N` | 248.6x | no | no |

The exact exponent ceilings are `0.1991738805` for 3x and `0.3248386079`
for 6x.  The optional 6x column is sensitivity only; it grants no Tier-B
authorization.

Passing the weight-only law is necessary, not sufficient.  The script also
reports layer count, `T`, predecessor/successor K/V length, terminal-segment
count and root count.  A design that batches only `N` while allowing any of
those dimensions to multiply certificates has not passed C7.

### 6.4 Online prover I/O, time and memory

For the weight terminal, R0 registers:

```text
packed bytes read per response = 2 * N
materialized L bytes           = 0
expanded Fp/Fp2 weight copy    = forbidden
source passes                  = 1 target
working chunk                  = configurable, default 256 MB
bandwidth floor                = (2*N) / 3.2e9 seconds
```

| Online weight-terminal item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| packed i16 bytes read | 248,000,000 B | 61,652,800,000 B |
| source passes | 1 target | 1 target |
| bytes written for `L`/spill | 0 B | 0 B |
| resident expanded weight wrapper | 0 B | 0 B |
| 256-MB chunks | 1 | 241 |
| 3.2-GB/s bandwidth floor | 0.0775 s | 19.2665 s |

| Online memory item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| configurable weight-stream chunk | 256,000,000 B | 256,000,000 B |
| materialized `L` | 0 B | 0 B |
| expanded resident Fp/Fp2 weights | 0 B | 0 B |
| packed successor K/V source | 5,529,600 B | 56,524,800 B |
| code/hash/operator workspace | not derived | not derived |
| complete peak RSS/device memory | **not established** | **not established** |

The exact compute/boundary/K/V proxies used by the target allocations are
`353,894,400 / 460,800 / 2,764,800` cells for GPT-2 and
`48,837,427,200 / 10,598,400 / 28,262,400` cells for the 31B envelope.  They
make layer, response-token, successor-length, K/V-head and head-width
dependence executable.  The terminal schedule has 106/378 claims, all with
multiplicity one.

This floor is not prover time.  The complete symbolic time is

```text
T_response
  = T_incremental_fixed_point_decode
  + T_operator_reduce
  + max(weight_bytes_read / BW_source,
        field_work / field_throughput)
  + T_code_open_and_hash
  + T_MAC
  + T_serialize_and_fsync.
```

No R0 source supplies the missing composed field/hash rates or proves the
single-pass code schedule, so total seconds are `not established`.  The
time-space sumcheck literature gives bounded RAM by repeated passes; it does
not establish one pass and bounded memory simultaneously.  Any R1 schedule
must report exact pass count, source/oracle bytes read, scratch bytes written,
peak RSS/device use and bandwidth rooflines.

The 256-MB chunk is a configurable target, not a complete peak-memory claim.
The missing code/hash/operator rows are an explicit Backend-A hard stop; they
cannot be filled by reclassifying the 1.221-TB 31B persistent oracle as
"setup" while mapping it resident during a response.

### 6.5 Setup, persistent storage and refresh

The script makes linear setup visible instead of treating it as free:

```text
packed model                  = 2*N bytes
ERA-style encoded oracle      = 4.4*N field symbols * 8 B
P1/P2 permutations + M        = N*(4 + 4 + 8) bytes
Merkle tree                   = 2*ceil(4.4*N/64)*32 B
```

| Setup/storage item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| packed i16 model | 248,000,000 B | 61,652,800,000 B |
| ERA-style 4.4x field-symbol oracle | 4,364,800,000 B | 1,085,089,280,000 B |
| `P1` permutation | 496,000,000 B | 123,305,600,000 B |
| `P2` permutation | 496,000,000 B | 123,305,600,000 B |
| multiplier vector | 992,000,000 B | 246,611,200,000 B |
| compact Merkle tree, 64 symbols/leaf | 545,599,968 B | 135,636,159,968 B |
| persistent oracle + Merkle | 4,910,399,968 B | 1,220,725,439,968 B |
| **total setup disk** | **7,142,399,968 B** | **1,775,600,639,968 B** |
| minimum fused preprocessing I/O | 7,142,399,968 B | 1,775,600,639,968 B |
| 3.2-GB/s preprocessing floor | 2.2320 s | 554.8752 s |
| non-fused Merkle extra read | 4,364,800,000 B | 1,085,089,280,000 B |

A full fresh-root refresh has the same `7.142 GB / 1.776 TB` I/O floor in
this screen.  A consumable `2^20` root/oracle pool would require about
`5.149 PB / 1.280 EB` before other metadata, so it is sensitivity evidence
against silently switching to policies 1 or 4.  Four-byte permutation
indices require canonical segment-local shards below `2^32`; that layout is
an assumption, not a completed indexer.

The encoded-oracle and indexer numbers are consequences of the R0 ERA-style
storage model, not a selected production layout.  They are intentionally
large and contribute to Backend A's NO-GO.  Setup preprocessing time is
reported as bytes processed and a bandwidth floor; code generation, hashing
and random-permutation work remain separately unmeasured.

Policy 3 has no routine static-weight root refresh within a connection.  A
model change rebuilds all model setup.  If the privacy theorem fails and a
fresh-root or finite-pool policy is selected, its full re-encoding/storage
refresh cost must be added before implementation.  Response trace storage is
attempt-local.  The accepted K/V provider state persists only the current
canonical prefix and its commitment data; old proposed states are deleted
only after durable acceptance or recorded burn according to the future R1
journal design.

### 6.6 Security budget

| Security item | Registered value |
| --- | ---: |
| attempts in connection horizon | `2^20` |
| response-local bad events | 64 |
| allocation per event | `2^-110` |
| `epsilon_response` | `2^-104` |
| hash / PCG / state / framing | `2^-128 / 2^-128 / 2^-120 / 2^-128` |
| exact `epsilon_connection` | `17592186044675 / 2^128` |
| effective connection bits | `83.99999999997877` |
| strict whole-bit label | 83 bits |
| target | at least 78 bits |

The exact result must remain at least 78 bits after the `2^20` horizon.  If a
concrete backend needs more than 64 local events, a larger list/degree
numerator, more roots, or additional error terms, the per-event parameter is
raised and the executable calculation rerun before code.

## 7. Lean-first obligations

`lean/VoltaZk/C7StatefulAlfc.lean` is additive and does not modify frozen
M1--M12 statements.  It proves the following algebra/state seams:

| Obligation | Lean result |
| --- | --- |
| heterogeneous packed functional | `packed_functional_eq` |
| fixed-before-beta RLC | C7 fixed-claim RLC root/cardinality theorem |
| multi-commit terminal MAC, both limbs | C7 two-limb key/MAC linearity theorem |
| affine mask reuse extraction | `reused_affine_mask_extract` |
| append MLE/linear-functional difference | C7 append-difference theorem |
| prefix and accepted-tail induction | C7 prefix/transition-chain theorems |
| atomic promotion/replay/fork exclusion | C7 wrappers over the existing durable state seam |
| connection union bound/shared Delta | C7 wrapper over M10's slice union theorem |
| serialized schedule refinement | C7 canonical schedule-to-ALFC refinement theorem |

These theorems prove no concrete PCS binding, hash/PCG security, transformer
compiler completeness or malicious-DV privacy.  Those assumptions remain
visible in `AcceptC7` and cannot be hidden behind an ideal ALFC API.

## 8. R0 disposition and exact resume conditions

### 8.1 Backend/control recommendation

- **Backend A: NO-GO for R1 implementation.**  Keep it as the selected design
  candidate and resolve the one-pass code schedule, exact storage, terminal
  adapter and stateful privacy theorem before changing this verdict.
- **WHIR-UD control: GO for a smallest local control only.**  It may test the
  canonical packed schedule and no-clear adapter on a tiny case.  It grants no
  complete certificate, scale, privacy or E2E credit.

### 8.2 Resume conditions for an R1 proposal

An owner may consider opening R1 only after a new checkpoint supplies all of:

1. an executable canonical compiler with terminal multiplicity exactly one
   for every physical weight, boundary and K/V segment;
2. a proved/checked ALFC adapter whose two Fp limbs enter VOLE-MAC without a
   clear evaluation or reusable affine fold;
3. a one-pass bounded-memory backend schedule with exact setup/oracle and
   online read/write byte counts;
4. a malicious-DV connection privacy theorem for the selected static-root
   policy and the exact `R_max` game;
5. a composed certificate/security budget replacing allocation constants
   with derived protocol counts while retaining the gates.

If those pass, R1 is the smallest complete production-equivalent case: two
incremental responses, real finite PCG, only consumed profiles,
serialization/reload/full verifier, accepted predecessor/successor K/V,
mutation tests, abort burn and atomic promotion.  It starts locally.  A first
pod experiment still requires a later explicit owner GO and must run the
smallest complete serialized case before any scale component.

## 9. Deviations and non-credit record

- The Gemma-class 31B point is a declared envelope because no exact target
  checkpoint/configuration was supplied.  Its ratio and all model-shape inputs
  are explicit and replaceable in the executable budget.
- R0 selects policy 3 because fresh weight roots or a finite full-mask pool
  would add unbudgeted full encodings/storage.  The policy is not accepted for
  production until its new privacy theorem is proved.
- The proof-byte table is a target allocation calibrated to public component
  evidence, not a composed certificate derivation.  It is `credit:false` and
  is one reason Backend A remains NO-GO.
- No pod, production provider, frozen forward, quantization spec, or frozen
  M1--M12 statement was touched in R0.

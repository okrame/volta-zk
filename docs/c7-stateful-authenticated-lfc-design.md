# C7 — stateful authenticated linear-functional commitment

**Status:** C7 R0.5 policy-3 terminal NO-GO; policy 2 awaits an explicit owner
decision.  No SIMT kernel, large prover, E2E or pod.  This document is the
task-specific authority named by `prototype-status.md`.

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

R0.5 retains the owner's 1.A/2.A/3.A choices and records the terminal result
of the CPU-first policy-3 screen.

1. The immutable model, response trace and persistent cache are separate
   commitment planes.  "One opening" means one transcript-bound
   multi-commitment ALFC invocation, not one literal Merkle root.
2. Every physical packed segment has **exactly one** operator-reduced terminal
   point before the ALFC batching challenge.  This is the only admitted
   resolution of the `O(KN)` packed-functional hard stop.
3. Policy 3 was the sole active static-weight line through R0.4 and still
   defines the no-clear experiment, but R0.5 gives it a terminal **NO-GO**
   under the registered gates.  Every credible construction now has an
   append-only disposition across security/privacy, setup/storage, online
   resources and serialized query/challenge bytes.  Policy 2 remains dormant
   and grants no implementation authority until a later explicit owner
   activation.
4. The published Merkle/BCS forms of Ligerito, ERA and WHIR reveal queried
   row/column/leaf payloads.  Therefore Backend A plus a terminal-only
   VOLE-MAC adapter is **rejected under policy 3**, not an architectural
   front-runner.  WHIR-UD remains **GO only as a transparent tiny/scaled code
   control**; it carries no private-weight or no-clear credit.
5. Persistent setup has target `A_setup <= 2.00` and hard ceiling
   `A_setup <= 2.10`.  The interval `(2.00, 2.10]` is a preregistered 5%
   tolerance, not permission for an expanded field/code/tag plane or an
   N-scale temporary.
6. Weight-oracle `B_query_wire` (the interactive successor to the historical
   `B_query_FS` label) is included inside `B_weight_ALFC`, never added as a
   seventh component.  Its hard ceiling is 105% of the registered target; use
   of the tolerance is recorded explicitly and the complete certificate must
   still pass Tier A and the 3x growth gate.
7. The authorized tiny CPU screen is complete.  Its online algorithm works,
   but it fails code distance and ordered-root setup, so
   `C7_CPU_REFERENCE_PASS=false`.  No further backend, large-prover/E2E,
   provider or pod action is authorized.
8. No current backend passes setup, one-pass opening and private query-byte
   gates together.  The digest-only form is terminally rejected as a composed
   policy-3 backend.  Logical `g=141` remains the screened format; `g=256`
   is not an automatic recovery option.
9. Privacy comparisons use equal witness-independent `Leak_base`; hiding
   roots, digests and paths are generated independently in the two worlds.
   Requiring equal binding roots would make weight and K/V privacy vacuous.
   The only salt length retained for screening is 256 bits.  A concrete
   Poseidon2 leaf function is implemented, but no commitment receives
   cryptographic or setup credit without its checker/hiding/binding theorem.
10. Fresh honest-DV `rho_i`, `beta` and `gamma`, each sampled after its exact
    committed prefix and serialized in the durable transcript, are selected.
    The selected protocol uses no Fiat--Shamir oracle (`Q_FS=0`); FS remains
    quarantined, not a dormant uncounted transform.
11. No optimized SIMT kernel or GPU scaffold may exist: the executable CPU
    screen proves the online cost identity but does not pass the PCS distance
    and setup gates.
12. After that checkpoint, SIMT may accelerate only streaming setup,
    `LeafCom`/Merkle, PCG/VOLE, MAC, Fp/Fp2, leaf checks and reductions.  It
    must remain byte-identical to CPU and may not add a codeword, model-sized
    scratch, second scan, `qN`, unassigned traffic or transcript difference.
    Logical `g=141` never changes; any wider device tile is temporary measured
    zero padding excluded from commitments, certificate and transcript.
13. Direct sparse-coordinate regeneration is rejected by the
    generator-incidence argument.  The explicit one-stage RA shared circuit
    removes `qN` online work but fails the independent distance/root gates;
    the tiny search is closed.

The following are terminal R0 hard stops.  Until all are discharged there is
no large prover implementation, production equivalence claim, provider/pod
contact, or proof/time/memory credit:

- a concrete compiler census must show one terminal point per physical
  segment; any segment with multiplicity `K_i > 1` reopens the `sum K_i N_i`
  stop;
- any newly selected code/commitment composition must have a proved,
  executable one-pass bounded-memory schedule, with exact read/write traffic
  and no expanded resident Fp/Fp2 weight wrapper;
- the CPU reference must derive
  `C(N,q,h)=c_source*N+P(q,h)` with `c_source` independent of `q`, and
  `M<=chunk+M_fixed+P_M(q,h)`; timing sweeps alone cannot discharge this stop;
- SIMT work is blocked until the ledger records `C7_CPU_REFERENCE_PASS`.
  Afterwards any second packed read, complete codeword, model-sized scratch,
  `qN` source work, unmetered host/device traffic, unclassified barrier or
  CPU/SIMT transcript mismatch is terminal for that implementation;
- the authenticated terminal must operate in the actual Fp2 extension field
  under one shared `Delta`; its two serialized Fp limbs must be checked without
  replacing Fp2 multiplication by independent base-field MACs;
- under policy 3, every queried oracle payload and every witness-dependent
  intermediate message—not merely the terminal evaluation—must remain hidden
  or authenticated and privately verified;
- a concrete domain-separated `LeafCom`, tree hash and transcript hash must
  supply adaptive hiding, position binding and an arithmetized private
  checker; collision resistance alone is not hiding, and an ideal random
  oracle is not an executable checker;
- soundness must use either a direct authenticated-checker theorem or an
  explicit committed-input PoK/extractor.  Opaque handles plus the verifier's
  `Delta` do not extract a virtual clear PCS transcript, while serializing a
  raw prover tag would reveal the plaintext;
- a weight oracle may persist only the canonical packed weights, one compact
  digest-only salted leaf commitment/index and compact metadata.  An expanded
  Fp/Fp2 weight copy, encoded codeword, per-coordinate authentication plane,
  P1/P2/multiplier planes or consumable root/mask pool is an anti-X4d hard
  stop; the registered numeric tolerance does not admit those shapes;
- every candidate must compile the exact query count by root and round and
  the complete serialized bytes under the selected challenge mode.  Query
  answers/private handles, authentication or multiproof material, round
  commitments and framing are assigned exactly once to the six certificate
  components.  Missing interactive messages or later Fiat--Shamir transform
  bytes fail closed;
- the malicious designated-verifier, adaptive, stateful privacy theorem must
  cover the full connection horizon, rejection feedback, retries and
  selective aborts;
- certificate constants, setup/oracle storage and refresh must be obtained
  from the composed protocol.  The R0 calculator contains allocation caps and
  artifact-volume sensitivity only, all `credit:false`; it is not a compiled
  certificate, security proof or construction theorem.

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

One real execution exposes:

- model identifier, architecture, quantization/layout digest and static
  weight commitment root;
- input/output token transcript, response length and sampling policy;
- predecessor/successor epochs and cache lengths, but not K/V contents;
- commitment roots, certificate length, public challenge/query metadata,
  accept/reject and durable journal state.

Privacy is only required between weight/cache witnesses inducing the same
declared **base leakage** `Leak_base`, which excludes every witness-dependent
hiding commitment value: `C_W`, boundary/K/V roots, leaf digests and paths.
The challenger constructs these independently in each left/right world.  The
public shape, indices, lengths and equality/linkability pattern must match;
the root bytes need only be indistinguishable.  Within either world `C_W`
remains static and therefore linkable across attempts.  Requiring the same
binding root in both worlds would restrict the game to essentially identical
weights and make the privacy claim vacuous.

Availability and suppression of a sampled response are not hidden.  The C7
relation requires a published token to follow the committed sampling coins;
it does not promise unbiased service after a provider chooses to abort.
Every such attempt still consumes the connection horizon and burns its
masks/correlations.

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
6. a client sampling-entropy commitment, the later prover sampling-seed
   commitment, the client's canonical opening and the exact pre-response
   prefix deriving per-step sampling coins; the provider opening remains
   private and is proved inside the relation, and sampling entropy is
   domain-separated from proof challenges;
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
- the provider's private 32-byte sampling seed opening, constrained to its
  public pre-response commitment and to every derived sampling coin;
- the canonical K/V tail written by the `T` steps, intermediate logical cache
  views, and successor opening data;
- commitment randomness for the fresh trace/successor planes;
- operator-reduction messages, the canonical terminal schedule, private
  terminal values, extension-field authenticated shares/tags, the two-limb
  serialization witness, and the exact one-time VOLE correlations/masks
  consumed by this attempt.

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
session_binding = Encode(protocol_version, connection_id, nonce, e, k, T,
                         model/layout/quantization digests, C_W, C_KV,e,
                         predecessor_certificate, sampler_policy, input_tokens),
client_entropy_commit =
  H("VOLTA-C7/SAMPLE/CLIENT/v1" || session_binding || client_entropy),
prover_seed_commit =
  H("VOLTA-C7/SAMPLE/PROVER/v1" || session_binding ||
    client_entropy_commit || prover_seed),
KV_(t+1) = KV_t || KV_write_t,
sampling_prefix = Encode(protocol/session/authorization,
                         client_entropy_commit, prover_seed_commit,
                         client_entropy_open),
coin_t   = H(domain, connection_id, nonce, e, t,
             prover_seed, client_entropy, H(sampling_prefix)).
```

The client commits its entropy first.  The prover then commits its seed before
the client opens.  After that client opening verifies, the prover keeps its
seed private, derives the coins and proves inside `AcceptC7` that the seed
opens `prover_seed_commit` and was used correctly.  The two preimages are
exactly 32 bytes and the deterministic commitments use no separate opening
randomness.  Collision/binding, preimage-hiding of the uniform client entropy
until `prover_seed_commit` is fixed, and preimage-hiding of the provider seed
from the verifier are named hash hypotheses charged to `epsilon_hash`, not
consequences of the codec or of collision resistance.
`sampling_prefix` ends at the verified client opening and explicitly excludes
output tokens, `C_B,e`, `C_KV,e+1` and every response-proof message.  Both commitment
openings and the canonical prefix are checked by the response relation, while
the provider opening never crosses the wire, so no sampling coin depends
circularly on an output it helps generate or enlarges declared leakage.
Greedy decoding is the degenerate sampler with no random branch.

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
   `t = 0,...,T-1`, including the public client opening, the private provider
   opening, the exact pre-response prefix, the fixed token tie rule and
   sampler coins.
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
8. **Terminal settlement.** One post-ALFC challenge settles all
   extension-field MAC residuals to zero; both serialized coordinates check,
   and every reserved correlation/mask is consumed exactly once.
9. **Atomic state change.** A durable compare-and-swap on the predecessor head,
   nonce and slot promotes `(e,k,C_KV,e)` to `(e+1,k+T,C_KV,e+1)` together with
   the certificate/transcript journal.  The ACK is sent only after this commit.

Concrete PCS binding/knowledge soundness, code distance, collision resistance,
fresh honest-DV entropy delivery and transcript binding, real-PCG security and
malicious-DV privacy are explicit hypotheses.  Fiat--Shamir/ROM applies only
to the quarantined alternative.  Component lemmas do not imply this complete
predicate.

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

For `F_{p^2} = F_p[u]/f(u)`, write `v = v_0 + u v_1`.  The terminal is one
authenticated value over the extension field with one connection-scoped
`Delta in F_{p^2}`.  Its canonical codec has two `F_p` coordinates and must
check both, but those coordinates are not independent MAC fields: extension
multiplication includes cross-limb terms.  The R0 allocation reserves one
8-byte correction per coordinate; the concrete correlation construction and
wire codec remain hard stops.  Direct per-cell corrections are forbidden.

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

The budget-only illustrative layout uses eight weight segments per layer, two
global weight segments, four response-boundary segments, two predecessor K/V
segments and two successor K/V segments.  That produces illustrative counts
of 106 and 378; no canonical serializer/compiler manifest currently derives
them.  Likewise `J_screen_cap = 512` is an admission target, not an enforced
codec bound.  The corresponding `2^29` connection-handle count is only a
sensitivity screen.  Neither number may parameterize a privacy theorem until
the concrete compiler, codec and every partially visible attempt are counted
and a 513th handle fails closed before any challenge or correlation release.

### 3.3 Packed-functional identity and its cost

Let public disjoint segments `S_i` partition the non-padding packed indices.
Let `local_i(j)` be the canonical local coordinate of `j in S_i`, and let the
one terminal point be `r_i`.  After all entries are fixed, sample one scalar
`beta in F_{p^2}` and set `beta_i = beta^(ordinal_i+1)`; this exact
scalar-power schedule is what the RLC root theorem analyzes.  Define

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
reserve slot, nonce, terminal
correlation ranges; persist
high-water marks; commit fresh
sampling entropy
        |  authorization + entropy commitment
        |------------------------------------------->
        |                    commit prover seed only
        |<-------------------------------------------|
        |  open sampling entropy
        |------------------------------------------->
provider verifies the client opening, privately derives every coin_t
from the exact pre-response sampling prefix, executes all T DecodeStep_q
        |  output tokens + sampler metadata + C_B,e + C_KV,e+1
        |                    + first proof messages
        |<-------------------------------------------|
bind public state, fresh F_VOLE+id, C_W, C_KV,e, all four roots,
output tokens, sampler metadata and each operator/code message m_i
the response relation proves the private provider-seed opening and coin use
        |  fresh DV challenge rho_i; repeat by round
        |------------------------------------------->
        |       close canonical schedule, every q_j,
        |       authenticated(v_j), prefix and shape
        |<-------------------------------------------|
        |  fresh response-wide batching beta
        |------------------------------------------->
        |                 one multi-plane ALFC proof
        |<-------------------------------------------|
        |  fresh terminal-settlement gamma
        |------------------------------------------->
        |                 one Fp2 MAC settlement
        |<-------------------------------------------|
verify complete relation and CAS old head -> new head
persist certificate + transcript + consumed ranges
        |  durable ACK
        |------------------------------------------->
```

The selected path is deliberately interactive: an honest designated
verifier samples each `rho_i`, then `beta`, then `gamma` only after its exact
canonical prefix is fixed, and the durable certificate serializes them.
Privacy is still against a malicious verifier choosing them arbitrarily; the
existing ideal-VOLE theorem already permits adaptive challenges.  Soundness
uses honest unpredictable verifier randomness and pays the registered attempt
union bound, not an unbounded Fiat--Shamir grinding oracle.

The alternative noninteractive compiler replaces each challenge message with
locally recomputed

```text
H_FS(domain || F_VOLE_id || statement || canonical_prefix || round_id).
```

It is **quarantined**, not silently enabled.  Its prover and verifier must
recompute identical challenges; `Q_FS` is a separate adversarial query bound.
A roughly 128-bit Fp2 challenge with `Q_FS=2^64` has at most a roughly 64-bit
direct grinding bound.  Even before degree/list factors, retaining 110 bits
would require `Q_FS<=2^18`, at least 174 effective challenge bits, or a proved
independent repetition whose extra terminal multiplicity, scan work and bytes
are all counted.  Concrete factors can only tighten those requirements.  R0.4
therefore fixes `Q_FS=0`: no FS query or grinding term exists in the selected
protocol, while serialized interactive challenges and framing still count in
the certificate.  Reintroducing FS changes the statement and byte budget and
requires a later owner decision.

An abort at any point after reservation burns the slot, nonce, seed
commitment, masks and every reserved correlation range.  It leaves the
accepted head unchanged.  A retry begins strictly after the burned high-water
marks and has a fresh response root and transcript.

## 4. Stateful privacy and connection security

### 4.1 Selected static-weight line and dormant fallback

R0.2 selects policy 3 as the sole active line:

> PCS symbols and linear evaluations are never revealed; they are delivered
> only as one-time, connection-domain-separated VOLE-authenticated shares,
> under a new malicious-DV multi-session privacy theorem.

R0.5 records that every credible instantiation of this line fails at least one
registered composition gate, so policy 3 is now terminally rejected for
implementation.  The game below remains the exact statement that was tested
and explains the rejection; it is not a claim that its missing theorem was
proved.  Policy 2 is still dormant until explicit owner activation.

This policy permits a static `C_W` only if the theorem below is discharged;
until then static-root reuse is unauthorized even inside one connection.
It does not permit reuse merely because an underlying code/PCS is hiding or
HVZK.

Policy 2—bounded clear masked-symbol queries under a proved total horizon—is
retained only as a dormant fallback.  Failure of one policy-3 candidate or
one gate does not activate it.  Activation requires (i) an append-only
terminal classification of every credible policy-3 line, retaining each
security, setup, prover, memory and proof-byte reason, and (ii) a later
explicit owner decision.  Exhaustion means that all credible constructions
have been disposed, not that one construction must fail every axis at once.
There is no automatic or silent fallback.  R0.5 satisfies condition (i);
condition (ii) is now the exact owner decision gate.

If policy 2 is later activated, its theorem and durable counter must bound
every query made against a root across accepted attempts, failures, retries,
selective aborts, connections and colluding designated verifiers.  That
horizon and its clear-symbol leakage must be fixed before parameters or
proof bytes are optimized.

If policy 3 is accepted and proved, its first proposed scope is one
connection.  Reusing the same root across connections or colluding designated
verifiers remains unauthorized until either a multi-user theorem supplies a
root-wide attempt/query bound or a durable root-wide counter accounts the sum
of every attempt.  A per-connection union bound cannot justify global reuse.

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

`C7-ALFC-MDV-STATEFUL-PRIV(lambda,R_max,L,Q_leaf,interactive)` is a left/right
game for the selected protocol (`Q_FS=0`).
For two valid witness histories `(W_0,KV_0,trace_0)` and
`(W_1,KV_1,trace_1)` with equal witness-independent `Leak_base`, the
challenger samples `b`, independently constructs that world's hiding roots
and salts, and runs at most `R_max` durable reservations.  A malicious
designated verifier controls `Delta`, its keys, public challenges, aborts,
retries and rejection feedback.  Its view includes every byte prefix,
queried digest/path/index, length and admitted timing class, accept/reject and
journal transition.  The weight root remains static and linkable within the
chosen world.  No root equality is required across worlds.

Every witness-dependent message must occur only after reservation; an abort
at any byte prefix burns all associated state.  The concrete codec must
enforce the number of handles and windows; `J_screen_cap=512` and `2^29` are
not theorem parameters until compiled.

The required hybrid sequence is explicit:

1. replace the salt PRF and real PCG/VOLE by ideal independent salts and
   `F_sVOLE+id` correlations;
2. refine the concrete private leaf/hash/PCS checker to public-shape
   authenticated windows whose only openings are true zero residuals;
3. use the existing straight-line malicious-verifier simulator for all
   corrections, adaptive challenges and partial transcripts;
4. replace branch-0 roots, queried digests and public paths by branch 1 using
   adaptive multi-target `LeafPathHide`;
5. reverse the ideal-window and PRF/PCG hybrids for branch 1, then compose
   durable replay/fork transitions over the connection.

The ideal-VOLE middle is already formal: `BlindSumcheck.lean` lets the
verifier choose `Delta` and the complete indexed key function **upfront**,
then choose every public challenge and `chi` adaptively;
`bsc_zeroBatch_perfect_zk` gives perfect ZK when all opened claims are zero;
`sequential_composition_perfect_zk` composes arbitrary windows with a shared
`Delta` and fresh offsets.  R0.4 therefore does **not** invent a duplicate
ideal privacy theorem.  The missing theorem is the concrete
checker/codec-to-window refinement.

R0.5 fixes the real-to-ideal key policy rather than silently strengthening
that theorem.  Connection initialization fixes and binds the key-tape
seed/domain identifier; it cannot depend on any later response transcript.
Each durable attempt then atomically reserves a canonical interval on every
required correlation/limb tape before the first witness-dependent byte:

```text
connection: (connection_id, compiler_digest, key-tape/domain commitment)
attempt:    (attempt_nonce, start, J_cap(codec, public_shape)).
```

Keys may be expanded lazily by index from the connection-bound state, so this
does not require an `O(N)` key array or setup.  The attempt range is exact,
cannot be extended after seeing a correction, and its unused suffix is burned
on accept, abort, crash or retry; retry starts above the durable high-water
mark.  `J_cap` is not 512 until the codec compiles it.  Allowing a malicious
verifier to select a new connection seed or keys from successive corrections
would require a different adaptive-key theorem and is not C7.

The connection privacy bound must have the form

```text
Adv_priv_conn
 <= Adv_PRF_salt(L)
  + 2*L*Q_leaf/2^sigma
  + epsilon_LeafPathHide_extra
  + sum_attempt (
        Adv_real_VOLE_malV(J_a)
      + Adv_PCG_a
      + epsilon_checker_refinement_a
      + epsilon_codec_timing_a)
  + epsilon_state_replay.
```

There is no honest-challenge term in this **privacy** game: the malicious DV
may choose every challenge arbitrarily, and the ideal zero-residual theorem
already covers that.  Honest post-prefix unpredictability is used for
soundness; concrete challenge framing, timing and abort leakage remain inside
the codec/state terms above.

`Q_leaf` counts adversarial offline commitment-oracle work and is not bounded
by `R_max`.  At the selected logical `g=141`, the large-model static tree has
`L=961,958,582 < 2^30` leaves.  With the registered analytic adversary screen
`Q_leaf<=2^64`, 256-bit independent
salts give

```text
2*L*Q_leaf/2^256 < 2^-161,
```

whereas 192-bit salts give about **97.16 bits**.  The selected 256-bit screen
has about **161.16 bits**, leaving substantial margin above both the 110-bit
response allocation and 78-bit connection target.  This is still a
**screen**, not adaptive-hiding proof: the connection-wide leaf census and
concrete adaptive-hiding theorem/private checker remain missing.

`LeafCom(payload;salt)`, `H_tree(left,right)` and `H_transcript` are separate
domain-separated primitives; `H_FS` exists only in the quarantined compiler.
The leaf input binds a root context derived from the layout digest,
commitment nonce and plane, plus position, exact total/leaf count, payload
length and padding.  It cannot contain the Merkle root itself, which would be
circular.  Collision resistance supplies binding, not hiding; a random-oracle
salt-guess calculation does not make that oracle an arithmetizable private
checker.

#### Soundness/knowledge is a separate game

`C7-ALFC-STATEFUL-KS` asks whether a prover can cause the first durable state
promotion for which no extracted witness satisfies the full C7 relation and
accepted predecessor.  Its bound separately charges challenge soundness,
leaf/position binding, code unique-decoding/knowledge soundness, Fp2 MAC/RLC,
the private checker, PCG and state/replay/fork errors.

```text
Pr[Bad]
 <= epsilon_honest_DV_challenge(R_max,t,|Fp2|)
  + epsilon_AuthCheckerExtract(J_total)
  + epsilon_LeafComBinding(L,U_leaf,Q_leaf)
  + epsilon_MerklePositionBinding
  + epsilon_CodeKS_or_UniqueDecode
  + sum_attempt (
        epsilon_MAC_Fp2
      + epsilon_private_checker
      + epsilon_RLC_operator
      + epsilon_codec)
  + epsilon_PCG
  + epsilon_state_replay_fork.
```

No term is declared independent merely because attempts use fresh masks; the
same `Delta` is handled by fixed-other-coins slices and union bounds.

The earlier step “extract a virtual clear PCS transcript” is rejected as
circular.  Opaque handles plus verifier data `(Delta,k)` do not reveal the
authenticated plaintext; exposing the prover tag together with them destroys
privacy.  `OpeningMac.lean` reasons about a mathematical authenticated output
but does not extract it from serialized bytes.  The concrete construction
must instead prove either direct authenticated-checker soundness or an
explicit committed-input PoK/extractor in `F_sVOLE+id`, including its trapdoor
and challenge-oracle log.  Evaluation binding from preprocessing is not this
knowledge theorem.

### 4.4 What is and is not cryptographically proved

The repository proves four relevant ideal/algebraic facts; none instantiates
the private oracle.

1. `bsc_zeroBatch_perfect_zk` and
   `sequential_composition_perfect_zk` prove perfect straight-line privacy in
   ideal `F_sVOLE` for public-shape windows with true zero residuals, even
   when one malicious verifier fixes shared `Delta` and its whole indexed key
   function upfront, then chooses challenges adaptively.  The missing concrete
   refinement is not assumed by them.
2. The terminal batch is linear in the actual extension field under one
   shared `Delta`; applying either canonical coordinate projection yields the
   corresponding equality for both serialized Fp limbs.  This fixes the old,
   invalid model of two unrelated base-field MACs, but does not construct the
   adapter or its codec.
3. `connection_hybrid_advantage_bound` proves the sequential hybrid
   recurrence

   ```text
   Adv(R) <= epsilon_fixed + R * epsilon_attempt
   ```

   provided the concrete serialized game supplies the uniform step premise
   for every reachable transcript/journal state.  That premise is precisely
   the missing malicious-DV per-attempt simulator; the lemma does not assume
   an ideal ALFC.
4. `c7_registered_connection_error_below_78_bits` proves in exact rational
   arithmetic that the current allocation is below `2^-78`, *if* all 64
   attempt-local event bounds and the four connection-wide terms are actually
   established with their registered scopes.

The fixed-prefix Lean result proves only that an accepting-challenge set has
at most `T` elements when one already serialized prefix supplies a nonzero
residual and acceptance implies its scalar-power identity.  It does not prove
transcript freezing, honest challenge delivery or commitment binding (nor
Fiat--Shamir uniformity in the quarantined alternative).  The
serializer refinement is only decode/encode round-trip.  Its authenticated
value is now an opaque handle, so the type no longer accidentally permits
serializing plaintext/tag pairs, but no codec-privacy theorem follows from
round-trip correctness.
Likewise, the packed-functional theorem is algebra only, the append theorem is
a list dot-product identity rather than a concrete Boolean MLE codec, and the
atomic wrappers inherit an abstract old/new state type rather than proving a
filesystem WAL or CAS implementation.

The existing correction-privacy seam also records why serializing a raw
prover tag alongside verifier material exposes the plaintext.  No duplicate
C7 lemma is added: a salt-counting identity or another ideal theorem would
not discharge concrete adaptive commitment hiding.

This is the maximal honest R0.4 composition result.  Full concrete
cryptographic soundness/privacy is **not proved** until `LeafCom`, the private
checker/codec refinement, real PCG/VOLE, honest-DV entropy/transcript binding
and code knowledge soundness are instantiated and composed.

### 4.5 Horizon and conditional union budget

Set

```text
R_max = 2^20 attempts.
```

An attempt is counted when its durable nonce/correlation reservation is
created, whether it later accepts, fails, crashes, retries or is selectively
aborted.  The connection closes before a `2^20 + 1`-st reservation.

R0 allocates a cap of 64 response-local bad events, each at most `2^-110`:

| Class | Maximum events |
| --- | ---: |
| operator/compute reductions | 16 |
| boundary commitments | 8 |
| predecessor/successor state | 8 |
| code/ALFC binding, proximity and privacy | 16 |
| extension-field terminal/MAC codec | 8 |
| sampling/range rules | 4 |
| serialization/order | 4 |
| **Total** | **64** |

This is a partition of an error budget, not an event census.  Each concrete
event must have an identifier, theorem/hypothesis, numerator, denominator,
repetition count and connection/attempt scope.  Hash, PCG and privacy query
factors must be connection-wide rather than silently charged once.  In
particular the `2^-128` hash row is an allocation, not a consequence of the
32-byte digest, and a Fiat--Shamir event cannot retain a `2^-110` label
independently of `Q_FS`.  Until a
fail-closed registry derives every row, the following is conditional
arithmetic only:

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

The executable calculator computes the non-rounded bit value.  If every
premise is discharged, this retains almost six bits of reserve above the
78-bit connection target.  The shared
`Delta` does not justify independence: the formal wrapper reuses M10's
fixed-other-coins slice and ordinary union bound.

The conditional strict whole-bit label would be 83 bits, five whole bits
above 78; the effective allocation is approximately 83.99999999998 bits.  It
is not a C7 security label while the event registry and per-attempt privacy
premise are missing.

### 4.6 Atomic promotion, replay and forks

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
- The publications are explicit about their oracle interface: Ligerito sends
  requested rows and a terminal matrix, ERA sends requested columns and
  Merkle proofs, and WHIR/BCS queries return leaf payloads plus paths.
  2026/391 likewise describes a Merkle query as a leaf value plus its
  authentication path.  Its ZK encoding makes a bounded set of masked symbols
  simulatable; it does not make those symbols absent from the wire.

Local evidence anchors are `sota/2025-1187-ligerito.md` §§5--6,
`sota/2026-864-era-codes.md` §7, `sota/2024-1586-whir.md` §§4/6 and
`sota/2026-0391-zero-knowledge-iopps-constrained-interleaved-codes.md`
Definitions 4.7 and §12.3.  These anchors remain part of the rejection record.

**Assumptions / missing composition**

- 2026/391 proves HVZK for a query-bounded non-adaptive distinguisher, not the
  C7 malicious-DV connection game.
- No paper supplies private verification of every Merkle leaf/code response,
  intermediate witness-dependent symbol and terminal value under VOLE-MAC.
  A terminal-only adapter leaves the published clear-symbol channel intact.
- ERA's query-efficient `2^32` proof is an estimate, not a prover/memory
  measurement; its random permutations/multipliers and indexer oracles are
  linear setup objects.
- Neither Ligerito nor ERA supplies the required one-sequential-scan,
  bounded-memory composed schedule at 31B.

**R0.2 disposition:** **REJECT AS COMPOSED UNDER POLICY 3 / NO-GO FOR R1**.
Retain its code, proof-law and storage evidence.  Under the active policy it
becomes eligible only if a new authenticated-oracle compiler privately
verifies every queried payload and passes the setup/query gates.  That is a
new protocol, not a terminal adapter.  Dormant policy 2 would require the
separate exhaustion and explicit activation procedure in Section 4.1.

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

**R0.2 disposition:** retain as an analytic challenger, **NO-GO**.

### 5.3 C — strict unique-decoding WHIR control

**Evidence:** WHIR-UD is the most mature executable code control in the
tournament.  Published 128-bit, rate-1/2 proofs are 621 KiB at `2^24` and
770 KiB at `2^28`; prover evidence reaches 62 seconds at `2^28` on a large
host.  Staying inside unique decoding avoids WHIR's correlated-agreement
list-decoding conjecture.

**Assumption:** WHIR supplies no hiding/stateful privacy theorem, authenticated
terminal, or bounded-memory result.  A `2^30` low-rate case ran out of memory
on a 768-GiB host.

**R0.2 disposition:** **GO as a transparent tiny/scaled code control only**
after a packed illustrative schedule exists.  It may test the packed identity,
unique-decoding verifier and byte/I/O instrumentation on public or synthetic
data.  It cannot test a no-clear adapter that does not exist and cannot use
private production weights.  The C6.3 eight-body WHIR+Bolt topology is
forbidden.  Results remain component evidence and cannot promote C7 state or
grant privacy/E2E credit.

### 5.4 R0.4 policy-3 construction funnel and CPU gate

Only one architectural shape remains eligible for further analytic work; it
is not a selected backend:

```text
root_context = H_ctx(domain || layout_digest || commitment_nonce || plane)
digest_i = LeafCom(
  domain || root_context || plane || i || leaf_count || total_symbols
         || length || padding || payload_i;
  salt_i)
```

The persistent oracle is a **digest-only salted leaf commitment**.  Leaf
digests, indices and the exact Merkle multiproof are public.  Payloads and
salts are never public: they receive fresh attempt-local VOLE masks, and the
authenticated verifier proves the leaf preimage equation and the PCS
algebraic predicate under MAC.  Only constrained zero residuals may be
opened.  Internal Merkle paths stay public, so the private verifier pays one
leaf-hash check per unique leaf rather than privately proving every path hash.
`commitment_nonce` and `layout_digest` are fixed before the tree; the root
codec must recompute `root_context`, which is not the Merkle root.
Collision resistance supplies binding only; adaptive hiding of the static
salted root/path requires a separate theorem.  Provider-side PRF-derived
256-bit salts are eligible only under that theorem and the real-PCG/PRF
budget.  Neither a generic random oracle nor SHA/BLAKE/Poseidon is selected:
the concrete primitive must also be cheap enough inside the private checker.

No encoded payload/codeword is persistent.  After the selected challenge mode
fixes the queried leaves, a candidate must implement

```text
BatchOpenBlocks(W, queried_indices)
  = O(N + poly(q, log N))
```

with one sequential packed-weight scan, bounded memory and no N-scale
scratch.  If requested encoded blocks cannot be regenerated under that
schedule, the candidate fails; a second scan or a full persisted oracle is
not an alternative implementation.  No published Ligerito, ERA, WHIR,
SwitchFold or 2026/391 composition currently supplies this compiler.

The R0.4 schedule audit closes the current families: direct Ligero/RS queried
evaluation is `Theta(qN)`; BaseFold/X4 needs full NTT/Mobius materializations;
WHIR persists matrices and Merkle levels; published ERA is specified through
full permuted/accumulator vectors and supplies no one-source-pass,
no-N-liveness schedule, while direct restriction again costs `Theta(qN)`.
“Linear-time encodable” is not “locally openable.”  The
former sparse-output-generator escape is now rejected by the following exact
cost identity.

**Generator-incidence theorem.**  Let `G in F^(k*n)`, `Enc(m)=mG`, have rank
`k` and minimum distance `d`.  Each basis word `e_j G` is a nonzero codeword,
so its row weight is at least `d`; hence

```text
nnz(G) = sum_j wt(e_j G) >= k*d,
E_uniform_column[support] = nnz(G)/n >= k*d/n.
```

For logical `g=141`, put `B=ceil(n/141)`, zero-pad only the final logical
block, and let `I_b` count generator incidences in block `b`.  For
`1<=U<=B`, `sum_b I_b>=k*d`; a uniform `U`-block subset has expected direct updates at
least `U*k*d/B`.  Equivalently this is approximately
`U*141*k*delta_phys`, where `delta_phys=d/(141B)`.  A direct routine that
accumulates each requested output performs exactly those coefficient
scale-adds.  Constant relative distance therefore gives an **expected**
`Omega(U*k)` cross-term for uniform subsets, which is `Omega(U*N)` when `N=k`
denotes the packed source length.  Moreover, the `U` heaviest leaves contain
at least `ceil(U*k*d/B)` incidences, giving the corresponding worst-case
bound.  It may be called `Omega(qN)` only in a schedule that defines
`q=Theta(U)`; `q_open` and unique leaves otherwise remain distinct counters.
This rejects direct sparse-coordinate regeneration under the uniform screen
and in the worst case; it says nothing about an arbitrary hand-picked sparse
subset and is not a general linear-circuit lower bound.  A
structured pruned/shared DAG could reuse intermediate nodes and remains the
only logical escape, but receives no credit without its exact schedule.
For a nonuniform query distribution `mu`, define
`delta_mu=min_(m!=0) Pr_(i<-mu)[(mG)_i!=0]`.  The same row argument gives
`E_mu[wt(G[:,i])]>=k*delta_mu`; a plain independent proximity sampler at
`lambda` bits needs no finite `q` when `delta_mu=0`, exactly one query when
`delta_mu=1`, and otherwise
`q>=ceil(lambda*ln(2)/-ln(1-delta_mu))`.  Bias toward sparse systematic
columns **may** lower `delta_mu`; a candidate must derive it, and whenever it
does fall the required queries, private payload and proof bytes rise.  This is
a sampling screen, not a lower bound on richer IOPs, whose exact schedule must
still be compiled.
For example, dense prefix-sum outputs share one running accumulator and can be
selected in `O(k+q)` despite `Theta(k^2)` incidences (their relative distance
is only `1/k`, so this is a scope witness, not a candidate code).

| Candidate shape | R0.4 disposition and reason |
| --- | --- |
| sparse output generator | **REJECT:** `nnz(G)>=kd`; useful distance forbids uniformly sparse output functionals |
| RS/Ligerito/WHIR direct openings | **REJECT:** direct restriction is `qN`; shared FFT/encoding requires full vectors; WHIR stays control-only |
| ERA/RAA as published | **QUARANTINE AS-IS:** the linear shared encoder is closest, but the published full-vector schedule does not prove one-pass/no-N-liveness; direct restriction is `qN` |
| Brakedown/LDPC | **REJECT:** sparse encoding/parity circuit does not imply sparse generator outputs; its proof-size law was already ineligible |
| Bolt | **REJECT:** systematic stream still needs `C(Hx)`/fresh RS work; direct selected parities are `qN` or shared state is model-linear |
| QA/QAFold/SwitchFold | **REJECT:** shared WHT/full transforms and multi-root/deferred topology violate this relation |
| constrained-code HVZK 2026/391 | **EVIDENCE ONLY:** small-space interleaving does not supply post-challenge `BatchOpenBlocks` |
| new structured pruned/streaming code | **TINY SEARCH ONLY:** exact CPU DAG, distance/soundness and proof-byte census required |

Repository evidence matches the paper audit: `rust/volta-pcs/src/ligero.rs`
stores the full encoded matrix and tree; `rust/volta-pcs/src/x4/ntt.rs`
allocates a full transform vector; `x4/artifacts_v4.rs` records two complete
rebuild materializations; and `c61_persisted_mmcs.rs` persists matrices and
digest layers before serving rows.  These are historical/control
implementations, not templates for C7.

#### CPU `BatchOpenBlocks` admission certificate

Choice 3.A authorizes a tiny CPU reference only after the search identifies a
concrete structured algorithm.  It does not authorize a placeholder API.  The
reference consumes the canonical packed i16 stream, the canonical query plan
fixed by the serialized `rho_i` prefix, logical `g=141`, and commitment
metadata.  Passing requires a derivation from the implementation together
with exact counters:

```text
C(N,q,h) = c_source*N + P(q,h),       h=ceil(log2 N)
M(N,q,h) <= chunk + M_fixed + P_M(q,h),
```

where `c_source` is independent of `q` and `P,P_M` are preregistered
polynomials with no `qN` or `N log q` term.  An empirical sweep alone is not a
proof.  The executable assertions are:

```text
packed_source_opens              = 1
packed_source_passes             = 1
packed_source_bytes_read         = 2*N
backward_seeks_or_reopens        = 0
model_linear_scratch_write_bytes = 0
complete_codeword_bytes          = 0
expanded_weight_bytes            = 0
```

Offsets are strictly increasing and each source byte is consumed once.  Live
memory is at most the configurable chunk, a 140-symbol cross-chunk carry and
`poly(q,log N)` state.  Disk output is only the queried logical blocks and
`poly(q,log N)` proof/audit data; no source, codeword or stage vector may spill.
The reference produces exact 141-symbol leaves and salts only
provider-internally and feeds them directly into the authenticated checker;
neither is serialized.  Its external result contains digests/root and
multiproof checks, opaque authenticated handles/corrections and all counters.
A truncated, extended or mutated source, counter mismatch, noncanonical query,
second pass or hidden model-linear allocation fails before output or state
promotion and burns the reserved attempt when run inside a lifecycle.

The report separates source-dependent from query-only work and records:

- opens, read calls, logical bytes, EOF, seek/reopen and pass count;
- i16 decode, candidate primitives, Fp/Fp2 adds/muls/reductions, `LeafCom`,
  Merkle compressions, AES blocks, PCG/VOLE correlations, MACs, leaf checks and
  reduction nodes;
- host disk read/write/syscall bytes, scratch bytes/files and durable syncs;
- configured chunk, peak logical scratch, RSS and `VmHWM`;
- output, certificate, framing, transcript and padding bytes.

Geometric `N,q` fixtures must reconcile the formula: at fixed `N`, changing
`q` cannot change the source-linear count; at fixed `q`, doubling `N` changes
only its derived linear term.  Full-encoder equality is checked on tiny
fixtures.  Only after all these checks may the ledger record
`C7_CPU_REFERENCE_PASS`.

#### SIMT path after the CPU checkpoint

The stage order is analytic screen -> CPU reference -> scoped checkpoint ->
SIMT implementation -> byte-exact conformance -> scaled local integration.
No optimized kernel or GPU scaffold is admitted earlier.  SIMT may replace
only pure stages for streaming setup, `LeafCom`/Merkle, PCG/VOLE, MAC, Fp/Fp2,
leaf checks and reductions under the same host orchestration.  Canonical
serialization, challenge release and correlation indexing remain unchanged.

Logical leaf width is always 141.  If a later device implementation uses a
wider physical tile, every extra lane is temporary zero scratch and obeys

```text
gpu_padding_persistent_bytes = 0
gpu_padding_certificate_bytes = 0
gpu_padding_LeafCom_input_bytes = 0
gpu_padding_transcript_bytes = 0.
```

Padding symbols/bytes, operations, device zeroing and peak VRAM are measured;
cryptographic hash padding and device-lane padding are distinct.  A chunk of
packed source may cross H2D only once in each separately accounted setup or
response scope.  Reports add per-phase H2D, D2H,
explicit D2D, device-generated/zeroed bytes, VRAM and pinned peaks, allocation
counts, kernel launches, and synchronization count/reason/wall.  Any
unclassified barrier or unassigned byte fails.  Streaming setup and online
response are separate scopes; traffic or peaks cannot be netted between them.

On identical input, queries, verifier coins and finite PCG fixture, CPU and
SIMT must match byte-for-byte on provider-internal leaves and salts, exact
PCG/VOLE values and consumption, leaf digests, root, multiproof,
handles/corrections, correlation schedule digest, transcript after every
frame, challenge sequence, both Fp2 limbs, terminal settlement, certificate,
CPU-verifier result and journal transition.  Tiny conformance fixtures compare
the internal values directly; production reports retain only domain-separated
digests and counters, never those secrets.  Thread/block order cannot alter
serialization, reductions or correlation consumption.  A requested
unavailable SIMT backend fails rather than falling back silently.

The future implementation should reuse `Transcript::canonical_binding_digest`,
`CorrScheduleAudit`, `BackendStats` and the existing RSS/`VmHWM` reader.  These
are measurement/orchestration seams only; no X4/C6 oracle, lifecycle, constants
or model-sized batch implementation transfers.  R0.4 creates no duplicate
stats abstraction or speculative kernel.

The following shapes are rejected, not deferred optimizations: a persistent
expanded field/code oracle; an O(N) plane of VOLE tags or per-coordinate
opening proofs; privately proving the whole Merkle path; reusable secret
linear sketches; and a consumable root/mask pool.  Preprocessing-backed
evaluation is also ineligible until the proof establishes correctness of the
preprocessed data structure, not only evaluation binding.  This funnel leaves
no implementation GO: the sole candidate still lacks the malicious-DV
refinement, concrete `LeafCom`, soundness/PoK bridge, one-scan block-opening
algorithm and exact compiled byte/resource census.

#### R0.5 executable dense exception and terminal policy-3 screen

The structured-circuit escape is real.  A one-stage
repeat--permute--diagonal--accumulate word has output

```text
y[j] = sum_(position(occurrence) <= j)
         diagonal[position(occurrence)] * W[source(occurrence)].
```

For sorted queried coordinates, one source contribution is added only at the
successor queried coordinate; one prefix pass over the queried coordinates
then recovers every requested output.  The CPU implementation is
`rust/volta-pcs/src/c7_ra_batch_open_screen.rs`.  A fixed-depth binary trie
makes every successor lookup exactly 64 steps.  For `N` packed values,
repetition `r`, `U` leaves and `V<=141U` valid coordinates its checked counts
are

```text
source passes / bytes                 = 1 / 2N
permutation, diagonal, Fp mul         = rN each
successor lookups / trie steps        = rN / 64rN
range_adds + successor_misses         = rN
query prefix additions                = 141U
live logical memory                   = O(64V + 141U + U)
codeword / N-scratch / expanded W     = 0 / 0 / 0 bytes.
```

The tiny differential test agrees with a full encoder, including canonical
padding, and counter/input mutations fail closed.  This is a working
`BatchOpenBlocks` **algorithm screen**, not a PCS and not
`C7_CPU_REFERENCE_PASS`.  Its affine interleaver and diagonal are deterministic
fixtures, not a random ensemble or cryptographic generator.

The current input is a borrowed `&[i16]`.  Thus “one open”, “one pass” and
“2N bytes” are exact logical-access counters, not filesystem calls, measured
disk traffic, RSS or `VmHWM`.  A reader/mmap wrapper and physical counters were
intentionally not added after the distance/setup rejection; they remain part
of the unchanged CPU admission gate, so this component cannot be cited as a
production one-scan measurement.

Two independent gates reject promotion.  First, no accepted theorem gives
constant relative distance for this one-accumulator Goldilocks construction.
Binary one-stage RA has only sublinear minimum-distance evidence; accepted
weighted nonbinary linear-distance results use at least two accumulators.
Those binary exponents are evidence, not silently transferred to `Fp`.
Second, a random interleaver lets the online range-add trick consume `W` in
order, but emitting the *entire* accumulated oracle in leaf order for the
root requires a model-sized reorder/scatter or nonmonotone source reads.  Two
accumulators restore the relevant distance line but reintroduce an N-vector,
random intermediate reads or a `qN`/two-dimensional restriction.  Thus the
dense shared circuit closes only the online block subproblem.

The distance dispositions are anchored to the binary RA minimum-distance
analysis ([Kliewer--Zigangirov--Costello 2007](https://web.njit.edu/~jkliewer/wp/paper/KZC_Allerton07.pdf)),
the weighted nonbinary repeat-multiple-accumulate result
([Amat--Rosnes 2011](https://doi.org/10.1109/ITA.2011.5743575)), and the
two-stage/full-vector construction in
[ERA Codes](https://eprint.iacr.org/2026/864).  None proves the concrete
one-stage C7 fixture.

R0.5 also implements the minimum concrete leaf-function candidate in
`rust/volta-pcs/src/c7_policy3_leaf.rs`, reusing the locked Plonky3
Poseidon2/Goldilocks permutation:

```text
logical payload                 141 canonical Fp symbols
private salt                    256 bits, eight injective u32 limbs
bound metadata                  root context, plane, index/count, total symbols, length, padding
sponge                          width 16, rate 12, capacity 4
absorbed/padded fields          166 / 168
permutations                    14
digest                          four canonical Fp limbs = 32 bytes
secret S-box multiplications    8,400 per leaf
private input corrections       (141 + 8)*8 = 1,192 bytes per opened leaf.
```

The root-local salt is derived from a provider-private 32-byte seed by a
domain-separated BLAKE3 PRF over the complete geometry.  The 32-byte root
context is itself a domain-separated digest of the public layout digest,
commitment nonce and plane; the future root codec must recompute it rather
than accept a prover-selected value.  Known-answer,
canonical-codec, metadata/salt/payload/padding/geometry and exact-cost tests
pass.  This proves executable determinism and injective parsing only; it does
not prove Poseidon binding/hiding.

At the largest integer repetition still within the setup ceiling, `r=4`
(`r=5` already gives the digest-tree floor
`1+32r/141=2.13475x > 2.10x`), the exact compact-tree screen, including 64
bytes for salt seed and commitment nonce, is:

| Item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| leaves | 3,517,731 | 874,507,802 |
| packed + tree + minimum root metadata | 473,134,816 B | 117,621,299,360 B |
| amplification over packed | 1.9078017x | 1.9078014x |
| Poseidon permutations | 49,248,234 | 12,243,109,228 |
| S-box multiplication-equivalents | 29,548,940,400 | 7,345,865,536,800 |
| salt KDF calls in current one-shot helper | 3,517,731 | 874,507,802 |
| salt keyed-hash calls | 3,517,731 | 874,507,802 |
| internal tree-hash compressions | 3,517,730 | 874,507,801 |

Storage alone fits the 2.00x target, but this is exactly the setup warning:
trillions of large-model S-box multiplication-equivalents plus the unresolved
ordered oracle generation are not a lightweight streaming setup.  The S-box
row is only a lower bound: it excludes the listed salt KDF/PRFs, tree hashes and
their uncompiled I/O/root schedule.  No setup credit is awarded.

The current `c7_leaf_salt` convenience function derives the BLAKE3 root key on
every call, so the table charges both one KDF and one keyed hash per leaf.  A
reopened backend would cache one derived key per root/worker, but no such setup
optimization is implemented or credited after the terminal rejection.

A private verifier cannot receive 8,400 product corrections per leaf.  The
only retained checker shape puts all queried Poseidon traces into fresh
`C_B,e`, fixes its root, runs one shared randomized degree-7 zerocheck in
`Fp2`, and links authenticated salt/payload inputs and the four public digest
limbs at the terminal.  Its approximate full trace is
`14*30*16*8 = 53,760` bytes per unique leaf, or 55.1 MB (52.5 MiB) at
`U=1024`, with `O(U)` rather than model-sized working memory.  No generic
degree-7
authenticated zerocheck, concrete schedule or byte census exists, so this
checker is not implemented.

The exact soundness bridge that would be required is deliberately
non-circular:

```text
TreeBind_BLAKE3
+ LeafBind_Poseidon2
+ TracePCSBinding
+ AuthenticatedZerocheckSound
+ CodeKS_or_UniqueDecode
+ ALFC/MAC/RLC
+ AtomicState
=> accepted -> exists W, C7Relation(W, predecessor, successor).
```

and its error must charge every term, for example

```text
Adv_tree_CR + Adv_leaf_bind + epsilon_trace_PCS
+ 8*m/|Fp2| + epsilon_code_KS + epsilon_RLC + epsilon_MAC
+ epsilon_PCG + epsilon_codec + epsilon_state.
```

Opaque handles plus `(Delta,k)` still do not extract plaintext.  Consequently
R0.5 does not fabricate the requested soundness, codec-to-Lean or stateful
malicious-DV theorems.  Their concrete prerequisites remain, respectively:

- `private_checker_all_opened_residuals_zero` for this exact Poseidon/code
  checker;
- a typed wire grammar with no payload, salt, raw PCS symbol, plaintext or
  prover-tag constructor, plus canonical decode/encode and public census;
- `serialized_private_oracle_view_refines_windows` proved from that grammar
  and schedule, and equality of both `Leak_base` and the public oracle
  envelope before applying `LeafPathHide`;
- the real PRF/PCG/VOLE hybrids with the upfront key-range reservation above;
- prefix/selective-abort closure, burn and the existing atomic
  replay/fork-exclusion state transition.

Only after those facts would the existing ideal zero-residual privacy theorem
and conditional connection hybrid yield a stateful malicious-DV theorem.  A
codec round trip or a newly named hypothesis is not that bridge.

The catalog reduces to two exhaustive known shapes under these gates.  A
compact root over the packed source plus a private scan lacks a binding/PoK
bridge from that root to the fresh linear functional; linear/group and
preprocessing commitments fall here.  A hidden encoded oracle avoids that
bridge only by regenerating or persisting code structure, which restores an
N-intermediate, reorder/random I/O or `qN` restriction; code-based PCS,
RA/RAA/ERA/WHIR and LigeSIS fall here.  The policy-3 catalog is therefore
terminal under the registered constraints:

| Line | Privacy/soundness | setup / online / wire disposition |
| --- | --- | --- |
| published Ligerito/ERA/WHIR/2026-391 | queried symbols remain clear or only HVZK-bounded | reject literal policy 3; full encodings/intermediates or `qN` restriction |
| one-stage RA dense screen | private block algorithm works; no distance/KS theorem | one pass online passes shape; ordered root setup fails |
| RAA/two-stage ERA | relevant distance evidence exists | N-intermediate/random reread or `qN`; persistent/full-vector setup fails |
| Poseidon2 salted leaf | concrete function with injective input parsing; binding/hiding/checker conditional | storage fits, but setup work is enormous and checker bytes are uncompiled |
| full dense root-and-dot circuit | could bind a functional without spot-check payloads | even a packed-weight root costs 1.836T large-model S-box multiplication-equivalents per response; the screened `r=4` encoded oracle costs 7.346T, both before GKR/trace work, with no one-pass bounded-memory prover; this is the rejected full-circuit/Mac'n'Cheese shape |
| BLAKE3 salted leaf control | conventional collision-resistance/setup control, not intrinsic hiding | the private bit/carry checker and its proof bytes are absent; BLAKE3 remains eligible for `H_tree`, transcript hashing and salt PRF, not an accepted private LeafCom |
| [LigeSIS/subset sum](https://eprint.iacr.org/2026/751) | cited result gives SIS collision resistance for bounded binary inputs, not hiding/malicious-DV privacy | `c=7` has a 56-B digest and at `r=4` the tree floor alone is `1+56*4/141 = 2.5887x`, before its 32x table/full PCS; `c=4` lacks the cited reduction |
| linear salted hash | cheap | four public linear equations permit constructed collisions; reject |
| Pedersen/KZG/IPA/lattice/group lines | may bind | non-native verification or full large-field MSM/oversized setup violates gates |
| preprocessing-only evaluation binding | does not give strong binding/knowledge soundness | proving data-structure correctness restores omitted setup/work |

This is documented credible-candidate exhaustion, not a universal lower bound
against unknown cryptography.  Policy 3 receives a **NO-GO** and policy 2
remains dormant until an explicit owner activation.

### 5.5 Layout/reference-only and quarantined lines

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

## 6. Registered analytic screens

The executable calculator is `scripts/budget_c7_stateful_alfc.py`.  Every
output carries `credit:false`.  It reproduces scaling arithmetic, allocation
caps and one selected artifact-volume scenario; it is not an authority for a
compiler manifest, certificate codec, security-event registry or measured C7
time.

The two registered self-check invocations are:

```text
python3 scripts/budget_c7_stateful_alfc.py
python3 scripts/budget_c7_stateful_alfc.py --chunk-mb 64 --bandwidth-gbps 1.6
```

Both must exit zero; neither supplies production credit.

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
the symbolic definitions are authoritative only for this screen:

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
`2^32`, 100-bit estimate and uses the larger `log^2 N` law.  The other
formulas are **allocation caps** sized to expose layer, token, K/V length,
illustrative terminal-segment and root dependence.  They omit real protocol
message counts and cannot become `B_*` evidence without compiler and
serializer provenance.  Changing them remains a ledger deviation, not a free
fit after measurement.

### 6.2 Serialized query-and-challenge wire ledger (hard stop)

Query count is a first-class certificate and privacy parameter, not only a
verifier/prover-time parameter.  For each concrete candidate keep five
different counters:

- `q_open[c,r]`: PCS spot checks for commitment/root `c` in round `r`;
- `U_leaf[c,r]`: unique leaves after exact deduplication/multiproof sharing;
- `P_secret[c,r]`: witness-dependent symbols inside those leaves and all
  authenticated intermediate messages;
- `Q_leaf`: adversarial offline queries against the leaf commitment;
- `Q_FS`: adversarial transcript-hash queries if Fiat--Shamir is selected.
  Neither is `q_open`, a certificate byte count or bounded by `R_max`.

Here `c` ranges only over auxiliary weight-oracle commitments/round roots
below top-level `C_W`.  It excludes boundary/K/V planes and all four top-level
roots (`C_W`, `C_B,e`, `C_KV,e`, `C_KV,e+1`), whose 128 bytes are already
assigned to `B_framing`.

Then define

```text
q_open_weight_total = sum_(weight root c, round r) q_open[c,r]

B_query_wire
  = sum_c,r (
        P_secret[c,r] * authenticated_symbol_or_correction_bytes
      + U_leaf[c,r] * leaf_digest_bytes
      + exact_sibling_hashes[c,r] * hash_bytes
      + private_leaf_check_bytes[c,r]
      + index_and_query_framing_bytes[c,r])
  + B_authenticated_weight_oracle_IOP_messages
  + B_aux_weight_oracle_round_roots_and_prechallenge_messages
  + B_serialized_weight_oracle_rho.
```

`B_query_wire` is a cross-cutting sub-ledger, not a seventh certificate
category.  Every byte is assigned exactly once to one of the six registered
`B_*` components and the sub-ledger must reconcile to those assignments.  The
selected interactive `rho_i`, `beta` and `gamma` messages and their framing
are serialized and count.  Only weight-oracle challenge frames enter
`B_query_wire`; response-wide `beta/gamma` and nonweight `rho_i` are assigned
exactly once to `B_MAC`, `B_framing` or their owning component.  Query indices
may be omitted only when the
verifier reconstructs them canonically.  A multiproof receives only its exact
measured/derived sibling sharing: neither naive `Q*depth` charging nor free
path deduplication is acceptable.  FS would change this ledger, not erase it.

For unique queried leaves `A_0`, let `A_(l+1)` be their distinct parents.  The
layout-independent exact sibling count is

```text
F(A_0) = sum_l |{sibling(v) : v in A_l, sibling(v) exists} minus A_l|.
```

When every selected parent has two children this reduces to
`sum_l (2*|A_(l+1)|-|A_l|)`.  The compact-tree codec must account explicitly
for odd/singleton levels.  This, not `U_leaf*depth`, is serialized.  The byte
identity is

```text
B_weight_nonquery + B_query_wire <= B_weight_ALFC_limit,
```

so the query ledger never receives the whole weight allocation for free.

R0.3 preregistered a target and one 5% hard tolerance for the weight-oracle
share.  R0.4 carries the same limits over to all serialized weight-oracle
query and challenge material inside `B_weight_ALFC`; response-wide and
nonweight challenges remain in their separate owners:

| Weight-oracle envelope | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| target `B_weight_ALFC` | 3,116,843 B | 5,234,948 B |
| `floor(105*target/100)` hard ceiling | 3,272,685 B | 5,496,695 B |
| tolerance reserve over target | 155,842 B | 261,747 B |
| complete certificate if the hard ceiling is fully used | 12,541,405 B | 19,474,047 B |

Bytes at or below target are a target pass; bytes above target and at or
below the hard ceiling are `pass_with_tolerance` and require an append-only
deviation entry.  Any larger value is a hard failure.  The tolerance supplies
no privacy, soundness or compiled-certificate credit and cannot offset an
overrun in another component.

The leaf-size tension is already severe.  With an optimistic 8-byte
authenticated symbol, one full leaf, one unshared Merkle path and **zero**
bytes for salt, private hash checking, IOP messages or framing, the gross
ceilings are:

| `g` | GPT-2 bytes/leaf; leaves under hard / 5% reserve | 31B bytes/leaf; leaves under hard / 5% reserve |
| ---: | ---: | ---: |
| 128 | 1,792; 1,826 / 86 | 2,016; 2,726 / 129 |
| 141 | 1,864; 1,755 / 83 | 2,120; 2,592 / 123 |
| 256 | 2,784; 1,175 / 55 | 3,008; 1,827 / 87 |

These are optimistic upper bounds, not query budgets.  Fp2 payloads,
multiproof misses and the nonlinear private checker only reduce them.

Before a candidate is admissible, the same GPT-2 and 31B workload reports all
five counters, answer alphabet/handle widths, exact multiproof nodes, round
roots, interactive challenge frames, codec bytes and total `B_query_wire`.
Those counts must parameterize
both the malicious-DV privacy theorem and the complete connection soundness
bound.
Reducing `Q` by weakening proximity error is not a size optimization.  The
compiled complete certificate must still pass 30/100 MB and at most 3x
growth; every weight-dependent `N^a` query-byte term must satisfy
`a <= 0.1991738805`.

Historical X4 evidence explains this gate without granting C7 credit.  With
128 draws, even an ideal shared-chain lower bound had **4,021,594 B** of
query frames and failed its 4-MB query gate.  The later `s=111` profile still
serialized **2,615,414 B** of query material in a **2,683,236-B** PCS.  The
Ligerito analysis likewise identifies Merkle openings as the asymptotic
communication dominant.  C7 therefore never accepts “few roots”, “small
interactive messages” or fast proving as a substitute for the compiled wire
byte census.

ERA's published `2^32`, 100-bit estimate already contains **72,418 field
elements** and **53,011 hashes** for approximately **4.014 MB**.  Under policy
3 each witness-dependent element must instead be eliminated or privately
authenticated and checked, so that byte point cannot be copied unchanged
into `B_weight_ALFC`.  Distance amplification likewise cannot be judged by
`q_open` alone: fewer queries can widen each leaf and increase both private
verification and certificate bytes.

### 6.3 Illustrative allocation table

| Certificate component | GPT-2 (B) | 31B envelope (B) | Classification |
| --- | ---: | ---: | --- |
| `B_compute` | 6,000,000 | 9,379,670 | allocation cap |
| `B_boundary_commitments` | 1,200,000 | 1,846,426 | allocation cap |
| `B_state` | 2,000,000 | 2,676,008 | allocation cap |
| `B_weight_ALFC` | 3,116,843 | 5,234,948 | ERA-calibrated transposition |
| `B_MAC` | 2,208 | 6,560 | allocation cap; both Fp limbs |
| `B_framing` | 66,512 | 68,688 | allocation cap; all four roots |
| **Sum of allocation caps** | **12,385,563** | **19,212,300** | **`credit:false`** |

The ratio of these chosen allocations is `1.55118503697x`.  Their arithmetic
fits the three Tier-A ceilings (`12.39 MB <= 30 MB`, `19.21 MB <= 100 MB`,
ratio `<= 3x`), but the protocol gates are **unevaluated**.  The calculator
emits `compiled_certificate_bytes_counted:false`; every allocation must be
replaced by an exact compiled byte census before the table can become a
certificate or growth claim.

The preferred gates are GPT-2 approximately at or below 30 MB, the 31B point
at or below 100 MB, and large/GPT-2 growth at or below 3x.  Tier B's 200-MB
large-model ceiling is inactive and requires explicit owner approval.

### 6.4 Scaling-law screen

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

### 6.5 Packed-source functional scan target

For only the direct packed-source dot product, R0 registers:

```text
packed bytes read per response = 2 * N
materialized L bytes           = 0
expanded Fp/Fp2 weight copy    = forbidden
packed-source passes           = 1 target
source chunk                   = configurable, default 256 MB
read-only roofline             = (2*N) / 3.2e9 seconds
```

| Online weight-terminal item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| packed i16 bytes read | 248,000,000 B | 61,652,800,000 B |
| packed-source passes | 1 target | 1 target |
| bytes written for `L`/source-scan spill | 0 B target | 0 B target |
| resident expanded weight wrapper | 0 B | 0 B |
| 256-MB chunks | 1 | 241 |
| 3.2-GB/s packed-source read-only roofline | 0.0775 s | 19.2665 s |

| Online memory item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| configurable weight-stream chunk | 256,000,000 B | 256,000,000 B |
| materialized `L` | 0 B | 0 B |
| expanded resident Fp/Fp2 weights | 0 B | 0 B |
| packed successor K/V source | 5,529,600 B | 56,524,800 B |
| code/hash/operator workspace | not derived | not derived |
| complete peak RSS/device memory | **not established** | **not established** |

The compute/boundary/K/V proxies used by the allocation caps are
`353,894,400 / 460,800 / 2,764,800` cells for GPT-2 and
`48,837,427,200 / 10,598,400 / 28,262,400` cells for the 31B envelope.  They
make layer, response-token, successor-length, K/V-head and head-width
dependence executable.  The 106/378 terminal counts are illustrative and do
not exist as a compiled schedule.

This packed-source read-only floor is not prover time.  The complete symbolic
time is

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

The 256-MB chunk is only a configurable source-stream target, not complete
working memory.  The missing code/hash/operator rows are an explicit
Backend-A hard stop; they
cannot be filled by reclassifying the 1.221-TB 31B persistent oracle as
"setup" while mapping it resident during a response.

### 6.6 Selected artifact-volume and refresh sensitivity

The calculator makes one linear artifact-volume scenario visible instead of
treating preprocessing as free:

```text
packed model                  = 2*N bytes
ERA-style encoded oracle      = 4.4*N field symbols * 8 B
P1/P2 permutations + M        = N*(4 + 4 + 8) bytes
Merkle tree                   = 2*ceil(4.4*N/64)*32 B
```

X4d is a historical rejection witness for setup topology, not a claim that
its setup independently received a FAIL verdict.  Its actual GPT-2 packed
source was **249,403,904 B**, while the durable Fp2 coefficient/root tier was
**9,618,587,808 B** (**38.566x**).  Rebuild materialized a
**76,948,701,184-B** rate-expanded oracle and a **37,094,424,416-B** cache;
measured accelerated rebuild peaks reached **133,544,189,952 B** host RSS and
**43,486,546,048 B** device, while selected onboarding took
**452.468691324 s** and the X4d.2 fresh campaign took **1,967 s**.  X4d.1's
actual failure was flatness and X4d.2 stopped on a CUDA mismatch; the durable
reason retained here is that this artifact shape cannot be imported into C7.

For every new candidate the setup manifest must report

```text
S_total = S_packed_i16 + S_binding_index + S_metadata + S_other
A_setup = S_total / S_packed_i16,
```

plus exact preprocessing read/write/traffic/wall, peak resident and mapped
host/device bytes, temporary disk, rebuild/refresh cost and safe invalidation.
The active structural gate allows one streaming digest-only commitment scan
with `chunk + O(log chunks)` working memory and no model-sized temporary.  The
only per-weight-width persistent payload plane is packed i16; a compact
chunk-granular salted digest tree is separately counted.  Leaf/chunk
granularity must also enter the serialized query-wire ledger, so large
leaves cannot move setup cost silently into proof bytes.

R0.3 registers

```text
target:       A_setup = S_total / S_packed_i16 <= 2.00
hard ceiling: A_setup <= 2.10
```

The interval `(2.00, 2.10]` is the owner-approved 5% tolerance.  It requires
an append-only deviation entry and never relaxes the structural anti-X4d
gate.  Exact byte ceilings are **496,000,000 / 520,800,000 B** for GPT-2 and
**123,305,600,000 / 129,470,880,000 B** for the 31B envelope (target / hard).
Anything above the hard ceiling fails.

For `M` source/code symbols, `g` symbols per leaf, `h` digest bytes and
authenticated symbol width `b_auth`, the first required trade-off screen is

```text
S_tree            ~= 2*h*M/g
B_secret_payload  ~= U_leaf*g*b_auth.
```

Increasing `g` shrinks setup/tree storage but expands the private leaf
payload and leaf-hash circuit.  A hierarchy merely reintroduces the hashes it
claims to remove; neither direction receives free credit.

Ignoring all persistent metadata `K`,

```text
A_setup ~= 1 + 140.8/g + K/S_packed.
```

Thus `g>=141` is the first integer meeting the 2.00 target asymptotically;
`g=128` is only the pre-metadata 2.10 boundary.  At the illustrative 4.4x
code geometry, exact compact-tree floor screens are:

| Symbols/leaf | GPT-2 total | 31B total | Setup disposition before `K` |
| ---: | ---: | ---: | --- |
| 64 | 793,599,968 B | 197,288,959,968 B | reject; about 3.2x |
| 128 | 520,799,968 B | 129,470,879,968 B | only 32 B hard headroom; not realistically admissible |
| 129 | 518,685,280 B | 128,945,158,432 B | tolerance band |
| 141 | 495,648,224 B | 123,218,149,216 B | first integer target screen |
| 256 | 384,399,968 B | 95,561,839,968 B | first power-of-two target screen |

These rows count packed weights plus digests only.  They do not prove that a
codeword can be generated, committed and post-challenge opened in one source
scan, nor count the private leaf checker.  R0.4 selects logical `g=141` as the
format for the authorized search, not as setup or backend credit.  In
particular `g=128`
fails unless the complete persistent manifest, salt state and metadata fit in
32 bytes.  `g=256` requires concrete power-of-two codec necessity; larger
leaves buy setup by spending private query bytes.

Changing only the tree to `g=141` does not rescue the ERA topology.  If its
full 4.4x oracle, P1/P2 and multiplier planes are materialized, the scenario
is still **6,844,448,224 B / 1,701,529,829,216 B**.  A valid setup therefore
needs a streaming root builder that never materializes those planes; no
current backend supplies it.

| Setup/storage item | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| packed i16 model | 248,000,000 B | 61,652,800,000 B |
| ERA-style 4.4x field-symbol oracle | 4,364,800,000 B | 1,085,089,280,000 B |
| `P1` permutation | 496,000,000 B | 123,305,600,000 B |
| `P2` permutation | 496,000,000 B | 123,305,600,000 B |
| multiplier vector | 992,000,000 B | 246,611,200,000 B |
| compact Merkle tree, 64 symbols/leaf | 545,599,968 B | 135,636,159,968 B |
| packed + digest tree only (candidate floor screen) | 793,599,968 B | 197,288,959,968 B |
| persistent oracle + Merkle | 4,910,399,968 B | 1,220,725,439,968 B |
| **selected artifact-volume sum** | **7,142,399,968 B** | **1,775,600,639,968 B** |
| ideal fused artifact read/write volume | 7,142,399,968 B | 1,775,600,639,968 B |
| 3.2-GB/s preprocessing floor | 2.2320 s | 554.8752 s |
| non-fused Merkle extra read | 4,364,800,000 B | 1,085,089,280,000 B |

This illustrative layout is approximately **28.8x** the packed model at both
scales and fails the anti-X4d structural gate.  Being smaller than X4d's
38.566x durable coefficient tier does not make it admissible.

At the illustrative 4.4x oracle geometry and 64-symbol leaves, retaining only
packed weights plus digests is already approximately **3.2x** packed size.
That row is a floor screen, not a constructed setup: it omits the private
leaf checker, salts/PRF theorem, exact tree layout and block-regeneration
algorithm.  It records why both the setup and query-byte gates are required
before selecting a leaf size.

A hypothetical full re-encoding has the same `7.142 GB / 1.776 TB` volume in
this chosen screen; this is not a proved refresh schedule.  A consumable
`2^20` oracle pool would require about
`5.149 PB / 1.280 EB` before other metadata, so it is sensitivity evidence
against silently switching to policies 1 or 4.  Four-byte permutation
indices require canonical segment-local shards below `2^32`; that layout is
an assumption, not a completed indexer.

The encoded-oracle and indexer numbers combine unproved assumptions about
4.4x rate, P1/P2/multiplier cardinalities, four-byte sharded indices and a
compact unpadded Merkle tree.  They are a sensitivity scenario, not a derived
ERA layout or total setup.  Base-code/code-switch/masking artifacts, forest
roots and intermediate traffic remain unknown.  The 3.2-GB/s number is an
illustrative throughput floor, not preprocessing time.

Policy 3 has no routine static-weight root refresh within a connection.  A
model change rebuilds all model setup.  If the privacy theorem fails and a
fresh-root or finite-pool policy is selected, its full re-encoding/storage
refresh cost must be added before implementation.  Response trace storage is
attempt-local.  The accepted K/V provider state persists only the current
canonical prefix and its commitment data; old proposed states are deleted
only after durable acceptance or recorded burn according to the future R1
journal design.

### 6.7 Conditional security allocation

| Security item | Registered value |
| --- | ---: |
| attempts in connection horizon | `2^20` |
| response-local event budget cap | 64; registry incomplete |
| allocation per event | `2^-110` |
| `epsilon_response` | `2^-104` |
| leaf salt screen | 256 bits; 192 bits rejected |
| leaf-oracle work screen | `Q_leaf=2^64`; not a theorem cap |
| challenge mode / `Q_FS` | fresh honest-DV post-prefix interactive / `0`; entropy delivery and transcript binding not instantiated |
| hash / PCG / state / framing | allocated `2^-128 / 2^-128 / 2^-120 / 2^-128`; not yet derived |
| exact `epsilon_connection` | `17592186044675 / 2^128` |
| effective connection bits | `83.99999999997877` |
| conditional strict whole-bit allocation | 83 bits |
| target | at least 78 bits |

The arithmetic must remain at least 78 bits after the `2^20` horizon, but it
is not a protocol security result until a complete fail-closed event/hybrid
registry supplies every term and scope.  If a concrete backend needs more
than 64 local events, a larger list/degree numerator, more roots, query-scaled
hash/PCG loss or additional hybrid terms, parameters are raised and the
calculator rerun before code.

The arithmetic also does not survive an uncharged Fiat--Shamir grinding
factor.  In particular one roughly 128-bit Fp2 challenge and `Q_FS=2^64`
give only a roughly 64-bit direct ROM screen.  The registered 110-bit event
allocation is therefore compatible with the selected fresh post-prefix
verifier challenges.  A later amplified FS construction would need a new
owner decision and must charge its work, multiplicity and bytes.

### 6.8 Interactive challenges versus amplified Fiat--Shamir

This is a soundness comparison, not a privacy hybrid.  Fix one complete
pre-challenge transcript and suppose its nonzero RLC residual has at most
`T` accepting challenges in `E=Fp2`.  With the current analytic cap `T=512`
and `p=2^64-2^32+1`:

| Mode | Fixed-prefix/grinding bound | Effective screen | Wire/work status |
| --- | --- | ---: | --- |
| selected interactive honest DV | `T/card(E)` | ~119 bits | one canonical 16-B challenge per draw; no grinding |
| direct FS control, `Q_FS=2^64` | `Q_FS*T/card(E)` | ~55 bits | reject security target |
| two-challenge amplified FS, `Q_FS=2^64` | `Q_FS*T^2/card(E)^2` | ~174 bits | security screen passes; proof/work bytes unknown, so NO-GO |

The pair bound requires two independent, domain-separated fresh random-oracle
slices sampled canonically into `Fp2`, both checking the same complete
relation.  Two equations using the same challenge do not amplify.  The
declared `Q_FS` must cover the whole grinding scope, including restored or
forked transcript states.  Random-oracle programmability, XOF/domain
separation, rejection sampling, state binding and transcript-prefix binding
remain named hypotheses.

Fiat--Shamir removes explicit verifier challenge frames but does not make its
second check free.  Every additional response, opaque handle, queried leaf,
multiproof sibling, authenticated correction, terminal settlement, hash,
field operation and packed-source pass must be assigned once to the six-byte
ledger.  The current compiler cannot determine whether both functionals can
share one scan or which paths/answers can be shared, so the amplified FS byte,
work and scan rows are `unknown` and fail closed.  This preserves the owner's
proof-size concern: an asymptotically stronger probability is not permission
to duplicate a large query transcript.

The selected protocol remains interactive with `Q_FS=0`: it is simpler, has
about nine bits of event-level margin over the 110-bit allocation at this
uncompiled `T` cap, and avoids both grinding and an uncounted second response.
Connection composition still separately counts every challenge event and all
non-RLC terms; the 119-bit row is not a complete connection theorem.

The sampling commit/private-open prelude has exactly two 32-byte public
commitments and one 32-byte public client opening.  Its 96-byte payload belongs
to `B_framing`; frame headers are not compiled and the allocation table does
not yet reconcile it, so it remains `credit:false`.  The private provider seed
opening contributes no wire bytes but must be covered by the relation and the
malicious-DV privacy theorem.

## 7. Lean-first obligations

`lean/VoltaZk/C7StatefulAlfc.lean` is additive and does not modify frozen
M1--M12 statements.  It proves the following algebra/state seams:

| Obligation | Lean result |
| --- | --- |
| heterogeneous packed functional | `packed_functional_eq` |
| fixed-before-beta RLC | `fixed_prefix_rlc_accepting_card_le`; prefix/residual implications are premises, with no transcript/FS theorem |
| multi-commit terminal MAC, both limbs | extension-field key/MAC linearity under one `Delta`, then both coordinate equalities |
| affine mask reuse extraction | `reused_affine_mask_extract` |
| append MLE/linear-functional difference | C7 append-difference theorem |
| prefix and accepted-tail induction | C7 prefix/transition-chain theorems |
| atomic promotion/replay/fork exclusion | C7 wrappers over the existing durable state seam |
| connection union bound/shared Delta | finite bad-set cardinality wrapper over M10; no computational-privacy claim |
| independent two-challenge counting | product-cardinality and sliced connection bounds; RO freshness/programming remain external |
| connection hybrid composition | additive advantage recurrence, conditional on the concrete per-attempt game step |
| registered 78-bit arithmetic | exact rational inequality, conditional on the incomplete event registry |
| serialized schedule refinement | opaque-handle codec round-trip only; no binding/privacy theorem |
| ideal malicious-DV privacy | existing `bsc_zeroBatch_perfect_zk` and `sequential_composition_perfect_zk`; applies only after concrete checker-to-window refinement |

These theorems prove no concrete PCS binding, hash/PCG security, transformer
compiler completeness or malicious-DV privacy.  Section 2.4 names the prose
predicate and its hypotheses; no Lean `AcceptC7` definition yet exists.  A
future definition must expose those assumptions rather than hide them behind
an ideal ALFC API.

R0.5 adds only
`c7_independent_bad_challenge_product_card_le` and
`c7_pair_challenge_connection_sliced_union_bound`.  They prove the finite
counting numerators used in Section 6.8, not Fiat--Shamir security.  Raw-tag
leakage and ideal shared-`Delta` privacy were already proved; a new
salt-counting identity would not prove adaptive hiding.  The generator
incidence obstruction and CPU/SIMT resource contract are not statements about
the frozen protocol semantics.  The next useful statements would be
`serialized_private_oracle_view_refines_windows` and
`private_checker_all_opened_residuals_zero`, but adding them before an admitted
codec/checker would only rename missing cryptography.  Because the concrete
policy-3 backend is rejected, no fake `C7Policy3Codec.lean` is created.
The focused command
`cd lean && lake build +VoltaZk.C7StatefulAlfc:olean` passes without
`sorryAx` in these C7 lemmas.

## 8. R0.5 disposition and exact resume conditions

### 8.1 Backend/control recommendation

- **Backend A as composed: REJECT under policy 3 / NO-GO for R1.**  Keep only
  its code/proof-law/storage evidence.  A terminal-only adapter cannot hide
  the row/column/leaf payloads already exposed by its oracle queries.
- **Digest-only private-oracle shape: terminal NO-GO under policy 3.**  A
  concrete Poseidon2 leaf function and a real one-pass one-stage-RA block
  screen now exist, but they do not compose: the code has no admitted distance
  theorem, ordered root generation violates the setup schedule, and the
  private checker/codec/soundness/privacy/proof-byte gates remain open.  This
  is candidate exhaustion, not `C7_CPU_REFERENCE_PASS`.
- **WHIR-UD control: GO for a transparent tiny/scaled control only.**  It may
  test the packed identity and code path on public/synthetic data.  It cannot
  test no-clear privacy and grants no complete certificate, scale, privacy or
  E2E credit.

### 8.2 Resume conditions for an R1 proposal

Policy 3 is now terminally rejected under the registered constraints and
policy 2 remains dormant pending the owner's explicit activation.  The
selected challenge baseline remains interactive honest-DV (`Q_FS=0`) and
logical `g=141`; the setup and query envelopes retain their 5% hard
tolerances.  The
fail-closed readiness handoff is
`docs/c7-r03-prover-pod-handoff.md`.  Preparation does not authorize a large
prover/E2E, pod contact or pod execution.

The next step is an owner design decision, not implementation.  If policy 2
is explicitly activated, a new checkpoint must first fix the total
root-wide query/connection horizon—including failures, retries, selective
aborts, connections and colluding verifiers—and compile its post-challenge
query/proof bytes.  Only then may an R1 proposal be considered, and it must
supply all of:

1. the selected-policy root lifecycle and exact root-wide attempt/query
   horizon;
2. an executable canonical compiler with terminal multiplicity exactly one
   for every physical weight, boundary and K/V segment;
3. a proved/checked extension-field ALFC adapter under one shared `Delta`,
   with both serialized limbs, every allowed oracle response and the bounded
   policy-2 leakage covered by the selected theorem;
4. `C7_CPU_REFERENCE_PASS`: a derived and executable one-pass bounded-memory
   `BatchOpenBlocks` schedule with exact operations/setup/oracle/online I/O;
5. a malicious-DV connection privacy theorem for the activated static-root
   policy and the exact root-wide horizon;
6. a composed certificate/security budget replacing allocation constants
   with derived protocol counts while retaining the gates;
7. if SIMT is proposed, byte-exact CPU/SIMT equivalence and every registered
   transfer, memory, padding and synchronization counter.

The tiny search has taken the second branch: credible-candidate exhaustion is
documented in Section 5.4 and the append-only register.  No SIMT S3, prover or
pod work follows from the negative screen.  Policy 2 is not automatic; owner
activation must also select its exact query/root budget and interactive versus
amplified-FS mode before any codec or prover implementation.

If those pass, R1 is the smallest complete production-equivalent case: two
incremental responses, real finite PCG, only consumed profiles,
serialization/reload/full verifier, accepted predecessor/successor K/V,
mutation tests, abort burn and atomic promotion.  **“Starts locally” means
only tiny/scaled integration preflight.**  The first complete GPT-2 E2E is
pod-only.  It may be proposed only after the ledger records `C7_POD_READY`,
and `C7_POD_READY` is necessary but not authorization: pod contact and that
first run still require a new explicit owner GO.  The pod must run the
smallest complete serialized case before any larger component benchmark.

## 9. Deviations and non-credit record

- The Gemma-class 31B point is a declared envelope because no exact target
  checkpoint/configuration was supplied.  Its ratio and all model-shape inputs
  are explicit and replaceable in the executable budget.
- R0 originally selected policy 3 because fresh weight roots or a finite
  full-mask pool would add unbudgeted full encodings/storage.  R0.1 demotes it
  to a candidate: the published Merkle/code candidates expose masked query
  symbols and do not implement the literal policy.
- R0.2 records the owner's selection of policy 3 as the sole active line.
  This supersedes the R0.1 decision gate but does not authorize static-root
  reuse, select a backend or discharge the missing privacy theorem.  Policy 2
  remains a documented but dormant fallback under Section 4.1.
- R0.3 registers 2.00/2.10 setup and 100/105% weight-byte envelopes, then
  finds no current backend satisfying those gates together with one-pass
  opening and private proof bytes.  It corrects the non-vacuous privacy game,
  separates `Q_leaf` from `Q_FS`, rejects clear-transcript extraction and
  leaves challenge generation at an owner decision gate.
- R0.4 resolves that gate with fresh interactive honest-DV challenges,
  `Q_FS=0`, logical `g=141` and a tiny CPU search.  It rejects the former
  sparse-generator escape by `nnz(G)>=kd` and blocks every optimized SIMT
  implementation until a derived/counted CPU `BatchOpenBlocks` pass.
- R0.5 implements the dense one-stage-RA exception and Poseidon2 leaf
  candidate.  The former passes only the online algorithm shape and fails
  distance plus ordered-root setup; the latter has exact tests/counts but an
  enormous setup and no authenticated shared checker.  The checkpoint records
  policy-3 candidate exhaustion rather than promoting either component.
- The proof-byte table is a target allocation calibrated to public component
  evidence, not a composed certificate derivation.  It is `credit:false` and
  is one reason Backend A remains NO-GO.
- No pod, production provider, frozen forward, quantization spec, or frozen
  M1--M12 statement was touched in R0/R0.1/R0.2/R0.3/R0.4/R0.5.

## 10. Append-only decision and rejection register

Entries in this section are append-only.  A later decision may supersede an
entry, but must retain its evidence and reason.

| ID / date | Disposition | Evidence and durable reason |
| --- | --- | --- |
| `C7-D001` / 2026-08-26 | retain | One terminal point per physical segment; otherwise coefficient generation is `sum_i Theta(K_i N_i)` and no tournament construction removes it for arbitrary points. |
| `C7-D002` / 2026-08-26 | reject | C6.3 eight-body WHIR+Bolt topology: measured resource failure history and wrong lifecycle shape for one response-wide C7 relation. |
| `C7-D003` / 2026-08-26 | reject under policy 3 | Published Ligerito sends requested rows and its terminal matrix; ERA sends requested columns plus Merkle proofs; WHIR/BCS queries reveal leaf evaluations/payloads. 2026/391 masks these payloads under bounded-query HVZK but still sends them. A terminal-only VOLE adapter therefore cannot satisfy “no PCS symbol in clear.” |
| `C7-D004` / 2026-08-26 | reject | Modeling Fp2 settlement as `Fin 2` independent Fp MACs with `Delta : Fin 2 -> F`: it omits extension-field cross terms and the single shared `Delta`. Replaced by extension-field linearity plus coordinate consequences. |
| `C7-D005` / 2026-08-26 | demote to screen | Eight segments/layer, 106/378 claims, `J=512` and `2^29` handles lack a canonical compiler/codec census. They remain illustrative caps and may not parameterize privacy. |
| `C7-D006` / 2026-08-26 | demote to conditional arithmetic | The 64-event table is an allocation, not a theorem-backed registry. The 83-bit figure holds only if every event/hybrid and global scope is derived. |
| `C7-D007` / 2026-08-26 | demote to allocation | 12.386/19.212-MB sums and their 1.551x ratio are chosen allocation caps, not compiled proof bytes or proof-growth evidence. Unknown components fail closed. |
| `C7-D008` / 2026-08-26 | demote to source target | One `2N` scan and zero `L` writes cover only the packed functional dot product, not encoding, Merkle/oracle I/O, operator reduction, total prover time or memory. |
| `C7-D009` / 2026-08-26 | demote to sensitivity | 7.142-GB/1.776-TB totals combine an illustrative 4.4x ERA oracle, assumed P1/P2/multiplier sizes and Merkle layout; they are not a derived setup or refresh construction. |
| `C7-D010` / 2026-08-26 | reject as proof | Fixed-error RLC root counting does not prove transcript freeze/FS; codec round-trip does not prove no-clear serialization; a finite-set union bound does not compose computational privacy. The conditional hybrid recurrence exposes the missing concrete per-attempt premise. |
| `C7-D011` / 2026-08-26 | select policy 3; policy 2 dormant | Owner selects no-clear authenticated-only policy 3 as the sole active line. Policy 2 may be activated only by a later explicit owner decision after append-only terminal disposition of every credible policy-3 construction across privacy/soundness, setup, online resources and proof bytes; one candidate failure is insufficient. |
| `C7-D012` / 2026-08-26 | anti-X4d setup hard stop | X4d's setup did not independently receive a FAIL, but its 249.404-MB packed source expanded to a 9.619-GB durable Fp2 tier, 76.949-GB rebuilt oracle and 37.094-GB cache; onboarding/rebuild and 133.544-GB host / 43.487-GB device peaks make the topology ineligible. C7 permits no expanded persistent field/code/tag plane or model-sized temporary; exact setup amplification remains an owner gate. |
| `C7-D013` / 2026-08-26 | post-Fiat--Shamir query-byte hard stop | Query count is both a privacy/soundness parameter and a certificate-size driver. X4's 128-draw ideal shared-chain lower bound already spent 4,021,594 B on query frames; its later 111-draw profile still spent 2,615,414 B. Every C7 candidate must reconcile exact post-FS answers/handles, authentication or multiproof nodes, commitments and framing once into the six certificate components and pass complete Tier-A/growth gates. |
| `C7-D014` / 2026-08-26 | narrow policy-3 funnel | Only a digest-only salted leaf commitment remains analytically eligible: payload/salt and the PCS predicate are checked under attempt-local VOLE, while digest and Merkle path stay public. Persistent expanded oracles, O(N) VOLE-tag/opening planes, private full paths, reusable secret sketches and consumable root pools are rejected because they move nonlinear work, cost or leakage into setup/proof rather than solving it. The survivor has no implementation authority. |
| `C7-D015` / 2026-08-26 | reject query-count-only optimization | `q_open`, unique leaves, secret symbols and adversarial RO queries are distinct. ERA's 4.014-MB point contains 72,418 field elements and 53,011 hashes; under policy 3 witness-dependent elements must be eliminated or privately authenticated, so the byte point cannot be transposed unchanged. Fewer wider leaves can increase proof/private-verifier cost even when spot checks fall. |
| `C7-D016` / 2026-08-26 | demote digest-only size to floor screen | At the illustrative 4.4x/64-symbol geometry, packed weights plus only the digest tree are already 793.600 MB / 197.289 GB, about 3.2x packed. This omits the private checker, salt theorem and block-opening algorithm, so it is neither a setup result nor a pass; leaf size must be chosen jointly against setup and `B_query_FS`. |
| `C7-D017` / 2026-08-26 | register setup target/tolerance | Owner registers `A_setup<=2.00` target and `<=2.10` hard ceiling. The 5% band is recorded tolerance, never permission for expanded code/tag planes or N-scale scratch. At 4.4x, `A_setup~=1+140.8/g`: `g=141` is the first integer target screen; `g=128` leaves only 32 B for all metadata and is not a realistic pass. |
| `C7-D018` / 2026-08-26 | register weight/query envelope | `B_weight_nonquery+B_query_FS` remains one `B_weight_ALFC` component. Exact hard bytes are `floor(1.05*target)=3,272,685/5,496,695 B`; the 155,842/261,747-B tolerance reserves cannot hide query material or offset another component. Every leaf payload, exact multiproof sibling, private check, IOP message and frame counts after the selected challenge transform. |
| `C7-D019` / 2026-08-26 | authorize preparation only | Owner authorizes R0.3 theorem/census and fail-closed prover/pod preparation. This does not authorize prover execution, provider contact or pod use. `C7_POD_READY` requires every readiness gate, and even then a later run-specific owner GO remains mandatory. |
| `C7-D020` / 2026-08-26 | repair privacy game | Requiring identical declared leakage while including binding `C_W`/K/V roots makes the left/right game essentially compare the same witness. `Leak_base` now excludes witness-dependent hiding commitments; each world constructs its own roots, while within-world static-root linkability remains visible. |
| `C7-D021` / 2026-08-26 | parameterize leaf commitment; reject 192-bit salt | Collision resistance does not imply hiding and an ideal random oracle is not an executable private checker. With `L<2^30,Q_leaf<=2^64`, 256-bit salts give a `<2^-161` salt-hit screen while 192-bit salts give only about 97 bits. `LeafCom`, tree hash and challenge hash remain separate; no concrete hash/commitment receives implementation GO. |
| `C7-D022` / 2026-08-26 | reject clear-transcript extraction | Opaque handles plus verifier `(Delta,k)` do not extract an authenticated plaintext; exposing the prover tag would reveal it. Soundness therefore needs direct authenticated-checker soundness or an explicit committed-input PoK/extractor. Ideal malicious-DV zero-residual privacy and shared-Delta composition already exist in Lean and are reused only after a concrete codec-to-window refinement. |
| `C7-D023` / 2026-08-26 | quarantine Fiat--Shamir pending owner choice | A roughly 128-bit Fp2 challenge with `Q_FS=2^64` has only a roughly 64-bit direct grinding screen, contradicting the unqualified 110-bit event allocation. Fresh honest-DV randomness after the committed prefix is recommended; FS needs an exact work bound or amplified challenges with all extra scans, multiplicity and bytes counted. |
| `C7-D024` / 2026-08-26 | current private-oracle backend NO-GO | No retained family passes setup, one-pass opening and private query bytes together. Direct RS/Ligero restriction is `Theta(qN)`; BaseFold/X4 materializes full transforms; WHIR persists matrices/tree levels; ERA uses N-scale permutation/accumulator intermediates or `Theta(qN)` restriction. A new locally openable code remains a tiny design search, not a prover/pod candidate. |
| `C7-D025` / 2026-08-26 | select interactive challenges; FS quarantined | Owner selects fresh honest-DV `rho_i`, `beta` and `gamma` after their exact committed prefixes. Every challenge is serialized; `Q_FS=0` in the selected protocol. This supersedes the D023 owner gate without erasing its reason: any future FS transform must restore a grinding/work bound and count every changed byte. |
| `C7-D026` / 2026-08-26 | select logical `g=141` with tolerance retained | `g=141` is fixed in the logical LeafCom/query/certificate format and gives packed-plus-digest floor bytes 495,648,224 / 123,218,149,216. Headroom is 351,776 / 87,450,784 B under the 2.00x targets and 25,151,776 / 6,252,730,784 B under the 2.10x hard tolerance, all before metadata. The 105% weight-wire tolerance also remains. Device padding cannot change `g`; `g=256` requires codec necessity and a new byte census. The 256-bit-salt, `Q_leaf<=2^64` screen is about 161.16 bits at 961,958,582 large-model leaves. |
| `C7-D027` / 2026-08-26 | authorize tiny CPU search/reference only | Owner authorizes discovery and, once a concrete algorithm exists, the smallest CPU `BatchOpenBlocks` reference. No large prover/E2E, optimized SIMT kernel, provider contact or pod is authorized. Full GPT-2 remains pod-only after `C7_POD_READY` plus a later run-specific GO. |
| `C7-D028` / 2026-08-26 | CPU-before-SIMT hard gate | SIMT is allowed later only for streaming setup, LeafCom/Merkle, PCG/VOLE, MAC, Fp/Fp2, leaf checks and reductions after `C7_CPU_REFERENCE_PASS`. It must be byte-identical to CPU and report passes, operations, disk I/O, H2D/D2H/explicit-D2D, RSS/VRAM/pinned peaks, padding, launches and synchronizations. Full codewords, model-sized scratch, a second scan, `qN`, unassigned bytes or transcript/correlation changes fail. |
| `C7-D029` / 2026-08-26 | reject sparse-output-generator escape | For `G in F^(k*n)` of distance `d`, every row is a nonzero basis codeword, hence `nnz(G)>=kd`; uniform output coordinates have average support at least `kd/n`, and direct opening of `U` logical 141-symbol blocks has expected `Omega(U*k)` work at constant relative distance. This rejects direct sparse accumulation, not every structured linear circuit. Only an explicit pruned/shared DAG with derived `c_source*N+poly(q,log N)`, one packed scan and bounded memory remains open. |
| `C7-D030` / 2026-08-26 | executable dense screen; reject as PCS | The one-stage RA successor-trie implementation exactly matches a full tiny encoder with `rN` source work, `64rN` lookups, `141U` query work, one `2N` scan and `O(64*141U)` memory. It is deliberately `screen_only_not_pcs`: its affine/diagonal fixtures have no admitted Goldilocks distance/KS theorem, while a random interleaver cannot emit the complete committed accumulator oracle in order without forbidden reorder/random I/O. `C7_CPU_REFERENCE_PASS` remains false. |
| `C7-D031` / 2026-08-26 | implement leaf candidate; no crypto/setup credit | Poseidon2 Goldilocks width 16/rate 12 hashes an injectively parsed 141-Fp payload, 256-bit salt and complete metadata into a 32-B digest in 14 permutations/8,400 private-checker multiplications. Tests fix KAT, codec, mutations and cost. At `r=4`, minimum persistent storage is 473,134,816/117,621,299,360 B, but setup needs at least 29,548,940,400/7,345,865,536,800 S-box multiplication-equivalents before salt/tree hashes and still lacks ordered oracle generation and the shared authenticated checker. |
| `C7-D032` / 2026-08-26 | policy-3 terminal NO-GO under registered gates | Published clear-query PCS/HVZK, one-stage RA, RAA/two-stage ERA, full dense root-and-dot proving, Poseidon2/BLAKE3/LigeSIS/linear/group leaf lines and preprocessing-only evaluation binding now have retained terminal dispositions across privacy/soundness, setup, online I/O/memory and proof bytes. This is credible-candidate exhaustion, not a universal cryptographic lower bound. Policy 2 remains dormant until explicit owner activation. |
| `C7-D033` / 2026-08-26 | fix malicious-verifier key schedule upfront | `MaliciousV.key : Nat -> F` is a total tape fixed upfront; only public challenges and `chi` are transcript-adaptive. Real connection initialization therefore binds the key-tape seed/domain once. Each attempt atomically reserves the exact codec-derived interval on every required tape before its first witness-dependent byte, expands lazily, forbids extension and burns the unused suffix on every outcome. Adaptive post-correction keys are rejected absent a new theorem. |
| `C7-D034` / 2026-08-26 | retain interactive; quarantine amplified FS on bytes | With analytic `T=512`, interactive `T/|Fp2|` is about 119 bits; direct FS with `Q_FS=2^64` is about 55 bits; two independent challenges give the conditional `Q_FS*T^2/|Fp2|^2` screen of about 174 bits. The pair numerator is proved in Lean, but RO freshness/programming and every duplicate/shared response, path, MAC, scan and byte remain uncompiled. Interactive `Q_FS=0` stays selected. |
| `C7-D035` / 2026-08-26 | repair sampling causality; keep provider seed private | Output-dependent roots cannot precede the client-entropy opening that determines decode coins. The fixed order is client commitment, provider seed commitment, client opening, then decode/output roots; `AcceptC7` proves the private provider-seed opening and coin use. Revealing the provider seed is rejected because coin plus token can enlarge logits/CDF leakage. The public prelude has 96 payload bytes before uncompiled framing and requires distinct hash binding/client-hiding/provider-hiding hypotheses. |
| `C7-D036` / 2026-08-26 | repair canonical leaf geometry and root context | `leaf_index<leaf_count` alone admitted empty or partial internal leaves and did not bind a layout identity. `LeafCom` now derives a root context from layout digest, nonce and plane; absorbs exact total symbols; derives the unique leaf count/final length; and rejects empty, mismatched or internally partial layouts. The future root codec must recompute the context. Updated KAT/mutations prove parsing behavior only, not hash binding/hiding or checker soundness. |

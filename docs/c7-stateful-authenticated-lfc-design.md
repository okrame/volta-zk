# C7 — stateful authenticated linear-functional commitment

**Status:** C7 R0.6; policy 2 is active for design and exact query accounting,
with no backend or numeric root budget selected.  Policy 3 remains a terminal
NO-GO under the registered gates.  No SIMT kernel, large prover, E2E or pod.
This document is the task-specific authority named by `prototype-status.md`.

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

R0.6 retains the owner's 1.A/2.A/3.A choices, the R0.5 terminal policy-3
record, and activates the bounded-query policy 2 with interactive challenges.

1. The immutable model, response trace and persistent cache are separate
   commitment planes.  "One opening" means one transcript-bound
   multi-commitment ALFC invocation, not one literal Merkle root.
2. Every physical packed segment has **exactly one** operator-reduced terminal
   point before the ALFC batching challenge.  This is the only admitted
   resolution of the `O(KN)` packed-functional hard stop.
3. The active static-weight statement is policy 2: **only root-bound masked
   PCS responses within a durable global budget are visible; the terminal
   evaluation remains VOLE-authenticated and is never cleartext**.  This is
   design authority only.  No concrete codec, backend, numeric `q_attempt`,
   `Q_root` or `R_root` is selected.
4. Policy 3 is terminally rejected under the registered gates, with every
   reason retained in the append-only register.  Its Poseidon2/private-checker
   work is historical control evidence, not a requirement of policy 2.
   Ligerito/WHIR plus a t-query ZK encoding is reopened only as a theorem
   carrier; ERA `r=4` is only a byte/prover control.  Neither is admitted.
5. Persistent setup has target `A_setup <= 2.00` and hard ceiling
   `A_setup <= 2.10`.  The interval `(2.00, 2.10]` is a preregistered 5%
   tolerance, not permission for an expanded field/code/tag plane or an
   N-scale temporary.
6. Weight-oracle `B_query_wire` (the interactive successor to the historical
   `B_query_FS` label) is included inside `B_weight_ALFC`, never added as a
   seventh component.  Its hard ceiling is 105% of the registered target; use
   of the tolerance is recorded explicitly and the complete certificate must
   still pass Tier A and the 3x growth gate.
7. The historical authorized tiny CPU screen is complete.  Its online algorithm works,
   but it fails code distance and ordered-root setup, so
   `C7_CPU_REFERENCE_PASS=false`.  No further backend, large-prover/E2E,
   provider or pod action is authorized.
8. No current backend passes setup, one-pass opening, normalized nearly
   constant query counts, proof bytes and stateful malicious-DV privacy
   together.  Logical `g=141` remains fixed; every grouped/alphabet query is
   unstacked into this format and Fp2 counts as two Fp limbs before admission.
9. Policy 2 permits a public salted BLAKE3 leaf/tree check because the masked
   queried payload and its salt are visible.  This removes the private
   Poseidon2 checker; it does not prove randomized-encoding root hiding,
   adaptive t-query privacy, collision/position binding or cross-root
   composition.  The 256-bit salt screen remains; Poseidon2 is quarantined as
   a historical policy-3/inside-circuit control.
10. Fresh honest-DV `rho_i`, `beta` and `gamma`, each sampled after its exact
    committed prefix and serialized in the durable transcript, are selected.
    The selected protocol uses no Fiat--Shamir oracle (`Q_FS=0`); FS remains
    quarantined, not a dormant uncounted transform.
11. No optimized SIMT kernel or GPU scaffold may exist: the historical executable CPU
    screen proves the online cost identity but does not pass the PCS distance
    and setup gates.
12. After that checkpoint, SIMT may accelerate only streaming setup,
    `LeafCom`/Merkle, PCG/VOLE, MAC, Fp/Fp2, leaf checks and reductions.  It
    must remain byte-identical to CPU and may not add a codeword, model-sized
    scratch, second scan, `qN`, unassigned traffic or transcript difference.
    Logical `g=141` never changes; any wider device tile is temporary measured
    zero padding excluded from commitments, certificate and transcript.
13. Direct sparse-coordinate regeneration remains rejected by the
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
- only root-bound masked codec payloads may be exposed, within the exact
  reserved query schedule; raw weights, unmasked code symbols and the
  terminal evaluation remain forbidden on the wire;
- a concrete domain-separated public `LeafCom`, tree hash and transcript hash
  must supply collision/position binding, while the randomized encoding plus
  salt/root construction must supply the separately named adaptive hiding
  theorem.  Collision resistance alone is not hiding;
- soundness must bind every visible masked response and authenticated terminal
  to one extracted randomized encoding of the same canonical `W`; t-query
  privacy or opaque MAC handles alone do not provide knowledge soundness;
- a weight oracle may persist only the canonical packed weights plus the
  candidate's fully counted root/index/metadata inside `A_setup<=2.00`
  (hard `2.10`).  Expanded Fp/Fp2 copies, per-coordinate authentication,
  P1/P2/multiplier planes, full codewords or N-scale setup temporaries remain
  anti-X4d hard stops; a new root is never a free budget reset;
- every candidate must compile the exact query count by root and round and
  the complete serialized bytes under the selected challenge mode.  Query
  answers/private handles, authentication or multiproof material, round
  commitments and framing are assigned exactly once to the six certificate
  components.  Missing interactive messages or later Fiat--Shamir transform
  bytes fail closed;
- the malicious designated-verifier, adaptive, stateful privacy theorem must
  cover all connections and colluding verifiers sharing a root, rejection
  feedback, retries, crashes and selective aborts, plus bounded composition
  over root rotations;
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
declared **base leakage** `Leak_base`.  This equality predicate contains only
witness-independent API semantics, counters, shapes and the public
equality/linkability pattern.  It excludes the complete branch-derived
closure `Deriv_b`: `C_W`, boundary/K/V roots, leaf digests and paths,
`root_budget_id`, authenticated receipts, predecessor-certificate digests,
and transcript/journal heads computed from any of those values.  The
challenger constructs `Deriv_0` and `Deriv_1` independently and returns the
resulting full views; their bytes are required to be indistinguishable, not
equal.  Within either world `C_W` remains static and therefore linkable across
attempts.  Requiring either equal binding roots or equal deterministic
derivatives of those roots would restrict the game to essentially identical
weights and make the privacy claim vacuous.  A named
`BranchDerivedViewClosure` reduction must cover every serialized derivative;
omitting one fails admission.

Availability and suppression of a sampled response are not hidden.  The C7
relation requires a published token to follow the committed sampling coins;
it does not promise unbiased service after a provider chooses to abort.
Every such attempt still consumes the connection horizon and burns its
masks/correlations.

## 2. Exact response relation

Let `e` be the accepted epoch, `k` the predecessor cache length, `T` the
response length, and `tau_0,...,tau_T` the public token boundary and response.
For the registered workload, `k = 100` and `T = 50`.

The response epoch `e` is distinct from the weight-oracle privacy epoch
`omega`.  One `omega` identifies the immutable `C_W` plus the complete ordered
set of auxiliary randomized-code roots, their root contexts, encoding/masking
parameters and one policy-2 profile digest binding the query vector, privacy
atom, plane-tagged fixed attempt charge vector, `Q_root`, `Q_B`, `Q_KV` and
rotation policy.  Its
`root_budget_id` is the
domain-separated hash of that canonical descriptor.  Replacing, renaming or
reordering any auxiliary root creates a new `omega`, consumes the model-wide
root-epoch allowance and never resets leakage accounting for free.

### 2.1 Public and durable session state

The public instance `x_e` contains, in canonical byte order:

1. protocol/version and all domain-separation labels;
2. `connection_id`, model/layout/quantization digests, immutable `C_W`, and
   the complete `omega` descriptor with `root_budget_id` and policy-2 profile
   digest;
3. accepted `epoch = e`, predecessor certificate digest, `C_KV,e`, and
   `kv_len = k`, plus the authenticated `state_budget_head` and either the
   prior accepted map transition or `InitKVState(s0)` record;
4. attempt slot, single-use response nonce, connection/MAC key-domain ID,
   reserved correlation ranges and their already-durable high-water marks;
5. a globally unique root-budget reservation receipt binding `omega`,
   `root_budget_id`, profile digest, attempt ID, the complete receipt-free
   `reservation_request_binding` (`connection_id`, nonce, MAC key domain and
   fixed plane-charge vector included), weight/predecessor-KV pre/post-spend
   high-water marks and nonrefundable boundary/successor-KV assignment slots;
   a later authenticated plane-assignment record binds those already-burned
   slots to `C_B,e` and `C_KV,e+1` before either root is disclosed.  Its
   authenticated lifecycle is `Reserved -> InFlight -> Burned | Accepted`.
   Receipt authenticity and allocator linearizability use the separately
   scoped hypotheses in Sections 4.3 and 4.6;
6. public input/output tokens, `T`, maximum context/capacity and the exact
   sampler policy;
7. a client sampling-entropy commitment, the later prover sampling-seed
   commitment, the client's canonical opening and the exact pre-response
   prefix deriving per-step sampling coins; the provider opening remains
   private and is proved inside the relation, and sampling entropy is
   domain-separated from proof challenges;
8. fresh response root `C_B,e`, successor root `C_KV,e+1`, successor length
   `k + T`, and the canonical claim-schedule digest;
9. hash/code/field parameter identifiers and the complete certificate framing
   lengths.

The accepted client state is the tuple

```text
(connection_id, e, k, C_W, omega, root_budget_id, policy2_profile_digest,
 C_KV,e, reservation_receipt, root_budget_high_water,
 plane_assignment_receipt, boundary_budget_high_water,
 predecessor_KV_budget_high_water, successor_KV_budget_high_water,
 state_budget_head,
 predecessor_certificate, accepted_transcript_head,
 MAC_key_domain_id, correlation_high_water, attempt_high_water).
```

The authoritative model-owner/provider allocator keeps two separated durable
ledgers:

```text
weight_epoch_ledger[omega] =
  (root_budget_id, profile_digest, Q_root, spent_root, sealed)

state_plane_ledger =
  (reservation_map[receipt -> (omega, reserved_session_binding, status,
                                transcript_state, cached_reply,
                                plane_charge_vector, assignment_status)],
   boundary_budget_map[attempt -> (C_B_or_tombstone, Q_B, spent_B, sealed)],
   kv_budget_map[s -> (C_KV, Q_KV, spent_KV, sealed, accepted_epoch?)],
   state_budget_head, root_epoch_high_water, D_model_high_water).
```

The malicious designated verifier cannot mint receipts or roll this ledger
back.  The provider obtains the reservation from that allocator and refuses
every attempt-local `W`/`omega`-dependent response without it; the client
persists only the authenticated receipt and its local state.  `C_W` cannot
change within the connection; auxiliary roots may change only through the
sealed rotation protocol in Section 4.6.

Before the first accepted predecessor `C_KV,0` or its certificate is
disclosed, `InitKVState(s0)` atomically creates
`kv_budget_map[s0]`, applies its creation charge and authenticates the initial
`state_budget_head`.  A predecessor imported from an earlier accepted session
must already have the same live entry; otherwise the request rejects before
any new response.  `InitKVStateSound` and its malicious-DV privacy reduction
remain named hypotheses.  Weight-epoch creation or rotation cannot create,
replace or reset this entry.

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
request_binding = Encode(protocol_version, connection_id, nonce, e, k, T,
                         model/layout/quantization digests, C_W, C_KV,e,
                         requested_omega, root_budget_id, profile_digest,
                         predecessor_certificate, sampler_policy, input_tokens),
client_entropy_commit =
  H("VOLTA-C7/SAMPLE/CLIENT/v1" || request_binding || client_entropy),
reservation_request_binding = Encode(request_binding, MAC_key_domain_id,
                                     q_attempt_by_plane,
                                     attempt_plane_charge_vector),
reservation_receipt = AuthAllocator(reservation_request_binding,
                                    pre_spend, post_spend),
reserved_session_binding = Encode(reservation_request_binding,
                                  reservation_receipt),
prover_seed_commit =
  H("VOLTA-C7/SAMPLE/PROVER/v1" || reserved_session_binding ||
    client_entropy_commit || prover_seed),
KV_(t+1) = KV_t || KV_write_t,
sampling_prefix = Encode(reserved_session_binding, protocol/authorization,
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

1. **Plane/epoch binding.** `C_W`, every auxiliary root in `omega`, `C_B,e`,
   `C_KV,e` and `C_KV,e+1` bind their canonical layouts under the named
   concrete binding hypotheses.  The canonical `omega` descriptor and
   `root_budget_id` contain the complete ordered weight-oracle root set;
   setup knowledge soundness ties every auxiliary encoding to the same
   canonical packed `W` opened by `C_W`, which binds the same weight cells at
   every layer and step.
2. **Accepted predecessor.** The old K/V commitment, length, epoch and
   predecessor certificate exactly equal the durable accepted head; its live
   `kv_budget_map` entry and authenticated high-water equal
   `state_budget_head`.  At `e=0`, the checked `InitKVState(s0)` transition
   precedes any disclosure.
3. **Plane-budget reservation.** `ReceiptUnforgeability` validates one
   globally unique, unrefundable receipt for this attempt, `omega`, profile,
   complete receipt-free `reservation_request_binding` and positive fixed
   charge; combining the verified receipt with that binding uniquely derives
   `reserved_session_binding`.  Its plane-tagged charge vector has weight,
   boundary, predecessor-K/V and proposed-successor-K/V components.  Weight
   and predecessor high-water marks are consecutive within `Q_root` and the
   existing `Q_KV[s_old]`; boundary/successor slots are burned with no refund.
   Before their roots are emitted, an authenticated assignment CAS creates
   `boundary_budget_map[a]` and `kv_budget_map[s_new]`, applies the reserved
   creation charges and fixes their high-water marks within `Q_B[a]` and
   `Q_KV[s_new]`.  Both receipt digests are in the frozen transcript prefix.
   A linearizable allocator CAS
   admits only its single lifecycle.  An exact duplicate input at the current
   transcript state may return only the cached byte-identical reply; a
   divergent replay, including a different challenge, fails before a new
   `W`/root-dependent byte.  The parsed response census is componentwise at
   most the receipt's plane-tagged `q_attempt` vectors and uses exactly their
   privacy-unit mappings.
4. **All real steps.** The recurrence in Section 2.3 holds for every
   `t = 0,...,T-1`, including the public client opening, the private provider
   opening, the exact pre-response prefix, the fixed token tie rule and
   sampler coins.
5. **Append-only successor.** `KV_T = KV_0 || canonical_tail`, the prefix is
   unchanged, the length is `k + T`, all written addresses are canonical and
   no other cell changes.
6. **Response-wide stacking.** Operator, weight, boundary and K/V claims cover
   all `T` steps in one protocol execution.  There is no per-token proof or
   later debt.
7. **Canonical schedule.** Serialization parses uniquely; ordinals, segment
   bounds, padding, roots and query-vector derivations match the public layout;
   every physical segment appears exactly once.  Commitments, schedule,
   query vectors and authenticated claimed values are fixed before `beta`.
8. **ALFC.** The one logical multi-commitment opening accepts and transfers
   every terminal linear result directly into the connection VOLE-MAC.  Only
   the profile-approved masked code symbols may be visible and every one is
   charged to its W/B/KV plane component in the reservation/assignment
   records; no clear `W~(r)`, K/V evaluation,
   terminal value or reusable affine fold is exposed.
9. **Terminal settlement.** One post-ALFC challenge settles all
   extension-field MAC residuals to zero; both serialized coordinates check,
   and every reserved correlation/mask is consumed exactly once.
10. **Atomic state change.** A durable compare-and-swap on the predecessor head,
   nonce and slot promotes `(e,k,C_KV,e)` to `(e+1,k+T,C_KV,e+1)` together with
   the certificate/transcript journal, seals the boundary budget record and
   retains the successor K/V record with its creation spend.  The ACK is sent
   only after this commit.

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
Client / DV journal                Model-owner allocator + provider/prover
-------------------                ----------------------------------------
choose single-use request nonce;
commit fresh sampling entropy
        |  authorization + requested active omega/profile
        |  + nonce + MAC-key-domain ID + entropy commitment
        |------------------------------------------->
provider validates the active complete omega/profile; atomically debits the
weight and predecessor-KV components, burns/escrows the boundary and proposed-
successor components of the fixed plane-charge vector, and persists an
authenticated receipt over the receipt-free reservation-request binding in
`Reserved` status; before emitting anything, it commits the provider seed,
CASes `Reserved -> InFlight` and caches the complete first reply plus
connection correlation ranges
        |  omega/profile/receipt + commit prover seed only
        |<-------------------------------------------|
client durably records the receipt
        |  open sampling entropy
        |------------------------------------------->
provider verifies the client opening, atomically advances the exact cached
transcript state, privately derives every coin_t from the pre-response
sampling prefix, then executes all T DecodeStep_q; before disclosing the new
roots it atomically binds the already-burned slots to C_B,e and C_KV,e+1,
creates their budget-map records and caches the root-assignment reply
        |  output tokens + sampler metadata + C_B,e + C_KV,e+1
        |  + plane-assignment receipt + first proof messages
        |<-------------------------------------------|
bind public state, omega's complete ordered root set, profile/receipt,
fresh F_VOLE+id, C_W, C_KV,e, all four top-level roots, output tokens,
sampler metadata and each operator/code message m_i
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

### 4.1 Selected static-weight line: bounded masked queries

R0.6 activates policy 2:

> Only root-bound masked PCS responses, quantitatively limited by a durable
> global root counter, are shown; the terminal evaluation remains
> VOLE-authenticated and is never revealed in clear.

The policy-3 no-clear line remains terminally rejected under the registered
gates.  That historical decision is not erased: it explains why C7 now
accepts a bounded masked-symbol leakage channel instead of inventing a
private checker for every leaf/hash/PCS response.

Every complete weight-oracle epoch `omega` from Section 2.1 has one public,
compiler-bound reservation profile and one global durable record.  The
authoritative attempt census is plane-tagged:

```text
q_attempt[p]  = (U_leaf, S_visible_Fp, H_sibling), p in {W,B,KV_old,KV_new}
q_response[p] = the actual response vector, componentwise <= q_attempt[p]
A_attempt = 1 for every successful global reservation
```

`U_leaf` counts unique opened logical leaves; `S_visible_Fp` counts every
serialized masked base-field symbol occurrence; `H_sibling` counts exact
Merkle multiproof siblings; and `A_attempt=1` for every successful
reservation.  An Fp2 symbol is two Fp symbols.  A complete `g=141` leaf costs
141 visible symbols even if only one inner coordinate was requested.  A
grouped or N-dependent alphabet query is never counted as one before this
unstacking.  No cross-attempt deduplication receives privacy credit.  The
profile maps these vectors to a fixed charge vector

```text
u_attempt = (u_W, u_B, u_KV_old, u_KV_new).
```

No component pays another plane's horizon.

The privacy theorem chooses its exact atom.  Until it does, the conservative
scalar is `S_visible_Fp`; a vector or a worst-case weighted scalar is required
for multiple correlated oracles/alphabets.  Merkle siblings cost bytes and
belong to the simulator view, but are not silently equated with one masked
field symbol.  The following quantities remain separate:

```text
q_attempt   maximum plane-tagged vectors reserved by one attempt
q_response  actual plane-tagged vectors for one response
Q_root      total theorem-backed privacy capacity for one complete omega
R_root      maximum reserved attempts before that omega is sealed

R_root <= floor(Q_root / u_W).
```

This formula is admitted only with
`0 < u_W <= Q_root`; each nonzero plane charge must likewise fit its named
`Q_B`/`Q_KV` horizon, and a profile that cannot reserve one complete attempt
is invalid.  Positive headroom beyond the selected service floor remains
mandatory.

Proof size constrains `q_attempt/q_response`; privacy constrains `Q_root`;
setup constrains root construction and rotation; one-pass work constrains an
attempt.  There is no valid single minimum across these quantities.

Before the first attempt-local provider response byte whose distribution
depends on `W` or its root, a linearizable durable reservation increments
`spent_root += u_W`, debits `u_KV_old` against the accepted predecessor,
burns `u_B/u_KV_new` assignment slots and increments the attempt count.  The public root
itself is a baseline **view element**, not free leakage: replacing it between
worlds is charged to `SaltedMerkleRootPathHide`.  The reservation
cannot be extended or refunded.  Accept, reject, timeout, crash, retry and
selective abort all burn the full reservation.  Insufficient capacity rejects
before answering.  The record is global to the root across users,
connections, replicas and colluding designated verifiers.  Per-user quotas
and rate limits may run before it to mitigate denial of service, but they are
not cryptographic counters.

After response computation but before `C_B,e` or the proposed successor root
is emitted, one no-extension assignment CAS binds the burned slots, creates
`boundary_budget_map[a]` and `kv_budget_map[s_new]`, and records their exact
high-water marks.  It cannot increase a charge.  Abort before assignment
leaves tombstoned burned slots; abort/reject after assignment seals both new
records.  Acceptance seals the one-shot boundary record but leaves the same
successor K/V record active for future predecessor debits.

Uniqueness is not single use by itself.  The allocator authenticates the
receipt-free `reservation_request_binding`; appending that receipt defines the
complete `reserved_session_binding`.  It enforces
`Reserved -> InFlight -> Burned | Accepted`.  Every protocol message advances
one canonical transcript state by compare-and-swap.  Repeating the identical
input may return only its cached byte-identical reply; a different connection,
nonce, MAC domain, prefix or challenge is rejected before any new
`W`/root-dependent byte.  Thus replica races cannot obtain two adaptive query
sets after one charge.  This state machine, its receipt codec and its cache
durability are still unimplemented hypotheses, not consequences of a unique
receipt identifier.

At exhaustion the root is sealed; it is not rotated on adversarial demand.
A replacement uses independent encoding randomness, salts and seeds, proves a
bridge to the same canonical `W`, compiles setup/storage/refresh, and switches
atomically.  A model-wide epoch cap `K_model` or a multi-root composition
theorem is still required: fresh roots do not reset leakage for free.

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
It applies equally to partial code symbols or terminal folds.  Policy 2 may
show theorem-approved randomized-code symbols, but never two affine folds
under one reusable mask.  Attempt masks/correlations are fresh and burned on
abort; root-level reuse is limited only by the proved t-query capacity and
global counter.

### 4.3 Named privacy theorem still required

`C7-P2-MDV-STATEFUL-PRIV(lambda,K_model,D_model,Q_root,{Q_B},{Q_KV},
Q_hide,Q_PRF,interactive)` is the active
left/right game (`Q_FS=0`).  One adversary represents unlimited identities,
connections and colluding designated verifiers.  It adaptively chooses legal
challenges, queries, abort points and timing while the global allocator
enforces each root budget and a model-wide epoch bound.  Its view contains
all masked payloads, opened salts, indices, digests, paths, byte prefixes,
exhaustion errors, accept/reject results and journal transitions.  The
terminal value occurs only as a VOLE-authenticated value.

For equal witness-independent `Leak_base`, each world independently builds
its hiding roots.  Requiring an equal binding root would make the game
vacuous.  The simulator covers the adaptive union of observations under a
root, not one independent response at a time.  A published non-adaptive HVZK
or t-query encoding is therefore only a named hypothesis until extended to
this stateful malicious-DV game.

The game is operationally a paired-history oracle.  At attempt `a`, the
adversary submits one common public request and two branch-specific valid
continuations extending the accepted predecessor in their respective worlds.
Their next canonical **base** frame must be byte-identical: public
prompt/input, output tokens, lengths, sampler policy, admitted
availability/abort class, counters, public shape and linkability pattern are
included.  Malformed pairs or unequal base frames reject before any
branch-dependent protocol byte.  The challenger then constructs the complete
branch-derived closure `Deriv_b`, including roots and every identifier,
receipt/authentication, predecessor digest and transcript/journal head derived
from them.  These bytes are not an equality precondition: their replacement
is paid by the hiding/authentication hybrids and
`BranchDerivedViewClosure`.  The adversary may choose later pairs from its
adaptive view, but each pair must remain valid in both branch histories.  C7
therefore hides weights only beyond the authorized inference/API leakage; it
does not hide public model outputs.

Let `D_model` bound the distinct connection/MAC key domains that receive an
attempt-local `W`-dependent response during the model lifetime.  Each domain
fixes one `Delta` and complete indexed key-tape domain before its first
response.  The adversary may correlate `Delta` and key functions across
domains; provider-side coins/masks are fresh and domain-separated.  `D_model`
is bounded by the global reservation journal (and in
particular by total reserved attempts), not by user identity.  The existing
Lean simulator covers one domain with one shared `Delta`; C7 additionally
requires a named `MultiUserVoleCompose(D_model)` hybrid theorem.  Colluding
verifiers cannot be charged to the single-connection theorem.

`Q_root` applies only to the complete weight-oracle epoch `omega`.  It does
not silently pay for the fresh response and persistent state planes.  A
concrete compiler must additionally instantiate:

```text
Q_B[a]       visible masked-symbol/path horizon for fresh response root C_B,a
Q_KV[s]      lifetime horizon for every created K/V root instance s
```

and tag every census entry by plane.  `C_B,a` is charged once per attempt.
Every proposed successor `C_KV,e+1` creates a distinct root instance `s` and
burns its creation charge before disclosure, even if the attempt later aborts
or rejects.  An unaccepted instance is sealed permanently.  If accepted, the
same `Q_KV[s]` counter continues whenever that exact root is reused as a
predecessor; acceptance does not reset it.  If a backend reveals no
payload/path for a plane, its zero charge must follow from its concrete
authenticated-only codec and hiding theorem.  Until the per-plane horizons
and reductions exist, boundary/K/V privacy is fail-closed.

The required lifetime bound is

```text
Adv_priv_lifetime
 <= sum_root (
       zeta_joint_adaptive_tZK(root,Q_root)
     + Adv_PRF_root_masks_and_salts(Q_PRF[root])
     + epsilon_SaltedMerkleRootPathHide(Q_hide[root]))
  + sum_attempt (
       zeta_boundary_plane(a,Q_B[a])
     + Adv_PRF_boundary_masks_and_salts(a)
     + epsilon_boundary_root_path_hide(a))
  + sum_created_KV_root s (
       zeta_KV_plane(s,Q_KV[s])
     + Adv_PRF_KV_masks_and_salts(s)
     + epsilon_KV_root_path_hide(s))
  + sum_MAC_domain (
       Adv_real_VOLE_malDV(domain,{J_a})
     + epsilon_key_domain_separation)
  + sum_attempt (
       Adv_PCG_a
     + epsilon_terminal_codec_a
     + epsilon_timing_a)
  + sum_rotation Adv_RotateSameW_private_bridge
  + epsilon_MultiUserVoleCompose(D_model)
  + epsilon_BranchDerivedViewClosure
  + epsilon_receipt_auth_privacy
  + epsilon_global_counter_rollback_fork
  + epsilon_plane_budget_assignment_rollback_fork
  + epsilon_InitKVState_privacy
  + epsilon_state_budget_carry_privacy
  + epsilon_state_replay
  + epsilon_rotation_composition.
```

Admission additionally requires the composed model-lifetime game—not merely
one connection slice—to satisfy

```text
Adv_priv_model_lifetime(K_model,D_model,Q_root,{Q_B},{Q_KV},Q_hide,Q_PRF)
  <= 2^-78.
```

There is no honest-challenge term in this privacy game; honest post-prefix
unpredictability is a soundness premise.  The existing ideal shared-`Delta`
VOLE-MAC simulator can discharge one domain's terminal middle only after a
concrete codec refinement.  It neither simulates the visible PCS encoding nor
proves the multi-domain hybrid.

The preferred public leaf/tree candidate is BLAKE3 with separate domains for
leaf, tree and transcript hashing.  An opened masked payload and 256-bit salt
let the verifier recompute its leaf and path, so no private Poseidon2 checker
is required.  Collision resistance still proves neither root hiding nor
adaptive t-query privacy; `SaltedMerkleRootPathHide`, randomized-encoding
privacy and position/geometry binding remain named hypotheses.

The active hash reductions use three non-interchangeable work bounds:

```text
Q_CR[root]    collision/binding work against leaf/tree hashing
Q_hide[root]  adaptive root/path-hiding oracle work and cumulative view
Q_PRF[root]   mask/salt PRF oracle work, including all derived leaves
```

The concrete reductions must derive these from `K_model`, every `omega`, the
opened-leaf/path union and the adversary's declared oracle access.  They are
not `q_attempt`, `Q_root`, each other, or the historical policy-3 `Q_leaf`.

#### Historical policy-3 game and rejection evidence

`C7-ALFC-MDV-STATEFUL-PRIV(lambda,R_max,L,Q_leaf,interactive)` is a left/right
game for the rejected policy-3 protocol (`Q_FS=0`).
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

There is no honest-challenge term in that historical **privacy** game: the malicious DV
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

In that historical line, `LeafCom(payload;salt)`, `H_tree(left,right)` and `H_transcript` are separate
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
public salted-leaf/position binding, randomized-code unique-decoding/knowledge
soundness, the bridge from every masked response and authenticated terminal
to one encoding of the same `W`, Fp2 MAC/RLC, PCG and state/replay/fork
errors.

```text
Pr[Bad]
 <= epsilon_honest_DV_challenge(R_max,t,|Fp2|)
  + sum_root (
        epsilon_MaskedOracleExtract(J_root,Q_root)
      + epsilon_LeafComBinding(L_root,U_leaf_root,Q_CR[root])
      + epsilon_MerklePositionBinding
      + epsilon_CodeKS_or_UniqueDecode
      + epsilon_EncodedRootSetupBinding)
  + sum_rotation (
        epsilon_RotateSameW_KS
      + epsilon_bridge_transcript_binding
      + epsilon_seal_cutover_fork
      + epsilon_state_budget_carry_binding)
  + sum_MAC_domain epsilon_MAC_domain
  + epsilon_MultiUserMacCompose(D_model)
  + sum_attempt (
        epsilon_MAC_Fp2
      + epsilon_masked_response_binding
      + epsilon_RLC_operator
      + epsilon_codec
      + epsilon_PCG)
  + epsilon_ReceiptUnforgeability
  + epsilon_PlaneBudgetAssignmentSound
  + epsilon_InitKVStateSound
  + epsilon_global_allocator_rollback_fork
  + epsilon_state_replay_fork.
```

No term is declared independent merely because attempts use fresh masks; the
same `Delta` is handled only within one MAC domain by fixed-other-coins slices
and union bounds.  Cross-domain composition is the named multi-user premise.
The root and rotation sums range over at most `K_model` complete `omega`
descriptors.  `RotateSameW` must knowledge-bind both randomized encodings to
the immutable `C_W`; its private bridge transcript and bytes/setup are charged
separately rather than hidden inside root creation.

The earlier policy-3 step “extract a virtual clear PCS transcript” remains
rejected as circular.  In policy 2 the masked oracle transcript is concrete,
but soundness still needs an extractor/unique-decoding theorem tying it and
the opaque terminal handle to one committed randomized encoding of `W`.
`OpeningMac.lean` supplies only the mathematical authenticated-output seam.
Evaluation binding from preprocessing is not this knowledge theorem.

The allocator trust boundary is explicit.  Privacy assumes an honest
model-owner/provider allocator satisfying `AllocatorPrivacyIntegrity`; a
corrupt allocator can intentionally exceed the advertised leakage budget and
is outside this game.  Soundness against a dishonest prover instead uses
`ReceiptUnforgeability` plus verifier-side validation, so the prover cannot
mint or fork budget/state authority.  The shared implementation may support
both properties, but one undifferentiated `GlobalBudgetReceiptSound` label is
not accepted as a proof of either.

### 4.4 What is and is not cryptographically proved

The repository proves four relevant ideal/algebraic facts; none instantiates
the active masked PCS oracle, global budget or rotation protocol.

1. `bsc_zeroBatch_perfect_zk` and
   `sequential_composition_perfect_zk` prove perfect straight-line privacy in
   ideal `F_sVOLE` for public-shape windows with true zero residuals, even
   when one malicious verifier fixes shared `Delta` and its whole indexed key
   function upfront, then chooses challenges adaptively.  The missing concrete
   refinement is not assumed by them.  This is one MAC/key domain, not the
   active multi-connection `MultiUserVoleCompose` theorem.
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
   an ideal ALFC and does not compose distinct `Delta`/key domains.
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

This is the current proved boundary.  Full concrete cryptographic
soundness/privacy is **not proved** until public `LeafCom` binding and adaptive
root hiding, the masked-code codec/t-query theorem, the same-`W` terminal
bridge, paired-history game, transcript-bound authenticated allocator receipt,
multi-user VOLE/MAC theorem, private knowledge-sound rotation, distinct hash
work bounds, real PCG/VOLE, honest-DV entropy/transcript binding and code
knowledge soundness are instantiated and composed.

### 4.5 Horizon and conditional union budget

The connection-level security allocation retains

```text
R_max = 2^20 attempts.
```

An attempt is counted when its durable nonce/correlation reservation is
created, whether it later accepts, fails, crashes, retries or is selectively
aborted.  The connection closes before a `2^20 + 1`-st reservation.  This is
not `R_root`: the active root privacy budget can seal a root earlier, and all
connections sharing that root debit the same allocator.  Conversely, a root
rotation cannot restart the model-lifetime privacy game without the missing
`K_model`/multi-root composition theorem.

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
`(connection_id, epoch, old_root, predecessor_certificate, slot, nonce,
omega, root_budget_id, profile_digest, reservation_receipt_digest,
plane_assignment_receipt_digest, state_budget_head, MAC_key_domain_id)`.
Recovery observes either the complete old record or the complete new record.
It never observes a promoted root without the matching certificate and
consumption high-water marks.

The root-wide query reservation is a separate linearization that must become
durable before the first attempt-local provider response byte dependent on
`W`/`omega`.  A local hash chain is insufficient against rollback or replica
forks; the implementation needs a shared allocator or monotonic anchor.
Before the receipt or any other first reply is emitted, an allocator CAS
changes the exact internally created receipt from `Reserved` to `InFlight`
and caches that complete first reply.  Each later input CASes the expected
transcript state and caches its reply.  A duplicate with identical state/input receives
only that byte-identical cache entry; any divergent replay fails without a
new witness-dependent reply.  Before the first reply containing `C_B,e` or
`C_KV,e+1`, the same CAS chain binds the pre-burned plane slots, initializes
their budget maps and caches the authenticated assignment record with that
reply.  Terminal settlement changes `InFlight` to exactly one of `Burned` or
`Accepted`.  State acceptance validates both transcript-bound receipts and
all W/B/KV high-water marks but never refunds them.  Abort/reject seals every
assigned response/successor record; acceptance seals the response record and
promotes the already-charged successor record without resetting it.

- A byte-identical produced certificate may be retransmitted after ACK
  ambiguity; no different certificate may occupy that slot.
- Once one certificate advances epoch `e`, neither it nor a sibling fork from
  the same old head is admissible against epoch `e+1`.
- Abort/reject marks the attempt burned and cannot promote K/V state.
- No retry may reuse the burned nonce, sampler seed commitment, PCS mask/root
  for the response-local planes, or either base-limb correlation range.

Rotation is a stop-admit protocol, not an automatic response to exhaustion:

1. atomically seal `omega` against new reservations;
2. resolve every outstanding receipt by completing the byte-identical
   in-flight attempt or durably burning/cancelling it; no unaccounted attempt
   may cross cutover;
3. construct `omega'` with independent encoding randomness/salts and prove a
   `RotateSameW` relation anchored to immutable `C_W` that knowledge-binds both
   complete oracle descriptors to the same canonical packed `W`;
4. charge bridge proof bytes, setup/I/O and a malicious-DV private bridge
   transcript, verify them, initialize only a fresh **weight-epoch** bounded
   counter and atomically activate `omega'` while carrying the complete
   `state_plane_ledger`, every live/sealed K/V high-water and
   `state_budget_head` byte-identically into the cutover record;
5. retain old roots only for verification/audit of accepted certificates;
   they answer no new openings.

`RotateSameW` therefore needs distinct binding/knowledge, bridge-privacy and
atomic-cutover theorems.  A successful bridge consumes one of at most
`K_model` root epochs; it does not erase the old epoch's leakage or reset any
boundary/K/V capacity.  Because admission is stopped and every in-flight
receipt is resolved first, no plane assignment can straddle the cutover.

The C7 Lean module reuses the existing C6 durable-state definitions only as
an already proved abstract state-machine seam; it does not reuse the C6 proof
backend or certificate topology.

## 5. Backend tournament

Labels mean: **Evidence** is a proved/published component fact;
**Assumption** is required but not supplied for C7; **Dead end** is excluded
from the selected line.

R0.6 narrows active analysis to two non-admitted lines:

1. RS t-query ZK plus strict-UD WHIR/Ligerito and a salted public BLAKE3
   Merkle tree, as the best carrier for binding/privacy theorems;
2. ERA `r=4` plus the same public tree, only as a concrete query-byte and
   linear-prover control.

Neither line currently supplies the joint adaptive stateful privacy theorem,
an ordered root construction inside the setup gate, and an executable
`O(N+poly(q,log N))` one-scan opener.  Therefore neither authorizes code.
Every candidate must first unstack its query alphabet to logical `g=141` and
Fp limbs.  The GPT-2 and 31B `U_leaf` and `S_visible_Fp` attempt caps must be
constant (the registered 5% tolerance is allowed only as a recorded hard
ceiling); Merkle depth may grow only if exact total wire bytes still pass.

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
- No paper supplies the joint theorem that the visible masked code responses
  remain private under adaptive root-wide queries and are bound to the same
  `W` as the VOLE-authenticated terminal.  A terminal-only adapter does not
  establish either property.
- ERA's query-efficient `2^32` proof is an estimate, not a prover/memory
  measurement; its random permutations/multipliers and indexer oracles are
  linear setup objects.
- Neither Ligerito nor ERA supplies the required one-sequential-scan,
  bounded-memory composed schedule at 31B.

**R0.6 disposition:** reopen only the RS t-query-ZK plus strict-UD
WHIR/Ligerito composition as a theorem carrier.  The published 2026/391
statement is non-adaptive HVZK over an N-dependent alphabet, not C7's
stateful malicious-DV theorem.  ERA remains a byte/prover control: as
published its `O(lambda log N)` field-coordinate query law fails the strict
constant normalized-query gate and its N-scale intermediates fail setup.

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

**Historical R0.2 disposition, superseded by the R0.6 no-backend GO:**
**GO as a transparent tiny/scaled code control only**
after a packed illustrative schedule exists.  It may test the packed identity,
unique-decoding verifier and byte/I/O instrumentation on public or synthetic
data.  It cannot test the missing masked-encoding privacy/same-`W` composition
and cannot use private production weights.  The C6.3 eight-body WHIR+Bolt
topology is forbidden.  Results remain component evidence and cannot promote
C7 state or grant privacy/E2E credit.

### 5.4 Historical R0.4/R0.5 policy-3 funnel and CPU gate

Under the then-active policy 3, only one architectural shape remained eligible
for analytic work; it is now terminally rejected and retained only to explain
the current exclusions:

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
The policy-3 contract that kept leaves/salts provider-internal is historical
and terminally superseded.  Under active policy 2, the reference produces the
exact profile-approved masked 141-symbol payload occurrences, opened salts,
indices and public Merkle multiproof that are actually serialized, plus the
authenticated-only terminal handle and all counters.  No clear terminal
evaluation is added.  A truncated, extended or mutated source, counter
mismatch, noncanonical query, second pass or hidden model-linear allocation
fails before output or state promotion and burns the reserved attempt when
run inside a lifecycle.

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
SIMT must match byte-for-byte on the serialized masked payload occurrences,
opened salts and indices, exact PCG/VOLE values and consumption, leaf digests,
root, multiproof,
handles/corrections, correlation schedule digest, transcript after every
frame, challenge sequence, both Fp2 limbs, terminal settlement, certificate,
CPU-verifier result and journal transition.  Tiny conformance fixtures compare
any additional internal values directly; production reports retain only
domain-separated digests and counters for material not already serialized.
Thread/block order cannot alter
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
against unknown cryptography.  Policy 3 receives a **NO-GO**; R0.6 later
activates policy 2 without erasing any of these rejection reasons.

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

### 5.6 R0.6 public leaf and setup screen

The preferred policy-2 leaf candidate is

```text
d_i = BLAKE3(
  domain || root_context || geometry || i
  || masked_ZK_code_payload_i || salt_i).
```

The verifier receives the masked payload and 256-bit `salt_i`, recomputes the
leaf and exact multiproof publicly, and never receives the terminal weight
evaluation.  The leaf digest itself need not be serialized when recomputable.
BLAKE3 removes the historical 8,400 secret multiplications per Poseidon2 leaf
and its private trace checker.  It does not remove salt bytes, path bytes,
root-hiding, binding or adaptive encoding privacy.  SHA-256/BLAKE2 add no
missing property; Poseidon2 is retained only if a future admitted protocol
must hash inside an arithmetic proof.

Setup is screened independently from query privacy and wire bytes.  For an
illustrative randomized codeword of `M=c_eff*N` Fp symbols, a compact 32-byte
digest tree, `g=141`, and packed i16 source, the digest-only floor is

```text
A_setup ~= 1 + 32*c_eff/141,
c_eff = c0*(1+t/N)                 # only for append-t-symbol ZK encodings

target 2.00: c_eff <= 4.40625
hard   2.10: c_eff <= 4.846875.
```

For `c0=4.4`, the illustrative bounds are `t/N<=1/704` at target and
`t/N<=13/128` at the hard tolerance.  On GPT-2 these correspond to floors of
176,136 and 12,593,750 extra symbols before metadata.  If, purely as a unit
check, `q_attempt=830` consumed the same scalar units, the corresponding
root lives would be at most 212 and 15,173 attempts.  These are not selected
`Q_root/R_root` values: ERA's alphabet, masking and interleaving are not
compiled, and one logical query may expose many Fp symbols.  The calculation
exists to prevent a privacy budget from silently buying an X4d-sized setup.

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
verifier/prover-time parameter.  For each candidate and model, first compile
plane/root/round-tagged entries and their aggregate attempt and
accepted-response vectors

```text
q_attempt[p]  = (U_leaf, S_visible_Fp, H_sibling)
q_response[p] = (U_leaf, S_visible_Fp, H_sibling),
q_response[p] <= q_attempt[p] componentwise,
p in {W,B,KV_old,KV_new}; A_attempt=1.
```

`q_attempt` is fixed by the public schedule and reserved before any
attempt-local provider response byte whose distribution depends on `W` or its
root; `q_response` is the actual accepted census.  Both retain
per-root and per-round detail.  `S_visible_Fp` counts occurrences, including
overfetch and padding in every opened 141-symbol leaf; Fp2 counts twice.
`H_sibling` counts exact digests, not field leakage.  Aborted prefixes are
also measured, but the global privacy allocator conservatively burns the full
reserved worst case with no refund or cross-attempt deduplication.

Separately record:

- `q_open[c,r]`, the logical PCS samples before alphabet/leaf unstacking;
- `Q_root`, the theorem-backed lifetime privacy capacity in its exact query
  atom, and `R_root<=floor(Q_root/u_W)` for the fixed weight-plane charge;
- `Q_B[a]`, the per-attempt response-plane horizon, and `Q_KV[s]`, the
  per-created-K/V-root horizon covering proposed-successor disclosure plus
  every predecessor reuse if that same root is accepted;
- `Q_CR`, `Q_hide` and `Q_PRF`, respectively the collision/binding,
  adaptive root/path-hiding and mask/salt-PRF reduction work bounds, all
  indexed by the complete `omega` and composed across `K_model`;
- `Q_FS`, adversarial transcript-hash queries, fixed to zero in the selected
  interactive protocol.

None of these is automatically a certificate byte count, bounded by the
connection `R_max`, or interchangeable.  A single scalar counter is admitted
only when a joint theorem supplies worst-case class weights.

Admission is the conjunction, never one optimized minimum:

```text
q_sound_min(theta,N) <= q_attempt(theta,N)
B_query_wire(theta,N,q_attempt) <= B_weight_ALFC_limit(N)
R_root*u_W <= Q_root <= t_ZK(theta)
q_B_attempt[a] <= Q_B[a] <= t_ZK_B(theta)
q_KV_create[s] + sum_(accepted predecessor reuses of s) q_KV_use
  <= Q_KV[s] <= t_ZK_KV(theta)
Setup_bytes/time(theta,N,Q_root) <= setup_limit(N)
Work_attempt(theta,N,q_attempt) <= one_scan_and_memory_limits.
```

In the following weight sub-ledger, `c` ranges only over auxiliary
weight-oracle commitments/round roots below top-level `C_W`.  Boundary/K/V
query payload/path bytes are reconciled separately into
`B_boundary_commitments` and `B_state` under their `Q_B/Q_KV` horizons.  The
four top-level root bytes (`C_W`, `C_B,e`, `C_KV,e`, `C_KV,e+1`) remain
assigned once to `B_framing`; this byte assignment does not pay their privacy
terms.

Then define

```text
q_open_weight_total = sum_(weight root c, round r) q_open[c,r]

B_query_wire
  = sum_c,r (
        S_visible_Fp[c,r] * masked_symbol_bytes
      + U_leaf[c,r] * opened_salt_bytes
      + nonrecomputable_leaf_digests[c,r] * leaf_digest_bytes
      + exact_sibling_hashes[c,r] * hash_bytes
      + index_and_query_framing_bytes[c,r])
  + B_masked_weight_oracle_IOP_messages
  + B_authenticated_terminal_adapter
  + B_aux_weight_oracle_round_roots_and_prechallenge_messages
  + B_omega_profile_and_authenticated_reservation_receipt
  + B_serialized_weight_oracle_rho.
```

`B_query_wire` is a cross-cutting sub-ledger, not a seventh certificate
category.  Every byte is assigned exactly once to one of the six registered
`B_*` components and the sub-ledger must reconcile to those assignments.  The
complete epoch/profile descriptor and reservation receipt/authentication bytes
are serialized and currently unknown.  The later plane-assignment receipt is
also serialized but is reconciled outside this weight sub-ledger exactly once
to `B_boundary_commitments`, `B_state` or `B_framing` by field ownership.
Neither receives a free framing allowance.
The
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

The leaf-size tension remains severe.  The following R0.3 table is a
historical optimistic floor using one 8-byte symbol, one full leaf, one
unshared Merkle path and **zero** bytes for salt, IOP messages or framing:
ceilings are:

| `g` | GPT-2 bytes/leaf; leaves under hard / 5% reserve | 31B bytes/leaf; leaves under hard / 5% reserve |
| ---: | ---: | ---: |
| 128 | 1,792; 1,826 / 86 | 2,016; 2,726 / 129 |
| 141 | 1,864; 1,755 / 83 | 2,120; 2,592 / 123 |
| 256 | 2,784; 1,175 / 55 | 3,008; 1,827 / 87 |

These are optimistic upper bounds, not query budgets.  Fp2 payloads, opened
256-bit salts and multiproof misses only reduce them.  Policy 2 removes the
nonlinear private checker but must serialize the masked payload itself.

Before a candidate is admissible, the same GPT-2 and 31B workload reports the
full vectors and auxiliary counters, answer alphabet/handle widths, exact multiproof nodes, round
roots, interactive challenge frames, codec bytes and total `B_query_wire`.
Those counts must parameterize
both the malicious-DV privacy theorem and the complete connection soundness
bound.
After unstacking, logical PCS samples `q_open`, ZK-alphabet query atoms,
`U_leaf` and `S_visible_Fp` in `q_attempt` must each stay within the separately
registered 5% growth tolerance from GPT-2 to 31B.  Packing or deduplication may
identify two counters only under a proved codec equivalence.  Merkle paths may
grow only while the complete byte gates pass.  This is stricter than the
generic `N^0.199` proof-law screen and forces nearly constant PCS query count
in the weight dimension.

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
2 those field elements may be visible only if they are outputs of the proved
masked encoding and fit `Q_root`; the point still cannot be copied unchanged
into `B_weight_ALFC`.  Distance amplification likewise cannot be judged by
`q_open` alone: fewer logical queries can widen each leaf and increase both
privacy leakage and certificate bytes.

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

The weight oracle is not the only persistent artifact.  The allocator manifest
separately reports bytes per reservation, boundary and K/V record; live versus
sealed counts; worst-case model-lifetime storage under `K_model`, `R_root` and
state horizons; journal writes/fsyncs; and refresh/recovery traffic.  This
state-plane ledger is not charged to `A_setup`, but it is not free storage.
Authenticated compaction may replace old records only after a proved
high-water-preserving refinement; no such compaction is currently admitted.

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
B_opened_payload  ~= U_leaf*g*b_masked.
```

Increasing `g` shrinks setup/tree storage but expands the visible masked leaf
payload and public leaf-hash work.  A hierarchy merely reintroduces the hashes
it claims to remove; neither direction receives free credit.

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
scan, nor count opened masked payloads, salts, paths or public leaf checks.
R0.4 selects logical `g=141` as the format for the authorized search, not as
setup or backend credit.  In
particular `g=128`
fails unless the complete persistent manifest, salt state and metadata fit in
32 bytes.  `g=256` requires concrete power-of-two codec necessity; larger
leaves buy setup by spending public masked-query bytes.

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
That row is a floor screen, not a constructed setup: it omits opened masked
payloads, salts/PRF and adaptive root-hiding theorems, exact tree layout and
block-regeneration algorithm.  It records why both the setup and query-byte
gates are required before selecting a leaf size.

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

Under active policy 2, root exhaustion may require rotation even when the
model does not change.  Every rotation therefore charges full root
construction, validation, storage, refresh traffic and atomic cutover; it also
needs an independent mask/salt seed and a proved bridge to the same canonical
weights.  The rotation ledger separately reports `RotateSameW` proof bytes,
verification work, privacy/KS error and outstanding-receipt resolution; none
is amortized into a response certificate without an explicit allocation.
Neither `Q_root` nor a new root is free setup.  Response trace
storage is attempt-local.  The accepted K/V provider state persists only the
current canonical prefix and its commitment data; old proposed states are
deleted only after durable acceptance or recorded burn according to the
future R1 journal design.

### 6.7 Conditional security allocation

| Security item | Registered value |
| --- | ---: |
| attempts in connection horizon | `2^20` |
| root privacy budget / root attempts | `Q_root` / `R_root`, numeric values unselected; fixed full-reservation burn |
| response/state privacy horizons | per-attempt `Q_B[a]` / per-created-root `Q_KV[s]`, unselected and not paid by `Q_root`; aborted successor roots are charged then sealed |
| model root epochs | `K_model`, unselected pending multi-root composition |
| MAC/key domains over model lifetime | `D_model`, unselected; multi-user VOLE/MAC composition unproved |
| response-local event budget cap | 64; registry incomplete |
| allocation per event | `2^-110` |
| `epsilon_response` | `2^-104` |
| leaf salt screen | 256 bits; 192 bits rejected |
| active hash work bounds | `Q_CR / Q_hide / Q_PRF`, all unselected and distinct |
| historical policy-3 salt screen | `Q_leaf=2^64`; not an active theorem cap |
| challenge mode / `Q_FS` | fresh honest-DV post-prefix interactive / `0`; entropy delivery and transcript binding not instantiated |
| hash / PCG / state / framing | allocated `2^-128 / 2^-128 / 2^-120 / 2^-128`; not yet derived |
| exact `epsilon_connection` | `17592186044675 / 2^128` |
| effective connection bits | `83.99999999997877` |
| conditional strict whole-bit allocation | 83 bits |
| connection soundness/state target | at least 78 bits |
| policy-2 model-lifetime privacy target | at least 78 bits after all roots, connections and colluding verifiers; bound not derived |

The arithmetic must remain at least 78 bits after the `2^20` connection
horizon, but it
is not a protocol security result until a complete fail-closed event/hybrid
registry supplies every term and scope.  If a concrete backend needs more
than 64 local events, a larger list/degree numerator, more roots, query-scaled
hash/PCG loss or additional hybrid terms, parameters are raised and the
calculator rerun before code.

The policy-2 privacy advantage in Section 4.3 is additional and has its own
`Adv_priv_model_lifetime<=2^-78` gate.  It ranges over all roots, connections
and attempts, including counter rollback/fork and rotation terms; it cannot be
paid by this 64-event arithmetic until a concrete adaptive t-query theorem and
exact `Q_root/Q_B/Q_KV/K_model` values are registered.

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

The displayed pair bound interprets one adversarial RO trial as one paired
invocation on the same frozen prefix/grinding nonce, expanded with internal
domain separation into two independent canonical `Fp2` challenges that both
check the complete relation.  `Q_FS` counts paired trials.  Two equations
using the same challenge do not amplify; two separately queryable challenge
oracles do not inherit this formula and require a new joint bound (potentially
including a product of grinding budgets).  The declared `Q_FS` must cover the
whole grinding scope, including restored or forked transcript states.
Random-oracle programmability, XOF/domain separation, rejection sampling,
state binding and transcript-prefix binding remain named hypotheses.

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
| fixed policy-2 root lifetime | `policy2_root_lifetime_le_budget_div_reservation`; Nat accounting only |
| worst-case query-class charge | `policy2_worst_case_query_counter_dominates`; no leakage theorem |
| connection union bound/shared Delta | finite bad-set cardinality wrapper over M10; no computational-privacy claim |
| independent two-challenge counting | product-cardinality and sliced connection bounds; RO freshness/programming remain external |
| connection hybrid composition | additive advantage recurrence, conditional on the concrete per-attempt game step |
| registered 78-bit arithmetic | exact rational inequality, conditional on the incomplete event registry |
| serialized schedule refinement | opaque-handle codec round-trip only; no binding/privacy theorem |
| ideal malicious-DV privacy | existing `bsc_zeroBatch_perfect_zk` and `sequential_composition_perfect_zk`; applies only to authenticated terminal/windows after concrete codec refinement and does not cover the visible masked code |

These theorems prove no concrete PCS binding, hash/PCG security, transformer
compiler completeness, durable global allocator or malicious-DV privacy.
Section 2.4 names the prose
predicate and its hypotheses; no Lean `AcceptC7` definition yet exists.  A
future definition must expose those assumptions rather than hide them behind
an ideal ALFC API.

R0.5 added only
`c7_independent_bad_challenge_product_card_le` and
`c7_pair_challenge_connection_sliced_union_bound`.  They prove the finite
counting numerators used in Section 6.8, not Fiat--Shamir security.  Raw-tag
leakage and ideal shared-`Delta` privacy were already proved; a new
salt-counting identity would not prove adaptive hiding.  The generator
incidence obstruction and CPU/SIMT resource contract are not statements about
the frozen protocol semantics.  The historical policy-3 next statements would
have been
`serialized_private_oracle_view_refines_windows` and
`private_checker_all_opened_residuals_zero`, but adding them before an admitted
codec/checker would only rename missing cryptography.  Because the concrete
policy-3 backend is rejected, no fake `C7Policy3Codec.lean` is created.
R0.6 adds only the two natural-number policy-2 accounting lemmas above.  They
formalize fixed reservation and conservative class weighting, not atomicity,
the query atom, transcript-bound epoch receipts, multi-user `Delta`
composition, adaptive t-query privacy or root rotation.  The next active Lean
refinement waits for a concrete compiler/receipt codec; adding an abstract
wrapper now would only rename the distinct missing
`AllocatorPrivacyIntegrity`, `ReceiptUnforgeability` and single-session CAS
properties.
The focused command
`cd lean && lake build +VoltaZk.C7StatefulAlfc:olean` passes without
`sorryAx` in these C7 lemmas.

## 8. R0.6 disposition and exact resume conditions

### 8.1 Backend/control recommendation

- **Policy 2: ACTIVE FOR DESIGN; NO BACKEND GO.**  Only budgeted root-bound
  masked PCS responses may be visible; the terminal evaluation stays
  authenticated.  Numeric counters remain fail-closed and unset.
- **RS t-query ZK + strict-UD WHIR/Ligerito + salted BLAKE3: preferred theorem
  carrier, census only.**  It still lacks adaptive stateful malicious-DV
  privacy and a setup-safe, one-scan opener.
- **ERA `r=4` + salted BLAKE3: byte/prover control only.**  Its published
  field-query law grows with `log N`, its masked encoding is unproved here,
  and its N-scale setup intermediates remain excluded.
- **Historical policy-3/Poseidon2 and one-stage RA lines: terminal NO-GO.**
  Their checker cost, distance and ordered-root failures remain recorded.

### 8.2 Resume conditions for an R1 proposal

Policy 3 remains terminally rejected under the registered constraints and
policy 2 is active.  The selected challenge baseline remains interactive
honest-DV (`Q_FS=0`) and
logical `g=141`; the setup and query envelopes retain their 5% hard
tolerances.  The
fail-closed readiness handoff is
`docs/c7-r03-prover-pod-handoff.md`.  Preparation does not authorize a large
prover/E2E, pod contact or pod execution.

The next step remains a design/census checkpoint, not implementation.  Before
an R1 proposal it must supply all of:

1. exact plane-tagged GPT-2/31B `q_attempt/q_response` vectors,
   theorem-defined weight `Q_root`, response `Q_B` and state `Q_KV` horizons,
   derived `R_root`, positive privacy headroom, distinct
   `Q_CR/Q_hide/Q_PRF`, bounded `D_model`, and a bounded `K_model` or
   multi-root theorem;
2. an executable canonical compiler with terminal multiplicity exactly one
   for every physical weight, boundary and K/V segment, plus the complete
   ordered `omega`, profile and authenticated single-session
   reservation plus no-extension plane-assignment receipts, durable W/B/KV
   high-water maps and state machine;
3. a proved/checked extension-field ALFC adapter under one shared `Delta` per
   MAC domain, both serialized limbs, every allowed oracle response, and a
   multi-user composition covering all `D_model` colluding domains;
4. `C7_CPU_REFERENCE_PASS`: a derived and executable one-pass bounded-memory
   `BatchOpenBlocks` schedule with exact operations/setup/oracle/online I/O;
5. the paired-history policy-2 adaptive malicious-DV lifetime theorem with
   complete branch-derived-view closure, honest-allocator privacy integrity,
   dishonest-prover receipt unforgeability, global receipt CAS/cache
   rollback-fork protection, full burn, and a private
   `RotateSameW` bridge with stop-admit/outstanding-attempt resolution and
   atomic cutover;
6. a composed certificate/security budget replacing allocation constants
   with derived protocol counts while retaining the gates;
7. if SIMT is proposed, byte-exact CPU/SIMT equivalence and every registered
   transfer, memory, padding and synchronization counter.

The R0.5 policy-3 exhaustion remains documented in Section 5.4 and the
append-only register.  No SIMT S3, prover or pod work follows from activating
policy 2.  Interactive `Q_FS=0` is fixed; amplified FS remains quarantined.

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
- R0.6 activates policy 2 with a global root-wide fixed-reservation counter,
  separates query/privacy/setup/work gates, retains interactive `Q_FS=0`, and
  makes salted public BLAKE3 the preferred leaf candidate.  Backend, query
  atom, numeric `Q_root/R_root/K_model`, codec and prover remain unselected.
- The proof-byte table is a target allocation calibrated to public component
  evidence, not a composed certificate derivation.  It is `credit:false` and
  is one reason Backend A remains NO-GO.
- No pod, production provider, frozen forward, quantization spec, or frozen
  M1--M12 statement was touched in R0/R0.1/R0.2/R0.3/R0.4/R0.5/R0.6.

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
| `C7-D037` / 2026-08-26 | activate policy 2; retain policy-3 terminal record | Owner activates bounded masked PCS responses while the terminal evaluation remains VOLE-authenticated. This supersedes D011/D032 only as the active line; it does not erase why private-checker policy 3 failed or authorize a backend/prover. |
| `C7-D038` / 2026-08-26 | separate query, privacy, setup and work quantities | `q_attempt`, `q_response`, `Q_root` and `R_root` have different roles and cannot be collapsed into one minimum. The authoritative attempt census distinguishes unique leaves, visible masked Fp occurrences, exact sibling digests and attempts; Fp2 counts twice and a full g141 leaf counts all 141 symbols. |
| `C7-D039` / 2026-08-26 | require global fixed reservation and bounded rotation | Before any attempt-local provider response byte dependent on `W`/root, a linearizable global allocator reserves and burns the full `q_attempt_privacy_units` and declared census profile on accept, abort, timeout, crash or retry, across users/connections/colluding verifiers. The public root is a baseline view element whose replacement is charged to root hiding. Rate limits and user quotas mitigate DoS only. Root exhaustion seals the root; rotation needs independent randomness, same-W bridge, counted setup/cutover and `K_model` or a multi-root theorem. |
| `C7-D040` / 2026-08-26 | retain interactive challenges | Policy 2 does not reopen the Fiat--Shamir decision. Fresh post-prefix interactive challenges remain selected with `Q_FS=0`; amplified FS stays quarantined because its second responses, paths, MACs, scans and bytes are uncompiled. |
| `C7-D041` / 2026-08-26 | prefer salted public BLAKE3 under policy 2 | Because masked queried payloads and salts are visible, the verifier can recompute leaves/paths publicly and the Poseidon2 private checker is unnecessary. BLAKE3 collision resistance still does not prove randomized-root hiding, adaptive t-query privacy or position binding; 256-bit salts and those named hypotheses remain. Poseidon2 is historical/inside-circuit control only. |
| `C7-D042` / 2026-08-26 | require nearly constant normalized PCS queries | Before comparison, grouped and N-dependent alphabet queries are unstacked to logical g141 leaves and Fp limbs. GPT-2 to 31B `U_leaf` and visible-symbol attempt caps may not grow beyond the separately recorded 5% hard tolerance; paths may grow only if exact proof bytes pass. ERA's published O(lambda log N) coordinate law fails this strict gate absent a different compiled counter. |
| `C7-D043` / 2026-08-26 | narrow R0.6 to two analytic lines | RS t-query ZK plus strict-UD WHIR/Ligerito is retained only as the best security/privacy theorem carrier; ERA r=4 is retained only as byte/prover control. Neither has the joint adaptive stateful theorem, ordered root-only setup and one-scan bounded opener, so neither receives implementation GO. The setup screen remains 2.00 target/2.10 hard and forbids X4d-style expanded planes. |
| `C7-D044` / 2026-08-26 | separate model-lifetime privacy from connection arithmetic | The global policy-2 adversary spans roots, connections and colluding verifiers, so an 83-bit conditional connection union bound alone is insufficient. Admission separately requires `Adv_priv_model_lifetime(K_model,D_model,Q_root,Q_hide,Q_PRF)<=2^-78`; its parameters and bound are not derived yet. |
| `C7-D045` / 2026-08-26 | bind the complete weight-oracle epoch and reservation receipt | `Q_root` applies to immutable `C_W` plus the complete ordered auxiliary randomized-root set, encoding parameters and profile, not to a convenient root name. Replacing any member creates a new `omega` and consumes `K_model`. A globally authenticated reservation receipt and spend high-water enter `x_e`, the frozen transcript prefix and the journal; otherwise auxiliary-root churn could reset accounting. |
| `C7-D046` / 2026-08-26 | require paired-history and multi-user malicious-DV composition | Public prompts, outputs, lengths and abort class are authorized leakage and must match in an operational paired-history query; branch roots are challenger-generated view elements paid by hiding. The existing Lean VOLE simulator covers one connection key domain/shared `Delta`, not colluding domains. `D_model` and a domain-separated `MultiUserVoleCompose` theorem are therefore hard stops. |
| `C7-D047` / 2026-08-26 | separate hash-reduction work bounds | Collision binding, adaptive root/path hiding and mask/salt PRF security use distinct `Q_CR`, `Q_hide` and `Q_PRF` bounds composed across `K_model`. The historical `Q_leaf` salt screen cannot stand in for any of them or for `Q_root`; all active values remain unset pending a concrete codec/reduction. |
| `C7-D048` / 2026-08-26 | make rotation a private stop-admit protocol | Exhaustion never triggers an unchecked root swap. Rotation seals new admissions, completes or burns every outstanding receipt, knowledge-binds both full oracle epochs to immutable `C_W`, charges malicious-DV bridge privacy plus all proof/setup bytes, and only then atomically cuts over. Old roots become verify-only. |
| `C7-D049` / 2026-08-26 | scope the quarantined amplified-FS screen to paired trials | The `Q_FS*T^2/|Fp2|^2` control applies only when one RO trial on one frozen prefix yields a domain-separated challenge pair and `Q_FS` counts such pairs. Separately queryable challenge oracles may incur a product grinding budget and need a new proof. Interactive `Q_FS=0` remains selected. |
| `C7-D050` / 2026-08-26 | make reservation receipts stateful and single-session | A unique receipt alone does not stop replica replay under fresh challenges. The allocator binds the complete connection/nonce/MAC-domain session and enforces `Reserved -> InFlight -> Burned | Accepted`; exact duplicate inputs may receive only cached byte-identical replies and divergent inputs fail before new witness-dependent bytes. |
| `C7-D051` / 2026-08-26 | close paired-history leakage under branch-derived values | Requiring equal root-derived IDs, receipt authenticators or transcript/journal heads would make the two-world game impossible. Only the witness-independent base frame is equal; the challenger constructs the complete branch-derived closure and a named reduction pays for its indistinguishability. |
| `C7-D052` / 2026-08-26 | separate weight, boundary and K/V privacy horizons | `Q_root` pays only for the complete weight-oracle epoch. Fresh response roots use per-attempt `Q_B[a]`; persistent accepted K/V roots use per-state `Q_KV[e]` across retries. A backend may claim zero visible-query charge only from its concrete authenticated-only codec and hiding theorem. |
| `C7-D053` / 2026-08-26 | separate local MAC error, multi-user composition and allocator trust | Soundness sums per-domain MAC error once and then adds one `MultiUserMacCompose(D_model)` term. Privacy assumes an honest allocator with integrity; dishonest-prover soundness separately requires receipt unforgeability. One generic receipt hypothesis cannot discharge both scopes. |
| `C7-D054` / 2026-08-26 | update the CPU/SIMT byte contract to active policy 2 | The policy-3 provider-internal leaf/salt contract is superseded. CPU and later SIMT must emit and match the exact serialized masked payload occurrences, opened salts, public paths and authenticated-only terminal; otherwise a stale policy-3 preflight could falsely satisfy the active resume condition. |
| `C7-D055` / 2026-08-26 | charge every proposed K/V root, including aborted successors | D052's accepted-state wording omitted a successor root already shown before promotion. Every created K/V root instance now receives a creation charge; abort/reject seals it, while acceptance preserves the same `Q_KV[s]` counter for later predecessor reuse. This prevents selective abort from creating uncounted state-root views. |
| `C7-D056` / 2026-08-26 | remove receipt self-reference and cache before disclosure | A receipt cannot authenticate `reserved_session_binding` if that value already contains the receipt. The allocator instead authenticates a receipt-free `reservation_request_binding`; appending the receipt derives the session binding. The provider transitions the internal record to `InFlight` and caches the complete first reply before emitting receipt/seed commitment, closing the root-dependent first-byte race without an exemption. |
| `C7-D057` / 2026-08-26 | make every plane charge enforceable in durable state | Merely adding `Q_B/Q_KV` to a union bound left them absent from the relation and allocator. The fixed profile/receipt now binds separate W/B/KV charges: W and predecessor K/V debit existing maps, boundary/successor charges burn into nonrefundable slots, and a no-extension CAS assigns those slots to the new roots before disclosure. Abort seals them; acceptance preserves the successor high-water. This prevents `Q_root` from silently paying other planes. |
| `C7-D058` / 2026-08-26 | keep state budgets outside weight-root rotation | An initial accepted K/V root had no map to debit, and placing K/V maps inside `omega` would let `RotateSameW` reset their capacity. `InitKVState(s0)` now creates and charges genesis before disclosure. The state-plane ledger and all K/V high-waters persist byte-identically across weight rotation; only the weight-epoch counter is fresh. |
| `C7-D059` / 2026-08-26 | apply the 5% query-growth gate before every packing layer | D042 constrained leaves and visible Fp occurrences but left logical PCS samples and ZK-alphabet atoms unchecked. All four normalized counts must independently remain within 1.05 from GPT-2 to 31B unless a proved codec equivalence identifies them. This prevents constant leaf payload from hiding a model-growing internal query schedule. |

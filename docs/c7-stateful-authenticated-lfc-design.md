# C7 — stateful authenticated linear-functional commitment

**Status:** C7 R0.8g bounded direct-Bolt screen; policy 2, direct Goldilocks Fp3, rate 1/2,
`k0=4`, one packed weight root, logical `g=141` and interactive `Q_FS=0`
remain fixed.  R0.8a makes published constructions exact-cost
baselines/controls and a new co-designed C7 shared circuit the main research
line.  Strict-UD RS is an algebraic/security control whose prover must not be
implemented.  The carrier-independent Rust reference now includes the Fp3
terminal, frozen BLAKE3-XOF addressing, public BLAKE3 leaf/tree, one-leaf
codec, nonrefundable query counter and in-memory KV CAS. It is not a
PCS/PCG/VOLE refinement or durable allocator. `C7-SPBT-v0` remains a valid
algebraic reduction, but its carrier line is closed: the last native
`StreamOpenIntoMac` screen needs linear online corrections or forbidden
preprocessing. The authorized one-candidate tournament then screened a direct
packed `Bolt-min` code switch rather than rebuilding C6's WHIR wrapper. Its
source-linear term is independent of `q` and its optimistic persistent bytes
fit 3x, but its layout needs model-linear setup state or excessive query wire,
and every response creates a fresh complete Fp3 RS word. It is NO-GO; the
bounded tournament is closed and C7 is blocked until a named candidate earns
a new owner decision.
`C7-DV-SPQ-v0` remains a quarantined terminal primitive. No carrier has a complete row or
`BatchOpenBlocks` CPU-prototype authorization. BLAKE3-XOF remains the primary
performance/parallelism mask candidate; frozen KMACXOF256-v1 remains an
unpromoted high-margin control.  The approved privacy allocation is not
theorem discharge.  Policy 3 remains terminal.  No SIMT, prover, E2E or pod.
This document is the task-specific authority named by `prototype-status.md`.

Volta-ZK is a stateful designated-verifier proof architecture for
private-weight autoregressive inference. Like modern public zkML systems, it
certifies an entire causal response without re-proving every decoding prefix.
Unlike them, Volta keeps transformer boundaries and committed-weight
evaluations authenticated under a session VOLE-MAC, performs one batched PCS
opening into that MAC per response, and binds each response to an append-only
authenticated KV-cache transition.

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

R0.8 retains the owner's latest 1.A/2.A/3.B choices, the R0.5 terminal policy-3
record and R0.6 bounded-query policy 2, carries forward the allocator
authority and Pareto-before-caps order with interactive challenges, closes
the two bounded post-Pareto alternatives, and audits the retained Fp2 schedule
before any field change.  Its required output is the canonical codec plus
security, serialized bytes and resource row; R0.8 is not an implementation GO.

1. The immutable model, response trace and persistent cache are separate
   commitment planes.  "One opening" means one transcript-bound
   multi-commitment ALFC invocation, not one literal Merkle root.
2. Every physical packed segment has **exactly one** operator-reduced terminal
   point before the ALFC batching challenge.  This is the only admitted
   resolution of the `O(KN)` packed-functional hard stop.
3. The active static-weight statement is policy 2: **only root-bound masked
   PCS responses within a durable global budget are visible; the terminal
   evaluation remains VOLE-authenticated and is never cleartext**.  This is
   design authority only.  The Fp3 g141 opening subcodec has an exact
   conservative census, but the complete codec and executable backend remain
   open.  Numeric `Q_root/R_root/K_model` are selected only for the separately
   labelled fallback variant below, not for the main line.
   Root masks use one fresh private 256-bit seed per root epoch and a
   domain-separated addressed PRG/PCG.  Privacy is computational and its
   multi-root advantage is charged once in the 78-bit model-lifetime bound.
   Uniform persisted coefficients remain a baseline, not the main line.
4. Policy 3 is terminally rejected under the registered gates, with every
   reason retained in the append-only register.  Its Poseidon2/private-checker
   work is historical control evidence, not a requirement of policy 2.
   RS t-query ZK plus strict-UD Ligerito/WHIR is retained only as an
   algebraic/security control baseline.  Its current realization is not the
   selected theorem carrier and its prover must not be implemented.  ERA
   `r=4` remains only a byte/prover control.
5. Persistent setup keeps `A_setup <= 2.00` as target and `<=2.10` as the
   baseline tolerance.  A separate exploratory ceiling near `3.00x` is
   registered, but it passes only with absolute persistent-disk, setup-wall
   and refresh-wall caps fixed before measurement.  X4d-scale expansion and
   uncounted/model-sized temporary storage remain forbidden.
6. Weight-oracle `B_query_wire` (the interactive successor to the historical
   `B_query_FS` label) is included inside `B_weight_ALFC`, never added as a
   seventh component.  The 105% value is now the target, not an immediate hard
   stop.  An exact exploratory cap may be preregistered inside 125--150% only
   if the complete certificate also stays within 35/115 MB and 3.5x growth.
7. The historical authorized tiny CPU screen and the bounded R0.8g Bolt screen
   are complete.  Their source-linear pieces work, but neither supplies a
   complete admitted relation/resource/security row, so
   `C7_CPU_REFERENCE_PASS=false`.  No executable-backend implementation, large-prover/E2E,
   provider or pod action is authorized.
8. No current backend passes setup, domain support, one-pass opening, all four
   normalized query counts, proof bytes and stateful malicious-DV privacy
   together.  Logical `g=141` remains fixed; every grouped/alphabet query is
   unstacked into this format and Fp2 counts as two Fp limbs before admission.
   The active 1.30 query-growth ceiling is componentwise and does not transfer
   slack to proof wire, setup, certificate or security.  Their distinct
   exploratory envelopes still require every conjunctive cap.
9. Policy 2 selects a public salted BLAKE3 leaf/tree check because the masked
   queried payload and its salt are visible.  This removes the private
   Poseidon2 checker; it does not prove randomized-encoding root hiding,
   adaptive t-query privacy or cross-root composition.  BLAKE3 collision and
   position binding remain named assumptions, distinct from root hiding.  The
   256-bit salt screen remains; Poseidon2 is quarantined as
   a historical policy-3/inside-circuit control.
10. Fresh honest-DV `rho_i`, `beta` and `gamma`, each sampled after its exact
    committed prefix and serialized in the durable transcript, are selected.
    The selected protocol uses no Fiat--Shamir oracle (`Q_FS=0`); FS remains
    quarantined, not a dormant uncounted transform.
11. No optimized SIMT kernel or GPU scaffold may exist: the historical executable CPU
    screen proves the online cost identity but does not pass the PCS distance
    and setup gates.
12. After that checkpoint, SIMT may accelerate only streaming setup,
    `LeafCom`/Merkle, PCG/VOLE, MAC, selected Fp/Fp2/Fp3 arithmetic, leaf checks and reductions.  It
    must remain byte-identical to CPU and may not add a codeword, model-sized
    scratch, second scan, `qN`, unassigned traffic or transcript difference.
    Logical `g=141` never changes; any wider device tile is temporary measured
    zero padding excluded from commitments, certificate and transcript.
13. Direct sparse-coordinate regeneration remains rejected by the
    generator-incidence argument.  The explicit one-stage RA shared circuit
    removes `qN` online work but fails the independent distance/root gates;
    the tiny search is closed.
14. The global allocator authority is the model owner/provider.  Privacy is
    conditioned on an honest linearizable durable allocator; authenticated
    receipts protect soundness against a dishonest proof worker, not against a
    corrupt allocator.
15. Mainline numeric `Q_root`, `R_root`, `K_model` and `D_model` remain unset
    until a complete non-scalar Pareto table exists.  The separately labelled
    BLAKE3 fallback alone pins the numeric root profile and `K_model` below;
    its other cells remain fail-closed.  No setup, proof-size, privacy or
    service-life tolerance is transferable between the two lines.
16. Setup-wall targets/hard caps are 900/990 seconds for GPT-2 and
    5,400/5,940 seconds for the 31B envelope.  Refresh has distinct counters
    with the same initial numeric target/cap and no budget transfer.  R0.8 does
    not test or credit refresh; its caps remain registered for later work.

The following are terminal R0 hard stops.  Until all are discharged there is
no large prover implementation, production equivalence claim, provider/pod
contact, or proof/time/memory credit:

- a concrete compiler census must show one terminal point per physical
  segment; any segment with multiplicity `K_i > 1` reopens the `sum K_i N_i`
  stop;
- any newly selected code/commitment composition must have a proved,
  executable one-pass bounded-memory schedule, with exact read/write traffic
  and no expanded resident extension-field weight wrapper;
- the CPU reference must derive
  `C(N,q,h)=c_source*N+P(q,h)` with `c_source` independent of `q`, and
  `M<=chunk+M_fixed+P_M(q,h)`; timing sweeps alone cannot discharge this stop;
- SIMT work is blocked until the ledger records `C7_CPU_REFERENCE_PASS`.
  Afterwards any second packed read, complete codeword, model-sized scratch,
  `qN` source work, unmetered host/device traffic, unclassified barrier or
  CPU/SIMT transcript mismatch is terminal for that implementation;
- the authenticated terminal must operate in the selected extension
  `E=F_{p^d}` under one shared `Delta`: `d=2` during the bounded audit and
  `d=3` on its selected fallback.  All `d` serialized Fp limbs must be checked
  without replacing extension multiplication by independent base-field MACs;
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
- query-miss and algebraic/proximity-gap errors must each meet the registered
  per-response reserve before lifetime composition.  Current unamplified Fp2
  controls do not; no Fiat--Shamir grinding credit transfers into interactive
  `Q_FS=0`;
- a weight oracle may persist only the canonical packed weights plus the
  candidate's fully counted root/index/metadata inside `A_setup<=2.00`
  (hard `2.10`).  Expanded extension-field copies, per-coordinate authentication,
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
8-byte `F_p` values.  The audit baseline uses `F_{p^2}` and carries both
base-field limbs.  If the bounded audit fails, D071--D072 select `F_{p^3}` and
three canonical base-field limbs; this conditional row is not admitted until
its field, codec, MAC and privacy bridge pass.  The field identifier and basis
are fixed in the transcript prefix, so one epoch cannot mix the two modes.

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
atom, plane-tagged fixed attempt and init/rotation charge vectors, `Q_root`,
`Q_B`, `Q_KV`, lifecycle-attempt caps and rotation policy.  Its
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
 root_lifecycle_reserve, root_lifecycle_high_water,
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
  (root_budget_id, profile_digest, Q_root,
   u_init, u_rotate_in, u_rotate_out,
   service_spent, lifecycle_reserved, lifecycle_spent,
   candidate_status, sealed)

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
  terminal values, extension-field authenticated shares/tags, the selected
  two- or three-limb serialization witness, and the exact one-time VOLE correlations/masks
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
   high-water marks are consecutive within `Q_root` after preserving the
   authenticated init/rotation reserve; predecessor marks are within the
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
   extension-field MAC residuals to zero; all `d` serialized coordinates check,
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

For the transcript-selected `E=F_{p^d}=F_p[u]/f_d(u)`, write
`v=sum_(ell<d) v_ell*u^ell`.  The terminal is one authenticated value over `E`
with one connection-scoped `Delta in E`.  Its canonical codec has exactly `d`
`F_p` coordinates and must check all of them, but those coordinates are not
independent MAC fields: extension multiplication includes cross-limb terms.
The audit row has `d=2`; if its bound fails, the selected fallback has `d=3`.
Each coordinate costs one 8-byte correction.  The concrete irreducible
polynomial/basis, correlation construction and wire codec remain hard stops,
and the provisional two-limb `B_MAC` allocation must be recomputed for Fp3.
Direct per-cell corrections are forbidden.

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
`beta in E` and set `beta_i = beta^(ordinal_i+1)`; this exact
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
   `W[j] * beta_i * eq(...)` into all `d` Fp limbs;
4. never materialize `L` or an expanded extension-field copy of `W`.

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
        |                 one E=Fp^d MAC settlement (d=2 audit / d=3 fallback)
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
With the selected Fp3 field and fixed-prefix bad-set cap `T=512`, the separate
challenge-mode screen is:

| Mode | Bound for the fixed prefix | effective bits | selected |
| --- | --- | ---: | --- |
| interactive | `T/|Fp3|` | 183.000 | yes |
| direct FS, `Q_FS=2^64` | `Q_FS*T/|Fp3|` | 119.000 | no |
| paired FS amplification | `Q_FS*T^2/|Fp3|^2` | 302.000 | no |

The interactive row serializes 24 bytes per Fp3 draw.  Direct FS removes
those draw bytes but must define whether `Q_FS` is per attempt, connection or
model lifetime and still pays nonce/framing/hash work; the connection union
and every other event remain separate.  Paired FS is not a free 302-bit row:
it needs one frozen paired-RO prefix, two independent Fp3 challenges checking
the same relation, and exact duplicate/shared response, path, MAC, scan and
wire accounting.  Its proof-size/resource gate is false.  Neither FS form
changes malicious-DV privacy or the root query budget.  R0.8 therefore retains
`Q_FS=0`; reintroducing FS changes the statement and needs a later owner
decision.

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

Weight-epoch setup and rotation have distinct censuses in the same units:

```text
q_init[omega]
q_rotate_out[omega,j]
q_rotate_in[omega',j]
```

They count every disclosed setup-validation or bridge prefix, including
failed/aborted attempt `j`.  A zero vector is legal only if a concrete
authenticated-only codec theorem proves that setup/bridge reveals no masked
PCS payload or path.

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
u_lifecycle = (u_init, u_rotate_in, u_rotate_out).
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
R_root      maximum response-attempt reservations before that omega is sealed

F_omega = u_init
        + A_rotate_in*u_rotate_in
        + A_rotate_out*u_rotate_out

F_omega + R_root*u_W <= Q_root
R_root <= floor((Q_root-F_omega)/u_W).
```

This formula is admitted only with
`0 < u_W <= Q_root`, `F_omega<=Q_root` and fixed finite setup/rotation-attempt
caps.  Each nonzero plane charge must likewise fit its named `Q_B`/`Q_KV`
horizon, and a profile that cannot reserve its lifecycle plus one complete
response is invalid.  The allocator preserves the unspent lifecycle reserve
rather than consuming it as service headroom.  If the privacy theorem keeps a
vector of correlated-component loads, every displayed inequality is
componentwise; no scalar projection may hide a saturated component.

For the model-lifetime game the allocator must establish

```text
L_W[omega] = u_init[omega]
            + sum_(reserved responses a using omega) u_W[a]
            + sum_(rotation attempts j entering omega) u_rotate_in[omega,j]
            + sum_(rotation attempts j leaving omega) u_rotate_out[omega,j]
            <= Q_root[omega]
L_B[a]     = u_B[a] <= Q_B[a]
L_KV[s]    = u_create[s] + sum_(reserved predecessor uses a of s) u_KV_old[a]
             <= Q_KV[s]

|A_model|    <= sum_omega R_root[omega]
|Omega_disclosed_candidates| <= K_model
|rotation_attempts_with_W_dependent_bytes| <= K_model-1
|B_created|  <= |A_model|
|KV_created| <= 1+|A_model|
|domains|    <= D_model.
```

Here `domains` is the union of every connection/MAC key-tape domain
instantiated anywhere in the model/state lifecycle: weight or K/V setup/init,
response, or `RotateSameW` bridge, including failed and aborted attempts.  Its
per-domain load `J_d` includes all correlations reserved or consumed by those
phases.  A lifecycle phase may be omitted from this union only under a
concrete codec theorem that it creates no VOLE/MAC domain and consumes no
correlation; its PCS/root leakage remains charged by `u_init/u_rotate_*`.

The state-plane counters persist across weight rotation.  These are symbolic
admission relations, not selected numeric service levels.

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
before answering; service admission also checks that all preregistered
`u_rotate_out` reserve remains available.  The record is global to the root across users,
connections, replicas and colluding designated verifiers.  Per-user quotas
and rate limits may run before it to mitigate denial of service, but they are
not cryptographic counters.

Likewise, the allocator reserves `u_init` before the first W-dependent setup
validation byte and reserves both `u_rotate_out` on the old epoch and
`u_rotate_in` on the candidate epoch before the first bridge/root-dependent
byte.  Abort, failure or retry burns those full reservations.  A disclosed
candidate is sealed and consumes one `K_model` epoch even if it is never
activated; a retry uses fresh encoding randomness, counters and candidate
index.  If either lifecycle charge is claimed zero, the transcript must be
covered by the named authenticated-only zero-visible-query theorem.

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
Q_hide,Q_saltPRF,{Q_mask_words},interactive)` is the active
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

The smallest new theorem is
`C7-OnlineMDVViewRefine(backend,codec,omega)`: every legal adaptive
byte-prefix transcript, including malicious challenges and selective aborts,
must factor through a bounded adaptive RS oracle plus the simulator for the
authenticated-only terminal.  For every plane `p`, root component `c` and
legal prefix `T`, the compiler supplies

```text
S_p(T)          every witness-dependent Fp occurrence disclosed by codec(T)
load[p,c,T]     coordinate queries made to RS masking component c

CapFp(p,r) = max q such that
  S_p(T) <= q -> load[p,c,T] <= t[p,c] for all legal T and every c.
```

The selected extension contributes `d` Fp occurrences (`d=2` for the audit,
`d=3` for the fallback), and a complete logical leaf contributes 141.
Without a proved codec/load identity, `CapFp` is the worst correlated
component capacity: one query to an interleaved `Sigma^(2^k)` alphabet is not
one Fp query.  Proposition 3.19 of 2026/391 gives fixed-set RS t-query privacy
with error zero, but its composition class is explicitly non-adaptive and its
result is HVZK.  It does not prove this online stateful refinement.

That proposition also fixes a non-negotiable capacity cost: for
`RS[F,L,ell]`, perfect privacy for `t` queried locations uses message length
`ell-t` and randomness length exactly `t`.  With `W` canonical base-field
message coefficients, C7 therefore needs `ell >= W+t`; at rate 1/2 the oracle
contains `2*ell` base-field symbols.  The current `S_visible_Fp` reservation is
a conservative scalar charge, not yet an equality with the paper's alphabet
query unit: Claim 3.23 preserves `t` interleaved alphabet queries while one
answer contains `2^k` base symbols.  Section 6.6 screens the resulting
power-of-two geometry.  It proves that `R_root=R_max` is incompatible with the
setup cap, but does not admit `Q_root` or `R_root` before the codec load map,
adaptive refinement, lifecycle reserve and concrete mask-generator bound are
complete.

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

Let `D_model` bound the union of distinct connection/MAC key domains created
anywhere in the model/state lifetime: weight or K/V setup/init validation,
ordinary response attempts and inbound/outbound `RotateSameW` bridges,
including failed or aborted lifecycle attempts.  Each domain fixes one
`Delta` and complete indexed key-tape domain before its first W-dependent
byte.  The adversary may correlate `Delta` and key functions across domains;
provider-side coins/masks are fresh and domain-separated.  `J_d` counts every
correlation reserved or consumed in all those phases, including burned
suffixes.  `D_model` is bounded by the global reservation journal, not by
accepted responses or user identity.  A concrete init/bridge codec may avoid
adding a domain only by proving that it creates no VOLE/MAC domain and consumes
zero correlations; its visible PCS leakage is still charged separately.  The existing
Lean simulator covers one domain with one shared `Delta`; C7 additionally
requires a named `MultiUserVoleCompose(D_model)` hybrid theorem.  Colluding
verifiers cannot be charged to the single-connection theorem.

`Q_root` applies only to one complete weight-oracle epoch `omega`, including
its typed init/inbound/outbound lifecycle charges.  `Omega` contains every
candidate whose root or other W-dependent byte was disclosed, not merely
epochs that reached activation.  It does not silently pay for the fresh
response and persistent state planes.  A concrete compiler must additionally instantiate:

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

With `eps_RV^p(r,q)` defined by

```text
eps_RV^p(r,q)
  = eps_OnlineMDVViewRefine^p(r,q)
  + zeta_RS_adapt^p(r,q)
  + Adv_SaltPRF^p_r(Q_saltPRF[r])
  + Adv_BLAKE3_RootPathHide^p_r(Q_hide[r]),
```

the required lifetime bound is

```text
Adv_priv_model
 <= sum_(omega in Omega) eps_RV^W(omega,Q_root[omega])
  + sum_(a in B_created) eps_RV^B(a,Q_B[a])
  + sum_(s in KV_created) eps_RV^KV(s,Q_KV[s])
  + Adv_RootMaskPRG_multi(K_model,{Q_mask_words[omega]})
  + K_seed_attempts * epsilon_mask_rejection
  + Adv_MultiUserVOLE_MDV(D_model,{J_d})
  + sum_domain Adv_PCG_d(Q_PCG[d])
  + sum_attempt (epsilon_terminal_codec_a + epsilon_timing_class_a)
  + sum_(every accepted/failed/aborted rotation attempt j)
      epsilon_RotateSameW_priv_j
  + epsilon_BranchDerivedViewClosure
  + epsilon_state_codec_carry.
```

`MultiUserVOLE_MDV` owns the domain composition once; a second per-domain
union term is not added unless its eventual theorem exposes one.  If all
branch-derived receipts and heads are canonical witness-independent
post-processing of already simulated roots/state, data processing makes the
branch-closure term zero; otherwise it stays explicit.  Under the
owner-selected `AllocOK` trust boundary, allocator failure is a premise, not a
cryptographic advantage term.  A concrete implementation theorem may add
`Pr[not AllocOK]`; receipts cannot repair a corrupt or forkable allocator.

Admission additionally requires the composed model-lifetime game—not merely
one connection slice—to satisfy

```text
Adv_priv_model_lifetime(K_model,D_model,Q_root,u_init,u_rotate_in,
                        u_rotate_out,{Q_B},{Q_KV},Q_hide,Q_saltPRF,
                        {Q_mask_words})
  <= 2^-78.
```

There is no honest-challenge term in this privacy game; honest post-prefix
unpredictability is a soundness premise.  The existing ideal shared-`Delta`
VOLE-MAC simulator can discharge one domain's terminal middle only after a
concrete codec refinement.  It neither simulates the visible PCS encoding nor
proves the multi-domain hybrid.

The selected public leaf/tree function is BLAKE3 with separate domains for
leaf, tree and transcript hashing.  An opened masked payload and 256-bit salt
let the verifier recompute its leaf and path, so no private Poseidon2 checker
is required.  Collision resistance still proves neither root hiding nor
adaptive t-query privacy; `SaltedMerkleRootPathHide`, randomized-encoding
privacy and position/geometry binding remain named hypotheses.

The active hash reductions use three non-interchangeable work bounds:

```text
Q_CR[root]    collision/binding work against leaf/tree hashing
Q_hide[root]  adaptive root/path-hiding oracle work and cumulative view
Q_saltPRF[root]       salt-derivation PRF work
Q_mask_words[root]    addressed root-mask generator words, including failed setup seeds
```

The concrete reductions must derive these from `K_model`, every `omega`, the
opened-leaf/path union and the adversary's declared oracle access.  Root-mask
PRG, salt PRF and VOLE PCG are distinct hybrids and are counted once each.
They are not `q_attempt`, `Q_root`, each other, or the historical policy-3
`Q_leaf`.

The owner selects a **computational seeded root mask** as the main line.  Each
disclosed candidate root samples one fresh private 256-bit seed; the same seed
defines that root's randomized encoding for its entire bounded lifetime and is
never serialized in a response.  There is no per-response reseed or setup.
Every generator word has the fixed address

```text
domain(model,epoch,layout,field,rate,k0,coefficient_index,draw_index).
```

For a coefficient, C7 takes the first little-endian 64-bit word below the
Goldilocks modulus among six addressed draws.  This canonical rejection map is
exactly uniform in the ideal-generator hybrid conditioned on success, supports
random access, and avoids transcript-dependent stream offsets.  Since one
draw rejects with probability `(2^32-1)/2^64`, the six-draw union bound at the
largest geometry-only root capacities is 163.379 bits for GPT-2 and 156.859
bits for 31B per seed attempt.  Exhausting all six draws aborts before root
disclosure and burns the seed/candidate slot.

The selected privacy declaration is therefore computational:

```text
Adv_RootMaskPRG_multi(K_model,{Q_mask_words[omega]})
  + K_seed_attempts * epsilon_mask_rejection
  <= 2^-110
```

as one provisional component of the complete 78-bit model-lifetime bound.
The generator primitive, its multi-key/multi-root work-factor theorem,
`K_seed_attempts` and numeric `Q_mask_words` are not yet selected, so this gate
is false.  The explicitly persisted uniform-Fp coefficients remain the
information-theoretic reference baseline.  They are not a fallback silently
used by the main setup path.  Seeded coefficient addressing solves persistent
entropy storage and CPU/SIMT reproducibility; it does not solve the ordered
one-scan RS generator or the adaptive load theorem.

Existing repository generators do not close this cell.  `FpStream`/ChaCha8 is
explicitly a mock-PCG stand-in with a sequential unbounded rejection loop.
The production AES-128-MMO primitive is registered only for fixed-key 16-byte
WYKW GGM-node expansion, not as the selected 256-bit addressed root-mask
function.  Its non-default 16-byte BLAKE3 GGM sibling has the same scope.
ChaCha8 is rejected for production use; both GGM paths are quarantined until a
C7-specific multi-root reduction accounts the actual `Q_mask_words`.  Public
salted BLAKE3 remains the leaf/tree commitment choice; that separate use does
not select BLAKE3 as the private mask PRG.

The owner now selects **keyed BLAKE3-XOF as the primary root-mask candidate**,
because its native keyed mode, seekable XOF and tree parallelism match the
addressed, streaming setup.  This is a candidate order, not security credit.
The [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex)
targets 128-bit security for its goals and describes the 256-bit key only as
extra defense, including against possible multi-target attacks.  It does not
instantiate C7's quantitative multi-root advantage.  Therefore the key length
must not be promoted to 256 security bits.  Even if the stated 128-bit target
applies directly, the `2^-110` component reserve permits at most 18 bits, or a
factor `2^18`, of total multi-root/query loss.

The exact gate is:

```text
Adv_BLAKE3_XOF_multi(K_model,{Q_mask_words[omega]})
  + K_seed_attempts * epsilon_mask_rejection
  <= 2^-110.
```

The frozen logical candidate codec is `C7-RM-B3XOF-v1`.  It initializes
BLAKE3 keyed mode with the private 32-byte root seed, absorbs
`suite||model_id||epoch_id||layout_digest||field_id||rate||k0`, and reads the
little-endian word for `(coefficient_index,draw_index)` at byte offset
`8*(6*coefficient_index+draw_index)`.  Thus each candidate root has one
seekable XOF stream and fixed addresses independent of rejection history.
The largest screened 31B six-draw position is 1,818,867,683,328 bytes, below
BLAKE3's `2^64-1` output-byte limit.  CPU and eventual SIMT paths must emit the
same bytes; this codec is not implemented and earns no setup/security credit.

Here `Q_mask_words` counts every addressed 64-bit word actually consumed to
construct every candidate root, including rejected draws and failed seeds.
It is not the visible PCS query count unless a tighter leakage reduction proves
that substitution.  At the exploratory 31B geometry, even the mandatory first
draw is 37,893,076,736 words (`>2^35`), while the six-draw cap is
227,358,460,416 words.  No inspected BLAKE3 source supplies the required
multi-root theorem at this volume, so the candidate remains fail-closed.
As a proof-form control, any bound losing linearly in `Q` could cover at most
`2^18=262,144` words.  The current conservative one-attempt visible-Fp charges
are 234,342/297,510, so GPT-2 only barely fits that control and 31B already
misses it by 35,366 before lifecycle reserve.  This is not yet a BLAKE3
NO-GO: the mapping from visible-Fp charges to the exact theorem loss remains
unproved, and a tighter primitive-specific reduction may use another scope.

If it fails after the exact root horizon fixes `Q_mask_words`, the next line is
KMACXOF256.  [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final)
standardizes KMAC as a SHA-3-derived function usable as a PRF.  C7 now has the
concrete chunk-addressed codec screen below, but still needs the exact
multi-key reduction and a measured setup-wall pass.
If KMAC also fails a conjunctive gate, reduce attempts per root and recompute
the RS randomness dimension.  The 78-bit connection target is never reduced
to admit either generator.

#### Owner-authorized BLAKE3 fallback root profiles

The maximum is preregistered, never inferred from a favorable completed setup.
`R_root` counts accepted responses, failures, retries and selective aborts.
Each proposal additionally reserves 1/8 of its response-attempt charge for
typed init/rotation/load-refinement events and permits at most two setup seeds;
each failed seed is fully charged and burned.  A second setup failure closes
the candidate epoch before disclosure.

| model | proposed `R_root` | service charge | lifecycle reserve | proposed `Q_root` | all-seed six-draw `Q_mask_words` | unused RS capacity | setup tier |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| GPT-2 | 512 | 119,983,104 | 14,997,888 | 134,980,992 | 1,619,771,904 | 9,454,464 | target 2.00x |
| 31B | 8,192 | 2,437,201,920 | 304,650,240 | 2,741,852,160 | 32,902,225,920 | 791,486,208 | target 2.00x |

These are authorized only for the computational fallback, not admitted
profiles or mainline parameters: the 1/8 reserve
must later be split by plane and lifecycle event, and the visible-Fp-to-paper-
query refinement remains open.  A control of the form `Q/2^128` certifies only
97.406/93.063 bits after both allowed setup seeds, so it fails the 110-bit gate
for both profiles.  Keyed BLAKE3-XOF can advance only with a tighter exact
multi-root theorem; otherwise the registered order promotes KMACXOF256 or
reduces `R_root`.

The owner confirms that the fallback caps the **global model-variant attempt
horizon** at `2^20` across all connections, not `2^20` per connection.  Hence
`K_model=ceil(2^20/R_root)` is
2,048/128 and the total two-seed counts are 4,096/256.  Across that full
horizon, maximum `Q_mask_words` is
3,317,292,859,392/4,211,484,917,760.  Under the explicitly named—but unproved
for BLAKE3—linear 128-bit XOF control, the BLAKE3 term is 86.407/86.063 bits;
including six-draw rejection leaves the same rounded values and fails the
mainline 110-bit component gate.

The owner authorizes a separate fallback admission test:

```text
epsilon_privacy_model
  = Adv_BLAKE3_multi(K_model,{Q_mask_words})
  + epsilon_rejection(K_seed_attempts)
  + epsilon_adaptive_RS_view
  + Adv_saltPRF_multi
  + Adv_root_path_hash
  + Adv_multi_user_PCG_VOLE
  + Adv_multi_user_MAC
  + epsilon_allocator_state
  + epsilon_replay_fork_collision
  + epsilon_abort_timing
  + epsilon_codec_transcript
  <= 2^-78.
```

The known mask terms alone pass 78 and leave an other-terms budget slightly
smaller than `2^-78` (78.004/78.005 effective bits).  R0.8 now registers the
complete target allocation separately from theorem discharge:

```text
adaptive RS view, salt PRF, root/path hash,
multi-user PCG/VOLE, multi-user MAC, abort/timing   each <= 2^-110
allocator/state, replay/fork/collision              each <= 2^-120
codec/transcript refinement                          exact, epsilon = 0
```

Adding every target to the known mask control gives 86.406856/86.062533 bits,
so the **allocation** passes 78.  Every corresponding achieved advantage is
still nonnumeric, and no BLAKE3-specific multi-root theorem was found in the
bounded primary-source audit.  Therefore the actual complete epsilon remains
undefined, the fallback is not admitted, and implementation remains
forbidden.  Failure promotes KMACXOF256 or reduces `R_root`; it never lowers
78.

#### KMACXOF256 unpromoted high-margin control

KMAC is not promoted yet.  The minimal SIMT-compatible candidate is
`C7-RM-KMACXOF256-v1`: one private 32-byte candidate-root seed keys independent
64-KiB KMACXOF256 chunks.  The customization string is the 24 ASCII bytes
`VOLTA-ZK/C7/root-mask/v1`.  Each chunk input is a 104-byte fixed descriptor
followed by its little-endian 64-bit chunk index:

| descriptor field | bytes |
| --- | ---: |
| magic `C7RMKX01` | 8 |
| model ID / epoch / root slot | 32 / 8 / 8 |
| layout-and-root-profile digest | 32 |
| field `Fp3/u^3-2`=`0x03` / rate numerator=`1` / denominator=`2` / `k0=4` | 1 / 1 / 1 / 1 |
| logical `g=141` / draw cap=`6` / `Q_root` / seed-attempt index | 2 / 1 / 8 / 1 |

The descriptor is exactly 104 bytes and the KMAC input exactly 112 bytes.
For coefficient `i` and draw `d in {0,...,5}`, set

```text
total_bytes = 8*6*Q_root
for c in 0..ceil(total_bytes/65536)-1:
len_c       = min(65536, total_bytes-65536*c)
chunk_c     = KMACXOF256(seed, descriptor||le64(c), 8*len_c, S)
offset      = 8*(6*i+d)
c           = floor(offset/65536)
local       = offset mod 65536
draw        = le64(chunk_c[local..local+8])
```

The last chunk is the exact required prefix; no padding byte is serialized.
This is SP 800-185 KMACXOF semantics: every call absorbs `right_encode(0)`;
`8*len_c` controls only how many output bits are squeezed.
Chunks are emitted in increasing index/word order.  This keeps the logical
coefficient stream identical on CPU and SIMT, enables parallel chunk
evaluation, needs at most 65,848 working bytes per worker, and creates no
persistent mask/codeword, proof byte or visible PCS query by itself.  It does
not authorize implementation or a second packed-weight scan.  In particular,
zero persistent codeword does **not** make online mask work free:
`BatchOpenBlocks` must still derive the selected mask/codeword contribution in
`O(N+poly(q,log N))`, one packed scan and bounded memory.  That schedule and
its per-attempt generator bytes are currently unknown; setup work cannot be
transferred into this online cell.

For KMACXOF256, rate/capacity are 1,088/512 bits.  The 24-byte customization,
32-byte key and 112-byte chunk input each fit their single padded rate block.
Consequently a full chunk costs 484 Keccak-f[1600] permutations: 482 squeeze
blocks plus two prefix/key blocks.  Chunking adds 0.41494% over a monolithic
squeeze and yields the exact resource controls:

| model | output per candidate seed | chunks | permutations/seed | two-seed root cap | target throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| GPT-2 | 6,479,087,616 B | 98,864 | 47,849,710 | 12,958,175,232 B / 95,699,420 perm. | 14.398 MB/s / 106,333 perm./s |
| 31B | 131,608,903,680 B | 2,008,193 | 971,965,171 | 263,217,807,360 B / 1,943,930,342 perm. | 48.744 MB/s / 359,987 perm./s |

These are root-construction generator bytes: ephemeral work, not disk or
certificate bytes, but fully charged to setup.  They do not settle the open
online mask-contribution row above.  The target-throughput cells assume both
allowed seeds inside 900/5,400 seconds; the hard-cap floors are 13.089/44.313
MB/s.  No setup time is measured or credited.

The [sponge indifferentiability theorem](https://keccak.team/papers.html)
gives the generic control `N(N+1)/2^(c+1)`.  Under an expressly unselected
`2^64` adversarial Keccak-permutation-query screen, counting all honest setup
permutations model-wide gives:

| conditional term | GPT-2 bits | 31B bits |
| --- | ---: | ---: |
| sponge, `c=512` | 385.000 | 385.000 |
| multi-key guessing control | 180.000 | 184.000 |
| independent-seed collision | 233.000 | 241.006 |
| six-draw rejection | 152.992 | 152.647 |
| conditional sum | **152.992** | **152.647** |

Thus the arithmetic has ample 110-bit margin in the ideal-permutation control,
with rejection—not output volume—the largest known term.  It is not a C7
security result: SP 800-185 states the construction and PRF role but does not
supply the required adaptive multi-key KMAC-to-fixed-Keccak-f reduction, the
`2^64` adversary screen is not an admitted security definition, and the
fixed-permutation advantage is nonnumeric.  `passes_component_reserve=false`,
`candidate_promoted=false`, and every full-privacy term remains required.  If
the same complete other-term targets above are added, the conditional KMAC
whole-privacy allocation is 107.414568 bits for both profiles and passes 78;
this is still an allocation result, not theorem discharge.

The owner freezes this 64-KiB v1 KMAC descriptor and the registered privacy
target allocation, but does not promote KMAC: keyed BLAKE3-XOF remains the
primary performance/parallelism candidate.  Current challenge generation
remains interactive with `Q_FS=0`.  A future Fiat--Shamir selection is a
separate decision and domain: KMACXOF256 is preferred if preserving security
margin dominates; BLAKE3 is preferred for throughput only with a tightly
preregistered `Q_FS` and a complete ROM, multi-target and certificate-byte
sum.  Root-mask expansion and transcript hashing may not silently share a
security bound merely because the same primitive family is used.

#### Bounded online RS screen and current-carrier NO-GO

Closing the root/codec fixed point makes the missing online cost concrete.
The initial selected rate-1/2 codewords contain `2^29`/`2^36` Fp symbols.
The bounded screen tests every registered standard realization at the exact
selected profiles:

| realization | GPT-2 control | 31B control | disposition |
| --- | ---: | ---: | --- |
| independent dense opening | 19,426,682,171,904 FMA | 2,518,021,731,025,920 FMA | qN control; not a lower bound on shared circuits |
| persist complete codeword plus tree | 4,786,653,504 B (19.301x packed) | 642,600,433,216 B (10.423x) | fails even 3x setup |
| online full materialization | 4,294,967,296 B scratch | 549,755,813,888 B scratch | model-sized scratch forbidden |
| pruned/subset shared transform | no exact C7 schedule | no exact C7 schedule | registered shape is `O(N log q)` or has a model-linear frontier |
| seeded mask alone | random access only | random access only | does not evaluate the dense RS map |

No row proves `O(N+poly(q,log N))` with a q-independent source-linear
constant, one monotone packed scan and bounded memory.  Therefore the current
strict-UD RS realization is **NO-GO**, `C7_CPU_REFERENCE_PASS=false`, and no
CPU prover or SIMT kernel may be implemented.  This is not a universal lower
bound: a new structured shared circuit or genuinely different code-switch may
reopen the line, but only with exact operations, proof bytes, setup, I/O and
memory.  Relaxing one of the recorded one-scan, bounded-memory or 3x setup
gates is an owner decision, not an analytic substitution.

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
to one encoding of the same `W`, selected-extension MAC/RLC, PCG and state/replay/fork
errors.

```text
Pr[Bad_KS]
 <= Adv_CR_BLAKE3(Q_CR_total)
  + sum_descriptor (
        epsilon_geometry_position
      + epsilon_strictUD_query
      + epsilon_strictUD_proximity_gap
      + epsilon_setup_binding
      + epsilon_masked_oracle_to_same_witness)
  + sum_rotation (epsilon_RotateSameW_KS + epsilon_atomic_cutover)
  + Adv_MultiUserMAC(D_model,{J_d})
  + sum_attempt (
        epsilon_honest_DV_challenge
      + epsilon_RLC_operator
      + epsilon_E_terminal
      + epsilon_PCG)
  + Adv_EUF_Receipt(Q_receipt)
  + epsilon_InitKVStateSound
  + epsilon_plane_assignment
  + epsilon_replay_fork.
```

No term is declared independent merely because attempts use fresh masks; the
same `Delta` is handled only within one MAC domain by fixed-other-coins slices
and union bounds.  Cross-domain composition is the named multi-user premise.
The root sum ranges over at most `K_model` disclosed candidate `omega`
descriptors, and the rotation sum includes every accepted, failed or aborted
bridge that emitted a W-dependent byte.  `RotateSameW` must knowledge-bind both randomized encodings to
the immutable `C_W`; its private bridge transcript and bytes/setup are charged
separately rather than hidden inside root creation.

The earlier policy-3 step “extract a virtual clear PCS transcript” remains
rejected as circular.  In policy 2 the masked oracle transcript is concrete,
but soundness still needs an extractor/unique-decoding theorem tying it and
the opaque terminal handle to one committed randomized encoding of `W`.
`OpeningMac.lean` supplies only the mathematical authenticated-output seam.
Evaluation binding from preprocessing is not this knowledge theorem.

The allocator trust boundary is explicit and owner-selected.  Privacy assumes
an honest model-owner/provider allocator satisfying `AllocOK`; a corrupt
allocator can intentionally exceed the advertised leakage budget and is
outside this game.  Soundness against a dishonest proof worker instead uses
receipt EUF plus verifier-side validation, so that worker cannot mint or fork
budget/state authority.  If the prover also controls the signing key or
ledger, receipts prove nothing.  `Q_CR` belongs to this soundness reduction;
it is not a privacy or root-capacity counter.

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
2. The terminal batch is linear in any extension field under one shared
   `Delta`; applying every canonical coordinate projection yields all
   serialized Fp equalities.  R0.8 generalizes the consequence from `Fin 2`
   to `Fin d`, so direct Fp3 has all three coordinate equalities without
   modeling three unrelated base-field MACs.  This still does not construct
   the Rust adapter or prove its codec refinement.
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
knowledge soundness are instantiated and composed.  In particular, the
inherited Fp2 proximity-gap analysis does not certify the event allocation;
admission needs a tighter proved bound or a separately selected algebraic
amplifier.  Raising only the proximity-query count does not change this term.

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
independently of `Q_FS`.  The current unamplified strict-UD Fp2
analysis certifies only about 89.006 bits after unioning all 32 folds in the
31B rate-1/2 `k0=4` control, so it does not instantiate any `2^-110` row.
This is insufficiency of the proof, not a security upper bound.  Until a
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
3. create the candidate ledger entry and durably reserve `u_rotate_out` on
   `omega` plus `u_init+u_rotate_in` on `omega'` before disclosing its root or
   any bridge byte; then construct `omega'` with independent encoding randomness/salts and prove a
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
atomic-cutover theorems.  Every candidate disclosed by a successful, failed or
aborted bridge consumes one of at most `K_model` root epochs.  Failure seals
that candidate and burns both sides' reservations; a retry creates a fresh
candidate and consumes another preregistered outbound slot.  No outcome
erases the old epoch's leakage or resets boundary/K/V capacity.  Because
admission is stopped and every in-flight receipt is resolved first, no plane
assignment can straddle the cutover.

The C7 Lean module reuses the existing C6 durable-state definitions only as
an already proved abstract state-machine seam; it does not reuse the C6 proof
backend or certificate topology.

## 5. Backend tournament

Labels mean: **Evidence** is a proved/published component fact;
**Assumption** is required but not supplied for C7; **Dead end** is excluded
from the selected line.

R0.7 owner-selects the role of two still non-admitted lines:

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
- i16 decode, candidate primitives, selected Fp/Fp2/Fp3 adds/muls/reductions, `LeafCom`,
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
only pure stages for streaming setup, `LeafCom`/Merkle, PCG/VOLE, MAC, selected Fp/Fp2/Fp3,
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
frame, challenge sequence, all selected extension limbs, terminal settlement, certificate,
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

The selected policy-2 public leaf/tree function is

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

### 5.7 R0.7 theorem carrier and Pareto checkpoint

The owner selects three decisions without granting an implementation GO:

1. RS t-query ZK plus strict-unique-decoding WHIR/Ligerito is the theorem
   carrier, with public salted BLAKE3 leaves/tree; ERA `r=4` remains only a
   byte/prover control.
2. The model owner/provider is the one global allocator authority.  Privacy is
   conditional on `AllocOK`; receipt EUF is a dishonest-proof-worker
   soundness term and does not protect against a corrupt allocator.
3. No numeric `Q_root`, `R_root`, `K_model` or `D_model` is selected before a
   complete Pareto table.  Missing cells fail closed.

For a concrete model `mu`, plane `p`, root `c` and round `r`, the canonical
census compiler must emit

```text
D[mu,p,c,r]   logical protocol draws, with multiplicity
J[mu,p,c,r]   distinct Fp positions after alphabet/extension unstacking
A0            {(c,floor(j/141)) : j in J}

q_open        = |D|
Z_atom        = |J|
U_leaf        = |A0|
S_visible_Fp  = 141*U_leaf.
```

The audit Fp2 control contributes two positions and the conditional Fp3 row
three.  Deduplication is allowed only inside one
`(root,round,proof)` group under the canonical codec, never across roots,
rounds or attempts.  For `A_(l+1)=parents(A_l)`, the exact Merkle charge is

```text
H_sibling = sum_l |{sibling(v) : v in A_l, sibling(v) exists} minus A_l|.
```

The wire identity per group is

```text
B_group = 8*S_visible_Fp + 32*U_leaf + 32*H_sibling
        + B_indices + B_group_framing,
```

with zero separate leaf-digest bytes only when payload and salt reconstruct
it.  Every prover/verifier Fp/Fp2 message, interactive challenge, query seed,
round root, terminal adapter and authenticated epoch/profile receipt is then
added exactly once.  `Q_FS=0`: BCS, PoW and Fiat--Shamir benchmark bytes are
not silently transposed.

The selected RS fact is precise but narrower than C7: for
`RS[F,L,ell]`, Proposition 3.19 of 2026/391 gives message length `ell-t`,
randomness `t` and fixed-set t-query ZK error zero.  Interleaving preserves a
query count while widening its answer by `2^k`, and Definition 4.7's
composition class is non-adaptive.  Therefore `t` is not a visible-Fp budget
until `C7-OnlineMDVViewRefine` and the codec load map prove the conversion.

The executable formula control enumerates initial rates 1/2 and 1/4 and
constant folds `k=1..8` at 110 query-security bits.  It mirrors
`q=ceil(-110/log2((1+rho)/2))` in the strict-UD regime and unstacks each
grouped row.  The 110 bits are per proximity phase before round union and
algebraic terms, so this is an optimistic control rather than a composed
soundness profile.  Representative rows are:

| Formula control | GPT-2 `q_open` / Fp positions | 31B `q_open` / Fp positions | growth (`q` / Fp) |
| --- | ---: | ---: | ---: |
| rate 1/2, `k=2` | 1,468 / 10,680 | 1,912 / 14,232 | 1.302 / 1.333 |
| rate 1/2, `k=4` | 832 / 22,368 | 1,054 / 29,472 | 1.267 / 1.318 |
| rate 1/4, `k=4` | 723 / 20,528 | 945 / 27,632 | 1.307 / 1.346 |

Every representative constant-schedule pair exceeds the independent 1.05
gate.  This is a formula control, not an impossibility proof: auxiliary ZK
atoms, concrete leaf indices, multiproofs and non-oracle messages remain
unknown.  It cannot dominate or admit a row.

R0.7 also runs an exact finite Pareto DP over **every** integer tail-fold width
after starting rate 1/2 and `k0=4`, with the registered strict-UD query formula,
direct-send threshold six and both Fp2/Fp3 unstacking choices.  No Pareto pair
passes both first-stage 1.05 gates.  The best minimax pairs are

```text
Fp2 GPT-2: [4,5,3,3,3,3]     q=831    Fp=19,104
Fp2 31B:   [4,4,3,3,3,4,4,4] q=1,054  Fp=24,128  -> 1.268x / 1.263x
Fp3 GPT-2: [4,5,3,3,3,3]     q=831    Fp=26,528
Fp3 31B:   [4,3,3,3,4,4,4,4] q=1,055  Fp=33,848  -> 1.270x / 1.276x.
```

Thus fold-width choice alone is rejected.  On the Fp2 minimax row the
large-model logical-draw and unstacked Fp-position formula controls need
separate reductions of 17.215% and 16.863% relative to their own 1.05 gates;
17.215% is only the uniform common factor that would make both pass.  These
positions are not the uncompiled g141 `S_visible_Fp`.  The corresponding Fp3
vector is 17.294%/17.707%, with a 17.707% common factor.  These gaps are
non-fungible: headroom on one axis cannot pay the other.  Sharing only
indices can reduce logical draws but not Fp payload leakage; Merkle multiproof
sharing changes paths, not either control.  Deliberately adding dummy GPT-2
queries or choosing a dominated GPT-2 schedule would only inflate the
denominator and is forbidden by Pareto-first/no-padding.  This is an exact
negative result for the registered pure-fold family, not a universal WHIR
lower bound.  A live row needs a proved cross-round joint sampler **and** a
codec sharing/deriving later-round visible symbols, or a genuinely different
code-switch schedule.

Two published rows remain explicitly non-admitted controls.  Ligerito at
`2^30`, 100 bits reports 148 queried rows/round, about 420 KiB, 80 s and
31 GiB allocated, but uses Fiat--Shamir and matrix/full-codeword memory rather
than the C7 codec.  ERA at `2^32`, 100 bits reports 72,418 field elements,
53,011 hashes and about 4.014 MB, but keeps its `O(lambda log N)` query law,
N-scale intermediates and missing adaptive privacy theorem.  These values
preserve comparison evidence; they cannot fill unknown C7 cells.

The field/domain distinction is subtler than a single smooth-domain check.
Padding the weight polynomial and using an initial rate 1/2 gives this many
logical initial-oracle positions:

| Model | message dimension | initial-oracle positions | `|L0|/N` |
| --- | ---: | ---: | ---: |
| GPT-2 | `2^27` | `2^28` | 2.164802 |
| 31B envelope | `2^35` | `2^36` | 2.229241 |

The published Goldilocks WHIR benchmarks omit pairs whose initial exponent
exceeds 32.  The retained control instead represents the first oracle as rows
of width `2^k0` and performs the base-field DFT over the row domain.  Its exact
guard is

```text
D + log2(1/rate) - k0 <= TWO_ADICITY(Fp) = 32.
```

Thus a 31B control is field-valid at `k0>=4` for rate 1/2 and `k0>=5` for
rate 1/4.  This removes the claimed Goldilocks impossibility; it does not
inherit evidence from the omitted paper rows or prove the C7 codec/theorem
bridge.  Increasing `k0` exposes a width-`2^k0` alphabet before g141 packing,
so every logical sample, Fp atom, unique leaf and visible-Fp count must still
pass independently.  Segmentation and a new smooth field remain fallbacks,
not forced alternatives.

The minimal physical baseline keeps one dense canonical scalar stream packed
into exact g141 leaves; it does not pad every `2^k0` row to a leaf divisor.
Rows may straddle leaf boundaries, and all touched leaves are opened and
charged.  At `k0=4` one 16-Fp row touches at most two g141 leaves; the exact
union depends on the compiled indices.  Persistent row-alignment padding
would change setup, LeafCom and transcript bytes and is forbidden.  Device
tiling may still add only the already-authorized temporary measured zero
padding.  The digest-only setup numbers below are the dense-stream floor, not
an admitted block-opening codec.

The corrected algebraic soundness cell is already a hard stop.  The 110-bit
query target bounds only the strict-UD query miss event.  Let
`p=2^64-2^32+1`.  The inherited unique-decoding analysis gives the exact
field-cardinality error upper bound

```text
epsilon_gap <= 2^(D + log2(1/rate)) / p^2.
```

The first GPT-2/31B challenge at rate 1/2 therefore certifies
99.9999999993/91.9999999993 bits (100.000/92.000 when displayed to three
decimals); `bit_length(p^2)=128` is informational and is never substituted for
`p^2`.  This does **not** upper-bound the construction's real security.  The
field-valid constant-`k0=4` controls contain 24/32 folding challenges.  Union
of their inherited bounds certifies only 97.023/89.006 bits for the complete
fold sequence and 77.023/69.006 after `R_max=2^20`, before other terms.  This
is insufficient to derive either the registered 104--110-bit response reserve
or the 78-bit lifetime target, but it is not an impossibility result or a
tight attack.

The analytic remedies remain distinct:

| Remedy control, 31B rate 1/2 `k0=4` | Inherited certificate | Query/payload consequence | Missing premise |
| --- | ---: | ---: | --- |
| tighter strict-UD analysis | needs about 21 additional all-fold bits for 110 | none if proved | no tighter theorem or tight attack is registered |
| two independent complete Fp2 experiments | 178.011 all-fold; 158.011 after `R_max`, conditional | 58,944 Fp / 471,552-B payload floor, about 2x | adaptive AND-repetition, shared-root/one-scan and privacy theorem |
| Goldilocks Fp3 | 153.006 all-fold; 133.006 after `R_max` | 42,080 Fp / 336,640 B, +42.8% payload | field/codec, three-limb MAC/terminal and privacy bridge |
| interactive PoW | no statistical amplification under `Q_FS=0` | conditional 16,711,680 hash trials and 32 serial syncs | new resource-bounded computational theorem |

Payload figures exclude salts, paths, roots, indices, sumcheck, MAC and
framing.  Retained Fiat--Shamir grinding is unavailable in the selected
interactive mode.  The audit-then-Fp3 closure path is selected, but no remedy
is admitted here.

Digest-only BLAKE3 floors for a single rate-1/2 oracle, with zero selected ZK
randomness and no auxiliary root/metadata, are
369,843,040 B (1.4913x) and 92,844,619,232 B (1.5059x).  Holding old and new
trees for atomic same-W rotation gives 1.9826x and 2.0119x before metadata,
bridge state or temporary work.  Thus static storage passes the 2.00 target,
while large-model rotation already uses the tolerance.  Rate 1/4 static
storage is 1.9826x/2.0119x, but dual-root rotation is 2.9652x/3.0237x and is
rejected.  These floors do not prove an ordered root build: stock FFT/matrix
encoders still lack the required one-scan, bounded-memory, no-codeword
schedule.  Padding leaves 10,217,728 / 3,533,338,368 coefficient slots before
the actual packed messages reach `2^27` / `2^35`.  R0.7 treated these only as
unused message slots.  R0.8 D091 now derives the RS randomness-dimension
screen from Proposition 3.19, but still does not admit `Q_root`: the adaptive
Fp load theorem, all correlated components, persistence/generation path and a
positive service margin remain missing.

The Pareto vector is deliberately non-scalar:

```text
(q_open by plane/root/round, Z_atom, U_leaf, S_visible_Fp, H_sibling,
 certificate GPT2/31B/growth,
 setup persistent/temp/read/write/time/rotation,
 online passes/read/write/work/RSS, verifier work,
 knowledge soundness, model-lifetime privacy,
 q_init/q_rotate_in/q_rotate_out and lifecycle reserve,
 R_root, K_model, D_model).
```

Each cell is tagged `DERIVED`, `PAPER`, `COMPILER`, `THEOREM` or `MEASURED`.
Security-invalid rows are discarded first; an unknown prevents PASS and
Pareto dominance.  There is no weighted score and no tolerance transfer.  At
R0.7 the feasible admitted set is empty, so all four lifetime caps remain
unset.

### 5.8 Bounded closure screens and owner 1.30 fallback

This screen does not reopen pure fold-width search.  It tests only the two
post-D075 forms authorized by the owner and records a NO-GO for each under the
original 1.05 gate.

**Cross-round joint sampling with actual Fp derivation.**  The strongest
bounded candidate fixes every round root, samples iid path seeds `s_j`, and
uses balanced quotient projections into adjacent round domains.  When the
same path is active in adjacent rounds, one coordinate of the later fiber can
be reconstructed from the prior opened fiber and omitted from the later leaf
payload.  This is genuine symbol derivation rather than index or Merkle-path
sharing.  On the already-selected Fp2 controls it gives:

| Quantity | GPT-2 | 31B | growth |
| --- | ---: | ---: | ---: |
| per-round `t_i` | `266,121,111,111,111,111` | `266,121,112,111,111,111,111,111` | -- |
| canonical `q_open=sum_i t_i` | 831 | 1,054 | 1.268351x |
| original unstacked Fp-position control | 19,104 | 24,128 | 1.262982x |
| maximum adjacent derivation | -1,130 | -1,576 | -- |
| remaining Fp-position control | 17,974 | 22,552 | 1.254701x |
| remaining payload floor only | 143,792 B | 180,416 B | 1.254701x |

One shared seed is not one PCS opening: every distinct round/root fiber still
has an authenticated oracle opening.  Roots have distinct paths, so neither
`q_open` nor Merkle authentication collapses.  The payload floor omits salts,
leaves, paths, indices, roots and framing.  In particular, these Fp-position
controls are not `S_visible_Fp`.  The exact g141 codec must still compile
`Z_atom`, `U_leaf` and `S_visible_Fp=141*U_leaf`; no ratio follows from the
table for those cells.

The required delayed-joint soundness theorem is also new.  If all roots are
binding and fixed before the path seeds, every projection is balanced and iid
across `j`, and every extraction failure fixes a discrepancy set `B_i` of
density at least `delta_i`, the desired bound is

```text
Pr[all links pass and some round is bad]
  <= sum_i (1-delta_i)^t_i
   + sum_i epsilon_gap_i + epsilon_binding + epsilon_MAC.
```

The current WHIR order does not supply this theorem: its link samples precede
the next root and enter the next constraint.  Delaying all samples requires a
`DelayedJointWHIRStrictUD` round-by-round extractor and a new transcript
proof.  Correlated samples preserve each marginal bound but do not create
independent miss exponents when bad sets align.

For privacy, write every revealed or derived linear observation in an
adaptive abort prefix `T` as `A_T Enc(W;r)` with
`Enc(W;r)=G_W W+G_R r`.  A sufficient codec-level condition is

```text
im(A_T G_W) subseteq im(A_T G_R)  for every legal T,
```

plus the global root-budget charge.  Fixed-set RS t-query ZK does not prove
this adaptive joint-image condition.  `BalancedJointPath`, the delayed RBR
extractor, `JointFoldAdaptiveRSZK`, a derivation-aware g141 codec, same-W
binding and a one-scan bounded root/open schedule are all absent.  Sequential
fold challenges otherwise require a retained folded oracle or a reread; making
all challenges early violates later commit-before-challenge.  The candidate
therefore remains **NO-GO** at 1.05 and is not implemented.

**Different code-switch.**  The bounded local tournament also yields no
complete row:

| Candidate | Best bounded control | Terminal reason |
| --- | --- | --- |
| ERA to BaseFold | published-geometry extrapolation gives `q_open=2370/3602` (1.519831x) and unstacked Fp `68612/71076` (1.035912x) | fails even the 1.30 q gate; optimistic setup floor `1+140.8/141+66/141=2.466667>2.10`; a materialized 25-stack alone is 6.25x packed bytes; no one-scan, policy-2 masking, same-W terminal or malicious-DV theorem |
| SwitchFold/QAFold/BrakeFold | a depth-only 4-to-5 control is about 1.25x, not an exact C7 census | per-level auxiliary/carry roots and full encodings; QAFold WHT `O(N log N)` and 377-GiB host evidence; no bounded one-scan schedule, Goldilocks row, hiding or authenticated terminal |
| 2026/391 HVZK code-switch/amplified RS | alphabet-width asymptotic `35/27=1.296296x` before constants | no exact g141/path/setup/opener row; wider answers unstack to Fp; HVZK/non-adaptive composition is not stateful malicious-DV privacy; the amplified example materializes a much wider codeword |
| LigeSIS | none complete | full RS word, bit matrix, secondary PCS and optional large table; no exact paired census or hiding theorem |
| ITC3 batching | none multilinear | the compiler is univariate and its multilinear linear-time adaptation is explicitly open |

Thus the selected carrier is **NO-GO under the original 1.05 query-growth
gate**, and no alternative code-switch supplies a complete row even at 1.30.
This is a bounded tournament result, not a lower bound on all future codes.

The owner's fallback now activates a distinct **1.30 hard growth ceiling**,
componentwise, for `q_open`, `Z_atom`, `U_leaf` and `S_visible_Fp`.  The exact
Fp2 Pareto control passes only its two known axes:

```text
q_open:        1054/831   = 1.268351x <= 1.30  (26 draws of integer headroom)
Fp positions: 24128/19104 = 1.262982x <= 1.30  (707 positions of headroom)
```

This selects the pair only as the next **formula query-axis candidate**.  It
does not pass the four-axis gate while `Z_atom`, `U_leaf` and `S_visible_Fp`
are uncompiled, and it grants no certificate, setup, prover, privacy or
soundness credit.  Proof wire now has a 105% target and a preregistered
125--150% exploratory hard band conditional on complete 35/115-MB and 3.5x
caps.  Setup keeps 2.00/2.10 as target/baseline and adds a near-3x exploratory
ceiling with absolute disk/time/refresh caps.  One packed scan/bounded memory
and 110/78-bit security are unchanged.  Fp3 can close only the
algebraic-security axis and must pass the same complete census.

### 5.9 R0.8 fixed envelope, Fp3 selection and opening subcodec

The owner authorizes the design-only R0.8 compiler/security/resource pass and
retains, without reopening the backend tournament:

```text
carrier       RS t-query ZK + strict-UD WHIR/Ligerito
rate          1/2
first fold    k0=4
weight roots  one packed root
leaf format   flat logical g=141
challenge     fresh post-prefix interactive; Q_FS=0
```

R0.8 must emit the canonical plane/root/round codec, exact reserved and actual
query counters, all serialized bytes, the complete security-event registry,
and setup/refresh/online I/O, wall and memory resources.  It may not change
the field merely to fill an incomplete codec cell.  The first step is the
inherited strict-UD algebraic-gap audit on the selected Fp2 Pareto schedules
`[4,5,3,3,3,3]` and `[4,4,3,3,3,4,4,4]`.

For round `i`, with `m_i` variables and inverse-rate exponent `r_i`, the
registered proved upper bound is

```text
epsilon_i <= k_i * 2^(m_i+r_i) / |Fp2|,
epsilon_all <= sum_i epsilon_i.
```

Using the exact Goldilocks modulus rather than a rounded 128-bit denominator
gives:

| Selected Fp2 schedule | `q_open` | unstacked Fp | all-fold response bits | after `R_max=2^20` |
| --- | ---: | ---: | ---: | ---: |
| GPT-2 | 831 | 19,104 | 97.017 | 77.017 |
| 31B envelope | 1,054 | 24,128 | **89.087** | **69.087** |

The 31B row therefore misses 110 by 20.913 bits and misses the 78-bit
connection target by 8.913 bits before hash, PCG, state, codec, privacy or
other terms.  This is a proved upper-bound audit, not a tight attack or an
impossibility theorem.  A modest response-target change to 104 or the bare
98-bit minimum cannot admit it.  With all other errors temporarily omitted,
the largest 78-bit lifetime is only 2,175 attempts; 2,048 attempts leave
0.087 bit of slack, while an 84-bit intermediate target permits only 33.
The owner selects direct Goldilocks Fp3 and keeps the 78-bit connection
target.  This closes only the registered algebraic-gap axis.  Using
`|Fp3|=p^3`, three canonical Fp limbs after the first base-field oracle and
the selected schedules gives:

| Selected Fp3 schedule | `q_open` | `Z_atom` / unstacked Fp | response bits | after `R_max=2^20` |
| --- | ---: | ---: | ---: | ---: |
| GPT-2 `[4,5,3,3,3,4]` | 831 | 29,192 | 160.011 | 140.011 |
| 31B `[4,3,3,3,4,4,4,4]` | 1,055 | 33,848 | **153.173** | **133.173** |

The GPT-2 row changed because the selected mask capacity raises its coefficient
dimension from `2^27` to `2^28`; the 31B row remains unchanged.  Both exceed
110/78 on this axis before the other connection terms.  The full 78-bit
theorem remains false until the complete
codec, adaptive privacy, transcript/receipt, hash/PCG, multi-user VOLE/MAC and
state/replay terms are derived.

R0.8 fixes the executable field representation rather than using cardinality
alone:

```text
E = Fp[u] / (u^3 - 2)
x = x0 + x1*u + x2*u^2
wire(x) = le64(x0) || le64(x1) || le64(x2), each xi < p
```

Here `p mod 3 = 1` and
`2^((p-1)/3) mod p = 2^32-1 != 1`; hence 2 is not a cube in the cyclic
`Fp*`.  The cubic has no Fp root and is irreducible.  Decoding rejects a
length other than 24 bytes or any limb `>=p`.  With `u^3=2`, multiplication
uses

```text
c0 = a0*b0 + 2*(a1*b2 + a2*b1)
c1 = a0*b1 + a1*b0 + 2*a2*b2
c2 = a0*b2 + a1*b1 + a2*b0                 (all mod p).
```

The terminal has one shared `Delta in E` and verifies `k=m+Delta*x` in E.
It serializes one 24-byte provider correction, never `x`, and may not replace
the equation by three independent Fp MACs.  The generic Lean coordinate
consequence covers all three limbs.  The carrier-independent Rust seam now
implements the canonical codec/KAT and tests shared-`Delta` linearity plus
three-limb mutation rejection.  It deliberately instantiates no PCG, VOLE or
PCS, so the concrete adapter/codec refinement and protocol credit remain open.

The exact conservative g141 opening reservation compiles as follows.  Each
queried `2^k`-symbol block touches at most two logical leaves; leaf payloads,
256-bit salts, compact-tree multiproofs, interactive challenges, auxiliary
roots, the direct-send tail and the three-limb terminal frame are counted.

| Counter | GPT-2 | 31B | growth | 1.30 gate |
| --- | ---: | ---: | ---: | --- |
| `q_open` | 831 | 1,055 | 1.269555x | PASS |
| `Z_atom` | 29,192 | 33,848 | 1.159496x | PASS |
| `U_leaf` | 1,662 | 2,110 | 1.269555x | PASS |
| `S_visible_Fp` | 234,342 | 297,510 | 1.269555x | PASS |

The exact worst-case compact-tree sibling caps are 20,997/39,843.  Known
serialized opening bytes are **2,605,740 / 3,729,724 B** (1.431349x), within
the 105% weight-wire targets in isolation.  This is not the complete wire
gate: strict-UD non-oracle sumcheck/OOD messages, the authenticated
`omega`/profile reservation receipt, plane-assignment receipt and root-hiding
capacity metadata remain unknown and fail closed.  Actual accepted counts may
be smaller, but reservations never refund.

Setup and refresh use separate, non-transferable clocks:

```text
GPT-2 setup target/hard cap       900 / 990 s
31B setup target/hard cap        5400 / 5940 s
refresh target/hard cap          same initial numbers, separate counters
refresh test in R0.8              forbidden / not credited
```

The 3x persistent-disk ceiling remains conjunctive with the setup time cells.
Refresh cannot borrow setup slack; its registered placeholder caps do not
authorize a refresh measurement.

### 5.10 R0.8b co-designed construction screen and reference seam

R0.8b implements only the carrier-independent pieces that remain valid for
every future entrant. `rust/volta-pcs/src/c7_policy2_reference.rs` fixes:

- the exact 90-byte keyed `C7-RM-B3XOF-v1` descriptor
  `suite||model_id||epoch_id||layout_digest||03||01||02||04` and addresses
  draw `(i,d)` at byte `8*(6i+d)`, with six-draw Goldilocks rejection;
- a public, domain-separated salted BLAKE3 `LeafCom`, position/level-bound
  binary tree and canonical one-leaf opening frame of `1296+32h` bytes;
- distinct fixed `q_attempt` reservation and observed `q_response` census,
  with full charge before disclosure and no refund after abort;
- the existing shared-`Delta` Fp3 transfer and an in-memory accepted-KV CAS
  that rejects replay and a competing fork.

The tiny two-leaf Rust test exercises XOF KAT/address rejection, canonical
padding, root/path/frame round-trip, mutation rejection, abort burn, acceptance,
budget exhaustion, the Fp3 terminal equation and KV replay/fork exclusion.
This is an executable conformance seam, not `BatchOpenBlocks`: the tree is
full-memory, the budget and KV state are not durable, no root-wide privacy
theorem is instantiated, and no relationship binds its masked leaves to a
code or the terminal. It therefore earns no PCS, setup, security, lifecycle
or `C7_CPU_REFERENCE_PASS` credit.

The bounded circuit search also closes three tempting shortcuts while keeping
their reasons distinct:

1. For one geometric coset `z^B=c`, a coefficient scan can accumulate the
   `B` residues modulo `X^B-c` and evaluate the whole block in
   `O(N+B log B)` work and `O(B)` memory. This genuinely meets the one-scan
   algebraic shape. It fails soundness amplification: a density-`delta` error
   may occupy only a `delta` fraction of cosets, so one whole coset remains
   only one worst-case hit. `t` independent cosets require `t` residue
   accumulators and restore `tN`; one larger coset retains the same worst-case
   partition obstruction. The row is **NO-GO**, not an implementation target.
2. Persisting only the parity half of any rate-1/2 Goldilocks code already
   costs `2N + 8N = 10N` bytes including canonical packed i16 weights, or
   **5x packed before Merkle nodes**. More generally the floor is
   `1+4(1/rate-1)`; even 3x requires `rate>=2/3` before the tree. The fixed
   rate-1/2 line is therefore **NO-GO** for a persisted parity/codeword escape.
3. A causal linear encoder that emits in packed-source order and retains only
   a bounded delayed tail gives the last nonzero input only that tail's output
   support. It cannot have constant relative distance without a linear tail
   or noncausal setup/access. This rejects that bounded-tail subclass only;
   it is not a lower bound on arbitrary linear circuits.

No co-designed carrier row is complete. The four R0.8a pre-CPU obligations
remain false, so the next local test may extend only this non-PCS seam until a
new circuit supplies the missing same-W soundness/privacy bridge and one-scan
opener.

### 5.11 R0.8c designated-verifier secret-point carrier

The absence of a published construction is not a rejection condition. R0.8c
therefore promotes the *research question*, but not the carrier, to a concrete
C7 object named `C7-DV-SPQ-v0`. The carrier is the PCS/code substrate that
binds packed weights and carries the operator/GKR terminal linear functional
into VOLE-MAC; it is not the transformer proof by itself.

For the univariate core, let `F(X)=sum_i f_i X^i`, let `tau` be a root-scoped
verifier secret, and let `A=F(tau)`. Neither party may receive `A` in clear.
Enrollment must instead create persistent secret shares of `A`, later imported
into a fresh connection-scoped shared-`Delta` Fp3 MAC. For a public point `r`
and authenticated claim `v`, define

```text
Q(X) = (F(X)-v)/(X-r)
F(tau)-v = (tau-r) Q(tau).
```

The honest synthetic-division recurrence is

```text
q[d-1] = f[d]
q[i-1] = f[i] + r*q[i]       for i=d-1,...,1
v      = f[0] + r*q[0].
```

It can be generated during one manifest-fixed reverse sequential scan with
constant plain state if `tau` is known. C7 requires the stronger primitive:
`OpenQuotientIntoMac` must perform the `tau`-dependent part without revealing
`tau`, `F(tau)`, `Q(tau)` or `v`, without one correction per coefficient, and
while binding `Q` to the enrolled `F` and fixed `v`. Three new interfaces are
therefore explicit rather than hidden behind an ideal PCS:

1. `EnrollSecretPoint` binds one packed `F` and creates shares of `F(tau)`;
2. `ImportRootShareIntoMac` moves those shares into a fresh connection domain;
3. `OpenQuotientIntoMac` authenticates the fixed quotient evaluation.

R0.8d closes the algebraic part of this gap only on an exact one-dimensional
curve.  For a segment with padded length `2^n`, the curve and denominator are

```text
r_k(t) = t^(2^k) / (1 + t^(2^k)),
D_n(t) = product_(k<n) (1 + t^(2^k)).
```

Then `eq(r(t),j)=t^j/D_n(t)` and the raw packed segment values are already the
coefficients of the univariate `F_i`.  No Möbius transform, expanded wrapper
or materialized `L` is needed.  This is a conditional functional-basis PASS,
not an admitted bridge: arbitrary independent GKR points do not lie on this
curve, and forcing public sequential GKR challenges onto it breaks the
existing soundness schedule as shown in Section 5.12.

#### Conditional algebraic margin and transcript order

Goldilocks Fp3 has 191.999999999 bits of cardinality. If a nonzero identity of
degree below `2^28`/`2^35` is fixed before any `tau`-dependent output, and the
view leaks no predicate of `tau` beyond terminal accept/reject, the adaptive
first-false-accept union controls are 155.000 bits for 512 GPT-2 attempts and
144.000 bits for 8,192 31B attempts. Charging four planes over the complete
`R_max=2^20` horizon leaves 135.000 bits. These are algebraic screens, not
security credit: the 110-bit component is met only after the four hypotheses
below are proved.

```text
reserve attempt, pre-enrolled tau slot, masks and correlations
  -> fix epoch/layout/root handles, claims, query vectors and MAC handles
  -> fix the response-wide RLC and the quotient relation
  -> run one reverse packed scan plus OpenQuotientIntoMac
  -> settle F(tau)-v-(tau-r)Q(tau)=0 under the Fp3 MAC
  -> atomically promote KV state, or burn everything on any abort.
```

The required hypotheses are: the false identity is fixed before secret-point
feedback; the malicious view has a simulator that hides every other predicate
of `tau`; failures, retries and selective aborts are all charged; and the
response-wide RLC leaves one nonzero identity when any packed claim is false.
If `tau` is revealed, a cheating prover can set
`Q(tau)=(F(tau)-v)/(tau-r)` for any `v`. If `F(tau)` or `Q(tau)` is clear, the
privacy goal is already violated. Reusing an uncharged accept/reject oracle can
adaptively test root sets. Enrollment with `F'` and opening with `F`, or
re-importing one persistent share under a reused connection MAC domain, breaks
same-weight or one-time-correlation soundness. These are separate fail cases.

The stateful theorem target is simulation based. For any malicious designated
verifier controlling connections, challenges, retries, concurrency and aborts,
and for two fixed-weight histories with identical allowed leakage (public
tokens, shapes, length/timing buckets, counters and explicitly budgeted masked
PCS symbols), the complete serialized views must be indistinguishable. The
simulator receives only that leakage and the accept/abort/promotion journal; it
does not receive weights, clear terminal evaluations, `tau`, root shares or
MAC keys. Root and connection domains are jointly simulated, so opening a new
connection cannot reset `R_root` or the model-global horizon.

The games are not conflated. Dishonest-prover soundness fixes the enrolled
polynomial/root first, then has the honest designated verifier sample uniform,
domain-separated `tau`; every later quotient is fixed before any
`tau`-dependent feedback. Model privacy permits a verifier to choose malformed or repeated
points and schedules; the protocol must validate the public profile, reveal at
most its prescribed share/view, charge the attempt, and otherwise abort. The
135-bit root bound cannot be cited as malicious-verifier privacy.

The soundness reduction must expose, rather than absorb, every term:

```text
Adv_sound <= Adv_enroll_same_F
           + Adv_import_MAC
           + Adv_open_quotient_malicious
           + Adv_RLC
           + 4*R_max*(2^35-1)/|Fp3|
           + Adv_MAC + Adv_PCG/VOLE
           + Adv_hash/commitment + Adv_state/replay/fork.

Adv_priv  <= Adv_SPQ_view_sim
           + Adv_root_mask_multi
           + Adv_PCG/VOLE + Adv_MAC
           + Adv_hash/path + Adv_abort/timing
           + Adv_allocator/state + Adv_codec_refinement.
```

The algebraic term is about `2^-135`; every other term still uses the existing
110/120-bit allocation and their complete sum must remain at most `2^-78`.
`Adv_SPQ_view_sim`, `Adv_enroll_same_F` and
`Adv_open_quotient_malicious` are named hypotheses, not consequences of the
equation. An implementation may not replace them with an ideal API assertion.

#### Bounded realization screen

| Realization | Exact obstruction under current gates | Disposition |
| --- | --- | --- |
| algebraic-PRF verifiable polynomial evaluation | at least one authenticator group element per coefficient; even an optimistic 32-byte element gives packed weights plus tags `17x`, and online evaluation retains full group work | NO-GO |
| silent OLE/VOLE or LPN/LWE NIIP | known general-field inner products retain linear wire; the `2N+o(N)` OLE control is `48N+o(N)` bytes in Fp3 | NO-GO online certificate |
| Merkle root of response quotient | post-root queries require a second packed scan or a model-sized quotient/tree scratch | NO-GO |
| public powers/KZG-style quotient | `N` public powers and a full large-field MSM violate setup and online gates | NO-GO |
| finite hidden credential pool | credential bytes can be small, but pre-revealing the pool destroys challenge unpredictability and no near-linear hidden multipoint enrollment is supplied | QUARANTINE |
| structured `X^B-c` residue | choosing the coset before quotient binding permits adaptation; binding first requires another pass, while independent amplification restores the already rejected `tN` work | NO-GO; preserves D105 |
| succinct OTE/LFE | useful evidence for short private function evaluation, but no concrete same-`F` malicious proof, Fp3 codec or 110-bit parameters | CONTROL |

The wider published screen also remains fail-closed for distinct reasons:
small-alphabet Brakedown has a square-root certificate and no direct Fp3
bridge; FRI-Binius has polylogarithmic proofs but full folding oracles and a
characteristic-two/privacy bridge gap; Blaze's safe published row is rate 1/4,
while rate 1/2 and good-setup certification rely on unproved or insufficient
events and it supplies no hiding; binary GKR retains an encoded matrix and
transpose plus no Fp3 same-value bridge; polynomial preprocessing gives only
evaluation binding, and its fast multivariate theorem does not cover the
needed multilinear specialization. These labels retain the rejection reason;
they are not impossibility claims about a new C7 construction.

Primary evidence for the new core screen is the converted Markdown for
[algebraic-PRF/OPE](../sota/2015-004-oblivious-polynomial-evaluation-secure-set-intersection.md)
and [LPN/LWE NIIP](../sota/2023-072-noninteractive-secure-inner-product-lpn-lwe.md).
The former keeps one group authenticator per coefficient and linear server
work; the latter explicitly retains linear communication, including the
`2N+o(N)` general-field silent-OLE comparison. They justify only the control
rows above, not a lower bound against `C7-DV-SPQ-v0`.

#### Safe future online-only boundary

An eventual deployment may expose only the online prover, but this is a
process boundary, not an authorization. Root setup runs separately, records
all source reads, temporary writes, traffic, RSS and wall time, and activates
nothing until an immutable manifest and setup-relation receipt verify. The
existing 900/990-second and 5,400/5,940-second setup clocks and exploratory 3x
persistent-disk ceiling remain unchanged; a failed setup creates no active
root or reusable privacy budget. Refresh is still untested and unauthorized.

The future online process gets read-only model/root access, reserves the full
attempt before witness-dependent output, performs exactly one
manifest-direction monotone `2N`-byte packed scan with no reopen or model-sized
spill, and writes only the bounded proof and atomic journal. Abort burns the
secret-point slot, correlations, masks and `q_attempt`; acceptance promotes KV
state only after terminal MAC settlement. No online prover exists until the
operator-transcript bridge, enrollment binding, succinct malicious
`OpenQuotientIntoMac`, full stateful privacy theorem and exact codec/resource
row all pass.

### 5.12 R0.8d exact `eq` bridge and transcript hard stop

#### Exact heterogeneous scalarization

Fix one canonical segment `i`, including its zero padding to length
`N_i=2^n`, and write

```text
F_i(T) = sum_(0 <= j < N_i) W_i[j] T^j.
```

For a scalar `t_i` for which every `1+t_i^(2^k)` is nonzero, define the curve
and denominator from Section 5.11.  Since

```text
1-r_k(t_i) = 1/(1+t_i^(2^k)),
```

the binary expansion `j=sum_k j_k*2^k` gives

```text
eq(r(t_i),j)
  = product_(j_k=1) r_k(t_i) * product_(j_k=0) (1-r_k(t_i))
  = product_k t_i^(j_k*2^k) / D_n(t_i)
  = t_i^j / D_n(t_i).
```

Therefore the already-proved heterogeneous identity refines exactly to

```text
sum_i beta_i * MLE(W_i,r(t_i))
  = sum_i [beta_i/D_i(t_i)] * F_i(t_i).
```

Padding remains zero and contributes nothing.  The illustrative schedule has
98/370 weight segments and 106/378 all-plane segments for GPT-2/31B, below
the screen cap 512, but these remain illustrative until the real compiler
manifest derives them.  A reverse physical traversal can feed one synthetic
division per segment while reading exactly `2N` packed bytes once.  Excluding
the still-missing private quotient adapter, the source work is
`N+O(J log N_max)`, the source-linear constant is independent of `J`, and no
`L`, Möbius transform or extension-field weight wrapper is stored.
Merely sharing one Fp3 token per illustrative weight segment would contribute
only 4,704/17,760 combined two-party bytes for GPT-2/31B; this is a lower bound,
not a setup estimate. Same-`F` binding, share protection, receipts and their
construction traffic remain uncounted, and any realization still fails if it
introduces a codeword, per-coefficient authenticator or setup beyond the
registered disk/wall caps.

This curve is also essentially the exact direct-power condition.  At a
nondegenerate point, `eq(r,j)=c*t^j` for every `j` if and only if

```text
c = eq(r,0),
r_k/(1-r_k) = t^(2^k)  for every k.
```

Necessity follows by dividing the coefficient at `j=2^k` by that at `j=0`;
sufficiency is the product calculation above.  An arbitrary independently
sampled GKR point fails these relations in general.  The budget v26 modular
self-check verifies the identity and an explicit two-coordinate
counterexample over Goldilocks.

#### Why the current public GKR transcript is unsound on the curve

The bridge cannot be installed by merely changing challenge derivation.
`protocol-sketch.md` fixes public verifier challenges, and
`SumcheckSound.card_deviation_le` counts independent uniform vectors in
`F^n`: the round-`i` prover message sees only the prior coordinates, while the
current coordinate is fresh over the whole field.  The curve contains at most
`|F|` correlated vectors and does not meet that hypothesis.

The failure is constructive for the degree-two product sumchecks used by GKR.
Revealing `r_0=t/(1+t)` reveals `t=r_0/(1-r_0)`, hence every later coordinate.
In the opposite direction, after revealing
`r_k=t^(2^k)/(1+t^(2^k))`, an adjacent lower coordinate has only the two
possibilities induced by `y` and `-y`, where `y^2=t^(2^k)`:

```text
s_plus  =  y/(1+y),
s_minus = -y/(1-y).
```

For `P(X)=(X-s_plus)(X-s_minus)`, direct algebra gives

```text
P(s_plus)=P(s_minus)=0,
P(0)+P(1)=1.
```

If the current false sumcheck gap is `delta`, the malicious prover sends the
true next-round polynomial plus `delta*P`.  The round-sum check absorbs the
whole gap, yet evaluation at either possible challenge returns the true value;
the prover then continues honestly.  Before reaching such a round, a nonzero
gap can be carried without risk by adding the constant `delta/2`, because the
field has odd characteristic.  A known single next challenge is even easier:
a degree-at-most-two polynomial can be chosen to have the prescribed
`h(0)+h(1)=delta` and a root at that challenge.

No coordinate permutation repairs this.  Once a lower power has been shown,
any later higher power is deterministic.  Avoiding every such ascent forces a
strictly descending permutation; a complete strictly descending order has
adjacent powers and therefore the two-root attack.  Thus a false gap can be
carried to a vulnerable round and erased with probability one on every
nondegenerate execution.  This is a **NO-GO** for
`C7-DV-SPQ-v0 + LogisticEqCurve + current public sequential blind GKR`, not a
claim that secret-point commitments are impossible.

#### Bounded escape screen

| Escape | Evidence | Disposition |
| --- | --- | --- |
| retain independent per-round challenges | preserves the existing soundness theorem, but generic `r` fails the direct-power condition | CONTROL; no univariate SPQ bridge |
| projective/monomial sumcheck | removes `D_i` and puts truth-table values directly in the monomial basis, but does not restore independent challenges | NO-GO as a transcript escape |
| fuse all `n` variables into one univariate skip | obtains one fresh scalar, but the round polynomial has degree `Theta(2^n)=Theta(N)` and needs a linear message/oracle or another PCS | NO-GO under proof-wire and recursion gates |
| bounded-size univariate skips | keep degree and messages bounded, but leave multiple independent scalars and a multivariate terminal | CONTROL; not the required scalar quotient |
| keep challenges secret/encrypted | the current prover cannot form later round messages from an opaque challenge; no bounded-wire secure-fold refinement is supplied | QUARANTINE as a new operator protocol |

The projective and univariate-skip controls are supported by the primary
`sota/2026-762-projective-sumcheck.md` and
`sota/2025-1473-time-space-tradeoffs-sumcheck.md` records.  Neither supplies a
complete C7 row.  R0.8d therefore closes the scalar algebra but fails the
operator composition.  Same-`F` enrollment, malicious succinct
`OpenQuotientIntoMac`, the stateful malicious-DV theorem and the exact codec
also remain open, so no CPU prototype, prover or SIMT work is authorized.

### 5.13 R0.8e secret-point butterfly transform

R0.8e replaces the unsound logistic operator bridge, not the independent
GKR transcript.  The new reduction `C7-SPBT-v0` accepts each ordinary
independent terminal point `r` already produced by blind GKR and changes the
basis of the committed segment before one fresh secret-point check.  It is a
reduction candidate, not an admitted PCS.

#### Exact relation and invertibility

Let a canonically padded segment have length `M=2^n`, coefficient vector
`p_0` and polynomial

```text
P_l(X) = sum_(0 <= j < M/2^l) p_l[j] X^j.
```

At level `l`, split `P_l(X)=E_l(X^2)+X O_l(X^2)` and use the ordinary,
independently sampled GKR coordinate `r_l` to define

```text
p_(l+1)[i] = (1-r_l) p_l[2i] + r_l p_l[2i+1]
z_(l+1)[i] = p_l[2i] - p_l[2i+1].
```

Writing the corresponding polynomials as `Y_(l+1)` and `Z_(l+1)`, the exact
one-level identity is

```text
P_l(X)
  = (1+X) Y_(l+1)(X^2)
  + (r_l-(1-r_l)X) Z_(l+1)(X^2).                 (SPBT-1)
```

The pair map has matrix

```text
[ 1-r_l   r_l ]
[   1      -1  ]
```

and determinant `-1`, for every `r_l`.  Its inverse is therefore unconditional:

```text
p_l[2i]   = p_(l+1)[i] + r_l z_(l+1)[i]
p_l[2i+1] = p_(l+1)[i] - (1-r_l) z_(l+1)[i].
```

After `n` levels, the only surviving fold is
`y=p_n[0]=MLE(p_0,r)`.  The complements contain
`M/2+M/4+...+1=M-1` coefficients, so

```text
T_r : p_0 <-> (Z_1,...,Z_n,y)
```

is an invertible `M`-coefficient transform.  This is the key difference from
a raw fold transcript: no second `Y` oracle is committed, and there is no
rate expansion in the number of algebraic coefficients.

For

```text
D_l(X) = product_(h<l) (1+X^(2^h)),
c_l(X) = r_l-(1-r_l)X^(2^l),
```

induction on (SPBT-1) gives

```text
P_0(X)
  = D_n(X) y
  + sum_(l=0)^(n-1)
      D_l(X) c_l(X) Z_(l+1)(X^(2^(l+1))).        (SPBT-2)
```

Every term has degree at most `M-1`.  Because `T_r` is bijective, a proposed
`(Z_1,...,Z_n,y)` differs from the true transform if and only if the residual
polynomial in (SPBT-2) is nonzero.  Budget v27 checks (SPBT-2), coefficient
count and the inverse exactly over Goldilocks on a 64-coefficient instance.
The identity is field-generic; the selected execution and terminal remain
Goldilocks Fp3.

For heterogeneous segments, the canonical tagged stream contains every
`Z_(i,l)` and `y_i` once.  A response-local `C_Z,e` may be one interleaved
root inside the fresh boundary plane `C_B,e`; it is not another persistent
weight root.  Jagged layout rules determine tags and padding, but do not add
the paper's online adapter.  The one logical ALFC invocation opens the
structured functional of `C_W` and `C_Z,e` into the session MAC and checks
`y_i=v_i`, where `v_i` is the already authenticated operator terminal.  No
`y_i`, `P_i(tau)` or `Z_(i,l)(tau^(2^(l+1)))` is cleartext.

#### Required transcript and conditional soundness

The only sound public-challenge order found is:

```text
reserve the whole attempt and bind accepted predecessor state
  -> run response-wide GKR with its ordinary independent r_i
  -> fix every authenticated terminal claim and the complete C_Z,e
  -> sample tau after all transform coefficients are bound
  -> derive and fix every structured query vector from tau
  -> sample beta after all roots/claims/handles/query vectors are fixed
  -> open C_W and C_Z,e structured evaluations into shared-Delta Fp3 MAC
  -> settle SPBT residuals and y_i-v_i in one terminal RLC
  -> atomically promote KV successor, or burn on every failure/abort.
```

Under named binding and authenticated-opening hypotheses, if any of `J`
segment transforms or terminal claims is false, fresh `tau` makes every false
residual evaluate to zero with probability at most `(M_max-1)/|Fp3|`.
Conditioned on a nonzero scalar residual vector, the later beta aggregate
vanishes with probability at most `(J-1)/|Fp3|`.  Thus the new algebraic term is

```text
epsilon_SPBT,response <= (J-1 + M_max-1)/|Fp3|.
```

Using the current conservative `M_max=2^28/2^35` and illustrative
`J=106/378` controls gives about 164/157 bits per response and 144/137 bits
after the full `R_max=2^20` connection horizon.  Both exceed the 110-bit
component reserve.  These figures are conditional algebra only.  A complete
bound must still expose

```text
Adv_sound <= Adv_bind_CW + Adv_bind_CZ + Adv_same_W
           + Adv_delayed_open_into_MAC
           + epsilon_SPBT,response
           + Adv_MAC + Adv_PCG/VOLE
           + Adv_hash + Adv_state/replay/fork.
```

No missing advantage is set to zero, and the existing R0.8d attack remains
the durable reason that correlated logistic challenges cannot replace this
independent transcript.

#### One-scan transform schedule and exact dense cost

A binary carry stack computes the transform in canonical packed order.  Each
incoming coefficient occupies level zero; whenever a level already has a
pending value, one butterfly emits the next tagged `Z_l` coefficient and
carries `Y_l` upward.  For segment lengths `M_i`, this gives

```text
butterflies = sum_i (M_i-1) = M_total-J,
N <= M_total < 2N,
source reads = 2N bytes in one monotone scan,
working state = one Fp3 value per level + one g141 leaf/hash frontier.
```

The source-linear constant is independent of query count and the stream can
be hashed without an expanded resident weight wrapper.  One extension-scalar
multiplication and two additions/subtractions suffice per butterfly.  This
arithmetic path is SIMT-friendly in principle, but remains analytic and has
no implementation authority.

The dense transform traffic is not free.  `Z_1` is base-field-valued because
the source is in Fp.  The remaining complements plus `y` are `M_total/2`
Fp3 values.  The canonical dense stream is therefore exactly

```text
(M_total/2)*8 + (M_total/2)*24 = 16*M_total bytes,
```

or between `16N` and `32N` bytes before hashing.  The current workload bounds
are:

| Dense response-local transform control | GPT-2 | Gemma-class 31B |
| --- | ---: | ---: |
| one packed source read | 248,000,000 B | 61,652,800,000 B |
| `16N` auxiliary-stream minimum | 1,984,000,000 B | 493,222,400,000 B |
| `<32N` auxiliary-stream upper bound | <3,968,000,000 B | <986,444,800,000 B |
| packed + retained minimum | 9x | 9x |

The stream bytes are online generated/hash input, not certificate bytes.  If
discarded, they do not enlarge persistent setup.  If retained so that a
later challenge can be opened, they are forbidden model-sized scratch and
already exceed the 3x setup envelope if moved to preprocessing.  An
optimistic two-party preprocessed sign/square-root orbit uses at least one
Fp3 token per coefficient per party: `48N` additional bytes, or at least 25x
including packed weights.  This explicitly prevents SPBT from recreating the
heavy XD4-style setup through another name.  No setup-wall or refresh test is
authorized.

#### Commit/challenge/open triangle: current realization NO-GO

The reduction closes the operator transcript but exposes one remaining
non-fungible triangle:

| Schedule | Exact consequence | Disposition |
| --- | --- | --- |
| reveal `tau` before `C_Z,e` | one scalar equation leaves `M` proposed transform coefficients; a prover adapts one of them to any false `y` | **NO-GO: unsound** |
| fix `C_Z,e`, then retain it until `tau` | canonical dense response scratch is `16*M_total` bytes, at least 8x the packed source in addition to the source | **NO-GO: model-sized scratch** |
| fix `C_Z,e`, discard it, then recompute after `tau` | needs a second packed read and another transform | **NO-GO: second scan** |
| keep `tau` hidden during the one scan | needs a malicious-secure streaming inner product/OPE into MAC with sublinear wire and no per-coefficient correction | **OPEN primitive; no complete row** |
| save an exact plain sketch for arbitrary later `tau` | evaluations at `M` distinct points determine every degree-`<M` polynomial, so an information-theoretic exact sketch must be injective | **NO-GO for sublinear plain sketches; not a PCS lower bound** |

A computational polynomial commitment can evade the plain-sketch argument,
but it must then supply the exact delayed-opening witness algorithm.  KZG-like
multilinear-to-univariate controls use group setup and online MSM work;
BaseFold-like controls restore an encoded oracle; the known space-efficient
PCS control explicitly assumes multi-pass streaming input.  None gives C7 a
one-scan, setup-safe delayed opening.  These are construction-specific
rejections, not a universal lower bound.

Primary controls are
[MicroNova](https://eprint.iacr.org/2024/2099), whose compressed path uses a
universal KZG setup and group operations;
[BaseFold](https://eprint.iacr.org/2023/1705), which obtains multilinear
commitments from foldable codes and encoded-oracle work; and the
[space-efficient PCS](https://eprint.iacr.org/2020/1425), whose stated sender
interface has multi-pass streaming access.  Jagged remains only the canonical
heterogeneous layout reference in `sota/2025-917-jagged-pcs.md`; none of these controls instantiates
the SPBT delayed opener.

Raw Merkle sampling is also insufficient.  `T_r` is invertible but rate one,
so it has no distance: one false coefficient can change the claimed
polynomial while occupying one leaf.  Even reusing the current 831/1,055
query controls, the miss probability is at least 0.999527/0.999997 on the
minimum g141 leaf counts, far from one security bit.  Wrapping the stream in
the rate-1/2 code returns the already rejected full-codeword setup or online
materialization.  A finite public `tau` pool cannot supply 110-bit challenge
entropy and also worsens reuse privacy.

Two other exact reductions remain closed with their reasons.  Committing all
sumcheck rounds as functions of one scalar merely turns the R0.8d correlated
challenge attack into a polynomial identity; enforcing causal dependence with
degree-two prefix tables grows as `3^round` and requires another PCS.
Middle-coefficient convolution can express a matmul exactly, but materializes
linear convolution remainders per matmul/token or requires persistent FFT
weight transforms, violating response scratch or setup.

#### Policy-2 and stateful privacy consequences

Because `T_r` is invertible, revealing all unmasked complements is equivalent
to revealing the weights.  `C_Z,e` must therefore be fresh and attempt-bound,
computationally hiding, and covered by policy 2.  Its operational disclosures
charge the attempt-local `Q_B[a]`, while every weight-derived view also
charges the model-global `Q_root`; a public salted hash root alone is not a
hiding theorem.  Any visible
leaf is exactly 141 masked Fp symbols, with each Fp3 value charged as three.
Queries, paths, failed attempts, retries and selective aborts all consume the
preregistered root budget before disclosure.  Abort never promotes the KV
state and never refunds masks or correlations.

The required malicious-DV theorem must simulate the joint `C_W/C_Z,e` roots,
all masked adaptive leaf views, the opaque authenticated structured
evaluations, accept/reject feedback and the atomic KV journal from only the
allowed leakage.  It must also prove that the `y_i` authenticated by SPBT are
the same values used by the operator proof and that every segment comes from
the same canonical `W`.  Its new term is explicit:

```text
Adv_priv,connection <= Adv_SPBTView
                     + Adv_RootMaskPRG_multi + Adv_PCG/VOLE + Adv_MAC
                     + Adv_hash/path + Adv_abort/timing
                     + Adv_allocator/state + Adv_codec_refinement.
```

`Adv_SPBTView` and the exact `q_attempt/Q_root` vector are not derived, so the
78-bit stateful privacy gate remains false.  The one fresh transform-root
digest is only a 32-byte certificate lower bound; all delayed-opening paths,
masked payloads, MAC frames and interactive messages are unknown.  Proof-size
and 3.5x growth gates therefore remain false rather than being inferred from
the small root.

**R0.8e disposition.**  `C7-SPBT-v0` passes the exact algebraic relation,
preserves the independent public GKR soundness schedule, and has a conditional
one-source-scan `O(N)` transform with bounded working state.  Its current
Merkle/secret-point realizations fail the delayed-opening gate.  It is the
main reduction candidate but not a selected carrier, and
`C7_CPU_REFERENCE_PASS=false`.  Resume requires one concrete delayed-opening
primitive that fixes all coefficients before `tau`, opens directly into the
Fp3 MAC with sublinear wire, retains one packed scan and bounded memory,
introduces no full codeword/heavy setup, and supplies the adaptive policy-2
privacy bridge.  Until then there is no CPU prover, SIMT, refresh, provider or
pod action.

### 5.14 R0.8f native `StreamOpenIntoMac` screen

R0.8f tests only the last open SPBT edge.  Let `E=Fp3`, let `C_x` bind a
canonical length-`M` coefficient vector, and let the designated verifier hold
secret `tau in E` and the connection MAC key `Delta`.  The requested ideal
functionality is

```text
StreamOpenIntoMac(C_x, q_tau; prep, transcript)
  -> P: (v, m_v), V: k_v

v   = <x,q_tau>
k_v = m_v + Delta*v,
```

where neither `tau`, `v`, `m_v` nor `k_v` is reconstructed on the wire.
`prep` is independent of `x` and `tau`; there is no SRS or trusted setup.  A
complete realization would additionally have to prove that one `x` bound by
`C_x` supplies the response relation and terminal MAC, and simulate the
adaptive malicious-verifier view under the policy-2 root budget.  It must use
one monotone packed scan, bounded memory, `o(M)` wire, no correction per input
coefficient and no persistent dense codeword/oracle.

The only sound one-scan ordering would be:

```text
fix C_W, response statement and independent GKR challenges r
V privately samples tau; tau is not sent to P
one packed scan fixes C_Z,e while evaluating its tau-functionals into MAC
fix every authenticated output handle and derived query descriptor
sample beta; settle the response-wide RLC; atomically promote or burn
```

Hiding `tau` prevents the R0.8e adaptive-coefficient attack, but it turns the
stream step into a private inner product.  The repository's native MAC
correction has exactly the standard affine form: a fresh scalar `x_i` is
derandomized against a correlation mask by sending `d_i=x_i-r_i` (8 bytes),
while an Fp3 direct transfer sends three such limbs (24 bytes).  Silent VOLE
can expand the input-independent correlations; it does not compress this
input-dependent vector.

The obstruction can be stated without treating it as a universal PCS lower
bound.  In the affine native-VOLE class, suppose the online corrections use a
`tau`-independent matrix:

```text
c = A(x-r) in E^s.
```

for preprocessing `r` independent of `x` and `tau`.  If `A(x-x')=0`, the two
online views are identical, so exact correctness for every permitted point
forces `<q_tau,x-x'>=0`.  Therefore

```text
ker(A) subseteq intersection_tau ker(q_tau),
span{q_tau} subseteq row(A).
```

For `q_tau=(1,tau,...,tau^(M-1))`, any `M` distinct points form an invertible
Vandermonde matrix.  Hence `rank(A)>=M`, `s>=M`, and the online correction
wire is `Omega(M)` extension-field elements.  Budget v28 checks rank 8 over the
actual Goldilocks modulus as a small executable witness; the general result is
the Vandermonde determinant argument.  Its scope is standard affine
VOLE/OLE derandomization with `A` independent of `tau`, not arbitrary
computational PCS, `tau`-dependent secure computation, FHE or general
two-party computation.

The concrete floors already trigger the owner kill gate:

| route | GPT-2 | Gemma-class 31B | disposition |
| --- | ---: | ---: | --- |
| optimistic one 8-byte Fp correction/packed scalar | 992,000,000 B | 246,611,200,000 B | linear wire; exceeds 35/115 MB alone |
| one 24-byte Fp3 correction/coefficient | 2,976,000,000 B | 739,833,600,000 B | linear wire; stronger failure |
| persist source plus optimistic Fp corrections | 5x packed | 5x packed | exceeds exploratory 3x setup before tags/tree |
| persist source plus Fp3 corrections | at least 13x packed | at least 13x packed | exceeds setup gate |

Horner evaluation at hidden `tau` uses `M` secret multiplications/OLEs and has
the same linear online problem.  The published general-field batch-OLE control
reduces a length-`M` inner product to `M` OLEs and reports
`2M+o(M)` field-element communication; its LPN/LWE non-interactive encodings
are also linear in `M`
([local paper](../sota/2023-072-noninteractive-secure-inner-product-lpn-lwe.md)).
Group OPE/KZG uses the forbidden group/SRS or per-coefficient material
([local control](../sota/2015-004-oblivious-polynomial-evaluation-secure-set-intersection.md)).
Garbled/full-MPC evaluation is linear in circuit size.  HE/PIR/FHE has no
native VOLE/MAC, same-`W`, policy-2 malicious bridge and is quarantined rather
than credited; two-server FSS/PIR changes the trust architecture.

**R0.8f disposition.**  The native primitive has no complete malicious-secure
row.  It triggers the rigid `Omega(M)` wire/per-coefficient-correction gate;
moving those corrections to setup gives 5x/13x persistence.  Consequently the
SPBT carrier line is closed and the dual-track carrier tournament is reopened
with no active entrant.  The exact SPBT algebra may be reused only if a future
carrier independently passes every gate; its prior failure reasons remain
binding.  This is `credit:false`: there is no new Lean/Rust protocol, CPU
prototype, SIMT, refresh, provider contact or pod authorization.

### 5.15 R0.8g direct `Bolt-min` code-switch screen

R0.8g spends the one candidate authorized by D111 on a concrete topology,
`C7-BOLT-MIN-G141-v0`, derived from
[Bolt](../sota/2026-310-bolt.md).  This is deliberately **not** C6.3's Bolt
precode inside eight Hiding-WHIR bodies and not C6.4's six-body projected
residual suffix.  It applies Bolt directly to the immutable weight plane:

```text
X in Fp^(k x 128),                 M = 128k
U = H X,                          H in Fp^((k/8) x k), degree 16
C_H^128(X) = (X, RS_1/2^128(U)),

r <- Fp3^128
x = Xr, u = Ur = Hx,
w = RS_1/2(x).
```

One typed root would bind the systematic masked rows and encoded sketch rows.
The `t=128` rows are flattened into the fixed dense `g=141` stream with zero
persistent row padding; a row therefore touches at most two leaves.  The final
multilinear evaluation would still enter the shared-`Delta` Fp3 MAC.  The
sparse `HX` work and the `t` short setup encodings are source-linear with a
constant independent of the number of queries.  This is the genuine advantage
over the rejected direct `qN` RS control.

The setup storage cell is promising but incomplete.  Padding the row count to
`k=2^20/2^28` gives `M=2^27/2^35`.  Counting the existing packed source, the
rate-1/2 encoding of the one-eighth sketch, and a conservative 96 bytes for
salt/leaf/internal-digest material per one of `5k/4` committed rows gives:

| direct-Bolt setup control | GPT-2 | Gemma-class 31B |
| --- | ---: | ---: |
| packed source | 248,000,000 B | 61,652,800,000 B |
| encoded sketch payload | 268,435,456 B | 68,719,476,736 B |
| salted tree control | 125,829,120 B | 32,212,254,720 B |
| total | **642,264,576 B (2.590x)** | **162,584,531,456 B (2.637x)** |
| exploratory 3x cap | 744,000,000 B | 184,958,400,000 B |

Thus this use of Bolt does **not** repeat X4d/C6 merely by existing: its
optimistic persistent footprint is below the 3x disk cap and setup happens
once per long-lived root.  This is positive size evidence, not admission: the
encoded sketch is still one complete persistent codeword, forbidden by the
unchanged gate.  The masked-root manifest, exact tree storage, temporary I/O
and 990/5,940-second walls are also unmeasured.

The hard failure appears when setup layout and later row openings are required
together:

1. In row-major order, each queried 128-symbol row touches at most two g141
   leaves.  A single
   packed scan computing random sparse `HX` must retain all `k/8 x 128`
   accumulators: 134,217,728 B / 34,359,738,368 B.  Externalizing the degree-16
   read-modify-writes moves at least 34,359,738,368 B / 8,796,093,022,208 B.
   Both are model-linear setup state, not bounded streaming memory.
2. In column-major order, live syndrome state falls to 1,048,576 B /
   268,435,456 B and the packed source can be traversed once, but a systematic
   row spot touches 128 distinct g141 leaves.  Under the conservative
   Goldilocks query row this reserves up to 592,640 leaves and **768,061,440 B
   of leaf frames before paths**, exceeding either complete-certificate cap.
3. Persisting a row-major packed transpose repairs both access patterns but
   raises setup to 910,700,032 B / 231,304,008,192 B, or 3.672x/3.752x.  A
   bounded block-local `H` is not an escape: a nonzero word supported in one
   block bounds relative distance by `block_rows/k`, which vanishes for
   bounded blocks.

The proof's code switch creates a second independent stop.  Bolt sends an
explicit length-`t` function `g`, samples `r`, and creates the fresh
rate-1/2 word `w=RS(Xr)`.  Because C7's challenge is Fp3, `w` occupies
`2k*24` bytes.  The encoded syndrome combination has another `k/4` Fp3
elements:

| response-local proximity payload | GPT-2 | Gemma-class 31B |
| --- | ---: | ---: |
| fresh `w` | 50,331,648 B | 12,884,901,888 B |
| syndrome combination | 6,291,456 B | 1,610,612,736 B |
| total | **56,623,104 B** | **14,495,514,624 B** |

This remains a complete response-local codeword family and model-linear
scratch even though it is only a `1/128` column combination and its source
term is independent of `q`.  Streaming its root does not remove the complete
word or the FFT working set; increasing `t` trades it directly for the
explicit `g` and every opened row.

The query/security control also cannot import the paper's best row.  At 110
bits, the published `GF(2^32)` `gamma=0.096` gives 2,345 systematic plus 266
base-code rows.  The requested row symbols plus the 128 Fp3 elements of `g`
already total 334,592 Fp occurrences.  Because dense g141 rows may cross leaf
boundaries, the fail-closed reservation is 5,222 leaves and 736,686 visible Fp
occurrences, **3.144x/2.476x** the selected GPT-2/31B controls.  That distance
does not transfer to Goldilocks.  The historical Goldilocks diagnostic
`gamma=0.049` instead gives 4,630+266 rows: its requested-symbol lower bound is
627,072, while the dense reservation is 9,792 leaves and 1,381,056 visible Fp
occurrences, **5.893x/4.642x**.  Both rows fail the 150% wire control.  Its
prior exact finite-distance proof covered C6's
specific D22 ensemble, not these D20/D28 message dimensions, so even this
worse count is not an admitted 110-bit theorem.  Fp3 repairs the algebraic
challenge axis; it cannot repair code distance or reduce row leakage.

Published Bolt explicitly provides no hiding/zero knowledge, sends `g` in
clear, and proves an ordinary public evaluation rather than a terminal MAC
handle.  Its non-amortized sparse-`H` closure relies on Mulperm whose cost is
estimated because no implementation was available.  C7 would still need a
masked-code same-`W` theorem, exact root-wide query budget, direct Fp3
VOLE-MAC adapter, malicious-prover knowledge bridge and stateful
malicious-DV simulator.  Adding Hiding-WHIR by default is forbidden: it would
recreate the C6 topology before those costs were screened.

The C6 postmortem remains attributed correctly.  C6.3 retained an inherited
17,179,869,184-byte encoded weight oracle, generated 17 profiles in 2,092.76
seconds, and stopped first at recorder lifecycle then at finite-PCG underflow,
with zero certificates.  Those are failures of the complete composed path,
not a standalone Bolt impossibility.  R0.8g avoids those exact objects and
transfers no timing/byte credit; it rejects the direct topology on the new
layout, fresh-codeword, query and theorem gates above.

**R0.8g disposition.** `C7-BOLT-MIN-G141-v0` is NO-GO and is not promoted to
carrier.  The setup-size control is retained as positive evidence, while the
separate codeword/layout/wire/security rejection reasons and the C6
differential remain durable.  The
one-candidate tournament is closed.  `C7_CPU_REFERENCE_PASS=false`; there is
no CPU prototype, Rust/Lean protocol change, SIMT, refresh, provider contact
or pod authorization.  Any further carrier or reopening of the non-affine
line requires a new owner decision.

## 6. Registered analytic screens

The executable calculator is `scripts/budget_c7_stateful_alfc.py`.  Every
output carries `credit:false`.  Schema v29 reproduces scaling arithmetic,
allocation caps, artifact-volume scenarios, the R0.7 strict-UD controls and
the two bounded closure screens, and adds the exact selected-schedule Fp2/Fp3
audits, g141 opening subcodec, known serialized bytes and setup resource
floors, the confirmed global fallback horizon and the conditional
chunk-addressed KMACXOF256 screen, closes the root/codec geometry fixed point
and records the bounded selected-RS online NO-GO.  It also registers the
fail-closed carrier admission boundary, the tested carrier-independent
`Fp[u]/(u^3-2)` field/terminal seam, the policy-2 reference codec, the three
bounded co-designed rejections above, and the conditional `C7-DV-SPQ-v0`
margin, missing interfaces, realization controls and safe online boundary. It
also records the exact logistic `eq` identity, its one-pass conditional cost,
the executable degree-two correlated-challenge attack and the bounded escape
screen.  It additionally checks the exact SPBT identity/inverse, conditional
Fp3 soundness, one-scan butterfly work, dense auxiliary traffic, raw-Merkle
query miss and every branch of the delayed-opening triangle.  It also checks
the native affine-VOLE Vandermonde rank obstruction, exact 8/24-byte
correction floors and 5x/13x persistence controls, then records SPBT closed.
It additionally checks the single direct-Bolt candidate's padded dimensions,
query rows, setup storage, layout trilemma, fresh Fp3 codeword bytes and C6
differential, then closes the bounded tournament with no entrant.  It is
not an authority for a complete compiler manifest, complete
certificate, security theorem or measured C7 time.

The two registered self-check invocations are:

```text
python3 scripts/budget_c7_stateful_alfc.py
python3 scripts/budget_c7_stateful_alfc.py --chunk-mb 64 --bandwidth-gbps 1.6
```

Both must exit zero; neither supplies production credit.

For the scoped R0.8e checkpoint, the focused
`tiny_policy2_codec_budget_terminal_and_state_seam` test and standalone
rustfmt check for `c7_policy2_reference.rs` pass, as does `git diff --check`.
The full Rust workspace has one committed, out-of-scope C6 source-guard
failure: `native_persistence_source_guard_bypasses_hidden_u_owner` includes a
later helper signature containing `session_digest`.  The failing
`volta-bench` source is unchanged by C7, so it is recorded rather than repaired
inside this scoped checkpoint.

R0.8f changes no Rust or Lean.  Its two budget-v28 invocations and
`git diff --check` are the only new executable checks; no protocol artifact or
benchmark receives credit.

R0.8g likewise changes no Rust or Lean.  Its checks are the two registered
budget-v29 invocations, `python3 -m py_compile` and `git diff --check`; it
creates no prover or benchmark credit.

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
overfetch and padding in every opened 141-symbol leaf; the selected extension
counts once per base-field limb.
`H_sibling` counts exact digests, not field leakage.  Aborted prefixes are
also measured, but the global privacy allocator conservatively burns the full
reserved worst case with no refund or cross-attempt deduplication.

Separately record:

- `q_open[c,r]`, the logical PCS samples before alphabet/leaf unstacking;
- `Q_root`, the theorem-backed lifetime privacy capacity in its exact query
  atom; typed `q_init/q_rotate_in/q_rotate_out` and
  `u_init/u_rotate_in/u_rotate_out`; and the derived response-attempt
  `R_root<=floor((Q_root-F_omega)/u_W)` after lifecycle reserve;
- `Q_B[a]`, the per-attempt response-plane horizon, and `Q_KV[s]`, the
  per-created-K/V-root horizon covering proposed-successor disclosure plus
  every predecessor reuse if that same root is accepted;
- `Q_CR`, `Q_hide`, `Q_saltPRF` and `Q_mask_words`, respectively the
  collision/binding, adaptive root/path-hiding, salt-PRF and root-mask PRG
  reduction work bounds, all indexed by the complete `omega` and composed
  across `K_model`;
- `Q_FS`, adversarial transcript-hash queries, fixed to zero in the selected
  interactive protocol.

None of these is automatically a certificate byte count, bounded by the
connection `R_max`, or interchangeable.  A single scalar counter is admitted
only when a joint theorem supplies worst-case class weights.

Admission is the conjunction, never one optimized minimum:

```text
q_sound_min(theta,N) <= q_attempt(theta,N)
B_query_wire(theta,N,q_attempt) <= B_weight_ALFC_limit(N)
u_init + A_rotate_in*u_rotate_in + A_rotate_out*u_rotate_out
       + R_root*u_W <= Q_root <= t_ZK(theta)
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

R0.3 preregistered a base allocation and a 105% ceiling for the weight-oracle
share.  R0.7 now retains 105% as the target rather than an immediate hard
stop.  A candidate may preregister one exact exploratory hard cap in the
125--150% band before its compiled measurement; response-wide and nonweight
challenges remain in their separate owners:

| Weight-oracle envelope | GPT-2 | 31B envelope |
| --- | ---: | ---: |
| registered `B_weight_ALFC` allocation | 3,116,843 B | 5,234,948 B |
| 105% target ceiling | 3,272,685 B | 5,496,695 B |
| 125% exploratory-band floor | 3,896,053 B | 6,543,685 B |
| 150% exploratory absolute maximum | 4,675,264 B | 7,852,422 B |
| complete certificate at 105% | 12,541,405 B | 19,474,047 B |
| complete certificate at 125% | 13,164,773 B | 20,521,037 B |
| complete certificate at 150% | 13,943,984 B | 21,829,774 B |

Bytes at or below 105% meet the target.  Values above it are not an automatic
failure, but the exact 125--150% hard cap must be selected before measurement
and the **complete** compiled certificate must simultaneously remain at or
below 35 MB for GPT-2, 115 MB for 31B and 3.5x growth.  Above 150% always
fails.  The exploratory band supplies no privacy or soundness credit and
cannot offset an overrun in another component.  Until the exact cap and full
codec bytes exist, the gate remains fail-closed.

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
active 30% hard growth tolerance from GPT-2 to 31B.  This owner-authorized
fallback supersedes the original 5% query-growth gate only after the two
bounded screens in Section 5.8 returned NO-GO.  Packing or deduplication may
identify two counters only under a proved codec equivalence.  Merkle paths may
grow only while the complete byte gates pass.  The active ratio corresponds
to exponent about 0.0476 in the weight dimension, still stricter than the
generic `N^0.199` complete-proof screen.  It does not alter the separate 105%
weight-wire target or its conditional 125--150% exploratory band.

Reducing `Q` by weakening proximity error is not a size optimization.  The
compiled complete certificate should pass the preferred 30/100 MB and 3x
targets.  If the proof-wire exploratory band is invoked, its conjunctive hard
caps are instead 35/115 MB and 3.5x; no component may invoke the band alone.

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
large-model ceiling is inactive and requires explicit owner approval.  The
new proof-wire exploratory envelope is narrower and conjunctive: at most
35/115 MB and 3.5x, only with an exact preregistered 125--150% weight-wire
cap.  It is not Tier B and does not relax any security or setup gate.

### 6.4 Scaling-law screen

| Weight-law term | 31B/GPT-2 growth | Within 3x? | Within optional 6x? |
| --- | ---: | :---: | :---: |
| `log N` | 1.295981257x | yes | yes |
| `log^2 N / log log N` | 1.556932990x | yes | yes |
| `log^2 N` | 1.679567419x | yes | yes |
| `N^(1/4)` | 3.970775020x | no | yes |
| `sqrt(N)` | 15.767054259x | no | no |
| `N` | 248.6x | no | no |

The exact exponent ceilings are `0.1991738805` for 3x, about `0.2271` for the
conditional 3.5x exploratory proof cap, and `0.3248386079` for 6x.  The
optional 6x column is sensitivity only; it grants no Tier-B authorization.

Passing the weight-only law is necessary, not sufficient.  The script also
reports layer count, `T`, predecessor/successor K/V length, terminal-segment
count and root count.  A design that batches only `N` while allowing any of
those dimensions to multiply certificates has not passed C7.

### 6.5 Packed-source functional scan target

For only the direct packed-source dot product, R0 registers:

```text
packed bytes read per response = 2 * N
materialized L bytes           = 0
expanded extension-field weight copy = forbidden
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
| expanded resident extension-field weights | 0 B | 0 B |
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

R0.3 registered the target/baseline pair.  R0.7 now adds a distinct
exploratory ceiling:

```text
target:                A_setup = S_total / S_packed_i16 <= 2.00
baseline tolerance:    A_setup <= 2.10
exploratory ceiling:   A_setup <= 3.00
```

The interval `(2.00,2.10]` remains the preferred tolerance.  The exploratory
3x ceiling fixes absolute persistent-disk caps of **744,000,000 B** for GPT-2
and **184,958,400,000 B** for the 31B envelope.  Setup-wall target/hard caps
are **900/990 s** and **5,400/5,940 s**.  Refresh has separate counters and
initially registers the same numeric pairs, with no transfer of setup budget.
R0.8 neither tests nor credits refresh.  Temporary disk, preprocessing
read/write, peak RSS/VRAM and eventual refresh traffic remain separately
counted; X4d-scale planes or unbounded scratch cannot be hidden inside the 3x
ratio.  Anything above 3x fails.

For the selected rate-1/2, one-root Fp3 opening screen, the persistent setup
stores packed i16 weights, the compact g141 digest tree, 64 bytes of root
salt-seed/nonce metadata and the selected 32-byte private root-mask seed.  It
does not persist the codeword payload:

| Setup floor | GPT-2 | 31B |
| --- | ---: | ---: |
| persistent bytes | 491,686,208 | 92,844,619,328 |
| amplification over packed i16 | 1.982606x | 1.505927x |
| minimum packed-read + tree-write bytes | 491,686,112 | 92,844,619,232 |
| oracle payload hashed | 4,294,967,296 | 549,755,813,888 B |
| target oracle-symbol rate | 596,523/s | 12,725,829/s |
| target payload-hash rate | 4.772 MB/s | 101.807 MB/s |

These are the selected seeded-mask-capacity geometry/I/O floors, not complete
or measured setup credit.  GPT-2's selected `Q_root=134,980,992` crosses the
next power-of-two boundary: `ell=2^28` and the rate-1/2 oracle has `2^29` Fp
symbols.  Gemma remains at `ell=2^35`.  Recompiling the codec at those exact
dimensions reproduces the same selected root profiles, closing the fixed
point.  Proposition 3.19 makes the first capacity screen
exact: an RS polynomial with total coefficient dimension `ell` hides at most
`t=ell-W` queried locations while retaining `W` message coefficients.  Using
the complete visible-Fp leaf reservation as a conservative per-attempt charge
gives:

| Fixed current tree | GPT-2 | 31B |
| --- | ---: | ---: |
| total RS coefficient dimension `ell_0` | 134,217,728 | 34,359,738,368 |
| zero-tree-growth random coefficient headroom | 10,217,728 | 3,533,338,368 |
| reserved visible-Fp charge per attempt | 234,342 | 297,510 |
| full attempts before lifecycle reserve or margin | **43** | **11,876** |

These are provisional ceilings, not selected service lives: the paper counts
distinct alphabet locations, whereas C7 conservatively burns every visible
base-field occurrence and forbids cross-attempt refunds.  The exact
cross-round load refinement, init/rotation charges and positive privacy margin
can only tighten the admitted row.  Under the selected 32-byte seed, without
persisting the expanded random coefficients, the power-of-two tree geometry
permits the following full-opening-reservation controls within each setup tier:

| Geometry-only tier | GPT-2 attempts | GPT-2 persistent | 31B attempts | 31B persistent |
| --- | ---: | ---: | ---: | ---: |
| target 2.00x | 616 | 491,686,208 B | 11,876 | 92,844,619,328 B |
| tolerance 2.10x | 616 | 491,686,208 B | 127,367 | 124,036,438,528 B |
| exploratory 3.00x | 1,761 | 735,372,288 B | 127,367 | 124,036,438,528 B |

The owner selects the seeded computational line represented by this geometry,
but the numeric attempt ceilings remain unadmitted until the exact load map
and lifecycle margin exist.  Persisting all uniform Fp mask coefficients is
retained as the information-theoretic baseline: its corresponding attempt
ceilings are **43/43/134** for GPT-2 and
**11,876/11,876/25,596** for 31B across the same three tiers.  The selected
32-byte seed removes that coefficient store, but its PRG advantage is now an
explicit term in the 78-bit lifetime budget and the ordered one-scan schedule
remains unproved.

Charging every compiled round for all `R_max=2^20` attempts gives the
provisional controls 245,725,396,992/311,961,845,760 random Fp coefficients
and 249,782,553,920/560,721,907,712 B of geometry
(1007.188x/9.095x), before coefficient persistence.  This full-round row
still awaits the cross-round load refinement.

The **NO-GO** does not depend on that missing sharing theorem.  The initial
`k0=4` oracle alone exposes a reserved 75,012 Fp positions per attempt.  For
its 16 dense interleaving lanes, `16*max_c load_c >= sum_c load_c`; every lane
needs at least its own queried-location load in RS randomness.  Concretely,
on distinct nonzero evaluation points with `q` below the lane message
dimension, the message Vandermonde has rank `q`, the mask image has rank at
most `r`, and privacy requires `im(G_message) subseteq im(G_mask)`; hence
`r>=q`.  Thus
`R_max` requires at least 78,655,782,912 random Fp coefficients even if every
later-round disclosure is free.  The corresponding GPT-2/31B geometries are
125,015,276,992 B (**504.094x**) and 186,420,076,992 B (**3.023708x**), both
above the absolute 3x caps.  Therefore one root for the full connection
horizon is NO-GO.  Root rotation is necessary, but its same-`W` bridge and
composition remain open; R0.8 neither tests nor credits refresh.  The setup
gate also remains false pending the exact full load refinement, concrete
generator advantage, an ordered rate-1/2 RS symbol generator with
one packed-source scan, and measured wall/RSS/temporary I/O.  Full codeword or
model-sized temporary materialization remains forbidden.

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
| 64 | 793,599,968 B | 197,288,959,968 B | reject; about 3.2x, above exploratory cap |
| 128 | 520,799,968 B | 129,470,879,968 B | baseline 2.10 boundary; only 32 B pre-metadata headroom |
| 129 | 518,685,280 B | 128,945,158,432 B | baseline tolerance band |
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
verification work, `q_init/q_rotate_in/q_rotate_out`, their typed privacy
charges, privacy/KS error and outstanding-receipt resolution; none is
amortized into a response certificate without an explicit allocation.  Every
disclosed failed candidate is stored as a sealed consumed epoch and counted in
`K_model`.
Neither `Q_root` nor a new root is free setup.  Response trace
storage is attempt-local.  The accepted K/V provider state persists only the
current canonical prefix and its commitment data; old proposed states are
deleted only after durable acceptance or recorded burn according to the
future R1 journal design.

### 6.7 Conditional security allocation

| Security item | Registered value |
| --- | ---: |
| attempts in connection horizon | `2^20` |
| root privacy budget / response attempts | `Q_root` / `R_root`, numeric values unselected; `u_init+A_rotate_in*u_rotate_in+A_rotate_out*u_rotate_out+R_root*u_W<=Q_root`, componentwise, with full burn |
| response/state privacy horizons | per-attempt `Q_B[a]` / per-created-root `Q_KV[s]`, unselected and not paid by `Q_root`; aborted successor roots are charged then sealed |
| model root epochs | `K_model`, unselected; counts every disclosed candidate, including failed/aborted rotation roots |
| MAC/key domains over model lifetime | `D_model`, unselected; multi-user VOLE/MAC composition unproved |
| response-local event budget cap | 64; registry incomplete |
| allocation per event | `2^-110` |
| `epsilon_response` | `2^-104` |
| leaf salt screen | 256 bits; 192 bits rejected |
| active hash/generator work bounds | `Q_CR / Q_hide / Q_saltPRF / Q_mask_words`, all unselected and distinct |
| root-mask privacy | selected 256-bit per-root seed; computational `Adv_RootMaskPRG_multi + K_seed_attempts*epsilon_rejection <= 2^-110`; primitive/work bound unselected |
| BLAKE3 fallback only | `R_root=512/8192`, global attempts `2^20`, `K_model=2048/128`, total seeds `4096/256`, model-wide `Q_mask_words=3,317,292,859,392/4,211,484,917,760`; complete target allocation is 86.407/86.063 bits and passes 78, but achieved terms remain nonnumeric/false |
| KMAC unpromoted high-margin control | same confirmed global horizon/profile; frozen 64-KiB v1 codec; conditional ideal-permutation PRG sum 152.992/152.647 bits and conditional whole-privacy allocation 107.415 bits; multi-key reduction/fixed-permutation advantage/setup measurement missing, so unpromoted/false |
| historical policy-3 salt screen | `Q_leaf=2^64`; not an active theorem cap |
| challenge mode / `Q_FS` | fresh honest-DV post-prefix interactive / `0`; future FS selects neither primitive now—KMAC favors margin, BLAKE3 throughput only with tightly preregistered `Q_FS`; entropy delivery and transcript binding not instantiated |
| inherited unamplified strict-UD Fp2 bound, rate 1/2 `k0=4` | certifies 97.017/89.087 bits across all GPT-2/31B folds; 77.017/69.087 after `2^20`, before other terms; insufficient for admission, not a security upper bound |
| algebraic closure | direct three-limb Goldilocks Fp3 selected; fixed-point schedules certify 160.011/153.173 response bits and 140.011/133.173 after `2^20` on this axis; Rust codec/KAT and the carrier-independent MAC equation seam pass, while PCS/PCG/VOLE refinement and all other bytes/work/security terms remain required |
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

This table covers only the terminal/RLC fixed-prefix residual.  It does not
amplify the strict-UD proximity-gap event: fresh interactive Fp2 challenges
leave only the inherited 97.023/89.006-bit all-fold certificate for the
rate-1/2 `k0=4` controls.

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
non-RLC terms; the 119-bit row is not a complete connection theorem and does
not cure the insufficient strict-UD proximity-gap certificate.

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
| multi-commit terminal MAC | extension-field key/MAC linearity under one `Delta`; `multi_commit_terminal_mac_equation_on_coordinates` is generic in `Fin d` and covers all three Fp3 limbs |
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
R0.6 added only the two natural-number policy-2 accounting lemmas above.  R0.7
adds no Lean wrapper: until the compiler types `S_visible_Fp` and the Pareto
rows, another arithmetic lemma would only duplicate `Finset.sum_le_sum` or
rename a cryptographic hypothesis.  The existing lemmas
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

## 8. R0.8 disposition and exact resume conditions

### 8.1 Backend/control recommendation

- **Policy 2: ACTIVE FOR DESIGN; NO EXECUTABLE BACKEND GO.**  Only budgeted root-bound
  masked PCS responses may be visible; the terminal evaluation stays
  authenticated.  Numeric counters remain fail-closed and unset.
- **RS t-query ZK + strict-UD WHIR/Ligerito: CONTROL BASELINE ONLY.**  Owner
  choice 2.A demotes it from selected carrier and forbids implementing its
  prover.  It retains the algebraic/security census and every rejection
  reason: missing `OnlineMDVViewRefine`, adaptive malicious-DV privacy,
  setup-safe one-scan opener and an admitted root horizon.
- **Root-mask realization: COMPUTATIONAL SEEDED LINE SELECTED.**  One private
  256-bit seed is persisted per root, with fixed addressed rejection sampling
  and no response reseed.  `Adv_RootMaskPRG_multi` plus rejection failure is
  included in the 78-bit lifetime budget with a provisional 110-bit component
  reserve.  The concrete primitive/work-factor theorem remains unselected;
  explicit uniform coefficient persistence is baseline evidence only.
- **Unamplified Fp2 strict-UD: NO-GO under current evidence, not declared
  insecure.**  The inherited all-fold bound does not certify the target; no
  tight attack or impossibility theorem is claimed.
- **Selected-schedule Fp2 audit: COMPLETE FAIL.**  The 31B schedule certifies
  89.087 response bits and 69.087 after `R_max=2^20`, before other terms.
  A modest relaxation to 104 or 98 cannot preserve the 78-bit connection
  target.
- **Direct Goldilocks Fp3: SELECTED FOR THE CODEC; ALGEBRAIC AXIS PASS.**  The
  31B schedule certifies 153.173 response bits and 133.173 after `R_max`.
  The carrier-independent Rust codec/KAT and shared-`Delta` equation seam now
  pass focused tests.  This is not full connection security: PCS/PCG/VOLE
  refinement, malicious-DV privacy and every other error term remain open.
- **Policy-2 reference seam: TINY CONFORMANCE PASS, NO PCS CREDIT.** The exact
  90-byte BLAKE3-XOF descriptor, public salted leaf/tree, `1296+32h` opening,
  fixed reservation versus actual-response census, abort burn, Fp3 terminal
  and in-memory KV replay/fork checks execute together. The tree/state are not
  streaming or durable, and no code, same-W extractor or privacy reduction is
  instantiated. This prepares a local test but does not authorize a
  `BatchOpenBlocks` prototype.
- **Two Fp2 repetitions: fallback only.**  It preserves the field but needs a
  new adaptive repetition/shared-scan theorem and conservatively doubles the
  query/privacy payload.  **Interactive PoW remains NO-GO** under `Q_FS=0`
  without a new computational soundness model.
- **Owner-selected compiler envelope:** starting rate 1/2, first fold `k0=4`,
  one flat packed weight oracle/root and the dense logical `g=141` stream.
  Pure-width optimization and both bounded alternatives are closed under the
  original 1.05 gate.  The Fp3 g141 opening subcodec now compiles
  `(q,Z,U,S)=(831,29192,1662,234342)` and
  `(1055,33848,2110,297510)`; all four growth ratios pass 1.30.  Known opening
  bytes are 2,605,740/3,729,724 B, but the non-oracle and receipt frames remain
  unknown, so the complete codec/wire gate is false.  Segmentation, another
  field and persistent row padding do not waive any unchanged gate.
- **Selected strict-UD RS realization: NO-GO.**  The root/codec fixed point
  requires `2^29/2^36` initial symbols.  Direct opening is qN; persisting the
  codeword is 19.301x/10.423x packed; online materialization is model-sized;
  and no exact `O(N+poly(q,log N))` shared schedule is registered.  Seeded
  BLAKE3/KMAC does not solve the RS linear map.  This is not a universal lower
  bound.  It is retained only as the control above.
- **New-carrier tournament: BOUNDED SCREEN CLOSED, NO ADMITTED CARRIER.**
  Owner choice 1.A retained published controls and a co-designed main line,
  then D111 allowed exactly one concrete candidate. R0.8g spends that slot on
  direct packed Bolt-min and rejects it below. Pure fold width, the two bounded
  R0.7 alternatives and prior families remain closed. A further carrier or
  non-affine line requires a new owner decision; no generic search continues.
- **`C7-BOLT-MIN-G141-v0`: DIRECT CODE-SWITCH NO-GO.**  It avoids C6's
  eight/six-body WHIR wrappers and has a q-independent source-linear term.
  Its optimistic persistent setup is 2.590x/2.637x packed, but row-major setup
  requires model-linear syndrome state, column-major query frames exceed the
  certificate caps, and a transpose exceeds 3x. Every response creates a
  50.332-MB/12.885-GB fresh Fp3 RS word. The transferable Goldilocks distance,
  hiding, same-W MAC bridge and stateful malicious-DV theorem are absent.
- **`C7-SPBT-v0`: ALGEBRA RETAINED; CARRIER LINE CLOSED.**  Its
  invertible complement transform preserves ordinary independent GKR
  challenges and gives one degree-`<M` secret-point identity.  The algebra,
  inverse, coefficient count, conditional 144/137-bit lifetime margins and
  one-source-scan butterfly schedule pass.  The complete row fails: sampling
  `tau` before the transform root is unsound; retaining the root payload costs
  at least 9x packed; recomputation is a second scan; hidden-`tau` streaming
  still needs a sublinear malicious OPE/inner product into MAC. R0.8f shows
  that the `tau`-independent affine native-VOLE form needs linear online
  corrections; even the optimistic Fp control is already 5x if persisted
  packed. Raw Merkle sampling has no distance. No code or CPU credit follows.
- **`C7-StreamOpenIntoMac-v0`: NATIVE VOLE/MAC NO-GO.** For `tau`-independent affine online
  corrections `A(x-r)`, exact evaluation at all secret points implies the
  Vandermonde query family lies in `row(A)`, hence `rank(A)>=M` and linear
  wire. Optimistic GPT-2/31B base-Fp floors are 992 MB/246.6112 GB, while moving them to
  setup is 5x packed before tags/tree. This is a scoped native-VOLE/OLE rank
  result, not a universal PCS or 2PC lower bound.
- **`C7-DV-SPQ-v0`: QUARANTINED TERMINAL PRIMITIVE.**  Its ideal equation
  retains conditional Fp3 margin, but the R0.8d logistic composition is
  constructively unsound and R0.8e does not instantiate its same-`F`
  enrollment or succinct opening. It remains only a quarantined reference;
  it is not an active SPBT terminal after the carrier line closes.
- **R0.8b co-designed bounded rows: NO-GO.** A single `X^B-c` coset has the
  desired one-scan evaluator but only one worst-case soundness hit; independent
  amplification restores `tN`. Persisted rate-1/2 field parity is 5x packed
  before the tree. A packed-order causal encoder with bounded delayed tail has
  sublinear distance. These scoped rejections do not prove that no suitable
  shared circuit exists.
- **ERA `r=4` + salted BLAKE3: byte/prover control only.**  Its published
  field-query law grows with `log N`, its masked encoding is unproved here,
  and its N-scale setup intermediates remain excluded.
- **Historical policy-3/Poseidon2 and one-stage RA lines: terminal NO-GO.**
  Their checker cost, distance and ordered-root failures remain recorded.

### 8.2 Resume conditions for an R1 proposal

Policy 3 remains terminally rejected and policy 2 is active.  Strict-UD RS is
now only the control baseline; R0.8f closes SPBT as a carrier and R0.8g closes
the authorized one-candidate direct-Bolt screen with no admitted entrant.
SPBT and Bolt's setup-size control remain reusable evidence only and do not
weaken any recorded rejection.
The selected challenge baseline remains interactive
honest-DV (`Q_FS=0`) and logical `g=141`.  Setup retains its 2.00 target/2.10
baseline, with a conditional exploratory 3x ceiling plus absolute disk,
setup-wall and refresh-wall caps.  Proof wire retains 105% as target and may
use a preregistered 125--150% cap only under complete 35/115-MB and 3.5x
limits.  The four componentwise query-growth counts use the distinct 1.30 hard
ceiling.  The
fail-closed readiness handoff is
`docs/c7-r03-prover-pod-handoff.md`.  Preparation does not authorize a large
prover/E2E, pod contact or pod execution.

Both bounded post-Pareto alternatives and the one-candidate tournament are
closed. C7 is blocked: there is no generic R0.8h, prototype or further gate
relaxation. A named candidate needs a new owner decision and must satisfy all
four R0.8a screen obligations before even a tiny CPU prototype. The tested Fp3
codec/MAC seam is expressly carrier-independent and is not such authorization.
Fp3, 78 connection bits, setup 900/990 and
5,400/5,940 seconds, separate untested refresh counters and computational
per-root masks otherwise remain fixed.  Any successor must serialize and
authenticate all three base-field limbs directly under the connection-scoped
MAC domain; there is no Fp2 embedding, limb truncation or hidden second
terminal.  Pure fold-width search and the already bounded alternatives stay
closed.  Before an R1 proposal the successor must supply all of:

1. exact plane-tagged GPT-2/31B `q_attempt/q_response` vectors,
   theorem-defined weight `Q_root`, response `Q_B` and state `Q_KV` horizons,
   typed `q_init/q_rotate_in/q_rotate_out` and
   `u_init/u_rotate_in/u_rotate_out`, derived `R_root` after lifecycle reserve,
   positive privacy headroom, distinct
   `Q_CR/Q_hide/Q_saltPRF/Q_mask_words`, a concrete multi-root PRG advantage
   meeting its 110-bit component reserve, bounded `D_model`, and a bounded
   `K_model` or multi-root theorem;
2. an executable canonical compiler with terminal multiplicity exactly one
   for every physical weight, boundary and K/V segment, plus the complete
   ordered `omega`, profile and authenticated single-session
   reservation plus no-extension plane-assignment receipts, durable W/B/KV
   high-water maps and state machine;
3. a proved/checked extension-field ALFC adapter under one shared `Delta` per
   MAC domain, all selected extension limbs, every allowed oracle response, and a
   multi-user composition covering all `D_model` colluding domains;
4. `C7_CPU_REFERENCE_PASS`: a derived and executable one-pass bounded-memory
   `BatchOpenBlocks` schedule with exact operations/setup/oracle/online I/O;
5. the paired-history policy-2 adaptive malicious-DV lifetime theorem with
   complete branch-derived-view closure, honest-allocator privacy integrity,
   dishonest-prover receipt unforgeability, global receipt CAS/cache
   rollback-fork protection, full burn, and a private
   `RotateSameW` bridge with two-sided pre-byte reservations, disclosed
   candidate/abort/retry accounting, stop-admit/outstanding-attempt resolution
   and atomic cutover;
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
- R0.7 owner-selects the RS t-query-ZK/strict-UD theorem carrier, provider-owned
  allocator and Pareto-before-caps order.  The formula census exposes the
  non-adaptive-HVZK gap, the retained post-first-fold domain rule, unamplified
  Fp2 algebraic-security failure, constant-schedule query-growth failures and
  dual-root rotation floor; no executable backend or lifetime cap is promoted.
- R0.8 fixes the codec/security/byte/resource output and retains rate 1/2,
  `k0=4`, one packed root, g141 and interactive `Q_FS=0`.  Its exact selected-
  schedule Fp2 audit fails 110/78 on 31B; setup-wall targets become 900/5,400
  seconds while tolerance and refresh caps await the owner decision.
- R0.8e adds only an exact analytic reduction and budget-v27 self-check.  It
  preserves independent GKR challenges and one packed source scan, but the
  delayed opening is not constructed; no Lean/Rust/prover/SIMT code follows.
- R0.8f adds only the ideal `StreamOpenIntoMac` relation, a scoped affine-VOLE
  rank obstruction and budget-v28 cost checks. It closes SPBT as a carrier
  without claiming a universal PCS/2PC lower bound; no prototype follows.
- R0.8g screens only one direct packed Bolt-min topology.  It avoids C6's
  multi-WHIR wrapper and transfers no historical credit.  Its setup-size
  control is below 3x, but the one-pass layout, fresh Fp3 codeword, Goldilocks
  query wire and malicious security/privacy rows fail; no prototype follows.
- The proof-byte table is a target allocation calibrated to public component
  evidence, not a composed certificate derivation.  It is `credit:false` and
  is one reason Backend A remains NO-GO.
- No pod, production provider, frozen forward, quantization spec, or frozen
  M1--M12 statement was touched in R0/R0.1/R0.2/R0.3/R0.4/R0.5/R0.6/R0.7/R0.8.

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
| `C7-D060` / 2026-08-26 | select theorem carrier, not backend | Owner selects RS t-query ZK plus strict-UD WHIR/Ligerito and public salted BLAKE3 as the theorem carrier; ERA `r=4` remains only a byte/prover control. No concrete codec, field, one-scan opener or prover is admitted. |
| `C7-D061` / 2026-08-26 | select provider-owned allocator trust boundary | The model owner/provider is the one global linearizable allocator authority across identities, connections and replicas. Privacy is conditional on `AllocOK`; receipt EUF protects soundness against a dishonest proof worker, but receipts cannot repair a corrupt/forkable allocator or a worker that also controls the authority's signing key. |
| `C7-D062` / 2026-08-26 | require Pareto before numeric lifetime caps | `Q_root`, `R_root`, `K_model` and `D_model` remain unset until one coherent candidate has a complete provenance-tagged vector for query atoms, wire, setup/rotation, online work/memory, verifier, security and service life. Security-invalid rows are discarded first; unknown prevents PASS/dominance; no scalar score or tolerance transfer is allowed. |
| `C7-D063` / 2026-08-26 | do not promote CFW HVZK to stateful privacy | 2026/391 Proposition 3.19 gives fixed-set RS t-query ZK with error zero, while Definition 4.7 is non-adaptive and interleaving widens an answer by `2^k`. A paper query therefore is not an Fp privacy atom. Admission requires `C7-OnlineMDVViewRefine` plus a codec load map for every correlated RS component and abort prefix. |
| `C7-D064` / 2026-08-26 | distinguish published smooth-domain scope from retained interleaving | The initial rate-1/2 oracle has `2^28`/`2^36` scalar positions, but retained WHIR groups width `2^k0` before the base-field DFT and guards `D+r-k0<=32`. The 31B control is field-valid at `k0>=4` for rate 1/2 (`>=5` for rate 1/4). Published Goldilocks benchmarks omit initial exponents above 32, so they provide no evidence for this retained row. A new field or segmentation is fallback, not forced; the interleaved theorem/codec bridge and all g141 counters remain open. |
| `C7-D065` / 2026-08-26 | retain setup/rotation and constant-schedule failures | The rate-1/2 digest-only static floors are 1.4913x/1.5059x, but dual-root rotation is 1.9826x/2.0119x before metadata; rate-1/4 dual-root rotation is about 2.9652x/3.0237x and is rejected. Representative strict-UD constant schedules grow 1.267–1.307x in logical samples and 1.318–1.346x in the unstacked Fp control, above 1.05, including the field-valid rate-1/2 `k0=4` row. These are optimistic formula controls, not an impossibility proof or compiled census. |
| `C7-D066` / 2026-08-26 | defer new Lean arithmetic | Existing policy-2 Nat lemmas already express fixed reservation and conservative weighting. Until the compiler types the Fp occurrence/load relation, another weighted-sum/Pareto wrapper would be tautological and could double-count g141/Fp2; the next Lean statement follows the concrete codec. |
| `C7-D067` / 2026-08-26 | count multi-user composition exactly once | This refines D053's schematic wording: `Adv_MultiUserVOLE_MDV(D_model,{J_d})` and `Adv_MultiUserMAC(D_model,{J_d})` each own their full domain composition once. A separate per-domain union is added only if the eventual theorem exposes it as an additional term; otherwise adding both would double-count rather than add security. |
| `C7-D068` / 2026-08-26 | inherited Fp2 strict-UD bound is insufficient | The 110-bit formula input covers query misses only. For `p=2^64-2^32+1`, the retained analysis proves `epsilon_gap<=2^(D+r)/p^2`; the first GPT-2/31B challenge certifies 99.9999999993/91.9999999993 bits, not an upper bound on real security. `bit_length(p^2)=128` is not used as a denominator. Unioning the 24/32 folds of the rate-1/2 `k0=4` controls certifies 97.023/89.006 bits and 77.023/69.006 after `2^20`, before other terms, so current evidence cannot establish the registered targets. No tight attack is claimed. Admission requires a tighter proved bound or fully charged independent repetition/Fp3; interactive PoW has no statistical amplification under `Q_FS=0` without a new computational theorem. |
| `C7-D069` / 2026-08-26 | keep dense g141 packing across interleaved rows | Width-`2^k0` rows are serialized into the canonical dense g141 stream and may cross leaf boundaries; every touched leaf is charged (at `k0=4`, at most two per row before union). Persistent row-alignment padding would alter committed/setup bytes and violates the fixed logical format. Only temporary measured SIMT padding remains permitted. Exact row-to-leaf union is a compiler cell, so this decision creates no backend credit. |
| `C7-D070` / 2026-08-26 | reserve setup/rotation leakage and count disclosed candidates | Response charge `u_W` alone does not cover setup validation or `RotateSameW`. Every epoch has typed `u_init/u_rotate_in/u_rotate_out`; both old and candidate records reserve before the first W-dependent bridge/root byte, and abort/retry burns in full. A zero charge needs an authenticated-only zero-visible-query theorem. Every disclosed candidate, activated or not, is sealed and consumes `K_model`; retries require fresh candidate capacity. The componentwise invariant is `u_init+sum u_W+sum u_rotate_in+sum u_rotate_out<=Q_root`. |
| `C7-D071` / 2026-08-26 | select one bounded strict-UD audit, then automatic Fp3 analytic fallback | The current Fp2 formula is an insufficient certificate, not evidence of an attack. One audit may tighten only the retained strict-UD all-fold argument, must be schedule-parametric and must certify the eventual 31B schedule inside the rate-1/2/first-`k0=4` envelope at 110 bits without conjectural/list-decoding assumptions. The constant-`k=4` row is only a known-failing query control. Failure selects the already charged Goldilocks Fp3 control; it does not reopen interactive PoW or an unbounded paper search. |
| `C7-D072` / 2026-08-26 | use a direct three-base-limb terminal if Fp3 is reached | The conditional Fp3 path serializes and authenticates all three canonical base-field limbs under the connection-scoped MAC domain, and requires matching three-limb key/MAC linearity plus codec/privacy refinement. An Fp2 wrapper, truncation or two hidden terminal settlements would obscure bytes and assumptions. This is a design selection only; no Fp3 theorem or implementation is credited. |
| `C7-D073` / 2026-08-26 | fix the compiler envelope, not a known-failing constant schedule | Starting rate 1/2, first fold `k0=4`, one packed root and dense g141 are fixed because they are the least-setup retained field-valid 31B envelope. The constant-`k=4` tail is explicitly rejected: its 1.267x logical-sample and 1.318x Fp-position growth violate the 1.05 gates. Tail scheduling/query sharing remains unselected and must pass all four gates before CPU work. Segmentation, another base field and row padding neither waive nor inherently repair query growth. |
| `C7-D074` / 2026-08-26 | include every lifecycle VOLE/MAC domain in `D_model` | `D_model` is the union of key-tape domains instantiated anywhere in the model/state lifetime: weight or K/V setup/init, response attempts and inbound/outbound rotation bridges, including failed/aborted attempts; `J_d` counts their reserved/consumed correlations and burned suffixes. Counting only domains that return an attempt-local response would omit lifecycle composition. A phase may contribute zero domains only under a codec theorem proving zero VOLE/MAC domain and zero correlation use; its PCS leakage still pays the typed plane charge. |
| `C7-D075` / 2026-08-26 | reject pure variable-fold tuning under Pareto/no-padding | Exact DP over every integer tail after rate 1/2/first-`k0=4` finds no Pareto GPT-2/31B pair meeting both 1.05 gates. Fp2's best pair is `(831,19104)` versus `(1054,24128)`, or 1.268x/1.263x; its separate large-model gaps are 17.215% in logical draws and 16.863% in visible Fp positions, with 17.215% only the uniform common factor. Fp3 is 1.270x/1.276x with gaps 17.294%/17.707% and therefore does not fix query growth. The axes are non-fungible. Dummy queries or dominated GPT-2 schedules merely game the denominator and are rejected. Index or Merkle-path sharing alone cannot lower visible Fp atoms. A survivor needs proved cross-round joint sampling plus visible-symbol sharing, or a genuinely different code-switch; this is not a universal WHIR lower bound. |
| `C7-D076` / 2026-08-27 | reject bounded cross-round joint sampler at 1.05 | Balanced shared paths can genuinely derive at most 1,130/1,576 adjacent Fp positions, leaving 17,974/22,552 (1.255x), but canonical openings remain 831/1,054 (1.268x) because every round/root fiber is distinct. Shared seeds are not shared PCS openings and roots do not share paths. Soundness needs all roots fixed before paths plus a new delayed strict-UD/RBR extractor; privacy needs `im(A_T G_W) subseteq im(A_T G_R)` for every adaptive abort prefix, not fixed-set RS t-query ZK. Sequential challenges also lack a one-scan/no-folded-oracle schedule. The result is bounded-family NO-GO, not an impossibility theorem. |
| `C7-D077` / 2026-08-27 | reject bounded different-code-switch set | ERA-to-BaseFold's optimistic exact control has `q=2370/3602` (1.520x), Fp 68,612/71,076 (1.036x), setup floor 2.4667x and a 6.25x packed-byte 25-stack; q, setup and one-scan fail. SwitchFold/QAFold/BrakeFold lack an exact C7 census and retain auxiliary/carry roots, full encodings, large memory, clear evaluations and no privacy/terminal bridge. 2026/391's `35/27` alphabet-width asymptotic is not an exact row and supplies HVZK rather than adaptive malicious-DV privacy. LigeSIS retains a full RS/secondary PCS setup; ITC3 is univariate. None is complete even under 1.30. |
| `C7-D078` / 2026-08-27 | supersede only the query-growth gate with owner 1.30 fallback | After both 1.05 screens returned NO-GO, the owner authorizes a componentwise 1.30 hard ceiling for `q_open`, `Z_atom`, `U_leaf` and `S_visible_Fp`. The Fp2 controls 1.268351x/1.262982x pass with 26/707 integer units of headroom and select the existing Pareto pair only as a formula query-axis candidate. The 105% weight-wire ceiling, 30/100-MB and 3x certificate gates, setup 2.00/2.10, one-scan/bounded memory and 110/78-bit security are unchanged and non-fungible. Dummy denominator padding remains forbidden. |
| `C7-D079` / 2026-08-27 | correct Fp-control semantics and constrain Fp3 | The DP's `Fp_positions` is an unstacked field-position formula control, not the compiled g141 payload `S_visible_Fp`; exact `Z_atom`, `U_leaf`, `S_visible_Fp=141*U_leaf`, paths and bytes remain unknown, so the four-axis 1.30 gate is still fail-closed. Fp3 can discharge only the algebraic-security axis and must independently pass the same complete codec/resource census; it cannot promote a row by field choice alone. |
| `C7-D080` / 2026-08-27 | relax proof-wire as a conditional exploratory envelope | The former 105% hard ceiling becomes the target. A candidate may preregister one exact hard cap in 125--150% before compiled measurement, but only if the complete proof also stays within 35 MB GPT-2, 115 MB 31B and 3.5x growth. Above 150% fails. The band cannot pay another component or supply privacy/soundness credit; exact cap and full codec bytes remain fail-closed in R0.7. This supersedes D018/D026/D078 only on proof-wire resource tolerance and retains their accounting reasons. |
| `C7-D081` / 2026-08-27 | add conditional near-3x setup exploration | Setup keeps 2.00 as target and 2.10 as baseline tolerance, while adding `A_setup<=3.00` as an exploratory ceiling. For the fixed workloads this gives absolute persistent-disk caps 744,000,000 B / 184,958,400,000 B. Absolute setup-wall and refresh-wall seconds must be preregistered before measurement; they remain unset until an R0.8 candidate/owner SLA exists, so the exploratory gate is false. All temporary disk, traffic, peak memory and refresh work remain counted, and X4d-scale expansion/unbounded scratch remains rejected. This supersedes D017/D043/D078 only on the setup ratio. |
| `C7-D082` / 2026-08-28 | open R0.8 without changing the carrier envelope | R0.8 is design/analytic-only and must output the canonical codec, security-event registry, serialized bytes and resource row. RS t-query ZK + strict-UD WHIR/Ligerito, rate 1/2, `k0=4`, one packed weight root, logical `g=141` and fresh interactive `Q_FS=0` remain fixed. No prover, SIMT, E2E or pod is authorized. |
| `C7-D083` / 2026-08-28 | strict-audit Fp2 before any Fp3 transition | The selected schedules certify 97.017/89.087 all-fold response bits and 77.017/69.087 after `R_max=2^20`. The 31B row fails both 110 and 78 before other terms. A 104- or 98-bit response relaxation cannot repair it. A bare 78-bit lifetime permits at most 2,175 attempts and an 84-bit intermediate target only 33; these are screens, not selected horizons. Field degree remains Fp2 until the owner chooses Fp3, a materially shorter horizon, or a weaker connection target. |
| `C7-D084` / 2026-08-28 | register setup-wall targets but not post-hoc tolerance | GPT-2/31B setup-wall targets are 900/5,400 seconds. The owner requires tolerance, but its numeric hard caps and the separate refresh targets/caps remain unset and fail-closed. Persistent-disk 3x, temporary disk, traffic, peak memory and invalidation remain independent conjunctive gates. |
| `C7-D085` / 2026-08-28 | select direct Fp3 and retain 78 connection bits | The owner rejects shortening the horizon or weakening the target. On schedules `[4,5,3,3,3,3]` and `[4,3,3,3,4,4,4,4]`, the exact inherited `p^3` all-fold bound certifies 161.017/153.173 response bits and 141.017/133.173 after `R_max=2^20`. This passes only the algebraic-gap axis. Full connection security remains false pending concrete Fp3 arithmetic/serialization, shared-Delta terminal soundness, complete codec, malicious-DV privacy and every other error term. |
| `C7-D086` / 2026-08-28 | fix independent setup and refresh clocks | GPT-2 setup target/hard cap is 900/990 s; 31B is 5,400/5,940 s. Refresh receives separate counters and the same initial numeric pairs, cannot borrow setup budget, and is explicitly not tested or credited in R0.8. This supersedes D084's unset cells without changing persistent disk, temporary I/O or peak-memory gates. |
| `C7-D087` / 2026-08-28 | compile the Fp3 g141 opening reservation but not the full codec | Conservative GPT-2/31B counts are `q_open=831/1055`, `Z_atom=26528/33848`, `U_leaf=1662/2110` and `S_visible_Fp=234342/297510`; growth is 1.269555x/1.275935x/1.269555x/1.269555x, so all four owner 1.30 gates pass without denominator padding. Exact compact-tree sibling caps are 19,335/39,843 and known serialized opening bytes are 2,552,532/3,729,724 B. The latter fit the 105% targets only in isolation: strict-UD non-oracle/OOD frames, authenticated reservation/assignment receipts and root-hiding capacity metadata remain unknown, so complete codec, certificate and backend gates stay false. |
| `C7-D088` / 2026-08-28 | pin canonical Fp3 and generalize the Lean coordinate consequence | Select `Fp[u]/(u^3-2)`, canonical `le64(a0)||le64(a1)||le64(a2)` with each limb `<p`, and reject noncanonical 24-byte encodings. Since `p mod 3=1` and `2^((p-1)/3) mod p=2^32-1!=1`, 2 is a non-cube and the cubic is irreducible. The terminal uses one shared `Delta in Fp3`, one 24-byte correction and no clear evaluation; three independent Fp MACs are forbidden. `multi_commit_terminal_mac_equation_on_coordinates` is generalized from `Fin 2` to `Fin d`; the focused C7 Lean build passes. Rust codec/KAT and the concrete terminal refinement remain unimplemented and uncredited. |
| `C7-D089` / 2026-08-28 | recompute interactive versus Fiat--Shamir on selected Fp3 | For one fixed prefix and `T=512`, fresh interactive Fp3 has 183.000 effective bits and serializes 24 B/draw. Direct FS under the analytic `Q_FS=2^64` control has 119.000 bits; paired FS has 302.000 only if one frozen paired-RO invocation yields two independent challenges checking the same relation. Connection composition is separate. Both FS rows remain unselected: their nonce/hash scope and exact duplicate/shared response, path, MAC, scan and byte costs are uncompiled, and neither improves malicious-DV privacy or the root budget. `Q_FS=0` remains fixed. |
| `C7-D090` / 2026-08-28 | quarantine the apparent 1.49x/1.51x setup pass | The 369,843,104/92,844,619,296-B rows count packed i16, one rate-1/2 compact g141 tree and root metadata only. They are pre-mask-capacity lower bounds, not complete setup: the RS t-query ZK randomness dimension and any persistent payload/index bytes are unknown. Those bytes cannot be hidden behind a digest root or preprocessing label. Until capacity plus ordered one-scan generation, temporary I/O, RSS and wall are derived, setup remains false even though the known floor is below 2x; any X4d-scale expansion remains rejected. |
| `C7-D091` / 2026-08-28 | bound RS mask capacity and reject one root for `R_max` | Proposition 3.19 requires randomness length `t` for perfect t-query RS privacy, so `ell>=W+t` and a rate-1/2 oracle has `2*ell` symbols. Conservatively charging all visible Fp occurrences gives zero-tree-growth ceilings of only 43/11,876 attempts for GPT-2/31B. Geometry-only 2.00/2.10/3.00x ceilings are 616/616/1,761 and 11,876/127,367/127,367 attempts; explicit persistence of uniform coefficients lowers them to 43/43/134 and 11,876/11,876/25,596. These are not admitted `R_root`: paper alphabet queries still need the g141/interleaving load refinement, and lifecycle reserve/margin can only reduce them. The full-opening control is 1007.188x/9.095x. Independently, the initial 16-lane oracle alone reserves 75,012 Fp positions per attempt; `16*max load>=sum load` forces at least 78,655,782,912 random coefficients over `2^20` attempts, yielding 504.094x/3.023708x geometry. Hence one root for `R_max` is NO-GO even if all later rounds are free. Rotation is necessary but refresh remains untested; a short seed requires a separately charged computational PCG/PRG and one-scan random-access refinement. |
| `C7-D092` / 2026-08-28 | select computational per-root seeded masks and retain explicit coefficients as baseline | The main line persists one fresh private 256-bit seed per disclosed candidate root, never reseeds per response, and declares weight-root privacy computational. Fixed addresses include model/epoch/layout/field/rate/k0/coefficient/draw indices. Six addressed 64-bit Goldilocks rejection draws give exact ideal Fp coefficients conditioned on success and per-seed failure bounds of 163.379/156.859 bits at the largest GPT-2/31B geometry-only capacities. The model-lifetime privacy theorem must include `Adv_RootMaskPRG_multi(K_model,{Q_mask_words}) + K_seed_attempts*epsilon_rejection <= 2^-110` as one component inside the 78-bit bound, distinct from salt PRF and VOLE PCG. The concrete generator and multi-key work-factor bound remain unselected, so security and setup stay fail-closed. Persisted uniform coefficients remain the information-theoretic baseline only. The seed adds 32 persistent bytes per root; setup occurs once per root epoch and refresh remains rare by design but untested and not a security assumption. |
| `C7-D093` / 2026-08-28 | quarantine existing generators for the C7 root-mask role | Repository reuse was audited before selecting a new primitive. `volta-field::FpStream`/ChaCha8 is rejected because it is explicitly a mock-PCG stand-in, has an unbounded sequential rejection loop and no C7 multi-root theorem. `volta-pcg` AES-128-MMO is quarantined because its registered scope is fixed-key 16-byte WYKW GGM-node expansion, not a 256-bit addressed root-mask function; the non-default 16-byte BLAKE3 GGM path is quarantined for the same scope mismatch. No claim is made that these primitives are broken in their registered roles. Public salted BLAKE3 remains selected for the separate leaf/tree commitment role. Resume requires a primitive-specific `Adv_RootMaskPRG_multi(K_model,{Q_mask_words})` bound before implementation. |
| `C7-D094` / 2026-08-28 | select keyed BLAKE3-XOF candidate order without lowering security | Keyed BLAKE3-XOF is the primary root-mask candidate for speed, seekable addressed output and parallelism; KMACXOF256 is the fallback, then the root-attempt horizon may be reduced and all RS/setup budgets recomputed. The connection target stays 78 bits. BLAKE3's specification targets 128-bit security and does not turn its 256-bit key into a 256-bit security claim or supply C7's quantitative multi-root theorem. Thus only 18 bits (`2^18` factor) of compositional loss can fit before the `2^-110` PRG reserve. `Q_mask_words` counts all generator words consumed by setup, not merely visible PCS queries absent a tighter proof. Under a linear-loss control, the 262,144-word ceiling barely exceeds GPT-2's conservative 234,342 one-attempt charge but is below 31B's 297,510; this is not terminal because the charge-to-theorem mapping is open. At exploratory 31B geometry the first-draw floor already exceeds `2^35` words. BLAKE3 and KMAC remain candidates with `credit:false` until their exact multi-root bounds and setup-wall rows pass. |
| `C7-D095` / 2026-08-28 | compile maximum preregistered root-profile proposals including failures | Post-hoc averages/refunds are forbidden. Proposed GPT-2/31B profiles use `R_root=512/8192`, include every accepted/failed/retried/selectively aborted response attempt, reserve a separate 1/8 attempt-equivalent margin for lifecycle/load refinement, and cap setup at two fully charged seeds. This gives proposed scalar `Q_root=134,980,992/2,741,852,160` and worst-case six-draw all-seed `Q_mask_words=1,619,771,904/32,902,225,920`; both fit target-2.00x RS capacity with 9,454,464/791,486,208 coefficients left. A linear `Q/2^128` proof form certifies only 97.406/93.063 bits, below 110. The proposals remain owner-unselected and unadmitted because the plane/lifecycle split and exact BLAKE3 multi-root theorem are missing. |
| `C7-D096` / 2026-08-28 | authorize a full-78 BLAKE3 fallback without relaxing mainline 110 | The owner authorizes D095's numeric profiles only as a computational fallback. Mainline root-mask PRG remains `<=2^-110`. The fallback caps all model-variant attempts across connections at `2^20`, yielding `K_model=2048/128`, total seed attempts 4096/256 and model-wide `Q_mask_words=3,317,292,859,392/4,211,484,917,760`. The named, non-theorem `Q/2^128` BLAKE3 control plus rejection gives 86.407/86.063 bits: it fails mainline 110 but does not alone exceed `2^-78`. Fallback admission requires the exact BLAKE3 multi-root term and every RS-view, salt/hash, PCG/VOLE, MAC, allocator/state, replay/fork, abort/timing and codec term to be numeric and their exact sum `<=2^-78`. They are not, so the variant remains fail-closed and unimplemented; failure promotes KMACXOF256 or reduces `R_root`. |
| `C7-D097` / 2026-08-28 | confirm one global model-wide fallback horizon | The owner confirms that `2^20` is the irrevocable aggregate maximum for the model privacy variant across all connections, users, accepted responses, failures, retries and selective aborts, not a per-connection allowance. This fixes `K_model=2048/128` for the fallback profiles and forbids resetting the lifetime by opening a new connection. |
| `C7-D098` / 2026-08-28 | compile but do not promote chunk-addressed KMACXOF256 | The 64-KiB `C7-RM-KMACXOF256-v1` codec uses a 104-byte root descriptor plus `le64(chunk)`, exact ordered six-draw word mapping and independent KMAC calls for bounded-memory CPU/SIMT equivalence. Two-seed root-construction controls are 12,958,175,232/263,217,807,360 generator bytes and 95,699,420/1,943,930,342 Keccak-f[1600] permutations. Zero persistent codeword does not pay the still-unknown online `BatchOpenBlocks` mask contribution; it must separately meet one scan, `O(N+poly(q,log N))` and bounded memory. Under an unselected `2^64` adversarial-permutation screen, the generic ideal-permutation PRG sum is 152.992/152.647 bits and conditionally passes 110; adding every registered other-privacy target gives 107.415 bits and conditionally passes 78. Neither is security credit because the adaptive multi-key KMAC-to-fixed-Keccak reduction, numeric fixed-permutation advantage, achieved non-generator privacy terms, online schedule and measured setup wall are missing. BLAKE3 remains the named primary order; KMAC is an unpromoted mainline alternative. |
| `C7-D099` / 2026-08-28 | separate complete privacy allocation from theorem discharge | Six non-generator terms receive target cap `2^-110`, allocator/state and replay/fork receive `2^-120`, and codec/transcript refinement must be exact. Adding every target gives 86.406856/86.062533 bits for the BLAKE3 fallback and 107.414568 bits for the conditional KMAC row, so both allocations pass 78. `complete_privacy_passes_78` remains false: a numeric target is not an achieved advantage, and promoting it would hide the missing adaptive RS-view, PRF/hash, PCG/VOLE/MAC, allocator/state, abort/timing and codec theorems. |
| `C7-D100` / 2026-08-28 | freeze KMAC v1 and privacy allocation without changing the primary | The owner freezes the 64-KiB `C7-RM-KMACXOF256-v1` chunk/descriptor and approves D099's target allocation, while reconfirming BLAKE3-XOF as primary for performance and parallelism and KMAC as an unpromoted high-margin control. Current challenges remain interactive with `Q_FS=0`. Future Fiat--Shamir selection is separate: KMAC is favored when security margin dominates; BLAKE3 is favored for throughput only under a tightly preregistered `Q_FS` and complete ROM/multi-target/proof-byte sum. Root-mask expansion and transcript hashing remain distinct domains and cannot share an advantage bound implicitly. |
| `C7-D101` / 2026-08-28 | close the root-profile/codec fixed point | D085/D087 used GPT-2's pre-mask `2^27` geometry, but selected `Q_root=134,980,992` requires `2^28` total coefficients and a `2^29`-symbol rate-1/2 oracle. Recompilation changes the GPT-2 schedule to `[4,5,3,3,3,4]`, `Z_atom` to 29,192, sibling cap to 20,997, known bytes to 2,605,740, algebraic bits to 160.011/140.011 and selected setup to 491,686,208 B (1.982606x). `q/U/S` are unchanged. Gemma remains at `2^35`, and all four large/GPT growth axes still pass 1.30. Recomputing capacity returns the same selected dimensions, so the fixed point is closed. This supersedes D085/D087/D090 only for the active selected geometry; their pre-mask observations remain historical evidence. |
| `C7-D102` / 2026-08-28 | selected strict-UD RS realization NO-GO under online gates | The exact initial codewords are `2^29/2^36` Fp symbols. Direct dense opening is a qN control (not a lower bound on shared circuits); persisting codeword plus tree is 4,786,653,504/642,600,433,216 B, or 19.301x/10.423x packed and fails 3x; online materialization needs 4.295/549.756 GB scratch; and the bounded repository/paper screen contains no pruned/shared circuit with a q-independent source-linear term, one packed scan and bounded memory. BLAKE3/KMAC random access removes mask storage but does not evaluate the RS map. No complete row exists, so `C7_CPU_REFERENCE_PASS=false` and prover/SIMT/pod remain forbidden. This is not a universal lower bound. Resume requires an owner-selected new code-switch/shared circuit with exact bytes and `O(N+poly(q,log N))`, or an explicit relaxation of a recorded hard resource gate. |
| `C7-D103` / 2026-08-28 | choose 1.A/2.A/3.B: open a new-carrier tournament, demote RS, implement only the Fp3 seam | All resource and security gates stay fixed. The tournament admits only a genuinely new shared code-switch/circuit with an exact q-independent source-linear term, one monotone packed scan, bounded memory, complete g141 codec/bytes and policy-2 soundness/privacy bridge. Pure fold width and the already closed joint-sampling/code-switch families are not repeated; their original rejection reasons remain controlling. Strict-UD RS is retained solely as an algebraic/security baseline, and its prover is forbidden. The only implementation authority is carrier-independent: canonical 24-byte `Fp[u]/(u^3-2)` encoding/KAT and the shared-`Delta` equation seam. Focused Rust tests cover wrong length, noncanonical limbs, multiplication, two-commitment RLC linearity and correction mutation in each limb. This supplies no PCS, PCG/VOLE, malicious-DV theorem or protocol credit. No prover, SIMT, refresh, provider or pod is authorized. |
| `C7-D104` / 2026-08-28 | split the R0.8a tournament into published controls and a co-designed C7 main line | Published constructions serve only as baseline/control rows and require exact independently verifiable costs. The main research line is a new co-designed C7 shared circuit because no published row currently combines one scan, bounded memory, nearly linear online work, policy-2 privacy and stateful authentication. Co-design earns no credit by intent: before a tiny CPU prototype it must supply a complete algebraic relation/codec; exact query, byte, memory, setup and work counts; the soundness/privacy bridge to MAC, KV cache and a malicious verifier; and a proof of one packed scan in `O(N+poly(q,log N))`. Until all four pass, no prototype exists. SIMT, a complete prover, refresh and pod remain separately forbidden. |
| `C7-D105` / 2026-08-28 | implement only the policy-2 reference seam; reject three incomplete co-designed shortcuts | R0.8b fixes the exact 90-byte keyed `C7-RM-B3XOF-v1` descriptor/address map, six-draw rejection, public domain-separated salted BLAKE3 leaf/tree, canonical `1296+32h` single-leaf frame, distinct fixed `q_attempt` and actual `q_response`, nonrefundable abort burn, shared-`Delta` Fp3 terminal and in-memory accepted-KV CAS. The tiny test covers KAT, codec/path/padding mutation, burn/accept/exhaustion and replay/fork. It remains `credit:false`: BLAKE3's multi-root theorem, a durable allocator/state store, PCS same-W binding, adaptive malicious-DV privacy and a one-scan opener are absent. The structured coset evaluator is `N+B log B` for one block but one coset supplies only one worst-case hit and `t` independent cosets restore `tN`; persisted rate-1/2 Fp parity is 5x packed before the tree; a bounded-tail causal packed-order encoder cannot have constant relative distance. These scoped rows are NO-GO and preserve their separate security/setup/distance reasons; they are not a general circuit lower bound. No `BatchOpenBlocks` prototype, SIMT, prover, refresh or pod is authorized. |
| `C7-D106` / 2026-08-28 | open the co-designed secret-point quotient line without relaxing gates | The owner permits a novel C7 construction even without a published instantiation. `C7-DV-SPQ-v0` becomes the main research candidate, not an admitted carrier. Its ideal root stores only secret shares of `F(tau)` and its online equation is `F(tau)-v=(tau-r)Q(tau)`, with all three values remaining under the connection MAC. The conditional Fp3 degree/attempt screen gives 155/144 bits per GPT-2/31B root profile and 135 bits after four roots over `R_max`; this receives no credit until transcript fixation and secret-view hypotheses are proved. The current `eq`-basis does not yet scalarize, and published algebraic-PRF, OLE/NIIP, Merkle-quotient, public-power, finite-pool and coset realizations fail or remain quarantined for their separately recorded setup, wire, pass, challenge-order or theorem gaps. Future root setup is isolated and immutable; an eventual online process is read-only, reserves before output, scans exactly once and burns on abort. No prover, SIMT, refresh or pod is authorized. |
| `C7-D107` / 2026-08-29 | accept the exact logistic `eq` bridge and reject its current public-GKR composition | For `r_k(t)=t^(2^k)/(1+t^(2^k))`, `eq(r(t),j)=t^j/D_n(t)` with `D_n(t)=product_k(1+t^(2^k))`. Thus each raw packed segment is already a univariate coefficient vector; one reverse scan conditionally costs `N+O(J log N_max)` with no Möbius transform, `L`, expanded wrapper or second packed read. This closes only the algebraic basis gap. Public sequential challenges on the curve are unsound: low-to-high reveals every future challenge; high-to-low exposes two-point square-root fibers, and the degree-two polynomial through those roots has `P(0)+P(1)=1`, letting a malicious prover carry then erase any false sumcheck gap. Any coordinate order eventually has a deterministic ascent or an adjacent descending pair. Independent challenges retain soundness but not scalarization; projective basis retains the correlation; all-variable univariate skip has linear degree/wire; bounded skips remain multivariate; secret challenges need a new secure operator protocol. The composed curve/current-GKR row is NO-GO, while the secret-point primitive remains quarantined research. Every resource/security gate and the ban on CPU prover, SIMT, refresh and pod remain unchanged. |
| `C7-D108` / 2026-08-29 | select `C7-SPBT-v0` as the main reduction candidate, not a carrier | For each independent GKR coordinate, the pair transform `Y=(1-r)E+rO`, `Z=E-O` has determinant `-1`. Recursing gives a bijection `W <-> (Z_1,...,Z_n,y)` with exactly `M` coefficients and `y=MLE(W,r)`, plus the degree-`<M` identity `P_0=D_n y+sum_l D_l c_l Z_(l+1)(X^(2^(l+1)))`. Fresh `tau` follows the transform commitment; every derived query vector is fixed before later beta RLC. The conditional error is at most `(M_max-1+J-1)/|Fp3|`, giving about 144/137 bits after `R_max` for the current GPT-2/31B controls. A binary carry stack computes all complements in one monotone packed scan with `M_total-J<2N-J` butterflies and logarithmic frontier state. Budget v27 checks the identity and inverse exactly. This repairs the R0.8d operator-challenge correlation without claiming a PCS or security theorem. |
| `C7-D109` / 2026-08-29 | current SPBT delayed-opening realizations NO-GO; retain every reason | Soundness requires the transform coefficients fixed before `tau`. Revealing `tau` first lets one of `M` free coefficients absorb any false terminal. Fixing `C_Z,e` first and retaining its typed dense payload costs exactly `16*M_total` bytes (at least 9x packed including source); discarding and recomputing requires a forbidden second source scan. Hidden-`tau` streaming is precisely a malicious private inner product/OPE into MAC and no sublinear-wire, no-per-coefficient-correction construction is supplied. A plain exact later-point sketch is information-theoretically injective; raw Merkle sampling has no distance and misses a one-leaf error with probability above 0.9995/0.999997 under the current query controls; a rate-1/2 wrapper restores the rejected codeword; a two-party sign/square-root orbit is at least 25x packed; finite point pools lack 110-bit entropy and worsen reuse privacy. Symbolic all-round scalar commitments preserve the correlated-challenge attack or grow as `3^round`; convolution remainders create response-sized scratch or persistent FFT setup. These are scoped construction rejections, not a universal PCS lower bound. `C7_CPU_REFERENCE_PASS=false`; no prover, SIMT, refresh, provider or pod is authorized. |
| `C7-D110` / 2026-08-29 | native `StreamOpenIntoMac` NO-GO; close SPBT carrier and reopen tournament | The target functionality keeps `tau` and the terminal value secret, outputs only shares satisfying `k_v=m_v+Delta*<x,q_tau>`, uses input-independent setup, one packed scan, bounded memory and sublinear wire, and must bind the same committed `x` against a malicious prover while simulating a policy-2 malicious verifier. In the `tau`-independent affine native-VOLE class, online corrections `c=A(x-r)` can evaluate every power query only if `ker(A)` lies in every query kernel. The `M` distinct-point Vandermonde queries span dimension `M`, so `rank(A)>=M` and at least `M` field corrections are required. Even the optimistic base-Fp floors are 992,000,000/246,611,200,000 B for GPT-2/31B; persisting them with the packed source is 5x before tags/tree, while Fp3 corrections give at least 13x. Silent VOLE compresses correlation generation, not fresh-input derandomization; published OLE/NIIP is linear, Horner/full MPC is linear, group/SRS routes are forbidden, HE/PIR lacks the complete native same-`W` bridge, and two-server PIR changes trust. This scoped result is not a universal computational PCS, `tau`-dependent secure-computation or 2PC lower bound. The rigid wire/setup criterion fires, so SPBT is closed as a carrier, its algebra is retained only as a reusable component, the dual-track tournament reopens with no entrant, and no CPU/Lean/Rust protocol/SIMT/refresh/provider/pod work is authorized. |
| `C7-D111` / 2026-08-29 | bound the reopened tournament to one concrete code-switch/shared circuit | The owner selects the native code-switch/shared-circuit line with a source-linear term independent of `q`, no trusted setup, groups/SRS or new computational assumption. The next phase may screen exactly one concrete candidate and must apply every setup, wire, one-scan, memory, proof-size, policy-2 and malicious-security gate immediately; it is not authorization for an open-ended tournament or implementation. The non-affine `tau`-dependent line remains secondary and may reopen only around an already concrete construction with an evident advantage, never as generic research. |
| `C7-D112` / 2026-08-29 | direct packed Bolt-min NO-GO; retain its setup advantage and the exact C6 differential | `C7-BOLT-MIN-G141-v0` is the sole D111 candidate: `alpha=1/8`, rate-1/2 RS, degree 16, `t=128`, dense g141 without row padding, Fp3 and interactive `Q_FS=0`. It does not rebuild C6.3's eight WHIR bodies or C6.4's six-body residual suffix. Its conservative persistent control is 642,264,576/162,584,531,456 B (2.590x/2.637x), below 3x but still a forbidden complete codeword and unmeasured against 990/5,940 s. Row-major one-pass setup needs 134,217,728/34,359,738,368 B syndrome state; column-major reserves up to 768,061,440 B of leaf frames before paths; a packed transpose makes setup 3.672x/3.752x. Each response additionally creates a 50,331,648/12,884,901,888-B fresh Fp3 RS word. The published GF(2^32) `gamma=0.096` does not transfer; even its dense-g141 cap is 736,686 visible Fp occurrences (3.144x/2.476x). The Goldilocks `gamma=0.049` diagnostic has a 627,072 requested-symbol lower bound and 1,381,056 dense-g141 cap (5.893x/4.642x). Both exceed 150%. Bolt supplies no hiding, direct VOLE-MAC terminal or stateful malicious-DV theorem, and its non-amortized Mulperm cost is estimated. C6.3's 17.180-GB inherited oracle, 2,092.76-s 17-profile setup and late PCG/lifecycle failures remain composed-path evidence, not a standalone Bolt lower bound. The candidate and bounded tournament close with no carrier, CPU prototype, SIMT, refresh or pod. Further search requires an owner decision. |
| `C7-D113` / 2026-08-29 | retain the complete-codeword ban; no abstract exception for Bolt's sub-3x setup control | The owner approves the scoped R0.8g checkpoint but declines any exception based only on the 2.590x/2.637x static storage control. The fresh per-response `RS(Xr)`, layout trilemma, dense-g141 wire above 150% and missing malicious soundness/privacy theorems are independent blockers. The gate may be reconsidered only for a concrete candidate that first eliminates the per-response codeword and supplies the entire one-scan, bounded-memory, wire, setup and security row. This authorizes no new screen, implementation, push, SIMT, refresh or pod. |
| `C7-D114` / 2026-08-29 | close the C7 tournament and block generic continuation | The owner declines R0.8h as generic research, every prototype and every further relaxation. C7 remains blocked with `C7_CPU_REFERENCE_PASS=false` until a named, concrete and transparent no-trusted-setup candidate first supplies a malicious-secure relation, same-W-to-MAC bridge, sublinear wire, setup within every gate, one packed scan and stateful privacy. A non-affine `tau`-dependent line also requires a new owner decision on the named candidate. This disposition authorizes only its scoped commit and branch push, not protocol implementation, SIMT, refresh, provider or pod work. |

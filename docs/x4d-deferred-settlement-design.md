# X4d deferred-settlement design and preregistration

**Status (2026-07-25): PHASE 2 M12 AND LOCAL RUST COMPLETE; FULL LEAN AND
RUST WORKSPACES GREEN; LOCAL CODEC REBASELINE COMPLETE. HARD STOP BEFORE
POD WORK PENDING PRODUCT-OWNER REVIEW.**

X4d moves the folding-PCS work out of each response and into one deferred
settlement over an exact union of frozen, MAC-authenticated weight claims. A
delivered response is complete and authenticated except for weight
consistency, whose state is explicitly `PENDING`. The verifier changes that
state to accepted only after a settlement covering the response succeeds.

This is a product-semantics and message-placement change. It does not convert
the immutable X4 or X4b failures into passes, and it does not reinterpret the
X4c measurements. Historical records, references and verdicts are immutable.

## 1. Authority, inputs and fixed facts

This design is subordinate to `AGENTS.md`, `docs/p7-handoff-spec.md` and
`docs/prototype-status.md`. The protocol baseline is Amendment 5 in
`docs/x4-folding-pcs-design.md`, including its Amendment-3 authenticated
output seam and Amendment-4 `equality OR LinkBad` rule. M9, M10 and M11 remain
as recorded in `docs/protocol-sketch.md`.

The measurement inputs are the clean `6277c3c` records:

- `benchmarks/results/x4c-gpt2-onboarding-2026-07-25-6277c3c.json`, SHA-256
  `bdf17c56e8e9a4d152b40ed2e1653d34cd665f09f52cb9dfe1cb1f57ae5e165d`;
- `benchmarks/results/x4c-gpt2-online-accelerated-2026-07-25-6277c3c.json`,
  SHA-256
  `5a5417c11c0d5b4abe57af1e6ea5fa1191962c709c0f7b86fb780c30af1dac89`.

They establish:

- an exact ten-file coefficient/root durable tier of **9,618,587,808 B**,
  five equal roots and no durable oracle files;
- one accelerated rebuild in **240.623922522 s**, with peak host RSS
  **133,544,189,952 B** and peak rebuild VRAM **43,486,546,048 B**;
- response-local model prove/verify selected walls
  **4.190497854 / 0.667958900 s**;
- X4c open/verify selected walls **0.130465952 / 0.059185522 s**;
- complete PCS/response lengths **2,683,236 / 43,953,700 B**; and
- exactly **4,809,293,824 initial encoded symbols read per response**.

The four X4c `pcs_total_s` observations are **306.624912063 s** warm-up and
**298.324984650 / 288.071288683 / 308.406747440 s** measured. The short
0.13-second `open_wall_s` is only the final canonical gather/open segment.
The response-fresh different-size-chain challenges force the full padded
oracle to be re-read and re-combined before that segment. This is the
folding-prover `O(N)`-per-proof trade, not an engineering defect. X4d removes
that structural work from individual responses by executing it once per
settlement batch.

The owner rulings fixed for this phase are:

1. deferred settlement is the selected product design;
2. the hard pending-claim cap is **3,320**;
3. the per-settlement expression remains

   ```text
   3320*(9/16)^111
     + 28,522,064,267,253
       / 340,282,366,762,482,138,490,186,164,457,219,031,041
   ```

   or **80.255370163990410893... bits**;
4. weight consistency is visibly pending until settlement;
5. the response carries no PCS block; and
6. all resulting references and validators are new and append-only.

No section below reopens those rulings.

### 1.1 Phase-2 root terminology clarification

Implementation exposed one terminology ambiguity in the Phase-1 prose. It is
resolved here without changing a statement, soundness term, child codec or
byte count.

The historical v4 field named `model_root` is the root of an epochized
manifest. It cannot be the object reused byte-for-byte across X4d
settlements, because each settlement has two fresh auxiliary cohort roots.
The X4c online record already demonstrates the distinction: epochs
3001--3004 have distinct `model_root` values even though their three weight
cohort roots and weight oracle are unchanged.

X4d therefore uses these two explicit objects:

```text
static_weight_commitment_digest
  = H(model config, weights digest,
      three static Wext cohort ids/roots, ordered descriptors)

settlement_model_root(epoch)
  = v4 manifest root(
      epochized manifest id,
      three static Wext roots,
      two settlement-fresh auxiliary roots)
```

The claim accumulator binds `static_weight_commitment_digest`. The packed
opening and settlement envelope bind `settlement_model_root(epoch)`. The old
X4c five-root durable tier and records remain immutable; X4d reuses only its
three weight cohorts and does not admit its two historical auxiliary cohorts
as settlement masks. The v4 manifest/root frame shapes are unchanged, so the
Section-8 exact formula is unchanged.

## 2. Product state and settlement policy

### 2.1 Response states

Every response nonce has exactly one monotone state:

```text
AUTHORIZED
  -> MODEL_AUTHENTICATED
  -> WEIGHT_PENDING
  -> WEIGHT_VERIFIED
```

or, from any nonterminal state:

```text
  -> TERMINAL_UNVERIFIED
```

`WEIGHT_PENDING` is the only delivery state. It means:

- the model proof and all non-PCS authentication checks have passed;
- the selected output is complete and immutable;
- every weight claim has been MAC-authenticated under the connection's
  `Delta`, frozen and added to the compared accumulator; and
- no verifier acceptance of weight consistency has occurred.

Only one successful settlement containing the response changes it to
`WEIGHT_VERIFIED`. A pending response is never called accepted, verified,
final, or weight-consistent in an API, record, UI or provider contract.
Deferral therefore creates no interval in which a wrong weight claim has been
accepted. The final cryptographic acceptance retains the bounded error
specified below.

### 2.2 Pinned triggers and limits

The `runpod-a100-x4d-v1` operational policy is:

```text
hard_pending_claim_cap       = 3,320
background_trigger_claims    = 1,632
background_trigger_responses = 16 for the fixed GPT-2 102-claim schema
max_inflight_settlements     = 1
```

Settlement is triggered by the first of:

1. the soft policy threshold of **1,632** open-batch claims;
2. explicit authenticated flush;
3. graceful connection close with a nonempty pending set; or
4. the hard cap before another response could be accepted.

The soft threshold is claim-count based. The response count is an exact
consequence only for the fixed X4d-v1 GPT-2 schema. No wall-time, traffic,
load or provider heuristic may silently change it.

At a trigger, the open batch is sealed as one ordered, contiguous accumulator
range. Later responses may enter the next open batch while the one sealed
settlement runs, but the total of sealed-in-flight plus open unsettled claims
still counts against 3,320. If a response would make that total exceed 3,320,
service is refused before model proving, response-nonce consumption or claim
append. It resumes only after the in-flight settlement succeeds and releases
its verified range. The refusal increments a permanent counter.

At the fixed GPT-2 geometry, 32 responses contain 3,264 claims and 1,632
masked groups. A 33rd would contain 3,366 claims and is therefore refused.
The permanent cap test also constructs a synthetic one-claim sequence and
proves that claim 3,321 is refused after exactly 3,320 pending claims.

## 3. Claim accumulator and MAC freeze

### 3.1 Canonical append-only state

Each fase-D connection owns one accumulator. It is append-only for the full
connection lifetime; successful settlement changes entry status but never
deletes, rewrites or renumbers an entry.

The initial digest is

```text
D_0 = BLAKE3-DERIVE(
  "volta-zk/x4d/claim-accumulator-init/v1",
  pcs_profile_digest || static_weight_commitment_digest || connection_id
).
```

For a frozen claim at connection-global `claim_index=i`, the canonical leaf
preimage is:

```text
connection_id[32]
response_nonce[32]
claim_index:u64_le
auth_handle_digest[32]
claim_frame_len:u32_le
complete canonical ReducedClaimFrameV4 bytes
```

The complete claim frame supplies and binds the block/descriptor id,
evaluation point and its length, parent claim, phase, affine scale and
authenticated domain. The decoder requires its descriptor, point and
authenticated domain to agree with the claim addressed by
`auth_handle_digest`; a self-consistent alternate is rejected.

The chain step is

```text
D_(i+1) = BLAKE3-DERIVE(
  "volta-zk/x4d/claim-accumulator-step/v1",
  D_i || canonical_leaf_i
).
```

`auth_handle_digest` is a shared opaque identifier, not a plaintext or a
local MAC share:

```text
BLAKE3-DERIVE(
  "volta-zk/x4d/authenticated-value-handle/v1",
  connection_id || response_nonce || claim_index ||
  auth_domain:u64_le || model_transcript_digest
).
```

It indexes write-once prover and verifier local shares. Neither local share,
`Delta`, a correlation plaintext nor a clear weight evaluation enters the
accumulator preimage.

The canonical order is response authorization order, then the existing
manifest/block order, then prefill before decode. GPT-2 appends exactly 102
claims per response. Reorder, omission, duplication, index reuse, a point or
block substitution, a handle mismatch or an alternate frame encoding changes
the digest and rejects.

### 3.2 Role comparison and durability

Both roles:

1. construct the same 102 canonical leaves from the accepted model
   transcript;
2. append all leaves atomically as one response batch;
3. compare `(first_index, appended_count, ending_digest)`; and
4. append and sync one `CLAIMS_FROZEN` journal record before response
   delivery.

The canonical response-proof byte count in Section 8 excludes this
connection-control state, just as fase-D setup/journal traffic is a separate
counted category. Phase 2 must report its exact channel and durable-write
bytes; it may not fold them into proof bytes or omit them. In the current
single-process harness, role comparison is direct, but the same tuple remains
mandatory and tamper-tested.

A role mismatch, partial append, journal failure or failed sync is a
malicious-check failure and terminally aborts the whole connection. A process
restart never resumes an unterminated connection: fase-D crash-burn applies,
and all its pending responses become `TERMINAL_UNVERIFIED`.

### 3.3 MAC freeze argument

At response time, every accumulated claim already has an authenticated value
under the connection's verifier-held `Delta`. The public handle fixes the
claim identity and the two write-once local shares. Later changing the
prover-side plaintext while keeping the verifier key would require a matching
tag change depending on unknown `Delta`; the existing M2/M9 MAC argument
rejects except with the already charged field-forgery probability (no worse
than approximately `1/p`, and `1/|E|` in the current `E=F_p^2` scalar
instantiation).

Deferral gives the prover no new adaptive choice:

- the static weight commitment and its three weight roots predate the
  connection;
- block, point, authenticated handle, response nonce and claim order are
  frozen and digest-chained before delivery;
- the complete settlement union is durably sealed before any settlement
  reduction, link, fold or query challenge; and
- every settlement challenge and auxiliary mask set is fresh after that
  seal.

This is the existing seal-before-query discipline lifted one level: first
seal all response claims, then ask the one settlement query.

## 4. Settlement protocol

### 4.1 One settlement, one epoch, one opening

A settlement is identified by:

```text
(connection_id, settlement_epoch,
 first_claim_index, claim_count,
 starting_accumulator_digest, sealed_accumulator_digest).
```

The tuple is durably burned before any settlement mask, correlation or
challenge is allocated. Epochs increase monotonically and are never retried.
The existing `one_opening_per_epoch` rule maps verbatim:

```text
one settlement = one commitment epoch = one packed opening.
```

The static weight commitment may be opened in later fresh settlement epochs.
The one-time object is the auxiliary mask set and challenge/correlation
schedule, not the static weight oracle.

The settlement contains exactly one contiguous pending accumulator range and
must cover every claim in that range. The verifier reconstructs the expected
ordered union from its own accumulator and compares every claim frame and
authenticated handle. An otherwise valid proof over a subset, superset,
reordered union or different settlement range is rejected before
cryptographic acceptance.

### 4.2 Interactive order

The normative order is:

```text
all response claims MAC-authenticated and accumulated
  -> settlement range/digests/epoch durably sealed
  -> fresh auxiliary mask set committed
  -> epoch, auxiliary root set and verifier query-seed commitment
     durably burned
  -> fresh settlement correlations allocated
  -> response-local two-claim groups reduced in canonical order
  -> all h values and M9 corrections fixed
  -> authenticated-output link rounds closed
  -> same-domain roots and one different-size fold chain sealed
  -> exactly 111 fresh query draws derived from the one-use verifier seed,
     settlement context, settlement model root and all sealed fold roots
  -> one packed query opening verified
  -> one settlement ZeroBatch closed
  -> every covered response marked WEIGHT_VERIFIED.
```

For GPT-2, each `(response_nonce, physical_block)` group contains exactly its
prefill and decode claims. Thus a `k`-response settlement has `102*k` claim
frames and `51*k` reduced/masked groups. It still has the same 51 static
weight blocks, one fresh auxiliary mask polynomial per physical block, 102
active `Wext`/auxiliary chain polynomials, five initial groups and 27 fold
rounds. Multiple response-local target points for one block are handled by
the one different-point reduction before the shared chain.

There is one fresh auxiliary mask set for the settlement, and it is destroyed
after success or failure. There is no simultaneous battery of per-response
mask epochs and therefore no X5 multi-mask lifecycle question in X4d.

### 4.3 Background scheduling and contention

Settlement is background work with strict response priority.

The fixed thread policy is:

```text
response proving Rayon pool = 8 workers
settlement Rayon pool       = 27 workers
```

The pools use disjoint recorded CPU affinity. PCG setup workers remain a
separate recorded pool. A host unable to provide the split fails profile
preflight; workers are not silently oversubscribed.

The single A100 is leased, not concurrently driven by independent response
and settlement streams. A response request has priority. Settlement yields
the GPU lease at the next completed kernel/fold boundary and does not submit
another kernel until the response releases the lease. A cap-triggered
blocking settlement receives the exclusive lease until it completes. This
policy bounds response interference without hiding settlement delay.

Every record reports:

- `settlement_wall_s`, from durable seal through terminal success/failure,
  including queueing and response-priority pauses;
- active CPU, GPU, lease-wait and pause walls separately;
- the isolated response wall and an overlapped response wall measured by
  same-process ABBA;
- absolute and percentage response interference delta; and
- whether any CPU or GPU interval overlapped.

`settlement_wall_s` is never folded into the response wall. Conversely, an
overlapped response slowdown is never omitted merely because settlement is
reported separately.

## 5. Cap, hiding and soundness

### 5.1 The Rust and Lean 3,320 constant

The current Rust schema-4 validator in
`rust/volta-pcs/src/x4/frame_v4.rs`,
`ResponseEnvelopeFrameV4::validate`, rejects when
`claim_frames.len() > 3320`. It separately enforces at most 1,660 masked/M9
groups and `relation_count = 2*m9_frames.len()`.

The Phase-2 X4d implementation does not duplicate that numeral:
`X4D_PENDING_CLAIM_CAP_V1` in
`rust/volta-pcs/src/x4/deferred_v4.rs` aliases
`folding_v4::MAX_RESPONSE_CLAIMS_V4`, and accumulator preflight, range
validation and settlement-envelope validation all consume that alias.

The current Lean theorem
`ud_model_global_folding_sound_v4` in
`lean/VoltaZk/X4FoldingPCSV4.lean` has the hypothesis:

```lean
hP : params.activePolys <= 3320
```

and `authenticated_output_batch_link_sound_v4` independently has:

```lean
hcount : relationCount <= 3320.
```

The numeral is therefore byte-for-byte and source-for-source the same
constant. M12 adds the semantic bridge from a canonical settlement union to
these theorem carriers rather than relying on numeric coincidence:

```text
claim_frames <= 3320
masked_groups <= 1660
two claims per response-local group
canonical union and activation schedule
  => relationCount <= 3320
  => activePolys <= 3320.
```

This bridge is proved by `x4d_claim_cap_implies_v4_bounds` in
`lean/VoltaZk/X4DeferredSettlement.lean`; the runtime constant alias and its
3,321 refusal tests are the implementation side of the same invariant.

### 5.2 Exact coefficient cross-check

The frozen maximum inventory remains:

| Accepting event | Exact charge |
| --- | ---: |
| fold/query | `3320*(9/16)^111 + 28,522,064,111,120/|E|` |
| claim reduction | `151,060/|E|` |
| authenticated link / `LinkBad` | `3,412/|E|` |
| settlement ZeroBatch | `1,661/|E|` |

At the largest X4d-v1 GPT-2 batch, `k=32`:

| Bound input | Exact X4d value | Frozen maximum |
| --- | ---: | ---: |
| raw frozen claim frames | 3,264 | 3,320 |
| masked groups | 1,632 | 1,660 |
| active chain polynomials | 102 | 3,320 |
| claim-reduction coefficient | `32*(51*4 + 3*1104) = 112,512` | 151,060 |
| link coefficient | `3,264 + 3*27 + 2 = 3,347` | 3,412 |
| ZeroBatch coefficient | `1,632 + 1 = 1,633` | 1,661 |

No coefficient increases. The exact per-settlement expression is therefore
unchanged by construction:

```text
epsilon_settlement
  = 3320*(9/16)^111
    + 28,522,064,267,253 / |E|
  = 6.9298888276461589731806059424696957e-25

-log2(epsilon_settlement)
  = 80.255370163990410893382823542456484 bits.
```

It remains **1.446075289990410893... bits** above the registered
**78.809294874-bit** floor. This margin is not a reserve. A batch schema with
more than 3,320 raw claims, more than 1,660 masked groups, a new accepting
event or a larger coefficient reopens preregistration and must be fully
re-summed before proof or code.

The result is per settlement. Across `S` accepted settlements, M12 composes by
an explicit union bound:

```text
S * epsilon_settlement
  + the existing M10 sum of per-response MAC terms.
```

No independence is assumed. Arbitrarily long X0 responses/connections retain
linear download and explicit settlement counters; X4d makes no constant-error
claim for an unbounded number of settlements.

### 5.3 Batched hiding/ZK budget

One auxiliary polynomial `g_b` is fresh for each touched physical block in a
settlement and may mask up to 32 GPT-2 response-local points for that block.
Publishing `m_b` masked evaluations gives a linear map of rank at most
`m_b`, so the coefficient fiber has cardinality at least:

```text
|E|^(2^ell_b - m_b).
```

Repeated or dependent points only lower the rank and increase the fiber. The
Amendment-3 correction-view map remains bijective, so M9/link corrections add
no further equation. At the 32-response cap:

| GPT-2 block `mu` | `ell` | remaining dimension `2^ell-32` | query exposure `111*mu^2` | slack |
| ---: | ---: | ---: | ---: | ---: |
| 20 | 16 | 65,504 | 44,400 | 21,104 |
| 22 | 16 | 65,504 | 53,724 | 11,780 |
| 26 | 17 | 131,040 | 75,036 | 56,004 |

Thus the worst admitted GPT-2 mask retains more dimension than the complete
111-query exposure budget. The batched packed opening still reveals no
`g_b(u)`, `W_b(z)`, `authS.x`, clear target evaluation or correlation
plaintext.

This table is part of the fixed GPT-2 X4d-v1 schema. A future model that
places more than 32 settlement evaluations on one auxiliary polynomial must
repeat this rank/fiber proof even if its total claim count is at most 3,320.
That is a ZK-admission obligation and cannot be waived by the statistical
soundness cap.

### 5.4 Correlation accounting

Claim freeze consumes **zero new correlations**: it freezes already
authenticated values. All X4 correlations move to settlement and are fresh
there.

For `k` GPT-2 responses:

```text
claim-reduction full correlations = 2*1104*k = 2208*k
settlement seam                   = 51*k + 2*27 + 1
total X4d settlement full         = 2259*k + 55.
```

| Responses | Claim reduction | Seam | Total fresh full correlations |
| ---: | ---: | ---: | ---: |
| 1 | 2,208 | 106 | 2,314 |
| 8 | 17,664 | 463 | 18,127 |
| 16 | 35,328 | 871 | 36,199 |
| 32 | 70,656 | 1,687 | 72,343 |

The 32-response value remains below the existing **98,001** all-maximum X4
screen. Prover/verifier counts, domains, allocation offsets and digests must
agree exactly. The durable freshness binding records
`expected_full_correlations_per_role = 2259*k + 55` before any settlement
correlation is released. The fase-D allocation ledger then consumes exactly
twice that number of raw sub-correlations, because each full `F_p^2`
correlation is built from two raw entries. Settlement success requires:

```text
settlement_raw_correlations_consumed
  = 2 * expected_full_correlations_per_role.
```

Zero, under- and over-allocation are terminal protocol errors. Settlement
allocations use a typed domain
`(connection_id, settlement_epoch, lane, ordinal, tensor_tag)` disjoint from
response domains; the existing connection-global stage counters still prove
that the same physical pool entry cannot be used twice. Response and
settlement paths share one physical pool loader rather than a second PCG
implementation. Unused settlement allocations are burned on every abort.

## 6. Abort, failure and connection close

Graceful close with pending responses runs one final settlement. The
connection reaches a successful terminal close only after that settlement
succeeds.

Any of the following before settlement success is terminal:

- accumulator digest mismatch or partial append;
- malformed, omitted, reordered, replayed or wrong-subset settlement claim;
- settlement proof or verifier failure;
- correlation, challenge, epoch or mask reuse;
- EOF, authenticated-channel loss, process kill or explicit abort; or
- inability to durably write a required lifecycle state.

On terminal failure:

1. every response already covered by a successful older settlement remains
   `WEIGHT_VERIFIED`;
2. every still-pending response becomes permanently
   `TERMINAL_UNVERIFIED`;
3. the failed settlement epoch, all response nonces, correlations, auxiliary
   masks and residual pools are burned;
4. no settlement retry is permitted in the same connection; and
5. fase-D burns the connection, all pools and base reservations.

A replacement request requires a new connection identity and new responses.
It cannot upgrade the old pending responses because their connection and
accumulator terminal states are immutable.

Permanent G6 tests cover graceful-close settlement, explicit abort before
settlement, settlement verification failure, process-kill/reopen,
malformed-frame failure, failure while a later open batch exists, and proof
that no terminal-unverified response can transition to verified.

## 7. M12 statement freeze and LinkBad inventory

These are statement shapes only. Phase 1 adds no Lean declaration or proof.
Definitional scaffolding may adapt carrier names, but conclusions, event
disjuncts, numeric coefficients and challenge-order hypotheses may not be
weakened. Every theorem must enter `lean/Audit.lean`; no new
`Ideal.lean` axiom is permitted.

### 7.1 Counter inventory before proof

The LinkBad rule is applied before theorem work:

| Rust/runtime family | Statement/event owner | Charge |
| --- | --- | --- |
| `accumulator_canonical_reject` | canonical leaf/digest theorem | deterministic pre-acceptance reject |
| `accumulator_digest_mismatch` | role-agreement theorem | deterministic terminal abort |
| `settlement_subset_reject` | exact-union/range theorem | deterministic pre-acceptance reject |
| `settlement_replay_reject` | one-opening epoch + accumulator range theorem | deterministic lifecycle reject |
| `pending_cap_refusal` | cap state-machine theorem | deterministic refusal |
| `post_freeze_substitution` | `FrozenClaimMacBad response` | existing per-response M2/M9 MAC term |
| `fold_query_bad` | `X4FoldBadV4` | exact frozen fold/query term |
| `claim_reduce_bad` | `X4ClaimReduceBadV4` | `151,060/|E|` |
| `auth_link_bad` | `X4AuthenticatedOutputLinkBadV4` / `LinkBadV4` | `3,412/|E|` |
| `settlement_zero_batch_bad` | `X4ResponseZeroBatchBad` renamed at the M12 wrapper | `1,661/|E|` |
| `pending_escape_reject` | pending-state theorem | deterministic rejection |
| `mask_or_epoch_reuse_reject` | one settlement/epoch/opening ZK theorem | deterministic privacy/lifecycle reject |
| `abort_terminal_unverified` | connection state-machine theorem | deterministic terminal transition |
| `delta_shift_attempt` | existing three-way event cover | diagnostic only; no fifth term |
| `beta_collision_witness` | existing `LinkBadV4` branch | diagnostic only; no fifth term |

There is no accepting runtime counter without a statement disjunct and no
statement disjunct without a runtime counter. A deterministic equality that
omits any known counted event is rejected at statement review.

### 7.2 Frozen proposition shapes

```lean
-- Canonical accumulation is append-only and range binding is exact,
-- conditional on the existing computational collision-free premise.
theorem x4d_accumulator_append_binding
    (hcanonical : CanonicalFrozenClaimEntry entry)
    (hhash : CollisionFreeOn X4dAccumulatorHash committedEntries)
    (ha : AppendClaim oldDigest entry = digestA)
    (hb : AppendClaim oldDigest entry' = digestA) :
    entry = entry'

theorem x4d_settlement_range_is_exact_union
    (hroles : ProverVerifierAccumulatorDigestEqual connection)
    (hseal : SettlementRangeDurablySealed settlement)
    (haccept : VerifySettlementEnvelope settlement proof) :
    proof.claims = orderedPendingClaimUnion connection settlement.range

-- The implementation cap is not merely the same numeral: canonical grouping
-- bridges raw claims to the active-polynomial and relation theorem carriers.
theorem x4d_claim_cap_implies_v4_bounds
    (hcanonical : CanonicalSettlementGrouping settlement)
    (hclaims : settlement.claims.length <= 3320)
    (hgroups : settlement.maskedGroups <= 1660)
    (htwo : ClaimsPerResponseLocalGroupAtMostTwo settlement) :
    settlement.relationCount <= 3320 /\
      settlement.activePolys <= 3320

-- A frozen claim cannot be reopened under a different plaintext without the
-- existing response MAC event. Equality is not built into raw handle lookup.
theorem x4d_frozen_claim_stable_or_mac_bad
    (hfrozen : FrozenMacBoundClaim response claim)
    (hlookup : SettlementUsesHandle settlement claim.authHandle) :
    SettlementClaimValue settlement claim = claim.auth.x \/
      FrozenClaimMacBad response claim

-- Batched masks retain the required coefficient fiber after every fixed
-- correction view and all response-local masked evaluations.
theorem x4d_batched_mask_fiber_lower_bound
    (hrank : BatchedMaskEvalRank points <= points.length)
    (hpoints : points.length <= 32)
    (hviews : CorrCorrectionViewsAreBijective settlement) :
    Fintype.card (ConsistentAuxMasks statement points) >=
      Fintype.card E ^ (2^ell - points.length)

theorem x4d_gpt2_mask_budget
    (hmu : mu = 20 \/ mu = 22 \/ mu = 26)
    (hpoints : pointsPerBlock <= 32) :
    111*mu^2 < 2^(x4dAuxEll mu) - pointsPerBlock

-- One successful settlement owns one fresh mask/challenge epoch and exactly
-- one opening. Static commitment reuse is not auxiliary-mask reuse.
theorem x4d_one_settlement_opening_per_epoch
    (hfirst : acceptSettlementOpening st epoch transcript1 = some st1)
    (hsecond : acceptSettlementOpening st1 epoch transcript2 = some st2) :
    False

-- Amendment-4 conditioning is retained. One settlement over the exact union
-- yields every response's M9 statement or a visibly charged event.
theorem x4d_accepted_settlement_implies_each_m9_or_bad
    (hfixed : AllFrozenClaimsFixedBeforeSettlementChallenge settlement)
    (hunion : ExactPendingClaimUnion settlement)
    (hcap : settlement.claims.length <= 3320)
    (haccept : VerifySettlementEnvelope settlement proof) :
    forall response : CoveredResponse settlement,
      ResponseM9OpeningIntoMac response \/
      FrozenClaimMacBadForResponse response \/
      X4FoldBadV4 settlement proof \/
      X4ClaimReduceBadV4 settlement proof \/
      X4AuthenticatedOutputLinkBadV4 settlement proof \/
      X4SettlementZeroBatchBad settlement proof

def x4dSettlementError : Rat :=
  (3320 : Rat) * ((9 : Rat) / 16)^111 +
  (28522064267253 : Rat) /
    (340282366762482138490186164457219031041 : Rat)

theorem x4d_settlement_error_is_v4 :
    x4dSettlementError = x4ResponseErrorV4

theorem x4d_settlement_soundness_m12
    (hcover : X4dWrongSettlementCoveredByNamedEvents settlement proof)
    (hcap : settlement.claims.length <= 3320)
    (hfold : X4dFoldBound settlement proof)
    (hclaim : X4dClaimReduceBound settlement proof)
    (hlink : X4dAuthenticatedLinkBound settlement proof)
    (hzero : X4dSettlementZeroBatchBound settlement proof) :
    statisticalError (X4dAcceptsWrongSettlement settlement proof) <=
      x4dSettlementError

-- This is the product-facing M12 result for one accepted union. The MAC
-- terms are per covered response and are not hidden in the PCS expression.
theorem x4d_accepted_union_implies_each_m9_soundness
    (hunion : ExactPendingClaimUnion settlement)
    (hm9 : AcceptedSettlementImpliesEachM9OrNamedBad settlement proof)
    (hmac : FrozenClaimsUseExistingM2M9MacBounds settlement) :
    statisticalError
        (SettlementAcceptsWrongCoveredResponse settlement proof) <=
      x4dSettlementError +
      coveredResponseMacTerms settlement

-- M10 supplies the shared-Delta, response-domain and fixed-rest lift. No
-- independence across responses or settlements is introduced.
theorem x4d_connection_composition_m12
    (hsettlements : EveryAcceptedSettlementSatisfiesM12 connection)
    (hm10 : ConnectionSharedDeltaCompositionM10 connection)
    (hnonces : InjectiveResponseNonces connection) :
    statisticalError (ConnectionAcceptsWrongWeightResponse connection) <=
      connection.acceptedSettlements.length * x4dSettlementError +
      connectionPerResponseMacTerms connection

-- Product state cannot label a pending or failed response accepted.
theorem x4d_pending_never_weight_accepted
    (hstate : response.state = WEIGHT_PENDING \/
      response.state = TERMINAL_UNVERIFIED) :
    not (WeightAccepted response)
```

M12 must reuse M9/M10 algebra and the audited v4 binding, ZK and batch
carriers. It may not bundle them into a new assumed functionality. If any
statement is unprovable without changing a conclusion, adding a premise that
assumes away a known bad event, changing a coefficient or adding an axiom,
Phase 2 stops with the exact obstruction.

## 8. Exact codec preflight

### 8.1 Per-response bytes

The clean X4c response identity is:

```text
41,270,400 B model transcript
        64 B model MAC closures
 2,683,236 B PCS block
------------
43,953,700 B current response
```

X4d removes the complete PCS block and adds no accumulator field to the
canonical proof/download payload; the state tuple is connection-control
accounting as specified in Section 3.2. Therefore the new exact response
reference is:

```text
X4D_GPT2_RESPONSE_BYTES = 41,270,464 B.
```

It contains zero folding-PCS, M9-transfer, auxiliary-mask, link, fold,
packed-opening or settlement-ZeroBatch bytes. Historical response references
remain unchanged.

### 8.2 Settlement codec and exact formula

The settlement envelope uses a new top-level X4d message kind and transcript
domains, but retains the canonical v4 child-frame widths and the 16-byte
top-level width. The v4 descriptor, manifest, N4 leaf/node and model-root
encodings remain unchanged; the model-root value is the fresh
`settlement_model_root(epoch)` defined in Section 1.1.

The two existing 32-byte schedule-digest fields are re-derived under:

```text
volta-zk/x4d/auth-output-link-schedule/v1
volta-zk/x4d/opening-schedule/v1
```

Their preimages additionally include the connection id, settlement epoch,
claim-index range, starting/ending accumulator digests and ordered response
nonces. Those are verifier-held statement/context data, not new prover
fields. The proof is replayed only against the locally expected accumulator
union. This gives cross-settlement replay and wrong-subset rejection without
adding wire bytes or changing any static weight root.

For the frozen GPT-2 descriptor and query geometry, the settlement components
are:

| Component | Exact bytes |
| --- | ---: |
| envelope structure/counts | 110 |
| unique descriptor digests | 1,632 |
| manifest frames | 12,227 |
| authenticated-output link frame, `d=27` | 933 |
| 27 fold frames | 2,446 |
| packed opening | 2,615,414 |
| settlement ZeroBatch frame | 50 |
| **fixed subtotal** | **2,632,812** |
| 102 reduced claim frames per response | `46,344*k` |
| 51 public `h` symbols per response | `816*k` |
| 51 M9 frames per response | `3,264*k` |
| **variable subtotal** | **50,424*k** |

The reduced-claim frame formula is exactly `108 + 16*mu` bytes. Each response
has 72 `mu=22`, 26 `mu=20` and 4 `mu=26` frames:

```text
72*(108+16*22)
  + 26*(108+16*20)
  + 4*(108+16*26)
= 46,344 B.
```

Therefore:

```text
X4D_GPT2_SETTLEMENT_BYTES(k) = 2,632,812 + 50,424*k.
```

The one auxiliary mask polynomial per physical block means claim multiplicity
does not add initial chain polynomials or query paths. The counts below are
exact, not estimates:

| Responses `k` | Frozen claims | Masked groups | Active chain polynomials | Fold rounds | Opened symbols | sibling digests | Settlement bytes |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 102 | 51 | 102 | 27 | 27,564 | 67,930 | **2,683,236** |
| 8 | 816 | 408 | 102 | 27 | 27,564 | 67,930 | **3,036,204** |
| 16 | 1,632 | 816 | 102 | 27 | 27,564 | 67,930 | **3,439,596** |
| 32 | 3,264 | 1,632 | 102 | 27 | 27,564 | 67,930 | **4,246,380** |

The one-response row has the historical length but will have a new reference
digest because X4d changes the schedule domain and statement context.

### 8.3 Amortized communication

| Responses | Response payloads + settlement | Settlement B/response | Total amortized B/response |
| ---: | ---: | ---: | ---: |
| 1 | 43,953,700 | 2,683,236.000 | 43,953,700.000 |
| 8 | 333,199,916 | 379,525.500 | 41,649,989.500 |
| 16 | 663,767,020 | 214,974.750 | 41,485,438.750 |
| 32 | 1,324,901,228 | 132,699.375 | 41,403,163.375 |

The binding 150--200 MB product envelope remains satisfied by each response
and by the separate settlement message. The old 4,000,000-B *per-response
PCS-block* gate does not apply to the 32-response settlement message; X4d G3
instead requires the exact formula and amortized accounting above. This
replacement is an owner-authorized consequence of moving the PCS block, not
a retrospective change to X4/X4b/X4c.

Phase 2 creates new response and settlement reference names, encoders,
decoders and validators. It first regenerates exact `k=1,8,16,32` vectors
from a clean tree, then pins their SHA-256 values. No existing JSON, reference
or historical validator is overwritten.

## 9. Online key-reuse hard-stop disposition

The ledger's open **ONLINE KEY-REUSE ACCOUNTING HARD STOP** is resolved by
this design. It does not remain as a dangling X4c obligation.

### 9.1 Reused state

The following reuse is intentional and sound:

- static weight coefficients, encoded oracle, N4 outer cache, the three
  weight cohort roots and `static_weight_commitment_digest` across responses
  and settlements;
- the verifier's one connection-scoped `Delta`, exactly as composed by M10;
- the fase-D PCG connection and its pool containers, while individual
  correlations remain one-use;
- public BLAKE3 derive-mode context states for the four v4 N4 hash domains;
  and
- immutable descriptors and manifest schema. Manifest frames and the
  settlement model root are rebuilt from static weight roots plus fresh
  auxiliary roots for each epoch.

The four cached 32-byte X4b hash-context keys seen by the X4c traffic
accounting are public deterministic derive-mode context state, not VOLE
correlations, verifier secrets, query challenges or auxiliary-mask keys.
They are generated once per CUDA context (**128 B on ordinal 0**) and reused
thereafter (**0 generated B on later ordinals**). Records must retain both
`hash_context_initialization_bytes` and `hash_context_reuse_hits`; calling
this a fresh cryptographic-key requirement is rejected.

Static commitment reuse is legitimate because the weight commitment predates
the connection and every settlement proves fresh, already-fixed claims
against that same static commitment. The settlement manifest root remains
epoch/fresh-auxiliary specific. Binding does not require recommitting
identical weights for each query.

### 9.2 Fresh state

The following is fresh and one-use per response:

- response nonce and all response-domain challenges;
- model-proof masks/corrections and correlation allocations; and
- the 102 frozen authenticated-value handles.

The following is fresh and one-use per settlement:

- settlement epoch and durable range seal;
- auxiliary mask polynomials, seeds, roots and coefficients;
- a verifier query seed whose commitment is globally burn-reserved before
  challenge release; its 111 exact-bit draws are derived only after every
  fold root is sealed;
- every claim-reduction, same-domain, activation, link, fold and ZeroBatch
  challenge;
- all 111 exact query draws;
- every M9/link/ZeroBatch correlation and monotone allocation offset; and
- all response-local `h` values and settlement proof messages.

No correlation value, auxiliary mask or settlement challenge is reused after
success, failure or abort. A failed settlement is never retried in the same
connection. The static-oracle reuse and fresh-settlement schedule answer the
accounting question completely; X4d supersedes the stopped X4c online path
whose per-response proof reread the full oracle.

### 9.3 Mandatory reuse/freshness counters

For fixed GPT-2, records and journals reconcile the following exact counters.
They are protocol/accounting counters and do not enter proof bytes.

| Object | Required counter identity |
| --- | --- |
| static commitment/oracle | `static_commitment_materializations = 1`; `settlement_static_root_uses = settlement_challenge_epochs_started`; no auxiliary root is counted here |
| fase-D MAC key | `connection_delta_keys_created = 1`; every authorized response and challenge-bearing settlement records the same connection-key id |
| public N4 hash contexts | `hash_context_initializations = 4`; `hash_context_initialization_bytes = 128` on online ordinal 0 and `0` thereafter; every later ordinal records a reuse hit |
| response nonces/handles | `response_nonces_burned = responses_authorized`; `auth_handles_created = 102*responses_frozen`; no handle appears in two claim indices |
| settlement epochs/seals | `settlement_epochs_burned = settlement_ranges_sealed`; exactly one durable range seal per epoch, including a pre-challenge failure |
| auxiliary masks | `aux_masks_created = 51*settlement_challenge_epochs_started`; every created mask is destroyed or burned in the same epoch |
| query challenges | `settlement_query_draws = 111*settlement_query_schedules_issued`; every seed commitment is globally burn-reserved and every issued schedule is domain-separated by connection, sealed range, epoch, settlement model root and fold-root vector |
| settlement correlations | for challenge-bearing batch sizes `k_j`, prover and verifier each allocate `sum_j (2259*k_j + 55)` full correlations before the first challenge; consumed plus abort-burned equals allocated |

The correlation ledger additionally compares first/last allocation offsets,
per-domain counts and allocation digests on both roles. A reuse hit for a
static/public object and a reuse attempt for a nonce, handle, mask,
correlation or challenge are different counter families; merging them is
rejected.

## 10. Preregistered gates

All gates are conjunctive. A communication pass cannot waive correctness,
cap, lifecycle, soundness, hardware or accounting failure.

### G1 — per-response online wall

On `runpod-a100-x4d-v1`, measure one warm-up and three responses and select
the upper median:

- model prove + model verify + claim freeze **<=5.000 s**;
- claim-freeze wall alone **<=0.025 s**;
- prefill **<=10 s**, decode marginal **<=4 s**, H2D **<=100,000,000 B**,
  max synchronization wall **<=0.150 s** and flatness **<=1.5** remain the
  inherited fase-D-class limits; and
- the response is exactly **41,270,464 B** with zero PCS/settlement work.

The current X4c model prove+verify anchor is **4.858456754 s**, before claim
freeze. The 5-second gate is a target, not a claim that X4c already passed
X4d.

CPU measures same-process ABBA with a re-run of the frozen T1 path on the same
native-target host. The X4d model-proof+freeze / T1 ratio must be **<=1.01**,
and CPU claim-freeze alone must be **<=0.050 s**. Historical context is the
clean four-worker C3b/T1 pair **38.118634535 / 38.317683641 s**, ratio
**1.005221832**; those machine-specific walls are provenance, not imported
denominators.

### G2 — settlement correctness and permanent tamper cases

One settlement over at least two responses and one over at least 16 responses
must verify every frozen claim and upgrade exactly the covered response set.
Permanent tests reject:

- post-freeze value substitution/MAC forgery;
- claim omission, duplication or reorder;
- accumulator digest mismatch;
- cross-settlement claim or proof replay;
- a settlement over a proper subset, superset or wrong contiguous range;
- wrong connection, epoch, start/end digest or response nonce;
- any existing v4 delta-shift, beta-collision, N4, link, fold or ZeroBatch
  tamper; and
- any pending-to-accepted state escape.

Mock and real/AES modes retain logical counter, allocation-digest and
transcript parity. Record-producing mode refuses mock.

### G3 — exact bytes and re-baseline

- response: exactly **41,270,464 B**;
- settlements: exactly `2,632,812 + 50,424*k` B for fixed GPT-2 `k`;
- the historical **4,000,000-B** ceiling remains immutable and applies to
  the X4/X4b/X4c **per-response PCS block**, not to the separate X4d
  settlement message. X4d G3 uses the pinned settlement formula: at `k=32`
  the message is **4,246,380 B** and amortizes to **132,699.375 settlement
  B/response**. This is neither a silent overrun nor a retrospective
  relaxation of any historical gate;
- exact clean reference vectors at `k=1,8,16,32`;
- exact component and amortized tables from Section 8;
- connection-control/journal traffic separately and completely counted;
- new response/settlement reference names and validators; and
- every historical row, reference and JSON byte-identical.

A missing category or a merely self-consistent alternate count is FAIL.

### G4 — cap and unchanged expression

- the first 3,320 pending claims are admissible;
- claim 3,321 refuses service until a settlement succeeds;
- total pending includes both the sealed in-flight and next open batch;
- `claim_frames<=3320`, `masked_groups<=1660`,
  `relationCount<=3320` and the M12 active-polynomial bridge all hold;
- the exact expression string is byte-for-byte
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`; and
- its evaluation remains **80.25537016399041 bits**.

Any new union term or coefficient is re-summed against the
78.809294874-bit floor before execution. A cap or expression mismatch is
FAIL, not a validator warning.

### G5 — settlement wall and background interference

For `runpod-a100-x4d-v1`, the first eligible settlement run is an informative
wall baseline:

- one background settlement covers at least 16 responses;
- `settlement_wall_s`, active CPU/GPU wall, lease wait and pauses are all
  present;
- isolated and overlapped response walls are measured by ABBA;
- absolute and percentage interference deltas are present; and
- no v1 settlement-total ceiling or projected verdict is invented.

A hard settlement-total ceiling is mandatory in a separately preregistered
`runpod-a100-x4d-v2`, following the fase-D first-baseline precedent.

The final packed-opening segments remain hard in v1:

```text
settlement open   <= 1.50 s
settlement verify <= 0.25 s.
```

The X4c **0.130465952 / 0.059185522 s** observation is provenance only.

### G6 — abort and terminal-state semantics

All Section-6 lifecycle tests pass with durable journal evidence. No failed,
aborted, disconnected or crash-burned pending response is ever reported
weight-verified. No settlement retry occurs in the same connection. Residual
correlations, masks, pools and base reservations reconcile as burned.

### Carried X4c onboarding gates

The following remain conjunctive:

- fixed GPT-2 weights, goldens, manifest and T=100+50 bit-exact output;
- same admitted cryptographic-build identity and append-only receipts;
- five exact roots from the ten-file **9,618,587,808-B** durable tier;
- accelerated fresh rebuild with CPU/GPU root cross-checks;
- real CUDA required, no automatic CPU fallback;
- exact host/device ownership and zero outstanding CUDA operations;
- zero response-window file I/O, staging and noncanonical D2H;
- real/AES PCG production mode and complete counters/digests; and
- R1b NOTE-6 `c3_weights_two_weight_set_leakage_smoke` as the first pod
  workload.

The five-root check remains an unchanged carried X4c onboarding gate. X4d
uses the three admitted weight roots and regenerates two auxiliary roots per
settlement; accepting either durable X4c auxiliary root as an X4d mask is a
freshness failure.

### Phase-2 implementation map

The implementation deliberately adds no competing PCS or connection
lifecycle:

- `volta-pcs/x4/deferred_v4.rs` owns the single cap alias, append-only
  accumulator, exact range/envelope validation and cooperative GPU lease
  accounting;
- `authenticated_output_v4.rs` retains one accelerated folding engine, with
  thin X4c and X4d entry points; only the X4d entry permits repeated
  response-local relations to accumulate onto the same static slots;
- `volta-pcg/production.rs` remains the sole durable fase-D lifecycle and
  adds `CLAIMS_FROZEN`, `SETTLEMENT_SEAL`, `SETTLEMENT_FRESHNESS`,
  `SETTLEMENT_ALLOCATE`, success/failure and crash-burn records. The
  freshness record binds the exact full-correlation count per role, and
  success reconciles it against the raw allocation ledger;
- `volta-bench/x4d_gpt2.rs` is orchestration only: it maps model outputs to
  frozen handles, materializes fresh auxiliary cohorts and invokes the
  existing accelerated chain; and
- `x4d_codec_reference` generates the exact response traffic projection and
  materialized settlement envelopes without claiming a proof or hardware
  gate verdict.

The local small-geometry cryptographic test covers two responses in one
different-size chain and completes M9-to-MAC plus ZeroBatch verification.
Permanent tests cover value substitution, omission, reorder, wrong subset,
claim replay, settlement-freshness replay, the 3,321st claim, the fixed GPT-2
33rd-response refusal, correlation under-allocation, settlement failure,
close, EOF and process restart.
The full no-default-features Rust workspace is green. R1c review scope is
extended to all implementation files above and the new X4d codec generator;
independent review is not claimed.

## 11. Frozen profile and phase order

`runpod-a100-x4d-v1` requires:

- exactly one selected A100-SXM4 80 GB;
- host RAM **>=256 GiB = 274,877,906,944 B**, checked fail-closed before
  allocation;
- local/transferable volume **>=150 GB**;
- response/settlement split pools of 8/27 workers with recorded CPU topology
  and affinity;
- wall-only gate timing plus complete counters, never CUDA-event gate timing;
- one warm-up plus at least three measured candidates where applicable; and
- NOTE-6 first.

The phase order and current boundary are:

```text
Phase 2a COMPLETE: exact M12 statements/proofs/audit
  -> full lake build, zero sorry/admit, standard axioms only
  -> HARD STOP on any obstruction

Phase 2b COMPLETE: local Rust implementation
  -> accumulator/freeze and product states
  -> settlement driver and generalized codecs
  -> cap/abort/background scheduler
  -> permanent G2/G4/G6 tests
  -> full workspace and synthetic-scale CPU green
  -> HARD STOP before pod (current boundary)

Phase 3: user-provisioned pod only
  -> NOTE-6 first and RAM/volume preflight
  -> onboarding and G1 candidates
  -> >=16-response settlement and all G2--G6 records
  -> CPU/GPU roots, re-baseline and ledger closure
  -> checkpoint/session memory
  -> provider-control-plane pod termination.
```

R1c mandatory scope is extended to the accumulator, authenticated-handle
store, settlement codecs/driver, cap and product-state machine, background
scheduler, interference accounting and abort cleanup.

**HARD STOP:** Phase 2 ends here. No endpoint, pod, remote storage, hardware
benchmark or provider control plane may be touched for X4d until the product
owner explicitly approves Phase 3 and provisions the registered profile.

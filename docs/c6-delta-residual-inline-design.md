# C6 — inline Δ-residual certificate and persistent cache

Status: **OWNER REQUIREMENTS FROZEN; Q=121 CONTINGENCY ACTIVATED BEFORE
IMPLEMENTATION; LOCAL IMPLEMENTATION AUTHORIZED; HARD STOP BEFORE POD**.

This document is the C6 plan of record.  It is a new descendant of the
accepted C4/T1 `rate=1/4,Q=120` inline profile.  It does not reopen or rewrite
the immutable C4 rate-8 FAIL, the C5 typed-PCG obstruction, or any X4/X4d
record.  C6 reuses implementation components where their statements match,
but it has a new proof statement, codec, state machine, soundness sum and
record lineage.

The construction removes the two dominant response fields:

1. the `38,348,720-B` direct `auth_corrections` vector is private witness to
   one verifier-linear **Δ-residual**;
2. the `17,235,968-B` Ligero `u_vectors` are private witness to native-field
   linear-functional proofs.

All remaining T1 fields stay byte-identical unless this document names the
change.  The wrapper is inline: acceptance of one response never waits for a
later settlement.

## 1. Owner requirements

C6 MUST satisfy all of the following.

- The first exchange, including every byte received by the client, is at
  most `150,000,000 B`.
- One connection has enough one-time correlation credit for at least
  **17 accepted baseline certificates** and a separately accounted retry
  reserve.
- Every final certificate is at most `35,000,000 B` and is independent of
  the number of already accepted certificates and of the current cache
  length.  A root, not the cache or prior key vectors, crosses the wire.
- The final wrapper payload `pi_final` is at most `4,500,000 B`.
- The complete inline prover wall is at most `20.000 s`.  The optimization
  target remains `11--18 s`; the ceiling, not the target interval, is a
  gate.
- Prompt prefill, decode length and attention context may increase prover
  work and exact correlation consumption.  They MUST NOT add a
  per-token proof instance, per-token PCS claim, or a certificate field
  linear in those lengths.
- The GPT-2 context bound remains `1,024` tokens.  The baseline continuation
  is prompt `100`, then `50` new tokens per accepted certificate; 17
  certificates end at context `950`.
- The verifier remains designated.  The provider never learns the
  connection secret `Delta`.
- Every certificate is sound conditional on the accepted predecessor cache
  state.  The registered per-certificate floor is exactly
  `78.80929487391641` bits.
- No provider/pod contact is authorized by this document.

The baseline is a capacity/gate workload, not a restriction on the API.
Larger legal workloads consume their exact raw-correlation count and can
therefore exhaust the connection before 17 accepts.  They do not change the
wire grammar or its cap.

## 2. Pre-code Q ruling and exact response budget

The C3/C4 response-wide Ligero bound for the two consolidated trees is

```text
epsilon_tree =
    (1 - (1-r)/2)^Q + (rows + claims + 1)/|Fp2|
epsilon_Ligero = epsilon_weights + epsilon_embed.
```

At Q=120:

```text
epsilon_Ligero = 1.8881578818430648e-24
bits            = 78.80929487391641.
```

C6 allocates four separately named wrapper events at `2^-128` each
(linear-functional sumchecks, wrapper PCS, cache argument and Δ-residual).
The exact rational re-sum at Q=120 is
`78.809294873916403493...` bits, below the registered decimal floor.  The
owner-preregistered contingency is consequently activated **before any C6
protocol implementation**:

```text
Q = 121
epsilon_Ligero = 1.1921205556486027e-24
Ligero bits    = 79.47274413860918.
```

The extra query costs exactly:

```text
weights: 4 + 8*24,576 + 16*97 + 2*32*15 = 199,124 B
embed:   4 + 8* 2,080 + 16* 7 + 2*32*17 =  17,844 B
total                                              216,968 B.
```

Starting from the immutable C4 anchor:

```text
C4 response                              84,544,352 B
- direct auth_corrections                38,348,720 B
- weights/embed u_vectors                17,235,968 B
retained Q=120 response                  28,959,664 B
+ Q=121 query increment                     216,968 B
retained C6 response                     29,176,632 B
35-MB cap - retained                     5,823,368 B
pi_final cap                             4,500,000 B
projected response at pi_final cap       33,676,632 B
absolute headroom                         1,323,368 B.
```

`pi_final` includes every new C6 byte: wrapper commitments, public
inner-product claims, residual frame, cache-transition header/proof and the
final proof encoding.  No new field may be moved outside this accounting
bucket.

The exact old `u_vectors` split is:

```text
weights: 16 * 8,704  * (96 + 1) = 13,508,608 B
embed:   16 * 33,280 * ( 6 + 1) =  3,727,360 B
total                                17,235,968 B.
```

## 3. Why the final residual remains affine

Every verifier-side MAC key is affine in the secret:

```text
k = m + Delta*x.
```

Authentication of a value `x` from a correlation `(a,m,k0)` uses the
correction `d=x-a`:

```text
kx = k0 + Delta*d = m + Delta*x.
```

The production verifier is **not** globally linear in its key inputs.
`prod_batch_verify` contains the unique nonlinear key expression

```text
k_a*k_b - Delta*k_c.
```

Treating this expression as a linear reverse-DAG node would discard a
quadratic term and is forbidden.  C6 instead splits the authenticated-value
IR into ordinary linear nodes and an opaque `ProductClosure` node.

For every direct authenticated source `i`, the provider-side committed
witness contains the base share `(r_i,m_i)`, hidden correction `d_i` and
corrected plaintext `x_i`, while the client retains the actual verifier-only
base key `k0_i`:

```text
x_i  = r_i + d_i
k0_i = m_i + Delta*r_i
k_i  = k0_i + Delta*d_i = m_i + Delta*x_i.
```

The wrapper proves the first equality and the typed `x`/`m` projection of
every public add/sub/scale node.  A post-commit client RLC binds the committed
base shares to the actual verifier-only base-key leaves:

```text
sum_i alpha_i*k0_i
    + Delta*(-sum_i alpha_i*r_i)
  = sum_i alpha_i*m_i.
```

The `alpha_i` schedule is generated from the already budgeted,
domain-separated wrapper batching challenge after every bound commitment.
It covers every direct source and every product mask correlation.  The
wrapper proves that its two aggregates use the same committed canonical
arrays.  In the information-theoretic model the coefficients are independent
uniform field challenges; the implementation expands the interactive client
challenge through the already named cryptographic transcript sampler and
reports that computational assumption separately.  No scalar-power RLC with
an uncharged `T/|F|` loss is permitted.

For one QuickSilver batch, with the existing post-commit product challenge
`chi` and `w_j = chi^(j+1)`, the wrapper proves

```text
Q  = sum_j w_j*(x_a[j]*x_b[j] - x_c[j]) = 0
M0 = m_mask + sum_j w_j*m_a[j]*m_b[j]
M1 = x_mask
     + sum_j w_j*(x_a[j]*m_b[j] + x_b[j]*m_a[j] - m_c[j]).
```

The mask is a full authenticated correlation and participates in the same
base-share binding.  Corrected-key validity and the existing M7 algebra then
give, for every `Delta`,

```text
sum_j w_j*(k_a[j]*k_b[j] - Delta*k_c[j]) + k_mask
  = M0 + Delta*M1 + Delta^2*Q
  = M0 + Delta*M1.
```

Thus `ProductClosure` discharges the nonlinear verifier node without placing
a key multiplication in the residual accumulator.  If any claimed product
is false, `Q=0` is precisely the already-audited M8 scalar-`chi` collapse
event; C6 does not introduce a second product event or challenge.

After every `ProductClosure` is discharged, all remaining verifier key
operations are public add/sub/scale.  Reverse accumulation over those typed
linear nodes, combined with the base-share binding constraints in the same
grand residual schedule, gives one response-wide equation

```text
K_base + Delta * D_corr = M_public.
```

- `K_base` is a linear combination of verifier-only base-correlation keys.
  The client streams it from the one-time range and public coefficient
  schedule; it is never sent by the provider.
- `D_corr` is the matching linear combination of the hidden direct
  corrections.  The wrapper proves this dot product against the committed
  canonical correction vector.
- `M_public` is the matching combination of retained prover tags and public
  values.

The provider computes and proves the two committed-witness aggregates but
cannot adapt them after the binding challenge and does not know `Delta` or
`K_base`.  The client performs this single grand affine check outside the
transparent wrapper.  A nonzero vector of affine closure errors is charged
once to the existing `epsilon_Delta_residual`; base-share binding is not a
fifth statistical wrapper event.  The old M8 product term remains in the
retained T1 soundness accounting.

The implementation MUST derive both prover constraints and the client
coefficient schedule from one typed authenticated-value DAG.  Its only legal
node classes are direct source/correction, public constant, add, subtract,
public scale, zero closure and `ProductClosure`.  A key multiplication outside
a certified `ProductClosure` is a construction-time error.  Hand-maintained
parallel formulas are forbidden.  Every base-key leaf, hidden-correction leaf
and product-mask leaf has one canonical correlation index, transcript
position and domain.  Missing, duplicate, reordered or dead leaves fail the
exact census.

## 4. Hidden Ligero vectors without an NTT trace

Simply omitting `u_c` or `u_g` is unsound.  C6 commits to them before the
Ligero column queries and proves the exact linear functionals checked by the
old verifier.

For one vector `u` and queried encoded column `j`,

```text
NTT(u)[j] = sum_{k < msg_len} u[k] * omega_j^k.
```

For one claim vector, the MAC bridge also needs

```text
ip_g = sum_{k < cols} u_g[k] * q_col_g[k].
```

The wrapper batches all queried NTT equations and all `ip_g` equations with
fresh verifier challenges.  **Weights and embedding use one response-wide
coefficient stream and one grand residual**, in canonical
family/query/vector/`ip` order; two independent per-family collapses are
forbidden because they would create two collision events.  The public
`ip_g` values and a digest of the exact `q_col_g` functional schedule are in
the pre-query statement.  The verifier derives that schedule independently
from the retained block claims.

A single `Fp2` check is not literally 128 bits:

```text
log2(|Fp2|) = 127.9999999993282...
```

Moreover, the ordinary degree-two sumcheck bound for the 21-round weights
oracle is only about `123.6` bits before amplification.  C6 therefore runs
**two independent complete repetitions** of the response-wide RLC and its
per-family linear sumchecks.  With at most `21 + 19` rounds and degree two,
the conservative named-event bound is

```text
epsilon_linear_functional
    <= |Fp2|^-2 + (2*(21+19)/|Fp2|)^2
    < 2^-243.
```

This is one amplified instance of the already allocated
`epsilon_linear_sumchecks`, not a fifth event.  Both repetitions' terminal
claims are included in the same packed wrapper opening.  A 32-byte
post-commit client seed may expand both independent coefficient vectors
through the already declared computational transcript sampler; the two
domain labels and coefficient order are certificate-bound.

The native-`Fp2` sumchecks prove the resulting linear functionals and open
the committed multilinear vectors through one packed response opening.
This avoids the field/representation obstruction of pretending that an X4
MLE opening is itself a Ligero univariate opening.  The explicit
linear-functional sumcheck is the link between the two representations.

The two fixed padded layouts are:

```text
weights U: 128 vectors x 16,384 entries = 2^21 Fp2
            97 live vectors, msg_len=8,704
embed U:     8 vectors x 65,536 entries = 2^19 Fp2
             7 live vectors, msg_len=33,280.
```

Both message lengths are `2^n + 512`, so the verifier evaluates each
truncated geometric functional as exactly two aligned Boolean subcubes.  It
does not scan an `u` vector.  The `q_col` live interval is a power of two.

The wrapper root(s), correction-vector root and statement digest are sent
before any query or batching challenge that they bind.  C6 retains the
interactive designated-verifier challenge model; it does not silently
replace it with Fiat--Shamir.

## 5. Wrapper backend

C6 V1 is transparent and native to Goldilocks/`Fp2`; it has no pairing-field
bridge and no client SRS.

- The linear correction and `u` relations reuse the audited shape of the
  existing strict-rate native folding/sumcheck machinery, but use a new C6
  statement and inline, response-sized oracles.
- Cache membership/update uses a fixed-capacity algebraic Merkle statement
  over the same field.  Paths and cache values are private proof witness.
- The proof envelope contains one packed wrapper opening per response, even
  when the backend internally has different-size oracle chains.
- Transparent preprocessing tables may be installed model-globally on the
  provider.  Their canonical digest/version is in every certificate.

An outer universal/updatable SRS compressor is not part of C6 V1.  It may be
proposed only in a separately named descendant if the transparent payload
cannot meet `4,500,000 B`; it may not be added after observing a production
timing in order to rescue a failed gate.  A fixed Groth16-style
model-specific ceremony is explicitly excluded.

The historical X4 settlement path is not used.  C6 builds only response-local
oracles whose logical input is the hidden correction/vector/cache-verifier
witness.  There is no model-global multi-minute settlement and no later
certificate can change the acceptance status of an earlier response.

## 6. Persistent cache commitment

The cache is a fixed-capacity `1,024`-token authenticated state.  The client
stores only a compact head; the provider stores the values and proof witness.

```text
CacheHeadV1 {
    protocol_digest,
    model_digest,
    params_digest,
    connection_id,
    epoch,
    cache_len,
    cache_root,
    predecessor_certificate_digest,
}
```

One certificate proves, conditional on the accepted `old_head`:

1. every old cache value used by the response is opened from
   `old_head.cache_root`;
2. the existing GKR/cache-input claims use those same values;
3. the new K/V slab is the authenticated output of this response;
4. updating exactly positions
   `[old_head.cache_len, new_head.cache_len)` yields `new_head.cache_root`;
5. all other fixed-capacity leaves are unchanged;
6. `new_head.epoch = old_head.epoch + 1` and cache length is monotone and at
   most `1,024`.

The paths, old values and new slab are private wrapper witness.  Certificate
size is fixed by the maximum profile, not by the current cache length.
Prover work may grow with the number of cache reads and with attention
context.

The formal theorem is conditional on an explicit commitment-binding
hypothesis.  No Lean theorem may smuggle collision resistance in as a new
axiom.

## 7. Certificate and challenge grammar

All integers are unsigned little-endian and all field elements use their
canonical existing encodings.  Decoders reject unknown versions, nonminimal
lengths, duplicate fields, trailing bytes and noncanonical field values.

The response protocol is ordered:

1. client sends the accepted head, fresh 32-byte nonce, requested workload
   and a reserved correlation range;
2. provider durably reserves the slot/range and sends the canonical public
   response prefix;
3. provider sends commitments to hidden direct corrections, hidden
   `u_vectors`, cache witness and the complete pre-query statement;
4. client sends the next verifier challenges, including Q=121 Ligero column
   queries and wrapper batching challenges;
5. provider sends retained T1 fields, queried columns, compact residual
   outputs, `new_head` and `pi_final`;
6. client verifies the wrapper, streams `K_base`, checks the Δ-residual, and
   atomically commits the new head plus certificate digest;
7. client sends an ACK naming that digest.

Every challenge is domain-separated by protocol/version, connection,
response nonce, epoch, old head, slot/range and the digest of all prior
frames.  A query is never cached or reused.

The final certificate binds at least:

```text
version, protocol/model/params digests,
connection_id, epoch, nonce,
old_head digest, predecessor certificate digest,
new_head digest, old/new cache lengths,
correlation stage/start/count and slot id,
workload digest and public token/output digest,
retained transcript digest,
wrapper statement/root digests,
Delta-residual public outputs,
pi_final length and digest.
```

## 8. Slot, abort and retransmission semantics

The provider keeps a durable append-only slot journal.  The only legal
states are:

```text
Available -> Reserved -> InFlight -> Produced -> Accepted
                                      \-> Burned
                         \-------------> Burned
```

- Reservation durably burns the complete correlation range before proof
  work starts.
- Abort before acceptance leaves the client's accepted head unchanged and
  moves the slot to `Burned`.  Its range is never reused.
- A retry reserves a new slot/range and a new nonce.
- Once `Produced`, `(old_head, nonce, slot)` has exactly one canonical
  certificate digest.  An ambiguous ACK permits retransmission of those
  exact bytes only.
- Producing a different child or different certificate bytes for the same
  tuple is a terminal fork fault for that connection.
- `Accepted` is recorded only for the client-ACKed digest.

Unlike the historical connection-terminal-on-any-abort path, C6 burns the
individual slot fail-closed and keeps the remaining connection credit
usable.  Malicious PCG/setup/check failure that invalidates the shared
connection material remains terminal.

## 9. Anti-rollback V1

V1 assumes one client with durable authenticated local storage.  The client
keeps:

```text
connection_id, accepted epoch/head, accepted certificate digest,
used nonce/slot high-water information, params/model/protocol digests.
```

Acceptance is a compare-and-swap against the exact old state, implemented as
write-new-record, file `fsync`, atomic rename, and parent-directory `fsync`.
Replay, provider-induced rollback and provider-induced fork are rejected by
the old head, epoch, predecessor digest, nonce and slot bindings.

V1 does not claim protection against restoration of an arbitrary old client
disk snapshot and does not support concurrent multi-device writers.  Those
require an external monotonic counter/log/synchronizer and are outside this
phase.

## 10. Correlation credit

The clean T1 connection record gives the canonical baseline raw allocation:

```text
sub/full protocol counts            4,793,590 / 181,933
complete allocated raw range                     5,235,692
terminal-one stage-3 usable                    110,918,718
21 * 5,235,692                                 109,949,532
remaining after 21 baseline slots                  969,186.
```

C6 reserves 21 baseline slots:

- 17 acceptance credits;
- 4 abort/retry credits.

The PCG first exchange stays exactly `38,371,465 B`.  No chain-six expansion
or seventh fase-D stage is needed.  Actual allocation is by raw count, not
by a nominal slot multiplier.  A legal variable workload declares and
durably reserves its exact preflight count; insufficient remaining credit
rejects before proof work and does not partially allocate a range.

The total C6 setup ledger is

```text
fase-D real/AES PCG                         38,371,465 B
+ all client-received C6 verifier params
+ canonical setup framing
<=                                         150,000,000 B.
```

Provider-only model-global tables do not count as client traffic, but their
digest/version/max geometry is certificate-bound.  Any byte received by the
client counts in full.

## 11. Soundness statement

For each certificate `i`, conditioned on an honestly accepted and binding
predecessor state:

```text
Pr[client accepts a false transition i | predecessor i-1 valid]
    <= epsilon_Ligero(Q=121)
     + epsilon_linear_sumchecks
     + epsilon_wrapper_PCS
     + epsilon_cache_argument
     + epsilon_Delta_residual
     + named computational-binding failures
    <= 2^-78.80929487391641.
```

Every statistical wrapper profile MUST be at least 128 bits before union;
the implementation reports every term and counter explicitly.  Merkle/hash
collision resistance and PCG assumptions remain separately named
computational assumptions rather than being silently converted into a
statistical bit count.  The existing M3/M7/M8/M2 MAC-closure inventory is
unchanged and remains tracked under the inherited T1 convention rather than
being duplicated as a fifth C6 wrapper allocation.  The four new allocations
remain linear-functional sumchecks, wrapper PCS, cache argument and the grand
Δ-residual.

The 17-certificate session union is informational and does not repartition
the per-certificate floor:

```text
17 * 2^-78.80929487391641 = 2^-74.72183203266607.
```

Using the rounded statement `2^-79` gives approximately `74.9125` bits.
Both numbers must be labelled with their convention.  No implementation may
describe an individual certificate as a 75-bit proof.

## 12. Gates and ordered implementation

All gates are conjunctive.

### A. Ledger, analytic census and formal seam

1. Append this C6 decision to `docs/prototype-status.md`.
2. Land an executable exact budget for Q, bytes, setup and raw credit.
3. Prove the new Lean addenda without editing frozen M1--M11/X4 theorems:
   Δ-residual algebra, base-share binding, corrected-key validity,
   QuickSilver product-polynomial expansion and `ProductClosure`
   composition, predecessor-conditional cache refinement, idempotent
   retransmission, unique child, abort-head stability and
   per-certificate/session composition.
4. Full `lake build`; zero `sorry`/`admit`; no new axiom beyond the standard
   mathlib set.  Commitment binding stays an explicit premise.

### B. State and codec

1. Implement canonical certificate/head/setup codecs and golden fixtures.
2. Implement atomic client state and provider slot journal.
3. Permanent crash-point tests cover every write/sync/rename boundary.
4. Permanent negative tests cover replay, rollback, fork, alternate child,
   nonce reuse, slot/range reuse, ambiguous ACK and noncanonical encodings.

### C. Residual IR

1. Implement one typed authenticated-value DAG, explicit
   `ProductClosure` nodes and the reverse accumulator for its linear
   subgraph.
2. Prove exact parity with the old verifier on scaled fixtures, including a
   nontrivial QuickSilver batch and its mask.
3. The direct, correction and product-mask leaf census must equal the old
   correlation/correction schedule.
4. Deleting, duplicating, reordering or changing one leaf must reject.
5. Any nonlinear key operation outside a certified `ProductClosure` must
   fail construction.

### D. Hidden-vector and cache wrapper

1. Commit before query and prove all old Ligero NTT/ip equations.
2. Prove `x=r+d`, the base-share RLC, every QuickSilver `Q/M0/M1`
   `ProductClosure`, the hidden correction dot product and the grand
   Δ-residual statement.
3. Prove fixed-capacity cache read/update and the authenticated new-slab
   link.
4. Exactly one packed wrapper opening per response; no per-token instance.
5. Proof payload `<=4,500,000 B`; complete response
   `<=35,000,000 B`.

### E. Local end-to-end

1. Golden GPT-2 output stays bit-identical.
2. Old C4/T1 profile and all historical validators stay unchanged.
3. One local connection produces 17 accepted certificates and separately
   exercises all four abort credits.
4. Every accepted certificate advances one atomic head; aborts advance none.
5. Proof size is flat across certificate ordinals and cache lengths.
6. Mock PCG is diagnostic only; production records require real/AES.

### F. Hardware

Only an explicit later owner GO may authorize a new clean A100 campaign.
The preregistered hard gates are:

```text
setup client traffic       <= 150,000,000 B
accepted baseline certs    >= 17
abort reserve              >= 4 baseline ranges
pi_final                   <= 4,500,000 B
complete response          <= 35,000,000 B
inline prover wall         <= 20.000 s
per-certificate soundness  >= 78.80929487391641 bits
cache/cert wire growth     0 B versus accepted ordinal/cache length
```

One warmup and at least three measured candidates are required.  No
selective retry, threshold relaxation, post-benchmark Q change or hidden
settlement is allowed.

## 13. Hard stops

C6 stops locally and records the obstruction if any of these occurs:

- the exact response lower bound exceeds `35,000,000 B`;
- the exact wrapper payload exceeds `4,500,000 B`;
- the setup/capacity formula cannot retain 17 accepts plus four burned
  baseline attempts below `150,000,000 B`;
- any cache proof field or opening count grows with current cache length;
- the construction needs a second response PCS opening or per-token proof
  instance;
- weights and embedding are collapsed under separate hidden-`u` RLC events,
  or the linear-functional block uses only one unamplified `Fp2` repetition;
- the residual coefficient schedule cannot be generated independently by
  the client without receiving the hidden correction vector;
- a key multiplication reaches the linear residual accumulator without an
  explicit, wrapper-certified `ProductClosure`;
- the base-share binding omits a direct source or product-mask correlation,
  uses a scalar-power RLC with an uncharged length loss, or is sampled before
  its witness commitments;
- one accepted predecessor admits two distinct accepted children for the
  same nonce/slot;
- abort permits correlation reuse or changes the accepted head;
- a new statistical event makes the complete bound miss the registered
  floor;
- a transparent local roofline projects above `20 s` without an
  implementation-backed optimization;
- implementation would require the historical deferred X4 settlement or a
  per-response trusted ceremony.

No hard stop may be bypassed by contacting a provider.

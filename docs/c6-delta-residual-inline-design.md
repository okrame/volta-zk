# C6 — inline Δ-residual certificate and persistent cache

Status: **OWNER REQUIREMENTS FROZEN; Q=121 CONTINGENCY ACTIVATED BEFORE
IMPLEMENTATION; FORMAL SEAM / ROOFLINE / PAIRED CODEC / PRODUCTION SOURCE
CENSUS / PAIRED COMPLETE SOURCE WITNESS / INDEPENDENT EXACT-INSTANCE
OPERATION DAG GREEN; PARAMETERIZED V2 TWO-SEED IDENTITY GREEN; CANONICAL PLAN
CODEC + FULL-T1 COMPILED RESIDUAL + DURABLE 17+4 SESSION + HIDDEN-U NATIVE
SUMCHECK REDUCTION + SCALED DUAL-TAPE C6RSC3 CODEC/DIFFERENTIAL GREEN; FUSED
T1 EVENT-SINK + FIRST/FOLDED/TERMINAL SCALED DIFFERENTIAL GREEN;
ROUND-SYNCHRONOUS SINGLE-BACKING ARENA LOCAL DIFFERENTIAL GREEN; SHARED
C6RSC3 COORDINATOR + SCALED FUSED PROVER AND VECTOR-FREE CLIENT TERMINAL
BYTE/TRANSCRIPT/PENDING DIFFERENTIAL GREEN; PACKED AUTHENTICATED-OUTPUT LINK
AND BLIND HIDDEN-U SOURCE ADAPTER GREEN; PCS-NATIVE DUAL-ROOT PERSISTENT-CACHE
AMENDMENT, EXACT 72-SLOT ROOFLINE AND SIX-GROUP C6LNK2 PACKED WRAPPER GREEN;
POINTWISE C6PC2 AND SOURCE-BOUND C6PS1 -> C6PC2 -> C6LNK2 -> PAIRED PCS
SCALED PATH GREEN WITH ZERO CACHE STAND-INS; FACTORIZED RUNTIME FOLD-BATCH
COMPILER + 653-ROOT FORMAL REPAIR + STRICT C6PS1 V2 TRANSCRIPT MIGRATION GREEN;
TYPED PENDING-TARGET / 24-ROUND CACHE INTEGRATION / `CacheSegK` REMOVAL /
BACKEND / FINAL ENVELOPE PENDING;
LOCAL IMPLEMENTATION AUTHORIZED; HARD STOP BEFORE POD**.

This document is the C6 plan of record.  It is a new descendant of the
accepted C4/T1 `rate=1/4,Q=120` inline profile.  It does not reopen or rewrite
the immutable C4 rate-8 FAIL, the C5 typed-PCG obstruction, or any X4/X4d
record.  C6 reuses implementation components where their statements match,
but it has a new proof statement, codec, state machine, soundness sum and
record lineage.

The construction removes the two dominant response fields:

1. the `38,348,720-B` direct `auth_corrections` vector is private witness to
   one amplified verifier-linear **Δ-residual event** evaluated in two
   independent MAC coordinates;
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
grand residual schedule, gives one response-wide equation per coordinate

```text
K_base[b] + Delta[b] * D_corr[b] = M_public[b],  b in {0,1}.
```

- `K_base` is a linear combination of verifier-only base-correlation keys.
  The client streams it from the one-time range and public coefficient
  schedule; it is never sent by the provider.
- `D_corr` is the matching linear combination of the hidden direct
  corrections.  The wrapper proves this dot product against the committed
  canonical correction vector.
- `M_public` is the matching combination of retained prover tags and public
  values.

The provider computes and proves each coordinate's committed-witness
aggregates but cannot adapt them after the binding challenge and does not
know either `Delta[b]` or `K_base[b]`.  The client performs both grand affine
checks outside the transparent wrapper.  They form one independently
amplified Δ-residual event.  A nonzero vector of affine closure errors is
charged once to the existing `epsilon_Delta_residual`; base-share binding is
not a fifth statistical wrapper event.  The old M8 product term remains in
the retained T1 soundness accounting.

The implementation MUST derive both prover constraints and the client
coefficient schedule from one typed authenticated-value DAG.  Its only legal
node classes are direct source/correction, public constant, add, subtract,
public scale, zero closure and `ProductClosure`.  A key multiplication outside
a certified `ProductClosure` is a construction-time error.  Hand-maintained
parallel formulas are forbidden.  Every base-key leaf, hidden-correction leaf
and product-mask leaf has one canonical correlation index, transcript
position and domain.  Missing, duplicate, reordered or dead leaves fail the
exact census.

### 3.1 Frozen production T1 source/correction census

The unchanged production-size T1 prover and verifier now expose an optional
logical schedule audit.  It is disabled by default and records only
`(ordinal, kind, role, product_triples, domain, kind-local offset, count)`;
it never records a mask, tag, verifier key, PCG seed or `Delta`.  The typed
`ProductMaskCorr` API makes an uncorrected full-field product mask distinct
from a direct corrected source and rejects a mask whose registered triple
count differs from the actual `prod_batch_prover` input.

Running the frozen GPT-2 `100+50` workload through the unchanged T1
prover/verifier gives:

```text
model direct subfield correction leaves             4,793,590
model direct full-field correction leaves              181,261
model-local ProductClosure masks / triples                672 / 672
final response-wide ProductClosure mask / triples           1 / 21,667
final response-wide ZeroBatch mask / zero closures          1 / 8,170

complete direct subfield leaves                     4,793,590
complete direct full-field leaves                     181,262
complete direct-correction leaves                   4,974,852
complete product-mask leaves                              673
complete source leaves                              4,975,525
total ProductClosure nodes / triples                   673 / 22,339.
```

The 672 local product closures are real one-triple QuickSilver closures
inside the model proof; they may not be collapsed in a hand-maintained
census.  They account for `672 * 32 = 21,504 B` of retained model product
messages.  The exact model transcript classification is:

```text
subfield auth_corrections                           38,348,720 B
full-field correction fields                        2,900,176 B
model-local product messages                           21,504 B
other model transcript bytes                                 0 B
model transcript total                             41,270,400 B
final product message + zero mask correction/tag           64 B
complete MAC transcript                            41,270,464 B.
```

The raw-correlation reservation independently reconciles:

```text
model raw = 4,793,590 + 2*181,933                    5,157,456
final product and zero masks                                  4
complete MAC raw                                    5,157,460
historical PCS reserve = 2*39,116                      78,232
complete allocated raw range                        5,235,692.
```

The canonical audit contains `81,661` model draws and `81,663` draws after
the two final masks.  Its pinned digests are:

```text
model allocation  06e789d6e27b9b5092c144463bc6a3e25328fa17f7fca38bd79c02385a134dc8
complete alloc.   b002d4a55d890aa61299c6dbe3e5794cef8d699d96dd64ad3c41d1ad34bb6c35
source schedule   526c28885fb6f77e8f569ece89c0c7442be24301a9430f3df4383428528cd9e7
correction sched. a7e22b733c9635de931ef3d9bd001c298facd413b80ff93ea48fa1b610e620da.
```

This closes the old-schedule source/correction census only.  The complete
GPT-2 authenticated-value DAG, cache witness and wrapper constraint census
remain separate gates.

### 3.2 Paired subfield witness extraction checkpoint

The production T1 path now has a second, explicitly opt-in prover-only
sidecar for the direct subfield leaves.  It materializes the canonical
`(r_i,d_i,m_i)` tuple in exactly the public schedule order:

- masks are copied only when witness collection is enabled;
- each historical correction-emission site attaches its canonical hidden
  `d_i`;
- tags already opened by T1 are retained, while tags for sources that T1
  never opens are expanded at sidecar close from the same already-consumed
  correlation range.  This does not consume a new domain, change counters or
  alter the allocation digest;
- a missing correction, duplicate/reordered domain, changed replayed tag or
  subfield draw after close fails closed.

The ordinary path never enables this collector and therefore retains the
frozen allocation and transcript.  After coordinate zero has run the model
once, coordinate one replays the exact complete correlation schedule against
an independent stream.  It reconstructs

```text
d_i[1] = x_i - r_i[1]
```

from coordinate zero's committed plaintext order, without rerunning model
inference or the old proof.  Full-field and ProductMask draws are replayed as
well so both stream schedules stay identical, but their witness extraction
belongs to the next full-DAG gate.  Distinct nonzero setup tape identities
are mandatory, and identical secret witness digests reject as an engineering
guard against relabelling one stream as two tapes.  The setup manifest, not
this digest inequality alone, remains the binding source of tape identity
and independence.

The clean frozen `100+50` reference run at `ba08871` gives:

```text
subfield leaves / coordinate                         4,793,590
hidden correction bytes / coordinate                38,348,720
prover-only (r,d,m) bytes / coordinate              153,394,880
second-coordinate model reruns                                0
plaintext digest
  b18cb65f0468dfbd9a9508bf2d70fcdfb57257a187235ae4b78e68a9bf782ea1
coordinate witness digests
  218bb80f5bfcb4fab22fd15e1b2ae9eee2041c5e934f32ce196ce0100ad3b8f4
  20add661a866d157f253f30e7f9b9e7b3cb1925fa2e7cf05735a68dd8733c5f8
pair digest
  4ed3f65d9c17f0eaeca7ea9f477f5516aa1a16f862a570b09759b17d2687cc1b
```

The `153,394,880-B` figure is local secret witness material, not client
setup, certificate traffic or a proposed serialized object.  The append-only
mock-PCG reference record is
`benchmarks/results/c6-t1-subfield-witness-2026-07-29-ba08871.json`,
SHA-256
`ae6d193329843445b5ff4e2fe757c5dcc87ee280ab5d39fa387966993fbdf505`.
It has no real/AES-PCG, wrapper-proof, final-byte, prover-time, cache or
hardware verdict.

### 3.3 Paired complete-source witness checkpoint

The opt-in source collector now also covers every full-field draw.  A direct
full-field source records `(r_i,d_i,m_i)` with `x_i=r_i+d_i`; a
`ProductMask` is separately typed, carries its exact product-triple count and
has canonical correction zero.  Every production T1 full-correction emission
site attaches its already-computed plaintext to the matching draw.  Missing
or duplicate direct corrections, a role/count mismatch, a correction on a
`ProductMask`, a late full-field draw after close, or any departure from the
pinned public schedule fails closed.  The collector is disabled on the
ordinary T1 path.

After the one coordinate-zero model/proof run, coordinate one replays the
same complete allocation schedule on a fresh stream:

```text
direct subfield:    d_i[1] = x_i - r_i[1]
direct full-field:  d_i[1] = x_i - r_i[1]
ProductMask:        fresh uncorrected r_mask[1], d_mask[1] = 0.
```

Consequently, the two coordinates must have identical direct-source
plaintexts but independent `ProductMask` plaintexts.  Comparing the aggregate
full-field plaintext digest across coordinates would be wrong because that
digest intentionally includes the fresh masks; a separate canonical digest
binds only the direct full-field plaintext schedule.  Distinct setup tape
identities and distinct subfield and full-field secret-witness digests remain
mandatory engineering guards.  The setup manifest remains the binding source
of tape identity and independence.

The clean frozen `100+50` reference run at `b98e453` gives:

```text
subfield leaves / coordinate                         4,793,590
direct full-field leaves / coordinate                  181,262
ProductMask leaves / coordinate                            673
all source leaves / coordinate                       4,975,525

hidden subfield corrections / coordinate            38,348,720 B
hidden direct full corrections / coordinate          2,900,192 B
all hidden direct corrections / coordinate          41,248,912 B

prover-only subfield (r,d,m) / coordinate           153,394,880 B
prover-only full-field (r,d,m) / coordinate           8,732,880 B
complete secret source sidecar / coordinate         162,127,760 B
second-coordinate model reruns                                0

subfield direct-plaintext digest
  b18cb65f0468dfbd9a9508bf2d70fcdfb57257a187235ae4b78e68a9bf782ea1
full-field direct-plaintext digest
  6e76ae45df26ae097dc47e85fd0fe571e1bd9af014be781dbd48cbe3c22a129d
coordinate full-field witness digests
  d907b75284ade00327d726854274946a5fdbe74cf98a058698d7cf44be381e3a
  84b7320269a1fa8c51768a73e0aff56d58bdc5a025debdb7aea4f37579a599dd
pair digest
  af1a0cbd392bfbb37b8bfa669d4bcafa8423f0dfbc8dc4f29513d8947e6d4b3d
```

The extra `16 B` beyond the model's `2,900,176-B` full-correction transcript
is the final response-wide ZeroBatch mask correction.  The 673 product masks
have canonical zero correction and add no hidden correction bytes.  All
secret-sidecar figures above are prover memory, not client setup,
certificate traffic or proposed serialization.

The create-new mock-PCG reference record is
`benchmarks/results/c6-t1-source-witness-2026-07-29-b98e453.json`, SHA-256
`c62941afd4cda3b0eed5c3e36dd27cffcd03301e7d0df14e9808ecffc9601ab5`.
It closes extraction and paired replay of the source leaves only.  It does
not yet link source/value IDs through the full authenticated-value operation
DAG, identify every operand of the 673 `ProductClosure` nodes, or prove the
cache/wrapper statement.  It carries no real/AES-PCG, final-byte,
prover-time, session or hardware verdict.

### 3.4 Operation-DAG migration seam frozen before code

The production DAG migration MUST NOT recover value identity from the
plaintext/tag pair `(x,m)`, from tag equality, from pointer identity or from
“most recently seen” values.  Copies, repeated public zeros and equal linear
expressions make those schemes ambiguous, while a malicious witness must not
receive collision-based aliasing freedom.

The admitted migration seam is therefore an explicitly separate
`c6-trace` diagnostic build:

- ordinary `ProverAuthed`, `ProverSubAuthed`, `VerifierKey`, `SubCorr` and
  `FullCorr` layouts remain byte-for-byte pinned at `32/24/16/24/32 B`;
- only the diagnostic build adds a copyable ghost provenance token.  The
  token is assigned from the canonical correlation/source ordinal or from
  the exact public/add/sub/scale operation that created the value;
- source tokens use the already-pinned interleaved source schedule.  They do
  not use a second counter inferred from secret witness values;
- `ProductClosure` operands/mask are captured only at the central
  `prod_batch_prover` seam, and zero roots only at the central ZeroBatch
  seam.  A missing/untracked token, wrong source role, reused mask or
  nonlinear ordinary node is a hard failure;
- the trace is normalized from ordered closure roots, so worker scheduling
  and allocation order cannot change the program digest.  The verifier trace
  must independently normalize to the same digest before the DAG milestone
  closes;
- the trace build emits a compact canonical plan/census artifact.  It is
  development evidence, not the production prover path and receives no
  timing credit.  The inline implementation consumes the compiled plan
  without enlarging authenticated-value objects.

The first trace checkpoint may migrate one value family at a time and stop at
the first untracked closure.  It may not replace that failure with a
value-based lookup or silently mark the value public.  Baseline T1 closure
targets remain exactly **673 ProductClosures / 22,339 triples / 8,170 zero
roots**.  The final response-wide corrected ZeroBatch mask remains a
base-share-bound direct source used by the retained ZeroBatch seam; it is not
miscounted as an 8,171st pre-mask zero root.

The prover-side migration checkpoint now reaches the complete frozen
`100+50` trace:

```text
canonical interleaved source tokens                    4,975,525
raw allocation-order linear nodes                     23,891,144
ProductClosures / product triples                    673 / 22,339
pre-mask zero roots                                         8,170
missing/untracked closure operands                              0
```

This was a dirty local diagnostic printed to stdout, not a run-of-record.
Golden output, transcript bytes, schedule digests and paired source-witness
digests remained unchanged.  The two fail-closed migration findings were
shape/provenance issues only: an MLE opening has 768 real authenticated
columns despite a 1,024-coefficient padded equality vector, and segmented
cache K/V folds must retain their sparse source expression across the GEMM
boundary.  The implementation binds the 768 real prefix and transports the
typed sparse expression; it does not synthesize padded sources or recover
identity from `(x,m)`.

The raw `23,891,144` count is explicitly **not** a canonical plan size or
timing result.  Allocation/scheduling order may change it.  The operation-DAG
milestone therefore remains open until ordered-root normalization emits a
compact plan digest and an independently generated verifier trace normalizes
to the same digest.

#### 3.4.1 Canonical trace normalization frozen before verifier migration

The normalizer is versioned as
`volta/proto/c6/operation-plan/v1`.  Its public inputs are the canonical
source manifest derived from the already-audited correlation draw schedule,
that manifest's `source_schedule_digest`, and exactly one independently
captured prover or verifier trace.  It does not inspect witness values, MAC
tags, verifier keys or corrections.

The ordered terminal stream is frozen as follows:

1. `ProductClosure`s in central-capture/protocol order;
2. within each closure, triples in vector order and operands in literal
   `(a,b,c)` order, followed by the closure's mask source;
3. after the last product closure, all pre-mask ZeroBatch roots in
   central-capture/vector order.

Closure boundaries, each triple count and both terminal counts are part of
the digest.  Reordering equal-looking roots is therefore not permitted.

Normalization performs an **iterative** ordered post-order traversal from
that terminal stream.  Source nodes encode their canonical flattened
schedule ordinal.  Public nodes encode the exact canonical little-endian
`Fp2(c0,c1)`.  `Add`, `Sub` and `Scale` retain their opcode, operand order and
exact scalar.  A raw operation is assigned its canonical node number at its
first post-order visit, so raw allocation IDs and worker interleaving are
irrelevant.  Existing DAG sharing is retained, but there is deliberately no
commutation, reassociation, constant folding, algebraic cancellation or
structural hash-consing: two separately constructed equal subgraphs remain
two nodes.  Cycles, out-of-range/future tokens, mixed trace namespaces and
untracked terminals fail closed.

Only terminal-reachable public/linear nodes enter the compiled plan.  Raw
operations outside every terminal are compiler garbage and are omitted while
their count is reported diagnostically; it is not hashed and receives no
security or timing credit.  In contrast, **every** scheduled source remains
in the leaf manifest and base-share RLC even when it is not reachable from a
linear/product operand.  This is required for the final corrected ZeroBatch
mask and for any direct leaf whose only terminal use is the base-share
binding.  It replaces the early residual-IR prototype's blanket
“every allocated node must be closure-reachable” check; it does not weaken
source binding.

The normalizer additionally enforces that every source whose manifest role
is `ProductMask` is the direct mask of exactly one ProductClosure, that no
other source is used as such a mask, and that a ProductMask is absent from
all linear operand graphs, product operands and ZeroBatch roots.  The final
ZeroBatch mask has role `DirectCorrection`; it is bound by the source
manifest/base-share RLC and is intentionally absent from the `8,170`
pre-mask root stream.

The compact artifact contains the version, source count and source-schedule
digest, reachable canonical node count, product/triple/zero censuses,
canonical program digest and diagnostic raw/reachable/omitted counts.  Only
the version, manifest identity, canonical census and program digest define
program equality; raw and omitted counts are informative.  The prover and
verifier use disjoint trace namespaces, normalize independently, and must
match all program-identity fields byte-for-byte.  A plan synthesized from
the prover result, a verifier formula table maintained by hand, or comparison
of counts without digest equality is not admissible.

The compiled model/build-global plan may be preinstalled at the provider.
Its digest and version are bound by every C6 certificate; if plan bytes are
ever installed at the client they count in full against the initial setup
budget.  The diagnostic trace/compiler remains outside the timed inline
prover.

The first full prover normalization on the frozen local `100+50` workload is
green.  It emits program digest
`0b4bb67835d315807e81d2c3457b5c53bcd82036622307d6f91dec2e62f489bf`
with **28,845,583 canonical reachable value nodes**.  Of the
**23,891,144** raw operation nodes, **23,874,732** are terminal-reachable and
**16,412** are omitted compiler garbage.  The omission rule was frozen above
before this measurement.  All **4,975,525 / 673 / 22,339 / 8,170** source
and closure censuses and the frozen transcript/allocation/source digests
remain unchanged.

This was a dirty, stdout-only diagnostic with no persisted record and no
timing credit.  It closes prover-side normalization only: the digest is not a
program identity of record until an independently instrumented verifier
normalizes to the same identity.

The independent verifier migration is now locally exact.  The complete
prover trace is finished and normalized before a fresh verifier trace
namespace begins; no trace token is copied between parties and both raw DAGs
are never retained simultaneously.  The diagnostic token carries an explicit
monotone namespace generation; linear operations, central closure capture and
normalization reject stale or mixed-namespace tokens.  Verifier correlation
expansion assigns the same canonical flattened source ordinals from its
independently audited draw schedule, and typed verifier keys retain provenance
through the exact public/add/sub/scale tree.  Corrections remain source
metadata, not artificial DAG operations.

On the frozen `100+50` workload both sides normalize to
`0b4bb67835d315807e81d2c3457b5c53bcd82036622307d6f91dec2e62f489bf`
with exactly **4,975,525 sources, 28,845,583 canonical nodes, 673
ProductClosures, 22,339 triples, 8,170 pre-mask zero roots and 23,874,732
reachable operations**.  Informative allocation-order diagnostics differ as
allowed by the frozen rule:

```text
                                      prover       verifier
raw operation nodes                23,891,144     23,874,804
terminal-reachable operations      23,874,732     23,874,732
omitted compiler garbage               16,412             72
```

The initial fail-closed comparison exposed one declared-sharing mismatch in
the final response-wide closure.  Each of 15 LogUp cross-checks creates two
distinct public `1` nodes on the prover side, but the verifier had reused one
equal public key between the two triples.  Mirroring the two verifier
constructions restored exact identity and accounts for all 15 missing
reachable nodes.  No algebraic rewrite or value-based matching was used;
values, MAC equations, correlations, corrections, challenge order,
transcript bytes, schedules and the frozen prover digest remain unchanged.

The successful schema-6 result was dirty and printed to stdout only.  It is
implementation evidence, not a persisted run-of-record and not a prover-time
measurement.  Diagnostic block hashes and targeted canonical-node/terminal
captures used to locate a mismatch are explicitly outside the program
identity.

The clean append-only identity record is
`benchmarks/results/c6-operation-plan-2026-07-29-28b2a16.json`, SHA-256
`404f5ab7625678e3c4449137e5eb74fb835f637eb1ced23b0daf56b0dd3c2592`.
It is bound to clean source commit `28b2a16538c2003b9efcf9f7d2030b09a075d325`,
records `git_dirty:false`, `pod_contacted:false`, exact prover/verifier
program identity and all frozen source/transcript/schedule censuses.  The
pre-existing untracked user note is named explicitly and excluded.  This
closes independent operation-plan identity only: the record still uses the
local mock PCG trace compiler and carries no inline-prover, final-byte,
session, real-PCG or hardware timing verdict.

#### 3.4.2 Parameterized compiled-plan seam frozen before code

The v1 identity above deliberately hashes the exact `Fp2` value of every
public node and every scale scalar.  That is correct evidence that the
prover and verifier executed the same authenticated-value program in the
frozen run.  It is not, however, a reusable model/build-global plan:
transcript challenges and public proof values change between responses, so
the v1 digest can change while the operation topology remains identical.
Treating the clean v1 record as reusable client parameters would therefore
be an engineering error.  The record remains valid and immutable in its
exact-instance scope.

Before a compiled residual plan or wrapper backend is implemented, C6 adds a
versioned parameterized identity with two separate bindings:

```text
topology_digest:
    source ordinals, structural zero, public-input slots,
    Add/Sub operand order, Scale(input, scalar-input slot),
    ProductClosure boundaries/roots and ZeroBatch roots

instance_digest:
    the canonical ordered `(slot kind, slot ordinal, Fp2 value)` stream
    for all public-node and scale-scalar slots in this response
```

`topology_digest` contains no response-specific field value.  A structural
zero created by the authenticated-value `ZERO` constructor is distinct from
a public-input slot whose runtime value happens to be zero; otherwise a
zero challenge or proof value could change graph sharing.  Public and scalar
slot ordinals are assigned in canonical post-order, not raw allocation
order.  The exact-instance v1 digest may continue to be emitted
diagnostically, but v2 topology equality and the per-response instance
binding are separate fields and may not substitute for one another.

Every certificate binds the v2 topology version/digest and the response's
instance digest after the public values and transcript prefix that determine
it.  The client derives the slot values independently from the retained
public proof and its own challenge transcript; the provider may not transmit
an instance-value vector or choose a client coefficient table.  The wrapper
proves its residual evaluation against that same ordered instance stream.
Changing, deleting, duplicating or reordering a slot must reject.

The first implementation checkpoint must satisfy all of the following before
the compiled plan is admitted:

1. independently captured prover and verifier traces have identical v2
   topology and instance identities for one response;
2. two otherwise identical full T1 runs with distinct transcript seeds have
   identical topology identities and different instance identities;
3. a permanent zero-valued public-slot test proves it does not alias the
   structural-zero node;
4. an exact opcode/operand/root encoding census establishes whether any
   client-received topology bytes fit the remaining `73,257,070-B` setup
   allowance.  No compression ratio is credited before a canonical decoder
   and measured artifact exist.

This checkpoint still does not authorize an inline trace compiler.  The
diagnostic trace remains outside the timed prover.  If the client cannot
regenerate the public slot stream or the topology cannot be represented
within setup without adding response-linear traffic, C6 records the
obstruction and hard-stops before wrapper benchmarking.

The first parameterized diagnostic checkpoint is green for identities and
provides a codec target, but does not yet claim a setup artifact.  Two
complete frozen T1 runs using transcript seed bytes `24` and `25` each
produce exact prover/verifier equality and the same v2 topology:

```text
topology digest
  bcdd169f3f9123bd3afe25a5427d4b4ae2f0859abdfd1e1b8dd20c0fc57af344

seed 24 exact / instance
  7f0154932ac19cec8448c4cdd7984a36cf7215abf03992eeb559b8e4dbaef81b
  7a21189b9580b163500595ca5cca8d1f5184017139f52ab3878e7238345cacaa
seed 25 exact / instance
  408ddb488524a9a362751a1f9f7e582040ce4f7612f2a5a95d22ff61ce420ab6
  1bd5aa751772c3f8e9404adbd1b7941a47474c9a5e333114b5fcc38856f734f7
```

The v2 canonical topology census is:

```text
source / structural-zero / public-input     4,970,850 / 1 / 1,436
Add / Sub / Scale                    12,961,295 / 83,197 / 10,828,852
canonical nodes / reachable operations       28,845,631 / 23,874,780
public-input / scalar-input slots                  1,436 / 10,828,852
nodes after ProductClosure terminals                    14,634,330
```

The additional 48 reachable nodes relative to historical v1 are exactly the
result of keeping zero-valued public inputs distinct from the single
structural-zero node.  Prover/verifier informative raw/omitted counts are
`23,891,222 / 16,442` and `23,874,882 / 102`.  Source, ProductClosure,
triple, zero-root, transcript and allocation schedules remain unchanged.

An absolute-ULEB source/operand candidate is `88,934,137 B`, which exceeds
the `73,257,070-B` client-parameter allowance by `15,677,067 B`.  The
preregistered specialized coding instead uses signed source deltas plus one
bit per operand to make backward distance one implicit:

```text
packed 3-bit opcodes                              10,817,112 B
signed source deltas                               6,400,974 B
operand unit-distance flags                        4,614,730 B
non-unit operand payloads                         41,858,132 B
terminal payload                                     303,651 B
canonical header                                      152 B
projection total                                  63,994,751 B
```

Of `36,917,836` operands, `18,183,230` have unit backward distance; of
`4,970,850` reachable sources, `3,422,207` immediately follow the previous
source ordinal.

The canonical codec checkpoint reproduces the projection exactly.  Full
schema-8 runs at both transcript seed bytes `24` and `25` materialize
independent prover and verifier artifacts of **63,994,751 B** and require
them to be byte-identical.  The cross-seed artifact is also identical, with
BLAKE3
`265f874ccf8dae865890a3218b33b0b29dd0f4236678470e093e6da31e51ebac`,
while the exact/instance digests differ as required.
The clean append-only records are
`c6-parameterized-plan-codec-seed24-2026-07-29-e437394.json` (SHA-256
`af785f987d7ef31cffc2111a607b778634bef5c7bd443220c644d5c1b9ee5580`)
and `c6-parameterized-plan-codec-seed25-2026-07-29-8006f36.json` (SHA-256
`6e054a12c8933fd7d20c4665df8edd1c9474d83e11f75af28eb3fcdbe306a861`);
both have `git_dirty:false`, `diagnostic:false`, `pod_contacted:false` and
`all_pass:true`.

The installed codec is `VC6PLN2\0`: a `152-B` manifest-bound header followed
by packed 3-bit opcodes, minimal zig-zag source-delta ULEB, one canonical
unit-distance bit per operand, minimal non-unit backward distances and
minimal terminal ids.  Its decoder is available in the ordinary non-trace
client build through a validating parser.  It recomputes the topology
digest and exact census and rejects wrong versions/manifests/digests,
reserved opcodes, noncanonical lengths/padding/ULEB, invalid sources,
forward operands, illegal ProductMask roles and trailing bytes.  Permanent
tests also establish compiler/normalizer equality and byte identity after
inserting an unreachable raw prefix.

The measured artifact is `9,262,319 B` below the total
`73,257,070-B` client-parameter/framing allowance.  Paired PCG
`76,742,930 B` + the existing `437-B` manifest + the artifact gives a
first exchange of **140,738,118 B**, leaving **9,261,882 B** for every
remaining client parameter and setup frame.  The plan-codec component
therefore records `materialized_artifact:true`,
`production_decoder_implemented:true` and `setup_fit_credit:true`.
This is not yet an overall setup or C6 PASS: the client-side generation of
the ordered instance slot stream, compiled residual execution, all other
setup parameters, inline timing, cache and wrapper remain open gates.

### 3.4.3 Runtime instance extraction seam frozen before code

The topology artifact deliberately contains no response values.  A second
response-linear vector of all `1,436 + 10,828,852` public/scalar slots on the
wire would undo that separation and is forbidden.  C6 instead records only
the raw public constants and public Scale operands that the existing role
actually constructs.  Structural zero is not a runtime instance event.

Canonical post-order and raw construction order are not assumed equal.
Offline compilation therefore produces two model/build-global extraction
maps:

- the provider map converts the prover's raw public/scalar event streams to
  canonical slot order; it is provider-preinstalled and its digest/version
  is included in `params_digest`;
- the verifier map converts the client's independently observed raw streams
  to the same canonical order; its exact bytes are included in
  `client_parameters` and count fully against the first exchange.

Neither map contains a field value.  Each role records its own runtime
values; the provider may not send an instance-value vector, a source
coefficient vector or a per-response extraction map.  Applying either map
must reproduce the certificate-bound `instance_digest`.  A count, kind,
ordinal or digest mismatch rejects before residual verification.

The extraction codec is fixed before measuring it as `VC6INS1\0`.  Its
header binds the codec/operation-plan versions, role, topology digest, raw
and canonical public/scalar counts, map digest and exact section lengths.
Public and scalar maps are separate sequences of raw ordinals in canonical
slot order.  Each sequence is encoded as its unique maximal runs of
successive `+1` ordinals.  A run stores:

```text
zigzag(start - expected_next_raw) as minimal ULEB
(run_length - 1)                  as minimal ULEB
```

where the first `expected_next_raw` is zero and later values are one past
the preceding run.  The strict decoder rejects nonminimal ULEB, a split
that could have been merged, zero/overflowing lengths, out-of-range or
duplicate raw ordinals, wrong canonical counts, nonzero reserved bytes and
trailing data.  Its recomputed map digest and topology binding must match
the installed setup manifest.

The first implementation stage is diagnostic compilation from the already
exact prover/verifier traces.  Two transcript seeds must produce
byte-identical maps for each role and both maps must reconstruct their
existing instance digests.  Only then may the response-local lightweight
value recorder be enabled.  The provider recorder is charged to total
inline prover wall; it records values only and may not enable the full
`c6-trace` graph or change ordinary authenticated-value layouts.  Client
recording and local buffering are verifier work and never wire credit.

If the verifier extraction artifact plus the `63,994,751-B` topology plan,
the canonical setup envelope and paired PCG exceeds `150,000,000 B`, or if
either role's map changes across the two frozen seeds, C6 hard-stops before
compiled-residual/runtime work.  No alternative mapping codec is selected
after seeing that measurement.

The implementation passes this gate in clean append-only runs at both
transcript seed bytes `24` and `25`.  Each map reconstructs the already
recorded canonical instance digest, and each role emits byte-identical
artifacts across the two seeds:

```text
                                      prover              verifier
raw public / scalar slots         1,466 / 10,837,046   1,466 / 10,828,876
canonical public / scalar slots   1,436 / 10,828,852   1,436 / 10,828,852
public / scalar maximal runs          262 / 2,552,791      262 / 2,552,791
header / public / scalar bytes        120 / 575 / 5,319,691
artifact bytes                                 5,320,386
```

The provider artifact has BLAKE3
`6506bdd9c0ed1ace474b32361a04adf3b0c6211cc06e9986be22aa38bfaea55f`
and map digest
`59a4e370a8904d15ebbd68f6e5afcf0e2458bd877fd7dfa7b0bfeb059b67065f`.
The verifier artifact has BLAKE3
`17ed0942429eec51d46ebc3f4bb418fefe55a2ae64f976f045f4e66797183535`
and map digest
`7dbc442c5e316de7e6f5e3f377348112c1d29e3d4501ecb04a8bb703b9737c20`.
Role separation deliberately makes the artifact digests different even
though their encoded lengths and run censuses coincide.

The client-received topology plus verifier map is `69,315,137 B`.
Including paired PCG and the existing `437-B` setup envelope gives
**146,058,504 B <= 150,000,000 B**, leaving **3,941,496 B** for every
remaining client parameter and setup frame.  This is a diagnostic
map-codec/setup-fit PASS, not runtime extraction: the lightweight
response-local recorder and its provider wall overhead remain mandatory
before compiled-residual credit.

The clean records are
`c6-instance-extraction-seed24-2026-07-29-3d8e2ea.json` (SHA-256
`d641f0bc652d1e76fb1e94d7e546cc56ffab9f6d04c049ce4fce1d049b71921c`)
and `c6-instance-extraction-seed25-2026-07-29-1817975.json` (SHA-256
`a4938bdda17a9c48b8470c2102cd26d0418da4904d58d7118e7fa74caa533280`).
Both are `git_dirty:false`, `diagnostic:false`, `pod_contacted:false` and
`all_pass:true`.

The lightweight recorder also passes complete same-response runs at both
seed bytes.  It is thread-local, does not add fields to any authenticated-
value type, and records only the existing `from_public` and public-`scale`
operands.  Each prover capture contains exactly `1,466 / 10,837,046` raw
public/scalar values and each verifier capture `1,466 / 10,828,876`;
applying the installed role maps reconstructs
`7a21189b9580b163500595ca5cca8d1f5184017139f52ab3878e7238345cacaa`
at seed 24 and
`1bd5aa751772c3f8e9404adbd1b7941a47474c9a5e333114b5fcc38856f734f7`
at seed 25 on both sides.  An event executed on a different thread is absent
from the owning thread's stream and therefore fails the exact raw census and
instance digest instead of being silently reordered.  Unit tests cover
ordinary-build capture, nested activation, overflow, thread migration,
role/map binding and exact scaled reconstruction.

The clean records are
`c6-runtime-instance-recorder-seed24-2026-07-29-3b01789.json` (SHA-256
`f4ea526eabdb7fa3a998d5d6c97a8d84bd3f3e6ba72e5a427da186d79110681b`)
and `c6-runtime-instance-recorder-seed25-2026-07-29-abf081c.json` (SHA-256
`c177506031cc31ff63d943bdb5c20d4cf6887f01125007bb2f037b864b5aff5b`).
Both are `git_dirty:false`, `diagnostic:false`, `pod_contacted:false` and
`all_pass:true`.  Full graph tracing is enabled in these record producers,
so they establish seam equality, not production overhead: a bound ordinary
build with graph tracing disabled and its provider wall delta remain required
before runtime/timing credit.

### 3.4.4 Installed reverse accumulator and coefficient-stream seam

The first compiled-residual implementation checkpoint is now green in scaled
scope.  The strict `VC6PLN2` decoder has one consuming installation path that
materializes local typed arrays for canonical opcodes, source ordinals,
backward operands, ProductClosure terminals and zero roots.  It is the same
validating pass used by the ordinary decoder; there is no second permissive
parser.  These arrays are local provider/client session memory.  They are not
serialized in setup or in a response, and the original canonical artifact
remains the only plan byte string counted against setup.

For one response, both roles combine the installed plan with their immutable
role-local extraction map and exact runtime instance values.  Reverse
accumulation seeds the `8,170` zero roots, walks the canonical nodes once in
reverse order, and emits:

```text
leaf_linear[source]  for every one of source_count schedule entries
public_plaintext     for public-input contributions
```

Scheduled leaves absent from the reachable linear graph receive coefficient
zero but still participate in base-share binding.  ProductMask leaves are
required to retain coefficient zero and remain full-field, uncorrected
sources.  Public and Scale values are fetched only through the installed
role map; topology, instance, cursor or census divergence rejects before any
residual output.

The post-commit base-share challenges are streamed directly from the existing
interactive `Transcript` sampler.  For source `i`,

```text
c_i = leaf_linear[i] + alpha_i

D_corr += leaf_linear[i] * d_i - alpha_i * r_i
M_public += c_i * m_i
K_base += c_i * k0_i
```

Provider and client hash the same streamed `c_i` schedule and compare a
constant-size binding.  No `Vec<alpha_i>`, `Vec<c_i>`, source-key vector or
prior-response vector is a wire field.  The production-shaped provider fold
streams both independent MAC coordinates in the exact interleaved physical
allocation order; the client seam accepts one local paired-key callback per
canonical source ordinal.

The paired source witness now binds both the physical allocation-schedule
digest and the accepted operation plan's `source_schedule_digest`.  This
extra binding was added before the full-T1 compiled-residual record because
checking only total leaves and ProductMask ordinals would not uniquely bind a
reordering of direct draw ranges.  Future paired-witness digests therefore
include the source-schedule digest; historical clean records remain immutable
evidence for their earlier extraction scope.

Permanent scaled tests prove exact equality with the historical residual
builder, paired subfield/full-field/ProductMask interleaving, both affine
coordinates, and fail-closed behavior for a divergent transcript or source
schedule.  The complete `volta-proto` `c6-trace` suite is green at
**138 passed / 0 failed / 1 ignored**.  This checkpoint is source-level
algebra and lifecycle evidence only.  Full-T1 installed-memory census,
paired residual execution, ordinary-build overhead, proof bytes, wrapper
soundness, real-PCG and the `20.000-s` gate remain open.

The next local diagnostic executes the same compiler and paired fold on the
full frozen `100+50` T1 shape.  Both roles accept the exact
`4,975,525`-source schedule, produce the same linear form and coefficient
binding, and accept both independent Δ coordinates.  No coefficient vector
is serialized; the residual response is two `Fp2` affine outputs, exactly
`64 B`.  This is only the residual output, not `pi_final` or a complete
certificate.

The measured structural memory census is:

```text
installed typed plan resident                         196,741,767 B
temporary reverse node workspace per role             461,530,096 B
retained compiled coefficients per role                 79,611,404 B
residual-only compile peak per role                    541,141,500 B
```

The compile peak is `temporary workspace + retained result`; it is not
whole-process RSS and excludes model, trace, runtime-value and paired-source
storage.  Provider and verifier are compiled sequentially in the diagnostic
harness, so these per-role values must not be summed into a claimed
deployment peak without a role-specific process measurement.

One dirty local release run reports:

```text
one-off installed-plan decode/install                   1.644425052 s
provider reverse compile                                0.507563488 s
provider paired source fold                             1.540541423 s
verifier reverse compile                                0.504332932 s
diagnostic client paired base-key fold                  1.501125329 s
```

The post-setup provider residual subtotal is
`0.507563488 + 1.540541423 = 2.048104911 s`.  All timings remain
`timing_credit:false`: graph tracing and mock source replay are active, the
unchanged T1 prover wall and runtime-capture overhead are not enclosed in one
ordinary-build timing scope, and the client side uses a diagnostic
source-derived key adapter rather than a deployed local key store.  Clean
cross-seed records are required before this full-shape checkpoint closes.
The hidden-vector/cache wrapper, final wire size, real-PCG session and
hardware gates remain open.

The clean cross-seed checkpoint is now complete at
`5f9a7ba1d7b1bcc8eaeec2739495170c4a2bea8e`.  Schema-11 records
`c6-compiled-residual-seed24-2026-07-29-5f9a7ba.json` and
`c6-compiled-residual-seed25-2026-07-29-5f9a7ba.json` have SHA-256
`b6d78a68f09e4dd2a78876e7e8451b715bd172f643c82a3d711a4b8ea2c852e4`
and
`445755cdde6ef33231986db29c60adeb462661bc8ce73e7e5a01d3b9bcc4139a`.
Both are clean non-diagnostic outer records with `pod_contacted:false` and
`all_pass:true`; the compiled-residual subrecord remains explicitly
diagnostic and receives no timing credit.

The topology, canonical plan artifact and all structural memory fields are
identical across the two seeds.  Instance, linear-form and combined
coefficient digests differ, establishing that the installed topology is
model-global while response-local values and transcript challenges are not
silently frozen.  Clean provider compile-plus-fold subtotals are
**2.115027772 s** and **2.031618948 s**, after one-off installs of
**1.637407891 s** and **1.646412629 s** respectively.  This closes Gate C's
full-shape residual execution evidence.  It does not close Gate D, the
ordinary-build timing scope, final wire replacement, real-PCG session or any
hardware gate.

Before wrapper integration, the paired coefficient seam was strengthened.
The clean diagnostic above streamed one `alpha_i` and reused it for both MAC
coordinates.  That proves arithmetic parity, but it does not instantiate
`c6_base_share_binding_two_vector_sound`: proportional error vectors could
share one accepting hyperplane.  The production paired fold now
derives two independent coefficient streams from the already budgeted
32-byte client batching seed under fixed coordinate-0/coordinate-1 domains.
For every source and coordinate

```text
c[b,i] = leaf_linear[i] + alpha[b,i].
```

The provider and client hash both ordered streams into one combined binding
digest.  Reusing, swapping or omitting either domain is a hard failure.  This
changes no setup or response byte count.  The historical records retain
their structural, arithmetic and timing-evidence scope, but receive no
base-share amplification or final-wrapper soundness credit.

The provider, client slice adapter and streaming client-key adapter all use
the same sealed paired expander.  A permanent test observes distinct
coordinate streams, accepts the honest paired residual, rejects a different
seed through the binding digest and preserves exact source-schedule failure.
The complete `volta-proto --features c6-trace` suite is
**144 pass / 0 fail / 1 ignored** and the workspace all-target check is
green.  The implementation source SHA-256 is
`63fddf8e1843987a6019c0dbb9e6197807b7bbf72d8c63db7a9fc4c47bf58c8e`.

The T1-to-sumcheck compiler is staged through the existing installed reverse
accumulator, never through a second hand-maintained DAG formula.  Its first
checkpoint accepts an exact terminal-weight schedule in installed
`ProductClosure/triple/(a,b,c)` order followed by installed zero-root order.
The schedule is bound to the plan artifact/topology, repetition and
plaintext-versus-tag role.  Both roles use the same reverse walker:
plaintext forms include public-node values, while tag forms treat public
nodes as zero and retain the same public scale inputs.  A zero-root-only
differential must reproduce the accepted compiled residual's leaf
coefficients and public term exactly.

This intermediate compiler deliberately does not yet define the post-root
weight-expansion domains or assemble source grammar, raw copy,
`ProductClosure` and `ZeroBatch` into a sumcheck statement.  Materialized
weights/leaf coefficients are reference-only and carry no production
memory, timing, proof or soundness credit.

The local checkpoint is green.  The installed census is exactly **22,339**
product triples and **8,170** zero roots.  One shared reverse walker now
serves both the historical compiled residual and the new plaintext/tag
terminal forms; the zero-product differential reproduces the historical
leaf coefficients and public term exactly, while an independent nontrivial
differential closes both plaintext and tag evaluations.  Runtime extraction
binding is checked even when a form happens to read no public or scalar
value.  The complete feature suite is **145 pass / 0 fail / 1 ignored**.
This result does not yet derive terminal weights from the transcript, build
the residual-sumcheck statement, hide its messages or bind its terminal PCS
claims.

The next checkpoint keeps the pre-query structural/root binding distinct
from the post-root relation statement.  After the five wrapper roots are
fixed, the already-budgeted 32-byte client residual batching seed is combined
with the fixed-root digest and installed plan artifact/topology under
`volta-zk/c6/residual-post-root-context-seed/v1`; the complete bundle is
bound under `volta-zk/c6/residual-post-root-challenges/v1`.  The resulting
context seed is local derivation state, not another message.  Existing
base-share streams continue to use their frozen coordinate domains, now from
this context seed.

The four terminal-weight streams use exact domains
`0xC65445524d0001`, `0xC65445524d0002`,
`0xC65445524d0101`, `0xC65445524d0102` for coordinate-0 plaintext/tag and
coordinate-1 plaintext/tag respectively.  Each expands ProductClosure
triples in installed `ProductClosure/triple/(a,b,c)` order, followed by
installed zero-root order.  A sealed bundle binds the root context, plan,
raw-seed commitment and all four schedule digests.  This closes challenge
provenance only; materialized schedules remain reference-only and the later
PCS orchestrator must enforce that the root token precedes release of the
client seed.

This local checkpoint is green.  The sealed reference bundle expands all
four schedules at the installed **22,339 triple / 8,170 zero-root** census,
and both the terminal reverse forms and paired base-key/provider folds have
post-root entry points that consume its context seed.  Deterministic replay
and every root/seed/domain/swap/mutation negative pass; the complete feature
suite is **145 pass / 0 fail / 1 ignored**.  The remaining ownership seam is
explicit: `volta-proto` currently receives the fixed-root digest, while the
later `volta-pcs` orchestrator must source it from the private fixed-root
typestate before releasing the seed.  Until that join and the complete
relation compiler exist, this carries no production or resource credit.

The subsequent relation-ownership audit found a soundness obstruction before
the compiler was written.  Identifying proof repetition `b` with MAC
coordinate `b` does not square the accepting set of an error confined to one
coordinate's tag, ProductClosure message or raw/aux copy: the other proof
repetition can remain honest.  The two-secret Delta theorem already exposes
this boundary through its two explicit `hbad` premises.  Shared plaintext is
enough for plaintext residual errors, not for every coordinate-local wrapper
relation.

The repaired v2 ownership is therefore:

```text
proof repetition 0: residual leaf slots 0..7; residual aux slots 0..15
proof repetition 1: residual leaf slots 0..7; residual aux slots 0..15
```

Each repetition independently batches one complete relation containing both
MAC coordinates.  MAC-coordinate alpha streams stay distinct; the affine
`leaf_linear` schedule stays shared.  Terminal challenge identity becomes
`(proof repetition, MAC coordinate, plaintext-versus-tag)`, yielding eight
streams.  Sumcheck rounds, maximum degrees and the **4,244-B** codec remain
unchanged, and no PCS slot or opening is added because both chains already
open the full registry.  Lean and the executable budget must certify this
amendment before the generic owner map or bundle v2 is implemented; v1 earns
no production credit.

Those two pre-code gates and the corresponding narrow Rust v2 checkpoint are
now green.  Both proof repetitions own leaf slots `0..7` and auxiliary slots
`0..15`, so each statement exposes **24** terminal tables and the pair exposes
**48** references without adding a PCS slot.  The residual proof magic,
version, proof domain and statement domain moved fail-closed to v2; a v1
proof is never reinterpreted as v2.  The encoded proof remains exactly
**4,244 B**.

The post-root schedule, context, seed-commitment, terminal-linear-form and
bundle domains likewise moved to v2.  The exact terminal stream domains, in
`(proof repetition, MAC coordinate, plaintext/tag)` order, are:

```text
(0,0): 0xC65445524D000001 / 0xC65445524D000002
(0,1): 0xC65445524D000101 / 0xC65445524D000102
(1,0): 0xC65445524D010001 / 0xC65445524D010002
(1,1): 0xC65445524D010101 / 0xC65445524D010102
```

All eight schedules replay exactly in installed triple-then-zero order, have
distinct schedule digests and are disjoint from the two retained paired-alpha
domains.  Schedule and terminal-form digests bind proof repetition, MAC
coordinate and form kind; out-of-range indices, kind/coordinate/repetition
swaps, changed roots, changed seeds and changed weights fail closed.  The
workspace, all-target check and the complete `c6-trace` feature suite are
green.  This checkpoint still receives no wire, timing or production credit:
the PCS fixed-root typestate join and the complete T1 relation compiler remain
mandatory.

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
post-commit client seed may expand both independent **grand-RLC coefficient
vectors** through the already declared computational transcript sampler; the
two domain labels and coefficient order are certificate-bound.  It does not
pre-expand the native sumcheck challenges.  For each family and repetition,
every sumcheck round is ordered

```text
prover fixes and sends the complete degree-two round polynomial
client returns one fresh Fp2 challenge
```

before the next round is formed.  Different-size families are
**round-synchronized**, not proved sequentially: at one global round the
prover fixes every active family's round polynomial, then the client releases
one challenge shared by those active instances.  A `mu=m` family activates
after `mu_max-m` leading rounds, so all terminal points are suffixes of one
global point.  In particular, hidden-`u` weights are active for all 21 rounds
and embedding activates after two rounds for the final 19.  Sending all
round challenges together with the grand-RLC seed, or starting the smaller
family after its suffix challenges have already been revealed, is forbidden:
either ordering lets the prover interpolate arbitrary degree-two messages
backwards between a false initial claim and the committed terminal opening.
The synchronized schedule preserves the existing `Transcript::append` then
`Transcript::challenge_fp2` interactive-DV model; it is not Fiat--Shamir and
adds no statistical event or response byte.

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

The first backend checkpoint implemented the functional construction,
degree-two round arithmetic, strict codec and terminal reduction.  Its
initial local driver proved the two families sequentially and remains only
an isolated arithmetic checkpoint.  The current pre-PCS driver replaces that
ordering with the round-synchronized schedule above and returns four
suffix-aligned terminal `U(r)` claims.
The verifier recomputes the public RHS and evaluates the truncated NTT
functional analytically; it never receives or reconstructs a hidden
`u_vector`.  The terminal point is extended by one zero coordinate when it
enters the strict-rate wrapper, selecting the witness half rather than the
random ZK half.

That hidden-only 21-round driver is not itself the final wrapper scheduler.
The complete repetition has one 24-challenge random point from the
`mu=24` cache family.  Paired residual activates at global round 1,
hidden-`u` weights at round 3, hidden-`u` embedding at round 5, and the
`ell=16` auxiliary point uses the last 15 random coordinates followed by the
shared fixed zero.  After all random rounds, appending that one zero gives
the 25-coordinate strict-rate PCS point; the residual, hidden-weight,
hidden-embedding and auxiliary points are its exact suffixes.

Consequently the hidden reducer must expose a step-wise prover/verifier
state: form and fix the active round messages, then accept exactly one
externally coordinated challenge, then bind.  Supplying an already sampled
24-challenge tape is forbidden for the same backwards-interpolation reason
as an upfront hidden-only tape.  The existing convenience driver may use the
step-wise state with no outer participants in arithmetic tests, but
production integration must use the one response-global coordinator.

The step-wise seam is now implemented.  For either side,
`fix/check_next_round` first freezes and validates every active hidden-family
message and returns its existing byte charge; only then may the outer
coordinator provide one challenge to `bind_challenge`.  A second round cannot
be formed while a challenge is pending.  The unchanged hidden-only
convenience functions are implemented on top of this state machine.

The four terminal values map into registered
`C6WrapperSlotOpeningClaim`s at their strict-rate `r || 0` points.  This
typed intermediate contains only repetition, cohort, slot, point and scalar
value; it contains no hidden `u` table.  A scaled cross-module differential
places those slot claims into two real packed PCS chains and verifies them.
This closes the hidden-to-PCS seam, not the complete wrapper scheduler:
cache, residual, auxiliary and the verifier-owned all-slot reduction still
must join the same 24-round coordinator before production acceptance.

The canonical sumcheck proof is exactly **4,004 B** at the production
`21+19`-round geometry, including its terminal digest.  This is charged
inside the existing `800,000-B` non-PCS allocation; it does not change the
`4,409,824-B` roof.  The reducer intentionally cannot return a production
acceptance result: its four terminal values remain untrusted until the one
packed C6 opening binds them to the pre-query roots.  Consequently no
historical `MultiOpenProof.u_c/u_gs` field is removed or credited yet.

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
  when the backend internally has different-size oracle chains and the two
  independent PCS fold/query repetitions required by Section 11.
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

The implementation may reuse only the low-level native-field primitives that
already have byte-level differentials: multilinear Möbius conversion,
rate-`1/8` NTT/folding, N4 Merkle construction/opening, and the standalone
schema-4 fold/opening frame codecs.  Reuse of those mathematical and codec
primitives does **not** admit the X4 response engine.  In particular C6 may
not call `GlobalChainDraftV4`, the X4 packed-schedule validator, an X4
manifest/settlement path, or any helper that silently reinstates the X4
`Q=111`/profile/model-global assumptions.

Every initial slot descriptor is a C6-domain digest of the C6 profile,
statement, cohort geometry and slot.  Every response-global fold descriptor
and packed opening schedule is likewise rehashed under a C6 domain and binds
the response statement, repetition, ordered C6 roots, fold frames and exact
86-draw tape.  Thus the reused N4 leaf/node hash implementation receives
C6-separated descriptors and cannot make an X4 root or schedule acceptable
as a C6 object.

### 5.1 Pre-backend wrapper roofline

Before backend code, C6 freezes the following capacity profile:

```text
profile                     mu/ell   slots/touched   encoded domain
cache witness                  24          8/8             2^28
paired Δ-residual witness      23          8/8             2^27
hidden-u weights               21          8/8             2^25
hidden-u embedding             19          8/8             2^23
wrapper auxiliaries        ell=16        32/32             2^19
```

The first four cohorts use the audited strict-rate weight-oracle geometry
`n_W=2^(mu+4)`; the auxiliary cohort uses `n_g=2^(ell+3)`.  The maximum
`mu=24` gives

```text
ell = ceil(log2(86 * 24^2 + 1)) = 16.
```

All 64 slots are present and touched, including zero/dummy capacity slots.
This keeps the opening grammar independent of the realized cache length,
response ordinal and final circuit census, and makes every inner-slot
frontier empty.  It is capacity, not evidence that the circuit fits.  The
production census must fit the exact per-cohort slots above; otherwise C6
hard-stops before backend benchmarking.

The frozen source census now discharges the paired-residual source capacity
preflight at `mu=23`.  Seven leaf-aligned columns use
`7 * 4,975,525 = 34,828,675` live entries.  The eighth closure-workspace
column is conservatively bounded by

```text
12*22,339 + 4*8,170 + 64 = 300,812 entries.
```

Thus the live upper bound is `35,129,487` entries inside
`8 * 2^23 = 67,108,864`, leaving `31,979,377` padded entries of headroom.
This is not yet the complete DAG/auxiliary circuit census and cannot be used
to waive any later wrapper-capacity gate.

The residual slot order is fixed before its source bridge:

```text
slot 0   common direct plaintext x; canonical zero at ProductMask leaves
slot 1   coordinate-0 base mask r
slot 2   coordinate-0 tag m
slot 3   coordinate-0 correction d
slot 4   coordinate-1 base mask r
slot 5   coordinate-1 tag m
slot 6   coordinate-1 correction d
slot 7   closure workspace
```

At every direct leaf the wrapper must prove
`x = r[0]+d[0] = r[1]+d[1]`.  At every ProductMask leaf it instead proves
`d[0]=d[1]=0`, uses the canonical zero in slot 0, and retains the two
independent mask plaintexts as `r[0]` and `r[1]`; ProductMasks are not falsely
identified across tapes.

The slot-7 live prefix is likewise canonical: ProductClosures in installed
plan order, triples in vector order, then coordinate 0 followed by coordinate
1, with each coordinate storing
`(x_a,m_a,x_b,m_b,x_c,m_c)`.  Zero roots follow in installed order, each as
coordinate-0 `(x,m)` then coordinate-1 `(x,m)`, followed by the already
budgeted 64-element footer reserve.  Remaining capacity padding is zero.
This freezes the witness grammar only.  Until the reverse-DAG binding,
product/zero constraints and residual sumcheck are implemented, these tables
produce PCS opening obligations, not an accepted residual proof.

The local reference source bridge now realizes this grammar without adding a
response field.  `C6PairedResidualLeafWitness` streams the exact installed
paired-source schedule into seven live prefixes, rejects a cross-coordinate
direct-plaintext mismatch or a corrected ProductMask, and exposes padded
tables only through an explicitly CPU/reference method.  The scaled
`C6PairedResidualClosureWitness` independently freezes the ProductClosure,
zero-root and footer order across two distinct witness commitments.  Its live
census is exactly

```text
12 * product_triples + 4 * zero_roots + 64.
```

Neither type is an accepted protocol message, and the production path must
consume live prefixes without allocating eight full padded host vectors.
The reverse-DAG/product/zero residual argument and its join to the global
round coordinator remain the next algebraic gate.

The serial slot-7 grammar is not by itself a multiplication
arithmetization: one opening `W(r)` cannot expose six different lanes of the
same ProductClosure row.  C6 therefore freezes the following use of the
already-budgeted auxiliary cohort before implementing the residual
sumcheck:

```text
aux  0..5    coordinate-0 product xa,ma,xb,mb,xc,mc
aux  6..11   coordinate-1 product xa,ma,xb,mb,xc,mc
aux 12..13   coordinate-0 zero-root x,m
aux 14..15   coordinate-1 zero-root x,m
aux 16..31   reserved to the cache argument
```

Each residual auxiliary lane has `2^15` semantic rows inside its `2^16`
coefficient vector.  Product lanes use the first 22,339 rows, zero lanes the
first 8,170 rows, and the remaining semantic rows are constrained zero.  The
upper `2^15` coefficients are independent ZK masks; the shared final zero
coordinate selects the semantic half.  They are not unconstrained witness
padding.  Raw slot 7 remains the canonical interleaved capture stream and a
post-root randomized copy identity binds it to the sixteen lane-aligned
views.  Thus the transpose is proved rather than trusted.

Each proof repetition owns one complete relation containing both MAC
coordinates.  It runs two round-synchronized sumcheck families:

```text
family                 rounds   maximum degree   activation
residual leaf/raw          23                2            1
residual auxiliaries       15                3            9
```

The first family proves direct/ProductMask source grammar, the two compiled
`D_corr`/`M_public` dot products, reverse-DAG leaf terms, raw-copy terms and
semantic-tail zero constraints.  The auxiliary family proves the matching
reverse-DAG targets, copied lanes, every zero root and the existing
QuickSilver `Q/M0/M1` equations.  Public selectors and randomized row
weights are combined into one public multilinear coefficient table before
the sumcheck, so a product term has degree three, never four.

At the first residual round the verifier records the initial leaf/raw claim.
When the auxiliary family activates, before releasing that round's shared
challenge, it checks that the two initial claims sum to the public
complete-relation target.  No prover-selected split scalar is serialized.
In **each** proof repetition, the terminal relations consume all eight
residual openings at `r_res || 0` and auxiliary slots 0--15 at
`r_aux || 0`.  Slots 16--31 remain exclusively cache-owned, preventing
duplicate terminal ownership.

All ProductClosure operands and zero roots must be committed before the
existing product/ZeroBatch challenges they use.  The production model path
therefore defers those closing challenges/messages until the five wrapper
roots are fixed; it may not recommit after seeing `chi`.  Coordinate 0 keeps
the existing retained ProductClosure messages and one-time masks.
Coordinate 1 emits one independent masked `(M0,M1)` pair per closure,
**673 * 32 = 21,536 B**, inside the existing 800,000-B non-PCS allocation.
No ProductMask is reused for two message pairs.

The residual proof sends, per repetition,

```text
23 * 3 * 16 + 15 * 4 * 16 = 2,064 B
```

of round values, or **4,128 B** across both proof repetitions before small
fixed framing.  This fits the frozen non-PCS allocation without changing any
cap.

The earlier `4/|Fp2|^2` term covered only the one-root MAC plus base-share
subterm; it did not include the residual sumcheck and batching roots.  The
complete named event now reserves a conservative per-complete-repetition
root budget of 256.  This covers the exact sumcheck degree-round total
`2*23 + 3*15 = 91` plus source/tail, reverse-DAG, copy, product and affine
batching terms.  Two independently domain-separated proof repetitions,
each checking both MAC coordinates, give

```text
epsilon_Delta_residual <= 256^2 / |Fp2|^2
                        = 2^16 / |Fp2|^2
                        > 239 bits of soundness.
```

This remains one amplified Delta-residual event, not a fifth event.  The
inherited M2/M8 product-collapse terms remain in the retained T1 accounting.
The complete-ownership gate is green: the exact budget reports **91**
degree-round roots, **256** reserved roots per complete proof repetition and
`2^16/|Fp2|^2 = 239.999999998656...` bits for the complete named event.
Q=121 complete response soundness is `79.472744138609180097...` bits.  At
that ownership checkpoint all five focused budget tests passed, full Lean
built **3,257 jobs**, and the derived audit was **283 total / 47 C6**
targets with only `propext`, `Classical.choice` and `Quot.sound`.  Its
obstruction/composition certificates are
`c6_split_coordinate_accepting_card` and
`c6_complete_relation_two_repetition_card_le`; the exact integer certificate
remains `c6_delta_wrapper_event_better_than_239`.  The sharper historical
theorem continues to describe only the MAC/base-share core.  The executable
ownership screen pins **24 owned table slots per proof repetition**, **48**
total references and **8** post-root terminal streams.  It adds
**68,157,440 coefficient symbols** to the informative work screen, raising
the effective estimate from 32 to **32.3037...** whole-cohort passes and the
model-plus-wrapper floor to **8.388 s**; this is conservative screening and
earned no benchmark credit.  The later atomic-relation re-sum below
supersedes those two timing-screen numbers without changing their
ownership result.

The first Rust milestone after this freeze is green and intentionally
narrower than the residual argument.  The versioned witness-only adapter
transposes the canonical slot-7 live prefix into the sixteen lane-aligned
semantic live prefixes above, rechecks the exact census and zero footer, and
materializes a zero-padded `2^15` semantic half only as a CPU/reference seam.
The T1 geometry **22,339 / 8,170 <= 32,768** and every scaled lane/order/tail
and malformed-layout case are permanent regressions.  The feature suite is
**145 pass / 0 fail / 1 ignored** and all-target compilation is green.
Residual source/export SHA-256 values are
`493fc8a501d51aeb4459194e3a18e7063a8fb842b12a539f09b94ffc71ef301b` /
`12dea86dbe8646d76d1688d55554ffa42aa477f2d86cde4e0cde2c9aa651df57`.
The adapter does not create the independent upper-half masks, a PCS source,
a proof field or any accepted obligation.  Admission into the wrapper
remains blocked on production installed-plan capture, the randomized
raw-copy identity and synchronized residual sumcheck.

The residual sumcheck implementation is split once more before the T1
relation compiler.  Its first checkpoint is a statement-generic arithmetic
engine over precombined public coefficient MLEs and exact wrapper slot
owners.  It enforces the frozen degree-2/degree-3 schedule, shared suffix
challenges, the activation-time public-target equality and PCS-bound
terminal-factor interface.  It does not by itself certify that those public
tables encode the source grammar, reverse DAG, raw transpose,
ProductClosure or ZeroBatch equations.  Materialized public tables are a
scaled/reference seam only.  Production memory/timing and any
round-transcript hiding claim remain blocked on separately reviewed
compiler/blinding paths.

The local arithmetic checkpoint implements that boundary with a strict
two-repetition codec of **4,244 B**: **4,128 B** of round values and
**116 B** of fixed framing.  Its scaled differential independently replays
the response-global coordinator, verifies the activation-time unsplit target,
checks every terminal against the source MLE and confirms the two exact
common-point suffixes.  This measured codec result still earns no
production-response removal: the materialized coefficient tables are not the
T1 relation compiler, the round messages have no implemented hiding layer,
and the terminal factors have not yet entered the packed PCS assembly.

The historical split-owner instance of that engine is superseded.  Its v2
statement builder now requires the complete `8 leaf + 16 auxiliary` owner set
in **each** proof repetition, and its scaled fixture exercises all 24 terminal
claims on both chains.  The post-root reverse compiler consumes one of the
eight `(proof repetition, MAC coordinate, kind)` schedules, while its v2
digest prevents any old four-stream form from being admitted.  This is only
the generic owner and challenge boundary: source grammar, reverse-DAG
equations, randomized raw-copy, ProductClosure/ZeroBatch equations and
semantic/padded-tail constraints must still be assembled by the separately
preregistered T1 compiler.

#### 5.1.1 Atomic T1 residual-relation manifest and challenge order

The compiler is hard-stopped once more before code.  One post-root seed is
not sufficient if it derives both the coefficients used to form public
outputs and the random weights later used to batch equations containing
those outputs.  For example, after seeing one batching row
`(rho_0,rho_1)`, an adaptive prover can choose nonzero errors
`(e_0,e_1)=(rho_1,-rho_0)` and make
`rho_0*e_0+rho_1*e_1=0` identically.  With two proof repetitions and three or
more adaptive public errors, the two batching rows still have a nontrivial
kernel.  The registered squared bound therefore requires the public
`D/M`, `M0/M1` and retained closure claims to be fixed before either complete
relation repetition receives its batching weights.

C6 freezes the following two-stage post-root order:

1. the PCS orchestrator produces a private fixed-root token binding the five
   ordered wrapper roots, this manifest, installed plan artifact/topology,
   source-schedule digest, runtime-instance digest and exact slot/census
   geometry;
2. only then does the client release the first fresh 32-byte
   `base_share_seed`, together with the retained post-root
   ProductClosure/ZeroBatch challenges in their unchanged protocol order;
3. the provider fixes one canonical public-claims frame containing all
   retained challenge/message digests, both coordinates' ordered
   ProductClosure `M0/M1` values and both compact `(D_corr,M_public)` output
   pairs; the client validates its manifest, counts and digest;
4. only after that frame is fixed does the client release an independent
   32-byte `relation_seed`;
5. the eight terminal schedules, both complete-relation atomic-weight
   streams and the two sumcheck statements are derived from the resulting
   relation context before the first residual round message.

The first seed drives only the existing independent alpha streams
`0x00C6524553494401` and `0x00C6524553494402`.  It does not drive any
coefficient that batches a provider public output.  The second seed drives
the terminal streams and two new atomic streams:

```text
proof repetition 0 atomic stream  0xC641544F4D000001
proof repetition 1 atomic stream  0xC641544F4D010001
```

All ten relation streams are disjoint from the two alpha streams.  Their
outputs are modeled as independent uniform `Fp2` challenges in the
information-theoretic analysis; the implementation uses the existing
domain-separated cryptographic expander and reports that computational
assumption separately.  The additional `relation_seed` costs exactly **32 B**
inside the already frozen **800,000-B** non-PCS allocation, so it changes
neither the **4,409,824-B** `pi_final` roof nor the
**33,586,456-B** complete-response roof.

The structural manifest is
`volta-zk/c6/t1-residual-relation-manifest/v1` with magic
`C6RLM1\0\0`.  It binds all formulas and orders below, the exact factor-tuple
set, table geometry, installed plan/artifact/topology/source schedule,
ProductMask ordinals, closure boundaries, triple and zero-root counts, raw
layout, live/tail cutoffs and every challenge domain.  No coefficient table
is serialized in setup or in a response.  The post-root implementation must
use distinct contexts

```text
volta-zk/c6/residual-base-share-context/v3
volta-zk/c6/residual-public-claims/v1
volta-zk/c6/residual-relation-context/v3
volta-zk/c6/residual-relation-challenges/v3
volta-zk/c6/residual-atomic-weight-schedule/v1
```

and v3 terminal-schedule/terminal-linear-form domains.  The current v2
post-root bundle remains valid diagnostic evidence but cannot be admitted by
the production T1 compiler.  The `C6RSC2` arithmetic proof codec need not
change: it already binds the complete-owner statement digest and strict
decode rejects a different statement.

For the atomic relation, let the residual leaf tables be

```text
L = [x, r0, m0, d0, r1, m1, d1, raw]
```

of semantic length `N_L=2^23`.  Let `A[0..15]` be the auxiliary semantic
halves of length `N_A=2^15`, in the already frozen lane order.  For source
ordinal `i`, `dir_i` and `pm_i` are the disjoint public Direct/ProductMask
selectors from the installed source manifest.  Define

```text
X_b(i) = dir_i*L[0][i] + pm_i*L[1+3*b][i]
T_b(i) = L[2+3*b][i].
```

The source grammar consumes three independent atomic weights for every
source, in source order:

```text
S_0(i) = dir_i*(L0-L1-L3)[i] + pm_i*L3[i] = 0
S_1(i) = dir_i*(L0-L4-L6)[i] + pm_i*L6[i] = 0
S_x(i) = pm_i*L0[i]                              = 0.
```

Thus a Direct row proves the two exact `x=r_b+d_b` equations, while a
ProductMask row proves canonical `x=0` and `d_0=d_1=0` without identifying
its independent `r_0,r_1`.  ProductMask sources must be installed
full-field leaves, must have zero `leaf_linear` coefficient and must be the
unique mask of exactly one installed ProductClosure.

Let `zeta_j=chi_zero^(j+1)` be the unchanged response-wide ZeroBatch powers,
and let the shared installed reverse walk seeded by those powers produce
`leaf_linear[i]=ell_i` and public term `P`.  The two alpha streams give
`alpha[b,i]`.  The public compact outputs are constrained, in coordinate
order, by

```text
R_D(b) = P + sum_i ell_i*d_b[i]
           - sum_i alpha[b,i]*r_b[i] - D_corr[b]       = 0

R_M(b) = sum_i (ell_i+alpha[b,i])*m_b[i]
           - M_public[b]                               = 0.
```

`ell_i` and `P` are shared between MAC coordinates; the alpha streams are
not.  This deliberate split is exactly the client coefficient schedule

```text
K_base[b] = sum_i (ell_i+alpha[b,i])*k0[b,i].
```

The client reconstructs it locally and later checks
`K_base[b] + Delta[b]*D_corr[b] = M_public[b]`.

For reverse-DAG binding, schedule `(p,b,Plaintext)` compiles public term
`P_rev[p,b]` and source coefficients `c_x[p,b,i]`; schedule
`(p,b,Tag)` compiles zero public term and coefficients `c_m[p,b,i]`.
Writing its installed triple weights as
`omega[p,b,kind,t,a/b/c]` and zero-root weights as
`nu[p,b,kind,z]`, the four scalar reverse relations inside repetition `p`
are exactly

```text
R_rev_x(p,b) =
    P_rev[p,b] + sum_i c_x[p,b,i]*X_b(i)
    - sum_t (omega_a*A[6b+0][t]
             +omega_b*A[6b+2][t]
             +omega_c*A[6b+4][t])
    - sum_z nu_z*A[12+2b][z]                           = 0

R_rev_m(p,b) =
    sum_i c_m[p,b,i]*T_b(i)
    - sum_t (omega_a*A[6b+1][t]
             +omega_b*A[6b+3][t]
             +omega_c*A[6b+5][t])
    - sum_z nu_z*A[13+2b][z]                           = 0.
```

Each receives one additional independent outer atomic weight so it cannot
cancel another named relation.

The raw-to-auxiliary transpose is not trusted.  For global installed triple
ordinal `t`, coordinate `b` and component
`k=(xa,ma,xb,mb,xc,mc)`,

```text
raw_pos = 12*t + 6*b + k
aux     = A[6*b+k][t].
```

For zero-root ordinal `z`, coordinate `b` and component `k=(x,m)`,

```text
raw_pos = 12*triples + 4*z + 2*b + k
aux     = A[12+2*b+k][z].
```

One fresh atomic weight is consumed per position in exactly this
triple/coordinate/component order and then zero-root/coordinate/component
order, proving the sum of `rho_pos*(L7[raw_pos]-aux)` is zero.  Independent
weights, rather than powers of one scalar, are mandatory.

For ProductClosure `c`, the existing challenge powers reset as
`w[c,j]=chi[c]^(j+1)` in that closure's triple order.  For both coordinates
the compiler includes

```text
R_Q(c,b) =
  sum_j w[c,j]*(xa[j]*xb[j]-xc[j])                     = 0

R_M0(c,b) =
  m_mask[c,b] + sum_j w[c,j]*ma[j]*mb[j] - M0[c,b]    = 0

R_M1(c,b) =
  r_mask[c,b]
  + sum_j w[c,j]*(xa[j]*mb[j]+ma[j]*xb[j]-mc[j])
  - M1[c,b]                                            = 0.
```

The mask values are read from the closure's unique ProductMask source row;
the operands are read from the corresponding six auxiliary lanes.  Each
`Q/M0/M1` scalar receives its own outer atomic weight in
closure/coordinate/`Q,M0,M1` order.  The two coordinate plaintext copies are
both constrained; neither is accepted merely because the other coordinate's
`Q` is zero.  The unchanged response-wide zero equations are

```text
R_Z(b) = sum_z zeta_z*A[12+2*b][z] = 0,  b=0,1,
```

with one outer atomic weight per coordinate.  Product and zero operands are
already root-bound before `chi[c]` or `chi_zero`; the inherited M8/M2
collapse terms remain in the retained T1 soundness accounting.

Every unused semantic coefficient is constrained zero.  Atomic weights are
consumed row-major for slots `0..6` on
`[source_count,N_L)`, then for raw slot 7 on
`[12*triples+4*zero_roots,N_L)`, including the frozen 64-entry footer.
Auxiliary tails are consumed lane-major: lanes `0..11` on
`[triples,N_A)` followed by lanes `12..15` on
`[zero_roots,N_A)`.  The independently random upper `2^15` auxiliary halves
are excluded from these equations and are selected away by the final zero
coordinate; they are not silently zero-filled.

Within each proof repetition the atomic stream is consumed in this exact
order:

```text
1  source S0,S1,Sx per source
2  affine R_D,R_M per coordinate
3  reverse outer R_rev_x,R_rev_m per coordinate
4  raw-copy positions
5  ProductClosure Q,M0,M1 per closure and coordinate
6  ZeroBatch R_Z per coordinate
7  leaf/raw zero tails
8  auxiliary zero tails.
```

At the frozen T1 census this is, per proof repetition,

```text
source grammar              3 * 4,975,525        14,926,575
affine outputs              2 * 2                         4
reverse outer              2 * 2                         4
raw copy                    12*22,339 + 4*8,170     300,748
product equations          673 * 2 * 3                4,038
zero equations             2                             2
leaf/raw zero tails                                   31,979,441
auxiliary zero tails                                     223,540
atomic stream outputs / repetition                    47,434,352
atomic stream outputs / two repetitions               94,868,704.
```

The raw zero-tail count starts at `300,748`, so it explicitly includes the
64-entry footer; the already reported `300,812` slot-7 live layout is
`300,748` copied values plus that zero footer.

Each listed scalar or cell equation `R_j=C_j+W_j=0` receives its next
independent atomic weight `eta_j`.  The compiler adds witness terms
`sum_j eta_j*W_j` to the two sumcheck families and sets the public unsplit
target to

```text
target[p] = -sum_j eta_j*C_j.
```

This fixes every sign: public terms are never inserted as hidden dummy
tables.  The only legal leaf factor tuples are the eight linear slots.  The
auxiliary factor tuples are the sixteen linear slots plus exactly

```text
(0,2) (0,3) (1,2) (1,3)
(6,8) (6,9) (7,8) (7,9),
```

corresponding respectively to `xa*xb`, `xa*mb`, `ma*xb`, `ma*mb` in each
coordinate.  All contributions with the same factor tuple are accumulated
into one canonical coefficient MLE; duplicate terms or any other quadratic
tuple reject.

Provider and client must derive byte-identical manifest, public-claims,
coefficient and statement digests.  The provider may stream/fuse coefficient
generation, and the client may stream only the statement digest and terminal
coefficient evaluations; neither side is allowed to serialize or retain a
response-linear coefficient vector merely to satisfy an API.  A production
compiler must also prove that its source `x/m` rows are the exact installed
T1 source IDs and runtime instance, preserving the existing subfield/full-
field roles; it may not add a witness-trusted source table or infer identity
from values.

The pre-compiler formal and executable gates are now green.  Lean
constructively exhibits the one-row cancellation in
`c6_adaptive_two_claim_batch_has_nonzero_kernel`, proves the nonzero
three-error/two-row kernel by rank-nullity in
`c6_adaptive_three_claim_two_batch_kernel`, and records the repaired
fixed-before-weights bounds in `c6_fixed_relation_batching_sound` and
`c6_fixed_relation_two_repetition_sound`.  The full build remains **3,257
jobs** and the derived audit is **287 total / 51 C6** targets, zero
`sorry`/`admit` and only the standard axioms.

The executable report charges both 32-byte seeds, **10 complete-relation
streams**, **94,868,704 atomic outputs**, **601,496 terminal-expander
outputs** and **225,997,412 coefficient-accumulation writes**.  Charging one
read plus one write/multiply-add per accumulation yields a conservative
**547,465,024 compiler-equivalent symbols**, with explicitly no timing
credit before a fused-compiler benchmark.  Including the earlier ownership
amendment gives **7,796,270,912** screened coefficient symbols,
**34.7434735164...** whole-cohort passes, an **8.450848617...-s**
model-plus-wrapper floor and **11.549151382... s** to the 20-second ceiling.
The second seed remains inside the frozen 800,000-B non-PCS allocation:
`pi_final` stays **4,409,824 B** and the complete response stays
**33,586,456 B**.  All six focused wrapper-budget tests pass.

The authorized local v3 checkpoint is now green.  `C6RLM1` reconstructs and
binds the installed artifact, topology, runtime instance, exact
ProductMask-to-closure ownership, capacities, formulas, factor tuples and all
ten stream domains.  The production PCS seam can create the root-bound
typestate only from its private five-root token and an exact production
manifest.  The subsequent Rust states enforce

```text
fixed roots + retained chi
  -> base-share seed / alpha streams
  -> canonical D/M and ordered M0/M1 public-claims frame
  -> independent relation seed
  -> eight terminal schedules + two atomic schedules.
```

The two raw seeds have one common commitment domain; a zero seed or reuse of
the base-share seed as the relation seed rejects.  A claims mutation after
the relation seed invalidates the bound digest rather than silently
recompiling different weights.

The scaled differential compiler consumes all eight frozen atomic families
in order, independently evaluates each original equation, reconstructs the
public target with the registered sign and accumulates exactly the eight
leaf-linear, sixteen auxiliary-linear and eight canonical
auxiliary-quadratic coefficient MLEs.  Its nontrivial reference fixture has
family census

```text
[12, 4, 4, 32, 6, 2, 964, 32] = 1,056 outputs / repetition
```

and both complete repetitions accept the honest witness.  Independent
source-grammar, raw-order, leaf-tail and auxiliary-tail mutations reject in
their named family.  Changing an `M0` claim before relation-seed release
changes both complete statement digests and makes the Product family false;
changing it after seed release fails the context digest.  The v3 terminal
schedule digests are eight distinct values and remain separated from the v2
diagnostic schedule.

The reference bridge into `C6RSC2` validates the exact owner/table geometry
and factor-tuple set and binds the atomic compiler digest into the sumcheck
statement digest.  A two-repetition scaled prove/encode/decode/verify passes;
changed compiler binding, zero binding/output census, reordered tuples,
non-power-of-two tables, invalid suffix geometry and post-build mutation all
reject.  The legacy generic-statement hash path is unchanged when no compiler
binding is present, and the production proof codec remains exactly
**4,244 B**.

This remains a CPU/reference checkpoint.  It deliberately refuses production
geometry and clones materialized coefficient arrays only at small scale.
Therefore it earns no PCS, response-removal, memory or measured-time credit.
The next algebraic/engineering gate is a provider/client byte-identical fused
T1 compiler that streams coefficients and terminal evaluations into the
existing synchronized sumcheck/packed-PCS assembly without retaining or
serializing response-linear vectors.  Sumcheck-message hiding, production
auxiliary/upper-half sources, cache constraints and the final certificate
envelope remain pending.

#### 5.1.2 Dual-tape blind transcript and fused-state amendment

The post-`C6RSC2` implementation audit found three obstructions that must be
closed before a production-shaped fused compiler is admissible:

1. `C6RSC2` sends all degree-2/degree-3 round evaluations in clear.  Masking
   those evaluations on only one of the two C6 tapes introduces a
   one-field-secret forgery branch and would reduce the complete residual
   event to approximately 128 bits.
2. The generic prover and verifier retain every public coefficient MLE.
   Because the atomic weights are independent, an exact multilinear
   sumcheck cannot both discard all folded coefficient state and avoid
   replaying the complete atomic stream on every round.
3. A packed PCS claim at `r || 0` is still a clear MLE evaluation.  The
   independently random upper half hides the query/fold views, but it does
   not hide the claimed lower-half evaluation itself.  Production acceptance
   therefore requires the existing M9 pattern: correction-created pending
   authenticated claims followed by a blind link to the same packed PCS.

`C6RSC2` and its **4,244-B** codec remain immutable diagnostic/reference
objects.  The production candidate is versioned separately as `C6RSC3`.
Every hidden scalar in `C6RSC3` is authenticated on **both** independent
connection tapes.  For one proof repetition:

```text
leaf first round                         g(0),g(1),g(2)       3
leaf later rounds                    22 * [g(0),g(2)]        44
auxiliary first round              g(0),g(1),g(2),g(3)       4
auxiliary later rounds        14 * [g(0),g(2),g(3)]          42
round scalars / repetition                                     93
```

The first round of each family is deliberately uncompressed: it derives the
authenticated initial family claim as `g(0)+g(1)` without serializing a
provider-selected split.  Once that claim is live, subsequent rounds use the
existing M3/M11 compressed grammar.  The auxiliary first message may be
computed and sealed locally with the leaf first message, but it enters the
transcript only at the frozen activation round.  At that boundary, on each
tape, the prover ZeroOpens

```text
leaf_initial + auxiliary_initial - public_target.
```

The tag is uniformly masked by the fresh first-round correlations, so this
preserves the required check-before-challenge ordering without another
correlation draw.

The terminal interface accepts exactly 24 pending M9 claims per repetition
and per tape, in the frozen eight-leaf/sixteen-auxiliary owner order.  It
forms the two linear terminal expressions locally.  For the exact eight
quadratic tuples, it authenticates eight product values with fresh full
correlations, closes them in one eight-triple `ProductClosure` per tape, and
places the leaf and auxiliary terminal residuals into one two-row
`ZeroBatch` per tape.  A pending slot claim is not PCS-bound and cannot be
returned as an accepted value.  The later packed authenticated-output link
is the only constructor that may upgrade it to a bound claim.

The strict `C6RSC3` payload is:

```text
dual-tape round corrections       2*93*2*16              5,952 B
activation ZeroOpen tags          2*2*16                    64 B
eight product-value corrections   2*8*2*16                 512 B
two ProductClosure messages       2*2 tapes*32              128 B
two ZeroBatch correction/tags     2*2 tapes*32              128 B
strict headers/digests                                      116 B
total                                                       6,900 B.
```

The core consumes, on each tape, exactly

```text
round masks                 2 repetitions * 93              186
terminal product values     2 repetitions * 8                16
terminal ProductMasks       2 repetitions * 1                 2
terminal ZeroBatch masks    2 repetitions * 1                 2
blind core / tape                                             206 full correlations.
```

The 48 residual pending-slot transfers add 48 full correlations per tape,
for a residual subtotal of **254 full correlations/tape**.  This is an
allocation inside the already frozen **39,116-full** historical PCS reserve,
not an addition to the **5,235,692-raw** per-attempt reservation.  The
complete wrapper census must still account for hidden-u, cache and the common
authenticated-output link before any reserve is released or reduced.

The packed-PCS repair follows the already-proved M9/X4 authenticated-output
shape but is C6-domain-separated.  All 64 slot claims in a repetition are
first pending and dual-authenticated.  One degree-2 blind linear-functional
link batches their exact, fixed target points and moves them to a fresh
25-coordinate PCS point.  Its final ZK coordinate is protocol-checked
nonzero.  The existing packed fold/query chain opens only at that new point,
where every witness/auxiliary upper half one-time-pads the clear global
opening.  The two-chain PCS query payload and its **3,609,824-B** roof are
unchanged; the packed pending/link framing remains part of the 800,000-B
non-PCS allocation and must be frozen before integration.  A target-point
clear scalar, a verifier-supplied zero ZK coordinate or an unlinked pending
claim is a hard failure.

The production statement no longer hashes materialized coefficient arrays.
`C6RSC3` binds a semantic compiler descriptor containing the root token,
`C6RLM1` manifest, installed artifact/topology/source schedule, runtime
instance, canonical public-claims frame, relation context, both exact atomic
stream descriptors, target, owner registry, factor tuples and all censuses.
Those fields determine every coefficient uniquely.  The provider and client
derive the same descriptor before the first round; a coefficient-array digest
is retained only by the scaled `C6RSC2` differential.  This is a versioned
binding change, never a reinterpretation of a v2 digest.

The fused provider is allowed one bounded, ephemeral post-challenge
coefficient workspace because independent random coefficient MLEs cannot be
folded in sublinear state without either changing the batching distribution
or replaying the full stream every round.  This is sumcheck state, not a
serialized or cross-response retained vector.  The exact schedule is:

1. replay the atomic stream once to fix both first-family messages;
2. after the first leaf challenge, replay it once and accumulate directly
   into the half-size folded leaf coefficient state;
3. at auxiliary activation, reuse the already sealed first auxiliary
   message; after its first challenge, replay once into its half-size folded
   state;
4. fold those states normally, free each at family completion, and execute
   the two proof repetitions sequentially;
5. the client never allocates a coefficient vector: after the common
   terminal point is fixed it replays once and accumulates only the 32
   terminal coefficient scalars, then checks them against the semantic
   descriptor that both roles fixed before the first round.

No full `2^23` coefficient table may exist on host or device.  The largest
legal folded coefficient state is exactly

```text
8 * 2^22 = 33,554,432 Fp2 = 536,870,912 B.
```

Allocation counters must distinguish coefficient state, witness state and
codec buffers; a hidden clone, host spill, second live repetition or
response-persistent coefficient allocation fails the memory gate.

The conservative work screen charges four atomic expansions across provider
and client and ten read/write-equivalent operations per coefficient
contribution.  It therefore replaces the reference-only
**547,465,024-symbol** compiler charge with **2,640,050,432 symbols**.  The
effective screen becomes **44.0689172477...** whole-cohort passes and the
model-plus-wrapper floor **8.6911235221... s**, leaving
**11.3088764778... s** to the 20-second ceiling.  This is still an
informative preregistration and earns no timing credit.

Soundness is amended without adding a fifth wrapper event.  The original
fixed-relation branch remains bounded by `256^2/|Fp2|^2`.  Across both proof
repetitions, every complete relation is authenticated on both MAC tapes; the
dual checks cannot weaken the conservative single-tape root bound.  One
complete proof repetition charges exactly

```text
degree-round challenges                 2*23 + 3*15          91
activation ZeroOpen                                           1
eight-product scalar-power closure                      8+2 = 10
two-row scalar-power terminal ZeroBatch                  2+1 = 3
blind-transcript subtotal                                      105 <= 256.
```

The `8+2` and `2+1` terms are the existing Rust scalar-power M8/M3
implementation theorems, not the sharper independent-vector bounds.  The two
independently domain-separated **proof repetitions**, each checking both MAC
coordinates, therefore bound the blind-transcript branch by another
`256^2/|Fp2|^2`.  Their union gives

```text
epsilon_Delta_residual <= 2 * 256^2 / |Fp2|^2
                       = 2^17 / |Fp2|^2
                       > 238 bits.
```

The hidden-u reducers and the common pending-output link stay inside the
existing `linear_functional_sumchecks` event, now conservatively reserved as
`256^2/|Fp2|^2 >239 bits`.  Q=121 complete soundness remains
`79.472744138609180097...` bits; the proof and complete-response roofs remain
**4,409,824 B / 33,586,456 B** because both are allocation caps.

This amendment reinstates a Lean-first hard stop before `C6RSC3` Rust.  The
required additive statements are:

- the full-first-round claim and activation ZeroOpen close the same
  degree-2/degree-3 sumcheck relation as the compressed M3/M11 recursion;
- the eight terminal products plus two-row terminal ZeroBatch close the
  generic terminal expression;
- two independent proof-repetition bad sets of cardinality at most 256
  square, and the
  union of clear-relation and blind-transcript branches has numerator
  `2^17`;
- the exact Goldilocks-`Fp2` certificate proves that event better than
  238 bits.

That additive Lean checkpoint is now green.  The new
`C6BlindTranscript.lean` module proves
`C6FullFirstRoundWire.compressedRoundPoly_initialClaim`,
`c6_full_first_round_activation_closes`,
`c6_terminal_eight_products_two_zero_rows_close`,
`c6_eight_product_closure_sound_scalar`,
`c6_two_terminal_rows_zeroBatch_sound_scalar`,
`c6_blind_transcript_root_census_le_256`,
`c6_blind_two_repetition_card_le_256`,
`c6_clear_blind_union_card_le_2_pow_17` and
`c6_delta_blind_wrapper_event_better_than_238`.  The full project builds
**3,258 jobs**; the derived audit is **303 total / 67 C6** targets, with zero
`sorry`/`admit` and only `propext`, `Classical.choice` and `Quot.sound`.

That formal checkpoint advanced the hard stop to the scaled dual-tape codec
and its negative differential.  The scaled checkpoint below is now green;
the hard stop advances in order to the fused provider/client event sink.
Production packed-link, cache and CUDA work remain later gates.  No provider
or pod work is authorized by this amendment.

#### 5.1.3 Scaled C6RSC3 checkpoint

The separate Rust module `c6_residual_sumcheck_blind` implements the scaled
`C6RSC3` statement, strict codec, reference prover and designated verifier.
Its magic/version and statement/proof domains are distinct from immutable
`C6RSC2`.  The public statement digest binds the nonzero semantic compiler
descriptor, topology, target and geometry; it does not bind or expose the
materialized coefficient-array digest.  The small `C6RSC2` statement remains
private inside this scaled object solely as an arithmetic oracle.  Production
must replace that ownership with the fused semantic compiler.

The implementation enforces the amended interaction order:

1. both tapes authenticate the complete first leaf message;
2. later leaf messages use the compressed grammar;
3. the complete first auxiliary message and the activation residual are
   fixed and checked before the common activation challenge;
4. subsequent leaf and auxiliary challenges remain synchronized;
5. all 48 terminal table claims transfer into typed pending MAC values;
6. eight fresh products close through one `ProductClosure` per tape, then the
   two final rows close through one `ZeroBatch` per tape.

The verifier reconstructs verifier keys only.  It never receives a clear
round value and returns only pending verifier claims.  The pending frame is a
separate typed object and contributes exactly
`48 claims * 2 tapes * 16 B = 1,536 B` of correction wire; it is deliberately
not included in the 6,900-B sumcheck proof and is not PCS-bound.

The production constants are formulas over the frozen repetitions, table
count and terminal-product count rather than duplicated literals:

```text
round scalars / repetition                 93
core full correlations / tape             206
pending full correlations / tape           48
total full correlations / tape            254
strict proof bytes                       6,900
```

Every one-time correlation domain includes repetition, tape, purpose and
index and excludes the reserved domain bits.  The purposes distinguish leaf
rounds, auxiliary rounds, pending claims, product values, ProductMask and
ZeroMask.  Equal verifier secrets across the two MAC coordinates reject
fail-closed.

The non-production differential uses five leaf rounds and three auxiliary
rounds.  Its proof is exactly **2,292 B**, its separate pending correction
wire **1,536 B**, and each tape consumes exactly **110** full correlations in
**24** domains with zero subfield draws.  Prover and verifier transcript
ledgers are byte-identical; every pending plaintext equals the independently
verified clear `C6RSC2` terminal claim.  Five permanent tests cover the exact
production census, strict codec/version/canonicality failures, the clear
differential, distinct tape behavior, invalid topology and mutations at every
round/activation/product/zero/pending/owner/tape seam.

The focused suite is **5/5 PASS**; the complete `volta-pcs` group is
**157 pass / 0 fail / 1 ignored**; and `cargo test --workspace -q`,
workspace all-target checking, formatting, the executable C6 budget and the
Lean audit all exit zero.  Repository-wide `clippy -D warnings` remains
blocked by unrelated historical warnings in dependency and suspended X4
code, so it is not represented as a green gate.  A crate-local
`volta-pcs --lib --no-deps` pass with those inherited lint classes explicitly
isolated exits zero.

This checkpoint remains scaled/reference evidence.  It earns no production
response-removal, memory, setup, timing, real-PCG, cache, packed-PCS, CUDA or
hardware credit.  In particular, a pending claim cannot become accepted
until the common authenticated-output link binds it to the packed opening.
The next ordered implementation gate is the byte-identical provider/client
fused T1 event sink; only after that checkpoint may the packed link be
assembled.

#### 5.1.4 Fused atomic event-sink interface freeze

The fused compiler is a refactor of the exact v3 atomic grammar, not a second
compiler.  One witness-independent replay owns the atomic-weight stream and
emits two ordered event kinds:

```text
Output {
    proof_repetition,
    output_ordinal,
    family,
    weight,
    weighted_public_constant
}

CoefficientWrite {
    proof_repetition,
    output_ordinal,
    family,
    target,
    coefficient
}

target =
    LeafLinear(table, row)
  | AuxiliaryLinear(table, row)
  | AuxiliaryQuadratic(lhs, rhs, row).
```

`Output` occurs exactly once before every output's writes.  The emitter, not
the sink, draws `weight` from the frozen
`C6ResidualAtomicWeightSchedule`.  `output_ordinal`, family and target order
are canonical and checked; a sink cannot omit, duplicate, reorder or invent a
weight.  Every row/table/factor index is range-checked before delivery.

The one canonical output order is:

1. source ordinal, then its three SourceGrammar rows;
2. coordinate 0 then 1, correction then tag Affine rows;
3. coordinate 0 then 1, plaintext then tag Reverse rows;
4. product-triple raw copies, then zero-root raw copies, in frozen
   coordinate/component order;
5. closure ordinal, coordinate 0 then 1, `Q`, `M0`, `M1`;
6. coordinate 0 then 1 Zero rows;
7. leaf tables 0--6 tails, then slot-7 tail;
8. auxiliary product-lane tails, then zero-lane tails.

The completion record binds compiler/event version, manifest digest,
relation-challenge digest, linear-form digest, atomic-schedule digest, proof
repetition, target and exact per-family output/write censuses.  It does not
hash a materialized coefficient array.  An optional scaled audit sink may
hash every event for differential testing; that diagnostic hash is not a
production requirement and cannot add one hash call per production write.

The exact production write formulas per proof repetition remain:

```text
SourceGrammar   6*direct + 3*ProductMask             29,851,131
Affine          6*source                             29,853,150
Reverse         4*source + 12*triples + 4*zero       20,202,848
RawCopy         2*raw_copy                              601,496
Product         12*triples + 4*closures                 270,760
Zero            2*zero                                  16,340
LeafTail        manifest leaf-tail outputs           31,979,441
AuxiliaryTail   manifest auxiliary-tail outputs         223,540
total / repetition                                  112,998,706
total / two repetitions                            225,997,412.
```

The semantic emitter takes no witness.  It may compile only one reverse
terminal form at a time and may stream each alpha coordinate directly; eight
terminal coefficient vectors and two full alpha vectors may not coexist.
Provider witness evaluation is a sink concern.  Its live source adapter
binds the installed leaf, closure and auxiliary witness digests and supplies
canonical zero padding without allocating padded witness tables.  The client
uses no witness adapter.

Four consumers are fixed:

1. one provider replay accumulates both complete uncompressed first-family
   messages directly from the live witness;
2. after the first leaf challenge, one provider replay builds only the
   eight half-size leaf coefficient states;
3. after auxiliary activation, one provider replay builds only the
   twenty-four half-size auxiliary linear/quadratic states;
4. one client replay evaluates the exact 8+16+8 terminal coefficient scalars
   at the fixed leaf/auxiliary points and retains no vector.

At production geometry the largest legal coefficient allocation remains the
leaf state:

```text
8 * 2^22 Fp2 = 33,554,432 Fp2 = 536,870,912 B.
```

Only one proof repetition and one family state may be live.  Allocation
counters separately report leaf coefficient state, auxiliary coefficient
state, witness views and codec buffers.  A full `2^23` coefficient table,
eight simultaneous reverse forms, hidden witness padding, second live
repetition or response-persistent coefficient vector fails closed.

Implementation must first refactor the scaled reference compiler onto this
same emitter.  Its materializing/evaluation sink must reproduce the existing
statements, family residuals and mutation attribution exactly.  A second
provider-audit sink and witness-free client-audit sink must then produce the
same event completion and scaled per-event audit digest.  Only after that
differential is green may first-message, folded-state and terminal sinks be
connected to `C6RSC3`.  No proof bytes, soundness term, correlation count,
setup byte or gate changes in this interface freeze.

#### 5.1.5 Scaled fused event-sink checkpoint

The frozen interface is now implemented locally.  The old materializing
compiler remains only under `test+c6-trace` as an independent pre-refactor
oracle; the public scaled reference compiler uses the same
`replay_c6_residual_atomic_events` emitter as every fused consumer.  Both
proof repetitions reproduce the complete statement, target, family
residuals and mutation attribution byte-for-byte.  In the scaled fixture each
replay emits exactly **1,056 outputs / 1,185 coefficient writes**, with write
census

```text
[21, 24, 48, 64, 28, 4, 964, 32].
```

Provider and client audit sinks independently obtain the same semantic
completion and optional per-event digest.  Swapped repetitions, malformed
live-witness ownership, invalid row/point geometry and an oversized
coefficient allocation reject before acceptance.

The three concrete fused consumers are green against materialized arithmetic:

1. the live-prefix witness sink produces the exact three leaf and four
   auxiliary first-round evaluations, and their Boolean split sums to the
   statement target;
2. the folded sink reproduces every materialized `fold_low` coefficient table
   after an arbitrary first challenge;
3. the terminal sink reproduces all **8 + 16 + 8** `eval_mle` coefficient
   scalars without constructing an equality vector.

The terminal equality cursor is LSB-first, caches repeated rows and updates
sequential rows by their changed binary digits.  It precomputes inverses only
for nonzero factors and separately counts zero factors, so transcript
coordinates exactly equal to zero or one and nonmonotone row resets are
covered by permanent differentials.

The production target split implied by the same emitter is exact:

```text
leaf-selected writes / repetition                111,889,262
auxiliary-selected writes / repetition             1,109,444
total                                             112,998,706

leaf folded state       8 * 2^22 Fp2             536,870,912 B
auxiliary folded state 24 * 2^14 Fp2               6,291,456 B.
```

`RawCopy` is deliberately split one leaf and one auxiliary write per output;
the four closure writes per ProductClosure belong to the leaf family while
the triple expansion belongs to the auxiliary family.  A manifest-bound
response-local allocation tracker owns a non-clone lease for the live state:
a second family or repetition under the same owner fails before vector
reservation, dropping the first state returns the lease, and active/peak
elements and bytes are exposed for later backend accounting.  The scaled
test peak is **512 Fp2 / 8,192 B**.

The complete `volta-proto` feature suite is **146 pass / 0 fail / 1 ignored**,
the complete workspace suite exits zero, and all-target checking and
formatting are clean.  The final gate exposed
three stale assertions left behind when `7a0ea20` amended the executable
blind/fused re-sum but did not amend its Python test.  Only those assertions
were updated to the already-frozen report schema and constants; the budget
script was not changed, and the combined C6 budget suite is **9/9 PASS**.
Repository-wide strict clippy remains blocked by historical warnings in
unrelated modules; filtering the strict run to the modified
`c6_residual.rs` reports no warning.  This is still scaled/reference
evidence.  The production formulas and allocation guard have not been
exercised as a T1 prover, and no C6RSC3 proof, packed opening, response-byte
removal, setup/correlation change, cache argument, real-PCG, CUDA, timing or
hardware credit is earned.  The next ordered gate is to feed these sinks into
the already-versioned `C6RSC3` coordinator.

#### 5.1.6 Round-synchronous single-arena amendment

The first integration audit found one lifetime obstruction in the frozen
sentence “only one proof repetition and one family state may be live.”
`C6RSC3` does not run the two family sumchecks serially: the auxiliary first
message is fixed at global round 8, before challenge 8, and every later leaf
and auxiliary message pair must be fixed before the same shared challenge.
After challenge 8 the prover therefore needs both folded family states until
the auxiliary suffix completes.  Completing the leaf family first would
reveal suffix challenges before the corresponding auxiliary messages and is
forbidden.

The corrected invariant is one response-local coefficient arena and one
proof repetition, with late admission of the auxiliary family into that same
arena.  It does not permit a second arena, a second live repetition, a full
coefficient table, a response-persistent vector or an early auxiliary state.
The exact production lifecycle is:

1. after leaf challenge 0, admit the eight half-size leaf tables:

   ```text
   8 * 2^22 = 33,554,432 Fp2 = 536,870,912 B;
   ```

2. fold only the leaf state through challenges 1--7; before challenge 8 the
   auxiliary family retains only its sealed four-scalar first message;
3. fix the global-round-8 leaf message, auxiliary first message and
   activation check before challenge 8;
4. after challenge 8, fold leaf to eight `2^14` tables and admit the
   first-fold auxiliary state as twenty-four `2^14` tables:

   ```text
   leaf        8 * 2^14 = 131,072 Fp2 = 2,097,152 B
   auxiliary  24 * 2^14 = 393,216 Fp2 = 6,291,456 B
   combined   32 * 2^14 = 524,288 Fp2 = 8,388,608 B;
   ```

5. fold both states after each remaining shared challenge, release each
   family at completion, and begin the next proof repetition only after the
   arena is empty.

At arbitrary scaled geometry, auxiliary admission is legal only after the
leaf state has exactly `8 * (auxiliary_entries / 2)` elements; the admitted
auxiliary state has exactly `24 * (auxiliary_entries / 2)` elements.
Aggregate arena occupancy, per-family occupancy and peak bytes are checked on
every admission, fold and release.  Duplicate family admission, an early
auxiliary admission, a changed repetition, cap overflow, underflow or a
second arena fails before allocation or transcript progress.

Logical truncation is not physical release: Rust `Vec::truncate` preserves
capacity and therefore cannot justify the admission figures above.  The
production arena MUST own one fallibly allocated backing buffer whose
capacity is exactly the initial leaf state.  Leaf tables are folded in place;
at auxiliary activation their live prefixes are compacted to the front of
that same buffer, and the auxiliary replay writes into the reclaimed tail.
No per-table coefficient `Vec`, `shrink_to_fit`, allocator-dependent
reallocation or second coefficient backing allocation is admissible.  The
manifest must additionally prove that the combined activation occupancy fits
the initial leaf allocation:

```text
32 * (auxiliary_entries / 2)
    <= 8 * (leaf_entries / 2).
```

Reserved backing capacity and logical per-family occupancy are separate
counters.  Reserved capacity stays at the initial leaf allocation until the
proof repetition releases the arena; logical occupancy follows every fold.
The scaled path uses the same rule with its exact smaller initial allocation.

This amendment changes only allocation ownership.  It preserves the
canonical first-message/activation/shared-suffix transcript, the four atomic
replays, proof codec and bytes, correlation domains and counts, terminal
claims, soundness re-sum and the **536,870,912-B** maximum.  The earlier
single-family tracker is intentionally superseded before it is connected to
`C6RSC3`; no production or timing credit is earned by this freeze.

#### 5.1.7 Single-backing arena checkpoint

The amended arena is locally implemented.  Leaf admission performs one
fallible exact-capacity allocation for all eight coefficient tables; table
layout is metadata over that single `Vec<Fp2>`, not eight coefficient vectors.
Every fold updates live prefixes in place without changing capacity.  At the
shared-suffix boundary the leaf prefixes are compacted to the front and the
auxiliary replay writes its sixteen linear and eight quadratic tables into a
zeroed range of the reclaimed tail.  Read-only table views are stack arrays
of slices held under the arena lock and allocate no coefficient storage.

The arena separately reports current leaf, auxiliary and aggregate logical
elements, current/peak reserved capacity and peak logical occupancy.  A
non-clone family lease binds manifest, repetition, family and current table
length; every exact binary fold updates the arena before transcript progress.
Dropping one family releases only its layout.  The backing allocation is
released only when both synchronized families are gone, after which the next
proof repetition may start.

The scaled differential pins:

```text
initial leaf live/reserved                512 / 512 Fp2
activation leaf + auxiliary           16 + 48 = 64 Fp2
activation reserved                          512 Fp2
terminal leaf + auxiliary              8 + 24 = 32 Fp2
arena empty after both releases                 0 Fp2.
```

The backing pointer and capacity are identical before and after auxiliary
admission, while all folded leaf and auxiliary tables remain exactly equal to
the independent materialized `fold_low` oracle through terminal evaluation.
A separate no-large-allocation re-sum pins production at
**33,554,432 Fp2 / 536,870,912 B** reserved and
**524,288 Fp2 / 8,388,608 B** logically live at activation.

Permanent negatives reject auxiliary before leaf, early auxiliary admission,
duplicate family, changed live repetition, wrong manifest, terminal overfold,
individual/aggregate cap violations and a geometry whose combined activation
state cannot fit the leaf backing.  The complete `volta-proto --features
c6-trace` suite is **146 pass / 0 fail / 1 ignored**; workspace all-target
checking and formatting are green.  Strict clippy remains globally blocked by
historical unrelated warnings, while filtering the strict run to the modified
C6 source and export reports none.

This is still a scaled/local ownership checkpoint.  It does not execute a
production T1 allocation, feed a round into `C6RSC3`, remove response bytes or
earn timing, packed-PCS, cache, real-PCG, CUDA or hardware credit.

#### 5.1.8 Shared C6RSC3 prover-coordinator checkpoint

Before adding fused arithmetic, the reference prover's transcript/MAC loop
was factored behind one private round-synchronous arithmetic interface.  The
coordinator remains the sole owner of dual-tape authentication, correction
domains, activation `ZeroOpen`, challenge release, pending transfers,
terminal `ProductClosure`/`ZeroBatch`, proof assembly and transcript byte
charges.  Arithmetic providers may only fix the current leaf/optional
auxiliary messages, bind the released challenge and return terminal opening
values plus the compact **8 + 16 + 8** coefficient scalars.

The existing materialized reference state is the first adapter.  It rejects
statement/repetition/target/round/activation mismatches before transcript
progress and must return its clear proof to the diagnostic trace.  The
reference public API, proof codec and verifier are unchanged.  All five
focused blind tests remain green, including exact production census, strict
codec, byte/transcript/correlation differential and every registered terminal
tamper.

This is a semantic-neutral integration checkpoint only.  No fused sink or
arena is connected yet, no verifier replay changes, and no production
allocation, response removal, PCS, cache, setup, timing, CUDA or hardware
credit is earned.

#### 5.1.9 Scaled fused C6RSC3 prover checkpoint

The diagnostic `c6-trace` path now feeds the three provider fused consumers
into the shared coordinator.  One live-witness replay fixes both first
messages.  Challenge 0 admits the half-size leaf coefficient state; later
leaf rounds read the arena views directly.  At the activation boundary the
leaf state is folded first with the shared challenge, then the auxiliary
replay is admitted into the reclaimed tail with that same challenge.  Every
remaining shared challenge folds both families before the next message pair.
Terminal coefficient scalars are copied from the one-entry arena views and
the arena is empty before the next proof repetition begins.

The scaled witness adapter constructs each first folded witness table
directly at half size; it does not clone a full table and truncate it.  Later
witness folds are explicitly diagnostic and receive no production-memory
credit.  A feature-gated cross-crate fixture owns the installed operation
plan, runtime extraction, relation context, live paired witnesses and
independent materialized oracle under the same global trace lock.

The six focused blind tests pass.  The new differential proves exact equality
of proof objects and encoded bytes, pending corrections and authenticated
claims, transcript ledger/bytes, correlation counters and terminal
plaintexts between reference and fused provers.  The scaled arena reaches
the frozen **512-Fp2** reserved peak, reuses one backing and returns
active/reserved occupancy to zero after each repetition.  The independent
proto atomic differential remains green.

The designated verifier still derives terminal scalars from the materialized
reference statement at this checkpoint.  Therefore client vector-free replay
and the complete fused prover/client gate remain pending.  No production
allocation, response removal, PCS, cache, setup, timing, real-PCG, CUDA or
hardware credit is earned.

#### 5.1.10 Vector-free fused C6RSC3 verifier checkpoint

The designated-verifier loop now has one private terminal-compiler seam.  Its
unchanged reference entry point still evaluates the scaled materialized
arrays.  The feature-gated fused entry point instead executes exactly one
witness-free terminal replay per proof repetition after the leaf and
auxiliary points are fixed, validates repetition, target, both points,
nonzero write census and semantic completion digest, and supplies only the
**8 + 16 + 8** scalars to the existing terminal ProductClosure/ZeroBatch
coordinator.  The replay adds no transcript frame or correlation draw.

The fused differential now covers both roles.  Fused and reference verifiers
return identical pending keys and reproduce the prover transcript ledger.
As an independence test, the old materialized coefficient values are changed
while preserving their owner/length geometry and therefore the same semantic
blind-statement digest: the reference terminal evaluator rejects, while the
fused verifier still accepts with the original transcript.  Conversely, a
changed semantic compiler digest is propagated consistently through the
diagnostic proof/frame owners and the fused verifier rejects it.

All six focused blind tests pass with `c6-trace`.  This closes the scaled
provider/client event-sink-to-C6RSC3 connection.  It remains diagnostic
because the statement still carries small reference arrays and the folded
witness adapter is materialized at scaled geometry.  Production T1
allocation/execution, packed authenticated-output binding, response removal,
cache, setup, timing, real-PCG, CUDA and hardware credit remain pending.

#### 5.1.11 Local fused-coordinator gate closure

The complete post-integration local gate is green.  `volta-proto
--features c6-trace` is **146 pass / 0 fail / 1 ignored**.  The
`volta-pcs --features c6-trace` library group is **158 / 0 / 1**, with its
integration groups **14 / 0 / 2** and **2 / 0 / 0**.  The ordinary
`cargo test --workspace -q`, workspace all-target check, feature all-target
check and formatting all exit zero.  The exact C6 budget suite is **9/9
PASS**, and the unchanged Lean audit exits zero.

Repository-wide strict clippy remains a historical non-gate: current Rust
1.96 reports 21 existing `volta-pcs` findings and 107 existing
`volta-proto` findings outside this change.  The PCS pass exits zero after
isolating exactly its inherited lint classes, and a strict short-format
filter finds no warning in the modified proto residual, fixture or export
files.  No unrelated warning was edited.

This gate closure remains scaled/local.  It changes no byte, correlation,
soundness, setup or time formula and earns no production response-removal or
hardware credit.  The next ordered implementation boundary is the common
packed authenticated-output link that upgrades pending terminal claims; a
pending C6RSC3 claim still cannot become an accepted PCS value.

#### 5.1.12 Packed authenticated-output link freeze before code

The pre-code M9/X4 audit found two concrete production obstructions in the
otherwise useful all-slot assembler of Section 5.3:

1. it accepts and transcript-charges all 128 terminal values in clear at the
   old suffix points whose final coordinate is zero; and
2. the scaled C6RSC3 pending containers expose raw `ProverAuthed` and
   `VerifierKey` accessors even though no accepted constructor exists yet.

The first behavior contradicts the later C6RSC3 amendment's explicit
target-evaluation-leak rejection.  The second is an avoidable typestate
escape.  The old clear assembler is therefore retained only as a
scaled/reference differential.  It has no production authority after this
freeze.  Production may create `C6AssembledWrapperClaims` only through the
combined authenticated-output link below, and raw pending MAC material is
crate-private until that combined verifier succeeds.

For each proof repetition `b`, all 64 slot claims are already pending and
dual-authenticated in canonical fixed-root order:

```text
(cache 0..7,
 residual 0..7,
 hidden-u weights 0..7,
 hidden-u embed 0..7,
 auxiliary 0..31).
```

Each opaque descriptor binds the wrapper statement, fixed-root digest,
source-statement digest, repetition, cohort, slot and exact old target point.
For C6RSC3 residual claims the adapter appends the fixed zero coordinate to
the 23- or 15-coordinate semantic point; it does not reveal the terminal
value.  Every source-specific pending correction frame for both repetitions
and both MAC tapes is fixed before the first link challenge.

After that boundary the verifier releases one `beta_b`.  With canonical
slot ordinal `j` and `rho_j = beta_b^(j+1)`, the two tapes hold the same
plaintext initial claim

```text
C_b = sum_j rho_j * S_j
```

under independent MAC keys.  The prover runs one degree-two,
different-size blind sumcheck over exactly 25 global variables:

```text
G_b(X) =
  sum_j rho_j
      * f_j(X_suffix(j))
      * eq(X_suffix(j), target_j)
      * product_(leading virtual coordinates k) (1 - X_k).
```

The leading virtual factor is required because every smaller cohort is a
suffix of the 25-coordinate global point; trailing virtual folding would
bind the wrong variables.  At each round both tapes fix independently
authenticated `G_b(0)` and `G_b(2)` corrections before one shared verifier
challenge is released.  No round plaintext is serialized.

Let the resulting fresh point be `z_b`.  The prover must abort before
emitting any clear aggregate unless `z_b[24] != 0`.  A verifier-supplied zero
is a hard failure, not a fallback to the old target point.  For an honest
uniform verifier this adds only the separately reported liveness failure
probability at most `2/|Fp2|` across the two repetitions; it is not a
soundness relaxation.  The new per-slot PCS weight is

```text
w_j = rho_j
    * eq(z_b_suffix(j), target_j)
    * product_(leading virtual coordinates k) (1 - z_b[k]).
```

Exactly five new-point aggregate values per repetition are then sent:

```text
V_(b,c) = sum_(slot j in cohort c) w_j * f_j(z_b_suffix(c)).
```

These ten values are **160 B total**.  Individual old-point values are never
sent.  Every witness and auxiliary polynomial has an independently random
upper half, so the checked nonzero final coordinate one-time-pads each clear
new-point aggregate.  The existing single C6 packed envelope proves those
five claims in each of its two chains.  Only after both PCS chains and query
sections verify do both tapes ZeroOpen

```text
final_authenticated_link_claim - sum_c V_(b,c).
```

The successful combined path is the sole constructor of opaque bound slot
claims.  A pending claim, a link prefix without the PCS, or a PCS proof
without both terminal MAC closures cannot enter a response ZeroBatch or an
accepted certificate.

The normative interaction order is:

```text
five fixed roots
  -> every source-specific pending transfer for repetitions 0 and 1
  -> repetition 0 beta, 25 dual-tape round messages, nonzero point,
     five new-point aggregates
  -> repetition 1 beta, 25 dual-tape round messages, nonzero point,
     five new-point aggregates
  -> both existing packed PCS root/fold/query chains
  -> terminal ZeroOpen tags in (repetition, tape) order
  -> bound typestate.
```

The C6-only strict combined codec is frozen as `C6LNK1\0\0`, version 1,
with little-endian integers and canonical `Fp2` symbols.  It contains:

```text
magic/version/repetitions/tapes/relations/rounds/cohorts       16 B
per repetition:
  repetition + schedule digest                            1 + 32 B
  25 rounds * 2 tapes * [G(0),G(2)] * 16 B                1,600 B
  five new-point aggregates * 16 B                            80 B
embedded unchanged two-chain PCS                         3,609,824 B
four terminal ZeroOpen tags * 16 B                              64 B
final domain-separated BLAKE3 digest                            32 B
combined payload                                         3,613,362 B
non-PCS link overhead                                        3,538 B.
```

The link proof context is
`volta-zk/c6/authenticated-output-link-proof/v1`; the schedule context is
`volta-zk/c6/authenticated-output-link-schedule/v1`.  The latter binds the
wrapper statement, fixed roots, exact descriptor registry and the complete
correlation-domain schedule.  Round corrections are encoded
repetition-major, round-major, tape-major, then endpoint `0,2`; aggregates
are commitment-major and slot weights are never serialized.  Points,
`beta`, weights and cohort metadata are verifier-reconstructed.  A strict
decoder rejects old magic/version, wrong census/order/digest, noncanonical
field symbols and trailing bytes.

The link consumes exactly

```text
2 repetitions * 25 rounds * 2 endpoint masks = 100
```

fresh full correlations **per tape**, inside the frozen 39,116-full PCS
reserve.  Its domains are

```text
0x0C64_0000_0000_0000
| (repetition << 28)
| (tape << 24)
| 0x0001_0000
| (2*round + endpoint),
```

where `endpoint` is zero for `G(0)` and one for `G(2)`.  Reserved correlation
bits, collisions with C6RSC3 and reuse across an abort are hard failures.
No fresh correlation is needed for the final ZeroOpen.

The generic M3/X4 different-point theorem gives the exact one-repetition
link numerator

```text
64 relations + 3*25 degree-round roots + 2 = 141.
```

Two independent complete repetitions contribute `141^2 = 19,881`.  Unioned
with the already frozen hidden-linear numerator, the shared named event is

```text
6,401 + 141^2 = 26,282 < 65,536 = 2^16.
```

Thus `c6_linear_link_event_better_than_239` and the four-event Q=121 result
remain unchanged.  Before Rust, an additive Lean module must specialize the
generic different-point theorem to `(64,25)`, prove the `141` census and the
`26,282 < 2^16` composition.  It may not edit the frozen M9/X4 theorems or
add an axiom.  Until that audit is green, implementation is hard-stopped.

That gate is now green in the additive
`C6AuthenticatedOutputLink.lean` module.  It proves
`c6_packed_link_root_census`,
`c6_packed_authenticated_output_link_sound`,
`c6_packed_link_two_repetition_card_le`,
`c6_hidden_linear_plus_link_numerator` and
`c6_hidden_linear_plus_link_numerator_le_2_pow_16`.  The complete build is
**3,259 jobs** and the derived audit is **308 total / 72 C6** targets, with
zero `sorry`/`admit` and only `propext`, `Classical.choice` and
`Quot.sound`.  The hard stop therefore advances to the scaled strict
combined codec, opaque pending/bound typestate and prover/verifier
differential; production memory, response removal and timing remain later
gates.

That scaled Rust gate is now green.  The new
`c6_authenticated_output_link` reference module implements the exact
`C6LNK1` order above and refuses production-fixed roots.  Its integrated
fixture continues the same transcripts and correlation streams through
fixed wrapper roots, a real two-repetition `C6RSC3`, all remaining
source-specific pending transfers, the dual-tape link, both packed PCS
chains and four terminal ZeroOpens.  The scaled cohort dimensions are
`7/6/5/5/4`; all 64 slots are present in each repetition.  Of the 128
pending values, 48 come from the actual residual prover/verifier and 80 are
typed scaled stand-ins for the still-pending cache, hidden-`u` and remaining
auxiliary source adapters.

The scaled link has seven global rounds and therefore consumes exactly
`2*7*2 = 28` full correlations per tape.  Its non-PCS strict-codec overhead
is exactly `1,234 B`.  Compile-time identities independently retain the
production formulas of `100` correlations per tape, `3,538 B` link overhead
and `3,613,362 B` combined payload.  Canonical encode/decode is byte
identical, prover/verifier transcript ledgers and correlation deltas match,
and a leakage regression checks that none of the 128 individual old-point
Fp2 values occurs in the complete encoded proof.

The old clear assembler is now test-only and creates a typestate explicitly
rejected by both public assembled-PCS entry points.  Raw C6RSC3 pending MAC
accessors were removed; crate-private link extraction is the only bridge,
and public pending/bound `Debug` output is redacted.  The sole bound
verifier constructor runs after the embedded PCS verifies and all four
terminal tags accept; the prover bound view is emitted only after it has
constructed the complete PCS and tags.  Five permanent tests cover the exact
production census, the real
C6RSC3 round trip, strict old/noncanonical/corrupt/trailing codec rejection,
mutations on either tape, aggregate, schedule, PCS and terminal-tag
boundaries, and missing/duplicate/wrong-owner/wrong-slot/wrong-target/
cross-tape registry failures.  The complete ordinary and `c6-trace` Rust
gates, all-target checks, format, the unchanged `9/9` C6 budget and the
`308`-target Lean audit are green.

This checkpoint earns only scaled/reference algebra, byte and typestate
credit.  It does not instantiate the production cache, hidden-`u` or
remaining auxiliary pending sources, does not remove a production response
field, does not run the fused CUDA backend or real PCG session, and has no
prover-time, memory, setup, cache or hardware verdict.  The next ordered
gate is to replace the 80 typed stand-ins with those real source adapters
before any production envelope/backend work.

#### 5.1.13 Blind hidden-`u` source-adapter amendment

The first source-adapter audit found that the existing `C6HUSC1` reducer
cannot be inserted into the authenticated-output registry as-is.  It sends
all degree-two round values and the four old-point `U(r)` values in clear.
Wrapping only the four terminal scalars in corrections would remove the
literal old-point values from the link frame, but would leave response-linear
information about the hidden `u` vectors on the wire and would not provide
an authenticated recurrence from the public initial claims to the pending
PCS sources.  `C6HUSC1` therefore remains an immutable clear arithmetic
oracle.  The production candidate is the separately versioned
`C6HUB2\0\0` blind transcript below.

For each of the two independently challenged hidden-linear repetitions,
weights contributes 21 degree-two rounds and embedding contributes 19.  The
response-global activation offsets remain 3 and 5.  The initial claim of
each family is verifier-derived from the already sealed grand-RLC schedule,
so every round, including the first, sends only authenticated `g(0)` and
`g(2)` on both independent MAC tapes.  Each side reconstructs

```text
g(1) = current_claim - g(0)
```

and applies the public degree-two interpolation weights at the one shared
round challenge.  Corrections for every active family and both tapes are
fixed before that challenge.  No clear round polynomial or old-point
terminal value is serialized.

At the end of a repetition the prover creates one fresh dual-tape pending
correction for each of the two actual `U(r)` values.  Let `q_w(r)` and
`q_e(r)` be the public terminal functional evaluations independently
reconstructed by the verifier.  Before either pending value can enter the
common link, both sides form

```text
R_w = current_weights - q_w(r) * pending_weights
R_e = current_embed   - q_e(r) * pending_embed.
```

After both pending corrections are fixed, the verifier releases one fresh
`eta`; each tape ZeroOpens `R_w + eta*R_e`.  This remains valid when a
terminal functional happens to be zero and therefore does not add a
division or a hidden liveness assumption.  The terminal batch challenge and
its ZeroOpen add two conservative roots per complete repetition.

The hidden wrapper ownership is now fixed, not caller-selected:

```text
hidden-u weights slot 0    actual padded U_weights oracle
hidden-u weights 1..7      identically-zero semantic witness slots
hidden-u embed slot 0      actual padded U_embed oracle
hidden-u embed 1..7        identically-zero semantic witness slots.
```

Every unused slot has a public-zero pending MAC at its old suffix point.
The common random-point link plus packed PCS proves that its committed
semantic half evaluates to zero; the independently random upper half remains
available at the link's checked nonzero ZK coordinate.  These are real
dummy-slot zero constraints, not arbitrary stand-ins.  The source identity
binds the prequery/postcommit/layout digests and slot-zero policy through the
statement digest, then repetition, family, slot and the exact
response-global suffix point through the opaque pending descriptor.

The exact production blind hidden codec is:

```text
fixed headers, family headers and terminal digest                 104 B
2 repetitions * (21+19) rounds * 2 endpoints
  * 2 tapes * 16 B                                              5,120 B
4 actual terminal pending values * 2 tapes * 16 B                 128 B
2 repetitions * 2 tape terminal-batch ZeroOpen tags * 16 B         64 B
strict C6HUB2 payload                                            5,416 B.
```

It consumes exactly

```text
2 repetitions * (21+19) rounds * 2 endpoints = 160
4 actual terminal pending values                   =   4
blind hidden subtotal / tape                       = 164 full correlations.
```

Public-zero capacity slots consume no correlation.  This subtotal and the
existing residual/link allocations remain inside the frozen
39,116-full/tape reserve and do not change the 5,235,692-raw attempt
reservation or the first-exchange formula.

The prior clear hidden numerator `1 + 80^2 = 6,401` remains historical for
`C6HUSC1`.  The blind terminal batch makes the descendant numerator

```text
1 + 82^2 = 6,725.
```

Together with the unchanged packed-link numerator it is

```text
6,725 + 141^2 = 26,606 < 2^16.
```

Thus the existing `2^16/|Fp2|^2` allocation and complete Q=121 soundness
remain unchanged.  Before `C6HUB2` Rust, an additive Lean module must
specialize the compressed authenticated recurrence, prove the `82` census,
square the two complete repetitions and prove the exact `26,606 < 2^16`
composition.  It may not edit the historical `C6HUSC1`, M3/M9/X4 statements
or their earlier `26,282` certificate.

This amendment closes only the hidden-source design.  Cache slots and
auxiliary slots 16--31 remain blocked on the separately required exact
cache-hash/constraint freeze.  Hidden integration may proceed while that
hard stop remains open, as permitted by Section 6.

The additive formal gate is now green.
`C6HiddenUBlindTranscript.lean` proves the exact compressed Boolean-node
recurrence, the **80 degree roots / 82 complete roots** census, the
two-repetition product and the **6,725 + 141^2 = 26,606 < 2^16**
composition.  Full Lean builds **3,260 jobs**.  The derived audit covers
**315 named targets**, including the seven new hidden-source targets, with
zero `sorry`/`admit` and only `propext`, `Classical.choice` and `Quot.sound`.

The scaled/reference Rust gate is also green.  `C6HUB2` has a strict
canonical codec, dual-tape prover/verifier, redacted pending containers and
one fixed source adapter into the existing link registry.  At the scaled
four-round-per-family geometry its proof is **1,320 B** and consumes **48
full correlations/tape**.  The integrated packed-link fixture now contains

```text
48 actual C6RSC3 residual pending claims
32 actual hidden-u pending claims
   = 4 live U(r) claims + 28 public-zero capacity constraints
48 typed cache/cache-auxiliary stand-ins
128 total pending claims.
```

The complete residual→hidden→link→two-chain-PCS verifier is byte-,
transcript- and correlation-identical to the prover and still binds only
after the four link terminal closures.  Permanent negatives cover old,
noncanonical and trailing codecs; either hidden tape; a round correction;
an actual terminal correction; a terminal batch tag; equal MAC secrets; and
the existing complete link/PCS/registry mutation inventory.  No individual
hidden old-point value occurs in `C6HUB2`, and no individual one of the 128
old-point values occurs in the combined link proof.

Ordinary `volta-pcs` is **165 pass / 0 fail / 1 ignored** and the
`c6-trace` build is **166 / 0 / 1**.  Workspace/all-target checks and
formatting are green; the C6 budget is **9/9 PASS** and modified-file clippy
filters are empty.  Production compile-time identities remain **5,416 B /
164 full correlations/tape** for `C6HUB2` and **3,613,362 B / 100 full/tape**
for the packed link; both remain inside the existing allocation caps, so no
response/setup/soundness roof changes.

This is still a scaled source-adapter checkpoint.  The fixture runs the
internally round-synchronous hidden families as a source stage before the
link; it does not yet instantiate the single production 24-round
cache/residual/hidden coordinator, a production-size hidden witness, fused
CUDA, real PCG or response removal.  Cache and auxiliary slots 16--31 remain
the only 48 stand-ins and the exact cache hash/constraint census is the next
algebraic gate.  Source SHA-256 values are
`28889d76ed789cc9c6c72e66c20e2d3446e19a27e2846282581384de185547fc`
for the blind hidden module,
`96f376f2d368dcdbdbdf11ae498f035536d11514fc98ae07edb8818d21dbf081`
for the integrated link,
`5d7c6f58b6605f0df8ec4e124120a0266315b5fd7502482ca7365772893fbecf`
for the clear arithmetic adapter and
`788b4211aafca15bd0cb799d25ad276ed7afc67e4d04746672e2589c544626d6`
for the additive Lean module.

The wrapper PCS uses rate `1/8`, two independent fold/query chains and
`s=86` queries per chain.  Under the conservative 64-active-polynomial,
`2^28` weight-oracle and `2^19` auxiliary maxima, one repetition has

```text
epsilon_PCS,one =
    64 * (9/16)^86
  + 64 * ((2^28-1) + (2^19-1)) / |Fp2|.
```

The complete PCS event is its square.  The exact minimum satisfying the
literal 128-bit event gate is `s=85`; C6 selects `s=86` before backend code
and measurements, giving **130.7728997448832 bits**.  `s` may not be reduced
after seeing a benchmark.

Wire accounting maximizes the combined symbol-plus-Merkle-frontier bytes at
every domain over every possible number of distinct projected draws.  This
is stricter than assuming 86 distinct draws: collision-heavy tapes can have
fewer opened symbols but a larger small-domain frontier.  For one chain:

```text
opened Fp2 symbols                                  14,528
outer sibling digests                               49,052
inner sibling digests                                    0
packed-section metadata                                534 B
packed query section                             1,802,646 B
25 fold commitment frames (last has one extra E)     2,266 B
one-chain subtotal                               1,804,912 B
two-chain PCS subtotal                           3,609,824 B.
```

Both chain sections and all terminal claims are carried by one C6 packed
opening envelope.  The two-chain subtotal deliberately charges each section
as if it retained a complete standalone header; any future header sharing is
headroom, not a prerequisite.

C6 allocates at most `800,000 B` to **all** non-PCS new-response material:
certificate framing, paired ranges and residual outputs, prequery/root
frames, the client challenge seed, hidden-linear/cache/residual sumchecks,
terminal claims and wrapper-envelope metadata.  This is a cap, not a
predicted size.  Therefore:

```text
two-chain PCS subtotal                           3,609,824 B
non-PCS allocation                                 800,000 B
preregistered pi_final maximum                   4,409,824 B
pi_final cap - maximum                              90,176 B
complete response maximum                       33,586,456 B
35-MB response headroom                           1,413,544 B.
```

The exact non-PCS codec/census must land at or below its allocation; unused
allocation is not transmitted.  No field can escape into the retained
`29,176,632-B` transcript.

The remaining event allocations use the exact conservative bounds

```text
hidden-linear    6,401 / |Fp2|^2        >243 bits
cache argument   2^64 / |Fp2|^2         >191 bits
Delta residual    2^16 / |Fp2|^2        >239 bits.
```

The cache numerator is a hard capacity of at most `2^32` field roots per
repetition; the backend theorem and census must discharge it.  Together with
the amplified PCS term, all four events remain below their individual
`2^-128` allocations.

The time model is a screening boundary, not a hardware verdict.  Reusing the
current X4c response engine is forbidden: proportional scaling of its clean
`111.552679710-s` seal counter projects approximately `76.825 s` of wrapper
work, before the `4.104595717-s` model proof.  The only admitted backend route
is the response-local fused CUDA path backed by the existing P7 A100
Goldilocks NTT, BLAKE3/Merkle and streaming kernels.  The current screen
charges two full commit/recompute passes, two fold chains, the 32-pass
sumcheck base, the complete-owner expansion and the exact atomic compiler
census above.  It reaches **34.7434735164...** coefficient-equivalent passes
and an informative **8.450848617...-s** floor including the model proof,
leaving **11.549151382... s** for unmodeled cache construction,
orchestration and integration under the `20.000-s` gate.  This does not turn
the P7 microbenchmarks into an end-to-end PASS: if the optimized
implementation cannot remain below the ceiling, C6 stops without falling
back to the historical multi-minute engine.

The executable source of record is `scripts/budget_c6_wrapper.py`; it emits
the exact rational/integer report with `--json`.  Its permanent tests are in
`tests/test_budget_c6_wrapper.py`, including exhaustive frontier comparison
through 16 leaves and selected 32-leaf boundary cases.  At this checkpoint
the combined base-budget/wrapper suite is `9/9 PASS`.  This local evidence
closes the roofline milestone only; it is not a production census, backend
implementation or A100 measurement.

### 5.2 Response-local reference PCS checkpoint

The in-memory `c6_wrapper_pcs` backend now realizes the exact algebra and
wire grammar behind the roofline without invoking an X4 protocol driver.
All terminal values for both repetitions are fixed before cohort-activation
challenges; every fold line is fixed before its challenge; both complete
root chains are fixed before either exact 86-draw tape; and only then are the
two packed query sections emitted.  Different-size claims must be suffixes
of one repetition-global point.  Every capacity slot is present and opened.

The slot-reduction weights carried by a `C6WrapperOpeningClaim` are
verifier-owned upstream data, not prover-selected metadata.  The final
wrapper orchestrator must reconstruct them from its certificate-bound
post-commit challenge schedule and must not deserialize them as authoritative
provider input.  The reference PCS checks their geometry and binds them in
the C6 schedule digest; production acceptance remains disabled until that
upstream seam and all five cohort claim sources are integrated.

The materialized production-shape codec contains 25 fold frames and one
packed section per repetition and is exactly **1,804,912 B/chain** and
**3,609,824 B/two chains**, including the standalone schema-4 frame headers
already charged by the roofline.  This is a codec result, not a
production-size commitment, timing measurement or proof of the complete
wrapper circuit.  The CPU/in-memory implementation receives no prover-time
credit; the admitted production path remains the separately gated fused CUDA
backend.

### 5.3 Global-round and all-slot assembly seam

This section records the earlier clear all-slot assembly checkpoint.  Its
challenge-ownership and registry checks remain useful, but Section 5.1.12
supersedes its production terminal-value authority: the 2,048-B clear
old-point path is diagnostic only, and production assembly must originate
from the opaque pending-to-link-to-PCS typestate.

Before the complete wrapper implementation, C6 fixes one production
orchestration seam.  The five canonically ordered initial cohort roots are
fixed once, before either repetition receives a sumcheck challenge.  Each
repetition then has exactly 24 random rounds with the following participant
schedule:

```text
participant          activation   rounds   final global round
cache                         0       24                   24
paired residual               1       23                   24
hidden-u                      3       21                   24
```

At each global round every active participant fixes its complete message
before the verifier releases one shared challenge.  The coordinator may not
advance until every active participant acknowledges binding that challenge.
It neither accepts a presampled challenge vector nor exposes a challenge
before the complete active-message set is fixed.  The resulting 24-element
random point is extended by the one shared fixed zero; every cohort point is
the exact suffix of that 25-element point.

After both repetitions finish, the all-slot assembler requires exactly one
typed terminal scalar for every `(repetition, cohort, slot)` in the frozen
`8+8+8+8+32` registry.  It fixes all **128 Fp2 values = 2,048 B** before
drawing any same-point reduction weight.  It then derives one fresh
verifier-owned `Fp2` weight per canonical slot and constructs the five
aggregate opening claims per repetition locally.  Cohort IDs, slot numbers,
points, weights and aggregate values are reconstructed; they are not
authoritative provider-deserialized metadata.  Missing, duplicate, unknown
or wrong-point claims reject before the first reduction challenge.

The production packed-PCS entry point accepts only this sealed assembled
type and does not serialize or transcript-charge the ten deterministic
aggregate scalars a second time.  The earlier raw
`C6WrapperOpeningClaim` entry point remains a scaled/diagnostic reference
only.

This seam is now implemented.  `C6FixedWrapperCommitments` can be produced
publicly only by validating the exact production profile and fixing the five
roots, charged as **160 B**, before constructing a production coordinator.
The coordinator rejects missing, duplicate, reordered or empty participant
receipts, a second round while a challenge is pending, a wrong bind
acknowledgement and an incomplete finish.  Its completed point is bound to
the fixed-root digest and cannot be constructed through public fields.

`C6AssembledWrapperClaims` likewise has no public field constructor.  The
production assembler rejects every non-exact terminal registry before
charging **2,048 B** or drawing a reduction challenge, derives all 128
weights itself, and feeds the sealed aggregate directly into both packed PCS
chains.  A scaled differential verifies the two real packed chains while the
raw ten-aggregate transcript label remains zero.  A second differential
drives the actual hidden-`u` prover and verifier step states from a scaled
global coordinator and recovers identical suffix points and ledgers.

Complete `volta-pcs` is **161 pass / 0 fail / 3 ignored**; workspace tests
and the all-target `c6-trace` check are green.  Source SHA-256 values are
`b6a01f24ba44127d29b40acc84df5bf6d146f03c5aeeef0743908f115a2842fa`
for the packed/coordinator module and
`e00acca12d38f916a9bb5b64c13fe13b42aa2817c9645233585730edd9f6d82b`
for the integrated hidden step state.

This closes challenge ownership and canonical assembly only.  It does not
yet assign real cache/residual/auxiliary sources to every slot, prove
dummy-slot zero constraints, define the final envelope codec or earn wire,
timing or production credit.

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

The phrase “algebraic Merkle” is not an implementation license for an
unspecified hash.  Before cache backend code, C6 must freeze the exact
Goldilocks/`Fp2` compression permutation, domain separation, arity, round
constants, security argument and constraint/roofline cost.  Reusing BLAKE3
inside the algebraic wrapper, treating a host hash as an unconstrained
oracle, or choosing parameters after timing is forbidden.  Residual and
hidden-source integration may proceed independently while this cache-hash
gate remains open.

The formal theorem is conditional on an explicit commitment-binding
hypothesis.  No Lean theorem may smuggle collision resistance in as a new
axiom.

### 6.1 PCS-native dual-root amendment

The exact cache-hash census exposed an avoidable obstruction in the original
wording above.  Arithmetizing a second, newly selected hash over
`2 * 12 * 1,024 * 768` cache values would add a response-linear hash trace,
new round constants and a new performance surface even though the packed PCS
already provides a binding vector commitment.  C6 therefore adopts the
following pre-backend amendment.  It supersedes only the earlier requirements
that cache membership/update use a separately arithmetized Merkle hash and
that every initial descriptor bind the response statement.  All atomic-head,
append-only, challenge-order and one-packed-opening requirements remain in
force.

The persistent `cache_root` is the N4 root of a normal C6 PCS cache-state
cohort, not a host hash admitted as an algebraic oracle.  The N4/BLAKE3 tree is
used only through the existing computational PCS commitment-binding
assumption.  The cache transition itself is checked by native-field
sumchecks whose terminal values enter the same pending authenticated-output
link and the same packed PCS opening as every other wrapper claim.  There is
no in-circuit BLAKE3 call, no new hash permutation, no new SRS and no second
response opening.

A reusable cache-state commitment has a static descriptor.  It binds exactly

```text
C6 cache-state domain/version,
protocol/model/params/profile digests,
maximum context 1,024,
layer count 12, width 768,
K-or-V slot kind, slot number and fixed geometry.
```

It does **not** bind a response statement, old/new role, nonce, epoch,
current cache length or predecessor certificate.  Otherwise a successor root
could not be reused byte-for-byte as the next certificate's predecessor root.
Those dynamic fields and the ordered roles of both roots are bound by the
outer response statement, `old_head`, `new_head` and certificate digest.  A
root accepted under any other static descriptor is not a C6 cache-state root.

Each cache-state cohort contains eight fixed-capacity slots:

```text
slot 0   K, natural (layer, position, channel) order
slot 1   V, natural (layer, position, channel) order
slot 2..7 canonical public zero
```

One K or V state has

```text
12 * 1,024 * 768 = 9,437,184 live entries <= 2^24.
```

The slot geometry is the fixed 24-bit padded product of 16 layer values,
1,024 positions and 1,024 channels.  Invalid layers `12..15`, invalid
channels `768..1,023`, every position at or above the committed cache length,
and slots 2--7 are zero.  Genesis fixes the all-zero root.  Conditional on a
valid predecessor certificate, one transition proves in a single complete
relation per repetition that:

1. every cache value consumed by the response is the corresponding value in
   the predecessor K/V slots;
2. the successor prefix below `old_head.cache_len` equals the predecessor;
3. positions in `[old_head.cache_len,new_head.cache_len)` equal the response's
   authenticated K/V output slab;
4. the successor tail and every padded geometry entry are zero; and
5. the public lengths and epoch satisfy the bounds in Section 6.

The public range/geometry selectors and relation weights are fixed only after
both cache roots and every response-output root are bound.  They are
precombined as public multilinear coefficient tables.  The resulting cache
identity has 24 rounds and maximum per-variable degree two.  One fresh K/V
batching root and three complete-relation batching roots precede its
sumcheck; one terminal authenticated-output root joins its terminal claims to
the packed opening.  Before the blind adapter, these components gave the
preliminary subtotal

```text
2*24 degree-round roots + 3 relation roots + 1 K/V root + 1 terminal root
    = 53 roots,
```

The adapter audit found that this subtotal omitted the challenge needed to
prevent cancellation between invalid cells.  Section 6.1.1 below supersedes
the complete cache-event count with 77 roots.  Commitment/hash binding
remains a separately named computational assumption and is not converted
into statistical bits.

The packed profile consequently has six initial root groups and 72 active
polynomials per repetition:

```text
predecessor cache  8       successor cache  8
paired residual    8       hidden-u weights 8
hidden-u embedding 8       wrapper auxiliary 32
total                                             72.
```

The response-local authenticated-output link now has 72 relations.  Its
exact per-repetition root census is

```text
72 + 3*25 + 2 = 149,
blind hidden-u plus link numerator = 6,725 + 149^2 = 28,926 < 2^15.
```

The former 64-polynomial/141-root numbers remain immutable evidence for the
single-cache-root reference checkpoint; they are not the production C6
profile after this amendment.

The executable exact roofline for the 72-polynomial descendant is:

```text
one packed PCS chain                         1,939,733 B
two independent chains                      3,879,466 B
frozen non-PCS allocation                      600,000 B
pi_final maximum                            4,479,466 B
complete response maximum                  33,656,098 B
response headroom                           1,343,902 B
first-exchange known components            146,058,504 B
```

The earlier `800,000-B` non-PCS reserve is tightened to `600,000 B` before
the cache codec/backend.  The PCS headroom is only `20,534 B`; no later field
may be moved outside `pi_final` or added by benchmark-driven exception.  The
setup exchange is unchanged because both cache commitments use transparent
model-global descriptors and the existing provider-side PCS machinery.

For timing screening, the predecessor commitment receives **no reuse
credit**: the analytic model charges a full predecessor and successor
commitment even though a durable provider implementation may retain the
accepted predecessor tree.  The resulting conservative local kernel floor
is `11.1793342101 s`, leaving `0.8206657899 s` to the 12-second target,
`3.8206657899 s` to 15 seconds and `8.8206657899 s` to the binding 20-second
ceiling.  These are analytic projections, not measured prover walls.

The next production implementation gate is the exact model-global source map from
predecessor-cache operands and response-produced K/V slabs into the cache
relation.  It must be generated independently by the client from the static
layout and public workload, consume no historical cache key vector, and
leave all cache terminal values pending until the authenticated-output link
and packed PCS accept.  The source-bound scaled adapter is green and has no
cache/cache-auxiliary stand-in; the production 24-round streaming compiler
and resident source replay remain pending, so no response-removal or
prover-time credit is earned.

The additive formal and first scaled-reference gates are now green.  The new
`C6PersistentCachePCS.lean` descendant proves the exact live/padded capacity,
append refinement, context cap, successor uniqueness under an explicit
injective commitment premise, the preliminary `53^2=2,809` subtotal, and the
72-relation/149-root authenticated-output-link specialization.  Section
6.1.1 adds the blind-adapter soundness repair and Section 6.1.2 adds the
aggregate-correction identity.  Full Lean builds **3,261 jobs**;
the derived audit covers **337 total / 98 C6 named targets**, with zero
`sorry`/`admit` and only `propext`, `Classical.choice` and `Quot.sound`.

The additive Rust module `c6_persistent_cache` freezes a strict **184-B**
static-profile codec, eight unique response-independent slot descriptors and
a strict **320-B** outer transition-binding reference codec.  The latter is
not a new certificate field or 320 bytes of earned wire: it redundantly
encodes fields already required by Section 7 so descriptor portability and
canonical ordering can be tested before the final envelope exists.  Its
scaled checker verifies exact predecessor reads, unchanged prefix,
authenticated-output append order, zero tail/padded geometry, slots 2--7,
epoch/length bounds and the public source-map digest.  Five focused tests
pass and reject prefix, append value/order, read value/order, tail, zero-slot,
source-map, descriptor, corruption and trailing-byte mutations.  The compact
workload-derived two-band plan and its exact first/continuation/late-session
censuses add two focused tests, bringing this module to **7/7 PASS**.

This direct checker is not yet the blind cache proof.  It consumes an
expected public read map and typed append-source values, but the production
GPT-2 operation plan has not yet generated that exact map and the values have
not yet entered pending MAC containers.  It does not instantiate the
24-round sumcheck or replace any stand-in.

The subsequent packed-wrapper checkpoint has now migrated the production
profile from the historical five-group/64-slot `C6LNK1` reference to the
six-group/72-slot persistent-cache `C6LNK2` descendant.  The two cache roles
have distinct outer packed IDs but one shared N4 cache-state Merkle identity
and the exact same eight model-global descriptors.  Thus the outer fixed-root
digest binds ordered predecessor/successor roles while a successor root is
byte-identical when reconstructed as the next response's predecessor.  A
scaled differential proves this reuse across different response statements,
and a different static descriptor set changes the root; production root
fixing also rejects a descriptor set other than the installed one.

The strict production codec matches the executable roofline exactly at
`1,939,733 B` per chain and `3,879,466 B` for two chains.  `C6LNK2` has 72
relations, six aggregates per repetition, `3,570 B` of link overhead and
`3,883,036 B` combined link-plus-PCS bytes.  The first migrated scaled
integration used stand-ins for both 8-slot cache cohorts and the remaining 16
cache-owned auxiliary slots in each repetition: **32 per repetition / 64
total**.  Section 6.1.1's `C6PC2` checkpoint now replaces all 64 through the
real packed link and both PCS chains.  Removing `CacheSegK` and connecting the
production streaming compiler remain the next ordered gates.

### 6.1.1 Blind transition pointwise-soundness amendment

The pre-adapter `53`-root subtotal is not the complete blind transition
event.  A protocol that proves only

```text
sum_x transition_residual(x) = 0
```

is invalid: two bad cells can cancel.  Before any blind-cache Rust, C6 fixes
one independent relation point `a in Fp2^24` after both cache roots and all
response-output roots.  The cache prover must instead reduce

```text
sum_x eq(a,x) * transition_residual(x)
```

through the 24-round degree-two sumcheck.  The 24 coordinates of `a` are
verifier-owned transcript challenges.  They add no proof or setup bytes but
do add 24 Schwartz--Zippel roots to the cache event.  The exact complete
count is therefore

```text
48 degree-round roots + 24 relation-point roots
  + 3 complete-relation batching roots + 1 K/V root + 1 terminal root
  = 77 roots per repetition,
two independent repetitions: epsilon_cache <= 77^2 / |Fp2|^2
  = 5,929 / |Fp2|^2 = 243.466... bits.
```

This remains far below the frozen conservative
`(2^32)^2/|Fp2|^2` cache allocation.  Consequently Q=121 complete
soundness, the 149-root packed link, setup, response roofline and every time
screen are unchanged.

The three relation batching roots own, in canonical order: the pointwise
predecessor/successor append transition; the predecessor-cache attention
functionals; and the current-slab/output functionals.  One K/V root batches
the two cache kinds inside each relation.  The client derives all coefficient
tables and source aggregates from the public workload, runtime fold schedule
and authenticated response outputs.  An implementation may stream those
tables, but may not accept provider-authored coefficients or replace the
equality weighting with an unweighted sum.

The cache adapter owns predecessor and successor slots 0--1 as live pending
terminal evaluations.  Slots 2--7 in both cache cohorts are canonical zero.
The first scaled checkpoint also treated wrapper-auxiliary slots 16--31 as
zero, giving four live cache terminals and 28 zero claims per repetition.
A strict reference `C6PC2` core codec is capped at 24 rounds, two tapes and
two repetitions:

```text
fixed header and statement digest                                     48 B
2 repetition prefixes                                                 66 B
2 * 24 rounds * 2 endpoints * 2 tapes * 16 B                       3,072 B
2 * 4 live terminals * 2 tapes * 16 B                                256 B
2 repetitions * 2 tape terminal ZeroOpen tags * 16 B                  64 B
total                                                               3,506 B.
```

It consumes exactly `2 * (24*2 + 4) = 104` full correlations per tape.
Existing authenticated append/fold sources are linearly reused and consume
no replacement correlation.  The first Rust gate may use a scaled compiled
relation, but it must exercise all three relation owners, produce the four
live plus 28 zero pending claims per repetition, enter `C6LNK2`, and reject
unweighted/canceling, wrong-point, wrong-owner and wrong-source-schedule
mutations.  Production geometry must remain streaming and fail closed rather
than materialize `2^24` coefficient tables.

That scaled gate is now green.  `c6_persistent_cache_blind` implements a
strict schema-2 dual-tape codec/prover/verifier, hashes the fixed owner order
and client-derived source schedule, and derives the relation point plus all
batching roots from the verifier transcript.  The **6-round** reference proof
is **1,202 B**, consumes **32 full correlations/tape**, and emits exactly
**64 pending claims** across two repetitions.  Its upstream fixture
authenticates 12 append/fold source values before the adapter; `C6PC2` only
reuses them linearly.  The integrated `C6LNK2` test has no generic transfer or
stand-in entry left and closes all 72 slots through both packed PCS chains.

Four focused adapter tests cover the exact **3,506-B / 104-correlation**
production formula, domain uniqueness, canonical codec, both MAC tapes,
wrong relation point, owner and source schedule, and all round/terminal/tag
mutations.  A permanent `+d,-d` differential has zero unweighted residual but
is rejected after equality weighting.  The materialized constructor refuses
24 rounds, so this checkpoint provides no production memory, response-byte
removal or prover-time credit.  The next gate must compile the same relation
from the real runtime fold map in a streaming resident path and then remove
`CacheSegK`.  Section 6.1.2 closes the previously missing aggregate-key
bootstrap for this scaled path without adding a pending slot.

#### 6.1.2 Source-key bootstrap amendment before `CacheSegK` removal

The scaled `C6PC2` fixture supplied already-corrected verifier keys for its
append and fold-source aggregates.  That is not a production interface once
direct corrections are hidden: the client has only the aggregate base PCG
key and cannot reconstruct `k=m+Delta*x` from a historical corrected key.
Regenerating `CacheSegK` or accepting a provider-authored key is forbidden.

Before the production streaming compiler, C6 therefore adds one typed
`C6PS1` source-bootstrap frame.  It carries only aggregate corrections for
the exact authenticated sources already used by the model proof:

```text
four response-fixed fold aggregates (pred K/V, slab K/V)
two equality-weighted append aggregates per proof repetition (K/V)
two independent MAC tapes

fixed header + statement digest                                  48 B
(4 + 2*2) aggregates * 2 tapes * 16 B                           256 B
total                                                           304 B.
```

The client derives every aggregate base key by streaming the same canonical
source indices and public coefficients over its one-time PCG range, then
applies the aggregate correction.  The provider derives the matching
plaintext, tag and base-mask folds from the same typed sources.  No fresh
correlation is allocated: this is a linear opening of already consumed
one-time sources, not a replacement authentication.  The transition
aggregate corrections are sent only after the relation point is fixed and
are transcript-bound before the first sumcheck round.

The source aggregates are authenticated **inputs** to the cache sumcheck,
not new PCS outputs.  A tempting assignment to auxiliary slots 16--21 is
invalid: the transition aggregate depends on the relation point sampled
after the auxiliary commitment, creating a commit/challenge cycle.  Those
slots therefore remain canonical zero and the pending census remains four
live plus 28 zero claims per repetition.  The canonical direct-source
indices and coefficient schedule determine the aggregate base key; `C6PS1`
provides its correction, and the dual-tape `C6PC2` terminal closure rejects
an inconsistent source authentication.  The 72-polynomial PCS profile, 149
link roots, packed proof bytes and setup size do not change.  The
source-bound cache package is therefore
`3,506 + 304 = 3,810 B`; it remains inside the frozen 600,000-B non-PCS
allocation, so the `33,656,098-B` response maximum is unchanged.

The frame is not an independently acceptable proof.  Its corrected source
keys are provisional until the same six authenticated aggregates pass the
cache sumcheck and its four terminal outputs are accepted by `C6LNK2` plus
both packed PCS chains.  Wrong source correction, owner, K/V kind,
repetition, coefficient schedule or statement digest must fail closed.  This
amendment changes no statistical event: a bad aggregate is an error in the
already complete equality-weighted cache relation and its dual-tape terminal
closure.

The scaled implementation is now green.  `C6PS1` has a strict canonical
**304-B** codec and binds the statement plus four response-fixed fold
corrections before either relation point; each repetition's two append
corrections are computed and transcript-bound after that relation point and
before its first sumcheck round.  The verifier folds only canonical base
keys and applies `C6PS1`; the provider folds matching source plaintexts,
tags and base masks.  A mutation of the source frame fails the integrated
dual-tape path.  The 6-round source-bound package is **1,506 B**, still uses
**32 full correlations/tape**, emits **64 pending claims**, and closes through
the real 72-slot `C6LNK2` and paired PCS fixture.  Production geometry is
**3,810 B / 104 correlations per tape**.  Lean proves the aggregate key
identity directly; the full audit is **337 total / 98 C6** named targets.
This closes the scaled bootstrap only: resident source replay, the 24-round
streaming compiler and `CacheSegK` removal remain the next gate.

### 6.2 Continuation-prefill and cache-fold source-map seam

Inspection of the actual T1 attention path found a load-bearing seam before
the source-map adapter.  `CacheSegK` currently gives the verifier a stored
`VerifierKey` for every element of every earlier K/V segment, and
`cache_fold_rows_k` / `cache_fold_cols_k` fold those keys directly.  Also, the
main prefill path is the square `BandShape {t0=0,q=prompt}`.  Neither behavior
implements a later C6 certificate with `old_context>0`: hidden historical
corrections prevent reconstructing corrected keys from only the PCG seed,
and rerunning a square prefill would ignore or duplicate the accepted cache.

C6 therefore preregisters the following replacement before touching those
functions:

1. A first certificate may retain the existing square prompt band at
   `t0=0`.  For any later certificate, nonempty prompt prefill is one offset
   band `BandShape {t0=old_context,q=prompt_tokens}` whose prefix is the
   accepted predecessor cache.
2. Nonempty deferred decode is one second band at
   `t0=old_context+prompt_tokens,q=decode_tokens`.  Its prefix is the same
   predecessor cache followed by the current response's prompt slab.  Empty
   prompt or decode phases occupy a public-zero phase slot.  The maximum
   grammar is always two response-level bands, never one proof instance per
   token.
3. For each band/layer/head, the existing V column fold and K row fold are
   split into a predecessor-state linear functional and a current-response
   slab linear functional.  The old `CacheSegK` result is not accepted.
   Instead, the model proof exposes a typed pending target; the cache
   relation proves the predecessor contribution from the old PCS slots and
   the current contribution from K/V outputs already owned by this response.
4. The client derives every fold descriptor and coefficient schedule from
   the public workload, fixed GPT-2 geometry and the already verifier-owned
   attention challenges.  The provider supplies no authoritative indices,
   weights or old key vector.  Both roles compile the same compact topology
   and instance digest; missing, duplicate, reordered, wrong-axis,
   wrong-layer/head or wrong-band folds reject.
5. New K/V outputs are ordered by `(K then V, layer, position, channel)` and
   fill exactly `[old_context,new_context)`.  Prefix/tail/padding checks use
   the same ordering as Section 6.1.  No historical correction or key is
   reintroduced on the wire.

For a nonempty band there are exactly

```text
12 layers * 12 heads * (one V-column + one K-row fold) = 288 fold operations.
```

The two fixed phase slots therefore cap the topology at 576 fold operations
regardless of token count.  Token/context length changes the number of
coefficient applications, not the proof grammar.  At the baseline first
response `(old,prompt,decode,new)=(0,100,50,150)` the compact plan has two
bands, zero predecessor-cell uses, `1,843,200` earlier-current-slab uses and
`2,764,800` appended K/V sources.  A decode-only continuation
`(150,0,50,200)` has one live band, `2,764,800` predecessor-cell uses and
`921,600` appended sources.  The last baseline continuation beginning at
context 900 has `16,588,800` predecessor-cell uses but the same one-band
proof grammar and response cap.

These counts are logical source applications, not serialized values and not
new MAC correlations.  The production implementation must stream/batch them
inside the one 24-round cache relation.  Materializing the full coefficient
map, retaining `CacheSegK`, or charging a key-vector retransmission is
forbidden.  This amendment does not yet prove that the current attention
code can be migrated within the timing cap; it makes that migration and its
two-seed topology differential the next explicit gate.

The value-independent workload compiler for this seam is now locally green.
`derive_c6_persistent_cache_source_plan` accepts the canonical `C6Workload`,
emits only the zero-to-two band descriptors and recomputes all four logical
censuses above; a digest refuses reordered/mutated plans.  It does not yet
observe the actual attention calls or their challenge-derived coefficients,
so this is not the required prover/verifier two-seed runtime identity.  Both
ordinary and `c6-trace` `volta-pcs` suites remain green at **172/0/1** and
**173/0/1**, plus **14/0/2** integration and **2/0/0** layer tests in each
mode.

The next additive runtime checkpoint closes that observation gap on the host
T1 path.  Feature-only `c6_cache_fold` records the final bilinear cache
functional handed to each chained GEMM, after both folds: exact row and
64-column coefficient vectors, public band/section/layer/head geometry,
segment rows and the opaque authenticated target provenance.  It records no
plaintext cache cells or verifier keys.  Capture is same-thread guarded and
fail-closed on invalid section/head/window/coverage, duplicate semantic
identity, a missing K/V family or any cohort that does not contain exactly
all 12 heads.  The topology digest is sequence-sensitive and excludes
challenge values; the instance digest binds all coefficients in canonical
row-then-column order.  Opaque target tokens are deliberately excluded from
cross-role digest equality because prover and verifier operation traces use
different namespaces.

The real one-layer attention path at `T=4` produces exactly **24 folds / 6,144
coefficient applications**.  For two independent transcript/PCG seeds,
prover and verifier records and both identities are equal within each run;
the topology identity is equal across seeds while the instance identity
changes.  The existing frozen-artifact response E2E at prefill `12` plus one
offset band of `4` observes exactly **576 folds / 516,096 coefficient
applications**.  Both roles agree record-for-record; prefill segments are
`[12]`, continuation segments are `[12,4]`, and the scheduled sections
normalize from `0..11` and `16..27` to the same model layers `0..11`.

At this checkpoint the diagnostic did not yet replace `CacheSegK`, make the
recorded target a packed-link pending claim or instrument the resident
provider fold.  The successor-functional amendment below subsequently
removed the need for a separately authenticated predecessor/current-slab
target split, but it does not by itself close those runtime seams.  No
stand-in or response-byte credit is earned here.

#### 6.2.1 Runtime fold-batching amendment

The production-compiler audit found that the earlier `C6PS1` wording cannot
be used literally.  There are up to 576 authenticated attention targets, and
a fixed linear sum would permit cancellation.  Moreover, any sound random
batch differs between the two complete cache repetitions, so its correction
cannot be one of four response-fixed values.  Splitting each target into a
predecessor part and a current-slab part would also require an additional
authenticated equality tying their sum back to the target consumed by the
model proof.  Omitting that equality is unsound.

C6 instead batches the complete model targets and checks them directly
against the successor cache.  For canonical fold record `j`, let `t_j` be
the authenticated target and `C_j` its factorized row-by-column cache
functional.  In repetition `b`, the existing successor-owner root
`rho_b` is used in scalar-power order:

```text
t_K,b = sum_{j of kind K} rho_b^(j+1) * t_j
C_K,b = sum_{j of kind K} rho_b^(j+1) * C_j
t_V,b = sum_{j of kind V} rho_b^(j+1) * t_j
C_V,b = sum_{j of kind V} rho_b^(j+1) * C_j.
```

The successor-functional relation proves `t_K,b=C_K,b(new_cache)` and
`t_V,b=C_V,b(new_cache)`.  The pointwise append transition already proves
`new_cache=old_cache || response_slab`; therefore the model target is bound
to the accepted predecessor prefix and the current response output without
an unauthenticated split target.  The predecessor-functional owner is
canonical zero in this descendant; it may not carry provider-selected data.

No new challenge is introduced: `rho_b` was already sampled independently
in each repetition after every individual model target and coefficient
schedule was fixed.  Reusing it for 576 scalar powers raises that owner's
univariate degree from one to at most 577.  The complete cache census becomes

```text
77 - 1 + 577 = 653 roots per repetition,
two independent repetitions: 653^2 = 426,409 < 2^19,
epsilon_cache <= 426,409 / |Fp2|^2 = 237.298... bits.
```

This remains stronger than the frozen conservative cache allocation and
does not change Q=121 or any response/setup cap.  `C6PS1` keeps its exact
304-B size but advances to a new strict version and ordering:

```text
header + statement                                                 48 B
2 repetitions * (fold K/V + append K/V) * 2 tapes * 16 B          256 B
total                                                              304 B.
```

For each repetition, the fold K/V corrections are sent after `rho_b` and
before the 24-coordinate relation point; append K/V corrections remain
after that point and before the first sumcheck round.  The source-bound
package therefore remains **3,810 B / 104 full correlations per tape**, the
response roof remains **33,656,098 B**, and no historical corrected key
vector returns.

The preregistered compiler gate is now locally green.  The trace snapshot
retains each record's exact row/column factors and compiles global canonical
powers `rho^(j+1)` without a dense cache-coefficient field.  Compilation
recomputes individual and aggregate digests, row/column/application censuses,
section-to-layer normalization, segment coverage, ordinal uniqueness and
complete 12-head K/V cohorts.  It rejects changed factors, records, aggregate
identity and incomplete families.

At scaled `T=4`, an independent dense `4 x 768` oracle agrees on every K and V
cell: **24 folds / 1,632 retained factor values / 6,144 coefficient
applications**.  The real frozen-artifact `12+4` response compiles both role
traces under two distinct roots with identical per-root batch identities and
distinct cross-root digests: **576 folds / 44,928 retained factor values /
516,096 applications**.  The fixed fail-closed cap is **576 records /
626,688 factor values**, about 10.03 MB at 16 B per `Fp2`, versus a forbidden
`2^24` dense field.

Lean proves the scalar-power bad-root count at 576, the successor-functional
append transitivity and exact **653 / 426,409 <2^19** census.  Full build is
3,261 jobs; the audit is **345 total / 106 C6** named targets with stdout
SHA-256
`007a24a1d31f9dde8a7484905803155298eaf00dc5d47e45e776ed3ff27881e6`.
The subsequent strict transcript sub-gate is also locally green. `C6PS1`
advances from version 1 to version 2 while remaining exactly **304 B**.  Its
former four response-fixed corrections are gone.  In each repetition the
successor-owner root first defines canonical global powers
`rho^(ordinal+1)` over every individual model fold; the two K/V fold
corrections are then transcript-bound before the 24-coordinate relation
point.  The two K/V append corrections are bound only after that point and
before the first cache sumcheck round.  The predecessor-functional owner is
constructed as authenticated canonical zero and has no source constructor
or correction field.

The scaled relation now consumes an arbitrary ordered fold inventory (capped
at 576), checks each individual successor functional, and derives its two
repetition-local K/V aggregates from the exact scalar powers.  The strict v1
decoder, wrong fold/append frames, changed coefficient inventories, wrong
points and every former binding seam reject.  The existing source-bound
6-round path still closes through `C6PC2 -> C6LNK2 ->` both packed PCS chains
at **1,506 B / 32 full correlations per tape / 64 pending claims**;
production remains **3,810 B / 104 per tape**.  The direct 77-root pointwise
reference census and the current 653-root streaming census are now separate
executable constants, preventing historical metrics from silently claiming
the scalar-batch repair.

This closes strict `C6PS1` placement only.  Typed runtime targets still have
to replace the scaled fold-source fixture and enter the step-wise 24-round
cache participant; `CacheSegK` remains live.  No response, setup,
correlation, prover-time or hardware credit is earned yet.

## 7. Certificate and challenge grammar

All integers are unsigned little-endian and all field elements use their
canonical existing encodings.  Decoders reject unknown versions, nonminimal
lengths, duplicate fields, trailing bytes and noncanonical field values.

The response protocol is ordered:

1. client sends the accepted head, setup-manifest digest, fresh 32-byte
   nonce, requested workload and one indivisible pair of correlation ranges;
2. provider durably reserves the slot/range pair and sends the canonical
   public response prefix;
3. provider sends commitments to hidden direct corrections, hidden
   `u_vectors`, cache witness and the complete pre-query statement;
4. client sends the next verifier challenges, including Q=121 Ligero column
   queries and wrapper batching challenges; within every hidden-linear,
   cache and wrapper sumcheck this step is repeated round-by-round as
   prover-message then fresh client challenge, never as one upfront tape;
5. provider sends retained T1 fields, queried columns, compact residual
   outputs, `new_head` and `pi_final`;
6. client verifies the wrapper, streams both `K_base[b]` values, checks both
   coordinates of the amplified Δ-residual event, and atomically commits the
   new head plus certificate digest;
7. client sends an ACK naming that digest.

Every challenge is domain-separated by protocol/version, setup manifest,
connection, response nonce, epoch, old head, slot/range pair and the digest
of all prior frames.  A query is never cached or reused.

The final certificate binds at least:

```text
version, protocol/model/params/setup-manifest digests,
connection_id, epoch, nonce,
old_head digest, predecessor certificate digest,
new_head digest, old/new cache lengths,
both correlation stage/start/count tuples and slot id,
workload digest and public token/output digest,
retained transcript digest,
wrapper statement/root digests, including both correction roots,
both Delta-residual public-output pairs,
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

- Reservation durably burns both complete correlation ranges in one journal
  record before proof work starts.  No half-reservation is representable.
- Abort before acceptance leaves the client's accepted head unchanged and
  moves the slot to `Burned`.  Neither range is ever reused.
- A retry reserves a new slot/range pair and a new nonce.
- Once `Produced`, `(old_head, nonce, slot)` has exactly one canonical
  certificate digest.  An ambiguous ACK permits retransmission of those
  exact bytes only.
- Producing a different child or different certificate bytes for the same
  tuple is a terminal fork fault for that connection.
- `Accepted` is recorded only for the client-ACKed digest.

The durable slot reservation also binds the complete requested workload.
Binding only `(old_head, nonce, slot, ranges)` would allow proof work after
the range burn to change prompt/decode/cache geometry.  This field was added
before wrapper integration and moves only the provider-local slot-journal
component to codec v3; it does not add a field to the final certificate,
where the workload was already present.

Unlike the historical connection-terminal-on-any-abort path, C6 burns the
individual slot fail-closed and keeps the remaining connection credit
usable.  Malicious PCG/setup/check failure that invalidates the shared
connection material remains terminal.

## 9. Anti-rollback V1

V1 assumes one client with durable authenticated local storage.  The client
keeps:

```text
connection_id, accepted epoch/head, accepted certificate digest,
used nonce/slot high-water information,
raw high-water offset for each ordered MAC tape,
params/model/protocol digests,
setup-manifest digest binding both tape identities.
```

Acceptance is a compare-and-swap against the exact old state, implemented as
write-new-record, file `fsync`, atomic rename, and parent-directory `fsync`.
Replay, provider-induced rollback and provider-induced fork are rejected by
the old head, epoch, predecessor digest, nonce and slot bindings.

The raw ranges are client-owned.  Given a declared preflight count `n`, the
client derives coordinate `b` as

```text
[raw_high_water[b], raw_high_water[b] + n)
```

and atomically advances both offsets in the same durable reservation that
installs the pending attempt.  It never accepts provider-selected starts.
Abort and acceptance preserve those already advanced offsets.  Overflow of
either tape rejects before the state write.  A pending state is canonical
only when both range ends equal the corresponding stored high-water values.
This rule moves the client-state component to codec v3; setup and final
certificate wire remain v2 and retain their existing byte budgets.

V1 does not claim protection against restoration of an arbitrary old client
disk snapshot and does not support concurrent multi-device writers.  Those
require an external monotonic counter/log/synchronizer and are outside this
phase.

## 10. Correlation credit

The clean T1 connection record gives the canonical baseline raw allocation:

```text
sub/full protocol counts            4,793,590 / 181,933
model raw correlations                           5,157,456
final ProductClosure/ZeroBatch raw                         4
historical PCS raw reserve                          78,232
complete allocated raw range                     5,235,692
terminal-one stage-3 usable                    110,918,718
21 * 5,235,692                                 109,949,532
remaining after 21 baseline slots                  969,186.
```

C6 reserves 21 baseline slots:

- 17 acceptance credits;
- 4 abort/retry credits.

The ordinary T1 tape keeps its exact `38,371,465-B` first exchange.  C6 adds
one independently generated residual-only tape with the same conservative
first-exchange budget and capacity.  This is required because repeating an
RLC with the same connection secret does not amplify the case in which every
forged affine relation has that secret as a common root.  The two independent
MAC coordinates are:

```text
Delta_res[0] = ordinary T1 connection Delta
Delta_res[1] = independent C6 residual-only connection secret.
```

For each direct source, coordinate `b` has its own provider share
`(r_i[b],m_i[b])`, verifier base key and hidden correction
`d_i[b] = x_i-r_i[b]`.  The wrapper proves that both coordinates authenticate
the same typed plaintext DAG.  Product masks, base-share challenges and grand
residual checks are independent per coordinate.  The second tape is never
used to change the retained T1 verifier and adds no clear correction or tag
vector to the response.

Each attempt reserves equal raw ranges from both tapes atomically.  Abort
burns both ranges; neither coordinate can be partially reused.  Actual
allocation is by raw count, not by a nominal slot multiplier.  A legal
variable workload declares and durably reserves its exact preflight count in
both tapes; insufficient remaining credit in either tape rejects before proof
work and does not partially allocate a range.

The total C6 setup ledger is

```text
ordinary fase-D real/AES PCG               38,371,465 B
C6 residual-only real/AES PCG              38,371,465 B
paired-PCG subtotal                         76,742,930 B
+ all client-received C6 verifier params
+ canonical setup framing
<=                                         150,000,000 B.
```

Thus at most `73,257,070 B` remain for all client-received C6 parameters and
setup framing.  A future implementation may measure a smaller paired setup,
but the preregistered capacity proof and hard gate use the conservative full
duplication above.

Provider-only model-global tables do not count as client traffic, but their
digest/version/max geometry is certificate-bound.  Any byte received by the
client counts in full.

### 10.1 Paired codec and durable-state schema

The pre-amplification reference codec is not wire-compatible with the
two-tape construction.  C6 therefore retains canonical network/setup/final-
certificate codec schema `v2` and rejects old `v1` magic/version
fail-closed.  The client-state and provider slot-journal components are v3:
they add client-owned raw high-water offsets and workload-bound slot
reservations respectively.  Old v2 durable state/journal bytes reject rather
than being reinterpreted.  These component bumps do not alter setup or
certificate wire.

The setup manifest now binds `connection_id`, two distinct ordered tape
identities, and for each tape its raw capacity, per-baseline count and
client-received PCG setup bytes.  The client state and every attempt, slot
reservation and final certificate bind the setup-manifest digest.  An
attempt carries one `C6PairedCorrelationRanges` value: two complete ranges
with equal raw counts, serialized and journaled as one indivisible record.
Overlap of either coordinate with any live or burned predecessor rejects the
whole reservation.

The wrapper commitments carry two correction roots and the certificate
carries two affine residual-output pairs.  The final designated verifier
accepts only if both coordinates pass.  The compact cache head remains
single: both coordinates certify the same typed plaintext DAG and the same
atomic cache transition.

The scaled canonical fixtures are:

```text
setup manifest     437 B   c3388a149106ea3f...525c2fd833b29d75
genesis state v3   308 B   87f19b92d8e7a137...f234e903798b6d6b
small certificate  935 B   454a4482ab3329fc...c6322f8465ca8c1
```

The fixture setup exchange is exactly `76,743,367 B`, including both
`38,371,465-B` PCG tapes and the 437-byte manifest.  Certificate validation
also enforces the preregistered roofline maximum
`pi_final <=4,409,824 B`, strictly inside the owner hard cap
`4,500,000 B`; with the retained transcript this is
`33,586,456 B`.  The durable C6 module is **18/18 PASS** and the complete
`volta-proto --features c6-trace` crate is **143 pass / 0 fail /
1 pre-existing production-size ignore**.

The complete local lifecycle burns four baseline attempts and then accepts
17 on one connection.  It ends at cache epoch/length `17/17`, slot
high-water `21`, and raw high-water `109,949,532` on both tapes, leaving
`969,186` rows each.  All 17 fixture certificates have equal encoded length,
and one produced-but-unacknowledged slot is reopened and retransmitted
byte-identically before acceptance.  The accompanying Lean addendum proves
range start/end, equal paired counts, capacity preservation, burn
preservation and retry disjointness.  This is lifecycle and framing
evidence; the fixture wrapper bytes do not instantiate the cache argument or
earn final-proof credit.

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

Every statistical wrapper profile MUST be at least 128 bits before union.
Because

```text
|Fp2| = 340282366762482138490186164457219031041 < 2^128,
```

one field challenge is not literally a 128-bit event.  All four named C6
events therefore require two independent complete repetitions:

1. hidden-linear-functional RLC plus both family sumchecks;
2. wrapper PCS fold/query chain;
3. cache-argument batching plus its sumcheck;
4. the grand Δ-residual MAC coordinate, including its base-share binding.

For events 1--3 the two independent challenge tapes are derived under
distinct certificate-bound domains after all relevant commitments.  For
event 4 they additionally use the two independent connection secrets and
correlation tapes defined in Section 10; two RLCs under one `Delta` are
explicitly insufficient.  The two PCS chains remain inside **one** canonical
packed opening/envelope, so this amplification does not authorize a second
response opening or a fifth event.  The exact bytes, rounds, query counts and
per-event rational bounds land in the pre-backend roofline.

The implementation reports every term and counter explicitly.  Merkle/hash
collision resistance, transcript expansion and PCG assumptions remain
separately named computational assumptions rather than being silently
converted into a statistical bit count.  The existing M3/M7/M8/M2
MAC-closure inventory is unchanged and remains tracked under the inherited
T1 convention rather than being duplicated as a fifth C6 wrapper allocation.
The four new allocations remain linear-functional sumchecks, wrapper PCS,
cache argument and the amplified grand Δ-residual.

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
   per-certificate/session composition.  Before backend code, the additive
   `C6Amplification.lean` module must also prove the exact `Fp2` cardinal is
   below `2^128`, the generic two-independent-repetition cardinality square,
   the two-secret Δ-residual accepting-pair bound and the concrete
   Goldilocks inequalities used by the hidden-linear and Δ event budgets.
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
   Δ-residual statement in both independent MAC coordinates, with a
   cross-coordinate equality to the same typed plaintext DAG.
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
  baseline attempts in **both** residual tapes below `150,000,000 B`;
- any cache proof field or opening count grows with current cache length;
- the construction needs a second response PCS opening or per-token proof
  instance;
- weights and embedding are collapsed under separate hidden-`u` RLC events,
  or the linear-functional block uses only one unamplified `Fp2` repetition;
- any of the four named C6 statistical events uses only one unamplified
  `Fp2` repetition, the PCS repetitions become two response openings, or
  the Δ-residual repetitions reuse one connection secret/tape;
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

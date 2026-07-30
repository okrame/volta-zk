# C6 — inline Δ-residual certificate and persistent cache

Status: **OWNER REQUIREMENTS FROZEN; Q=121 CONTINGENCY ACTIVATED BEFORE
IMPLEMENTATION; FORMAL SEAM / ROOFLINE / PAIRED CODEC / PRODUCTION SOURCE
CENSUS / PAIRED COMPLETE SOURCE WITNESS GREEN; OPERATION DAG/CACHE/WRAPPER
PENDING; LOCAL IMPLEMENTATION AUTHORIZED; HARD STOP BEFORE POD**.

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
Delta residual       4 / |Fp2|^2        >253 bits.
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
Goldilocks NTT, BLAKE3/Merkle and streaming kernels.  Charging two full
commit/recompute passes, two fold chains and 32 coefficient-equivalent
sumcheck passes gives an informative kernel floor of approximately
`8.380 s` including the model proof.  It leaves approximately `11.620 s` for
unmodeled cache construction, orchestration and integration under the
`20.000-s` gate.  This does not turn the P7 microbenchmarks into an end-to-end
PASS: if the optimized implementation cannot remain below the ceiling, C6
stops without falling back to the historical multi-minute engine.

The executable source of record is `scripts/budget_c6_wrapper.py`; it emits
the exact rational/integer report with `--json`.  Its permanent tests are in
`tests/test_budget_c6_wrapper.py`, including exhaustive frontier comparison
through 16 leaves and selected 32-leaf boundary cases.  At this checkpoint
the combined base-budget/wrapper suite is `8/8 PASS`.  This local evidence
closes the roofline milestone only; it is not a production census, backend
implementation or A100 measurement.

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

1. client sends the accepted head, setup-manifest digest, fresh 32-byte
   nonce, requested workload and one indivisible pair of correlation ranges;
2. provider durably reserves the slot/range pair and sends the canonical
   public response prefix;
3. provider sends commitments to hidden direct corrections, hidden
   `u_vectors`, cache witness and the complete pre-query statement;
4. client sends the next verifier challenges, including Q=121 Ligero column
   queries and wrapper batching challenges;
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

Unlike the historical connection-terminal-on-any-abort path, C6 burns the
individual slot fail-closed and keeps the remaining connection credit
usable.  Malicious PCG/setup/check failure that invalidates the shared
connection material remains terminal.

## 9. Anti-rollback V1

V1 assumes one client with durable authenticated local storage.  The client
keeps:

```text
connection_id, accepted epoch/head, accepted certificate digest,
used nonce/slot high-water information, params/model/protocol digests,
setup-manifest digest binding both tape identities.
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
two-tape construction.  C6 therefore uses canonical codec schema `v2` and
rejects the old `v1` magic/version fail-closed; this is a codec/schema bump,
not a second product protocol.

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
genesis state      292 B   193255528fb5f7e3...066b99c8cc402c51
small certificate  935 B   454a4482ab3329fc...c6322f8465ca8c1
```

The fixture setup exchange is exactly `76,743,367 B`, including both
`38,371,465-B` PCG tapes and the 437-byte manifest.  Certificate validation
also enforces the preregistered roofline maximum
`pi_final <=4,409,824 B`, strictly inside the owner hard cap
`4,500,000 B`; with the retained transcript this is
`33,586,456 B`.  The paired C6/residual target is `20/20 PASS`; the complete
`volta-proto` crate is `130 PASS / 1 pre-existing production-size ignore`.

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

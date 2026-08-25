# C6.3 Authenticated Sketched WHIR Design

Status: **R0/R1 LOCAL GREEN / C63-G1 A100 PASS / CHECKPOINT 215d4f4 / POD PREFLIGHT PASS / FULL-SIZE DIFFERENTIAL PENDING**

This document is the authority for C6.3. It replaces C6.2 only for new C6.3
work; C6.2 code, artifacts and dispositions remain immutable evidence. The
first target is GPT-2 on one A100. A later Gemma-class design must be derived
from measured scaling rather than assumed here.

## 0. Authority, objective and hard stop

The owner opens autonomous local design and implementation of an
Authenticated Sketched PCS. The objective is a complete response proof below
20 seconds on one A100 without moving work to another response and without
weakening the existing designated-verifier statement. The certificate target
is `30,000,000 B`; a larger complete certificate is still serialized, verified
and recorded rather than discarded.

The minimum protocol path remains selected. The owner authorizes the minimal
resident projection/opening and WHIR message-ownership extension identified
by G2. It does not change the proof statement; it may extend ABI43 and the
local WHIR fork only as required by the registered five-item unblock.

1. keep the accepted K/V state compact and resident on the GPU;
2. represent padding and the six inactive cache columns as canonical virtual
   zeros;
3. start from one setup-owned all-zero predecessor;
4. update the accepted state from the exact authenticated K/V delta;
5. reshape the four K/V-tape correction columns into the screened
   append-aligned `t=16` Bolt rows, then adapt Bolt's sparse map and one
   extension-field row mix inside dedicated Volta Hiding-WHIR lanes;
6. make the systematic side a commitment to the existing one-time VOLE
   corrections, never to clear K/V values;
7. batch every sketch-consistency check of a response into one closure and
   settle it inside the same certificate.

Local reference work is authorized. The owner supplied and admitted the first
A100 for component work; G1 passed there. G2 stopped before E2E, consumed no
protocol correlations and created no certificate. Further pod protocol work
requires a clean component checkpoint and all terminal differentials. A
failure to prove both full binding and privacy remains a hard
stop: a small linear fingerprint by itself is not an admissible replacement
for the PCS.

## 0.1 Gates and clock definitions

The numerical gates are engineering targets, not permission to weaken a
cryptographic invariant. A time, certificate-byte or verifier-RSS miss records
`FAIL` but is nonterminal when the run can safely continue.

| Gate | C6.3 target |
|---|---:|
| public/connection setup | `<150,000,000 B` |
| setup plus first certificate | `<172,000,000 B` |
| complete certificate | `<=30,000,000 B` |
| `pi_final` partition | `<4,500,000 B` |
| response-specific prover on one A100 | `<20.000 s` |
| official four-thread CPU verifier | `<5.000 s` |
| verifier additional RSS | `<=8,000,000,000 B` |
| A100 device high-water guard | `<=45,818,576,864 B` |
| complete per-certificate soundness | `>=78.00 bits` |

`response_specific_prover` starts after setup, model weights and fixed
provider tables are resident. It includes fresh proof work, real/AES PCG
consumption, all synchronization and serialization. It excludes model
inference, network time and the one-time fixed preload. The first cold run
also records those excluded phases so the real deployment cost remains
visible. A cold total is not compared with the 20-second gate.

The cold record keeps the following clocks separate:

1. `provider_model_preprocess`: setup generation/validation, model and fixed
   table load, sparse-`H` expansion/upload and every other provider-fixed
   one-time operation;
2. `cold_inference`: generation of the model response and authenticated K/V
   append, after preprocessing is complete;
3. `cold_certificate_prover`: from the ready authenticated append through all
   fresh correlations, proof work, device synchronization and canonical
   certificate serialization; it excludes preprocessing, inference and
   verification;
4. `cold_verifier`: decoding and complete four-thread CPU verification;
5. `cold_request_to_accept`: inference, certificate generation and verifier;
6. `cold_deployment_to_first_accept`: preprocessing plus request-to-accept.

Crossing 20 seconds marks the prover gate **FAIL** but is not an execution
stop. Crossing `150.000 s` records a second diagnostic miss and the run still
continues until it produces and verifies a complete canonical certificate or
hits a genuine protocol/resource failure. Certificate bytes above 30 MB and
verifier RSS above 8 GB are handled the same way. The supervisor may terminate
only for imminent memory/disk exhaustion, a cryptographic rejection or an
invalid state transition.

The setup and fixed model cache may be shared by several connections when the
model and parameters are identical. K/V values, their sketch state, the
accepted head and all PCG correlation state are connection-specific and are
never shared.

The historical 17 accepted responses and four burn attempts remain future
session requirements. The first C6.3 experiment deliberately evaluates only
two accepted responses and records `session_gate_evaluated:false`; it cannot
claim the 17-response or burn gates.

## 0.2 R1 correction: public bulk, designated tail

The first exact Goldilocks screen invalidates the earlier `t=128` byte
assumption. Porting Bolt's YHC growth-rate calculation gives numerical root
`0.0497943788349776`; C6.3 uses the lower `gamma=0.049` for screening. The
systematic spot error `(1-gamma/3)^q` then needs
3,536 / 3,789 / 4,041 / 4,294 / 4,378 / 4,420 rows for
84 / 90 / 96 / 102 / 104 / 105-bit sub-budgets.

YHC Theorem 6.2 cannot justify a concrete D22 claim: its degree-16 term is
asymptotic `Theta(n^-7)` and omits both the constant and the length threshold.
C6.3 instead starts from Theorem 3.6's exact expected count of bad vectors.
The coefficient upper bound, an exact binomial-mode bound and Theorem 5.6's
decrease-then-increase shape give, for every weight `1 <= l <= 205,520`,

```text
E[A_l] <= (16*n + 1) * exp(n * phi(l/n)),  n = 2^22.
```

Rational witnesses `y=1/4` at `l=1` and `y=2/5` at the upper endpoint prove
`n*phi <= -234*ln(2)+1/2` and `n*phi < -7,645` respectively. Since
`205,520 < 2^18`, `16*n+1 < 2^27` and `exp(1/2) < 2`, the union probability
that setup has distance at most `0.049*n` is strictly below `2^-188`. This is
an exact rational screen; the tighter 80-digit evaluation is about
`2^-211.887` but is not needed for the claim. The source formula was checked
against the official arXiv TeX archive, SHA-256 `5fbb160a...56a`.

This closes the hidden-constant issue, not the complete protocol soundness.
The result transfers only to the exact YHC setup ensemble: one uniform socket
permutation, parallel edges allowed, and independent uniform nonzero
Goldilocks labels. Deduplicating edges, rejecting graphs or sampling labels
with bias changes the distribution and needs a new proof. Production expansion
and cryptographic randomness accounting remain hard stops. The one-shot public
seed was fixed locally, before any provider saw it, as
`deda54f405265cd5f57b0baec79fbc6fcd1e5149f68937e28bb0737338c5bdea`.

The scaled sampler reference now implements the exact socket construction:
one domain-separated BLAKE3-XOF stream drives descending Fisher--Yates with
unbiased rejection, another samples independent nonzero Goldilocks labels,
and the expanded source-major edge stream is hashed. It preserves parallel
edges. Four rejected draws fail closed; the union bounds are below `2^-126`
for the shuffle and at most `2^-102` for labels. Conditioned on success this
is the YHC distribution in the ideal-public-XOF model. A 32-byte public seed
cannot information-theoretically describe a uniform D26 permutation, so the
remaining hybrid term for a public BLAKE3 random tape is explicit and unknown.
The fixed seed is provider-independent and cannot be replaced or retried after
the provider sees it. Its full-size expansion and manifest digest still need
to execute on the pod.

At 90 bits, a D19-by-128 fixed-row opening is already `4,738,496 B` before
framing. Even a codec that reconstructs every public zero needs more than
3.3 MB at context 200. It cannot be added to C6.2's `3,485,131-B` `pi_final`.
Sending only post-challenge row products is also rejected: a Merkle path does
not authenticate a product without the committed row, and `H` has a kernel.

C6.3 therefore uses the same semantic split already present in the C6.2 WHIR
chains. Material independent of the verifier's secret MAC multiplier is the
**tagless public argument**: systematic correction rows, their frontier,
sparse-`H` messages and the Hiding-WHIR bodies. `pi_final` contains the two
MAC-dependent common-X closures and the residual/auxiliary authenticated
link. No byte disappears from the complete-certificate or setup-plus-first
counts. This is an explicit C6.3 deviation from the historical rule that put
every new C6 byte in `pi_final`; it requires a separation theorem and a new
closed codec before receiving credit.

Removing only the predecessor/successor cache cohorts, the three cache-only
components and their three 40-byte component headers projects the retained
residual/auxiliary tail to `2,703,013 B` before the new closure, leaving at
most `1,796,986 B` under the strict `pi_final` gate. The current public-bulk
front-runner is the `t=16` reshape with a 105-bit phase profile. Its exact
two-level `q_X=4,420` correction artifact is at most `2,042,062 B`. One
projected D19 query set at `q_A=245` costs `149,316 B`. The selected
transition layout gives each of four D19 bodies one successor opening and,
for a continuation, one predecessor opening. Eight openings plus four
presence flags cost at most `1,194,532 B`. Cross-body or cross-tape query
sharing is optional and receives no credit.

The selected adapter proves tape-separated decoded `m_l` at D22 and `u_l` at
D19 while supplying already encoded `w_l=C(m_l)` and `y_l=C(u_l)` initial
oracles. Four 105-bit cores per authentication tape give eight bodies and
`9,039,328 B`. The conservative executable layout assigns each D19 body its
own authenticated predecessor/successor transition opening and 20-byte outer
frame. Its public bulk is `12,276,610 B`; the complete designated tail is
`2,704,637 B`. The resulting complete certificate is `28,692,111 B` and setup
plus first is `129,889,808 B`. Both actual gates pass analytically. Filling
`pi_final` all the way to its independent maximum would instead give
`30,487,473 B`, so the two unused margins cannot be spent simultaneously.

This remains `credit:false`. The canonical public, designated and final
certificate codecs include
every required proof-of-work witness and the local projected verifier binds
the accepted `A` rows to the randomized initial oracle. Screen v16 unions all
120 registered phase events, four terminal ZeroOpen errors, both sparse
relations, systematic spots, inherited C6.1 terms and the finite
setup-distance term. With `H_pow` independent from `H_fs`, the inherited
`2^20` Fiat--Shamir query cap gives `78.019023342845... bits`. This clears the
owner-revised `78.00`-bit target by only about `0.0190` bits and charges a
conservative `2^-128` BLAKE3-XOF computational assumption. Grinding has about
`15,990,784` expected hashes and
a fail-closed `2^26` candidate cap per phase. Adding those hashes to one
monolithic oracle remains invalid and below target. This is a computational
screen, not a formal standard-model theorem or empirical gate credit.

## 1. Evidence selecting this direction

C6.2 measured `275.113308912 s` in cache precommit. Dense encoding,
persistence, reread and tree hashing occupied about `249.51 s` (90.69%). It
created `78,383,153,576 B` of durable data and moved about 103 GB read plus
113 GB written. Keeping GW4 at `7.359403833 s` and its conservative 3-second
reserve leaves:

```text
20 - 7.359403833 - 3 = 9.640596167 seconds
```

for the complete cache binding. The current precommit therefore needs about a
`28.54x` reduction. Faster disk hashing cannot bridge that gap; dense cache
encoding must leave the response path.

The Bolt paper's useful idea is the systematic sketched code
`CH(X) = (X, C(HX))`: `H` is sparse, so the short sketch `HX` is cheap to
update, and only that short object enters the denser base code `C`. The
systematic component `X` is load-bearing. Committing only to `HX` is not
binding because many different `X` values have the same sketch.

C6.3 keeps this composition but changes both roles to match Volta. The
systematic object is the vector of one-time VOLE corrections `D = X - R`, not
the secret cache `X`. `D` is statistically masked by the connection-specific
correlation `R`, so its queried rows may be hashed and opened without exposing
K/V. Hiding-WHIR supplies `C`, the proximity proof and hidden opening targets
for the short sketch `H D`. In compact notation:

```text
AuthenticatedSketchedWhir(X) =
    (MerkleRows(D), MerkleRows(C^16(H D)), constrained Hiding-WHIR proof),
    D = X - R
```

This is an integration of Bolt into WHIR, not a Bolt replacement for WHIR and
not a standalone WHIR commitment to `HX`. The two child commitments are bound
by one typed C6.3 state head.

The published implementation at commit
`3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2` is a benchmark reference, not a
dependency candidate. It uses binary fields and Apple Metal, has no CUDA or
Goldilocks path, no hiding layer, no complete Bolt prover/verifier codec, and
does not implement its non-amortized Mulperm closure. C6.3 therefore reuses
the mathematical precode and proof structure, not the crate.

Local sources:

- [Bolt](../sota/2026-310-bolt.md) for sketched codes and the concrete screen;
- [YHC finite-field LDPC](../sota/2010-2030-weight-distributions-regular-ldpc.md)
  for the exact first moment and the growth-rate shape used by the finite bound;
- [DeepFold](../sota/2024-1595-deepfold.md) for batching and possible hiding;
- [projective sumcheck](../sota/2026-762-projective-sumcheck.md) only after a
  measured sumcheck profile justifies it;
- [Brakedown](../sota/2021-1043-brakedown.md),
  [dynamic vector commitments](../sota/2023-1830-vector-commitments-efficient-updates.md)
  and [SwitchFold](../sota/2026-1489-switchfold.md) as rejected first-version
  alternatives, not implementation dependencies.

## 2. Canonical cache message

The logical cache geometry does not change. This preserves the Transformer
relation and its 24-coordinate evaluation points:

- `k = 2^24` rows per column;
- eight response-independent columns;
- column 0 is K and column 1 is V;
- columns 2 through 7 are permanent zero;
- 12 live layers inside 16 padded layers;
- 1,024 token positions;
- width 768 inside padded width 1,024.

Let `X_e` be the `2^24 x 8` logical matrix after accepted epoch `e`. A row
contains the K/V cell at the existing C6 flat index and six zeros. Values
outside the accepted length, padded channels and padded layers are also zero.
Those zero values exist in the statement but not in a GPU allocation.

For GPT-2 the first transition `0 -> 150` inserts exactly `2,764,800` field
values. The second transition `150 -> 200` inserts `921,600`. The old prefix is
not copied or expanded to its padded geometry. An accepted provider owner
stores the two compact live tables, both correction tapes, the short sketch
state needed by the next response, the stable state head, length and epoch.
The verifier stores the systematic root, the state head and a bound
correlation-replay owner for every birth epoch that may still be opened; it
does not store clear K/V. Retaining only the current response's PCG owner is
insufficient because a later proof may query an older cache row.

The exact map between a compact value and its D24 coordinate remains the
existing `C6PersistentCacheLayout`, `C6CacheCell`, source map and append order.
A separate C6.3 relation must prove that the compact view and the logical
matrix are equal at every used coordinate; a type conversion is not evidence.

## 3. Authenticated sketched commitment

### 3.1 Objects

Setup samples one versioned, domain-separated sparse matrix `H` and the base
code parameters. Setup carries the generation seed and digest, not an explicit
edge list: storing a D22-by-D19 degree-16 matrix would exceed the setup budget.
The initial screen uses Bolt-min's provisional values
`alpha=1/8`, nonzero degree 16 and base-code rate `1/2`, but none of its
binary-field security numbers transfer to Volta. The finite Goldilocks
distance screen is green at a conservative 188 bits. The versioned descriptor
is `80 B`: 32 bytes of public seed, 32 bytes of expanded-`H` digest and 16
bytes of profile framing. Adding only that descriptor to the measured C6.2
setup gives a `101,197,697-B` floor; adding a full 30-MB certificate gives a
`131,197,697-B` floor for setup plus first proof. Neither is a C6.3 setup
candidate because the stronger tensor profile and codec are still unencoded.
The simple resident representation is exactly a 256-MiB socket permutation
plus 512 MiB of coefficients. These memory counts remain `credit:false` until the
production sampler, public-XOF assumption, Fp2 opening error and complete
soundness union close.

For tape `l` and every live cache cell, Volta already consumes a one-time
subfield correlation `(r_i,l, m_i,l)` and emits the 8-byte correction
`d_i,l = x_i - r_i,l`. The verifier holds the matching base key and its secret
MAC multiplier. C6.3 persists those corrections in the canonical D24 semantic
order, commits to their fixed D22-by-16 reshape before any opening challenge,
and never commits to `x_i` in clear form.

`C63CorrectionPrivacy.lean` now states the joint privacy argument. Let `I`
index every live `(cell, version, tape)` allocation over the complete
connection and sample `R in F^I` uniformly once. Then the whole vector
`D=X-R` is uniform for every fixed `X`. Consequently any adaptive transcript
generated only from `D`, public data, verifier state and fresh coins has
exactly the same distribution for any two cache/model states. This one
post-processing statement covers the correction roots and paths, `H D`, `A`,
`rho`, `m/u`, `w/y`, fresh mask coefficients and WHIR messages together; it
does not assume that WHIR hides the opened deterministic `A` rows.

The same accepted correction may be read again while its plaintext version is
unchanged. “One-time” forbids using its mask for a different plaintext
version: two such corrections reveal the plaintext difference. Every changed
cell receives a fresh versioned allocation and an abort burns that range. The
existing designated-terminal theorem is reused: a final zero-opening tag is
safe only when it is computable from the verifier view. Serializing the raw
prover MAC tag paired with a correction would let the verifier reconstruct the
plaintext and is forbidden. The production codec audit is now closed at the
typed boundary: public payloads contain corrections and tagless PCS material;
the designated tail contains only simulator-compatible ZeroOpen tags; client
replay keys have a separate private codec and are absent from the certificate.
The rejected four-body C6.3 suffix consumed 24 sub-correlations and 703 full
correlations per tape, including two fresh terminal masks. The recommended
repair projects 705 full correlations per tape. Neither census proves the
AES-PCG assumption or replaces the required real execution.

The source behind the local HVZK-WHIR fork is Chiesa--Fenzi--Weissenberg,
*Zero-Knowledge IOPPs for Constrained Interleaved Codes*, ePrint 2026/391
([AnyDoc Markdown](../sota/2026-0391-zero-knowledge-iopps-constrained-interleaved-codes.md)).
Its Theorem 10.2 proves only **honest-verifier** zero knowledge, under bounded
queries to zero-knowledge encodings and private zero-evaders. It does not by
itself prove Volta's designated-verifier privacy against a verifier that
chooses messages adversarially. C6.3 therefore uses the paper only for the
fresh randomized code-switching construction. Model privacy continues to
follow from the stronger outer statement above: after conditioning on any
fixed verifier state, the complete correction vector is uniform, and all PCS
material is post-processing of that vector plus public data and fresh coins.
The production codec/PCG audit must instantiate this premise. Hiding-WHIR is
retained until component measurements exist; its removal is a later measured
simplification, not an unproved privacy shortcut.

The semantic correction message first has four columns:

```text
D_e in F^(2^24 x 4), columns = K0, K1, V0, V1
```

The selected Bolt view reshapes the same `2^26` scalars as
`D'_e in F^(2^22 x 16)`. This is a permutation, not a new witness. For the
existing C6 coordinate
`i = ((layer * 1024 + position) * 1024 + channel)`, define:

```text
row    = (position << 12) | ((layer >> 1) << 9) | (channel & 511)
column = tape | (kv << 1) | ((layer & 1) << 2) | ((channel >> 9) << 3)
S_e = H D'_e, H: F^(2^22) -> F^(2^19), S_e: 2^19 x 16
A_e = C^16(S_e), C: F^(2^19) -> F^(2^20)
```

The displayed bit lists use the repository's least-significant-variable-first
convention. All ten position bits remain in the row: every token is one
contiguous D12 tile containing channel-low-9 and layer-high-3. Layer groups 6
and 7, the high-channel half for `channel_low >= 256`, and the future-position
tail are typed virtual zeros. A transition appends position tiles and never
reconstructs a D24 dense owner.

For each accepted state:

```text
systematic_root_e = MerkleRows(D'_e)
encoded_sketch_root_e = MerkleRows(A_e)
head_e = Hash(parameters, predecessor head, epoch, length,
              systematic root, encoded sketch root, source schedule)
```

Each D22 systematic leaf is one 16-element row (`128 B` before metadata).
It binds the row, birth epoch, source schedule and full connection/allocation
scope, not merely the reusable logical domain number. Tail and padded fields
use canonical virtual zeros. On those public fields C6.3 defines
`X=R=D=0`; it does not treat an unallocated VOLE correction as zero. A live
correction whose value happens to be zero remains a typed live field.

Each accepted token tile hashes its first 3,072 rows (`layer_high < 6`) and
fills the remaining 1,024 rows from one setup-owned virtual leaf before
forming its D12 root. The state tree then combines accepted tiles with the
setup-owned tail in its D10 position upper tree. The raw 128-byte correction
row payload is `58,982,400 B` for `0 -> 150`
and `19,660,800 B` for `150 -> 200`; typed row metadata and Merkle nodes make
the actual hashing input larger. The semantic non-padding correction input
is respectively `44,236,800 B` and `14,745,600 B`. It never allocates the full
`536,870,912-B` logical matrix. These are deterministic byte censuses, not
timings or certificate sizes.

`S` has `2^23` base-field symbols. Its encoded tensor `A` is conceptually D20
rows by 16 columns, or `2^24` symbols at rate `1/2`. Its persistent Merkle
layout follows WHIR's prefix-interleaved first fold: adjacent code positions
are paired into one physical D19-by-32 row, `256 B` before metadata. This does
not change the tensor or symbol count. The base code is tensorial:
`C^16 = I_16 tensor C`, so `H` and `C` act independently on every column.
Passing the scalar flattening to an ordinary one-dimensional WHIR encoder is
forbidden: it proves a different row-distance statement. R1 must prove the
row metric, paired physical layout, permutation above and multi-target
Hiding-WHIR binding.

The accepted `head_e` is byte-identical when reused as the next predecessor.
The response nonce is bound outside it so retry metadata cannot change a
previously accepted state. A root of raw `S` alone is neither Bolt's encoded
second commitment nor a state commitment: `H` compresses and has a kernel.

The exact commitment and opening codec receives a new C6.3 magic and version.
C6.2 envelopes and roots are never reinterpreted as C6.3 objects.

### 3.2 Delta update

Genesis uses setup-owned zero correction and sketch roots. For the newly born
cells in an append, both tapes form `delta_D'` in the canonical reshaped rows
and:

```text
X_e = X_(e-1) + Delta_e
D'_e = D'_(e-1) + J(delta_D'_e)
S_e = S_(e-1) + H J(delta_D'_e)
A_e = A_(e-1) + C^16(H J(delta_D'_e))
```

`J` first places the compact append at its canonical D24 coordinates and then
applies the fixed bit permutation above. The correction is exactly the one
already attached to the K/V output of the frozen
Transformer witness; C6.3 may not allocate a replacement correlation. The
authenticated output link proves the equality. Sparse multiplication, compact
systematic hashing and Hiding-WHIR stay on the GPU.

The earlier tape-separated row mixes are rejected. If two committed error
vectors are opposite, fixed support separation can hide their sum unless a
new post-commit scalar or a second encoded-sketch proof is added. C6.3 instead uses the
standard Bolt tensor step: after both systematic and sketch roots are fixed,
the transcript samples one uniform `rho in Fp2^16` over all columns. For any
challenged row weight `g`, the source coefficient is:

```text
a_l(cell) = g(row(cell)) * rho[column(cell,l)]
R_l(cell) + D'_e[row(cell), column(cell)] = X(cell)
```

For authentication tape `l`, define the post-`rho` messages without
flattening the tensor and without adding the two tapes:

```text
m_l[row] = sum(column: tape(column)=l) rho[column] * D'_e[row,column]
u_l[out] = sum(column: tape(column)=l) rho[column] * S_e[out,column] = H m_l
y_l[code_row] = sum(column: tape(column)=l) rho[column] * A_e[code_row,column]
              = C(u_l)
w_l = C(m_l)
```

`A_e` is fixed before `rho`; each `y_l` is obtained only by opening complete rows of
that root and taking their tape-restricted `rho` combination. `w_l` is the fresh code switch
committed after `rho`. The constrained WHIR adapter proves the decoded
messages `m_l` and `u_l` against the already encoded initial oracles `w_l` and
`y_l`; it must not pass `w_l/y_l` as new messages to the ordinary encoder.
The sparse closure proves both decoded relations `u_l=H m_l` with shared
round challenges and separate authenticated round streams.

The persistent `A` root is deterministic and external to Hiding-WHIR's fresh
randomness. It is never the randomized initial oracle `ZC(S;zeta)`: reusing
one mask across responses accumulates openings beyond the present privacy
argument, while refreshing it would change the accepted root. Each response
therefore built four fresh randomized base-field initial roots in the rejected
combined-tape composition. The selected repair builds eight, one per
arithmetic limb, object and MAC tape, and links them to deterministic `D'`,
`A`, `w_l` and `y_l` inside the same transcript.

The CPU reference now packs the physical `A` rows as
`[column][fold_position]`, projects both limbs of `A*rho`, and obtains exactly
the existing fixed-base encoding of the correspondingly projected decoded
message. Reusing that fixed base with two independent random tapes produces
different roots and two valid WHIR proofs. Mutating an authenticated `A` row
or the honest projection is rejected. This check alone proves layout and
honest linearity; the linked projected-MMCS attack test below supplies the
scaled malicious-substitution check. Production resident composition remains
unexecuted.

A virtual row `A*rho + mask` alone is insufficient. A dishonest prover could
choose `mask = C(u)-A*rho+Enc(0,zeta)` and make ordinary WHIR valid for an
unrelated `A`. The linked adapter must additionally prove, at the same initial
query positions, that

```text
randomized_initial_row - project_rho(A_row) = Enc(0,zeta)_row.
```

The left side is obtained from the fresh randomized-root opening and the
authenticated `A` opening. A second equation inside the first WHIR round ties
it to the already tracked initial randomness `zeta`. This needs no new random
challenge or standalone proof body, but it changes the C6.3 MMCS proof and
the first-round relation. The historical no-link verifier must remain
byte-identical.

`H` and the base code act independently on the two Goldilocks limbs of `Fp2`.
The support of a nonzero extension-field word is the union of its two base
supports, so the base-code distance transfers; treating the two limbs as one
long scalar vector does not and is forbidden.

The row permutation preserves the linear functionals used by the existing
authenticated output link. The verifier closes the two MAC tapes separately:

```text
K_l(a_l) + Delta_l * D_l(a_l) = M_l(a_l) + Delta_l * X_l(a_l)
```

The selected statement binds `m_0` and `m_1` separately to the corresponding
Transformer output equation. It never publishes or authenticates only their
sum. The two MAC equations are never added because `Delta_0` and `Delta_1`
are independent secrets. R1 must prove that the output link, both sparse `H`
relations and all eight Hiding-WHIR bodies compile the identical per-tape
coefficients, including the base-to-extension conversion.

The exact Rust reference now exposes both tape contributions and both
arithmetic-limb keys separately.
For every canonical live K/V cell it checks that the Transformer-authenticated
source `X` and replayed mask `R` share a tag, that `X-R` equals the correction,
and that the verifier-key difference equals its secret multiplier times that
correction. It compiles the terminal functional with factorized channel,
layer and position equality weights rather than a dense D22 vector. The
resident coordinator now compiles and authenticates this functional directly
from the inference-owned paired source after the sparse terminal point is
fixed; it creates neither a dense cache nor a second correction log.

This removes the eight persistent D24/D25/D28 cache encodings, files and CPU
tree walks. It does not forbid the transient `w_l=C(m_l)` owners and the
constrained views `y_l` required by the opening proof. They are derived after the
state roots and are never promoted as cache state; the pre-`rho` encoded tensor
`A` is the persistent second Bolt object.

The proposed owner is separate from the accepted owner. Verification success
atomically promotes it. Verification failure or process interruption keeps the
old owner and burns the allocated correlation range. No state may be promoted
from provider success alone.

### 3.3 One response-local closure

The C6.3 envelope batches K/V, both tapes and old/new state. It retains two
separate MAC tapes and two terminal MAC equations, but Bolt uses one common
`rho in Fp2^16`. Sumcheck and Hiding-WHIR still derive their own later
challenges inside the same response-local envelope and settlement point.

The conservative R1 construction keeps the checks that make Bolt binding:

1. query the systematic correction root at transcript-derived rows;
2. open the pre-`rho` encoded-sketch tensor `A` at transcript-derived rows;
3. derive `m_l`, `u_l`, the row views `y_l` and fresh code switches `w_l`
   separately for both authentication tapes;
4. prove with the constrained Hiding-WHIR adapter that every `w_l/y_l` pair
   is valid and that its decoded messages satisfy `u_l=H*m_l`;
5. resolve every output into the existing two-tape VOLE authentication rather
   than a clear cache evaluation.

The common `rho in Fp2^16` collapses each tensor row to one extension-field
symbol. The current WHIR implementation accepts one base-field polynomial and
encodes it internally. The minimum new adapter instead accepts both a decoded
message and an already encoded resident initial oracle. It runs eight base
proof cores sequentially: for each tape, two D22 limbs of `m_l` against `w_l`
and two D19 limbs of `u_l` against `y_l`. The conservative codec gives each
D19 body an independent authenticated `A` transition opening. Target
decomposition, the projected MMCS and strict codecs exist in both the scaled
reference and resident adapters. The resident coordinator derives its D22
terminal keys from the exact source/output link, and the complete CPU-verifier
entry replays the same sparse, source, global-link and WHIR order. Base-field row
challenges are not assumed: one Goldilocks draw has only about 64 bits and
cannot alone cover the complete soundness target.

The existing `commit_c62_cached_fixed_base` seam already avoids double
encoding for the honest CPU path. The remaining adapter work is specifically
the verified initial link above: projected `A` rows enter the same initial
queries and the row difference is constrained to the encoding of fresh mask
coefficients. Calling the cached-base seam without that second equation is a
diagnostic only.

Each `m_l` has D22 `Fp2` symbols and `w_l=C(m_l)` has D23 symbols at rate
`1/2`; each `u_l` has D19 `Fp2` symbols and `y_l=C(u_l)` has D20. The selected 105-bit adapter profile
uses D22 intermediate rates `[1,2,3,3,4,5,6,7]` with at most 18 bits of
fold proof-of-work, and D19 rates `[1,2,3,4,5,6]` with at most 17 bits. The
respective claimless body sizes are `1,289,080 B` and `970,752 B`, including
native proof-of-work witnesses. Four bodies per tape cost `4,519,664 B` and
the selected eight bodies cost `9,039,328 B`. No
clear terminal evaluation is serialized. Each projected D19 artifact adds a
20-byte outer frame plus its authenticated `A` opening. An unmodified
WHIR call over D23/D20 would double-encode `w_l/y_l`; it is
a safe implementation fallback, not the selected statement. This geometry is
why `t=16`, rather than the smaller-row `t=4` or earlier `t=128`, is the
current byte/time front-runner.

| decoded core | round queries | final | mask | PoW witnesses | body |
|---|---|---:|---:|---:|---:|
| D22 `m` limb | 245, 245, 113, 74, 74, 55, 44, 36 | 31 | 257 | 17 | 1,289,080 B |
| D19 `u` limb | 245, 245, 113, 74, 55, 44 | 36 | 254 | 13 | 970,752 B |

The total work of applying `H` across all 16 columns
is `16 * 2^26 = 1,073,741,824` sparse field multiply-adds only for a fully
materialized logical matrix. C6.3 skips virtual zeros and updates the accepted
sketch from the append: genesis executes `88,473,600` multiply-adds and the
`150 -> 200` continuation executes `29,491,200`; it does not recompute the
accepted prefix. These are operation counts, not A100 timings.

WHIR replaces Bolt's two Reed-Solomon/Ligerito proximity layers and hides their
targets. It does not, by itself, replace the code switch, systematic spot
checks or the `H` consistency relation. The selected census is two limbs of
`w_l` and two limbs of `y_l` for each tape, implemented as eight base-field
WHIR cores. This is the Bolt-inside-WHIR contribution; it is not a separate
PCS.

The eight WHIR cores do not by themselves prove `u_l = H m_l`. The selected
Volta-specific replacement for Bolt's non-amortized MulPerm is one two-stream
authenticated inner-product proof. After a fresh `r in Fp2^19`, set
`q=eq(r)` and `a=H^T q`; prove `<q,u_l>=<a,m_l>` for both tapes in 22
degree-two rounds with common challenges, then link the four extension-field
terminal values to the eight WHIR bodies. Its exact production-dimension census is
`67,108,864` Fp2-by-Fp multiply-adds for the `H` scan, `524,287` Fp2
multiplications for `eq(r)`, `16,777,212` for sumcheck folds, about 72 MiB
scratch, `1,496 B` framed, 44 full correlations per MAC tape, and error at
most `128/|Fp2|` for the union of both tape relations.
This term does not silently cover any additional ZeroOpen or MAC failure.
The rejected four-body composition's final census was locally closed at 24
sub plus 703 full correlations per tape, but remains unexecuted with the real
generator. The scaled dual-tape Rust prover/verifier and strict codec pass
mutation tests.

This closes the algebraic shape, not production integration. Security review
found that the scaled reference did **not** receive four jointly authenticated
openings: it authenticated one arithmetic limb per MAC tape, reconstructed
clear `Fp2` scalars and let the sparse verifier create public keys for them.
That path is rejected and the terminal join is a hard stop. Its
production-dimension verifier would still scan the 768-MiB expanded `H`. A four-thread CPU
scan is projected at `0.17--0.40 s` from the registered local rate with
`65--80%` confidence, but must be measured. The historical outer codec and
real-PCG privacy audit are locally green only for the rejected four-body
suffix. GPU component measurements remain valid, but the terminal
join now precedes GPU ownership and receives no protocol credit.

The owner-selected repair keeps the authentication tapes separate all the way
through the sparse relation. For tape `l`, define `m_l` from only that tape's
eight correction columns and `u_l=H m_l`. Each is still an extension-field
message and therefore needs two base-field WHIR limb bodies. This gives four
bodies per tape, eight total. The two arithmetic limb base identities for one
object and tape are normalized and joined against the authenticated
extension-field target using the already implemented joint-bridge algebra;
the certificate still carries one terminal tag per object and tape. Opposite
errors cannot cancel because neither sparse equation adds the two tapes.

This repair doubles the claimless body bytes to `9,039,328 B`. The selected
conservative transition codec carries up to eight authenticated `A` openings,
giving `28,692,111 B` total and `129,889,808 B` setup plus first. It consumes
four rather than two WHIR masks per tape, moving the projected full-correlation
census from 703 to 705. The sparse proof remains 1,496 bytes, but its two round
streams now prove distinct `u_l=H m_l` relations. Screen v16 gives
`78.019023342845...` bits against the owner-revised `78.00`-bit gate while
keeping every phase at 105 bits. These remain analytic projections. The
statement digest, output-link coefficients, codecs and mutation tests must
close before implementation credit. The four-body cross-tape conversion is
rejected for this milestone.

The C6.3-specific contribution is the append-aligned 16-column reshape, the
typed correction-row commitment and batching around Volta's accepted
predecessor and already authenticated Transformer outputs. Both constrained
proximity relations adapt the existing Hiding-WHIR engine rather than adding a
second PCS.

The closure must establish all of the following in the same certificate:

1. the systematic correction root has the accepted old prefix, the exact
   authenticated append correction and canonical virtual zeros;
2. the proposed sketch is the accepted sketch plus `H J(delta_D')`;
3. the persistent `A`, fresh `w_l` and all eight limb proof views are valid
   under the dedicated C6.3 Hiding-WHIR profile, including each `y_l` row
   linkage;
4. both sparse `H` relations link the systematic and sketch sides;
5. every cache value used by the Transformer is reconstructed from the same
   correction and correlation, on both tapes;
6. the successor head, epoch and length are exactly the objects verified and
   later promoted.

There is no cross-response accumulator, deferred settlement or later repair.
If one of these statements is absent, the result is component evidence only.

A more aggressive Volta-only shortcut exists: if the verifier persisted every
corrected per-cell MAC key, a random linear check against Hiding-WHIR could
replace Bolt's code switch and sparse lookup. C6.2 does not persist that log,
and sending the two correction tapes for `0 -> 150` costs `44,236,800 B`, over
the complete certificate gate before any proof bytes. This shortcut is not the
R1 default. A one-tape state log is considered only if a new theorem proves it
preserves the two-tape statement.

### 3.4 Privacy instantiation is a separate hard gate

Plain Bolt exposes systematic rows and explicitly does not provide hiding.
C6.3's formal outer theorem makes those rows admissible because they contain
only one-time corrections. It may not serialize a clear K/V row, clear cache
evaluation, mask value, or raw prover MAC tag. A correction allocation is safe
only when its PCG domain is unique; repeated reads of the same accepted version
are allowed, but reuse for a changed value is forbidden.

The randomized initial oracle and hidden targets remain mandatory protocol
components, but model privacy no longer rests on an unsupported claim that
Hiding-WHIR conceals deterministic `A` openings. Production must instantiate
the Lean post-processing premise: every tagless field must be derived only
from the accepted correction state and public/fresh inputs, and every terminal
tag must use the designated simulator. The typed codec, correlation census,
whole-transcript order and local implementation audit are closed by the
resident coordinator and complete verifier. A full real/AES-PCG execution and
independent review remain open.

A Merkle root built over raw K/V plus masked query answers is rejected: the
masked answer is not linked to the raw leaf without revealing that leaf. A
Merkle root over corrections is admissible because the leaf itself is the
one-time-masked object, but its link to both VOLE tapes and the Hiding-WHIR
sketch still requires the full R1 proof and codec.

### 3.5 Minimum transcript order

The candidate is rejected if an implementation changes this dependency order:

1. bind version, parameters, `H` seed/digest, connection/attempt, workload,
   accepted head, source schedule, epoch/length and append census;
2. commit the successor systematic root `R_D`, encoded-sketch tensor root
   `R_A`, their descriptors and the evaluation-target decomposition;
3. derive one typed row-combination challenge `rho in Fp2^16`, construct
   both `m_l/u_l/w_l/y_l` groups, and bind the transient descriptors plus the eight fresh
   randomized initial roots required by the limb cores;
4. derive the sorted unique systematic spot set `q_X`, open complete `D'`
   rows, verify its deduplicated Merkle frontier and compute both tape-restricted
   row products `m_l[row]`; under the current screen `q_X=4,420`;
5. include those row/value pairs in the sparse-`H` statement, derive its
   compression challenge only after that header, and execute both tape
   relations. This yields the D22/D19 terminal points for each `m_l/u_l`;
6. open the eight already committed limb cores at those terminal points and
   finish them sequentially. The four `y_l` cores independently derive and
   open their projected `A` sets; under the current screen each `q_A=245`.
   In every round the message or next fold root precedes its challenge. Each
   proof-of-work search uses role/phase/snapshot-bound `H_pow`; only its
   accepted witness enters the separate `H_fs` transcript;
7. verify the `A -> y` initial-row equation, the fused `D' -> m` systematic
   spots and all ordinary WHIR query paths. `q_X` and `q_A` remain distinct
   typed sets;
8. only after both tapes' paths, sparse relation and output link are fixed,
   derive a separate terminal challenge and zero check for each tape;
9. bind the canonical codec digest, verify everything, then atomically promote
   the successor.

One tuple root is absorbed once. The common row mix is distinct from the two
MAC-tape challenges. MAC multipliers and terminal checks remain
domain-separated; combining them into one MAC equation is forbidden.

## 4. What must also change beyond dense encoding

The measured precommit was the largest blocker, but removing it alone does not
prove a sub-20-second result. C6.3 also requires:

1. **accepted predecessor reuse:** reuse the accepted correction and sketch
   roots instead of reconstructing them;
2. **a dedicated C6.3 Hiding-WHIR lane:** add a new parameter digest for the
   correction sketch, separate the 105-bit query target from fold
   proof-of-work, and encode the fixed-count witnesses under a new magic;
   do not change or rebenchmark GW4's D27/D28 chains;
3. **one batched consistency envelope:** use persistent `A=C^16(H D')`, fresh
   `w_l=C(m_l)` and eight sequential base-field WHIR cores over decoded D22/D19
   limb messages with pre-encoded `w_l/y_l` initial oracles; for the `y_l` cores,
   authenticate projected `A` rows and constrain the randomized-row difference
   to `Enc(0,zeta)` inside the first round; independent per-column closures and
   double encoding are forbidden;
4. **a compact cache arithmetic backend:** keep the existing authenticated
   round shell and source aggregation, but derive coefficients analytically;
   do not allocate the four D23 coefficient/witness vectors;
5. **a compact output-link backend:** replace the persisted cache PCS join
   after pending claims are assembled; the earlier GW4 chains stay unchanged;
6. **D23 residual measurement:** the separate delta-residual cohort was outside
   the completed
   precommit probe and may become the next bottleneck;
7. **direct GPU ownership:** source slabs, `H delta_D`, encoded `A`, roots,
   transient `w_l`, decoded `m_l/u_l`, fresh randomized oracles and opening work remain device-resident, with only
   the final codec copied out; GW4 transient owners are released before the
   eight sequential WHIR limb cores begin;
8. **reusable fixed owners:** the current one-certificate runner consumes
   fixed coefficient owners with `take()`; a two-response runner must borrow
   the immutable owners while keeping response state separate, and the
   verifier must retain derivable correlation owners for prior birth epochs;
9. **exact byte and verifier accounting:** the 30 MB screen includes every
   root, path, correction, transcript field and outer frame.

The integration point is the persisted cache PCS/output-link call after the
pending claims are fixed. `assemble_source_aggregates` remains unchanged. The
new backend returns the same authenticated receipt expected by the native
coordinator. This is the smallest replacement boundary found in the source
trace.

If retained D23 work keeps the measured projection above 15 seconds, the next
minimal step is to interleave its residual table into the same sketch and the
same response-local closure. It is not migrated speculatively before a timer
shows that need.

## 5. Analytic budgets, with no transferred credit

The historical additive screen that selected Bolt-min was:

```text
6.84 MB fixed remainder + 8 * 2.09 MB bodies = 23.56 MB
```

This is below the experimental 30 MB ceiling by 6.44 MB. With measured C6.2
setup `101,197,617 B`, the same decimal-byte screen gives `124,757,617 B` for
setup plus first certificate, below 172 MB. These are selection estimates,
not C6.3 byte results: Bolt measured another field, hardware, hash, codec and
non-hiding statement, and its non-amortized closure time was estimated rather
than implemented.

Source review corrects the interpretation of that formula: `2.09 MB` is the
paper's complete Bolt-min evaluation proof at its parameters, not one body per
column. Therefore `23.56 MB` is neither an upper nor a lower bound for C6.3.
It remains only a `credit:false` selection screen. C6.3 interleaves K/V and
both tapes behind `R_D`, commits `A=C^16(H D')` before `rho`, constructs fresh
`w_l=C(m_l)`, and maps the limbs of each `w_l/y_l` pair to eight sequential
base-field WHIR cores through decoded D22/D19 messages and pre-encoded initial
oracles. The analytic profile sizes are counted above; executable codec credit
still requires the adapter and proof-of-work witnesses.

The reproduced YHC calculation changes the field-size input from Bolt's
`2^32` to Goldilocks `P` and gives root `0.0497943788349776`, not `0.096`.
At the selected 105-bit target, `gamma=0.049` requires `q_X=4,420` rows.
The canonical D12-inside-D10 correction artifact is at most `2,042,062 B`,
including metadata and both multiproof levels. The persistent `A` root is
D19-by-32 physically. One projected opening at `q_A=245` costs `149,316 B`.
The selected continuation codec serializes one predecessor and one successor
opening for each of four D19 bodies. Eight openings plus four presence flags
cost at most `1,194,532 B`. Cross-body or cross-tape query sharing is not
counted.

The eight D22/D19 bodies add `9,039,328 B`. The paired-opening analytic lower
screen has `11,231,314 B` public bulk and a `27,646,815-B` certificate, but it
assumes query sharing that has no selected codec. The conservative layout
serializes all eight transition openings and four 20-byte projected frames,
giving `12,276,610 B` public bulk. The complete designated tail is
`2,704,637 B`. The selected complete certificate is therefore `28,692,111 B`,
leaving `1,307,889 B` below the experimental limit. Replacing the actual tail
with its independent `4,499,999-B` maximum would give `30,487,473 B`; that is
not composable with the full public-bulk maximum. Setup plus first is
`129,889,808 B`. These are exact analytic maxima for screen v16, not
serialized proof credit.

The selected screen unions all 120 phase events at 105 bits. It separately
charges the systematic spot event, `4,420/|Fp2|` spot fusion, two sparse
relations totaling `128/|Fp2|`, four terminal ZeroOpen failures, inherited
C6.1 terms, exact finite setup distance and a `2^-128` BLAKE3-XOF
computational assumption. Under the inherited `2^20` Fiat--Shamir query cap
the result is `78.019023342845... bits`, above the owner-revised `78.00`-bit
target by about `0.0190` bits. Any newly discovered error term reopens this
screen rather than being absorbed by the margin.

This calculation requires two independent modeled oracles:
`H_pow(profile, role, phase, snapshot, witness)` for grinding and
`H_fs(transcript, accepted_witness)` for challenges. A domain label on one
challenger is insufficient. The Rust reference now implements this separation
with keyed BLAKE3 for `H_pow`; only a valid witness is absorbed by the ordinary
Fiat--Shamir challenger. Changed role, transcript, phase or witness rejects,
and a differential test proves grinding consumes no Fiat--Shamir samples.
Expected grinding is `15,990,784` hashes; each phase stops after `2^26`
candidates. Treating grinding as Fiat--Shamir queries remains a rejected
monolithic model and fails the gate. The selected result is a computational
random-oracle screen, not a standard-model proof or empirical credit.

VRAM requires sequencing, not eviction of `H`. The ABI43 owner stores one
`67,108,864-B` D19-by-16 sparse sketch per state; WHIR then splits each column
into two zero-padded D19 NTT batches, so a single D20 NTT is explicitly
forbidden. Accepted and proposed `A` each use `134,217,728 B` of rows plus a
`33,554,400-B` full hash tree. Exact live correction rows plus both `S` and
both `A` owners give a `607,387,584-B` state proxy. Forced overlap of measured GW4,
the 768-MiB sparse map, that state and one complete D23/Fp2 lane guard is
`46,088,197,900 B`, or `269,621,036 B` above the A100 guard. The lane guard
already contains its D23 codeword; it is not counted twice. The transcript
requires all eight initial roots before the sparse point and exact source
link. Their initial codewords/evaluation tables retain `637,534,208 B` across
GW4. The resulting conservative linked-GW4 proxy is `41,196,590,892 B`,
leaving `4,621,985,972 B` below the device guard. After GW4 releases its
transient owners, the eight base WHIR cores execute one at a time with one
active workspace; including all still-pending initial owners gives a
`20,464,271,264-B` C6.3 proxy. These are `credit:false`: separate backend
accounting, allocator overhead and the complete-tree convention require the
A100 supervisor to confirm the real high-water. Spilling a codeword to host
is forbidden.

The two raw genesis correction tapes alone are `44,236,800 B`; therefore they
stay behind the systematic root and only queried rows, distinct deduplicated
frontiers for `D'` and `A`, and batched relations enter the certificate.
Hiding randomness, typed
framing and the Volta `H` closure may move the final size in either direction.

The executable screen is `scripts/budget_c63_authenticated_sketch.py` (schema
v16). Version 16 selects eight bodies, charges both predecessor and successor
`A` openings for every D19 body, counts 120 phase events and keeps the
owner-set complete soundness gate at 78.00 bits; every per-phase profile
remains 105 bits. Canonical correction-row/envelope version-2 and
public-argument/final-certificate version-3 codecs now exist locally. The exact
output link passes over canonical live-cell
inputs; resident source wiring is locally green and the complete CPU-verifier
entry compiles with green constituent and ordering checks. Its first complete
serialized-candidate execution remains part of the A100 run.
The historical exact byte, setup,
`pi_final` and computational soundness screens are evaluated but remain
`credit:false`; prover time, verifier time, RAM and VRAM stay unevaluated until
the real A100 artifact exists.

## 6. Ordered local implementation

Work advances in the following order. A failed check returns to the smallest
preceding design step; it does not silently relax a statement.

### C63-R0 — compact semantic reference

- add a C6.3-only compact K/V owner that reuses the C6 coordinate map;
- verify exact append order/count, preserved prefix and virtual zeros;
- compare it with the existing dense witness on scaled fixtures;
- keep all cryptographic fields absent so a semantic test cannot be mistaken
  for commitment evidence.

### C63-R1 — exact authenticated relation

- retain the green sparse reference identities
  `H(X + delta) = HX + H delta` and
  `<q, HX> = <H^T q, X>` as algebra evidence only;
- freeze the Goldilocks `H`, correction-leaf order, append-root rule, the
  105-bit-per-phase C6.3 Hiding-WHIR profile, transcript order and canonical
  codec; model proof-of-work and Fiat--Shamir as two independently
  domain-separated oracles with separate counters, or stop;
- prove that the tagless Bolt/WHIR bulk is independent of both secret MAC
  multipliers and that moving it to the public-argument partition preserves
  the complete Fiat-Shamir statement and every byte count;
- prove systematic-correction-plus-sketch binding, two-tape VOLE linkage,
  tensor target decomposition, sparse-code consistency, delta linkage and
  complete transcript privacy;
- replace the scaled sparse-`H` verifier's full inputs with separate terminal
  D22/D19 `m_l/u_l` openings while preserving its 1,496-B codec and two tapes;
- replace the honest cached-base check with a projected initial MMCS opening
  and the first-round mask-only equation; include an attack test where plain
  WHIR accepts a substituted base and the linked C6.3 verifier rejects it;
- recompute the complete soundness union for Goldilocks/Fp2;
- reproduce the green 188-bit rational distance screen independently and bind
  it to the production version of the exact-ensemble D22 setup sampler;
- add adversarial mutations for prefix, append ordinal/value, zero tail,
  correction domain/tape, `H delta_D'`, encoded-`A` row/root, fresh `w_l`,
  every `y_l` linkage, both child roots, epoch/length and framing.

Changing the protocol statement opens additive Lean work. Frozen historical
M1--M11 files are not edited; C6.3 lemmas must cover the new relation before a
production claim.

The scaled CPU reference executes four real Hiding-WHIR lanes (two D22 `m`
limbs and two D19 `u` limbs), checks one designated terminal MAC per lane and
reconstructs two clear `Fp2` openings. It does not cryptographically link
those reconstructed values to the two-tape sparse proof and therefore does
not close the terminal-opening integration step. The same test uses the
linked `A -> y` path for both D19 limbs and derives its fused systematic spots
from verified D12-inside-D10 correction multiproofs. All four actual proofs
round-trip through strict codecs before verification; the two D19 artifacts
contain exactly one linked `A` opening each. Production-depth synthetic codecs
include every registered PoW witness. This remains `credit:false`: the fixture
is scaled, uses mock correlations, serializes the public component but not one
complete final certificate, and is not composed with the GPU owner. The
owner-selected eight-body tape-separated repair above supersedes this
four-body terminal composition.

The selected scaled reference now executes eight real Hiding-WHIR bodies,
keeps both authentication tapes separate, joins each limb pair into one
authenticated extension-field target and passes those same hidden keys into
the two-stream sparse proof. Its D22 terminal keys come from the exact
canonical-cell `D=X-R` output functional, and the sparse verifier derives that
functional's point before replaying the eight WHIR bodies. Each limb closure
is normalized before the two limbs are recombined; the verifier is never
given a limb target key. Once `m_l` is fixed by the output link, the sparse
terminal equation determines the only compatible `u_l` key, which the
projected bodies must match. Its nine-component public codec round-trips and
mutations of the public payload, a tape key, correction value, cell order,
sparse terminal or final target tag fail. This closes the local
output/terminal verifier seam only: correlations are deterministic test
fixtures, dimensions are scaled, and concrete transcript derivation, the
production coordinator and complete inherited certificate verifier remain
open.

### C63-G1 — GPU component boundary

- consume the live K/V slabs without a dense host state;
- compute/update the correction root, raw `S` and encoded tensor `A` on GPU;
- use a C6.3-only fresh Hiding-WHIR owner and resident initial-message hook;
- retain accepted and proposed `A` until verification, and keep both fresh
  `w_l` plus the `y_l` proof views device-resident;
- serialize one complete candidate and run the CPU verifier;
- separately time cache update, base code, hashing, closure, D23, GW4,
  synchronization and serialization.

Admission requires cache binding below `9.640596167 s` when combined with the
unchanged GW4/reserve allocation, or an exact total below 20 seconds if work is
shared between them. Component results remain `credit:false`.

The first local G1 boundary now compiles on the Rust side. It owns the D22-by-16
live correction prefix, D19-by-16 `S`, D19-by-32 `A` and its device Merkle
tree; a proposal copies its accepted predecessor without mutating it and only
new D12 tile roots are rebuilt. Setup coefficients are uploaded in bounded
chunks; the 256-MiB permutation is currently one device upload. `H` remains
provider-fixed. Correction leaves use the versioned 216-byte `CR3`
frame so the existing GPU BLAKE3 tree hashes exactly the same bytes as the CPU
reference. ABI43 now compiles under CUDA 12.8 and both genesis and asymmetric
successor match the full CPU oracle on one A100.

The historical clean `178c37e` trace proved that the response-local work was
not a pure coordinator call and stopped before E2E; its record
`c63-g2-2026-08-24-178c37e.json` carries no timing or protocol credit. ABI44
later closed resident initial-message ownership, combined-tape projection and
canonical pruned `A` openings for one D19 lane. Tape-separated projection,
the revised terminal join and exact authenticated output functional then
passed locally, while resident source wiring and complete verification still
remained open at that checkpoint. The current local coordinator closes those
two seams: it consumes the inference-owned paired source, releases terminal
masks only after the existing global link, and exposes one complete CPU
verifier entry. This is compiled and mutation-tested code, not a measured
full certificate.

Checkpoint `215d4f4` also removes two caller-selected setup values before the
real run. The profile digest is derived from the exact sampled production
descriptor and fixed v16 domain; genesis derives the all-zero encoded-sketch
root from the physical D19-by-32 Merkle geometry. The direct append packer
reads the inference-owned correction audit in the source schedule, checks
`X=R+D` for every appended cell and emits exactly the kind/layer/position/
channel order consumed by the existing CUDA update. Focused local tests pass.
The production setup expansion, GPU zero-root match and asymmetric owner
differential remain terminal before E2E.

The first hardware check is the single ignored integration test
`volta-pcs/tests/c63_gpu_owner.rs`. It uses the production D22-to-D19 sampler,
one full GPT-2 token and one different successor token, then compares every
compact correction, every `S` and `A` field and both roots with an independently
built CPU result. It also requires prefix preservation, cleanup and native row,
NTT and Merkle counters. A scaled geometry cannot replace this test because
the ABI is intentionally fixed to the production layout. The clean G1 record
measures `7,316,008 ns` for genesis and `4,270,320 ns` for successor, excluding
setup, CPU-oracle construction and validation downloads; these are component
walls, not proof walls.

Here **complete the resident proof/verifier link** means only the narrow
production adapter at the existing cache-PCS/output-link join. It must borrow
the accepted/proposed device owners, derive `rho` after both roots, feed the
owner-selected authenticated lanes and sparse closure, assemble the revised
public argument, designated envelope and final certificate codecs, run the
CPU verifier, and promote the proposal only on acceptance. Large `D'`, `S`,
`A`, `m/u/w/y` owners never cross to host; only roots, authenticated queried
rows and final certificate bytes do.

After the ABI43 differential, this adapter has **no aggregate pod timebox**.
Focused component work continues while resource controls hold and each run can
produce useful evidence. Cold compilation and fixed setup remain separately
measured. The 150-second mark is a nonterminal supervisor event; only the
security and imminent-resource hard stops remain. The implementation reuses
the existing cached-fixed-base seam and
normalized joint-bridge algebra; no new proof engine, abstraction or kernel is
admitted unless a focused differential proves it necessary. A
dense-host or CPU-prover fallback remains forbidden. ABI44 closes the admitted
resident projection, initial-message and `A`-opening extension for one D19 lane.
Clean `377c03a` also measures the production-size resident sparse relation at
0.901--0.964 s prover, 0.926--0.971 s ordinary-CPU verifier, exactly 1,496 B
and 1,626,938,920 B combined device peak. Building the public `H` view takes
1.448--1.452 s and is model-fixed preprocessing. These are `credit:false`
component results. Clean `980f076` additionally opens sampled correction rows
from the resident owner and matches the independent CPU encoding byte for byte
without downloading a dense table. Clean `831d234` then measures
transcript-derived production sampling and 4,420-row spot fusion on a
150-token state: opening plus immediate CPU check is 0.399--0.401 s,
260,614 B, and the fused sparse proof remains 1,496 B. The resident
eight-body prepare/finish driver, exact source link and complete verifier now
pass 31 focused local tests; the CUDA-feature path compiles. The production
wrapper admission also accepts the two-cohort C6.3 profile. A real candidate,
measured cleanup and promotion still require the registered A100 run.

#### Pod admission and resource controls

The pod is admitted for component work only when preflight records one
exclusive A100 with 80 GB, `sm_80`, working `nvcc`, no competing device
process, at least 96 GiB of effective cgroup RAM, and at least 200 GiB free on
the persistent filesystem. Setup, weights, work, session and canonical
`rust/target` directories must use that filesystem; heavy data may not use
`/tmp`. Inodes, cgroup limits, driver/CUDA versions and the exact clean Git SHA
are recorded. CUDA output is `rust/target/cuda/libvolta_cuda_backend.so`; no
top-level or experiment-specific build target is created. The component
differential enables exactly `cuda,c6-trace,c61-p3-authenticated-reference`;
omitting `c6-trace` is a compile error, not a protocol failure.

Before official E2E, all of these checks are terminal:

1. the existing one-token CPU/GPU differential passes;
2. the same harness passes one asymmetric successor append, checking preserved
   prefix, new position, new epoch, `S`, `A` and both roots;
3. the fixed public setup seed
   `deda54f405265cd5f57b0baec79fbc6fcd1e5149f68937e28bb0737338c5bdea`
   is expanded once and its digest is bound by the setup manifest; the
   provider gets no alternative seed or retry;
4. one top-level C6.3 verifier, not certificate structural decoding alone,
   accepts the candidate produced by the resident coordinator;
5. a source/runtime sentinel proves the legacy dense cache-precommit path was
   never entered;
6. the measured backend high-water respects `45,818,576,864 B`, GW4 transient
   owners are released before C6.3 lanes, and provider/verifier thread counts
   are fixed at eight/four;
7. discarding a successful proposal returns active resident device allocation
   to the setup-only baseline; any cleanup mismatch is terminal.

A one-second supervisor records process resident/high-water memory, cgroup
events, device memory, process I/O, free bytes/inodes and result-tree growth.
It begins E2E only with at least 120 GiB still free, stops before allocation if
free space falls below 100 GiB or effective RAM has less than a 16-GiB reserve,
and treats unexpected run-artifact growth above 10 GiB as evidence that the
dense path returned. The 20- and 150-second proof marks use a monotonic clock
and emit nonterminal observations. A hard kill is reserved for imminent
resource exhaustion and still cannot promote state; an incomplete or rejected
proof burns its correlation range and leaves the predecessor unpromoted.

The cold and immediate warm records are staged in one create-new session
directory outside the Git checkout. Both record the same clean source SHA and
`git_dirty:false`; neither response makes the checkout dirty before the next
one starts. Small JSON dispositions are written to a temporary same-filesystem
name, synchronized, then renamed atomically. Only after both responses stop are
their immutable JSON/log digests copied under `benchmarks/results/` and
committed. Generated setup, weights and `rust/target` stay pod-local and are
removed after evidence export; result files are never included in cleanup.

On the historical first pod, `/workspace` failed the admission floor and the
root overlay was used. Every new pod repeats that filesystem preflight; it may
not inherit the old placement decision. All source, build, generated and
session paths stay on the one newly admitted filesystem. Pod-local data is not
credited as surviving pod destruction, so clean source checkpoints and small
evidence are pushed after each boundary. Losing disposable setup or weights
requires a fresh run and never permits a selective protocol retry.

### C63-E2E2 — two real responses

Only after local tests, exact budgets, clean source, artifact checks and a new
owner GO may one A100 execute the first experiment.

1. Generate/install the complete 17-profile setup if absent, then run real
   `0 -> 150`. Record every cold clock defined in Section 0.1 so provider
   model preprocessing is not conflated with inference or certificate
   generation. `cold_certificate_prover` is also the response-specific prover
   gate clock; 20 and 150 seconds are both recorded, nonterminal marks.
2. Without restarting, warming artificially or replacing state, promote the
   first accepted successor and run real `150 -> 200`. Record the complete
   warm request-to-accept wall plus provider proof and verifier subclocks.

The run also emits diagnostic-only component counters intended to guide the
next optimization without changing the official clocks:

- appended values, scheduled sparse edges, sparse-update time and effective
  edges per second;
- accepted-state copy time/bytes, all 32 base-code transforms, full encoded
  tree time, changed-input fraction and bytes that an incremental update could
  avoid;
- new versus reused correction-tree leaves, device-to-device/host transfers,
  synchronization calls and wall time;
- proof-of-work hashes per lane, D23 residual time, GW4 time, serialization
  time, CPU verifier subclocks and memory high-water by phase;
- process read/write bytes, result-directory growth and free disk before and
  after each phase.

The official run does not count per-atomic retry instrumentation because that
would perturb the timing. Contention is inferred from the public sparse-map
bucket distribution, scheduled edges and measured kernel throughput; a
separate pre-E2E component diagnostic may use a hardware profiler.

Both certificates use the real/AES PCG and the same connection with disjoint
correlation ranges. Compilation, repository synchronization and weight/setup
transfer are preparation, not deployment or response time. No mutation set,
four burns, 17-response loop or retry runs in this experiment. Security
rejection, invalid state promotion or imminent resource exhaustion stops and
records a create-new disposition. Byte, 20/150-second and verifier-RSS misses
continue through serialization and verification. Source moves through Git,
not SCP; weights and generated setup stay uncommitted on the pod, while the
small append-only JSON record returns through Git. A measurement miss never
replaces a complete artifact with a no-certificate disposition.

## 7. Current decision and confidence

The direction is **the append-aligned `t=16` Bolt sparse precode over Volta's
masked correction state, adapted inside WHIR as two tape-separated projections
of one deterministic pre-`rho` `A=C^16(H D')` tensor, eight fresh randomized
D22/D19 WHIR bodies over already encoded `w_l/y_l` oracles, and one two-stream
sparse inner-product closure; tagless bulk stays public and only the designated
tail enters `pi_final`**. It is not a Bolt crate port, a second PCS, a raw-K/V
Merkle tree or a sketch-only commitment.

- Probability that it removes the measured cache-precommit bottleneck:
  **88--96%**.
- Probability that the one-`rho`, two-tensor Bolt-to-WHIR algebra survives
  independent review before privacy and full error accounting: **90--96%**.
- Probability that the first complete GPT-2 certificate fits 30 MB:
  **88--95%** because screen v16 bounds the conservative eight-transition-
  opening codec at `28,692,111 B`; real serialization still must reproduce it.
- Probability that the new separation theorem and two-cohort codec preserve
  `pi_final <4.5 MB`: **94--98%**; the exact local projection is `2,704,637 B`.
- Probability that the complete warm prover reaches `<20 s` on one A100:
  **50--70%**. The resident path is locally complete but has not produced one
  full-size certificate, so this remains an engineering estimate.
- Probability that the four-thread verifier stays below 5 seconds:
  **70--85%**, dominated by the unmeasured 768-MiB `H` scan and WHIR bodies.
- Probability that an independent review accepts the finite Goldilocks
  distance bound without changing the query count: **92--98%**.
- Probability that independent review accepts the 105-bit two-oracle soundness
  screen and the 128-bit BLAKE3-XOF assumption without a profile change:
  **55--70%**. The computed result is `78.019023342845... bits` against the
  owner-revised `78.00`-bit gate, leaving almost no room for an omitted term.
- Probability that eight literal non-amortized Bolt closures reach `<20 s`:
  **below 10%**.

The largest uncertainties are independent review of the two-oracle model,
the pre-encoded resident WHIR adapter, unmeasured encoded-`A` update, 105-bit
grinding cost and D23 cohort. The projective/monomial-basis
sumcheck optimization is deferred until a timer shows that the sparse closure
matters; its present wire cost is only 1,496 B. A D23 merge likewise follows
only a measured bottleneck.

The lazier fallback is one direct compact Hiding-WHIR commitment to `D`,
without sparse `H`. A scalar D26 diagnostic body currently screens at
`1,063,480 B`, but the production profile rejects D26, its prover owner is
consumed after one proof and its VRAM screen passes only under sequential
scheduling. It is retained as a control, not substituted for the
owner-selected Bolt-inside-WHIR contribution, and is considered only if the
exact sampler or a measured component timer blocks `t=16`.

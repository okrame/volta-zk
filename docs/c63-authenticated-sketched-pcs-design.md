# C6.3 Authenticated Sketched WHIR Design

Status: **R0 GREEN / R1 T16 + FINITE-N + SAMPLER + SPARSE-CLOSURE + HONEST PRE-ENCODED REFERENCES GREEN / VERIFIED INITIAL LINK + PARTITION + PRIVACY + SOUNDNESS HARD STOPS / NO POD / NO GATE CREDIT**

This document is the authority for C6.3. It replaces C6.2 only for new C6.3
work; C6.2 code, artifacts and dispositions remain immutable evidence. The
first target is GPT-2 on one A100. A later Gemma-class design must be derived
from measured scaling rather than assumed here.

## 0. Authority, objective and hard stop

The owner opens autonomous local design and implementation of an
Authenticated Sketched PCS. The objective is a complete response proof below
15 seconds on one A100 without moving work to another response and without
weakening the existing designated-verifier statement. The owner accepts a
complete certificate up to `30,000,000 B` for this experiment.

No design choice currently needs owner input. The minimum path is selected:

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

Local reference work is authorized. No provider or pod may be contacted until
a new endpoint and explicit experiment GO are supplied. A failure to prove
both full binding and privacy is a hard stop: a small linear fingerprint by
itself is not an admissible replacement for the PCS.

## 0.1 Gates and clock definitions

The numerical gates are engineering targets, not permission to weaken a
cryptographic invariant. Only the certificate ceiling changes for the first
C6.3 experiment.

| Gate | C6.3 requirement |
|---|---:|
| public/connection setup | `<150,000,000 B` |
| setup plus first certificate | `<172,000,000 B` |
| complete certificate | `<=30,000,000 B` |
| `pi_final` partition | `<4,500,000 B` |
| response-specific prover on one A100 | `<15.000 s` |
| official four-thread CPU verifier | `<5.000 s` |
| verifier additional RSS | `<=8,000,000,000 B` |
| A100 device high-water guard | `<=45,818,576,864 B` |
| complete per-certificate soundness | `>=78.80929487391641 bits` |

`response_specific_prover` starts after setup, model weights and fixed
provider tables are resident. It includes fresh proof work, real/AES PCG
consumption, all synchronization and serialization. It excludes model
inference, network time and the one-time fixed preload. The first cold run
also records those excluded phases so the real deployment cost remains
visible. A cold total is not compared with the 15-second gate.

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
3,536 / 3,789 / 4,041 / 4,294 / 4,378 rows for
84 / 90 / 96 / 102 / 104-bit sub-budgets.

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
with bias changes the distribution and needs a new proof. The production
sampler, non-grindable seed procedure and cryptographic randomness accounting
remain hard stops.

The scaled sampler reference now implements the exact socket construction:
one domain-separated BLAKE3-XOF stream drives descending Fisher--Yates with
unbiased rejection, another samples independent nonzero Goldilocks labels,
and the expanded source-major edge stream is hashed. It preserves parallel
edges. Four rejected draws fail closed; the union bounds are below `2^-126`
for the shuffle and at most `2^-102` for labels. Conditioned on success this
is the YHC distribution in the ideal-public-XOF model. A 32-byte public seed
cannot information-theoretically describe a uniform D26 permutation, so the
remaining hybrid term for a public BLAKE3 random tape is explicit and unknown.
The seed must be provider-independent and non-grindable.

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
front-runner is the `t=16` reshape with a provisional 104-bit profile. Its
counted `q_X=4,378` systematic opening is `1,943,300 B`. The two `y` limbs
share one projected D19 query set: `q_A=243` gives a counted `148,164-B`
D19-by-32 opening; independent limb sets are the conservative
`q_A=486`, `280,772-B` fallback. The paired-query adapter is not executable
yet, so neither value receives credit.

The intended adapter proves decoded `m` at D22 and `u` at D19 while supplying
already encoded `w=C(m)` and `y=C(u)` as initial oracles. Two 104-bit cores of
each type screen at `4,488,880 B`; ordinary WHIR over D23/D20 would encode
`w/y` again and is only a `4,822,680-B` fallback. Paired public bulk is
`6,580,344 B`. The `1,496-B` sparse closure enters the designated tail, giving
a projected `2,704,509-B` `pi_final` and `22,995,717-B` certificate before
outer framing. Charging the strict `pi_final` cap instead gives
`24,791,207 B`, leaving `5,208,793 B`.
Without paired query sharing, public bulk is `6,712,952 B` and the same strict
projection is `24,923,815 B`, still leaving `5,076,185 B`.

This remains `credit:false`. The existing codec forbids the required
proof-of-work. The cached-base API and an honest D19-by-32 CPU projection are
now executable, but the verifier-visible link from the accepted `A` root to
the randomized initial root is absent. The inherited `2^20` transcript-query
bound also omits grinding. Known terms give
`81.0623977038 bits` only under an unproved one-error-per-core model. Unioning
just the 60 proof-of-work phase events gives `78.0076537129 bits` even before
grinding. Adding only the `3,997,696` expected trials instead gives
`78.7956111653 bits`, also below the gate, and an expectation is not a security
bound. C6.3 needs a whole-core theorem and a justified separated grinding
model; merely raising the registered profile does not repair a monolithic
query bound.

## 1. Evidence selecting this direction

C6.2 measured `275.113308912 s` in cache precommit. Dense encoding,
persistence, reread and tree hashing occupied about `249.51 s` (90.69%). It
created `78,383,153,576 B` of durable data and moved about 103 GB read plus
113 GB written. Keeping GW4 at `7.359403833 s` and its conservative 3-second
reserve leaves:

```text
15 - 7.359403833 - 3 = 4.640596167 seconds
```

for the complete cache binding. The current precommit therefore needs about a
`59.28x` reduction. Faster disk hashing cannot bridge that gap; dense cache
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

Define the post-`rho` messages without flattening the tensor:

```text
m[row] = sum(column=0..15) rho[column] * D'_e[row,column]
u[out] = sum(column=0..15) rho[column] * S_e[out,column] = H m
y[code_row] = sum(column=0..15) rho[column] * A_e[code_row,column] = C(u)
w = C(m)
```

`A_e` is fixed before `rho`; `y` is obtained only by opening complete rows of
that root and taking their `rho` combination. `w` is the fresh code switch
committed after `rho`. The constrained WHIR adapter proves the decoded
messages `m` and `u` against the already encoded initial oracles `w` and `y`;
it must not pass `w/y` as new messages to the ordinary encoder. The sparse
closure proves that the decoded messages obey `u=H m`.

The persistent `A` root is deterministic and external to Hiding-WHIR's fresh
randomness. It is never the randomized initial oracle `ZC(S;zeta)`: reusing
one mask across responses accumulates openings beyond the present privacy
argument, while refreshing it would change the accepted root. Each response
therefore builds four fresh randomized base-field initial roots, one per limb
core, and links them to deterministic `D'`, `A`, `w` and `y` inside the same
transcript.

The CPU reference now packs the physical `A` rows as
`[column][fold_position]`, projects both limbs of `A*rho`, and obtains exactly
the existing fixed-base encoding of the correspondingly projected decoded
message. Reusing that fixed base with two independent random tapes produces
different roots and two valid WHIR proofs. Mutating an authenticated `A` row
or the honest projection is rejected. This proves the layout and honest
linearity only; it is not yet a malicious-prover link.

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

Their authenticated contributions `t_0,t_1` are bound to the same Transformer
output relation, then the public target checks `m_target = t_0 + t_1`. The two
MAC equations are never added together because `Delta_0` and `Delta_1` are
independent secrets. R1 must prove that the output link, sparse `H` relation
and Hiding-WHIR targets compile these identical coefficients, including the
base-to-extension conversion.

The Rust reference executes the single 16-column pullback and checks that the
combined functional equals the sum of the two independently accumulated tape
contributions. This is executable algebra evidence, not yet the transcript,
privacy argument or binding theorem.

This removes the eight persistent D24/D25/D28 cache encodings, files and CPU
tree walks. It does not forbid the transient `w=C(m)` owner and the constrained
proof view `y=A*rho` required by the opening proof. They are derived after the
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
3. derive `m=D'*rho`, `u=S*rho`, the row view `y=A*rho` and the fresh code
   switch `w=C(m)`;
4. prove with the constrained Hiding-WHIR adapter that `w` and `y` are valid
   base-code words and that their decoded messages satisfy `u=H*m`;
5. resolve every output into the existing two-tape VOLE authentication rather
   than a clear cache evaluation.

The common `rho in Fp2^16` collapses each tensor row to one extension-field
symbol. The current WHIR implementation accepts one base-field polynomial and
encodes it internally. The minimum new adapter instead accepts both a decoded
message and an already encoded resident initial oracle. It runs four base
proof cores sequentially: two D22 limbs of `m` against `w`, and two D19 limbs
of `u` against `y`. The `w` limbs share one projected query set; the `y` limbs
share the persistent `A` rows and a paired D19 projected query set. They are
not four unrelated codewords. The target-decomposition lemma, paired MMCS and
resident adapter do not yet exist in the production codec. Base-field row
challenges are not assumed: one Goldilocks draw has only about 64 bits and
cannot alone cover the complete soundness target.

The existing `commit_c62_cached_fixed_base` seam already avoids double
encoding for the honest CPU path. The remaining adapter work is specifically
the verified initial link above: projected `A` rows enter the same initial
queries and the row difference is constrained to the encoding of fresh mask
coefficients. Calling the cached-base seam without that second equation is a
diagnostic only.

`m` has D22 `Fp2` symbols and `w=C(m)` has D23 symbols at rate `1/2`; `u` has
D19 `Fp2` symbols and `y=C(u)` has D20. The 104-bit analytic adapter screen
uses D22 intermediate rates `[1,2,3,3,4,5,6,7]` with at most 17 bits of
fold proof-of-work, and D19 rates `[1,2,3,4,5,6]` with at most 16 bits. The
respective body sizes are `1,279,752 B` and `964,688 B`, including native
proof-of-work witnesses; two limbs of each total `4,488,880 B`. An unmodified
WHIR call over D23/D20 would double-encode `w/y` and costs `4,822,680 B`; it is
a safe implementation fallback, not the selected statement. This geometry is
why `t=16`, rather than the smaller-row `t=4` or earlier `t=128`, is the
current byte/time front-runner.

| decoded core | round queries | final | mask | PoW witnesses | body |
|---|---|---:|---:|---:|---:|
| D22 `m` limb | 243, 243, 112, 73, 73, 54, 43, 36 | 31 | 254 | 17 | 1,279,752 B |
| D19 `u` limb | 243, 243, 112, 73, 54, 43 | 36 | 252 | 13 | 964,688 B |

The total work of applying `H` across all 16 columns
is `16 * 2^26 = 1,073,741,824` sparse field multiply-adds only for a fully
materialized logical matrix. C6.3 skips virtual zeros and updates the accepted
sketch from the append: genesis executes `88,473,600` multiply-adds and the
`150 -> 200` continuation executes `29,491,200`; it does not recompute the
accepted prefix. These are operation counts, not A100 timings.

WHIR replaces Bolt's two Reed-Solomon/Ligerito proximity layers and hides their
targets. It does not, by itself, replace the code switch, systematic spot
checks or the `H` consistency relation. The conservative body census is two
limbs of `w` and two limbs of `y`, implemented as four base-field WHIR cores.
This is the Bolt-inside-WHIR contribution; it is not a separate PCS.

The four WHIR cores do not by themselves prove `u = H m`. The selected
Volta-specific replacement for Bolt's non-amortized MulPerm is one
authenticated inner-product sumcheck. After a fresh `r in Fp2^19`, set
`q=eq(r)` and `a=H^T q`; prove
`<q,u>=<a,m>` in 22 degree-two rounds, then link the terminal `m` and `u`
values to the four WHIR cores. Its exact production-dimension census is
`67,108,864` Fp2-by-Fp multiply-adds for the `H` scan, `524,287` Fp2
multiplications for `eq(r)`, `16,777,212` for sumcheck folds, about 72 MiB
scratch, `1,496 B` framed, 44 full correlations per MAC tape, and error at
most `64/|Fp2|` for the tensor mix, random output point and sumcheck rounds.
This term does not silently cover any additional ZeroOpen or MAC failure;
their final C6.3 census is still open. The scaled dual-tape Rust
prover/verifier and strict codec pass mutation tests.

This closes the algebraic shape, not production integration. The current
reference verifier receives full `m/u`, scans the 768-MiB expanded `H`, and is
not connected to the WHIR terminal openings or state roots. A four-thread CPU
scan is projected at `0.17--0.40 s` from the registered local rate with
`65--80%` confidence, but must be measured. GPU ownership, privacy and the
root/WHIR terminal link remain hard stops and receive no timing or protocol
credit.

The C6.3-specific contribution is the append-aligned 16-column reshape, the
typed correction-row commitment and batching around Volta's accepted
predecessor and already authenticated Transformer outputs. Both constrained
proximity relations adapt the existing Hiding-WHIR engine rather than adding a
second PCS.

The closure must establish all of the following in the same certificate:

1. the systematic correction root has the accepted old prefix, the exact
   authenticated append correction and canonical virtual zeros;
2. the proposed sketch is the accepted sketch plus `H J(delta_D')`;
3. the persistent `A`, fresh `w` and all four limb proof views are valid under
   the dedicated C6.3 Hiding-WHIR profile, including `y=A*rho` row linkage;
4. the sparse `H` relation links the systematic and sketch sides;
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

### 3.4 Privacy is a separate hard gate

Plain Bolt exposes systematic rows and explicitly does not provide hiding.
C6.3 exposes only one-time corrections and their authentication paths; it may
not serialize a clear K/V row or clear cache evaluation. A correction is safe
only when its PCG domain is unique and never reused. Reusing a correction after
a cell changes is forbidden.

The complete Hiding-WHIR prover, not just its final MAC closure, protects the
sketch and transient opening oracles. Its randomized initial oracle and hidden
targets are mandatory. The proof must cover composition with the Fiat-Shamir
transcript; honest-verifier privacy of one component is not enough.

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
3. derive one typed row-combination challenge `rho in Fp2^16`;
4. bind the transient deterministic `w=C(D'*rho)` descriptor and the four
   fresh randomized initial roots required by the limb cores; no
   challenge-dependent fold root is anticipated here;
5. execute the sparse-`H` sumcheck and then the four limb cores sequentially.
   In every round the prover message or next fold root is absorbed before its
   challenge; all hidden targets follow the existing typed WHIR order. Each
   proof-of-work search uses a role/phase/snapshot-bound `H_pow`; only its
   accepted witness is absorbed once into the separate `H_fs` transcript;
6. only after all relevant round messages and fold roots are fixed, derive
   sorted unique final query sets: Bolt's systematic spot set `q_X`, the
   paired projected initial-oracle set `q_A` required by the two `y` cores,
   and the ordinary WHIR query sets. Under the 104-bit screen `q_X=4,378` and
   `q_A=243`; `q_X` and `q_A` are distinct typed sets;
7. open separate deduplicated frontiers for complete rows of `D'` at `q_X`
   and `A` at `q_A`, plus the initial roots required by the limb cores. Check
   their `rho` combinations against `m` and `y` and finish every core;
8. only after both tapes' paths, sparse relation and output link are fixed,
   derive a separate terminal challenge and zero check for each tape;
9. bind the canonical codec digest, verify everything, then atomically promote
   the successor.

One tuple root is absorbed once. The common row mix is distinct from the two
MAC-tape challenges. MAC multipliers and terminal checks remain
domain-separated; combining them into one MAC equation is forbidden.

## 4. What must also change beyond dense encoding

The measured precommit was the largest blocker, but removing it alone does not
prove a sub-15-second result. C6.3 also requires:

1. **accepted predecessor reuse:** reuse the accepted correction and sketch
   roots instead of reconstructing them;
2. **a dedicated C6.3 Hiding-WHIR lane:** add a new parameter digest for the
   correction sketch, separate the 104-bit query target from fold
   proof-of-work, and encode the fixed-count witnesses under a new magic;
   do not change or rebenchmark GW4's D27/D28 chains;
3. **one batched consistency envelope:** use persistent `A=C^16(H D')`, fresh
   `w=C(D'*rho)` and four sequential base-field WHIR cores over decoded D22/D19
   limb messages with pre-encoded `w/y` initial oracles; for the `y` cores,
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
   transient `w`, decoded `m/u`, fresh randomized oracles and opening work remain device-resident, with only
   the final codec copied out; GW4 transient owners are released before the
   four sequential WHIR limb cores begin;
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
`w=C(D'*rho)`, and maps the limbs of `w` and `y=A*rho` to four sequential
base-field WHIR cores through decoded D22/D19 messages and pre-encoded initial
oracles. The analytic profile sizes are counted above; executable codec credit
still requires the adapter and proof-of-work witnesses.

The reproduced YHC calculation changes the field-size input from Bolt's
`2^32` to Goldilocks `P` and gives root `0.0497943788349776`, not `0.096`.
At the provisional 104-bit target, `gamma=0.049` requires `q_X=4,378` rows.
The selected D22-by-16 systematic opening is `1,943,300 B`, including its
count. The persistent `A` root is D19-by-32 physically. A paired projected
MMCS lets its two limbs share `q_A=243` and costs `148,164 B`; two independent
sets cost `280,772 B` at `q_A=486`. The latter is the fallback if path sharing
does not survive the executable adapter.

The four D22/D19 bodies add `4,488,880 B`, so paired public bulk is
`6,580,344 B`. The sparse closure is MAC-dependent and belongs in `pi_final`:
`2,703,013 + 1,496 = 2,704,509 B`, leaving `1,795,490 B` under the strict
partition. Using that projected tail gives a `22,995,717-B` certificate and
`124,193,414 B` for the measured setup floor plus first certificate. Replacing
the projected tail with the strict `4,499,999-B` cap gives `24,791,207 B` and
`5,208,793 B` of certificate headroom. The new outer frame and any tensor-link
message not already in the bodies or closure remain uncounted. A codec and
separation theorem, not this arithmetic, decide the gates.

Paired queries are an optimization, not a certificate-size dependency. Two
independent 243-query limb sets have union at most 486; the maximum-frontier
screen then gives `6,712,952 B` public bulk, `23,128,325 B` with the projected
tail, or `24,923,815 B` under the strict `pi_final` cap. The last case still
has `5,076,185 B` of headroom before outer framing.

The smallest linked implementation may serialize the two `A` multiproofs
separately before an outer union driver exists. That deliberately lazier
fallback costs `296,328 B` for the two counted `A` openings, giving
`6,728,508 B` public bulk, `23,143,881 B` with the projected tail, or
`24,939,371 B` under the strict `pi_final` cap. It still leaves `5,060,629 B`
before outer framing. All three layouts remain analytic and `credit:false`.

The optimistic 104-bit union has `81.0623977038` bits under the inherited
`2^20` transcript-query bound, but assumes one 104-bit error event per core.
The current configuration has at least 60 proof-of-work phase events; unioning
only those gives `78.0076537129 bits`, so a whole-core theorem is a separate
hard stop. The profiles also introduce about `3,997,696` expected grinding
trials. Adding that expectation gives `Q=5,046,272`, while the exact maximum
compatible with the gate is `4,998,635`, and yields `78.7956111653 bits`.
Expected work is not a worst-case query bound. The proof-of-work hash must
either be separated from the
Fiat--Shamir/extractor oracle with a proof, or the profile and a fail-closed
trial cap must be rederived together. Raising the target alone makes the exact
union worse: at 105 bits, doubling expected grinding gives
`78.5237216403 bits`, while the monolithic `2^25` cap gives
`76.5878519781 bits`; 106 degrades again. The selected speed path therefore
keeps 104 bits and requires two
independent modeled oracles:
`H_pow(profile, role, phase, snapshot, witness)` for grinding and
`H_fs(transcript, accepted_witness)` for challenges. A domain label on one
challenger is insufficient. The unknown public-XOF hybrid remains an
additional term. No complete soundness number exists yet.

VRAM requires sequencing, not eviction of `H`. A deliberately conservative
state screen retains both accepted and proposed `A`: each uses `134,217,728 B`
of rows plus a `33,554,400-B` full hash tree. Together with the other old/new
owners the state proxy is `664,851,392 B`. Forced overlap of measured GW4,
the 768-MiB sparse map, that state and one complete D23/Fp2 lane guard is
`46,145,661,708 B`, or `327,084,844 B` above the A100 guard. The lane guard
already contains its D23 codeword; it is not counted twice. The normative
schedule keeps `H` resident, finishes GW4, releases all GW4 transient owners,
then executes the four base WHIR cores one at a time with one reused
workspace. Analytic phase proxies are `40,616,520,492 B` for GW4 plus `H`
plus state and `19,884,200,864 B` for C6.3. These are `credit:false`: the
state subtotal is an analytic census and the complete-tree convention
conservatively retains leaf hashes. An executable tensor/Fp2 guard and A100
high-water counter must agree. Spilling a codeword to host is forbidden.

The two raw genesis correction tapes alone are `44,236,800 B`; therefore they
stay behind the systematic root and only queried rows, distinct deduplicated
frontiers for `D'` and `A`, and batched relations enter the certificate.
Hiding randomness, typed
framing and the Volta `H` closure may move the final size in either direction.

The executable screen is `scripts/budget_c63_authenticated_sketch.py` (schema
v10). Every gate stays `evaluated:false` until a canonical C6.3 codec is produced and
verified. In particular, `pi_final`, exact soundness and complete prover time
are unknown rather than inferred from the 23.56 MB estimate.

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
  104-bit-per-core C6.3 Hiding-WHIR profile, transcript order and canonical
  codec; model proof-of-work and Fiat--Shamir as two independently
  domain-separated oracles with separate counters, or stop;
- prove that the tagless Bolt/WHIR bulk is independent of both secret MAC
  multipliers and that moving it to the public-argument partition preserves
  the complete Fiat-Shamir statement and every byte count;
- prove systematic-correction-plus-sketch binding, two-tape VOLE linkage,
  tensor target decomposition, sparse-code consistency, delta linkage and
  complete transcript privacy;
- replace the scaled sparse-`H` verifier's full `m/u` inputs with the terminal
  D22/D19 WHIR openings while preserving its 1,496-B codec and two MAC tapes;
- replace the honest cached-base check with a projected initial MMCS opening
  and the first-round mask-only equation; include an attack test where plain
  WHIR accepts a substituted base and the linked C6.3 verifier rejects it;
- recompute the complete soundness union for Goldilocks/Fp2;
- reproduce the green 188-bit rational distance screen independently and bind
  it to the production version of the exact-ensemble D22 setup sampler;
- add adversarial mutations for prefix, append ordinal/value, zero tail,
  correction domain/tape, `H delta_D'`, encoded-`A` row/root, fresh `w`,
  `y=A*rho`, both child roots, epoch/length and framing.

Changing the protocol statement opens additive Lean work. Frozen historical
M1--M11 files are not edited; C6.3 lemmas must cover the new relation before a
production claim.

### C63-G1 — GPU component boundary

- consume the live K/V slabs without a dense host state;
- compute/update the correction root, raw `S` and encoded tensor `A` on GPU;
- use a C6.3-only fresh Hiding-WHIR owner and resident initial-message hook;
- retain accepted and proposed `A` until verification, and keep fresh `w` plus
  the `y=A*rho` proof view device-resident with shared row paths;
- serialize one complete candidate and run the CPU verifier;
- separately time cache update, base code, hashing, closure, D23, GW4,
  synchronization and serialization.

Admission requires cache binding below `4.640596167 s` when combined with the
unchanged GW4/reserve allocation, or an exact total below 15 seconds if work is
shared between them. Component results remain `credit:false`.

### C63-E2E2 — two real responses

Only after local tests, exact budgets, clean source, artifact checks and a new
owner GO may one A100 execute the first experiment.

1. Generate/install the complete 17-profile setup if absent, then run real
   `0 -> 150`. Record `cold_deployment_to_first_accept`, including setup
   generation, process/model load, fixed preload, inference, proof,
   serialization and verification. Also record the gate clock
   `response_specific_prover` separately.
2. Without restarting, warming artificially or replacing state, promote the
   first accepted successor and run real `150 -> 200`. Record the complete
   warm request-to-accept wall plus provider proof and verifier subclocks.

Both certificates use the real/AES PCG and the same connection with disjoint
correlation ranges. Compilation, repository synchronization and weight/setup
transfer are preparation, not deployment or response time. No mutation set,
four burns, 17-response loop or retry runs in this experiment. Any failure
stops and records the create-new disposition.

## 7. Current decision and confidence

The direction is **the append-aligned `t=16` Bolt sparse precode over Volta's
masked correction state, adapted inside WHIR as one 16-column extension-field
mix, a deterministic pre-`rho` `A=C^16(H D')` tensor rooted as D19-by-32,
fresh randomized D22/D19 WHIR cores over already encoded `w/y` oracles, and one
dual-tape sparse inner-product closure; tagless bulk stays public and only the
designated tail enters `pi_final`**. It is not a Bolt crate port, a second PCS,
a raw-K/V Merkle tree or a sketch-only commitment.

- Probability that it removes the measured cache-precommit bottleneck:
  **88--96%**.
- Probability that the one-`rho`, two-tensor Bolt-to-WHIR algebra survives
  independent review before privacy and full error accounting: **90--96%**.
- Probability that the first complete GPT-2 certificate fits 30 MB:
  **85--93%** conditional on the paired adapter and counted framing; the
  independent-limb fallback adds only about 133 kB.
- Probability that the new separation theorem and two-cohort codec preserve
  `pi_final <4.5 MB`: **80--90%**.
- Probability that the complete warm prover reaches `<15 s` on one A100:
  **60--75%** before measuring encoded-`A`, fresh masks, proof-of-work, the
  resident adapter and D23 residual.
- Probability that the four-thread verifier stays below 5 seconds:
  **70--85%**, dominated by the unmeasured 768-MiB `H` scan and WHIR bodies.
- Probability that an independent review accepts the finite Goldilocks
  distance bound without changing the query count: **92--98%**.
- Probability that the production setup sampler, public-XOF term, Fp2 opening
  terms, two-oracle proof-of-work model, privacy and complete transcript union
  close under the 104-bit profile: **45--60%**. The newly explicit mask-only
  link is locally implementable but adds one proof and privacy obligation.
- Probability that eight literal non-amortized Bolt closures reach `<15 s`:
  **below 5%**.

The largest uncertainties are the two-oracle proof-of-work theorem, public-XOF
setup model, pre-encoded resident WHIR adapter, tensor/WHIR privacy composition,
unmeasured encoded-`A` update and D23 cohort. The projective/monomial-basis
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

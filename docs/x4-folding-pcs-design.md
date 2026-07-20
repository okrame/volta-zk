# X4 Phase-1 folding-PCS preregistration

**Status (2026-07-20): DESIGN FROZEN; implementation not authorized.**

This document is the Phase-1 preregistration for X4. It replaces the original
X4 premise in `docs/scaling-note.md`: lever A (cache/reuse fixed query rows)
is recorded UNSOUND and receives no credit. The replacement is a folding-PCS
package, co-designed with D3 per-layer commitments and canonical per-expert
blocks. This package contains design only. It changes no Lean theorem, Rust
code, proof, benchmark reference or gate verdict.

The candidate profile is named **`x4-zkdeepfold-v1`**. All parameters, byte
thresholds, measurements and failure rules below are preregistered before
implementation. A later change to a security parameter, block map, byte
codec or gate requires an append-only deviation before the affected run; a
failed result may not be tuned into a pass.

## 1. Decision and primary sources

X4 selects **zkDeepFold-UD**: the zkDeepFold protocol and batching layer,
specialized back to a proved unique-decoding radius instead of relying on
DeepFold's conjectural list-decoding radius. It is a BaseFold-family
Reed--Solomon multilinear PCS. It is selected because it has:

- a field-agnostic BaseFold commitment with linear/quasilinear prover work
  and polylogarithmic proof and verifier work;
- a published batch construction for different-sized polynomials and an
  explicit reduction for evaluations at different points; and
- an explicit statistical zero-knowledge layer rather than an assumed
  hiding wrapper.

The normative cryptographic references are:

1. [BaseFold: Efficient Field-Agnostic Polynomial Commitment Schemes from
   Foldable Codes](https://eprint.iacr.org/2023/1705), IACR ePrint
   2023/1705 (CRYPTO 2024). BaseFold supplies the field-agnostic multilinear
   PCS and the folding/proximity architecture.
2. [DeepFold: Efficient Multilinear Polynomial Commitment from Reed--Solomon
   Code and Its Application to Zero-knowledge
   Proofs](https://eprint.iacr.org/2024/1595), IACR ePrint 2024/1595, and the
   [published USENIX Security 2025
   version](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei).
   DeepFold supplies different-size batching, the different-point reduction
   and Section 5.2's `zkDeepFold` construction.
3. [Zero-Knowledge BaseFold Polynomial Commitments over Binary
   Fields](https://eprint.iacr.org/2025/1015), IACR ePrint 2025/1015, is
   corroborating work on BaseFold-family zero knowledge. It is not the
   selected instantiation because VOLTA's authenticated-value seam is over
   the Goldilocks extension, not a binary field.

[BrakingBase](https://eprint.iacr.org/2024/1825) is not selected. It has an
attractive linear-prover/polylog-verifier profile, but its stated scope does
not provide the zero-knowledge layer required for private weights. X4 will
not manufacture that missing property from an informal mask.

The references are protocol specifications, not implementation assurance.
Their external security claims remain assumptions until the exact selected
theorems and parameter arithmetic have been checked against the implementation
and connected to VOLTA's M9 seam.
The unique-decoding specialization, cohort Merkle layout and masked-sum
public relation are VOLTA adaptations, not claims copied from the paper;
Phase 2 must prove their reductions before any implementation authority.

### 1.1 Pinned conservative parameter screen

The initial profile is:

| Parameter | `x4-zkdeepfold-v1` value |
| --- | ---: |
| authenticated/evaluation field | `E = F_p[phi]/(phi^2-7)` (current `Fp2`) |
| PCS code/folding field | `K = E[psi]/(psi^2-phi)` (`F_p4`) |
| original block-variable range | `14 <= mu_b <= 30` |
| maximum original block variables `mu` | `30` |
| maximum extended RS domain | `2^(mu+1)/rho = 2^34` |
| Reed--Solomon rate `rho` | `1/8` |
| distance credited without a conjecture | unique-decoding radius `(1-rho)/2 = 7/16` |
| independent proximity queries `s` | `128` |
| ZK auxiliary variables | `ell_b = ceil(log2(s*mu_b^2 + 1))`, at most `17` |
| query term used in the screen | `(9/16)^128 = 1.0367724023455627e-32` |
| query-term bits | `106.24959981538402` |
| response-wide statistical target | at least `78.809294874` bits |
| hash | BLAKE3, computational binding accounted separately |

Here `phi` is a nonsquare in `E` because its norm is `-7`, a nonsquare in
`F_p`; the tower is therefore a field. Moreover,
`v2(|K|-1) = v2(p-1)+v2(p+1)+v2(p^2+1) = 32+1+1 = 34`, so the maximum
`2^34` multiplicative domain exists. The largest gpt-oss logical block has
`mu=30`; zkDeepFold's one-variable random extension makes it 31-variate and
rate `1/8` makes the first codeword length `2^34`. These identities are
pre-code unit and proof obligations, not assumptions to skip in Rust.

The GKR and VOLE-MAC boundary stays in `E`. Weight coefficients and the
opening point lie in `E` and are embedded canonically into `K`; all internal
RS, folding and PCS challenges lie in `K`. The public masked value is
canonically decomposed into two `E` tower components; two ordinary `E` MAC
transfers and the response ZeroBatch connect those components to the GKR
claim. This adds no `K`-valued PCG correlation.

Canonical `K` wire order is `(k0.c0, k0.c1, k1.c0, k1.c1)` for
`k0 + psi*k1`, four canonical little-endian Goldilocks limbs and exactly 32
bytes. Decoding rejects every limb `>=p`; no Montgomery or host-native
representation is transcript data.

All FRI/PCS query domains have power-of-two length. Query indices are sampled
uniformly with replacement from exactly the required number of fresh
verifier bits under the X4 transcript domain; they are not obtained by field-
element modulo reduction. Thus the historical Ligero modulo-bias boundary is
not inherited by the new profile.

The widely advertised small-query DeepFold figures use a conjectural
Reed--Solomon list-decoding radius. They are **not** a VOLTA input and no gate
or projection may quote the paper's approximately 34-query/304-KB point as a
VOLTA result. Before code, the complete published soundness expression must
be specialized to the unique-decoding regime and instantiated for `K`, the
maximum batch and all union terms. The blind-reduction, MAC and ZeroBatch
terms remain over `E`. Their response-wide composition must
meet the response-wide target corresponding to the current pinned Ligero
level (`1.8881578818430648e-24`, or `78.809294874` bits), in addition to the
separately stated BLAKE3 assumption. If `rho=1/8, s=128` does not do so under
the proved expression, X4 stops and preregisters a new profile; it does not
silently increase `s` after a benchmark.

The profile uses the paper's statistical ZK construction: extend each
committed multilinear coefficient vector by an equal-size random vector in
one extra Boolean variable, and commit to the auxiliary small random
multilinear polynomial required by `zkDeepFold`. For a `mu_b`-variate block,
the paper requires `2^ell_b > s*mu_b^2`; the deterministic formula in the
table gives `ell_b <=17` because
`2^17=131,072 >128*30^2=115,200`. The resulting ZK epsilon is part of the
pre-code security-arithmetic checkpoint.

## 2. Object being committed

X4 retains D3: one commitment namespace per transformer layer, plus a global
namespace, with independently openable blocks inside each namespace. It does
**not** create one public commitment per expert and does not return to a
whole-model monolith.

For every logical block `b`, the canonical descriptor fixes:

- profile/version, model-config digest and weights digest;
- layer/global namespace, block kind and block ordinal;
- logical tensor name, dimensions, row-major coefficient order and padding;
- source quantization type and the deterministic injections into `E` and `K`;
- logical and padded coefficient counts, code rate and oracle lengths;
- the auxiliary-mask and M9 transfer-domain template (never a live
  correlation value); and
- every static extension/auxiliary cohort root and the outer-manifest
  position.

The descriptor is statement data. A prover cannot choose it after seeing a
challenge. Shape validation, disjointness, exact coverage, zero padding and
integer-to-field conversion are checked before transcript consumption.
Tensors smaller than `2^14` coefficients are canonically co-packed into their
layer's fixed block or zero-padded to `mu_b=14`; no standalone smaller block
is allowed. This keeps `ell_b <= mu_b+1`, as required by the auxiliary-point
construction.

### 2.1 Block geometry

The gpt-oss sizing case has 24 layer namespaces and one global namespace. The
canonical analytic block inventory is:

- per layer: four attention blocks, one router block, and two blocks for each
  of 32 experts (aligned gate/up and down), hence `4 + 1 + 2*32 = 69`;
- global: embedding and unembedding, hence two blocks;
- total physical independently openable blocks:
  `24*69 + 2 = 1,658`; and
- at most two stacked phase claims per physical block, hence `3,316` claims.

The pinned sizing geometry has `d=2,880`, expert width `2,880` and vocabulary
`201,088`. The aligned gate/up expert block is at most
`4,096*8,192 = 2^25` coefficients. Each global embedding/unembedding block is
`262,144*4,096 = 2^30` after independent axis padding, establishing the
profile's `mu_max=30`. GPT-2's corresponding largest padded block is at most
`2^26`, so it exercises the same format without setting the field/domain cap.

For the 100-prefill + 50-decode analytic workload the existing expected
claim count is `3,314.06`, almost the maximum. X4 therefore claims no useful
expert-sparsity wall-time reduction for that workload. Block openability is a
communication and proportionality property; the workload may touch nearly
all expert blocks across its many tokens.

GPT-2 is the migration and measured validation case. It retains the existing
13 namespace roots and the existing 96-prefill + 6-decode claim geometry,
but receives new X4 block descriptors and new roots. Equality is required for
semantic weight evaluations and all downstream proof claims, not for the
commitment bytes.

### 2.2 Cohort commitment and one response envelope

X4 logically commits each block separately but physically shares Merkle
authentication within a layer. Blocks are partitioned by namespace, oracle
kind and padded variable count into canonical cohorts. For every codeword
coordinate in a cohort, an inner Merkle tree commits the ordered block-slot
symbols; an outer Merkle tree commits the ordered inner roots across codeword
coordinates. The cohort roots and exact block descriptors are leaves of the
layer manifest. The 24 layer manifests and one global manifest are then
leaves of one model manifest.

This two-dimensional layout is part of the PCS, not an accounting trick. At
one queried codeword coordinate, touched blocks reveal their `K` symbols with
one canonical inner multiproof and one outer path. Unopened block symbols are
not sent. An absent block slot has a distinct canonical leaf and cannot be
shifted or substituted. Hash binding of the cohort tree binds every member
codeword; the pre-code concrete binding theorem must cover this replacement
of DeepFold's one-tree-per-polynomial presentation.

Different points are never combined by a naive random linear combination.
For each touched block, a VOLE-blind batched sumcheck first reduces the
already fixed GKR weight claims to one claim at a canonical `E` point. A
transcript-bound random combination then combines same-size touched blocks
at the opened initial-codeword coordinates; the verifier recomputes that
combination from the multiproof symbols. Subsequent fold oracles are shared
per touched cohort. DeepFold's proved different-size batch reduction combines
the cohorts. Claims, cohort membership and block order are bound before
either reduction's challenge.

A response carries one response-wide opening envelope and only the symbols
and authentication material for touched blocks. It does not carry a fresh
fixed proof per namespace, expert or token. The cost is still linear in the
number of touched blocks at the initial-query layer; it is not falsely
described as independent of `B_touch`.

## 3. Private evaluation and the M9 seam

The standard PCS relation exposes an evaluation, while VOLTA must never
publish `W_tilde(r)`. X4 uses zkDeepFold's already-required small random
polynomial as a one-time evaluation pad, then transfers its value through the
existing `E`-valued VOLE-MAC interface. The public model root commits to
static `W` plus prover-secret ZK randomness; it contains no session/PCG
secret.

For every static block `b`, the one-off commitment does exactly the
zkDeepFold construction over `K`:

- embed `W_b` from `E` into `K`;
- append an equal-size uniform `K` coefficient vector to obtain the
  `(mu_b+1)`-variate `Wext_b`, with
  `Wext_b(z_b || 0) = W_b(z_b)`; and
- sample and commit a uniform `ell_b`-variate `K` polynomial `g_b`, where
  `2^ell_b > s*mu_b^2`.

Both roots are bound inside the block/cohort/layer manifest. For the single
permitted response opening:

1. Existing GKR relations produce fixed authenticated claims about `W_b`.
   The blind different-point reduction over `E` produces one authenticated
   `v_b = W_b_tilde(z_b)` at a canonical `z_b in E^mu_b`.
2. Define the paper's canonical auxiliary point
   `u_b = suffix_(ell_b-1)(z_b) || 0 in E^ell_b` and
   `s_b = g_b_tilde(u_b) in K`. The prover publishes only
   `h_b = embed(v_b.plaintext) + s_b in K`; it never publishes either
   summand. All `h_b`, source roots and claim order are fixed before batch,
   fold and query challenges.
3. The response-wide zkDeepFold-UD proof jointly opens `Wext_b` and `g_b`
   using DeepFold's different-size batching, but its public relation is the
   single masked equation
   `h_b = Wext_b(z_b || 0) + g_b(u_b)`. Same-size block batching is applied
   only after the individual roots and masked equations are fixed. Initial
   cohort query symbols and every subsequent fold are checked against those
   roots.
4. Write the canonical tower decomposition `s_b = s0_b + psi*s1_b` and
   `h_b = h0_b + psi*h1_b`, with all four components in `E`. The prover
   consumes two existing full-field correlations, sends the ordinary
   corrections for `s0_b` and `s1_b`, and thereby authenticates both
   components. No `K`-valued correlation or PCG primitive is introduced.
5. One fresh response ZeroBatch checks both
   `v_b + s0_b - h0_b = 0` and `s1_b - h1_b = 0` for every touched block.
   The verifier therefore obtains the committed authenticated weight
   evaluation as `Auth(h0_b) - Auth(s0_b)`, while the second equation proves
   that the public upper component is entirely mask. `W_b_tilde(z_b)` never
   appears in clear.

Uniform `g_b` makes `s_b`, and hence `h_b`, uniform in `K` at the nonzero
evaluation functional. The static commitment binds `Wext` and `g`; the
folding proof binds their masked sum; the two existing VOLE MACs bind the
tower components of `s`; and ZeroBatch ties the authenticated GKR evaluation
to `h-s`. The complete hiding proof must simulate the cohort-batched
transcript given only `h`. Citing zkDeepFold's theorem while still sending
the individual evaluations is not sufficient.

The exact PCS transfer allocation is `2*B_touch + 1` full correlations: two
mask components per touched block plus one response ZeroBatch mask. It
replaces the current PCS evaluation-transfer allocation and is counted in the
X4 rebaseline. At the two-phase upper sizing point,
`K_claim=2*B_touch`, so it receives no correlation-count saving. This is a
PCS-seam count/formula change, not a generator, tuple, setup, spool, pool,
reuse or lifecycle change. No other proof-path correlation budget changes.

The lifetime boundary remains the current one: **one response opening per
static commitment epoch**. `g_b` is a one-time pad, and X4 does not claim that
repeated zkDeepFold transcripts for the same static ZK randomness are jointly
zero knowledge. Recommitment/pad refresh, persistent multi-response serving
and correlation lifetime changes remain out of scope. A commitment epoch
rejects a second response opening; it may not rely on operator discipline.
“One-off commit” below means once per permitted model-commitment epoch under
the existing benchmark convention, not a new multi-response durability
claim.

### 3.1 What reopens in M9

The historical Ligero-specific M9 theorem package remains an immutable record.
X4 reopens only the abstract PCS-to-authenticated-evaluation seam. Before any
Rust implementation, a new Lean module (planned name
`VoltaZk/FoldingOpeningMac.lean`) must state and prove at least:

- `masked_aux_eval`: the semantic identities
  `Wext(z || 0) = W(z)` and `h = embed(W(z)) + g(u)` for the canonical
  auxiliary point;
- `masked_aux_hiding_count`: for fixed `W,z`, uniform auxiliary coefficient
  tapes give equal-size fibers for every published `h in K`; the individual
  `W(z)` and `g(u)` are not transcript fields;
- `pcs_subfield_eval`: embedding an `E`-coefficient MLE and an `E` point into
  `K` preserves its evaluation and gives zero upper tower component;
- `tower_mask_transfer`: the two authenticated `E` components of `g(u)` and
  the two ZeroBatch equations recover an authenticated `W(z)` without
  revealing it;
- ordered `BlockPCSClaim` and `BatchPCSOpening` statement types whose block,
  point, root and claim order are transcript-bound;
- `folding_batch_reduce_sound`: after claims are fixed, the blind
  different-point reduction leaves at most one canonical claim per block,
  with its exact finite-field failure term;
- `MaskedBatchBindsIntoMac`: a concrete counting predicate for accepting
  tapes on which a static/auxiliary masked equation, folded evaluation or
  transferred mask component is wrong;
- `masked_batch_opening_mac_sound`: acceptance of the folding opening and the
  response ZeroBatch while any authenticated weight evaluation disagrees
  with the committed block is bounded by the exact sum/union of PCS,
  reduction and MAC/ZeroBatch errors;
- `masked_batch_transfers_evals`: on a good tape, each downstream M3
  hypothesis receives the required authenticated `W_tilde(r)`; and
- a response-level composition theorem that accounts for every touched block
  and proves the preregistered statistical target without treating BLAKE3 as
  an information-theoretic event.

Names may change only in the pre-code theorem preregistration, but the
properties may not weaken. Every new theorem is added to `lean/Audit.lean`;
the derived audit must remain zero-sorry/zero-admit, standard-axiom-only and
must introduce no fifth `Ideal.lean` axiom. The concrete zkDeepFold binding
property remains an explicit hypothesis at the seam, ultimately discharging
the existing global `Ideal.WeightPCSBinding` boundary rather than being
declared as a new ideal axiom.

The sequence is the same proof-before-code discipline used for M10/M11:
freeze statements and exact error arithmetic, make Lean build and the audit
green, checkpoint and ledger it, then and only then authorize Rust. This
Phase-1 package performs none of those Lean or Rust steps.

## 4. N4(ii): new Merkle commitment format

All X4 roots use leaf/internal-node domain separation. The new format uses
BLAKE3 derive-key mode with these exact context strings:

```text
volta-zk/x4/pcs-leaf/v1
volta-zk/x4/pcs-node/v1
volta-zk/x4/manifest-leaf/v1
volta-zk/x4/manifest-node/v1
```

A PCS leaf frame is canonical little-endian and includes the schema/profile,
tree/oracle kind, namespace, cohort and block-slot identity, descriptor
digest, fold round, outer codeword index, inner block index,
logical/padded/code lengths, symbol count/type and symbol bytes. An internal
frame includes the schema/profile, tree identity, inner/outer role, level,
node index and ordered left/right child digests. Manifest frames separately
bind the full block/cohort descriptor and its root; PCS nodes cannot be
reinterpreted as manifest nodes or leaves.

Every inner and outer path depth is derived exactly from the committed
descriptor. Verification rejects a short or long path, an out-of-range
index, a non-canonical sibling order, a duplicated/missing multiproof node
and a node or leaf replayed across tree kind, cohort, block, oracle or fold
round. The new codec deliberately changes
all commitment roots. Historical C3/C3b/T1 roots, records and references are
never regenerated, relabeled or compared byte-for-byte to X4 roots.

## 5. Honest cost model

Let:

- `N_total` be all padded committed coefficients;
- `N_touch` be padded coefficients of touched blocks;
- `A_total = sum_b 2^ell_b` and `A_touch` its touched-block auxiliary
  subset;
- `B_touch` be touched physical blocks;
- `K_claim` be fixed evaluation claims before the one-per-block reduction;
- `n_max` be the largest touched padded block; and
- `s=128` be the pinned query count.

The preregistered asymptotic model is:

| Operation | Required model |
| --- | --- |
| one-off commit | `O(sum_b (N_b log N_b + 2^ell_b*ell_b))` field/code/hash work, implemented block/cohort-streaming |
| per-response open | `O(N_touch + A_touch)` folding/code work plus batch-reduction work |
| serialized opening | `O(s log^2 n_max + s*sum_c MP(B_c,M_c) + s*B_touch + K_claim)`; no term linear in `N_total` or `N_touch` |
| verifier | the same polylog/cohort-query expression in field/hash work |
| manifest auth | proportional to touched manifest paths, canonically deduplicated |

Here `M_c` and `B_c` are the total and touched block slots in cohort `c`, and
`MP(B_c,M_c)` is the exact canonical inner-Merkle multiproof hash count. The
closed byte formula must instantiate those counts; big-O is not accepted in
a gate record. Neither `N_touch` nor `A_touch` appears as a linear serialized-
byte term.

“Polylog PCS” refers to opening bytes and verifier work. It does **not** mean
polylog prover work. A response touching almost every expert block still
scans almost every relevant coefficient.

The storage expansion must be reported, not hidden. Coefficients and code
symbols in `K` take 32 bytes, the ZK extension doubles the coefficient vector
and rate `1/8` expands the first encoded oracle. The raw first-oracle screen
is therefore
`2 * N * 32 / (1/8) = 512*N` bytes, or 256 times an i16 source, before later
folding oracles, auxiliary polynomials and Merkle nodes. This is about 64 GB
for a 250-MB GPT-2 i16 source. Multiplying the unpadded 41.8-GB gpt-oss source
by 256 gives a **10.7008-TB source-equivalent floor**, not an upper bound;
independent axis padding can make the exact oracle larger. The largest
`ell=17` auxiliary polynomial alone has a 33,554,432-byte raw rate-1/8 first
oracle before its Merkle nodes; applying that maximum to all 1,658 blocks
would add 55.633248256 GB, while the gate uses the exact per-block
`sum_b 2^ell_b` instead. An implementation
may stream/recompute/deduplicate data if its root is identical, but it must
measure persisted bytes, bytes read per opening, recomputation wall, peak RSS
and peak VRAM. It may not claim a resident-A100 win by omitting host or disk
traffic.

### 5.1 Current measured comparison point

These are immutable current Ligero measurements, not X4 projections:

| Metric | CPU reference | official RunPod A100 reference |
| --- | ---: | ---: |
| one-off PCS commit | `10.785629 s` | `0.202467 s` |
| per-response PCS open | `0.767759 s` | `0.294423 s` |
| PCS verify | `0.080496 s` | `0.079365 s` |
| serialized PCS opening | `43,273,888 B` | `43,273,888 B` |

The current T1 response is `84,544,352 B`; subtracting the PCS component
leaves `41,270,464 B` of unchanged non-PCS response material. X4 cannot claim
that baseline until the same semantic GPT-2 response is reproduced.

### 5.2 Preregistered gates

Gates are conjunctive. A byte pass cannot override a security, correctness,
proportionality, storage or end-to-end failure.

**G1 — formal/security seam.** The exact unique-decoding soundness, modified
masked-relation ZK arithmetic and `E`/`K` composition for the pinned profile
meet at least `78.809294874` statistical bits response-wide; the M9 theorems
and derived Lean audit are green before Rust; no new ideal axiom, clear
`W_tilde(r)`, second opening or Fiat--Shamir claim exists.

**G2 — correctness and adversarial strictness.** GPT-2 fixed-point/golden
outputs, authenticated evaluations and downstream proof claims match T1
semantically. Honest batch verification accepts. Tests reject tampering with
root, manifest, descriptor, block, point, public `h`, either tower-component
mask correction/key/tag, claim add/drop/reorder, reduction transcript, fold
message, query answer, Merkle leaf/node/type/depth/index, auxiliary ZK
commitment and response
ZeroBatch. Cross-domain leaf/internal/manifest substitutions all reject.
The exact PCS transfer count is `2*B_touch+1` full correlations on both roles,
with no other proof-path counter change.

**G3 — GPT-2 communication.** The canonical serialized PCS component is at
most **4,000,000 B per response**. With the frozen non-PCS component this
projects an absolute response ceiling of **45,270,464 B**. The byte counter
must equal the serialized length and itemize roots/manifests, claims,
sumchecks/folds, queries, paths, public masked evaluations and MAC closure.

**G4 — measured isolated wall.** On the pinned 4-thread CPU profile:
one-off commit `<=180 s`, per-response open `<=15 s`, verify `<=0.50 s`.
On official `runpod-a100-v1`: one-off commit `<=15 s`, per-response open
`<=1.50 s`, verify `<=0.25 s`. These deliberately allow prover time to buy
communication, but not an unbounded implementation. The existing full
resident-pod absolute gates also remain conjunctive: prefill `<=10 s`, decode
`<=4 s`, H2D `<=100 MB`, maximum synchronization `<=0.150 s`, flatness
`<=1.5`. Commit is measured separately and never hidden in setup.

**G5 — touched-block proportionality.** A synthetic family with identical
block size and `1, 2, 4, 8, 16` touched blocks records `N_total, N_touch,
B_touch, K_claim`, coefficients read, every byte component and wall. Opening
source-weight reads equal the canonical `N_touch`; encoded, ZK-extension,
auxiliary and fold reads are counted separately. Serialized bytes match the
closed cohort/multiproof formula and have no linear `N_total`/`N_touch` term.
Doubling only unopened blocks may change opening bytes solely through the
exact manifest/cohort-depth formula, and same-process ABBA opening wall ratio
must be `<=1.05`. There is exactly one response envelope.

**G6 — storage and traffic honesty.** Records include source bytes, every
encoded/fold/Merkle/auxiliary artifact byte, persisted bytes, recomputed
bytes, host bytes read/written, H2D/D2H, peak RSS and peak device memory.
Artifact totals reconcile exactly. Block streaming must fit the official
A100 and cannot materialize a hidden whole-model GPU oracle. A storage or
traffic omission is a gate failure, not “instrumentation unavailable.”

### 5.3 gpt-oss analytic screen (not a verdict)

The sizing case is 24 layers, 32 experts and 41.8 GB of committed i16
weights, with 1,658 physical blocks and at most 3,316 stacked claims. Before a
real export, X4's analytic projection must show:

- serialized PCS opening `<=35,000,000 B` for the upper claim count;
- a closed byte expression with no term linear in the 41.8-GB total;
- marginal block-opening bytes proportional only to touched blocks and
  the exact cohort/manifest multiproof depths; and
- the raw-oracle/storage screen above, including the 10.7008-TB
  source-equivalent first-oracle floor, with an explicit
  streaming/recompute plan.

This screen is deliberately weaker than a measured gate. The expected
3,314.06 claims provide essentially no sparsity discount, and there is no
gpt-oss wall, proof-size or memory result until X5 supplies real artifacts and
an authorized run. Passing the analytic screen confers no X5 or product gate
credit.

## 6. Migration and re-baseline ritual

The migration is append-only and runs only after the proof-before-code
checkpoint authorizes implementation.

1. Create a new format/profile identifier, `x4-zkdeepfold-v1`, and new
   reference names. Never overwrite C3, C3b, T1 or historical root records.
2. Use a clean tree and one Git SHA for both sides of a same-process Ligero
   versus X4 ABBA run. Because `target-cpu=native` is pinned, remeasure Ligero
   on every new CPU/pod rather than importing a ratio.
3. Use the same GPT-2 weights/golden hashes, workload, model configuration,
   block semantics and claim schedule. New commitment roots are expected;
   clear evaluation is allowed only in a test oracle that checks semantic
   equality and is absent from production.
4. Run one untimed warmup and at least three measured ABBA pairs. Gate the
   preregistered upper median. Pin CPU model/thread count and the official
   provider/A100/driver profile.
5. Measure cold one-off commit separately from per-response open and verify.
   Record canonical serialized bytes, every component, peak RSS/VRAM,
   persisted artifacts, host I/O, H2D/D2H and synchronization. Record both
   success and failure; do not rerun away an outlier without a ledgered cause.
6. Append new `benchmarks/results/x4-<date>-<gitsha>.json` records with
   `git_dirty:false`, then add new reference rows. Historical rows and JSON
   remain byte-identical. Cut over the production default only after G1--G6
   and the inherited resident-pod gates all pass.

The initial migration case is GPT-2, not gpt-oss. The latter remains a sizing
case until a separately authorized export/golden package exists.

## 7. Explicitly out of scope

This X4 package does not authorize or claim:

- X5, gpt-oss download/export, frontend integration, weights, goldens or a
  real gpt-oss benchmark;
- any PCG generator, cryptographic assumption, tuple, allocation, spool,
  encryption, lifecycle, pooling, reuse or multi-response change;
- any proof-path change outside the PCS/M9 seam, including corrections,
  boundary thinning, LogUp, routing, fixed-point semantics, witness generation
  or the GKR relations that produce weight claims;
- Fiat--Shamir or a non-interactive public-verifier conversion;
- cached/reused query rows (unsound lever A), per-token proofs, per-token PCS
  claims, clear weight evaluations, Packed16 reinstatement or an MXFP4
  commitment format; or
- Lean statements/proofs or Rust implementation in this Phase-1 package.

## 8. Phase order and hard stop

After product-owner review, a separately authorized phase may perform the
pre-code security arithmetic and M9 Lean checkpoint. Only a later explicit
authorization may implement and benchmark the Rust profile. The order is:

```text
Phase 1 (this document): design preregistration -> HARD STOP
Phase 2: exact security arithmetic + M9 Lean proofs/audit -> checkpoint
Phase 3: Rust implementation + adversarial tests -> checkpoint
Phase 4: clean GPT-2 CPU/A100 measurement + gate disposition
Phase 5: X5/gpt-oss work only under a separate preregistration
```

**HARD STOP: no Lean, Rust, reference, benchmark or X5 work is authorized by
this document.**

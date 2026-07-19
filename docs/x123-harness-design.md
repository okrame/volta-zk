# X1--X3 model-agnostic harness and synthetic MoE design

**Status (2026-07-19): Phase 1 approved; Phase 2 explicitly authorized;
runtime `ModelConfig` foundation PASS; X1 routing PASS; X2 FAIL; package
stopped before X3.**  The
preregistered design remains binding; implementation evidence and verdicts
land in the ledger and append-only records.  The foundation passed its binding
GPT-2 T1 non-regression gate on clean `9a4c688`; X1 passed on clean `6be165f`.
X2's clean `87ce25b` record passed all functional/session predicates but
failed the binding symmetric full-correlation band.  Section 7.3 therefore
stops the package; X3 was not started and has no verdict.

The package is CPU-only.  No pod may be provisioned or contacted, no gpt-oss
checkpoint may be downloaded or exported, and X4 folding PCS and X5 gpt-oss
execution remain later packages.  PCG/setup/lifecycle, PCS parameters and
opening semantics, Lean, soundness machinery, proof publication policy and
correction types are frozen.  X1--X3 may instantiate only existing argument
classes.  Discovery of a required new class is an immediate hard stop and
ledger entry, exactly as under the T1 discipline.

T1 is closed at the exact `84,544,352 B` response reference.  R1 remains an
external Kimi3 review and is pending; this package continues to claim **no
independent or adversarial cryptographic-review assurance**.

## 1. Package order, authority and stop conditions

Phase-2 work is strictly ordered:

1. land the runtime `ModelConfig` foundation and pass the complete GPT-2 T1
   byte-level non-regression gate;
2. implement and close X1 routing soundness;
3. implement and close X2 synthetic MoE e2e;
4. implement and close X3 non-GPT operations.

No later item may be used to rescue an earlier FAIL.  `volta-proto` remains
the single model-agnostic proof crate: it may receive shape-parametric
builders and public schedules, but it must not be forked by architecture.
The immutable `ModelConfig`, public workload and public route metadata are
verifier inputs, never prover-selected proof fields.

The following are hard stops:

- any operation needs a proof relation outside blind/Thaler sumcheck,
  public-linear folds, existing range/requant limbs, LogUp/TableBank,
  Hadamard/`Pi_Prod`, `Pi_ZeroBatch`, C3b-style private comparison, existing
  band/cache authentication, PCS `BlockClaim`, or the proved T1 eq reducer;
- the GPT-2 compatibility run differs by one byte, counter, deterministic
  allocation-schedule digest, required within-run allocation/channel parity
  verdict or golden value;
- a milestone gate returns FAIL;
- implementation would alter Lean, the PCG tuple/default/lifecycle, PCS
  parameters, one-opening-per-response policy, 8-byte corrections, private
  weight opening semantics, or public leakage beyond D1;
- a real gpt-oss artifact or network/model download becomes necessary.

## 2. Runtime `ModelConfig` foundation

### 2.1 Chosen refactor

The runtime architecture layer will live inside `volta-gpt2`, whose public
role becomes fixed-point model witness generation rather than a GPT-2-only
frontend.  Existing `gemm`, LUT, band and decode primitives are reused.  The
frozen GPT-2 entry points remain compatibility wrappers around one validated
runtime configuration; core tensor allocation and scheduling cease to read
`D`, `DFF`, `H`, `DH`, `L`, `VOCAB` or the fixed 16-head/4096-QKV pads.

The in-place choice keeps `LookupTrace`, requant semantics, resident/band
witness layout and the bit-exact loader single-sourced.  It is not permission
to rename transcript labels, reorder domains, change serialization, or
perturb the legacy schedule.

`ModelConfig` has a canonical, versioned representation with these validated
fields:

- model id/schema, vocabulary, maximum positions, `n_layers`, `d_model`,
  per-layer FFN/expert widths and embedding/tied-output policy;
- per-layer query heads, KV heads, head dimension and explicit GQA group
  size/mapping; `n_q_heads % n_kv_heads == 0` is mandatory;
- `n_experts`, `top_k`, router score scale, public metadata ordering and the
  native tie rule;
- per-layer attention mode (`full_causal` or `sliding(window)`), attention
  sink count/shape, and RoPE rotary dimension, public coefficient-table
  digest, base/frequency/scaling parameters and coefficient fraction bits;
- norm kind (`layer_norm` or `rms_norm`) and activation kind (`gelu` or
  `swiglu` with explicit clamp bounds);
- global content-keyed LUT parameters plus all per-layer/per-operator requant
  shifts, residual scales, residual seam shifts, router shifts and D2
  per-expert-block weight shifts;
- boundary thinning `thin_k`.  Each phase/chunk derives groups
  `[0,k), [k,2k), ...`; a final short group is permitted and a chain never
  crosses a chunk.  `k=1` means no cross-layer seam is skipped, while the
  already-proved same-layer claim reducer may still be used.

Validation happens before allocation or transcript activity.  Dimensions,
group maps, windows, clamp bounds, shift lengths and tensor block maps are
checked with overflow-safe arithmetic.  A generic-profile configuration
digest is bound into its versioned session preflight.  The frozen GPT-2 T1
profile retains its existing implicit profile/version and sends no new byte
or challenge: this exception is required by the byte-level compatibility
gate, not an unbound prover choice.

### 2.2 Non-power-of-two layout rules

These rules are binding for witness tensors, sumcheck claims, T1 reducers and
PCS blocks.

For a logical row-major `rows x cols` matrix:

```text
row_pad = ceil_pow2(rows)
col_pad = ceil_pow2(cols)
flat(row, col) = row * col_pad + col
point = r_col || r_row
```

Column variables are the low/first, LSB-first variables; row variables
follow.  Arithmetic tensors and committed weights are zero outside the
logical rectangle.  Lookup columns instead use the existing content-specific
valid pad pair and a public real-cell mask; padding is never allowed to create
a false lookup or a proof-selected shape.  Every equality table, public
selector and T1 reducer uses the same `r_col || r_row` order.

A weight tensor `k x n` occupies exactly
`ceil_pow2(k) * ceil_pow2(n)` coefficients.  Its `BlockClaim` point is
`r_n || r_k`, its offset is a multiple of that whole power-of-two block, and
the point length is `log2(n_pad) + log2(k_pad)`.  Per-layer blocks are placed
largest-first at aligned offsets.  A non-power-of-two physical Ligero row
count may omit an unused outer tail, as C3 already does, but no block may
cross the physical row bound and `block_len >= pcs_cols` remains mandatory.

Heads, query rows, key rows, Q width, KV width, expert width, expert count and
vocabulary are padded independently.  GQA does not copy K/V into query-head
storage: the public query-head-to-KV-head map selects the authenticated KV
group.  Q/K/V column blocks have explicit offsets and pads; there is no
hard-coded GPT-2 `3*D` or padded-4096 interpretation.

The permanent pad regression uses `T=7`, `d_model=48` and `d_ff=80`, hence
row/hidden pads `8/64/128`.  It also uses vocabulary 97 (pad 128).  Tests
poison every would-be pad source, prove that canonical construction writes
zero/valid pads, and reject a real-cell mask or `BlockClaim` that admits a
poisoned pad.  This directly targets the P5 non-power-of-two wpe bug class.

### 2.3 Binding GPT-2 T1 non-regression gate

The compatibility configuration is exactly GPT-2 small, prompt 100 plus one
deferred 50-token decode chunk, C3b PCS `Q=120`, T1 `k=4`, and the current
real/AES connection profile.  With the reference seeds and artifacts, the
post-refactor run must satisfy all of the following simultaneously:

- serialized response is byte-for-byte identical and exactly
  **84,544,352 B**;
- prefill/decode/PCS split is `28,778,208 / 12,492,256 / 43,273,888 B`;
- authentication/reducer/q-bridge bytes are
  `38,348,720 / 22,848 / 672 B`;
- sub/full correlations are `4,793,590 / 181,933`, product/zero closures are
  `21,667 / 8,170`, and E-mult buckets are
  `2,800,595,736.8 / 114,852,961.2`;
- every operation counter, label allocation, deterministic per-stage
  correlation-allocation digest, PCS claim/block map and proof-section length
  equals the clean T1 reference;
- every existing mock/real-prepass and prover/verifier allocation/channel
  digest parity check remains present and true.  The literal lifecycle/setup
  digest hex strings are deliberately fresh because they start from the
  connection/response binding, and the correlation-spool digest is derived
  from fresh entropy; those session-bound values must not equal a prior run
  byte-for-byte.  AES-NI, ARMv8-CE and portable AES dispatch labels likewise
  identify function-equivalent hardware paths rather than transcript fields;
- the 50-token greedy decode and all golden tensors remain bit-exact;
- normal/chunked acceptance, malicious/replay/non-power-of-two tests,
  mock/real parity, both production leakage smokes, `cargo test --workspace`
  and the Python workspace suite are green.

The clean reference is
`benchmarks/results/t1-cpu-real-2026-07-19-b14577e.json`.  No tolerance,
rebaseline or profile-version change is permitted inside this gate.  A FAIL
stops before X1 code.

## 3. Exporter and numpy-reference framework

### 3.1 Shared interface

Architecture exporters will be thin adapters over one shared framework, not
copies of `export_gpt2.py`.  The common layer owns:

- round-half-away-from-zero, symmetric zero-point-0 i16 quantization,
  power-of-two scale selection, chained requant and strict overflow/clamp
  accounting from `docs/quantization-spec.md`;
- calibration-corpus hashing, per-site min/max/headroom reports, deterministic
  tensor ordering, aligned block-map construction and canonical little-endian
  artifact emission;
- canonical `ModelConfig`, source/exporter/config hashes, source dtype and
  dequantization metadata, every tensor shape/offset/shift, LUT content hash,
  calibration report, golden hash and future commitment block map/root fields;
- a common prompt/deferred-decode golden runner that invokes the architecture
  numpy reference and emits exact intermediate/output tensors, not checksums
  alone for the small synthetic fixtures.

An architecture adapter supplies source-name mapping, source decoding,
calibration hooks, config construction, public constants and its reference
forward.  GPT-2 becomes the first adapter while preserving its current
artifact bytes and golden outputs.  A deterministic `toy-moe-v1` adapter is
the Phase-2 interface test.  It creates its tiny source tensors locally; it
does not download anything.

The toy adapter exercises both source contracts:

- synthetic expert blocks enter through an `MXFP4_BLOCKS` source interface
  with explicit block scales, canonical dequantization and emitted per-block
  shifts;
- synthetic attention/router/embed tensors enter through a BF16 source
  interface and the shared calibration pass.

The toy codec is only an interface fixture and makes no claim to parse the
real gpt-oss checkpoint.  The future gpt-oss adapter must add the real format
decoder and is X5 work.

### 3.2 D2 and D4 are binding onboarding contracts

Under D2, future real MXFP4 expert blocks are canonically dequantized offline,
then symmetrically calibrated to private i16 with an explicit power-of-two
shift for every source block.  GEMM accumulation is i64 and all requant,
round and clamp behavior is the frozen integer behavior.  The committed
object is the emitted i16 block.  No 4-bit commitment, opening or response
credit is allowed.

Under D4, BF16 attention, router, embedding and unembedding weights undergo
the same P5-style symmetric i16 calibration, with explicit per-layer residual
scales and exact golden validation.  No BF16 arithmetic remains in the proof
witness.  A model is not onboarded until exporter/config/corpus/golden hashes,
block map, `t_export + t_calibration + t_commit`, and its commitment root are
recorded.  X1--X3 exercise the framework only with the toy adapter and do not
claim a gpt-oss onboarding time.

### 3.3 Reference operations

The numpy reference becomes config-driven while retaining the frozen GPT-2
wrapper.  X3 adds RMSNorm, clamped SwiGLU, public-coefficient RoPE, GQA,
attention sinks and lower-edge bands one operation at a time.  Every integer
accumulator, rounding point, LUT input/output, clamp flag and pad is emitted
for the synthetic golden.  Rust and numpy compare full arrays at each op
boundary before any end-to-end assertion.

## 4. X1 routing-soundness spike

### 4.1 Synthetic statement and public leakage

The X1 router-only shape is `T=31`, `L=4`, `d=48`, 32 experts and top-4:
124 token-layers.  Router rows use the existing committed GEMM, requant,
stable exp and reciprocal machinery.  For the fixture,
`exp_out_log2=12`, the existing reciprocal table is used, and the normalized
router score is the i16 result of the existing product/requant path with
`router_norm_shift=12`.  Existing signed-i16 requant range semantics pin

```text
-32,768 <= score_j <= 32,767.
```

Honest exp/reciprocal scores are nonnegative, but the limb derivation below
uses the full signed output envelope rather than relying on that tighter fact
or adding another lookup content.

Per D1, the four expert ids are public response metadata.  The accepted leak
is the complete token/layer expert-choice trace, a function of private router
weights and known tokens, analogous to the explicitly logged P4 public-bias
decision.  Scores, threshold and unselected weights remain private.  The
four-id metadata vector is canonically `[tau, e1, e2, e3]`, where `tau` is the
cutoff expert and the other three ids are ascending.  Thus the cutoff is a
designated slot in D1's already-public expert-index vector, not a fifth field
or an additional leak; gather/combine order is canonical and publicly
checkable.

The native rank is descending `(score, expert_id)`: a larger expert id wins a
tie, matching the existing last-maximum convention.  `tau` is the worst of
the four selected ranks and `theta = score_tau`.

### 4.2 One comparison per expert and the limb derivation

Let public `m_j` be one exactly for selected expert ids.  The comparison
column is

```text
c_j = score_j - theta - [j < tau]       when m_j = 1
c_j = theta - score_j - [j > tau]       when m_j = 0.
```

Equivalently this is one public-selector affine expression in
`score_j, theta`.  `theta` is tied to `score_tau` by the existing public
gather/weighted-row bridge.  Public preflight enforces four distinct in-range
ids, ascending order of the three non-cutoff slots, the designated cutoff
slot, and exactly 32 experts.

If all `c_j` are nonnegative, selected scores are at least the threshold and
unselected scores are at most it.  The strict indicator excludes a tied
unselected expert with a larger id and excludes a tied selected expert worse
than the declared cutoff.  Cardinality four then fixes exactly the native
top-4 set, including boundary ties.

The limb count is derived, not assumed.  Both scores are signed i16.  The
extreme affine values are `-65,536 <= c_j <= 65,535`, so the conservative
comparison bound is **`B=16`**.  Honest nonnegative values fit exactly in one
u16 limb.  A bounded negative integer cannot masquerade as a canonical
one-limb value because, for Goldilocks
`p = 2^64 - 2^32 + 1`,

```text
2^(16*1) + 2^(B+1) = 2^16 + 2^17 < p.
```

Thus its field residue is above the one-limb range.  Zero limbs cannot encode
the valid interval, so **one u16 limb is minimal**.  X1 performs exactly one
shared `Range(16)` lookup per expert/token/layer; it does not copy C3b's
three-logit-limb bound.

### 4.3 Existing-argument coverage

| X1 piece | Existing class instantiated | No-new-class reason |
| --- | --- | --- |
| router `x * W_router` | committed-GEMM Thaler/blind sumcheck + `BlockClaim` | same weight/activation claim as existing projections |
| router requant and score bound | existing signed-i16 chained range/requant site | new public shift, unchanged relation and no extra content |
| exp and reciprocal | existing stable-exp and reciprocal LogUp sites in one `TableBank` | content already exists and shares phase ordering |
| normalized score | existing Hadamard/`Pi_Prod`, linear row-denominator closures and requant | same softmax product pattern |
| public selected ids and `theta` gather | C3b public selector/weighted-row sumcheck and `Pi_ZeroBatch` | public selectors are the causal-mask class |
| affine `c_j` bridge | C3b private-argmax packed-selector bridge | selector and strict bits are public constants |
| nonnegative comparison | one u16 decomposition + shared `Range(16)` TableBank content | existing range limbs, no bespoke comparator |
| distinct/count/canonical-slot metadata | deterministic verifier preflight | wholly public relation, no proof primitive |

The comparison multiplicities bind in TableBank phase 1 before its existing
content alpha.  Routes and `tau` are fixed before that boundary and before
any selector challenge.  No score or threshold is opened in clear.

### 4.4 Permanent cheating smokes and gate

The permanent X1 tests are:

- replace one selected id with an unselected id (`wrong_expert_set`) -> reject;
- swap two private score cells after the router-score proof is fixed
  (`score_swap`) -> reject at the selector/comparison bridge;
- alter one comparison limb while keeping metadata fixed (`forged_limb`) ->
  reject through Range/linear reconstruction;
- an all-equal row emits canonical vector `[28,29,30,31]` with `tau=28` and
  accepts;
  selecting expert 27 instead, or declaring a worse tied cutoff, rejects.

Duplicate/out-of-range ids and a cutoff outside the selected set also reject
at public preflight.

The analytic X0 comparison geometry, now emitted by `budget_moe.py`, is:

```text
logical comparisons       = 31 * 4 * 32 = 3,968
padded comparisons        = 4 * ceil_pow2(31 * 32) = 4,096
C3b comparison anchor     = 157,705,530 / 7,864,320
predicted ctr_instances   = 82,138.296875 E-mult
prediction/token-layer    = 662.4056199596774 E-mult
```

X1 measures the isolated `ctr_instances` delta with the top-k
comparison/selector bridge enabled versus disabled; router GEMM and
exp/reciprocal construction are reported separately.  The preregistered
acceptance band is measured/predicted in **`[0.80, 1.20]`**, equivalently
`[529.924495967742, 794.8867439516129]` E-mult/token-layer.  Both endpoints
are inclusive.  Honest acceptance, every rejection above, exact
3,968/4,096 geometry, prover/verifier counter equality and allocation/channel
digest equality are also binding.  Any FAIL closes X1 FAIL; the band is not
relaxed after measurement.

**Measured outcome (clean `6be165f`): PASS.**  The isolated bridge measured
`87,702.4` E-mult total, `707.2774193548387` per token-layer, and a
measured/predicted ratio of `1.0677406683202548`.  Every preregistered
cheating/preflight smoke rejected, the crafted tie accepted the exact D1
vector `[28,29,30,31]`, and the unchanged PCS/closure/digest gates passed.
The append-only evidence is
`benchmarks/results/x1-routing-2026-07-19-6be165f.json`; exact counters and
the two explicit reused/layout deviations are recorded in the ledger.

## 5. X2 two-layer MoE e2e

### 5.1 Pinned CPU shape and route fixture

The script profile and command of record are:

```text
python3 scripts/budget_moe.py \
  --model x123-synthetic --prompt-tokens 7 --decode-tokens 0 --thin-k 1
python3 scripts/budget_moe.py \
  --model x123-synthetic --prompt-tokens 7 --decode-tokens 0 --thin-k 2

L=2, T=7, d=48, d_ff=80, heads=6, kv_heads=2, head_dim=8
experts=8, top_k=2, vocab=97, full-causal band in both layers
```

X2 deliberately uses the already implemented GELU expert body
`up -> GELU -> down`; X3 owns the later SwiGLU addition.  This preserves the
required X1 -> X2 -> X3 order while X2 exercises sparse gather, per-expert
GEMMs, weight claims, scatter/combine, TableBank composition and T1 seams.

Layer 0 uses these public routes by token:

```text
[0,1], [2,3], [4,5], [6,7], [0,2], [1,4], [3,5]
```

Layer 1 adds one modulo eight to every id.  Each layer therefore has the
balanced public expert-row histogram `[2,2,2,2,2,2,1,1]` up to rotation and
touches all eight experts.  X1 proves the route set before X2 consumes it.
The two weights associated with each route remain private router scores.

### 5.2 Proof/session composition

For each layer, public selectors gather compact token rows into eight public
expert jobs.  Touched experts run batched committed `up` and `down` GEMMs;
their GELU and requants use existing LogUp sites.  Public selectors scatter
the results back.  The private route-weight times expert-output products use
the existing Hadamard/`Pi_Prod` class, their public scatter sum is linear, and
the final combine requant is the existing range site.  There is no private
permutation, ORAM, per-expert commitment, per-token proof or per-token PCS
claim.

The whole two-layer response uses exactly one `TableBankP/V` two-phase
session.  Router, attention, normalization, eight expert cohorts and combine
multiplicities all bind in phase 1; every content draws its one existing
alpha only after finalization; all site proofs run in phase 2.  There is no
expert-local table side or alpha.

D3 is instantiated as three commitments: one per layer with aligned
attention/router/expert blocks and one global embedding/output commitment.
The fixed route touches every expert, so there are exactly 40 stacked claims
in one current-Ligero batched opening.  X4 is not used or anticipated by this
synthetic result.

The same native witness and public routes run twice:

- `thin_k=1`: no cross-layer seam is skipped;
- `thin_k=2`: layers `[0,1]` form one T1 group, using the already-proved
  downstream-to-upstream eq reducers and q-claim transport.  It retains the
  chunk entry and group exit and never crosses the chunk.

Both variants must produce identical logical model outputs and route/combine
results.  The k=2 proof must pass the permanent T1 internal-state and
chunk-boundary substitution smokes in addition to the X1 smokes.

### 5.3 Analytic counter gate

The pinned `budget_moe.py` values are:

| Counter | Prediction |
| --- | ---: |
| native integer MACs | 316,464 |
| logical lookup rows | 12,495 |
| padded lookup rows | 19,313 |
| lookup sites | 80 |
| sub correlations, k=1 | 330,820 |
| sub correlations, k=2 | 330,484 |
| full-correlation planning proxy, each | 17,040 |
| commitments / stacked claims | 3 / 40 |

The lookup-multiplicity component is 327,936 authenticated values: shared
`ln_rsqrt`, exp, reciprocal, GELU and `Range(16)` contents plus the pinned
`Range(8)` requant content.  X3-only SiLU and saturation contents are absent.

For both k values, prover and verifier must first agree **exactly** on every
operation count, sub/full correlation count, allocation digest, channel
digest, claim count, proof-section length and TableBank site/content count.
For the vector listed above, each measured/predicted ratio must then lie in
the inclusive interval **`[0.80, 1.20]`**.  Commitments/claims and the single
TableBank finalization are additionally exact invariants (`3`, `40`, `1`).
The full-field proxy is gate-eligible only for this pinned synthetic schedule;
closure replaces it with the measured exact allocation count.  E-mult buckets,
proof bytes, wall, RSS and verifier wall are reported diagnostics, not hidden
and not substituted for a predicted counter.

**Measured outcome (clean `87ce25b`): FAIL.**  Both k=1 and k=2 honest
proofs, the shared TableBank session, three unchanged-P4 commitments, 40
claims, product/zero closures, golden, allocation/channel parity and every
cheating smoke pass.  MACs are exactly 316,464.  Logical/padded/site counts
are 12,523 / 19,346 / 82, ratios 1.0022408963585434 /
1.001708693626055 / 1.025.  Sub correlations are 350,304 at k=1 and 349,793
at k=2, ratios 1.058896076416178 / 1.0584264291160843.  Full correlations
are 12,462 and 12,482 against the frozen 17,040 proxy, ratios
0.731338028169014 / 0.7325117370892019: both are below 0.80 and therefore
FAIL.  No band or prediction is changed.  The append-only evidence is
`benchmarks/results/x2-moe-2026-07-19-87ce25b.json`; per section 7.3, this
verdict stops the package and X3 was not started.

## 6. X3 operations pack on the band path

X3 reuses the X2 toy artifact and `T=7`, `d=48`, `d_ff=80`, but changes the
model operation configuration to RMSNorm, clamped SwiGLU, RoPE, GQA 6/2,
two attention sinks per query head, and layer windows `[full, sliding(4)]`.
The lower-edge layer therefore has real windows of lengths
`[1,2,3,4,4,4,4]`.  All full-array goldens and proofs use row pad 8, hidden
pad 64 and FFN pad 128.

| Operation | Fixed integer/reference contract | Existing proof machinery |
| --- | --- | --- |
| RMSNorm | omit mean subtraction; exact i64 sum-of-squares, existing rsqrt input/table/output, public gain and existing requant | LayerNorm square/Hadamard, small authenticated stats, LogUp and range subset |
| SwiGLU | expert gate/up GEMMs; SiLU table on gate; explicit config clamp bounds; gate/up saturation side-table entries; Hadamard product; down GEMM | content-keyed LogUp, existing saturation/range pattern, Hadamard/`Pi_Prod`, committed GEMM |
| RoPE | public quantized coefficient table; paired Q/K rotation is folded into the existing QK bilinear/score accumulation before its existing score requant; no RoPE table lookup | public-linear coefficient fold inside existing blind QK sumcheck; `Pi_ZeroBatch` closures |
| GQA | `q_head -> floor(q_head/3)` public map; only two KV heads are stored/authenticated and reused by six query heads | existing `CacheSeg`, public selector fold and band QK/AV arguments |
| attention sinks | one authenticated `6 x 2` vector per layer enters the shifted-exp/denominator row identity and softmax product | existing auth, exp LogUp, row-sum zero relation and Hadamard/`Pi_Prod` |
| sliding window | `lo(i)=max(0,t0+i+1-window)`, `hi(i)=t0+i+1`; only `[lo,hi)` is real | `BandShape` public real-cell/lower-edge selector, existing band/cache proofs |

RoPE adds **zero new lookup rows**: it has no nonlinear table and shares the
already existing score requant.  K and V are authenticated in their canonical
pre-RoPE/GQA-width cache representation; the public RoPE coefficients are
applied when QK consumes K.  No rotated-K cache or cleartext K/V opening is
introduced.

SwiGLU clamp changes table content, not argument class.  If the exact clamp
semantics cannot be expressed by the existing saturation-side lookup plus
linear/Hadamard relations, X3 hard-stops rather than adding a comparator.

The X3 gate is full-array bit-exactness between Rust and numpy, op by op and
for the integrated two-layer band witness.  It covers RMS statistics/output,
SiLU/clamp/product/output, RoPE pairs and QK scores, grouped K/V reads, sink
denominators/weights, lower-edge masks and final outputs.  Every honest proof
accepts and a one-cell tamper at each op boundary rejects through the mapped
existing relation.

The deliberate pad test fills source padding with distinct nonzero sentinels,
including wpe row 7 and hidden columns 48--63.  Canonical witness/commitment
construction must ignore and overwrite them, numpy/Rust logical outputs must
remain identical, and a verifier mask or claim that includes one sentinel
must reject.  Passing only a power-of-two companion case is insufficient.

## 7. Golden files, records and milestone closure

### 7.1 Synthetic fixtures

Phase 2 creates small committed fixtures under `tests/fixtures/x123/`:

- `toy-moe-v1.config.json`: canonical runtime config and block map;
- `toy-moe-v1.artifact.bin` plus manifest: deterministic BF16/MXFP4-interface
  sources converted to i16, shifts and LUT contents;
- `x1-router-v1.golden.bin`: raw/requant/exp/reciprocal scores, selected ids,
  cutoff, comparison values and limbs for all 124 token-layers;
- `x2-moe-v1.golden.bin`: per-layer gathers, expert up/GELU/down tensors,
  route weights, combined outputs and both k schedules;
- `x3-ops-v1.golden.bin`: full inputs/outputs for every X3 op and the
  integrated band witness, including real masks and canonical pads.

All files have a versioned magic, dimensions, little-endian integer payloads
and SHA-256 entries in the manifest.  The generator uses fixed public seeds
and writes only these small synthetic fixtures.  Tests load the files; they
do not regenerate expected values in-process with the same Rust code under
test.  Artifact/config/exporter/golden hashes are copied into every record.

### 7.2 Append-only record names

Clean CPU records are append-only and never overwrite an earlier run:

```text
benchmarks/results/x1-foundation-<date>-<gitsha>.json
benchmarks/results/x1-routing-<date>-<gitsha>.json
benchmarks/results/x2-moe-<date>-<gitsha>.json
benchmarks/results/x3-ops-<date>-<gitsha>.json
```

Every record includes full SHA, `git_dirty:false`, four-worker CPU identity,
shape/config/golden/exporter hashes, exact prover/verifier counters, bytes,
correlation/allocation/channel digests, proof acceptance and every gate
operand/verdict.  Timed ratios, if any are added as diagnostics, use
same-process ABBA/`time_paired`; sequential ratios are ineligible.  Counts
and bytes are exact integers.

### 7.3 Per-milestone ledger-row contract

Each boundary follows the scaling-note section-5 contract:

1. run the preregistered gate without changing its threshold;
2. write the clean append-only JSON;
3. add/update the milestone row and a verbatim PASS or FAIL ledger entry,
   including measured-versus-X0 deltas and every deviation;
4. commit that milestone checkpoint before starting the next one.

The ModelConfig foundation is its own checkpoint before `x1-routing`.  X1,
X2 and X3 each close separately.  A FAIL is recorded verbatim and stops the
package.  No checkpoint, projection or development run is itself a verdict.

## 8. Phase-1 disposition

Phase 1 pins the architecture/refactor choice, layouts, exporter contract,
router statement and limb proof, synthetic shapes, analytic bands, op
coverage, goldens, record names and closure discipline.  Phase 1 itself
authorized no implementation; the subsequent explicit Phase-2 approval is
recorded in the ledger and does not alter any pin or threshold above.

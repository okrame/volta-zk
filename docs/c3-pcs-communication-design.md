# C3 PCS/logits communication package

**Status (2026-07-18): C3b is CLOSED; G1, G2, G3 and G4 PASS on clean
`161fc59`.** The Phase-1 diagnosis and
preregistration amendment were reviewed before implementation, including the
pinned pod G2 denominator and removal of the L4-off mode. The immutable C3 table still
measures 105,725,808 B packed response. C3b keeps the selected PCS design and
communication win while replacing the inefficient private-argmax geometry
and host-streamed resident path described below.

## 1. Frozen baseline and scope

The clean C1 reference is
`benchmarks/results/c1-2026-07-15-2a3d731.json`; fase-D preserves the same
communication byte-for-byte. At T=100+50:

| Category | Bytes | C3 treatment |
| --- | ---: | --- |
| PCS opening | 66,733,504 | L1--L3 |
| `auth_corrections` | 59,545,008 | unchanged |
| packed public logits | 7,407,122 | removed by L4 |
| remaining transcript | 2,840,896 | unchanged before the L4 argument |
| **packed response** | **136,526,530** | binding old reference |

The remaining-transcript row is the exact subtraction
`136,526,530 - 66,733,504 - 59,545,008 - 7,407,122`.

C3 uses exactly the four authorized levers: code-rate/query re-resolution,
embed reshape, block-preserving commitment consolidation, and a private-logit
greedy-argmax argument. It does not use verifier-cached columns or linear
cross-point claim merging: the 2026-07-15 ledger entry proves those sketches
unsound. Corrections remain 8-byte F_p values; Packed16, boundary thinning,
PCG/setup/lifecycle changes, per-token openings or PCS claims, and all Lean
changes are excluded. Openings still resolve into VOLE-authenticated values
and there remains one batched opening per response and per commitment tree.

## 2. L1 soundness re-resolution

Let `E = F_p^2`, where `p = 2^64 - 2^32 + 1`. For a commitment with `R`
matrix rows, `G` claims, effective rate `r = (cols + 512) / code_len`, and
`Q` fresh queries, C3 uses the conservative statistical union bound

```text
epsilon_tree = (1 - (1-r)/2)^Q       query/proximity term
             + R/|E|                 row-combination RLC
             + (G+1)/|E|             claim RLC plus MAC/ZeroBatch term
             = (1 - (1-r)/2)^Q + (R+G+1)/|E|.
epsilon_response = sum(epsilon_tree over every opened tree).
```

The final `1/|E|` in `(G+1)/|E|` is the M9/zero-opening term; it is not
silently omitted or counted again. Merkle collision resistance is the same
unchanged computational assumption as in the current PCS and is not folded
into this statistical number.

For the current 12 layer trees (`R=1024,G=8`) plus one embed tree
(`R=8192,G=6`), `r=0.515625` and Q=200:

```text
epsilon_query   = 13 * 0.7578125^200 = 1.0624200937199772e-23
epsilon_field   = 20,595 / |E|       = 6.052326541614587e-35
epsilon_current = 1.0624200937260295e-23
total bits      = 76.31699184442515
```

The familiar 80.017431563-bit number is per tree; 76.316991844 bits is the
response-wide 13-tree union bound that C3 must meet or improve.

The sweep below uses the two consolidated geometries in section 3. “Nominal
rate” is `cols/code_len`; the exact effective rates include the fixed 512
secret message symbols. `Q_min` is the first integer satisfying
`epsilon_response <= epsilon_current`; `Q_pin` is the preregistered operating
point with a small integer margin.

| Nominal rate | Weight/embed effective rates | `Q_min` | `Q_pin` | Total bits at `Q_pin` | PCS bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 1/2 | 0.531250 / 0.5078125 | 199 | 200 | 76.993514040 | 60,605,728 |
| **1/4** | **0.265625 / 0.25390625** | **117** | **120** | **78.809294874** | **43,273,888** |
| 1/8 | 0.1328125 / 0.126953125 | 94 | 97 | 78.866516497 | 38,296,040 |

At the selected point,
`epsilon_response = 1.8881578818430648e-24`: it is 2.492303030 bits stronger
than the current response-wide configuration. Fresh queries are drawn after
all prover messages for every response; no query or column is cached or
reused.

### 2.1 Storage and one-off/per-response cost sweep

The wall columns are projections, not gate evidence. They scale the clean C1
CPU commit median 7.194570 s and the fase-D pod commit median 0.128612 s by
resident encoded-symbol count. Mask wall is an NTT-work projection from the
full P3.5 mask measurement. They are retained only as the selection rationale;
the measured C3b closure values are in Section 6.

| Nominal rate / `Q_pin` | Encoded codewords | CPU commit proj. | A100 commit proj. | Mask F_p2 symbols / response | Mask NTT work vs current | CPU mask proj. |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| current 13-tree 1/2 / 200 | 5,368,709,120 B | 7.195 s measured | 0.129 s measured | 3,768,320 | 1.000x | 0.080 s |
| 1/2 / 200 | 4,311,744,512 B (4.016 GiB) | 5.778 s | 0.103 s | 2,048,000 | 0.523x | 0.042 s |
| **1/4 / 120** | **8,623,489,024 B (8.031 GiB)** | **11.556 s** | **0.207 s** | **4,096,000** | **1.119x** | **0.090 s** |
| 1/8 / 97 | 17,246,978,048 B (16.063 GiB) | 23.113 s | 0.413 s | 8,192,000 | 2.384x | 0.191 s |

The 1/2 point cannot meet the 115 MB response gate after L4. The 1/8 point
saves only another 4,977,848 response bytes while doubling the selected
codeword storage and taking mask encoding from 1.119x to 2.384x current.
Nominal 1/4, Q=120 is therefore selected.

The selected codewords add 3,254,779,904 B to the old codeword inventory. The
clean table refresh supersedes the simple 11,280,818,420 B projection: the
A100 run reports 17,303,319,076 B peak inside the measured response session
and 19,362,496,372 B live including the reusable cache before trim, falling to
638,091,280 B after trim. The 80 GB A100 still has more than 60 GB decimal
headroom. Historical C3 used per-response pools because its connection-scoped
harness OOMed when the 110M allocation co-resided with PCS scratch. C3b's
bounded anonymous spool resolves that limitation: the clean connection-mode G1
record peaks at 8.629 GiB on the 11 GiB VM with no per-response-pool fallback.

## 3. L2/L3 commitment geometries

Both trees retain power-of-two data-column and NTT lengths. Only the matrix
row count becomes explicit and non-power-of-two; this preserves the existing
LSB-first column-variable split used by every `BlockClaim`.

### 3.1 Consolidated weights tree

```text
rows=24,576, cols=8,192, pad=512, msg_len=8,704
code_len=32,768, Q=120, claims=96
flat coefficients=24,576*8,192=12*2^24
```

Layer `l` remains the exact existing 2^24 block at offset `l*2^24`. Inside
each layer, the four existing tensor offsets and power-of-two block lengths
are unchanged. A layer occupies 2,048 complete PCS rows. Thus consolidation
replaces 12 separate roots and fixed passes with one without turning the
model into an unstructured monolith: layer and tensor blocks remain
independently addressable by aligned `BlockClaim`s for future sparse/MoE
opening.

### 3.2 Reshaped embed tree

```text
rows=2,080, cols=32,768, pad=512, msg_len=33,280
code_len=131,072, Q=120, claims=6
flat coefficients=2,080*32,768=2^26+2^20
```

The wte 2^26 block occupies rows 0--2,047 and the wpe 2^20 block rows
2,048--2,079. Their coefficients, row-major tensor padding, offsets and claim
points are unchanged; only the old trailing all-zero outer padding to 2^27 is
removed. At the old nominal 1/2 and Q=200 this exact-block reshape projects
the embed opening from 15,214,912 B to 7,283,520 B. Combined with selected L1
it is 5,868,800 B.

The implementation uses checked explicit row counts throughout
commit/open/verify, resident placement, gathers, Merkle leaves and byte
accounting; NTT lengths remain powers of two. Tests cover both production
geometries, a synthetic non-power-of-two row count, block preservation and
tail-claim rejection; the existing T=20 full-model e2e remains green.

### 3.3 Exact selected `byte_breakdown()` projection

| `MultiOpenByteBreakdown` category | Weights tree | Embed tree | Total |
| --- | ---: | ---: | ---: |
| `mask_root` | 32 | 32 | 64 |
| `u_vectors` | 13,508,608 | 3,727,360 | 17,235,968 |
| `corr_ss` | 1,536 | 96 | 1,632 |
| `zero_batch` | 32 | 32 | 64 |
| `column_indices` | 480 | 480 | 960 |
| `data_columns` | 23,592,960 | 1,996,800 | 25,589,760 |
| `mask_columns` | 186,240 | 13,440 | 199,680 |
| `commitment_merkle_paths` | 57,600 | 65,280 | 122,880 |
| `mask_merkle_paths` | 57,600 | 65,280 | 122,880 |
| `columns_total` | 23,894,880 | 2,141,280 | 26,036,160 |
| **`total`** | **37,405,088** | **5,868,800** | **43,273,888** |

This is the existing unpruned two-path formula. No cached-column or Merkle
multi-proof saving is credited.

## 4. L4 greedy argmax without published logits

Fifty public response tokens require 50 argmax statements: the prefill final
row selects token 0 and the first 49 decode rows select tokens 1--49. The
last decode logit row remains an internal witness and selects no response
token. The L4 real-row count is therefore exactly

```text
50 * VOCAB = 50 * 50,257 = 2,512,850 logical range lookups.
```

The rectangular proof domain is `64*65,536 = 4,194,304` entries. The logits
stay bound to the existing final-LN x tied-wte matvec claim, but its random
evaluation becomes authenticated/private instead of
`ProverAuthed::from_public`. No element-wise logit authentication or
correction stream is introduced.

For public token `tau` in a row, the argument forms `d_j=L_tau-L_j`. It uses
the existing range-lookup machinery to prove `d_j >= 0` for every real vocab
entry, and proves `d_j-1 >= 0` for `j>tau`. The latter preserves the current
Rust `Iterator::max_by_key` rule: the public token must be the **last** index
attaining the maximum. A public-token-derived one-hot `is_max` column has
rowsum one and is bound to the logits-difference column by the P5
hadamard-zero argument. Padding entries use a fixed valid range-table pad
value and a zero `is_max` marker. Thus a lower logit token, a later tied
maximum, a moved marker, or a malformed public token rejects; ties at lower
indices remain valid exactly as under the current last-maximum rule.

The range representation covers the full analytic i16-dot-product bound,
not only the golden rows: `|L_j| <= 768*32768^2 = 824,633,720,832`, hence
`0 <= d_j <= 1,649,267,441,664 < 2^41`. Existing limb/range columns must
cover that complete interval without clamp or wrap; a calibration-only table
would reduce verifier capability and is forbidden.

The preregistration estimated L4 from one logical comparison per real vocab
entry:

```text
added lookups                 2,512,850
added E-mult ceiling        252,792,710
C1 E-mult reference       2,618,017,868.8
relative E-mult increase          9.656%
```

The implemented full-bound representation has three u16 limbs for `d` and
three for `d-1`, hence six Range(16) instances over the padded rectangle:
**25,165,824** range-instance entries. The production-geometry L4 e2e
measures **712,224,541.2 E-mult equivalents in `ctr_instances` alone** over
the public-logit path; Hadamard and other work are additional. This
superseded the 252,792,710 projection and motivated C3b. The binding same-host
G2 results are recorded in Section 7.

Transcript additions remain logarithmic. Exact label accounting is
**66,016 B**, 480 B above the preregistered 65,536 B allowance. This does not
change either response-byte threshold, but it is recorded as a deviation in
the ledger rather than silently retaining the old projection.

### 4.1 C3b Phase-1 H2D and kernel diagnosis

The resident C3 implementation constructs the six padded limb columns and
the shared Range(16) multiplicity histogram on the host. Each call to
`BlockCtxP::inst` enters the incremental
`prove_engine_resident_from_host_leaves` bridge, which uploads both the
packed base-field leaf and its base-lifted F_p2 aux column. At one full
response repetition, the direct C3 L4 uploads are:

| Host source / upload | Bytes per upload | Uploads | Total bytes |
| --- | ---: | ---: | ---: |
| Range(16) `Vec<u32>` multiplicities | 262,144 | 1 | 262,144 |
| packed lookup leaf `Vec<u64>[2^22]` | 33,554,432 | 6 | 201,326,592 |
| base-lifted aux column `Fp2Repr[2^22]` | 67,108,864 | 6 | 402,653,184 |
| upper-round challenge points (lengths 1--20) | variable | 120 | 20,160 |
| leaf challenge point (21 F_p2) | 336 | 6 | 2,016 |
| aux external-claim points | variable | 6 | 5,040 |
| aux column ids | variable | 6 | 60 |
| aux fold weights | variable | 6 | 480 |
| **direct L4 subtotal** |  |  | **604,269,676** |

The private-logit integration also replaces ordinary matrix-point openings
with weighted-row openings. For the prefill row this moves 192 B instead of
176 B; for the 50-row decode band it moves 960 B instead of 256 B. The net is
another **720 B**, for an exact L4 on-minus-off H2D delta of **604,270,396 B**.
Every witness-sized row above is uploaded once per response repetition; none
is retained across repetitions.

This reconciles the measured counters byte-for-byte. On the 2026-07-18
same-host mock controls, H2D is 633,510,960 B with L4 and 29,240,564 B with
L4 disabled. The same pod's fase-D geometry control is 28,594,644 B, so the
full C3 delta is 604,916,316 B: L4 explains **99.8932%** and the remaining
645,920 B is the L1/L3/PCS-geometry residue. The direct buffers alone explain
99.99988% of the isolated L4 delta. This confirms D2 rather than merely
inferring it from the old aggregate counter.

The fail-closed CUPTI activity census contains 1,414,565 concurrent-kernel
records, 64 demangled families and zero dropped records. One kernel record
whose text was interrupted by the application's stdout JSON was reconstructed
before parsing; the raw trace and every parser/instrumentation hash are bound
in `c3b-cupti-kernel-census-2026-07-18-5a2edbe.json`. The largest within-trace
families are `logup_round_eval` (15.385%), `reduce_round` (11.028%),
`chacha8_prover_secret_fp_rows_kernel` (10.799%), `logup_fold` (8.892%),
`logup_aux_round_eval` (7.781%), `fp2_fold_rows` (7.703%) and the already
optimized `matrix_fold_kernel` family (5.909%). LogUp round/reduce/fold grids
span x=1--2,048, aux rounds x=1--4,096, F_p2 row folds x=1--32,768 and matrix
folds the recorded set x={1,2,3,4,6,8,16,30,32,58,64,128,150,233,256,300,
1,024,1,536}, all with the recorded blocks in the raw artifact.

The original C3 source diff added no CUDA or `volta-accel` kernel family. Grid-x=1 is
present in the existing reduction tails, scalar helpers and the legacy
small-term matrix-fold path; there is no new C3 family with the old P7b
large-term grid-x=1 pathology. The C3b post-implementation census records
1,423,901 launches, 69 families and zero dropped records. Its five new
`private_argmax_*` families use grid-x 64--16,384; none uses grid-x=1.
The audit therefore PASSes. CUPTI absolute walls are deliberately ineligible
for G2/G4.

The same-host wall-only+counters ablation used one warmup plus three measured
repetitions and the mock PCG backend so setup could not contaminate the
online delta:

| Configuration | Prove-response median | Samples | H2D |
| --- | ---: | --- | ---: |
| fase-D geometry control, Q=200 | 4.911634 s | 4.896895 / 4.911634 / 4.935140 | 28,594,644 B |
| C3 geometry Q=120, L4 off, logits published | 4.801484 s | 4.801484 / 4.814567 / 4.780371 | 29,240,564 B |
| C3 geometry Q=120, L4 on | 9.776394 s | 9.760156 / 9.776394 / 9.890984 | 633,510,960 B |

L4 therefore costs **4.974910 s** in this experiment, 50.887% of the current
L4-on prover wall. C3 geometry without L4 is 0.110150 s / **2.243% faster**
than the same-host fase-D geometry control; prefill and decode marginal are
2.743% and 1.466% faster. Phase 1 therefore finds no hidden L1/L3 GPU
regression. The L4-off binary is dirty, publishes 7,407,122 B of logits and is
recorded only as a diagnostic; it cannot satisfy or be promoted into any C3
gate. The aggregate is
`c3b-l4-ablation-diagnostic-2026-07-18-5a2edbe.json`.

### 4.2 Minimal-limb statement and last-tie semantics

The frozen quantization spec makes every tied-wte logit a 768-term product of
two i16 values with no requantization. Consequently

```text
|L_j| <= 768 * 32768^2 = 824,633,720,832 < 2^40.
```

C3b retains the conservative pinned operand envelope `|L_j| < 2^B` with
**B=41**; it does not calibrate to the golden prompt. For
`d_j = L_tau - L_j` and `a_j = [j>tau]`, both `d_j` and
`s_j = d_j-a_j` have absolute value below 2^42 before the max constraint is
applied. If an L-limb unsigned range proof accepts a negative integer through
its canonical field residue, that residue would have to lie below 2^(16L).
This is impossible whenever

```text
2^(16L) + 2^(B+1) < p,  p = 2^64 - 2^32 + 1.
```

For L=3, `2^48 + 2^42 < p`; all honest nonnegative values fit below 2^48,
and every bounded negative residue lies above that range. L=2 is incomplete:
2^32 cannot cover valid positive logit differences approaching 2^41. Thus
**three u16 limbs are minimal** for the pinned statement. No requantization,
truncation or lossy pre-comparison is allowed; the proof remains bit-exact on
the full i64 golden-decode logits, including near ties.

Current C3 separately decomposes `d` into three limbs and `s` into three
limbs. The first triple proves non-strict maximality and the second proves the
strict half of the tie rule. C3b keeps only the three limbs of `s` and binds

```text
d_j = s_j + a_j
L_tau - L_j = d_j.
```

For `j<=tau`, a_j=0 and `s_j>=0` proves `L_tau>=L_j`. For `j>tau`, a_j=1
and `s_j>=0` proves `L_tau>L_j`. At `j=tau`, a_j=0 and s_j=0, so the existing
is-max Hadamard zero can use `s` instead of a separately ranged `d`. This is
the same statement as the six-column proof, with the duplicate range
representation removed.

Rust's `(0..len).max_by_key(...)` returns the **last** equal maximum. C3b
therefore preregisters two explicit tests: a crafted row with equal maxima at
indices `a<b` must make native decode choose `b` and the proof for `b` accept;
forging public token `a` against that same witness must reject at closure.
The existing wrong-token test remains, and a forged-limb test must show that
changing any reconstructed `s` limb rejects.

### 4.3 Packed range geometry and cost amendment

Five positions fit in one 2^18 segment:

```text
5 * 50,257 = 251,285 <= 262,144       (4.321% segment padding)
```

The 50 positions form ten such public segments. Per limb, C3b schedules eight
segments as one 2^21 job and two as one 2^19 job. Hence

```text
real comparisons / limb       2,512,850
padded entries / limb         2,621,440 = 2^21 + 2^19
padded / real                  1.043213881 <= 1.15
three-limb padded total        7,864,320
old six-limb padded total     25,165,824
new / old                          0.3125
```

This is one logical flat batch per limb containing exactly two power-of-two
LogUp jobs, six jobs total across all three limbs. It is never 50
per-position instances. Segment starts, real-vocab masks and position ids are
public constants/selectors of the same class as the causal mask. All six jobs
enter one existing batched LogUp schedule and consume the one shared
Range(16) content through `TableBankP/V`; the aggregate multiplicity is bound
in protocol phase 1 before the existing shared alpha. There is no second table or
second alpha.

Linear scaling of the measured instance counter gives the central projection

```text
712,224,541.2 * 0.3125 = 222,570,169.125 E-mult equivalents.
```

The amended preregistration ceiling is **260,000,000 L4
`ctr_instances` E-mult equivalents**, 9.931% of the 2,618,017,868.8 C1
reference; the central projection is 8.501%. This is a projection to compare
against the Phase-2 measurement, not a substitute for G2. The exact C3b
measurement is **157,705,530**, 39.3% below the ceiling and 29.1% below the
central projection.

The old 65,536 B L4 allowance is honestly amended to the measured **66,016 B**.
C3b does not spend engineering effort to recover 480 B. Three limbs and
shallower 21/19-round jobs should make the transcript slightly smaller; the
conservative projection is no larger than the immutable C3 packed
**105,725,808 B**, while the binding G1 gate remains **<=115,000,000 B**.
No response bytes may be traded back for wall time.

### 4.4 C3b implementation contract and result

Phase 2 was explicitly authorized by the user on 2026-07-18. Its binding
requirements are:

1. After the resident lm_head matvec, logits remain on device. Diffs,
   selectors, three-limb decomposition, is-max columns and Range(16)
   multiplicity histograms are produced from those resident logits on device.
   In steady state no witness-derived L4 buffer crosses host-to-device and no
   repetition re-uploads one. Only challenges/seeds and the roughly 66 KB L4
   transcript may cross the bus. Full real-session H2D is asserted
   **<=100,000,000 B**.
2. Every L4 allocation joins the existing resident-workspace accounting and
   explicit resident cleanup remains exactly 0 B at session end.
3. The six power-of-two jobs run in one flat batch. The post-implementation
   CUPTI census confirms no new degenerate family outside the legacy
   terms<256/terminal path.
4. The shared two-phase TableBank alpha ordering above is unchanged: all
   multiplicities bind before alpha, with no separate Range(16) instance.
5. The CPU path uses Rayon over position blocks and limbs. The clean paired
   ABBA result is +14.5365%, within the +15% G2 ceiling.
6. The connection-scoped CPU harness retains fase-D's canonical expansion but
   serializes the terminal 110M correlation pool into an anonymous unlinked
   0600 file in 2^16-entry chunks. Responses range-read directly into their
   final pools and discard read page-cache ranges, so raw connection vectors
   do not co-reside with PCS scratch. Allocation/channel digests, one-time
   domain order, the connection Delta, setup traffic and burn/lifecycle
   semantics remain unchanged. There is no per-response-pool fallback.
7. Crafted-tie acceptance, forged-tie rejection, wrong-token and forged-limb
   rejection, exact limb/domain counters and both production-size leakage
   smokes pass; the full workspace and adversarial suite are green.
8. The Phase-1 L4-off/public-logit diagnostic scaffolding was removed before
   the records. No record-capable binary or mode can disable L4 or republish
   logits.

L1 stays pinned at nominal rate 1/4, Q=120, 78.809294874 response-wide bits
and 43,273,888 B. C3b changes no PCS parameter, correction stream, Lean
theorem, setup/PCG tuple, lifecycle rule or public capability.

The implementation produces the comparison witness directly from resident
logits, with device-side strict differences, three-limb decomposition,
selectors and Range(16) histogram. Three logical limb batches contain the six
2^21/2^19 jobs and reuse the existing shared Range(16) TableBank alpha. Exact
production-geometry tests measure **157,705,530 L4 E-mult equivalents**, below
the 260M ceiling, and **57,840 B** of L4 transcript. The resulting exact full
transcript reference is **105,717,632 B**, including the unchanged
43,273,888 B PCS opening and zero public logits.

A pre-record full mock pod diagnostic (one warmup plus three repetitions)
measures prove-response **4.924231 s**, maximum H2D **29,267,044 B**, maximum
absolute synchronization wall **0.120330433 s**, flat ratio **1.246401384**
and explicit resident cleanup **0 B**. These observations demonstrate the
intended recovery but remain ineligible for G2/G4 because they are dirty/mock
diagnostics. The clean real/AES records remain the only gate evidence.

## 5. Blinding, masks and leakage budget

The selected commitment-pad inventory is:

| Item | Weights | Embed | Total |
| --- | ---: | ---: | ---: |
| rows x 512 F_p pads | 12,582,912 | 1,064,960 | 13,647,872 |
| pad storage | 100,663,296 B | 8,519,680 B | 109,182,976 B |
| fresh queries/tree | 120 | 120 | 240 |
| unused one-opening pad headroom/tree | 392 | 392 | -- |

Each tree has independent pads. Q=120 is at most 512, so one response opening
reveals at most 120 distinct encoded positions in either tree and preserves
392 symbols of the existing one-opening hiding budget. Query headroom is not
pooled across trees and is not a license for cached/repeated queries. As in
the current preregistration, cumulative openings of one fixed padded
commitment are outside the one-opening leakage claim. C3b record mode retains
the one-response commitment-use policy. Production-size two-weight-set
leakage smokes for both geometries were run sequentially on the 11 GiB VM and
PASS. A future multi-response
lifetime policy requires a separate pad/recommitment design.

Fresh response masks are one proximity row plus one row per claim: 97 weight
rows and 7 embed rows. Their compact secret material is 17,235,968 B and
their encoded transient is 4,096,000 F_p2 symbols / 65,536,000 B. The opening
draws 102 full correlations for `s_g` plus two for the per-tree ZeroBatch,
**104 full correlations**, versus 102+13=115 today. All are one-time,
domain-separated and allocation-digest counted; the fase-D generator,
connection lifecycle, setup tuple and pool sizes do not change.

## 6. Clean records of closure

The exact packed response is **105,717,632 B**: 43,273,888 B PCS,
57,840 B C3b L4 transcript contribution, zero public logits and the unchanged
remaining protocol labels. It is 9,282,368 B below the G1 ceiling. Current
schema-9 Rust/Python validators bind this reference; historical profiles and
artifacts retain their old values.

Upper medians from one warmup plus three measured repetitions on clean
`161fc59` are:

| Prompt 100 + response 50 | CPU VM, 4 threads | RunPod A100, 8 threads |
| --- | ---: | ---: |
| Prove prefill | 10.104710 s | 2.536909 s |
| Prove decode marginal | 8.261699 s | 1.652746 s |
| Prove response | 18.366409 s | 4.183011 s |
| Full response-session wall | 30.445719 s | 5.600620 s |
| Accounted verifier | 0.468319 s | 0.910903 s |
| PCS commit / open / verify | 10.785629 / 0.767759 / 0.080496 s | 0.202467 / 0.294423 / 0.079365 s |
| Flat last/first | 1.162607 PASS | 1.228451 PASS |
| Real-PCG setup | 67.899078 s | 48.838775 s |
| Setup traffic | 38,371,465 B | 38,371,465 B |
| Peak RSS | 8.628704 GiB | 8.160240 GiB |

Both records use the same implementation SHA and the true connection-scoped
114,611,091-entry spool; `resident_raw_entries_after_spool=0`. Sources:
`c3b-cpu-real-2026-07-18-161fc59.json` and
`c3b-a100-realpcg-v3-2026-07-18-161fc59.json`. The immutable C3 `5a2edbe`
tables remain historical diagnostics and are not rewritten.

## 7. C3b gate verdict

| Gate | Verdict | Binding evidence |
| --- | --- | --- |
| G1 | **PASS** | Clean CPU T=100+50/Q=120 real/AES connection record; accepted/golden/chunked; exact categories; **105,717,632 <=115,000,000 B**; zero logit bytes; two verified PCS trees; 8.629 GiB peak RSS. |
| G2 CPU | **PASS** | Same-process ABBA: fase-D **17.288046 s**, C3b **19.801130 s**, **+14.5365% <=+15%**; ceiling 19.881253 s. |
| G2 pod | **PASS** | Pinned denominator **4.911634 s** only; C3b **4.183011 s**, **-14.8346%**; ceiling **5.6483791 s**. |
| G3 | **PASS** | Workspace green; crafted/forged tie, wrong-token and forged-limb coverage green; exact geometry; production weights/embed leakage smokes run sequentially and PASS. |
| G4 | **PASS** | `runpod-a100-realpcg-v3`: prefill **2.536909 <=10 s**, decode **1.652746 <=4 s**, H2D **88,812,564 <=100,000,000 B**, max sync **0.114894647 <=0.150 s**, flat **1.228451 <=1.5**, exact bytes/counters/digests and cleanup 0 B. |

The post-implementation CUPTI artifact is
`c3b-postimpl-cupti-kernel-census-2026-07-18-161fc59.json`; G3 details are in
`c3b-g3-2026-07-18-161fc59.json`. No record mode can disable L4 or republish
logits.

## 8. Backlog

The C3b rebaseline is complete. `runpod-a100-v1` stays bound to 144,820,930 B
and fase-D `runpod-a100-realpcg-v1/v2` plus C1 stay bound to 136,526,530 B;
no historical artifact was mutated or reinterpreted.

Backlog only, with no Basefold work authorized under C3: a Basefold/folding
PCS is the structural polylogarithmic replacement for phase X. It must be
co-designed with X4 and scaling-note D3 so per-layer commitments retain
per-expert block granularity and sparse openability. That work reopens the M9
binding hypothesis and the PCS ZK/blinding layer; it is explicitly outside C3.

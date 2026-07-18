# C3 PCS/logits communication package

**Status (2026-07-18): C3b Phase 2 is implemented and locally verified;
clean CPU/pod records and the post-implementation CUPTI audit remain pending,
so this is not yet a G1--G4 verdict.** The Phase-1 diagnosis and
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
full P3.5 mask measurement; Phase 2 must report measured values instead of
promoting these estimates.

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
headroom. The real-PCG online CPU run peaks at 8.616 GiB, but the formal
connection-scoped G1 harness still OOMs on the 11 GiB VM when the 110M
connection allocation co-resides with C3 PCS scratch; table timings therefore
use real per-response pools with setup excluded, while G1 remains pending.

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
supersedes the 252,792,710 projection and makes G2 a material pending risk;
only the required same-host ABBA record decides it.

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

The C3 source diff adds no CUDA or `volta-accel` kernel family. Grid-x=1 is
present in the existing reduction tails, scalar helpers and the legacy
small-term matrix-fold path; there is no new C3 family with the old P7b
large-term grid-x=1 pathology. C3b must rerun this census after batching and
fail the implementation check if a new family has a degenerate grid outside
that legacy terms<256/terminal path. CUPTI absolute walls are deliberately
ineligible for G2/G4.

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
against the Phase-2 measurement, not a substitute for G2.

The old 65,536 B L4 allowance is honestly amended to the measured **66,016 B**.
C3b does not spend engineering effort to recover 480 B. Three limbs and
shallower 21/19-round jobs should make the transcript slightly smaller; the
conservative projection is no larger than the immutable C3 packed
**105,725,808 B**, while the binding G1 gate remains **<=115,000,000 B**.
No response bytes may be traded back for wall time.

### 4.4 C3b implementation contract and pre-record result

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
   CUPTI census must show no new degenerate family outside the legacy
   terms<256/terminal path.
4. The shared two-phase TableBank alpha ordering above is unchanged: all
   multiplicities bind before alpha, with no separate Range(16) instance.
5. The CPU path uses Rayon over position blocks and limbs. Its orientation
   estimate is about +1.5 s on four cores; only paired G2 decides the gate.
6. The connection-scoped CPU harness retains fase-D's canonical expansion but
   serializes the terminal 110M correlation pool into an anonymous unlinked
   0600 file in 2^16-entry chunks. Responses range-read directly into their
   final pools and discard read page-cache ranges, so raw connection vectors
   do not co-reside with PCS scratch. Allocation/channel digests, one-time
   domain order, the connection Delta, setup traffic and burn/lifecycle
   semantics remain unchanged. There is no per-response-pool fallback.
7. Required new coverage is crafted-tie accept, forged-tie reject,
   wrong-token reject, forged-limb reject, exact limb/domain counters and the
   two already registered production-size leakage smokes. The full workspace
   and existing adversarial suite remain green.
8. The Phase-1 L4-off/public-logit ablation switch is diagnostic scaffolding
   only and must be removed before closure. No record-capable binary or mode
   may disable L4 or republish logits; this is checked before G1--G4 records.

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
commitment are outside the one-opening leakage claim. C3 record mode retains
the one-response commitment-use policy, and production-size two-weight-set
leakage smokes are registered for both new geometries. A future multi-response
lifetime policy requires a separate pad/recommitment design.

Fresh response masks are one proximity row plus one row per claim: 97 weight
rows and 7 embed rows. Their compact secret material is 17,235,968 B and
their encoded transient is 4,096,000 F_p2 symbols / 65,536,000 B. The opening
draws 102 full correlations for `s_g` plus two for the per-tree ZeroBatch,
**104 full correlations**, versus 102+13=115 today. All are one-time,
domain-separated and allocation-digest counted; the fase-D generator,
connection lifecycle, setup tuple and pool sizes do not change.

## 6. Measured response and performance

| Packed response category | Measured bytes |
| --- | ---: |
| unchanged `auth_corrections` | 59,545,008 |
| selected PCS opening | 43,273,888 |
| unchanged remaining transcript | 2,840,896 |
| exact L4 transcript addition | 66,016 |
| published packed logits | 0 |
| **packed response** | **105,725,808** |

The following is the canonical table refresh. Values are upper medians of one
warmup plus three measured repetitions on clean `5a2edbe`, with real/AES PCG
pools, golden/chunked acceptance and flat-cost checks. Setup is excluded from
the online walls. The setup rows retain the unchanged connection-scoped
fase-D measurements: the A100 run uses the exact same EPYC 7742/128-vCPU/2-TiB
host as `e95b839`, and C3 does not alter the generator, tuple or setup traffic.

| Voce -- prompt 100 + risposta 50 | Nota | CPU 4 thread | A100 RunPod + 8 worker Rayon |
| --- | --- | ---: | ---: |
| Prova prefill | Prova dei 100 token iniziali | 9.87 s | 2.67 s |
| Prova decode marginale | Prova dei 50 token generati | 11.01 s | 6.43 s |
| Prova risposta totale | Prefill + decode, esclusa l'apertura PCS | 20.88 s | 9.10 s |
| Sessione online completa | Prova, PCS, chiusura e verifica; setup escluso | 36.12 s | 10.36 s |
| Verifica pura | Controllo della prova, esclusa la verifica PCS | 0.363 s | 0.681 s |
| Verifica contabilizzata | Verifica della prova inclusa la verifica PCS | 0.474 s | 0.760 s |
| Token di decode provati/s | 50 token divisi per il tempo della prova totale | 2.39 | 5.49 |
| Setup real-PCG | Preparazione crittografica della connessione | 69.33 s | 48.84 s |
| Traffico preprocessing/setup | Traffico bidirezionale per preparare la connessione | 38.37 MB | 38.37 MB |
| -- prover -> verifier | Parte inviata dal server che prova | 31.58 MB | 31.58 MB |
| -- verifier -> prover | Parte inviata da chi verifica | 6.79 MB | 6.79 MB |
| Transcript della prova | Dati del protocollo, senza logit pubblici | 105.73 MB | 105.73 MB |
| Risposta packed totale | Transcript + logit pubblici packed | **105.73 MB** | **105.73 MB** |
| PCS opening | Quota del transcript che dimostra i pesi privati | 43.27 MB | 43.27 MB |
| Logit pubblici packed | Output necessario per verificare l'argmax | 0 MB | 0 MB |
| Primo scambio totale | Setup bidirezionale + prima risposta packed | 144.10 MB | 144.10 MB |

The 43.27 MB PCS opening is already included in the 105.73 MB transcript. The
real table artifacts are
`c3-table-cpu-real-2026-07-17-5a2edbe.json` (SHA-256
`399934ff895f0129430fa86cd9cc15ef53b9b714241e592fd3c9a391d741195c`)
and `c3-table-a100-real-2026-07-17-5a2edbe.json` (SHA-256
`c2520b2f1310f67352ef82574e1988fb58e320bc4bc6d77da012a74aef08a6ec`).
The paired mock diagnostics are retained append-only as controls.

Against the preceding table, prove-response wall rises by 25.17% on CPU and
112.17% on A100 while packed response falls by 30,800,722 B (22.56%). This
confirms the performance risk from section 4 but is not the binding paired G2
verdict. The A100 diagnostic also measures 693,055,968 B maximum H2D and
0.150158884 s maximum synchronization wall, both relevant to a future G4.
Verifier wall is reported and is never traded for response bytes or
capability.

## 7. Binding C3b closure gates

All append-only Phase-2 artifacts use `c3b-*.json`. The immutable C3
`5a2edbe` table remains a measurement and is never rewritten.

**G1 — clean CPU communication record.** Run full T=100+50, nominal rate
1/4, Q=120, two PCS trees, the real/AES default and the true connection-scoped
streaming configuration on the 11 GiB VM. Use one or more warmups and at least
three measured repetitions from one clean unchanged SHA. Frozen 50-token
golden decode, proof/verifier acceptance, zero public-logit bytes and exact
label/category reconstruction are mandatory. Packed response must be
**<=115,000,000 B**. Current validators are then rebaselined together to the
new exact measured reference; historical validators and JSONs remain bound
to their old references.

**G2 — paired same-host wall on both hosts.** On the CPU VM use `time_paired`
ABBA against the unchanged fase-D binary/configuration; its paired denominator
is measured by that record. For the pod only, the user has pinned the
2026-07-18 same-host fase-D control from the Phase-1 ablation as the sole G2
denominator: **4.911634 s**. The binding pod ceiling is therefore exactly
`4.911634 * 1.15 = 5.6483791 s`, reported to six decimals as
**5.648379 s**. No later control, historical 4.310 s value or alternative
denominator may replace it. Pod measurement remains wall-only+counters and
CUDA-event timing is forbidden. Report verifier deltas as informative. The
L4-off arm remains diagnostic and cannot decide or enter a gate record.

**G3 — capability and adversarial parity.** `cargo test --workspace` plus
all existing golden, normal/chunked, flat-cost, malicious, closure,
allocation-digest, anti-replay and real-backend suites stay green. The
crafted last-tie golden, forged-tie rejection, wrong-token rejection,
forged-limb rejection and exact three-limb/2^21+2^19 domain counters are
mandatory. Both registered production-size leakage smokes must actually run;
this is what claims G3. There is no reduced-capability mode and no fallback
to published logits.

**G4 — fresh RunPod profile.** `runpod-a100-realpcg-v2` remains the immutable
fase-D profile bound to 136,526,530 B and `e95b839`. C3b therefore uses the
fresh profile **`runpod-a100-realpcg-v3`** with the v2
A100-SXM4-80GB/Rayon=8/ABI-28/wall-only/real-AES contract. Binding gates are
prefill <=10 s, decode marginal <=4 s, full-session H2D <=100,000,000 B,
maximum absolute synchronization wall <=0.150 s, flat <=1.5, frozen golden,
normal/chunked acceptance, exact counter/allocation/channel digests, G2
setup/capacity and response bytes equal to the new exact G1 reference (itself
<=115,000,000 B). A post-implementation CUPTI census is attached as
non-gating diagnosis and must satisfy the grid audit in section 4.4.

If any gate fails, record the exact FAIL and attach the kernel census, then
stop. Do not relax a threshold, trade response bytes back, or disable L4 to
pass. No checkpoint, projection, diagnostic or partial run is a verdict.

## 8. Re-baseline ritual and backlog

After G1 measures the clean exact byte reference, Rust and Python **current
C3b validators** are updated together to that value and the v3 profile binds
it. Historical JSONs, milestone rows, selectors and profiles remain bound to
their recorded values: `runpod-a100-v1` stays at 144,820,930 B and fase-D
`runpod-a100-realpcg-v1/v2` plus C1 stay at 136,526,530 B. No old artifact is
mutated or reinterpreted. This is the same append-only re-baseline ritual C1
used.

Backlog only, with no Basefold work authorized under C3: a Basefold/folding
PCS is the structural polylogarithmic replacement for phase X. It must be
co-designed with X4 and scaling-note D3 so per-layer commitments retain
per-expert block granularity and sparse openability. That work reopens the M9
binding hypothesis and the PCS ZK/blinding layer; it is explicitly outside C3.

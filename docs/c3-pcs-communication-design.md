# C3 PCS/logits communication package

**Status (2026-07-17): L1--L4 implemented and the clean CPU/A100 E2E table
refresh is measured; formal G1--G4 remain pending, so this is not a gate
verdict.** The selected PCS design reduces the measured C1/fase-D packed
response from 136,526,530 B to **105,725,808 B**, leaving 4,274,192 B below
the 110 MB design target and 9,274,192 B below the binding 115 MB gate.

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

## 7. Binding Phase-2 gates

**G1 — clean CPU communication record.** Run full T=100+50, nominal rate
1/4, Q=120, two PCS trees, real/AES default, one or more warmups and at least
three measured repetitions from one clean unchanged SHA. Frozen 50-token
golden decode, proof/verifier acceptance and exact label/category
reconstruction are mandatory. The append-only result is
`benchmarks/results/c3-<date>-<gitsha>.json`; packed response must be
**<=115,000,000 B**. The 105,725,808 B figure is now exact in the clean table
diagnostics, but it does not become the validator reference until G1 lands.

**G2 — same-host wall.** On the CPU VM use `time_paired` ABBA against the
unchanged fase-D proving binary/configuration on the same host. Candidate
median prove-response wall may increase by at most **15%**. The historical
fase-D 16.681091 s median implies 19.183255 s only as an orientation value;
the paired same-host denominator is binding. Report verifier delta as
informative. On the pod, use wall-only+counters and run the unchanged
fase-D control and C3 candidate on the same provisioned host; the same +15%
bound applies and CUDA-event timing remains forbidden.

**G3 — capability and adversarial parity.** `cargo test --workspace` plus
all existing golden, normal/chunked, flat-cost, malicious, closure,
allocation-digest, anti-replay and real-backend suites stay green. Add
non-power-of-two PCS row/T completeness and rejection tests, consolidated
layer/tensor `BlockClaim` tests, wrong-token and last-tie argmax tests, and
the leakage smoke for both selected trees. There is no reduced-capability
mode and no fallback to published logits.

**G4 — new RunPod profile.** The requested name
`runpod-a100-realpcg-v2` cannot be new: it is already the immutable fase-D
absolute-sync profile bound to 136,526,530 B and record `e95b839`. Reusing it
would violate the required re-baseline ritual. C3 therefore preregisters the
fresh name **`runpod-a100-realpcg-v3`**, subject to user review here. It
carries the v2 A100-SXM4-80GB/Rayon=8/ABI-28/wall-only/real-AES contract,
prefill <=10 s, decode <=4 s, absolute synchronization <=0.150 s, H2D
<=100,000,000 B, flat <=1.5, G2 setup/capacity, golden, chunked, malicious,
anti-replay and digest gates. It changes geometry to Q=120/two trees and
binds response bytes to the exact clean G1 reference, which must itself be
<=115,000,000 B. The append-only result is
`runpod-a100-realpcg-v3-<date>-<gitsha>.json`. Pod provisioning costs money
and requires a separate user confirmation immediately before provisioning.

Any failed binding gate is recorded verbatim. No checkpoint, projection or
partial run is a verdict.

## 8. Re-baseline ritual and backlog

After G1 measures the clean exact byte reference, Rust and Python **current
C3** validators are updated together to that value and the v3 profile binds
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

# Prototype Status Ledger (P7b — RunPod resident A100)

The implementation-phase analogue of the formalization table in
`protocol-sketch.md`. One row per milestone; key numbers land here, raw runs
land in `benchmarks/results/*.json`. The repo-local plan of record is
`docs/p7-handoff-spec.md` plus this ledger; no external plan is authoritative.

Workload of record: **GPT-2 small (124M, L=12, d=768, h=12, d_ff=3072),
prefill T=100 + 50 deferred decode tokens, causal, PCS Q=200**, on the
designated RunPod A100 profile. P7 is closed; its CPU and rho numbers below
are historical. The active P7b gates and measurement hygiene are the
preregistered 2026-07-14 RunPod-provider deviation below, and P7b currently
has one valid official verdict: decode FAIL, with all other current gates
passing.

## Milestones

| Milestone | Status | Gate | Key numbers |
| --- | --- | --- | --- |
| P0 harness + analytic budget | **done** (2026-07-03) | workspace builds, budget pre-registered ✓ | budget below |
| P1 fused MAC epilogue microbench | **done** (2026-07-03) | ρ_kernel ≤ ~1.3 ✓ **PASSED** | ρ_kernel 1.06–1.11 per shape, 1.06 layer-weighted; epilogue ~2 ns/elem; GEMM 25–31 GMAC/s (4 cores); verifier fused scan 33 ns/elem → 0.37 s prefill-100 (q=3). `benchmarks/results/p1-2026-07-03-5113243.json` |
| P2 authenticated-value layer | **done** (2026-07-04) | e2e auth→open ✓, counters match budget ✓ | Π_Auth/Π_ZeroOpen/Π_ZeroBatch (fresh full-field mask) in `volta-mac`; corrections 8 B/value + 16 B/mask + 16 B/opened tag; soundness smoke 0/1000 forged accepts; P1-epilogue interop test green; counter formula reproduces 3,763,968 auth values |
| P2.5 clear-LogUp constant spike | **done** (2026-07-04) | informative — constant **23.2 E-mult/lookup, >2× budget est. ⇒ iteration plan logged** | 272 ns/lookup @2^23 (single-thread), verify 0.10 s, proof 20 KB; extrapolated prefill-100 LogUp prover 4.6 s vs native 0.30 s (ratio ~15.6 single-thread, ~4 on 4 cores). `benchmarks/results/p2.5-2026-07-04-a13cca4.json` |
| P3 blind sumcheck + Thaler + Π_Prod | **done** (2026-07-04) | GEMM (100×768)·(768×768) proved+verified e2e ✓; ρ decomposed ✓ | ρ_clear 1.49, ρ_blind/clear 2.25, ρ_total 3.34; blind split: fold 3.1 ms + **m_r expand 2.8 ms** + rounds 0.04 ms + Π_Prod 0.01 ms; verify 6.5 ms; proof 352 B (excl. 1.2 MB auth corr); corrs 153,600 sub + 21 full. Attribution: blinding IT ≈ free, cost is Freivalds folds + lazy tag expansion. `benchmarks/results/p3-2026-07-04-cef997d.json` |
| P3.5 static weight PCS (private weights) | **done** (2026-07-04) | opening ≤ 15% native prefill: **FAILED (230%)** — iteration plan logged below; leakage smoke ✓; M9 seam e2e ✓ | In-house Ligero (`volta-pcs`), full 2^27, rate 0.516, Q=200. Commit one-off 3.3 s; opening of record (row-local multi-eval, 220 claims) **0.70 s** = fixed 0.12 s + **~2.3 ms/claim**; verify 0.12 s; 73.8 MB/opening; peak RSS 7.3 GB. Rejected path (generic reduction sumcheck): 5.8 s. `benchmarks/results/p3.5-2026-07-04-1708c66.json` |
| P4 LogUp + fused blocks | **done** (2026-07-05) | one full layer proved+verified e2e (T=100, real PCS opening) ✓ **PASSED**; counts within 20% ✓ (witness streams = budget **exactly**, padded LogUp domains explained); LogUp ≤8–10 E-mult/lookup: **MISSED, motivated (12.20)**; 1 weight claim/tensor ✓ (4/layer) | prove 0.800 s vs native forward 0.033 s (ρ_layer ~24, 4 cores); verify 0.041 s; LogUp lookup-side **12.20 E-mult/lookup** (~34 ns/lookup, 5.4× vs P2.5 spike wall), table-side 3.86 raw → 0.32 /12-amortized; full instance cost 126.5 M E-mult/layer (≈42/padded lookup incl. aux folding + tables + closures); corr bytes 7.64 MB/layer (mult vectors 3.87 MB — see deviations); layer PCS 2^24: commit 0.34 s one-off, **open 0.035 s**, verify 0.006 s; projections (P3.5 cost model, 49/98 claims): prefill **0.233 s**, per-response **0.345 s**. Run of record `benchmarks/results/p4-2026-07-06-8b4ca11.json` (clean tree, `git_dirty:false`; the 07-05 JSON was a dirty-tree run whose sha names the parent commit) |
| P5 GPT-2 e2e prefill 100 tok | **done** (2026-07-06) | one-command run ✓ (`scripts/run_prefill.sh`), golden check ✓ (full logits bit-exact vs numpy at T=100, argmax 835 ' way'), counts vs budget: witness lookups = budget **exactly** (16,944,000) ✓ | **accepted e2e with real weights + 13 real Ligero commitments**: native (witness) 0.459 s, prove 11.0–11.2 s, **ρ ≈ 24** (matches P4's ×12 projection); verify 0.65 s + 0.07 s PCS; PCS open **0.73 s** / 52.8 MB (vs 0.237 s projection — 13× fixed costs, see deviations), commit one-off 7.6 s; **comm 159.6 MB/prefill** (mult vectors 59.4 + PCS 52.8 + boundary 36.9 + rest), projected response 212 MB; E-mult all-in 100.6/budget lookup; peak RSS 2.86 GB. `benchmarks/results/p5-2026-07-06-e52ce79.json` (clean tree) |
| P6 decode + authenticated KV cache | **done** (2026-07-07) | flat cost/token ✓ **PASSED** (curve last/first 1.12 ≤ 1.5, 5×10 chunks, cache 100→150); anti-replay smoke ✓ (prefill-row replay + position swap rejected); golden decode ✓ (50 tokens bit-exact vs numpy) | **accepted e2e, prompt 100 + 50 decode, one two-phase session, real 13-commitment PCS with STACKED claims (96 weight + 6 embed)**: native decode 30.9 tok/s (KV-cached baseline); prove_response 18.7 s = prefill 10.5 s + **decode marginal 8.2 s (0.164 s/token, ρ_decode 5.07 CPU)**; verified 2.67 tok/s; verify 0.57 s + 0.10 s PCS. Comm: transcript 137.4 MB (prefill 48.4 + PCS opening 66.7 + decode marginal 22.3 = **445 KB/token**) + public band logits 20.5 MB → **total response download 157.9 MB** (inside the 150–200 MB product envelope; the PCS opening is now the dominant lever, P7). Shared-α restructure landed with P6: mult corr 59.4 → 2.85 MB. PCS commit one-off 9.5 s; peak RSS 3.47 GB. `benchmarks/results/p6-2026-07-07-515bb1c.json` (clean tree) |
| P7 report + GPU budget model | **complete: resident full e2e + publication artifact; correctness/communication/flat PASS, rho FAIL** (2026-07-13) | T=100+50/Q=200, clean 1+3: golden ✓, proof/verifier ✓, flat 0.950 ✓, packed 144.821 MB ✓, explicit resident cleanup 0 B ✓; same-host exact native anchor ✓; **rho prefill 3707.60 >10 FAIL, decode 95.60 >2 FAIL**; tables/figures, hardware/checksum manifest, synthetic shape sweep and Lean audit ✓ | A100 resident core median: prefill **64.296±0.329 s MAD**, response **121.156±0.373 s**, decode marginal **57.296±0.809 s**. Native GPU: prefill **17.342±0.062 ms**, decode50 **599.346±0.990 ms**. Online-accounted response 121.774 s; full response-session wall 123.928 s; representative session 5.998 s kernels + 89.055 s host residual, 945.442 MB H2D + 138.488 MB D2H, 211,709 sync, 5.405 GB peak GPU. Raw sources `p7-integrated-resident-2026-07-13-1fd5195.json` / `p7-gpu-native-inference-2026-07-13-1fd5195.json`; aggregate `p7-2026-07-13-2c836b3.json`. Mock-PCG remains non-production. |
| P7b iteration 2 resident-A100 orchestration | **closed as superseded diagnosis** (clean quick; no gate verdict) | Historical Thunder count gate retired by the 2026-07-14 provider deviation | Clean schema-6 quick at `61aafe8`: **39,201 sync** (-36.45% vs `bf66c8f`), **12,656,708 B H2D** (-49.19%), prefill 27.154 s, decode marginal 23.628 s. The run remains an immutable, ineligible Thunder diagnostic. Mock-PCG remains non-production. |
| P7b iteration 3 diagnosis | **Phase 0a/0b/0c complete; scheduler phase cancelled as provider-specific debt** (no gate verdict) | Host-call diagnosis closed; no further Thunder coalescing is on the critical path | Clean same-SHA `098b2f1` quick A/B: deferred-events median session wall **54.507 s** versus Thunder wall-only+counters **32.575 s**, event tax **21.932 s / 40.24%**. The RunPod A100 control is **3.768 s** at identical quick geometry and **15.651 s** full session wall; it selected the new provider but is not retroactively a gate claim. |
| P7b RunPod official rebaseline | **official valid FAIL: decode only; diagnosis complete** (2026-07-14) | Clean schema-6/ABI-28 T=100+50/Q=200 on exact `runpod-a100-v1`, counters-only, Rayon=8, 1+3, golden and communication invariants; prefill <=10 s, decode <=4 s, max per-repetition sync-wall/session-wall <=2%, H2D <=100 MB | `33e5fb4`: prefill **7.801 s PASS**, decode **6.794 s FAIL**, session **15.995 s**; sync-wall max **0.768% PASS** with 59,868 sync diagnostic; H2D **28.595 MB PASS**; packed response **144.821 MB PASS**; golden/accepted/flat 1.412 PASS. Separate non-gating `70f64d4` event attribution measures a **6.275 s decode-marginal kernel floor**: GEMM 4.820 s, LogUp 1.098 s, other 0.358 s. Provider-neutral kernel work is required; D2H host-call wall includes queued-kernel waits and is not an additive transfer cost. |

Formal side note: **M9 (opening-into-MAC) proved 2026-07-04** —
`VoltaZk/OpeningMac.lean` (`opening_mac_sound`, error ≤ εΩ/|Ω| + 1/|F|,
composes with M3 via `hfin`; PCS binding as explicit hypothesis, axioms clean).
See the M9 row in `protocol-sketch.md`.

## Analytic budget (P0 pre-registration)

Generated by `scripts/budget_p0.py` — measured counts in P4/P5 are compared
against these; deviations > 20% must be explained here.

| Quantity | Count | Note |
| --- | --- | --- |
| Native integer MACs | 8.63 G | i16×i16→i64, incl. last-position logits |
| Authenticated values | 3,763,968 | boundaries only: K, V, block outputs (0.044% of MACs) |
| Correction bytes | 30.1 MB | **8 B/value, F_p-typed (M5)** — 2-byte packing is an open item, needs an authenticated carry bit |
| VOLE correlations | ~3.77 M | + O(10³) masks (73 GEMM sumchecks + RLC/Π_Prod) |
| Lookups total | 16.94 M | dominated by FFN: requant_ffn_up + gelu = 7.37 M/layer-group |
| — exp / scores / softmax | 2.20 M | causal 5050 pairs/head |
| — LayerNorm | 1.85 M | rsqrt + per-element requant |
| — requant (all GEMMs) | 9.22 M | |
| Verifier F_p² mults | 11.3 M | q=3 opening points via RLC, one streamed pass |
| Lookup / native-MAC ratio | 0.20% | lookups cost O(1) E-mults each (LogUp) |

Reading of the budget: authentication is structurally almost free (0.04% of
native work — the whole game is the *kernel* cost of producing corrections,
hence P1); prover-side protocol cost is dominated by LogUp over 17M lookups
and by the per-GEMM sumcheck passes, both O(few %) of native MACs if the
constant factors hold. That constant factor is what P3/P4 measure.

## Deviations / decisions log

- **2026-07-14 (P7b CUPTI census fail-closed correction; preregistered before
  the first CUPTI run)**: pre-run source audit found that NVIDIA's unmodified
  helper never calls `cuptiActivityGetNumDroppedRecords`; it therefore cannot
  satisfy the dropped-record gate preregistered immediately below.  No CUPTI
  run occurred under that incomplete boundary.  Supersede it with a minimal
  scratch-only patch, never copied into this repository or the CUDA backend:
  (1) select only `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL`, removing unrelated
  API/memory/NVTX activities; (2) after every completed buffer, query and print
  `cuptiActivityGetNumDroppedRecords(context, stream)` fail-closed.  The
  patched injection source and helper SHA-256 values are
  `2966efecd3d767e9fb3fb62f7683971b5ee0ef10cd6e72f0db274196ddafb34b`
  and `8590bba68b4ec975d4243c422c4ce5313afa4bb496903c417f4c334202e894ec`;
  the original Makefile remains
  `d6e6b3a0fdc3f757d66e48b47b106dae369deebea865ee0c3e44377235b10717`.
  Its unchanged companion `helper_cupti.h` is also a build input, SHA-256
  `aedb286fe6bc0af1893e4d42cff5b3f0b9c1ef120bb5d2f051c1cdb6ad4440bf`.

  All other geometry, source/profile, output and interpretation constraints
  below remain unchanged.  Sum every emitted dropped-record count and require
  exactly zero.  The trace must contain all twelve filtered names that have a
  source-level launch in this workload, or explicitly record zero invocations
  only when the report's path cannot call that family; any unexplained absence
  fails the census.  This correction is diagnostic hygiene only, not new
  maintained instrumentation.

- **2026-07-14 (P7b kernel-census profiler fallback; preregistered after the
  Nsight refusal and before the fallback run)**: the exact preregistered
  Nsight Compute 2025.1.1 invocation attached to clean `8adbead`, but RunPod
  denied GPU performance-counter access with `ERR_NVGPUCTRPERM`, including
  for root.  It collected no kernel metric and produced no `.ncu-rep`.
  The error CSV SHA-256 is
  `542a25cbac0fd849f50d625680f8ace0c2a3657d2f134d20b7676100d8883481`.
  The application nevertheless completed acceptance, golden decode and the
  flat-cost check, producing the explicitly ineligible append-only
  `p7b-integrated-resident-wall-only-counters-ncu-denied-2026-07-14-8adbead.json`
  (SHA-256
  `4127171cbc96552fd54c3bb7918163edca37d23752c15e773b5df580ce004c8b`).
  Its NCU-perturbed wall values are discarded, not a gate observation or a
  profiler result.  Do not mutate/reload the provider's NVIDIA kernel module
  to obtain privileged counters.

  The one permitted fallback is NVIDIA's unmodified CUDA-12.8
  `cupti_trace_injection` sample already installed on the same image.  Source,
  Makefile, shared helper and `libcupti.so.2025.1.1` SHA-256 values are,
  respectively,
  `2fcc5cc819cc903f1715fb6615a406389c2f98e9c3b62d95bda54b2a4f0bf141`,
  `d6e6b3a0fdc3f757d66e48b47b106dae369deebea865ee0c3e44377235b10717`,
  `7a364cc51e21daff55f72523c1955f5ff964f94d6ab4f8b3f7dd96af3618f606`,
  and `fccdc5fcc7c32f8cf4b3ed9b17f7f187a185a6fa0a5bcc06e3434cbd1687c808`.
  Build a copy outside the source
  checkout, inject it only via `CUDA_INJECTION64_PATH`, and rerun the same
  clean full T=100+50/Q=200 counters-only 0+1 report with eight Rayon workers.
  CUPTI activity timestamps require no privileged performance counters and
  do not alter the repository/backend ABI.  Keep trace stdout, application
  stderr and generated report outside the checkout and record all checksums.

  The unmodified sample also reports CUDA API/memory activity and the report
  executes its standard flat-cost curve after the measured session.  The
  summary must therefore filter only the same twelve proof-algebra kernel
  names preregistered above and aggregate the entire application as a
  **decode-emphasized ranking census**, not claim a decode-marginal duration
  or compare its absolute time with CUDA events.  Land one append-only JSON
  with each matching kernel's invocation count and summed activity duration,
  plus matched/total kernel counts, dropped-record count, provenance and raw
  trace checksums.  If CUPTI reports dropped activity records, an unmatched
  proof-algebra family, or an application correctness failure, stop without
  selecting an optimization.

- **2026-07-14 (P7b RunPod proof-algebra kernel census; preregistered before
  profiling or CUDA changes)**: run one non-gating Nsight Compute 2025.1.1
  census on the exact `runpod-a100-v1` profile with eight Rayon workers and
  the clean commit containing this entry.  Geometry is full T=100+50/Q=200,
  counters-only, zero warmups and one measured repetition.  Acceptance and
  golden decode remain mandatory, but `p7b_gate_evaluated:false`; profiler
  wall time and the report JSON are not performance or gate observations.

  Invoke the already-built `p6_report` binary directly under `ncu`, with
  `--target-processes application-only`, kernel replay, cache and clock
  control both `none`, rules disabled, and only
  `gpu__time_duration.sum`.  The exact function-name filter is the complete
  proof-algebra subset currently charged to `Operation::Gemm`:
  `subfield_corrections_kernel`, `pad_base_vector_kernel`,
  `matrix_fold_kernel`, `fp2_dot_terms`, `reduce_dot`,
  `fp2_product_round_terms`, `reduce_product_round`,
  `fp2_triple_product_round_terms`, `reduce_triple_product_round`,
  `ln_hadamard_factors_kernel`, `base_broadcast_fp2_kernel`, and
  `attention_above_mask_kernel`.  Fixed-point witness kernels and LogUp/PCS
  kernels are deliberately excluded: the former run before timed proving,
  while the latter already have separate event categories.  Preserve the
  raw profiler CSV outside the source checkout, record its SHA-256, and land
  an append-only JSON summary containing provenance, per-kernel invocation
  count and summed duration.  The CSV is diagnostic input, not a repository
  run of record.

  Nsight perturbs launch order and duration, so only the within-census rank
  and occupancy/launch evidence may select work; absolute profiler wall and
  cross-mode latency are inadmissible.  Do not edit CUDA until the census is
  written into this ledger and reconciled with the deferred-event broad-GEMM
  total.  Then preregister at most one provider-neutral implementation
  boundary against the dominant exact kernel family.  The boundary may
  change reduction/limb implementation below the ABI only; it may not change
  transcript order, proof bytes, challenge visibility, correlation use,
  scheduling, communication or public API.

- **2026-07-14 (P7b RunPod decode diagnostic closed; non-gating result)**:
  the preregistered full deferred-event diagnostic ran on the exact
  `runpod-a100-v1` hardware/software profile with eight Rayon workers,
  T=100+50, Q=200, one warmup and one measured repetition.  Its clean source
  checkpoint is `70f64d4b2c01f672b74684525b42e638a7398793`; that checkpoint
  differs from official source `33e5fb4` only by documentation and the two
  already-recorded raw official JSONs, not executable code.  The append-only
  diagnostic is
  `p7b-integrated-resident-2026-07-14-70f64d4.json` (SHA-256
  `dc6b75a766db56d12e7b56543b5286df4c9ca4d8614b3a8202877eecabe3e8ed`),
  with schema 6, CUDA ABI 28, `git_dirty:false`, acceptance and golden decode
  true, and `p7b_gate_evaluated:false`.  It is attribution evidence only and
  does not replace or amend the official counters-only verdict.

  Deferred events raise observed prefill from the official upper median
  7.801156381 s to **9.673567059 s** (+1.872411 s, +24.00%), decode marginal
  from 6.793572543 s to **8.478508650 s** (+1.684936 s, +24.80%), and session
  wall from 15.994870539 s to **19.493344560 s** (+3.498474 s, +21.87%).
  These are indicative instrumentation-tax comparisons rather than a
  same-SHA repetition, but the executable is unchanged and the magnitude
  reconfirms that official runs must remain counters-only.  The diagnostic
  itself issued 229,554 elapsed-event queries and 887,698 timing-event API
  calls over the response session.

  Event attribution measures **13.166116504 s** response-session kernel time
  minus **6.890863665 s** prefill kernel time = **6.275252839 s** of
  decode-marginal kernel work.  Its exact operation split is GEMM
  **4.819555111 s (76.80%)**, LogUp **1.097967857 s (17.50%)**, PCS
  **0.255029525 s (4.06%)**, authentication **0.055084417 s (0.88%)**, and
  mailbox **0.047615929 s (0.76%)**.  Thus kernel time alone exceeds the 4 s
  decode gate by **2.275252839 s**: even under the impossible assumption of
  zero non-kernel overhead it needs at least a **36.26%** reduction, and the
  broad GEMM category alone is 0.819555111 s above the complete gate budget.

  **Corrected host-call model**: response-minus-prefill blocking D2H host-call
  wall is 10.589072882 - 5.530127451 = **5.058945431 s**, but the corresponding
  CUDA-event transfer duration is only 1.003848378 - 0.527549949 =
  **0.476298429 s**.  A blocking D2H copy is also the completion barrier for
  previously queued kernels, so its host wall contains their wait and cannot
  be added to the event-attributed kernel total.  The official ABI-28 host-call
  counter exposed where the host waits, not an independent 5 s transfer
  bottleneck.  Explicit synchronization remains immaterial on RunPod.

  **Decision boundary**: diagnosis is closed and provider-neutral kernel
  optimization is mandatory.  No epoch-scheduler expansion, boundary-count
  target, transcript change, algebraic batching or proof-size trade is
  authorized by this result.  Before changing CUDA, identify the exact
  kernels hidden by the broad `gemm` attribution using a separately
  preregistered non-gating profiler census on this same profile.  Then
  preregister one narrow implementation boundary, preserve ABI/proof bytes
  and CUDA byte-identical differentials, and require a quick measured
  cost-model confirmation before another official 1+3 run.

- **2026-07-14 (P7b first `runpod-a100-v1` official verdict; measured valid
  failure)**: the exact clean source is
  `33e5fb4d0baf9726eb09b3876adcc08d97b4f5c8`, CUDA ABI 28, eight Rayon
  workers and the fully matched RunPod manifest.  Real remote CUDA
  differentials passed with `VOLTA_REQUIRE_CUDA=1` (including all 33 backend
  tests) before measurement.  The current SSH mapping retained the pinned
  control checkout and exact hardware/software manifest, so the existing pod
  identity `mkhzglt1crcain` / `eur-is-1` remains the serialized attribution.

  The append-only quick diagnostic is
  `p7b-integrated-resident-quick-wall-only-counters-2026-07-14-33e5fb4.json`
  (SHA-256
  `82c489ff6d52fd6528d3bcf19691edaaf58ee2a18df137b5eaf8605d2849d9bc`):
  prefill **1.958648334 s**, decode **1.168009144 s**, response-session wall
  **3.766704220 s**, 39,201 sync, sync-wall fraction **1.817183%**, H2D
  12,656,708 B, accepted and flat-cost 1.051.  As preregistered, 0+1 quick
  geometry has `p7b_gate_evaluated:false` and is not a verdict.

  The official raw result is
  `p7b-integrated-resident-wall-only-counters-2026-07-14-33e5fb4.json`
  (SHA-256
  `1d228a66df9f332adcffde189efb64a5fb09423a308edd710abf760f4020f7df`),
  T=100+50, Q=200, one accepted warmup and three accepted measured
  repetitions.  Prefill samples are **7.801156381, 7.772146461,
  7.817114100 s** (upper median **7.801156381 s**, MAD 0.015957719): PASS
  <=10 s.  Decode-marginal samples are **6.789678313, 6.893654885,
  6.793572543 s** (upper median **6.793572543 s**, MAD 0.003894230): **FAIL
  >4 s**.  Response-session wall upper median is **15.994870539 s**.  Golden
  decode, acceptance, flat-cost 1.411550, communication/no-growth at exactly
  144,820,930 packed bytes, H2D max 28,594,644 B, cleanup/accounting and
  mock-PCG non-production labeling all pass.

  The retired raw sync count is 59,868 in every repetition.  Explicit sync
  wall is only 0.105950, 0.122980 and 0.112825 s; the maximum session fraction
  is **0.768161%**, so the new <=2% gate passes with margin and confirms that
  a <=5,000 count gate would be provider-driven debt.  However, the new
  ABI-28 host-call counters expose a different bottleneck: response-session
  D2H call wall is **10.388801, 10.426275, 10.402024 s** across 8,901 calls
  and 138,490,068 B.  Prefill alone is 5.430663–5.454171 s across 4,574 calls
  and 49,012,724 B; the response-minus-prefill deltas are therefore
  **4.934630–4.995612 s**, 4,327 calls and 89,477,344 B.  H2D host-call wall
  remains only 0.031–0.033 s/session.

  **Verdict and next gate**: this is a complete official P7b FAIL solely on
  decode latency, but counters-only data contradict the assumption that the
  remaining gap is purely Goldilocks kernel time.  No kernel floor is claimed
  from a mode where event attribution is intentionally unavailable.  Before
  changing kernels or batching, run the already-permitted separate,
  non-gating full diagnostic on the same eight-thread profile with deferred
  event attribution (one warmup + one measured repetition), and use it only
  to split operation kernel time from D2H/host wall.  If D2H remains the
  binding term, instrument or restructure only provider-neutral materialized
  output boundaries; do not revive a global <=5,000 scheduler target or
  extend epoch machinery blindly.  Any transcript-scheduling or algebraic
  batching change still requires its own preregistered boundary.

- **2026-07-14 (P7b RunPod implementation-readiness checkpoint; no gate
  verdict)**: the profile migration, fail-closed schema-6 writer/selector,
  exact quick+official runner and targeted dead-API cleanup are committed
  through `b424e36`.  The clean local checkpoint passes `cargo test
  --workspace`, `cargo test --workspace --all-features`, all 17 Python tests,
  syntax checks for every repository shell script and the frozen Lean audit.
  The working tree remained clean.  A complete source bundle and the existing
  weight/golden artifacts are available for checksum-matched transfer; their
  canonical artifact checksums remain unchanged.

  No remote measurement is claimed.  SSH to the user-supplied RunPod endpoint
  returned `connection refused`, and the local `RUNPOD_API_KEY` is unset, so
  no active endpoint can be discovered without user input.  No provider
  mutation, resume or provisioning was attempted, and Thunder was not
  contacted.  Resume only after an already-running exact
  `runpod-a100-v1` pod and its current SSH mapping are supplied; then require
  real CUDA differentials before quick 0+1 and official 1+3.  Until those
  append-only JSONs exist, `p7b_gate_evaluated` has no new observation and
  P7b has no official verdict.

- **2026-07-14 (P7b targeted AI-slop/dead-code audit checkpoint)**: the
  preregistered repository-only cleanup boundary is complete.  An exact
  symbol-occurrence audit over every Rust `pub fn` / `pub(crate) fn` and every
  Python script function found six Rust API surfaces with no call site, test,
  documentation reference or published consumer: the verifier's two unused
  single-range reservation wrappers, three unused LogUp backend/aux wrappers
  that only forwarded to the already-canonical internal implementation, and
  `SchedulePlan::site_correlations`.  They are removed (**86 lines**) without
  changing a protocol implementation, transcript operation, proof type,
  schedule, counter or backend ABI.  Re-running the public-function inventory
  leaves no definition-only Rust function.

  The four explicit Rust `dead_code` suppressions were inspected rather than
  deleted: three protect standalone resident proof entry points exercised by
  CUDA byte-identical differentials, while `ResidentLayerP1::fulls0` feeds the
  same compatibility accounting path.  CUDA-only buffer/context members,
  ABI-28 host-call diagnostics, `SiteId`/`SchedulePlan`, historical Thunder
  tools and append-only results are likewise retained intentionally.  The
  targeted `volta-mac` + `volta-proto` all-feature suites pass (19 MAC
  unit/integration tests and 100 protocol tests).  Workspace-wide Clippy was
  attempted; the repository has a pre-existing lint baseline dominated by
  cfg-branch `needless_return`, protocol API argument counts and the explicit
  field-method/operator dual API, so those stylistic warnings were not
  converted into a broad mechanical refactor.  Full regression and remote
  CUDA execution remain mandatory before measurement.

- **2026-07-14 (P7b RunPod official-provider and gate-profile migration;
  preregistered before implementation or new measurement)**: the clean
  same-commit control demonstrates that the `<=5,000` synchronization-count
  gate encoded Thunder's CUDA-over-TCP cost rather than a protocol
  requirement.  At `098b2f1`, identical quick work and exactly 39,201
  host-output synchronizations take **32.575313301 s** median session wall on
  Thunder but **3.767662096 s** on co-located RunPod.  The RunPod full control
  has 59,868 synchronizations whose representative host wall is only
  **0.095070132 s** in a **15.650884654 s** session.  Across its three
  measured sessions, synchronization-wall/session-wall is **0.607443%,
  0.616840%, 0.746639%**.  A provider-specific count target would therefore
  force scheduler complexity without a material co-located cost.

  **Provider decision**: RunPod becomes the sole official P7b verdict
  provider under a new explicit schema-6 gate profile
  `runpod-a100-v1`.  Thunder results and microbenchmarks remain immutable
  comparative artifacts but are no longer gate inputs or dependencies; the
  Thunder instance may be terminated.  No existing RunPod ABI-27 control is
  promoted retroactively.  A new official result must use the current CUDA
  ABI, a clean unchanged source SHA and the exact profile below.

  **Gate contract**: retain prefill core **<=10 s**, decode marginal
  **<=4 s**, session H2D **<=100,000,000 B**, the packed-response
  communication/no-growth invariants, acceptance, golden decode, flat cost
  and mock-PCG non-production label.  Retire the numerical synchronization
  count gate and retain the raw count only as a diagnostic.  Its replacement
  is the **maximum over all measured repetitions** of
  `accelerator_session.synchronization_s /
  t_response_session_wall_s <= 0.02`.  A missing, non-finite, negative or
  zero-denominator sample fails closed.  Schema remains version 6, but every
  new official row must carry `p7b_gate_profile: "runpod-a100-v1"`, explicit
  retirement of the count gate, the per-run ratios, their maximum, the 0.02
  threshold and the corresponding verdict.  Historical schema-6 rows without
  that profile cannot become official under the new selector.

  **Reproducible machine profile**: provider `RunPod`, region `eur-is-1`,
  image `Ubuntu 24.04.3 LTS`, driver `580.159.04`, CUDA `12.8`, GPU exactly
  `NVIDIA A100-SXM4-80GB`, CPU `AMD EPYC 7713 64-Core Processor`, RAM metadata
  `1008` GiB and provider vCPU metadata `255`.  The proving process must set
  `RAYON_NUM_THREADS=8`, and the serialized `threads` field must equal 8;
  provider vCPU inventory is not a substitute for actual worker count.  The
  earlier control serialized 27 Rayon threads versus 7 on Thunder, so its
  latency is evidence for provider selection but not the official
  standardized denominator.  Any unavailable exact profile field makes the
  run ineligible; an instance id is recorded but is not pinned.

  **Implementation and cleanup boundary**: first update the Rust writer and
  Python run-of-record validator together, preserving schema-6 historical
  readability and making every new field fail closed.  Freeze further epoch
  scheduler/coalescing expansion: the existing `SiteId`, `SchedulePlan` and
  scheduled proof paths remain because they are used correctness machinery,
  but they are no longer a prerequisite for an official run.  Audit AI slop
  and dead code only inside this repository.  Remove a path only when
  all-target/all-feature builds, call-site inspection and differentials show
  it is unused or unjustifiably duplicated.  Intentional compatibility
  wrappers, formal seams, CUDA differentials, ABI-28 host-call diagnostics,
  append-only JSONs and historical Thunder reproduction tools are not dead
  merely because they are off the critical path.  Cleanup lands in isolated
  commits and may not change proof bytes, challenge order, communication,
  golden output or resource accounting.

  **Measurement order**: after local workspace/no-CUDA tests, report tests,
  CUDA all-feature differentials and cleanup checks pass, run one clean
  standardized RunPod quick smoke.  Only then run T=100+50/Q=200 with at
  least one warmup and three measured repetitions, counters-only timing,
  golden decode and full schema-6/current-ABI discipline.  The official
  result is valid whether performance passes or fails.  If decode remains
  above 4 s, perform separate non-gating profiling on the same eight-thread
  profile and prioritize provider-neutral Goldilocks multiplication limbing,
  occupancy and kernel fusion.  Use formally bounded batching only after a
  measured diagnosis and its own preregistered boundary.  No optimization is
  bought with proof size/communication, and no retained CUDA graph may cross
  a verifier-challenge barrier.

- **2026-07-14 (P7b iteration 3 diagnosis-first plan; preregistered before
  implementation or new measurement)**: iteration 2's first clean scheduler
  diagnostic is internally correct but does not support another blind
  coalescing step.  In the immutable `61aafe8` quick session, the
  **52.146336769 s** response-session wall contains **20.179340213 s D2H**
  (81,518,420 B across 39,201 host-output boundaries),
  **12.261196475 s explicit synchronization**, **0.203084724 s H2D**, and
  **19.371403444 s unattributed host residual**.  At this checkpoint that is
  about **514.76 us/D2H** plus **312.78 us/explicit sync** at each host-output
  boundary.  The residual is also 122.37 us for each of the 158,305 deferred
  CUDA elapsed-time queries if attributed entirely to that remote-call
  surface.  Yet versus the clean `bf66c8f` quick baseline, prefill changes
  only 27.868 -> 27.154 s and decode marginal regresses 23.425 -> 23.628 s
  despite 22,487 fewer synchronizations and 49.19% less H2D.  The explicit
  synchronization term alone predicts about **7.035 s** saved at the new
  per-sync cost.  This unexplained flat-wall anomaly blocks any further
  scheduler/coalescing measurement until Phase 0 closes.

  This plan is accepted as an architectural diagnosis/refactor, not a new
  permanent proving variant, under the following hygiene boundary.  Event
  attribution is one measurement policy selected at the resident backend
  boundary; it must not duplicate or condition the protocol/proving path.
  The counter-only policy bypasses CUDA event creation, recording and elapsed
  queries, so its operation/sync/traffic counters are host-side increments
  and it adds **zero remote timing calls**.  Host wall around required H2D,
  D2H and synchronization calls remains measured.  Event-derived kernel and
  coarse-interval attribution is explicitly unavailable under this policy
  (identified by the serialized timing method), never presented as a
  measured zero.  The existing reason-sum, byte, ownership, cleanup and
  poisoning invariants remain common to both policies.  This keeps the mode
  a removable observation concern rather than architectural debt.

  **Phase 0a -- instrumentation-tax A/B (mandatory first measurement)**:
  implement the policy seam and exact tests that counter-only mode performs
  no CUDA event calls/queries while preserving operation, byte, explicit
  synchronization, reason, allocation and cleanup counters.  On the
  designated Thunder A100, use quick T=16+8/Q=200 only, one clean pinned SHA,
  identical seeds/inputs, and three measured repetitions per policy.  Runs
  are counterbalanced in order (`events, counters, counters, events, events,
  counters`) and emitted as immutable append-only JSONs; no sample may be
  discarded.  Record response-session wall plus prefill/decode walls and all
  available host-call categories for every repetition.  Define event
  instrumentation tax as
  `(median(events wall) - median(counters wall)) / median(events wall)`.
  If it is >=10%, append a ledger decision before an official run making
  `wall-only + counters` the gate-run policy; full event attribution is then
  confined to separately labelled diagnostics.  Otherwise event timing
  remains the official policy.  A mode with any nonzero event-call/query
  counter is invalid as the counter-only arm.

  **Phase 0b -- flat-wall anomaly closure (blocks Phase 1)**: using only the
  immutable clean `bf66c8f` and `61aafe8` JSONs plus the Phase-0a JSONs,
  reconcile the wall delta by an explicit category-delta table for D2H host
  wall, explicit synchronization host wall, H2D host wall, unattributed host
  residual, event-query count/tax and residual remote variance.  Do not add
  overlapping coarse CUDA intervals to host-wall categories.  Correct the
  per-boundary model to distinguish (1) an explicit stream-sync round trip,
  (2) the blocking D2H round trip and payload, and (3) optional event
  instrumentation calls.  Append the quantitative explanation and corrected
  model here before any Phase-1 code begins.  If the observed deltas cannot
  close within the Phase-0a run dispersion, iteration 3 stops as unresolved
  remote variance rather than treating coalescing as validated.

  **Phase 0c -- co-located attribution control preparation, then explicit
  stop**: after 0a/0b, prepare but do not execute a checksum-matched source
  bundle for the same pinned checkpoint, exact CUDA/build commands, quick and
  full timing-off invocations, and an expected-output/cleanliness checklist
  for a co-located A100.  No provider is to be provisioned, enrolled or
  accessed without user-supplied instance access.  A Lambda/RunPod or other
  co-located result is an **attribution artifact only**, never a gate claim:
  Thunder remains the target and sole official-verdict provider.  Stop at
  this checkpoint and request access.

  **Phase 1 -- Thunder epoch scheduler (only after written 0a+0b closure;
  co-located access is not a dependency)**: extend the existing sealed
  role-antichain/heterogeneous mailbox scheduler to non-GELU LogUp sites,
  blind-sumcheck product rounds and Hadamard rounds.  The audited target is
  about 2,446 LogUp epochs and 3,100--4,200 total response barriers.  Fold
  each mailbox read into its barrier: one blocking D2H memcpy is counted as
  the synchronization and there is no preceding explicit stream sync.  This
  changes backend execution/accounting only; the sealed `SiteId`, public
  `SchedulePlan`, preflighted membership/depth/family, exact disjoint
  correlation reservation, active-set shrink-only rule and canonical order
  remain unchanged.  CPU-scheduled and resident-scheduled proofs must remain
  byte-identical, with unchanged proof structs, labels, counts, verifier
  behavior and communication.  Before a measured run, publish the exact
  quick-geometry barrier bound derived from `SchedulePlan` and its
  T=100+50 projection.  The first quick run is accepted as model-confirming
  only if its median wall reduction is compatible with `removed round trips
  x the Phase-0b measured round-trip cost`, allowing the larger of 20% of the
  projection or twice the Phase-0a median absolute dispersion.  Otherwise
  stop and return to diagnosis; do not iterate coalescing blindly.

  **Phase 2 -- kernel work plus official gate run (only if Phase 1 confirms
  the model and projects <=5,000 barriers at T=100+50)**: before the official
  run, treat Goldilocks kernel work as required scope, with multiplication
  limbing and occupancy changes isolated below the protocol boundary and
  guarded by CPU/CUDA field and full scheduled-proof differentials.  The
  decode <=4 s gate has only 1.14 s above the existing 2.860 s kernel floor,
  so this is not a stretch item.  Publish feasibility arithmetic as
  `prefill = 3.138 s kernel floor + epochs * measured RTT + true host
  residual`, using the corrected 0a/0c attribution rather than coarse event
  intervals.  Then run T=100+50/Q=200 on Thunder with at least one warmup,
  at least three measured repetitions, golden decode, clean identical full
  SHA before benchmark and serialization, the Phase-0a-selected timing
  policy, and all schema-6 provider, acceptance, flat-cost, communication,
  cleanup, mock-PCG and four-gate invariants.

  **Phase 3 -- conditional only on a measured Phase-2 gate failure**: first
  implement the already-proved and preregistered scalar-RLC round batching at
  its existing formal boundary, including the extra fresh domain-separated
  challenge and CPU reference differential; then consider retained CUDA
  graphs only for fixed device-only segments and never across a challenge
  barrier.  No Phase-3 work begins after a Phase-2 pass.

  Standing exclusions remain binding in every phase: no device transcript
  hashing; no verifier challenge seed, future challenge, or `Delta` on the
  prover/GPU; mock-PCG remains labelled non-production; no per-token proof or
  PCS opening; append-only results and clean-tree discipline; and no prover
  speed bought with proof size or communication.

  **Phase-0a access preflight (2026-07-14; no benchmark run)**: the
  user-supplied replacement Thunder endpoint identifies itself as
  `instance-rk6i1r0o-main`, but `nvidia-smi` reports **NVIDIA RTX A6000**
  (driver 610.43.02), not an A100.  It also has no existing
  `/home/ubuntu/volta-zk` checkout.  The endpoint may be used only to compile
  and smoke-test ABI 27; it is ineligible for the preregistered 0a A/B and for
  every P7b gate.  No timing sample was taken or discarded.  Phase 0a remains
  blocked pending a Thunder A100 endpoint, so 0b and later phases have not
  started.

  The ABI-27 implementation checkpoint is clean source `c4a8ced` (bundle
  SHA-256 `ba11353f72b7f429353b65f5c796db4761beeab99907d2d1a5f4840247a58f90`).
  On the ineligible A6000 it compiles with CUDA 13.0/sm_86 and the complete
  `volta-accel --features cuda` suite is **33/33** green, including the
  event-on/counter-only differential.  That differential confirms identical
  output, operation calls, traffic and synchronization reasons while the
  counter-only arm has zero timing records, elapsed queries and aggregate
  CUDA-event API calls.  This is implementation evidence only and carries no
  latency or P7b gate claim.

  `scripts/run_p7b_instrumentation_ab.sh` is the fail-closed 0a runner.  It
  executes the preregistered events/counters/counters/events/events/counters
  order as six isolated one-repetition quick reports, requires one unchanged
  clean full SHA, stages each result outside the repository between samples,
  and restores all six append-only JSONs only after the final clean-tree
  check.  This prevents an earlier result artifact from dirtying a later arm.

  **Phase-0a execution correction (2026-07-14; cohort not yet started)**:
  the first runner attempt at clean `40aa1a9` failed before proving because
  the report build omitted the Cargo `cuda` feature and emitted no JSON.  At
  clean `7077636` the first event arm completed with an accepted **49.79 s**
  response, but the runner then failed closed while staging it: its initial
  destination collided with the report's temporary basename and the two
  arms would not have had distinct final basenames.  That singleton is
  quarantined outside the repository and is excluded from 0a because the
  six-sample same-SHA cohort did not complete; it is neither silently
  discarded nor used to choose timing policy.  Before restarting, final
  names are made injective in `(policy, repetition)` and the entire six-run
  counterbalanced sequence restarts from sample 1 on one new clean SHA.

  **Phase 0a result and timing-policy decision (2026-07-14; clean quick,
  not a gate verdict)**: the complete counterbalanced cohort ran on Thunder
  A100 `instance-8mxkk5r7-main` at one clean full SHA
  `098b2f128b7152cf7a4c701cba6dd0d8a876e578`, in the registered order.
  Deferred-events response-session walls were **55.324175101,
  54.507356839, 53.568020169 s** (median **54.507356839 s**, MAD
  **0.816818262 s**); wall-only+counters walls were **33.605737162,
  32.575313301, 32.303299563 s** (median **32.575313301 s**, MAD
  **0.272013738 s**).  The registered tax is therefore
  **21.932043538 s = 40.236850%** of the event-on median, well above 10%.
  Prefill medians change **27.768384686 -> 16.779376102 s** and decode
  marginal medians **25.853503525 -> 14.597984860 s**.  All six proofs are
  accepted and clean, and their operation calls, 39,201 host-output syncs,
  12,656,708 B H2D, 81,518,420 B D2H, D2D/device-generated/device-zeroed
  bytes, allocator and arena counters are identical.  Each counter-only
  session has zero timing records, elapsed queries and aggregate event API
  calls; each event session has 126,438 timing records, 158,305 elapsed
  queries and 617,381 aggregate CUDA-event API calls.

  Per the pre-registered threshold, **wall-only+counters is now the sole
  official P7b gate-run observation policy**.  Full CUDA-event attribution is
  confined to separately labelled diagnostic runs and cannot be selected by
  the official-result validator.  Counter-only event-derived H2D, D2H,
  kernel, coarse and residual fields remain `null`, while wall, bytes,
  calls, synchronization host wall and reasons remain fail-closed.  This is
  an observation-policy selection at the existing backend seam; it does not
  fork protocol execution, proof bytes, challenges, communication or the
  verifier and therefore does not introduce a permanent proving variant.

  Immutable raw files (SHA-256 in event r1/r2/r3 then counters r1/r2/r3
  order) are:
  `9e47e573d3dca0751181b66e428d622e28246f7ba22db1d0a70aacec8132c43e`,
  `c36966f0b08d242161b5239c6c16c69eb238ff8f310adbc9e85c371dcf4b424e`,
  `d5cfd3385d671dc84547f1082ff78810459fa836aebb59729240429aa9670478`,
  `114e0e9d2b2094d07be93d6a548ab49815fdecc488a790252635c380dbd90b8c`,
  `cae49bdcb2b48f6fbd56b75386a8b557a3c011bb0a2437f6c893c98734af574d`,
  and
  `ac20849f387f43820dfe9c32a396c8d22145ca438329d714ff1c768857f7eae2`.

  **Phase 0b flat-wall closure and corrected cost model (2026-07-14)**:
  the old `bf66c8f -> 61aafe8` wall delta closes exactly without inventing a
  missing seven seconds.  In the non-overlapping event attribution identity,
  H2D changes **-0.014745801 s**, D2H **-4.938606840 s**, non-coarse device
  interval **-0.657179939 s**, the newly introduced coarse interval
  **+8.211153792 s**, and host residual **-3.029339138 s**; their sum is the
  observed wall **-0.428717926 s**.  Thus a new coarse event interval --
  explicitly documented as including remote launch-submit gaps -- relabelled
  8.211 s and numerically masked the 8.640 s reduction in the other identity
  terms.  It is not evidence of 8.211 s of new compute.

  Explicit `synchronization_s` is an overlapping diagnostic, not another
  addend in that wall identity.  Its measured change is **-3.492065594 s**.
  Multiplying 22,487 removed calls by the later 312.777645 us/call gives the
  invalid **7.033430911 s** projection; the remaining **3.541365317 s** is
  exactly the non-stationarity error from applying the later per-call value
  to all 61,688 baseline calls (255.369960 us/call at baseline).  The A/B
  proves why neither event-on value is a structural RTT: at identical work,
  median event-on synchronization wall is 12.689342499 s
  (**323.699459 us/boundary**), but timing-off synchronization wall is only
  0.441633804 s (**11.265881 us/boundary**).

  The 31,529 fewer elapsed queries also cannot be priced as independent wall
  savings from this A/B: the policy removes 459,076 event-record calls as
  well as 158,305 elapsed queries.  Dividing the aggregate 21.932 s tax by
  queries gives 138.543 us/query only as a blended normalization (and would
  predict 4.368 s for the query-count delta), while division by all 617,381
  event API calls gives 35.524 us/call; neither quotient identifies an
  elapsed-query RTT.  The event-arm median residual, 20.267596203 s, being
  close to the 21.932043538 s aggregate tax supports the instrumentation-tax
  diagnosis but does not make residual and sync/coarse event intervals
  additive.  Finally, the historical wall delta of 0.429 s is smaller than
  the new event-arm MAD of 0.817 s, so it carries no improvement claim beyond
  remote-run dispersion.

  The corrected timing-off host-output model is
  `C_boundary = C_memcpyAsync_D2H_host + C_required_sync_host`, plus payload
  dependence, with optional event instrumentation excluded entirely.
  `C_required_sync_host` is measured here as **11.265881 us/boundary**.  The
  event-derived D2H interval (**541.215569 us/boundary** at the new median)
  is a device-timeline interval and is **not** `C_memcpyAsync_D2H_host`; the
  current schema does not time that host API call in counter-only mode.
  Therefore no Phase-1 prediction may reuse 514.8 us as a D2H RTT or 312.8 us
  as a sync RTT.  The D2H host-call term must be measured without extra CUDA
  calls (or retained as an explicit unknown), and Phase 1 remains unstarted
  at this reporting checkpoint rather than iterating coalescing against a
  contaminated cost model.

  **Phase 0c preparation checkpoint (2026-07-14; explicit stop)**: no
  non-Thunder host has been provisioned, enrolled or accessed.  The one-off
  control is pinned to the exact 0a commit `098b2f1`; its prepared Git bundle
  is `/tmp/volta-zk-098b2f1.bundle`, SHA-256
  `64076288e251ea45194dd6b442e8f09f0862c3c64692734c2d6770b0f3a6ba77`.
  `docs/p7b-colocated-control-runbook.md` records the checksum-matched source
  and weight inputs, CUDA `sm_80` build/test commands, isolated quick and
  full wall-only+counters invocations, clean-tree staging and the complete
  expected-output checklist.  It requires a non-Thunder result to serialize
  `p7b_machine_eligible:false` and `p7b_gate_evaluated:false`; the artifact
  can inform attribution only and can never replace a Thunder verdict.  Work
  stops here pending user-supplied access to an already-provisioned
  co-located A100.  Phase 1 has not started.

  **Phase 0c execution result (2026-07-14; attribution only, no gate
  verdict)**: after the user supplied an already-provisioned RunPod endpoint,
  the exact `098b2f1` bundle ran on a co-located NVIDIA A100-SXM4-80GB
  (RunPod `mkhzglt1crcain`, `eur-is-1`, driver 580.159.04, CUDA 12.8,
  Ubuntu 24.04.3, AMD EPYC 7713).  The CUDA differential suite is **33/33**
  green.  The clean quick timing-off control is accepted at prefill
  **1.876885173 s**, response prover **3.115895127 s**, decode marginal
  **1.239009954 s**, and response-session wall **3.767662096 s**, with flat
  ratio **0.909699393**.  Its 39,201 syncs, 12,656,708 B H2D and 81,518,420 B
  D2H exactly match Thunder; event records/queries/API calls are zero.

  The clean full T=100+50/Q=200 control uses 1 warmup + 3 measured
  repetitions and is accepted with golden decode and flat ratio
  **1.470336027**.  Upper medians are prefill **7.672741861 s**, response
  prover **14.370455789 s**, decode marginal **6.697713928 s**, and full
  response-session wall **15.650884654 s**.  It has 59,868 syncs and
  28,594,644 B H2D.  These values numerically pass the prefill and H2D
  thresholds but miss decode and sync; more importantly the JSON correctly
  carries `p7b_machine_eligible:false` and `p7b_gate_evaluated:false`, so none
  of those comparisons is a gate verdict.  Quick/full JSON SHA-256 values are
  respectively
  `f18b06e7f40a7f4a4f323be5762d1e98823600f0a51d88f8c492289d290ca0f4`
  and
  `2849c0a16b235bf729700c934156b4becda09b2379b5c2db4b05711f7dc93370`.

  Against the Thunder counter-only quick median at the same source and
  counters, RunPod reduces session wall **32.575313301 -> 3.767662096 s**
  (delta **28.807651205 s**, 8.65x) and response proving
  **31.265796314 -> 3.115895127 s** (delta **28.149901187 s**, 10.03x).
  Explicit synchronization host wall accounts for only
  **0.441633804 -> 0.064483303 s**, a **0.377150501 s** provider delta
  (11.265881 -> 1.644940 us/sync).  The remaining **28.430496814 s** is a
  combined host CUDA-call, D2H, kernel/provider and CPU/platform term.  The
  different CPU/provider makes this a strong attribution result, not a
  component-exact subtraction; dividing all 28.430 s by the 39,201 outputs
  would invent a 725.249 us D2H RTT and is explicitly forbidden.

  **Phase-0b host-call closure addendum (pre-registered before implementation
  or another Thunder measurement)**: Phase 1 still needs the numeric
  `C_memcpyAsync_D2H_host` term required by its stop prediction.  ABI 28 may
  add host-only call counts and `steady_clock` wall nanoseconds immediately
  around the already-required resident H2D/D2H `cudaMemcpyAsync` calls.  It
  must add no CUDA call, event, barrier or protocol branch; the same wrapper
  and operation path serves both observation policies.  Counter-only phase
  attribution remains unavailable/null, while these explicitly named host
  API-call fields are available because they are ordinary CPU clocks, like
  `synchronization_s`.  Tests must prove identical bytes/output/sync/operation
  counters, exact transfer-call accounting and zero event API calls.

  On Thunder, run one clean quick counter-only diagnostic at a single pinned
  SHA with 0 warmups and 3 measured repetitions.  Define the corrected
  boundary cost as the median across repetitions of
  `resident_d2h_host_call_s / resident_d2h_host_calls +
  synchronization_s / synchronizations`; publish both terms and dispersion.
  The D2H call count must equal the 39,201 host-output boundaries in every
  repetition.  If it does not, or the three values do not support a stable
  numeric model, stop diagnosis.  Only after this lands may Phase 1 publish
  its exact `SchedulePlan` bound and use removed D2H calls and explicit syncs
  as separate projected savings.  This instrumentation is removable
  observation state at the backend ABI, not protocol or scheduler debt.

  **Phase-0b host-call diagnostic result and mandatory stop (2026-07-14)**:
  ABI 28 landed at clean `c5265b5`; host clocks wrap only the already-issued
  resident `cudaMemcpyAsync` calls, add no CUDA call or protocol branch, and
  the Thunder CUDA suite is **33/33** green.  The clean Thunder quick
  counter-only 0+3 JSON is accepted and non-gating, with zero event API calls
  and response-session walls **31.981356794, 30.601558430,
  31.252483604 s** (median **31.252483604 s**, MAD **0.650925174 s**).
  Its SHA-256 is
  `a0e71cb2734a7e5e44af3726bd5b6086ca5902934c941d16c2d48b91692af322`.

  The measured host-call terms are stable for the calls they cover: 9,529
  resident H2D calls in every repetition at median **12.935167 us/call**
  (MAD 0.140461 us), 7,335 resident D2H calls at median
  **484.398616 us/call** (MAD 13.304263 us), and 39,201 synchronizations at
  median **11.153362 us/call** (MAD 0.134363 us).  However, the
  pre-registered coverage gate fails: resident D2H call count is **7,335**,
  not the required **39,201** host-output boundaries.  Only **18.71%** of
  boundaries use the explicit resident-transfer entry point; **31,866**
  host-output syncs are paired with D2H issued inside other CUDA primitive
  paths and are not covered by this counter.

  Therefore `484.399 + 11.153 us` is valid only for the covered resident D2H
  subset and must not price all removed Phase-1 boundaries.  The diagnostic
  stop condition is triggered exactly as registered: Phase 1 remains
  unstarted, no SchedulePlan performance projection is published, and no
  further coalescing is attempted.  Covering the remaining D2H sites would
  require a new, broader single-wrapper host-call instrumentation decision;
  it is not silently folded into ABI 28.  The incomplete coverage exposes the
  pre-existing mixed resident/legacy host-output surface that Phase 1 was
  intended to remove; it is not debt introduced by the observation seam.

- **2026-07-13 (P7b target re-registration — resident GPU gate redefined;
  user decision)**: the preregistered rho_proof targets (<=10 prefill /
  <=2 decode) against the same-host native-GPU denominator are **retired for
  GPT-2-small batch-1**: the denominator (17.342 ms prefill) is
  launch-latency-bound (<1% A100 utilization), so rho<=10 implies a 173 ms
  full proof — below the 5.998 s of measured pure kernel time. This is a
  property of the degenerate denominator at 124M/T=100, not of the provider
  or implementation. The <=10/<=2 aspiration moves to a compute-bound
  denominator (phase-X scale, or batched-session throughput rho), per the
  scaling-note thesis. **P7b resident gates, pre-registered now**: prefill
  core **<=10 s** and decode marginal **<=4 s** (respectively 2.04x and
  3.59x faster than the same-host CPU prover: 20.421 s / 14.344 s from the
  `p6-2026-07-11-f72e4dd` baseline),
  blocking synchronizations **<=5,000/session**, session H2D **<=100 MB**.
  Stretch ("ottimo"): prefill <=6 s / decode marginal <=2.5 s. The measured
  kernel floors are 3.138 s prefill and 2.860 s decode marginal (5.998 s for
  the whole response-session scope), so decode stretch also requires
  kernel-level gains (Goldilocks mul limbing / occupancy).

  **Attribution audit before implementation**: Thunder Compute is
  GPU-over-TCP, but 343 us is only the aggregate 72.652 s / 211,709 and must
  not be treated as a uniform synchronization RTT. Of the 211,709 barriers,
  170,367 correspond to CUDA primitive calls whose profiling path executes a
  `cudaStreamSynchronize` after every operation; the other 41,342 are explicit
  uploads/downloads. The current transcript is an interactive DV mock with
  verifier-side, message-independent ChaCha8 challenges — explicitly not
  Fiat--Shamir — so device-side BLAKE3 transcript hashing is **rejected** as
  incompatible with unchanged proof/verifier/formal assumptions. RLC round
  batching likewise remains a separately preregistered protocol change, not a
  byte-identical optimization. The first protocol-neutral levers are deferred
  session timing, stable buffer reuse, persistent/D2D PCS commitments,
  coalesced proof-message reads, and device-side generation of mock-PCG/PCS
  masks without exposing the verifier challenge seed. The 945,442,180 B H2D
  is not mostly PCG masks: about 755 MB is static PCS weights plus pads rebuilt
  inside each measured response. For accounting hygiene, report both cold
  setup and warm-response H2D; the <=100 MB gate remains attached to the
  existing full response-session scope (including PCS work), so moving bytes
  outside the measurement alone cannot satisfy it. Provider stays Thunder
  (user decision, 2026-07-13); a 30-min launch/sync/D2H/graph microbench on
  the instance is the mandatory first step before any refactor.

  **Microbench preregistration**:
  use the same A100 instance and a clean tree; measure host wall for (a) one
  empty-kernel launch plus one device synchronization, (b) N direct launches
  followed by one synchronization, separating enqueue and final-barrier time,
  for N in {1, 8, 64, 512, 4096}, (c) a blocking 8-byte D2H copy, and (d)
  construction, instantiation and replay-plus-sync of a linear CUDA graph with
  the same N empty kernels. A fifth diagnostic measures 8-byte cudaMalloc and
  cudaFree separately because the run reports 271,567 allocation calls and
  allocator churn can serialize independently of explicit transcript reads.
  The full harness targets 1,800 s across the timed cases and reports
  count/median/MAD/p95/min/max plus per-launch amortization; quick mode is
  smoke-only. Operationally, direct launches count as
  "pipelined" only if both max-N enqueue and total time amortize to <=10% of
  the one-launch-plus-sync median. A max-N graph replay is a material lever at
  >=1.2x lower total wall than the direct burst. These classifications choose
  implementation order only; they are not prover performance claims. The
  first clean quick attempt produced no JSON: after the required cases had
  passed, repeated replay of the 4,096-node graph stalled inside the provider
  runtime (a separate 7-sample compile smoke had completed). Before the full
  run, graph replay is therefore capped at 7 quick / 31 full samples per N;
  graph build and instantiate remain measured, and the 1,800 s budget is
  distributed over launch/sync, direct bursts, D2H and allocator probes. This
  is a logged harness deviation driven by a provider-stability observation,
  not a discarded performance sample; the failed quick emitted no result.

  **Mandatory microbench result (closed before any prover refactor)**: clean
  SHA `8b5d177`, full measurement wall **1,802.864 s**, append-only result
  `benchmarks/results/p7b-thunder-cuda-rtt-2026-07-13-8b5d177.json`
  (SHA-256 `4063bfa6f4cb22622fd1500201fd767ec867a4dd7d74720976eb8c3be7283107`;
  local/remote checksum identical, `git_dirty:false`). The smoke companion is
  `p7b-thunder-cuda-rtt-quick-2026-07-13-8b5d177.json` (SHA-256
  `241f10d169eea9acaddbd6836a097348114203a58b55f4b353c40964207f489c`).
  Full medians: empty launch+sync **3.709 us** (p95 8.883 us, with a provider
  outlier of 1.473 s); blocking 8-byte D2H **301.208 us** (p95 350.633 us);
  8-byte `cudaMalloc` **1.149 us**, `cudaFree` **2.593 us**. A direct
  4,096-kernel burst takes **7,956.171 us**, of which **7,953.301 us** is
  enqueue time: **1.942 us/kernel** total, far above the preregistered
  0.371-us "pipelined/free" threshold. Replaying the corresponding fixed CUDA
  graph takes **17.945 us**, a **443.36x** reduction, but construction costs
  1.429 s and instantiation 38.484 ms, so graphs must be retained/replayed and
  cannot be rebuilt per proof. Decision branch is therefore exactly
  `coarsen-launch-surface-and-eliminate-blocking-d2h`: stable/generational
  buffer ownership first, removal of profiling barriers and coalescing of
  true host outputs second, then retained graphs for fixed device-only
  segments. Eliminating D2H alone is not the selected branch.

  **Formal audit gate before round-RLC batching — scalar implementation gap
  and abstract shared-round theorem closed (2026-07-13); concrete scheduler
  still gated**: the proposed
  batching is a real M3 extension, not a byte-identical refactor. The audit
  found that Rust `zero_batch_{prover,verify}` and `prod_batch_*` weight a
  closed list by powers `chi^(j+1)` of one scalar challenge, whereas the
  generic Lean `zeroBatch_sound` / `prodBatch_sound` theorems quantify an
  independently uniform coefficient vector `Fin T -> F`. The concrete Rust
  format is now covered directly: `card_scalarRlc_zero_le` proves at most `T`
  roots for a nonzero scalar-RLC list of length `T`;
  `zeroBatch_sound_scalar` gives `(T+1)/|E|`;
  `prodBatch_sound_scalar` gives `(T+2)/|E|`; and
  `blind_sumcheck_sound_scalar` gives
  `(Σ d_i + n + 2)/|E|` for its `n+1` closing claims. The M4 map is now
  explicit rather than documentary: `kv_cache_sound_scalar` and
  `authenticated_cache_sound_scalar` cover Rust's one-`χ` cache closure
  with upper bound `(T+1)/|E|`. Full `lake build` passes (2,572 jobs), and
  the expanded named audit checks 16 generic and
  implementation-mapped theorems, each depending only on `propext`,
  `Classical.choice`, and `Quot.sound`; no `VoltaZk.Ideal` assumption enters
  the boundary. This closes the pre-existing scalar code/theorem mismatch.

  The separate aggregate prerequisite is now
  `VoltaZk/BatchSumcheckSound.lean`:
  `outer_scalar_batch_blind_sumcheck_sound` fixes `K` claimed/true totals
  before a fresh outer `β`, uses weights `β^(k+1)`, and proves bad-tape
  count `(K + Σ d_i + n + 2)|E|^(n+2)` out of `|E|^(n+3)` — the
  `K/|E|` collapse plus scalar M3. Importantly, after `β` the aggregate
  round strategy is fully malicious; the proof does not assume honest
  execution of the linear combiner. `scalar_batch_blind_sumcheck_sound`
  instantiates that boundary for `FixedSumcheckBatch`, while
  `HasCommonPoint` names the scheduler invariant.

  **Pre-registered implementation boundary (not silently discharged by the
  theorem)**: cohort membership and all `K` initial claims are closed before
  `β`; a cohort is homogeneous in round count and public degree vector; all
  members consume the identical `r`/prefix history; `β` is fresh and
  domain-separated from `Δ`, `r`, and the inner scalar `χ` (no challenge
  reuse); the aggregate final opening remains public-linear and
  VOLE-authenticated. The interactive transcript must account for the extra
  field challenge, so this is not a byte-identical protocol refactor even if
  total communication decreases. Rust enablement still requires a CPU
  reference differential for the new transcript, an explicit interleaving
  state-machine/common-point assertion, LogUp layer-end alignment, and exact
  domain/correlation-counter tests. Cross-cohort/session soundness is an
  explicit union bound. No verifier seed or future challenge schedule may be
  exposed to the prover/GPU as a shortcut.

  **Post-attribution scheduler decision (2026-07-13; preregistered before
  implementation)**: exact full-run structure contains 58,205 interactive
  round readbacks (51,122 LogUp + 5,400 blind product + 1,683 Hadamard), plus
  433 LogUp roots and 6,639 layer/split boundaries. Local root/split batching
  cannot reach 5,000 while instances remain sequential. The first scheduling
  lever is therefore **proof-format/communication-neutral** round-synchronous
  co-scheduling, not RLC: it is an explicitly logged transcript-scheduling
  change, while every instance retains its own message, independent challenge,
  fold, proof bytes, and verifier path. One contiguous mailbox D2H serves all
  jobs ready in the same public epoch. Cohorts and initial claims are sealed before
  enqueue, challenges are drawn only after the complete epoch returns, no job
  may join after sealing, public depth/path controls membership, and canonical
  `SiteId` order (never completion order) binds all roots/splits.

  Prefill and deferred-decode phase-2 jobs may share a cohort only after both
  phase-1/auth/shared-alpha/KV domain states are already fixed; decode phase 2
  has no value dependency on prefill phase 2. A public `SchedulePlan` must
  prove an exact upper bound before the full run. Current shape projection is
  about 2,450 LogUp critical-path epochs and 3,100--4,200 total explicit
  barriers including non-LogUp/global/table/PCS work. This is a projection,
  not a gate result. Scheduled epochs must also replace or reserve beyond the
  512-record timing ring: co-scheduling roughly 24 layer jobs can otherwise
  inject a timing flush inside a sealed cohort. The scalar-RLC theorem remains
  the second lever only if exact co-scheduling fails the gate; CUDA graphs are
  subsequent device-only replay work and may not cross challenge barriers.

  **Schedule/transcript semantics fixed before Rust enablement**: "proof
  unchanged" means the existing proof structs, correction labels, message
  count and communication bytes are unchanged; it does **not** mean that a
  multi-job scheduled proof has the same field values as the historical
  sequential proof at the same deterministic mock-verifier seed. The current
  `Transcript::append` is accounting-only and the verifier challenge stream
  is global. In a scheduled epoch P first sends every active SiteId's message,
  then V returns the same number of fresh challenges in canonical SiteId
  order. Consequently CPU-scheduled and GPU-scheduled proofs must be byte
  identical to each other, while scheduled-vs-legacy values normally differ.
  Per-SiteId challenge substreams are rejected: they add a second transcript
  semantics without reducing barriers and would require separately routing
  every global chi/rho/finalizer challenge.

  `SiteId` v1 is a stable packed `(version, public section, round family,
  public lane)`, never a `Debug` string or runtime completion index. A sealed
  `SchedulePlan` is built from public geometry and both parties preflight exact
  membership, family, depth and reserved correlation range before consuming a
  transcript byte or one-time correlation. The active set may only shrink;
  missing/extra/duplicate jobs, refill and partial retry are errors. Product,
  degree-3 and LogUp messages may share one heterogeneous mailbox epoch, but
  every instance retains an independent challenge and verifier recursion.
  The public plan publishes mailbox bounds, but no CUDA timing metadata.
  Resident LogUp's private, deterministic preparation chunks are the sole
  source of truth for profiler-ring capacity; the last chunk reserves two
  additional records for the coarse mailbox interval and its D2H. These
  chunks never split protocol membership or add a proof-message epoch. An
  automatic timing flush inside the sealed epoch remains forbidden and cannot
  be hidden from the <=5,000 count.

  The first byte-identical mechanism before cross-instance scheduling
  coalesces already-independent scalar buffers at each local boundary: two
  LogUp roots, four normal splits, aux q0/q1/column splits, and final
  product/Hadamard scalars use one D2H mailbox per boundary. Exact full
  structure projects **19,932 fewer response-session barriers** (10,434
  prefill, 9,498 decode), about 6.00 s at the measured 301.208-us median
  8-byte D2H RTT, with unchanged D2H/H2D and about 0.45 MB extra D2D. This is a
  mechanism projection pending measurement and remains far above 5,000 by
  itself. The audited role-antichain LogUp plan is 2,446 epochs (873 FFN +
  1,573 attention; max 1,573 when those independent phase-2 branches are
  interleaved), validating the ledger's earlier ~2,450 projection without a
  coroutine or cross-layer mutable-context redesign.

  **P7b architecture-hygiene checkpoint (2026-07-13; no timing claim)**:
  before changing the round schedule, the resident allocation registry was
  replaced by an opaque generational `(generation, slot)` arena. Active-ID
  lookup and stale rejection are O(1); inactive physical allocations use
  best-fit reuse; logical free issues no CUDA call; explicit trim releases
  only inactive capacity after a classified allocator barrier. ABI 19 reports
  physical `cudaMalloc`/`cudaFree` separately from logical alloc/reuse/free,
  partitions every explicit stream synchronization into host-output,
  upload-lifetime, timing-flush, legacy-profiling, or allocator-flush, and
  enforces that the reason sum equals the total. Device memory is partitioned
  exactly into primitive workspace, active resident capacity, and cached
  resident capacity. The report records both pre-trim high water and
  post-trim teardown and accepts a schema-4 run of record only when both
  accounting invariants hold. Clean-tree detection now includes untracked
  files and treats a failed `git status` as dirty.

  PCS commit/open temporaries now have exhaustive RAII cleanup on every early
  return. Compound matrix teardown preflights all context ownership before it
  consumes a handle; a wrong-context error returns the complete matrix so the
  caller can retry with its owner. On Thunder A100, the rebuilt monolithic
  backend passes all **16/16** `volta-accel --features cuda` tests, including
  best-fit/no-alias, stale and double-free rejection, logical bounds, trim and
  reason accounting; all **3/3** resident PCS CUDA differentials pass,
  including injected partial-commit and cross-context opening failures.
  The legacy host-barrier timing fallback was also corrected to attribute its
  three barriers to H2D/kernel/D2H causes rather than labelling all of them as
  profiling.

  **Deferred resident profiling checkpoint (2026-07-13)**: ABI 20 adds a
  resident-only fixed ring of 512
  lazily allocated CUDA-event records. Device-only primitives and pageable
  H2D uploads now enqueue without a host barrier; D2H host outputs, a full
  ring, explicit stats/measurement completion, reset, and physical
  reclamation flush the stream with the existing reason accounting. The ring
  retains metadata only (no shadow upload payload or host-RSS growth), and a
  flush queries the complete batch before committing attribution. Failed
  calls abort the active record, while destroy/reset/reclaim preserve stream
  ordering. New exact counters report records, event queries, pending high
  water, and non-empty flushes; report rows expose all four. Empty H2D/D2H
  phases do not issue elapsed-time queries (a remote CUDA API call): a
  device-only primitive needs one query, not three. `synchronizations` and the
  <=5,000 gate count explicit backend stream barriers; pageable-H2D staging
  wall remains visible in end-to-end wall/residual rather than being
  mislabelled as an explicit barrier.

  The pageable-H2D lifetime assumption is load-bearing and is therefore a
  measured platform contract: on Thunder A100, immediate source mutation
  after a 4 MiB upload, source drop followed by generational free/reuse of the
  same physical allocation, and a 513-record ring-wrap all pass. The full
  rebuilt backend passes **19/19** CUDA tests and the resident PCS suite passes
  **3/3**; the local Rust workspace is green. Hybrid mode remains on the
  legacy timing path, and runtimes without usable event elapsed time retain
  the synchronous host-barrier fallback.

  Clean quick diagnostic at SHA `956f81f` (T=16+8, Q=200, one repetition;
  not the preregistered T=100+50 gate): immutable
  `benchmarks/results/p7-integrated-resident-quick-2026-07-13-956f81f.json`
  (SHA-256
  `bed809772fb926cf2328502a0572011a3dc2cca9696aaec2cc6c72af5c087a8a`,
  `git_dirty:false`) is accepted and flat-cost passes at **1.05**. Prefill
  proof is **28.599 s** and response proof **50.363 s** (decode marginal
  **21.764 s**); these quick-shape values are diagnostic, not gate results.
  The response-session attribution is **52.208 s** wall, **4.684 s** kernels,
  873,917,300 B H2D and 81,516,788 B D2H. Explicit barriers fall to
  **61,675**, all host-output; legacy profiling and upload-lifetime barriers
  are both zero. Prefill has 32,851 barriers = 32,819 host-output + 32
  allocator. Thus deferred timing closes exactly the profiling-barrier lever
  but misses the <=5,000 sync gate by 12.3x even at quick geometry: the next
  required lever is cross-instance host-output coalescing/RLC, not cheaper
  synchronization. The arena records only 239 physical allocations for
  181,021 logical requests (180,783 reuse hits). Empty-phase suppression
  reduces session elapsed-time queries to 189,426 for 151,835 records, but
  per-kernel queries remain a measured remote-call surface.

  A standalone CUDA implementation of the exact `rand_chacha 0.3.1`
  ChaCha8 stream layout plus Goldilocks rejection sampling is now available
  for device-side prover-owned pads/masks. It explicitly excludes verifier
  challenges and `Delta`. CUDA 13.2 / sm_80 results are byte-identical to the
  Rust `FpStream` oracle in the clean immutable result
  `benchmarks/results/p7b-chacha8-fp-diff-2026-07-13-32653fd7e076.json`
  (source SHA `32653fd`, `git_dirty:false`, result SHA-256
  `21207d234e32b8eec56545e0e652e2c97f56787c62ab4e138b361c67f3c97906`)
  on A100-SXM4-80GB. The Fp multi-block case has stdout SHA-256
  `1570f825215b0e38da4857fc32b40a97b8bf0efed7f90f6c44431e801b7c2634`
  and the Fp2/high-64-bit-domain multi-block case has stdout SHA-256
  `90abbd2a0773f9c455313a3eab8172a1647a2c7cea152fa71324ef996c220051`.
  Both raw stdout and parsed structures match. This checkpoint validates the
  generator and ownership boundary only; H2D savings are not claimed until
  it is integrated into the PCS kernels and measured in the full session.

  **Device-source PCS integration checkpoint (ABI 21; 2026-07-13)**:
  resident commitments no longer flatten or re-upload layer/embedding
  weights. Checked, aligned tensor placements copy the already-resident
  `CAttnProof`, projection, FFN and embedding views into a zeroed packed
  target via explicit D2D row copies. Row pads and padded Fp2 opening masks
  use the byte-identical device ChaCha8 expansion; `c` powers, block-row
  coefficients and all `s_g` row dots are also materialized on device. The
  pad seed remains a prover-secret of the static weight registration (not a
  response nonce); the ephemeral mask seed is response-fresh and separated
  by role/instance. Neither path receives a transcript challenge, a shared
  mock-PCG/correlation seed, or `Delta`. The public report calls the new
  counter `explicit_d2d_copy_bytes`: it covers these explicit row-copy APIs,
  not every internal kernel/workspace movement. H2D remains the complete
  backend payload counter used by the gate.

  On the designated Thunder A100, ABI-21 passes **21/21** accelerator tests
  (including a real Goldilocks rejection-sampling vector) and **5/5** resident
  PCS tests. The latter check CPU/GPU-identical commitment roots, full proof
  objects, transcript ledgers and correlation counts, two-placement padded
  geometry, wrong-context/overlap/failure cleanup, and response-fresh mask
  proofs with unchanged size and successful verification. Resident report
  schema 5 serializes the P7b observations explicitly: timing gates use the
  upper median across measured repetitions, count/traffic gates use the
  maximum measured session, and quick runs set `p7b_gate_evaluated:false`.

  Dirty-tree quick diagnostic only (never a gate claim):
  `p7-integrated-resident-quick-2026-07-13-8b5d177-1.json`, SHA-256
  `d9d06071355e4428cc3878eb952ada87bc8e30c36f4b7d029d31869f878866d0`,
  is accepted with all 13 Q=200 PCS openings and flat-cost 1.0003. Session
  H2D falls from the preceding quick checkpoint's 873,917,300 B to
  **24,909,172 B** (-849,008,128 B, -97.15%); D2H is 81,518,420 B. Explicit
  D2D copies are 313,339,392 B, device zeroing 702,652,416 B and device
  generation 115,302,400 B. Synchronizations are **61,688**, all
  `host_output`: the 13 new batched `s_g` scalar reads add exactly 13 to the
  prior 61,675, so this checkpoint closes the H2D mechanism but deliberately
  does not claim the <=5,000 scheduler gate. PCS commit/open/verify are
  0.181/0.592/0.296 s; total kernels are 4.458 s. Core wall (31.262 s prefill,
  26.756 s decode marginal) regressed under remote variance despite the lower
  kernel total and is not compared as a performance result. A clean immutable
  checkpoint is required before promoting the traffic observation.

  The immutable rerun now satisfies that hygiene gate:
  `p7-integrated-resident-quick-2026-07-13-bf66c8f.json` (source `bf66c8f`,
  `git_dirty:false`, SHA-256
  `1b405aa54237aab45425eedb3648c6a855ad89b9e0d4f85e9e10d929d63b59da`).
  It is accepted, all 13 Q=200 PCS openings verify, flat cost is 0.9882, and
  the traffic/count observations reproduce exactly: **24,909,172 B H2D**,
  81,518,420 B D2H, 313,339,392 B explicit D2D copies, 702,652,416 B device
  zeroing, 115,302,400 B device generation, and **61,688 host-output
  synchronizations**. PCS commit/open/verify are 0.174/0.566/0.349 s; kernel
  total is 4.839 s. Core prefill is 27.868 s and decode marginal 23.425 s.
  Because this is T=16+8 quick geometry, schema 5 correctly records
  `p7b_gate_evaluated:false`; it validates the implementation and H2D
  mechanism, not any of the T=100+50 official verdicts. The full-geometry H2D
  projection remains about 96.43 MB and must be confirmed, not inferred, by
  the later clean gate run.

  **P7b iteration-2 orchestration checkpoint (ABI 26 / report schema 6;
  implementation and correctness only, no timing claim)**: deferred CUDA
  timing now retries an elapsed-time query that returns success without
  writing its output, using one complete first pass followed by at most three
  exact retry sweeps and failing closed if a record remains unresolved.
  Separate attempt, successful-query and no-write counters must balance
  exactly. Measurement reset synchronizes and discards
  pre-window records without querying elapsed time before zeroing statistics;
  in-window records retain exact attribution. Aborting a coarse scope after
  any accounted primitive now poisons the measurement: statistics and finish
  fail closed until an explicit synchronizing reset, so discarded event
  intervals cannot reappear as host residual. Checked coarse timing scopes
  cover device-only cohort work, while segmented host outputs use one coarse
  mailbox scope and one D2H. None of these paths fabricates a duration or
  relabels remote CUDA calls as CPU work. The C ABI independently rejects
  mock-auth mask domains entering reserved bits 61--63 rather than relying on
  the safe Rust wrapper alone; ABI and `RawStats` layout remain version 26.

  Schema 6 retains the upper-median timing and maximum-session traffic/count
  rules from schema 5, but emits only `P7b-*` CUDA milestone names and makes
  an official verdict conditional on Thunder provider metadata, an A100,
  clean-tree checks both before benchmarking and before serialization, and
  one identical nonempty full Git SHA across that complete window,
  T=100+50/Q=200, at least one warmup and at least three measured repetitions.
  Acceptance, golden/flat checks, the 200 MB envelope and no growth in the
  P7 transcript, PCS-opening, packed-logits and packed-response components are
  mandatory alongside the four P7b gates. Mock-PCG is serialized with
  `pcg_production_ready:false`; the harness cannot present it as production.
  The Python selector independently reconstructs upper medians and maximum
  session counts from the raw repetitions and rechecks every invariant and
  exact threshold; a coherent measured failure remains an official verdict,
  while a missing or self-inconsistent boolean cannot become one.

  Correlation ownership is now sealed through exact, disjoint full-correlation
  range reservations and exact submask-row reservations before transcript or
  one-time stream consumption. Reservation failure is atomic, and unused
  reserved draws are released on error. Prover authentication masks may be
  expanded on device only for the named deterministic mock backend, using the
  byte-identical ChaCha8/Goldilocks stream and host-owned domain counters. The
  pooled/real-PCG backend retains its host-produced authenticated masks and is
  never silently routed through this device generator; mock remains explicitly
  non-production. Thunder A100 differentials for the ABI-26 substrate and
  fault injection, pre-window reset, segmented mailbox, device mock-auth mask,
  resident product batch and heterogeneous LogUp batch are green.

  The scheduling implementation now includes coalesced local scalar
  mailboxes; one canonical round mailbox for the twelve attention heads in
  each W·V and Q·K product cohort; and a generic heterogeneous-depth LogUp
  batch with sealed `SiteId`, exact correlation-role ranges and all-site
  `TableBank` manifests. Its leaf path keeps and folds only q0/q1; public
  p0/p1=1 values are reconstructed on the host rather than copied or assigned
  correlations. Existing proof structs, correction labels, message counts
  and communication bytes are preserved; CPU-scheduled and resident-scheduled
  outputs are the required exact differential, not scheduled-vs-legacy field
  values under a globally reordered challenge stream.

  GELU is the first response call-site integration: all twelve prefill layers
  and all twelve layers of every deferred decode band are preflighted into one
  response-wide manifest before table-bank finalization or scheduled-root
  mutation, then each public band runs one CPU/resident/verifier cohort. For
  the official one-T=100-prefill +
  one-q=50-band geometry this projects **3,993 fewer blocking
  synchronizations** than twelve sequential GELU sites; it is a geometry
  projection, not a measurement or gate result. A latent resident decode
  `SiteId` mismatch was also fixed: attention product sites had used the
  physical layer index where CPU/verifier used the public decode-domain
  section. Canonical ordering had masked the mismatch; the resident path now
  derives the same public section and has a dedicated regression test.

  The final architecture audit also made verifier entry and resident cleanup
  fail closed. `verify_response` validates public dimensions, every indexed
  phase-1 proof shape, table cardinalities, the at-most-five-chunk namespace
  and checked position arithmetic before consuming a challenge or correlation
  key. Greedy decoding now binds the first token of every later chunk to the
  final logits row of its predecessor; malformed calls leave transcript bytes,
  transcript ledger, allocation digest and verifier counters unchanged. The
  FFN scheduler, generic LogUp cohort and resident blind-sumcheck batch perform
  exhaustive ownership sweeps and propagate the first release error ahead of
  the operational error. In particular, a timing-capacity failure on LogUp's
  second preparation chunk can no longer strand the first 56 device owners.

  The implementation evidence remains separate from the performance verdict:
  CPU full-response e2e at T=12 plus one q=4 decode band is green; the full
  local workspace (including 80 protocol tests after the cleanup regressions),
  the five report tests, the five Python selector tests and the CUDA-feature
  `--no-run` build are green. The A100 ABI-26 accelerator suite is 32/32; on
  the clean `61aafe8` checkpoint the device-auth, product-sumcheck,
  heterogeneous-LogUp, attention, band-layer and full-response differentials
  are green; the scheduled proof remains byte-identical to its CPU path, the
  verifier accepts it and replay rejection remains green.

  The first clean call-site-scheduler measurement is the append-only quick
  diagnostic
  `benchmarks/results/p7b-integrated-resident-quick-2026-07-13-61aafe8.json`
  (full source SHA `61aafe8f8d8a1db6dded82266ad10a040715e8f7`, SHA-256
  `fe12b8efc77137587e08a11c6a41a2157520ab90cef182e14c8c6ad53e9a6a25`).
  It was run from an isolated clean clone of a checksum-matched bundle;
  before-benchmark and before-serialization trees are clean at the same full
  SHA, and the Thunder/A100 metadata is complete. The response is accepted,
  all 13 Q=200 PCS openings verify, chunked verification passes, flat cost is
  0.9872 and the packed 82,281,642 B response remains inside the communication
  envelope. Explicit resident bytes are zero after cleanup; cache trim leaves
  only the 14,286,896 B workspace. Mock-PCG is explicitly non-production.

  At T=16+8, response-session H2D is **12,656,708 B**, D2H is 81,518,420 B
  and blocking host-output synchronizations are **39,201**. Relative to the
  clean `bf66c8f` quick baseline this removes 12,252,464 B H2D (-49.19%) and
  22,487 synchronizations (-36.45%); D2H is unchanged. The single-sample core
  times are 27.154 s prefill, 50.782 s response and 23.628 s decode marginal,
  with 52.146 s response-session wall. ABI-26 coarse intervals include device
  idle gaps while the host submits remote work, so their 12.393 s aggregate is
  not comparable to the old per-call 4.839 s kernel total.

  Because this diagnostic has T=16+8, zero warmups, one measured repetition
  and no golden check, schema 6 correctly records
  `p7b_gate_evaluated:false`: **none of the <=10 s / <=4 s / <=5,000 sync /
  <=100 MB official gates is evaluated or claimed**. The 39,201 sync count is
  already 7.84x the numeric gate at smaller geometry, so an expensive official
  full run is deliberately withheld until another blocking-output batching
  step; this is a readiness decision, not an official failure verdict. The
  next protocol-neutral lever is further coalescing of dependent host-output
  boundaries, especially non-GELU LogUp and blind sumchecks.

- **2026-07-13 (P7 publication artifact closed)**: clean aggregate
  `benchmarks/results/p7-2026-07-13-2c836b3.json` (SHA-256
  `6aa5d6927e8f511b4d9ca7881ac4e6c50ffd32b8fb48fbb9badc764dcc9aa78a`)
  joins the resident proof only to its exact same-instance native anchor and
  records `measured_same_host_targets_fail`; the historical hybrid result
  remains a separate attribution artifact. `docs/p7-artifact.md` contains the
  quick/full A100 commands and claim boundary;
  `artifact/p7/hardware-a100.json` pins hardware, CUDA/Rust, workload and raw
  checksums. `scripts/p7_artifact_outputs.py` regenerates the checked-in
  result table, rho SVG, response-attribution SVG and shape CSV and has a
  strict `--check` mode. All eight Python artifact/report tests pass. The
  frozen Lean project builds (2571 jobs) and `scripts/audit_lean.sh` confirms
  all eight audited M1--M9 theorems depend only on `propext`,
  `Classical.choice` and `Quot.sound`; the four named external assumptions do
  not enter that boundary. P7 is complete with a negative performance
  verdict, not deferred or relabeled as production-ready.

- **2026-07-13 (post-e2e synthetic shape/memory sweep complete; no new
  frontend or e2e claim)**: clean append-only result
  `benchmarks/results/p7-shape-memory-sweep-2026-07-13-797f499.json`
  (SHA-256 `59df28891f7a5c024a98e66f1bb1d470cf8d7909d334dbcd92190076b5fec42a`)
  evaluates sequence lengths 150/512/2048/8192 for exactly three declared
  profiles: the measured GPT-2-small shape, a representative Llama-class 8B
  dense/GQA shape and the documented gpt-oss-20b/MoE-active planning shape.
  The frozen GPT-2 manifest closes exactly at 124,701,952 i16 elements /
  249,403,904 B; the analytic Llama shape is 8,030,261,248 parameters with
  GQA KV fraction 1/4; gpt-oss uses 20.9B total / 3.6B active parameters,
  hence 41.8/7.2 GB i16 total/active weight bytes. Linear state rows are
  monotone, GQA reduces KV as expected and active MoE weights remain below
  committed total weights. The JSON links the measured 5,405,147,708 B
  GPT-2 proof peak but explicitly projects neither non-GPT proof time nor
  proof peak memory. `ModelConfig`, Llama/gpt-oss frontends and non-GPT e2e
  remain out of scope.

- **2026-07-13 (`P7-integrated-resident` full run and same-host native anchor
  complete; performance gates failed)**: clean immutable full run
  `benchmarks/results/p7-integrated-resident-2026-07-13-1fd5195.json`
  (SHA-256 `02538a48511354f7ce92ba0602240edab9eede344aa30e351b7c03d338679c6b`)
  uses the workload of record T=100+50, Q=200, one warmup and three measured
  repetitions on A100-SXM4-80GB/CUDA 13.2. All three proofs accept; the full
  golden decode is exact, verifier and 13 stacked PCS openings pass, flat
  last/first is 0.950 <=1.5, and packed response download is 144,820,930 B
  inside the 150--200 MB envelope. Explicit resident bytes return to zero;
  104,988,720 B of reusable context workspace remain named, and peak device
  memory is 5,405,147,708 B. Peak RSS is 2.226 GiB.

  Protocol-core medians (MAD) are 64.295793 (0.329496) s prefill,
  121.155759 (0.372825) s response and 57.295866 (0.808726) s decode
  marginal. Online-accounted response is 121.774353 s and online marginal is
  57.924561 s; the complete single-process response-session wall is
  123.927768 s. PCS commit/open/verify are separately
  0.765752/0.610145/0.370512 s and accounted in that wall; accounted verifier
  is 1.044615 s. Resident witness generation is 0.111155 s for prefill and
  0.247386 s for the T=150 response, yielding measured resident pipeline
  totals of 64.406948 s (prefill inference + core), 122.021740 s (response
  inference + online-accounted prover) and 124.175155 s including the full
  local response session.

  The same-host exact native anchor
  `benchmarks/results/p7-gpu-native-inference-2026-07-13-1fd5195.json`
  (SHA-256 `73ce54cf8759b7b91b5a032098a1d5eb77bd8c804256ce9c5c8eba2820556c9f`)
  is golden-exact over seven repetitions: prefill 0.017341642 s (MAD
  0.000062169) and KV decode50 0.599345878 s (MAD 0.000989627), with weights
  resident and per-token logits D2H/argmax timed. Thus preregistered
  rho_proof is **3707.595 >10 FAIL** prefill and **95.597 >2 FAIL** decode;
  gaps to target are 370.760x and 47.799x. The online-accounted decode rho is
  96.646.

  Attribution explains why this is not a near miss: the representative
  response session has 5.998 s CUDA kernels, 89.055 s CPU residual,
  945,442,180 B H2D, 138,488,436 B D2H and 211,709 synchronizations (72.652 s
  synchronization wall). Even eliminating all measured host/transfer cost
  would leave kernel time far above the 173 ms prefill proof budget. The
  result therefore closes the requested e2e measurement honestly; it does
  **not** support a production-ready or target-meeting claim. Reaching the
  targets requires a new coarse-grained GPU protocol architecture (device
  transcript/challenge batching and materially fewer proof passes), not a
  local benchmark tweak. Mock-PCG remains the named baseline and its
  two-party/parameter hardening blockers remain unchanged.

- **2026-07-13 (`P7-integrated-resident-quick` clean ABI-v17 harness gate
  passed; full remains mandatory)**: immutable clean-tree run
  `benchmarks/results/p7-integrated-resident-quick-2026-07-13-1fd5195.json`
  (SHA-256 `630629287213978f8dd6aa5e46703e962d5fe2226ca843e5050bd5f048f7ddc1`)
  on A100-SXM4-80GB/CUDA 13.2 accepts the resident proof, all 13 Q=200 PCS
  openings, the unchanged verifier and the two-chunk flat-cost session at
  T=16+8. Protocol-core wall is 46.874 s prefill and 85.853 s response;
  online-accounted response (core + PCS open + closure) is 86.585 s, and the
  complete single-process response session is 88.354 s. PCS commit/open/
  verify are 0.851/0.724/0.311 s, flat last/first is 0.995 <=1.5, packed
  download is 82,281,642 bytes and peak device memory is 4,991,265,544 bytes.
  After dependency-ordered cleanup, total live equals the reusable workspace
  exactly (14,286,896 bytes) and explicit resident allocations are zero.

  Attribution is intentionally retained: the response session performs
  151,835 synchronizations, 873,917,300 B H2D, 81,516,788 B D2H, 4.002 s of
  kernels and 61.541 s of host residual. This exposes substantial remaining
  orchestration/transfer cost rather than relabeling device-resident witness
  storage as a fully GPU-saturated prover. Quick skips the full golden-decode
  gate and has one repetition, so its rho must not be quoted. Proceed with the
  preregistered T=100+50, one-warmup/three-repetition run before deciding the
  resident targets.

- **2026-07-13 (`P7-integrated-resident-quick` cleanup-accounting gate caught
  a workspace/ownership ambiguity; no JSON emitted)**: the first clean quick
  attempt from `634c59c` completed the resident proof, all 13 PCS openings,
  verification and the flat-cost curve, then deliberately aborted before
  serialization because total live CUDA memory was 14,286,896 bytes rather
  than zero. Audit shows these bytes are the 16 context-owned primitive
  workspace slots, which `ensure()` grows and intentionally retains for
  reuse; every explicit `DeviceBuffer` is tracked separately in the same
  total. Treating reusable workspace capacity as a witness leak would violate
  the preregistered persistent-workspace design.

  ABI v17 therefore adds a read-only memory breakdown computed from the CUDA
  context's workspace slots and opaque resident-allocation registry, with an
  internal invariant that their sum equals total live bytes. Report cleanup
  now requires **zero explicit resident bytes** and total live bytes equal to
  reusable workspace bytes; both values are serialized. No allocation is
  hidden or released merely to improve the number, and context destruction
  still frees both classes. The failed attempt produced no raw result and its
  observed quick timings are not a benchmark claim. The clean quick must be
  rerun from the ABI-v17 checkpoint before the full gate starts.

- **2026-07-13 (`P7-integrated-resident` e2e report harness landed; clean
  measurement still pending)**: the existing `p6_report` now selects the
  internal resident backend explicitly and consumes one persistent uploaded
  model, a resident prefill witness, a resident T=150 response witness and
  D2D-derived decode bands. The unchanged `ModelProof` is verified through
  the existing `verify_response`; the same 13 PCS commitments/openings are
  executed through resident matrices. Repetitions reuse the same context and
  buffers, while all owned allocations are released in dependency order and
  a zero-explicit-resident-bytes assertion closes the run (persistent CUDA
  workspace capacity is reported separately). CPU remains the default;
  asking for resident CUDA still fails explicitly if the feature/library is
  unavailable.

  Timing schema v3 preserves the preregistered protocol-core
  `t_prove_*`/rho fields, but also records per-repetition (a) online-accounted
  core + PCS opening + final closure exchange, (b) the complete one-process
  response-session wall including offline PCS commitment and verifier, and
  (c) PCS commitment/open/verify separately. Resident witness, proof and PCS
  accelerator scopes retain kernel, CPU residual, H2D/D2H, synchronization,
  allocation and peak/live-device attribution. The aggregate joins a full
  resident run only to a clean exact native-GPU anchor with the same cloud
  instance id and exposes resident inference + proving separately. Mock-PCG
  remains named and is never presented as production-grade. This is reporting
  and resource-lifecycle plumbing only: transcript, proof bytes, verifier,
  Q=200, quantization and Lean-facing assumptions are unchanged. No resident
  performance claim is registered by this entry; quick smoke and then the
  clean 1-warmup/3-repetition T=100+50 run are still required.

- **2026-07-13 (`P7-integrated-resident` stacked-response correctness gate
  landed; publication timing remains open)**: checkpoint `b0088f2` extends the
  existing square resident prover rather than introducing a parallel
  protocol. `prove_model_resident` remains the compatibility wrapper over one
  `prove_response_resident` core. Prefill and all decode bands bind their
  resident lookup columns before a single shared-alpha table-bank finalize,
  then contribute to the same model-wide product/zero batches and unchanged
  `ModelProof`. K/V plaintext is folded directly from the full contiguous
  device cache; Rust retains only ordered `(domain, rows)` prefix metadata.
  Band seams, embedding, final LayerNorm, public-logits claim and selection
  use checked resident operations with transactional ownership cleanup. The
  only host inputs unique to a chunk are public tokens and public logits,
  already required by the protocol/verifier.

  On A100 `instance-3d0rtrml-main` with CUDA 13.2, the release gate proves a
  real GPT-2 response at T=3 plus one Q=3 deferred chunk. Against the same
  seeds, CPU and resident paths match exactly for the entire proof, 96 weight
  claims, six embed claims, byte/lookup/correlation counters, all table
  closures, product/zero rows and transcript accounting. The existing
  `verify_response` accepts, including public greedy checks and true-weight
  resolution; global product and zero batches close. A second proof on the
  same CUDA context is identical with stable live device bytes, while a
  replayed chunk-K correction is rejected. The CUDA error word stays zero and
  resident LogUp/GEMM paths report no operation-local CPU residual. The CPU
  `volta-proto` suite remains 56/56. This 150.77-second test deliberately
  includes CPU reference, two resident proofs and verification; it is a
  correctness artifact, not a benchmark sample, JSON of record or rho.

- **2026-07-13 (`P7-integrated-resident` authenticated-prefix decode-band
  layer proof landed; stacked-response gate still open)**: checkpoint
  `0c56c66` generalizes the existing resident layer proof over the sealed
  `ResidentLayerView` and consumes the complete K/V cache through one
  contiguous device view plus a list of `(domain, rows)` segments. Prefix
  plaintext never returns to the host: Rust retains only the authentication
  domains needed to derive the matching MAC tags. The same phase-1/phase-2
  proof structs, transcript labels, verifier format and byte/count formulas
  are used for square and band shapes; runtime `(t0,q,seq)` geometry replaces
  any model-specific accelerator constant.

  On the replacement A100 `instance-3d0rtrml-main` (A100-SXM4-80GB, sm_80,
  CUDA toolkit 13.2), the new release differential proves layer 0 at
  `(t0,q)=(2,3)` after authenticating the two-row K/V prefix under separate
  domains. CPU and resident paths match exactly for the complete layer proof,
  four weight claims, byte and lookup breakdowns, table closures,
  product/zero batches, all domain/correlation counters and the transcript
  ledger; the CUDA sticky-error word remains zero and LogUp/GEMM report no
  operation-local CPU residual. This was a development correctness test, not
  a clean-tree benchmark or JSON of record. Full-response verifier,
  anti-replay, context-reuse and timing gates remain mandatory before any
  resident rho is recorded.

- **2026-07-12 (`P7-integrated-resident` full square-layer/model proving
  correctness gate landed; timing not yet permitted)**: ABI v15 connects the
  real T=3 square/prefill witness to both layer phases and to the complete
  twelve-layer model prover without materializing a host `ModelWitness`.
  Embedding, every block, final LayerNorm and logits are consumed through
  checked resident views; Rust retains challenges, transcript ordering,
  correlation domains and the unchanged proof representation. Generic
  resident requant-column and vector-repeat operations take runtime shapes;
  no GPT dimension was added to the accelerator interface. Failure cleanup is
  transactional, including the phase boundary where an FFN failure precedes
  attention ownership transfer.

  The clean detached checkpoint `c1486b8` was built as CUDA ABI v15 on A100
  `instance-3mq19up4-main` (sm_80, CUDA toolkit 13.0). All 15 accelerator
  tests passed, followed by the real-weight full-layer and full-model gates.
  With identical seeds the CPU and resident paths produce byte-identical
  proof objects, public claims, proof byte/count breakdowns, lookup and
  correlation counters, product/zero batches and transcript ledgers; the
  unchanged verifier accepts. Two model proofs reuse one CUDA context with
  stable live allocation bytes, and a CUDA-derived correction fault is
  rejected. This closes square/prefill proving correctness only: it is not a
  T=100 timing sample, has no JSON of record and carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` decode-band witness gate landed;
  band proving still open)**: ABI v16 adds one sealed, shape-parametric D2D
  strided-row compaction operation. A `ResidentBandModelWitness` borrows all
  contiguous q-row windows from a longer resident response witness, owns only
  the seven non-contiguous causal/head layouts, retains the complete K/V
  prefix as checked device views, and derives band final-LN/logits on device.
  It supports an arbitrary valid `(t0,q)` window, including a non-suffix band,
  so the P6 5x10 flat-cost curve can be derived from one resident T=150
  forward without host witness copies.

  On the same A100, clean checkpoint `5a571f1` passed all 15 CUDA accelerator
  tests and the dedicated T=6, `(t0,q)=(2,3)` differential. Every wire of all
  twelve layers, embedding rows, final LayerNorm and logits equals the CPU
  band bit-for-bit over repeated use of one context; live bytes are stable and
  the online transfer boundary is only the four-byte sticky-error init/result.
  This is a resident witness/dataflow result, not yet a decode proof or timing
  result. No resident rho may be quoted until band/full-response proof
  equivalence and the preregistered repeated A100 report are green.

- **2026-07-12 (`P7-integrated-resident` complete square-attention proof
  checkpoint; layer/model orchestration still open)**: ABI v13 materializes
  the proof-only attention view directly from the causal-packed resident
  witness: shared rectangular score/exp/weight columns, stable-softmax
  `is_max`, padded row tables, full and sparse-above QK accumulators, and the
  padded/permuted QKV range columns. One checked owner exposes only typed
  column views. The builder takes runtime q/s/head geometry, shifts and pad
  pairs; it contains no GPT-2 dimension or model configuration. Phase 1
  consumes these views for five lookup families/global histograms and
  authenticates LN vectors plus denom/recip/above/row-shift data without a
  host witness mirror. The real T=3 layer-0 differential checks every column
  in order against `build_attn_wires`, then matches all corrections, global
  multiplicities, alphas, counters and transcript exactly.

  ABI v14 adds the remaining reusable algebra: base-to-Fp2 lift/broadcast,
  a shape-parametric above-causal mask over a device equality row, weighted
  base-vector reduction, and strided-window MLE. Rust still generates every
  challenge and owns transcript/MAC orchestration. The resident attention
  phase 2 now covers projection, AV head splits, twelve W·V GEMMs, causal
  blind sumcheck, softmax normalization/row sums/row-max, twelve QK GEMMs,
  QKV and LN1. Mock-PCG boundary tags remain host-generated, while all
  plaintext folds and witnesses stay device-resident. The proof permutation
  of `c_attn` is prepared once in the internal GPT-2 model upload (setup), not
  embedded in the accelerator API.

  On A100 `3mq19up4`, the complete real `AttnBlockProof`, both PCS-bound
  weight claims, table closures, product/zero rows, theoretical counters,
  correlation consumption and transcript ledger are byte-for-byte equal to
  CPU. The unchanged verifier accepts after real-weight claim resolution and
  final batch closures. New primitive tests cover non-power-of-two window
  MLE, base broadcast, arbitrary weighted sums and above-mask indexing.
  CPU/default entry points and proof format are unchanged. This result is the
  full **square/prefill attention subgraph**, not yet a full layer/model or
  decode-band resident result and therefore carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` attention substrate checkpoint;
  attention proof still open)**: ABI v12 generalizes the resident matrix fold
  to a checked column window with an explicit physical row stride. This is
  the internal operation needed to fold per-head Q/K/V views without a
  gathered buffer; the accelerator receives only runtime geometry and a
  sealed scalar/axis tag. The original whole-matrix API remains a wrapper,
  so existing CPU/CUDA call sites and ownership rules are unchanged.
  `prove_gemm_act_chained_resident` consumes already-folded opaque device
  vectors and mirrors the existing activation×activation proof exactly:
  Rust still owns challenges, transcript messages, correlation domains and
  the caller-provided boundary MAC tag; only compressed round values and the
  final two field scalars cross D2H. Error paths consume both folds, and no
  new verifier or proof representation was introduced.

  CUDA 13.0/sm_80 on A100 `3mq19up4` validates the strided non-power-of-two
  fold bit-for-bit. A separate activation-GEMM differential compares the
  complete `ChainedGemmProof`, wire claim, bound point, transcript ledger and
  correlation counters with CPU over two uses of one context; all are exact
  and live device bytes remain stable. This checkpoint is intentionally a
  reusable attention substrate, **not** an attention/layer/e2e result and
  carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` complete FFN proof checkpoint;
  attention/model orchestration still open)**: ABI v11 adds only
  shape-parametric proof-data operations: canonical base-vector padding,
  zero-padded matrix MLE evaluation, typed pair columns for i16/i64/Fp
  sources, signed/nonnegative LUT histograms, a resident degree-3 triple
  product round, and broadcast Hadamard-factor construction. None embeds a
  GPT dimension or changes a protocol message. The mock correlation provider
  still supplies masks/tags on the host; witness values never cross D2H.
  `ResidentFfnP1` retains all five bound lookup-column allocations across the
  alpha boundary, authenticates the four padded LN vectors, and contributes
  its histograms directly to the global resident `TableBankP`. Phase 2 then
  consumes those columns, resident boundary openings, two resident committed
  GEMMs and a D2D-folded LN Hadamard proof. All owned phase-1 buffers are
  released transactionally on success or error. The existing verifier and
  proof structs are shared literally with CPU.

  On A100 `3mq19up4`, primitive tests cover non-power-of-two matrix MLE,
  nonzero vector pads, signed pair indices, LN inputs above i16 range,
  triple-product rounds and every padded LN factor bit-for-bit. The standalone
  Hadamard prover matches CPU proof/claims/product/zero rows, correlation
  counts and transcript across context reuse. The real layer-0 T=3 FFN gate
  uses frozen weights and biases: phase-1 corrections/global multiplicities,
  the complete `FfnBlockProof`, both PCS-bound weight claims, table closures,
  product/zero batches, theoretical counters, correlation consumption and
  transcript ledger equal CPU byte-for-byte. The unchanged verifier accepts
  the resident proof after true-weight claim resolution and both final batch
  closures. CPU `volta-proto` remains 56/56 and the CPU-default accelerator
  tests remain 3/3. This is a full FFN subgraph result, **not** yet a resident
  layer/e2e result; attention, layer/model seams, embedding/final-LN and PCS
  orchestration remain to be connected before reporting rho.

- **2026-07-12 (`P7-integrated-resident` explicit LayerNorm-accumulator
  checkpoint; no protocol change)**: the dataflow audit found that every
  LayerNorm affine accumulator is consumed by a requant proof but was not a
  first-class `LayerWitness` field; the CPU prover reconstructed it from the
  boundary/statistics/gain/bias values. ABI v10 removes that architectural
  asymmetry. The frozen CPU witness now records `ln1_acc`, `ln2_acc` and the
  final/band LN accumulator, while retaining the same recomputation as a
  prover-side consistency assertion for the already-logged LN-statistics
  deviation. The CUDA LayerNorm kernel writes the identical i64 accumulator
  in the same pass that emits mean, variance, rsqrt and requantized output;
  resident layouts expose it as a checked typed slice. Persistent model
  parameters also gain typed field selectors for later proof consumption,
  without exposing addresses, backend model constants or a `ModelConfig`.

  CUDA 13.0/sm_80 ABI v10 builds on A100 `3mq19up4`. The full non-power-of-two
  T=3 forward differential now checks both new accumulators in all 12 layers
  plus the final LN accumulator, alongside every pre-existing wire and full
  logits, bit-for-bit against CPU. Two context-reuse passes, forced-overflow
  rollback and recovery remain green; the measured online transfer boundary
  is unchanged (tokens/error initialization H2D, four-byte sticky error D2H).
  Quantization, proof/verifier formats, transcript and lookup counts are
  unchanged. This is a witness-contract correction required by resident
  proving, not a resident layer/e2e timing result.

- **2026-07-12 (`P7-integrated-resident` global table-bank checkpoint;
  layer wiring still open)**: the P6 one-vector-per-table-content construction
  now has a resident ownership mode inside the existing `TableBankP`, not a
  second protocol implementation. Per-site device histograms are accumulated
  D2D into one opaque `u32` allocation per `TableKey`. At phase-1 close, the
  replaceable mock-correlation seam supplies canonical masks H2D and only the
  existing 8-byte correction vector returns D2H; alpha ordering, domains and
  transcript labels are unchanged. At phase 2 the public table is uploaded,
  while its negative-multiplicity fraction tree and the global multiplicity
  MLE remain resident. A generic typed resident-MLE helper builds equality
  weights from the small transcript point on device and returns one scalar;
  the shared fraction-sum/cross-check tail is literally the CPU function.
  Error paths consume and release all owned multiplicity buffers, so a failed
  bank cannot leak allocations into context reuse.

  The A100 `3mq19up4` differential accumulates two padded range sites under
  the same content key, authenticates/finalizes them, proves both resident
  lookup instances, closes the resident table side, and repeats the full
  sequence on one context. Both site proofs, the complete `TableCloseProof`,
  product/zero rows, theoretical counters, correlation consumption and
  transcript ledger equal CPU exactly; live device bytes are stable across
  reuse and both caller-owned source buffers are freed exactly once. All 56
  CPU `volta-proto` tests remain green. This closes global multiplicity and
  table-side ownership, but is not yet a layer/e2e result: the FFN and
  attention phase-1 builders still construct their lookup sites from host
  `LayerWitness` vectors.

- **2026-07-12 (`P7-integrated-resident` device lookup-instance checkpoint;
  table-bank/layer integration still open)**: ABI v9 replaces the last
  host-built lookup-side inputs with shape-parametric resident operations.
  Requantization sites emit column-major proof columns directly from their
  accumulator/output buffers (single and chained forms), pair-LUT sites emit
  their two columns, and device histograms can be accumulated without a
  round-trip. A typed `DeviceLookupColumns` owns the allocation and exposes
  checked borrowed views; the protocol layer can pack `alpha_0 - f`, split
  every base column into even/odd Fp2 aux halves, and run the existing resident
  LogUp engine from that view. The source stays caller-owned. No raw pointer,
  GPT-2 dimension, transcript challenge, proof byte or verifier-format change
  enters the accelerator API.

  On A100 `3mq19up4`, the primitive differential covers single/chained range
  columns (including padded entries), pair columns, histograms plus in-device
  accumulation, packed leaves and aux deinterleaving bit-for-bit. The new real
  `blind_instance_prove_resident` gate uses a padded two-column range instance
  with a non-empty externally authenticated aux claim: proof object, roots,
  every open claim, product/zero rows, arithmetic counters, correlation
  consumption and transcript ledger equal the CPU path exactly. A second run
  reuses the same source/context with stable live allocation bytes; freeing the
  source subtracts exactly its allocation while the context's intentional
  workspace remains persistent. The earlier host-fed LogUp differential also
  remains green, as do all 56 CPU `volta-proto` tests (full frozen model,
  response proof and anti-replay included). This closes the lookup-side
  resident input seam, **not** a layer/e2e gate: global table multiplicities
  and table-side proofs still need resident ownership before wiring FFN and
  attention.

- **2026-07-12 (`P7-integrated-resident` protocol-algebra + chained-GEMM
  checkpoint; layer integration still open)**: ABI v8 introduces a sealed,
  typed resident field-algebra seam rather than GPT-specific proof kernels:
  subfield-auth correction generation for i16/i64/Fp inputs, Fp2-weighted
  matrix folds along either axis with power-of-two output padding, Fp2 dot
  reduction, compressed product-sumcheck rounds and D2D vector folds. Rust
  retains transcript challenges, correlation-domain allocation and proof
  construction; only the two compressed round values and final scalar claims
  cross D2H. Input matrices and every intermediate fold stay in opaque
  context-owned buffers. Scalar-kind tags and fold axes are sealed/validated
  on the Rust side, so downstream crates cannot forge an ABI layout.

  All 13 `volta-accel` CUDA tests pass on A100 `3mq19up4`, including signed
  conversion, non-power-of-two matrix shapes, both fold axes, padding,
  correction identities, Fp2 dot/product rounds and context ownership. The
  resident blind product-sumcheck is byte-for-byte equal to CPU for all round
  corrections, points, authenticated claims, correlation counts and
  transcript ledger, with stable live memory across reuse. Building on that
  shared primitive, the first real protocol path — a non-power-of-two
  committed chained GEMM — produces identical `ChainedGemmProof`, X/W claims
  and Π_Prod messages on CPU and CUDA across repeated use. Proof/verifier
  formats and CPU entry points are unchanged. This remains a substrate
  checkpoint: FFN/attention derived columns, LogUp leaf handles and model
  orchestration are not yet wired to it, so no layer/e2e resident result or
  rho is recorded.

- **2026-07-12 (`P7-integrated-resident` full forward + witness checkpoint;
  prover integration still open)**: ABI v7 adds shape-parametric fixed-point
  primitives for embedding, LayerNorm, biased GEMM/requant/residual, QKV
  split, causal-packed scores and softmax, AV, LUT application, seam requant
  and batched logits. The accelerator API receives runtime geometry and
  shifts only; GPT-2 constants and orchestration remain in `volta-gpt2`, and
  no `ModelConfig`, product CLI or stable public API is introduced.
  `ResidentGpt2Model` owns one persistent typed weight/LUT allocation;
  `ResidentModelWitness` owns packed i16/i64 allocations for every
  proof-relevant wire but deliberately has no lookup traces, which the
  protocol already recomputes from those wires. Accumulators, requantized
  values and residual boundaries remain distinct device regions, so later
  proving does not need to reconstruct or download them. A borrowed
  `DeviceSlice` carries only context-owned buffer identity, element offset
  and length, never a raw pointer.

  The CUDA 13.0/sm_80 library compiles on A100 `3mq19up4`. With the frozen
  weight artifact checksum-verified, the non-power-of-two T=3 differential
  compares embedding, all fields of all 12 layers, final-LN and the complete
  logits vector against the CPU `ModelWitness` bit-for-bit. It repeats the
  full forward twice on one context and returns live device bytes to the
  post-model-upload baseline after each explicit witness free. A forced
  fixed-point overflow additionally exercises transactional rollback: the
  call fails explicitly, every allocation made by that call is released,
  and a subsequent valid forward on the same context remains bit-exact.
  Inside the
  measured forward the only D2H boundary is the four-byte sticky
  no-clamp/domain error flag; online H2D is the token vector plus its
  four-byte initialization. The entire CPU workspace, including golden,
  full-proof and anti-replay tests, remains green without CUDA. This is a
  forward/witness contract checkpoint, **not** a resident e2e result: the
  current block/model prover still reads host `Vec` wires, so no resident rho
  is recorded and the report's `cuda-resident` guard remains in place.

- **2026-07-12 (`P7-integrated-resident` PCS family device path landed;
  model-witness integration still open)**: ABI v6 adds resident padded message
  construction, batched Fp/Fp2 NTT, row combinations and mask addition,
  selected-column gathers, and complete BLAKE3 Merkle trees/paths. Merkle
  parent nodes preserve the protocol's exact `blake3(left || right)`
  semantics (not BLAKE3's internal parent-compression flag), and Fp2 mask
  leaves support partial final hash blocks. `ResidentProverMatrix` is a
  separate internal type owning weight/pad/encoding/tree handles; public
  `Commitment`, `MultiOpenProof`, verifier and CPU/hybrid entry points are
  unchanged. During an opening, D2H is restricted to the mask root,
  u-vectors, queried data/mask columns and sibling paths already present in
  the proof format.

  On A100 `3mq19up4`, the primitive differential covers padded message rows,
  Fp/Fp2 NTT, combined rows, mask addition, gathers, every sibling path and
  roots, including a 48-byte Fp2 leaf with a partial BLAKE3 block. The PCS
  integration test passes CPU, hybrid and resident paths with
  `VOLTA_REQUIRE_CUDA=1`: commitment roots and full proof objects are equal,
  correlation counters/transcript ledgers match, the verifier accepts, a
  faulted queried column is rejected, and a repeated resident opening leaves
  live device bytes unchanged. All 11 CPU PCS tests also pass. This closes
  the PCS kernel family (mask rows, row combinations, NTT, gather and Merkle)
  for a host-fed checkpoint. Deterministic mask rows are still generated on
  the host before one upload, and weights/pads enter `commit_resident` from
  host slices; both are explicitly outside the final no-host-witness claim.

- **2026-07-12 (`P7-integrated-resident` LogUp family device path landed;
  host-witness upload still open)**: ABI v5 adds the degree-3 aux-leaf path.
  Aux columns and per-claim equality rows are packed once into resident
  buffers; equality rows are generated on device from the small transcript
  points, and q/column/eq folds remain device-to-device. Each aux round
  returns exactly `[g(0), g(2), g(3)]`; the only final D2H values are q
  splits and the two consolidated claims per aux column, all required by the
  existing protocol. Table/upper-tree behavior from the prior checkpoint is
  unchanged. The GPU uses uniform Fp2 leaf vectors while Rust preserves the
  original specialized theoretical E-mult counters exactly; transcript,
  proof format and verifier are unchanged.

  CUDA 13.0/sm_80 tests on A100 `3mq19up4` pass with
  `VOLTA_REQUIRE_CUDA=1`: all 11 `volta-accel` tests plus the blind-tree
  CPU/hybrid/resident differential. The aux differential now includes a
  non-empty, correctly opened external claim (therefore exercises batched
  eq-row generation and weighted aux accumulation), and repeats both table
  and aux trees on the same resident context. Proof objects, products,
  zero rows, counters, correlation consumption and transcript ledger equal
  CPU byte-for-byte; live device bytes are stable across reuse. This closes
  the progressively integrated LogUp kernel family, including aux leaves,
  rounds/folds and blind corrections. It is still **not** the resident e2e
  gate: `LeafQ`/aux columns originate as host vectors in the current prover
  entry point and are uploaded once. The device-witness entry point must
  supply those handles directly before paper measurement.

- **2026-07-12 (`P7-integrated-resident` LogUp core checkpoint; aux leaf
  still open)**: ABI v4 keeps the complete fraction tree, upper-layer round
  vectors, folds and suffix-equality tables in context-owned device buffers.
  Even/odd child separation and suffix tables are constructed by device
  kernels from the resident tree and the small transcript challenges; Rust
  receives only the two roots, four round accumulators and four final split
  claims required by the protocol. The table-side/non-aux leaf is
  materialized as resident Fp2 `(p,q)` from base-field leaves and uses the
  same device round/fold engine. The specialized CPU E-mult accounting is
  preserved exactly even though the GPU uses a uniform representation.

  On A100 `3mq19up4`, the targeted `volta-accel` residency test and
  `cuda_blind_tree_and_aux_proofs_match_cpu_byte_for_byte` pass with
  `VOLTA_REQUIRE_CUDA=1`: roots, proof, correlation products/zeros, counters
  and transcript ledger equal CPU. The aux case in that differential still
  executes its degree-3 leaf round and column/eq folds on the host; the test
  already exercises resident tree and upper layers around it. Consequently
  this is a progressive-kernel checkpoint, **not** the completed LogUp
  family and not a resident e2e gate. Next is the aux-leaf/column fold with
  only its three transcript evaluations and final column claims crossing
  D2H.

- **2026-07-12 (`P7-integrated-resident` ABI-v3 substrate landed; gate still
  open)**: the staged ABI could not preserve a value across calls because its
  16 workspace slots are freely resized and every primitive performs its own
  H2D/D2H. ABI v3 therefore adds context-owned opaque resident allocations,
  typed non-cloneable Rust handles, explicit alloc/upload/download/free
  boundaries, runtime cross-context rejection, and device-to-device GEMM plus
  fused requant/MAC-correction entry points. The API is shape-parametric and
  internal; it introduces no `ModelConfig`, public stable API or GPT-2
  constants. Persistent allocations are separate from reusable staged
  workspace and remain counted in live/peak device memory. Explicit resident
  transfers are timed and counted; resident kernels add no H2D/D2H bytes.

  The isolated A100 checkout on `3mq19up4` built the CUDA 13.0/sm_80 shared
  object and passed all 10 `volta-accel` tests with
  `VOLTA_REQUIRE_CUDA=1`. New gates cover non-zero buffer offsets,
  bit-exact i64 GEMM and fused outputs/corrections, measurement closure,
  zero kernel-time transfers, deterministic context reuse, live-byte return
  to zero after explicit frees, and rejection of a handle by a foreign CUDA
  context. CPU-only and `--features cuda` workspace checks compile locally.
  This is deliberately **not** a `P7-integrated-resident` result: forward and
  proving do not consume these handles yet, and no rho is recorded. Next
  checkpoints must keep LogUp/PCS/witness intermediates resident and expose
  only protocol messages to Rust.

- **2026-07-12 (same-host corrected native GPU anchor landed)**: clean
  schema-v2 run
  `benchmarks/results/p7-gpu-native-inference-2026-07-12-faa7667.json` on
  `3mq19up4`, explicitly paired with
  `p7-integrated-hybrid-2026-07-12-706d067.json`. The corrected timer excludes
  cache-seeding prefill from decode and times exactly 50 append-only steps,
  including 20,103,000 bytes logits/error D2H and host argmax; weights remain
  resident and their 249,403,904-byte one-time upload is excluded. Seven
  prefill samples give **20.929 ms median, 0.389 ms MAD** (19.252--21.465 ms);
  seven decode50 samples give **770.045 ms median, 8.648 ms MAD**
  (726.182--785.886 ms). All outputs are deterministic, prefill argmax 835
  and all 50 tokens match the frozen golden sequence, with no fixed-point
  error. Same-host CPU/native GPU speedups are 53.542x prefill and 2.901x
  decode. Persistent device allocation is 258,181,700 bytes and peak process
  RSS is 732,692,480 bytes.

  Combining this denominator with the *hybrid* proof medians yields
  rho_proof,prefill **2008.584** and rho_proof,decode **28.537**; absolute
  inference+proof is 42.0595/22.7448 s. These numbers quantify why staged
  materialization is not the paper result; they do not decide the preregistered
  resident <=10/<=2 gates. The 2026-07-11 native JSON remains immutable with
  its older timer semantics and machine fingerprint; comparisons must name
  which anchor they use. Clean refreshed aggregate
  `benchmarks/results/p7-2026-07-12-a5d4fa5.json` pairs runs by cloud
  `instance_id`, reports hybrid target gaps 200.858x/14.268x, and recommends
  `proceed-to-device-resident-prover-integration`.

- **2026-07-12 (same-host native GPU anchor rerun — pre-registered harness
  correction)**: before quoting rho for `3mq19up4`, rerun the exact fixed-point
  native GPU anchor against the clean CPU-native samples embedded in
  `p7-integrated-hybrid-2026-07-12-706d067.json`. Audit found that the prior
  CUDA harness performed the documented untimed cache-seeding prefill and
  then called `decode50()`, which performed a second prefill *inside* the
  decode timer. Retain the 2026-07-11 JSON unchanged, but correct the harness
  so `decode50` consumes the argmax/cache produced by the untimed prefill and
  times exactly 50 append-only decode steps including logits D2H + host
  argmax. One warmup + 7 repetitions, frozen 50-token golden equality and
  determinism remain mandatory. Schema v2 must retain raw prefill/decode
  samples plus median/MAD/min/max, live/peak device allocation estimate and
  process peak RSS; the baseline path is explicit rather than selected by
  machine-global filename heuristics. This is measurement-only: no Rust
  witness, proof, transcript, PCS, correlation or communication change.

- **2026-07-12 (`P7-integrated-hybrid` full attribution gate complete)**:
  clean schema-v2 run
  `benchmarks/results/p7-integrated-hybrid-2026-07-12-706d067.json` on
  Thunder `3mq19up4` (A100-SXM4-80GB, Xeon Platinum 8352Y, 7.92-core quota,
  CUDA toolkit 13.0 / UMD 13.3), workload T=100+50 stacked decode and Q=200.
  One warmup plus three measured repetitions all verify and match the frozen
  50-token golden sequence. Proof-only prefill samples are
  31.3637/42.0386/43.4575 s (median **42.0386**, MAD 1.4190); response samples
  are 52.6792/64.0133/71.7773 s (median **64.0133**, MAD 7.7640); paired
  decode marginals are 21.3155/21.9747/28.3198 s (median **21.9747**, MAD
  0.6592). The same-host CPU ABBA medians are 1.1206 s prefill and 2.2337 s
  decode50, hence the JSON's CPU-relative rho is 37.514/9.838; this is not
  the resident paper rho. Against the previous same-SKU native GPU anchor
  only as a cross-instance diagnostic, proof/native would be about
  2380.0/34.67; a fresh same-host native anchor is required before quoting
  final ratios.

  The representative second accelerator session closes exactly:
  100.850131590 s = 6.868208756 H2D + 25.432895559 D2H + 0.109572774
  kernels + 68.439454501 CPU. Each repetition transfers 17,812,501,992 H2D
  and 5,560,199,968 D2H bytes and executes 8,763 explicitly counted
  host-barrier timing synchronizations; peak live device allocation is
  4,312,989,696 bytes and peak RSS is 8.637 GiB. This is the intended hybrid
  diagnosis: staged transfers and Rust/CPU residual dominate, not CUDA
  arithmetic. PCS commitment/open/verify medians are 24.236/9.365/0.365 s;
  response verification is 0.979 s. Flat-cost last/first is 1.363 <= 1.5,
  packed response download is 144,820,930 bytes, and correlation counts stay
  8,479,926 sub + 176,880 full. The hybrid gate changes no proof/transcript/
  verifier/communication semantics and is not the P7 go/no-go; next is the
  device-resident witness/proving gate (the same-host native denominator has
  now landed separately above).

- **2026-07-12 (`P7-integrated-hybrid-quick` repeated attribution gate
  complete)**: clean schema-v2 run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-f45b220.json`
  retains every raw repetition and reports upper median/MAD/min/max. Three
  measured response-proof samples are 9.3162/8.2017/8.8064 s (median
  **8.8064 s**, MAD 0.5098); prefill-proof samples are
  6.4059/5.8868/5.9967 s (median **5.9967 s**, MAD 0.1099), giving paired
  decode marginals 2.9103/2.3149/2.8097 s (median **2.8097 s**, MAD 0.1006).
  PCS commitment/open/verify medians are 24.995/8.905/0.401 s. Every proof,
  PCS opening and flat-cost session is accepted; correlation counts,
  transcript ledgers and communication are identical across seeds 64--66;
  flat last/first is 0.965 and the packed quick response is 82,281,642 bytes.
  Each accelerator session closes exactly. The representative third sample
  is 44.353781742 s = 6.600317999 H2D + 13.758055079 D2H + 0.103830098
  kernels + 23.891578566 CPU, with 7,791 counted host barriers and
  4,311,678,976 peak live device bytes. This closes the hybrid quick gate and
  unblocks the full T=100+50/Q=200 hybrid measurement; it is still not the
  resident paper result and its quick-shape rho must not be quoted.

- **2026-07-12 (`P7-integrated-hybrid-quick` whole-session attribution
  landed)**: clean run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-d0de22c.json`
  closes the accelerator measurement exactly: 98.721858941 s wall =
  25.086696863 s H2D + 46.569393394 s D2H + 1.293115331 s kernels +
  25.772653353 s CPU residual. The latter is explicitly split into 2.130 s
  local to staged operations and 23.643 s Rust work outside backend calls;
  the JSON declares its scope as `response-session-including-pcs-and-verifier`
  to prevent double counting with the separate verifier lines. The run is
  accepted, Q=200 communication is unchanged, flat last/first is 1.039, and
  peak live device allocation is 4,311,678,976 bytes. This satisfies the
  hybrid quick correctness/attribution purpose, not the paper e2e gate.
  Same-host D2H phase time changed from 21.985 s in the immediately preceding
  clean quick to 46.569 s here (H2D 6.655 -> 25.087 s), while bytes and calls
  were identical. Therefore a single full sample would be non-publishable:
  add per-repetition raw times plus median/dispersion before running the full
  T=100+50 hybrid workload. Quick-shape rho remains explicitly non-record.

- **2026-07-12 (`P7-integrated-hybrid-quick` ABI-v2 phase timing landed;
  whole-session residual open)**: clean rerun
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-8f0eb17.json`
  is accepted with flat-cost 0.765 and the same Q=200 proof/communication
  accounting. A minimal same-host probe showed that Thunder's CUDA runtime
  returns `cudaSuccess` from `cudaEventElapsedTime` without writing its
  output. ABI v2 now detects that condition instead of emitting zero and
  declares `timing_method: host-barrier-wall`: each H2D, kernel and D2H phase
  is closed with an explicitly counted stream barrier. The witness reports
  69.4 ms H2D + 18.7 ms kernels + 404.8 ms D2H + 145.2 ms operation-local
  CPU across 336 GEMMs and 1,008 barriers. The staged proving/PCS session
  reports 6.655 s H2D + 0.331 s kernels + 21.985 s D2H + 2.177 s
  operation-local CPU, 7,791 barriers, 17.763/5.538 GB H2D/D2H and 4.312 GB
  peak live device bytes. The extra barriers are part of this hybrid
  attribution run and make it incomparable to a CUDA-event machine unless
  the timing method is shown. **Remaining accounting blocker**: those phase
  totals cover 31.147 s, while sequential proof + PCS commit/open/verify +
  response verify lines total about 54.171 s; Rust protocol/PCS work outside
  backend calls is not yet represented in `cpu_residual_s`. Add the complete
  begin/finish measurement wall and an unattributed-host closure, rerun quick,
  then permit the full hybrid workload. Quick rho remains non-paper evidence.

- **2026-07-12 (`P7-integrated-hybrid-quick` correctness landed;
  attribution timing blocked)**: clean-tree run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-54822a7.json`
  on Thunder `3mq19up4` (A100-SXM4-80GB, Xeon Platinum 8352Y, 7.92-core
  quota, CUDA toolkit 13.0 / UMD 13.3) is accepted at T=16+8 and Q=200;
  the two-chunk flat-cost curve is 1.030 <= 1.5, all 13 PCS openings verify,
  and the full `VOLTA_REQUIRE_CUDA=1` workspace suite passed beforehand,
  including bit-exact non-power-of-two/padding/aux/mask-row differentials,
  same-seed full-proof accounting, persistent-context reuse, CUDA-derived
  fault rejection, golden decode and KV anti-replay. Online proof timing is
  10.430 s prefill and 13.746 s response; PCS is reported separately at
  40.395 s commitment, 18.510 s opening and 0.395 s verification. The
  proving measurement counts 17,763,091,112 H2D bytes, 5,538,170,272 D2H
  bytes, 2,597 synchronizations (33.2 ms), 8.402 s CPU residual and
  4,311,678,976 peak live device bytes. **Instrumentation blocker**: all
  CUDA kernel, H2D and D2H time fields are zero because the integrated ABI
  currently reports counts/bytes but does not time those operations. The
  immutable JSON is therefore a correctness/accounting artifact only; do
  not quote its quick-shape rho or relabel it as e2e attribution. No full
  hybrid run is allowed until event/wall timing lands and a second clean
  quick run demonstrates nonzero, internally consistent attribution.

- **2026-07-11 (`P7-integrated-resident` — pre-registered)**: after the
  hybrid attribution gate, add a CUDA-resident path in which fixed-point
  forward, witness construction and proving share persistent device buffers;
  the complete `ModelWitness` must not be materialized on the host. Rust keeps
  transcript/challenge orchestration and transfers only protocol messages.
  Run the paper workload (GPT-2 small, prompt 100 + 50 stacked decode, Q=200)
  with one warmup and repeated timed samples on the A100 machine of record.
  Report native GPU inference, proof-only prefill, proof-only decode marginal,
  inference+proving, PCS commitment/opening, PCG setup/expansion and verifier
  separately. Hard gates: golden prefill/decode bit-exact; same-seed proof
  bytes, transcript/accounting counters and verifier result equal to CPU;
  fault-injected device output is rejected; decode last/first <=1.5; packed
  response <=150--200 MB; rho_proof,prefill <=10 and rho_proof,decode <=2.
  Every JSON records per-repetition times and dispersion, CPU residual,
  H2D/D2H, synchronization, peak RSS/device memory, full byte breakdown,
  hardware/software fingerprint, commit and dirty state. This gate, not the
  standalone spikes or the hybrid gate, determines the P7 GPU go/no-go.

- **2026-07-11 (`P7-integrated-hybrid` — pre-registered)**: introduce an
  internal optional CUDA backend while leaving CPU as the default. CUDA is
  feature-gated, owns persistent context/stream/buffers/workspace, accepts
  runtime shapes, and returns an explicit unavailable error when requested;
  there is no silent CPU fallback. Preserve the existing CPU APIs as wrappers
  around backend-explicit entry points. Integrate, in order, fused GEMM /
  requant / MAC corrections; LogUp tree, aux leaves, rounds/folds and blind
  corrections; PCS mask rows, row combinations, NTT, gather and Merkle. The
  first gate may upload an existing host `ModelWitness`, but timing must include
  all upload/download, synchronization and CPU-residual work. Hard correctness
  gate: on identical inputs/seeds, CPU and CUDA produce identical outputs,
  correlation counts/allocation digest, transcript accounting, proof bytes and
  verifier outcome, including padding, non-power-of-two domains, aux leaves and
  mask rows. Repeated-context and injected-fault tests must detect correlation
  reuse/state leakage and verifier rejection. This is an attribution and
  integration gate only; it is not an e2e rho result for the paper.

- **2026-07-11 (P7 prefill objective revised)**: the general GPU objective is
  now **ρ_prefill ≤ 10**, while **ρ_decode ≤ 2** is unchanged. On the
  `6mprfo7p` baseline this gives a **176.631 ms proof-only prefill budget**,
  required relative prover/native speedups **2.05125× prefill / 4.14684×
  decode**, and required integrated prover GPU/CPU speedups **115.616× /
  11.3141×**. `scripts/report.py` is the source of current targets. Existing
  JSONs and preregistered microkernel gates (including 5.48× screens) remain
  historical screening evidence; they are neither lowered nor reinterpreted
  as relative prover/native or e2e speedups.

- **2026-07-11 (P7 native fixed-point GPU inference anchor landed)**: clean
  exact run `benchmarks/results/p7-gpu-native-inference-2026-07-11-c06f323.json`
  on Thunder `6mprfo7p`. With the 238 MB quantized weights and all LUTs
  resident, the standalone sm_80 path executes the full 12-layer frozen
  semantics: embedding/LN/QKV/causal softmax/AV/projections/FFN/seams/final
  LN/logits for prefill and true append-only K/V decode. Prefill argmax and
  all 50 generated tokens match the accepted P6 golden sequence in every
  repetition; no fixed-point saturation/domain error occurred. Median of 7:
  prefill **17.663 ms**, 56.364x versus same-box CPU 0.99556 s; decode50
  **633.895 ms**, 2.728x versus CPU 1.72949 s. Decode timing includes a
  402,056-byte logits D2H and host argmax per token; one-time weights upload
  is excluded as preregistered. Combining those native accelerations with
  the same-box relative requirements 4.1025x/4.1468x means the integrated
  GPU prover must achieve **231.23x prefill / 11.31x decode speedup versus
  its CPU proving times**. Existing microkernel speedups cannot be divided
  into these numbers to claim rho; an integrated proving measurement is now
  the decision-critical next step. No Rust witness, protocol, proof, PCS,
  transcript, correlation or communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-18c3fea.json`
  (`git_dirty:false`, recommendation
  `proceed-to-integrated-gpu-prover-measurement`).

- **2026-07-11 (P7 native fixed-point GPU inference anchor —
  pre-registered)**: implement a standalone sm_80 CUDA anchor over the exact
  frozen `gpt2s-q.bin` semantics, not a GEMM-only or FP16 proxy. Prefill must
  execute embedding, both layer norms, biased QKV, causal score/row-max/exp/
  reciprocal/softmax, AV, attention projection + residual, FFN up + GELU,
  FFN down + residual, seams, final LN and tied-WTE logits for T=100 across
  all 12 layers. Decode must seed all 12 K/V caches from that prefill and run
  50 true incremental steps at positions 100..149, including logits D2H and
  host argmax before the next token. Arithmetic is exact i16*i16->i64 with
  the frozen chained round-half-up requant and LUT tables; weights/LUTs stay
  device-resident and their one-time upload is outside timing. Time one
  warmup + 7 GPU prefill and decode repetitions, median wall time with a
  completion/logits D2H barrier; reset cache via an untimed prefill before
  each decode repetition. Hard gates: prefill argmax and all 50 generated
  tokens match `golden-p6.bin`, repeated runs are deterministic, timing is
  sane, and no saturation/assertion is hidden. Report absolute prefill/decode
  time and acceleration versus the clean same-box P6 native baselines
  0.995562859/1.729492698 s. This anchor changes neither the Rust witness nor
  the proving path and makes no GPU-rho claim by itself; final rho still
  requires integrated proving timings. No protocol, proof, PCS, transcript,
  correlation or communication change.

- **2026-07-11 (P7 replacement-instance P6 baseline landed)**: clean full
  run `benchmarks/results/p6-2026-07-11-f72e4dd.json` on Thunder
  `6mprfo7p` (A100-SXM4-80GB, Xeon Platinum 8470, 7.92-core quota) is
  accepted, golden decode exact, and preserves the 144,820,930-byte packed
  response. ABBA native prefill is 0.9956 s and native 50-token decode is
  1.7295 s (28.91 tok/s). Proving prefill is 20.4215 s; full response
  34.7653 s with decode marginal 14.3439 s, hence CPU rho prefill **20.512**
  and decode **8.294**. The replacement-instance relative prover/native
  acceleration requirements are therefore **4.1025x prefill** for rho<=5
  and **4.1468x decode** for rho<=2. Verify 0.710 s; PCS commit/open/verify
  5.920/1.164/0.204 s; flat-cost last/first 1.249 <=1.5 and anti-replay
  gates remain accepted; peak RSS 3.53 GiB. These requirements supersede
  5.48x/3.97x only on `6mprfo7p`; older-instance measurements remain
  historical and must retain their own denominators. This is still a CPU
  fixed-point baseline, not the native GPU inference anchor.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-0ea449a.json`
  (`git_dirty:false`, recommendation
  `proceed-to-proving-path-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU blind LogUp general-layer plumbing landed)**: clean
  pinned-barrier run of record
  `benchmarks/results/p7-gpu-logup-blind-rounds-2026-07-11-534dcad.json`
  on replacement Thunder instance `6mprfo7p` (A100-SXM4-80GB, Xeon Platinum
  8470, CUDA toolkit 13.2 / UMD 13.3). At N=2^22, every accumulator, folded
  element and all **848 bytes** of root/22-round/split/product corrections
  match the 7-thread CPU reference, with the existing 22 round barriers and
  zero extra transcript rounds. Median CPU blind 265.26 ms vs GPU blind
  **41.30 ms = 6.423x**, passing >=5.48; paired clear 45.71 ms gives
  blind/clear 0.903, treated only as overhead <=1.05 (not as a claimed
  acceleration). Reusable pinned 64-byte destinations were load-bearing on
  Thunder; the pre-fix failures remain recorded below. The quick N=2^16 run
  was correct but launch dominated at 1.55x and is retained. Scope excludes
  aux-leaf/column corrections and Rust proving-path integration. Because the
  CPU model changed, this spike passed the fixed preregistered screen before
  the replacement P6 denominator landed; the subsequent baseline above gives
  4.10x/4.15x requirements, which it also passes. No protocol or
  communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-e4e0772.json`
  (`git_dirty:false`, recommendation
  `proceed-to-proving-path-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU blind LogUp plumbing — first full runs failed;
  pinned-barrier follow-up authorized)**: all blind root/round/split/product
  corrections (848 bytes), every round accumulator and every folded element
  were exact, with zero extra transcript rounds, but the preregistered
  performance gates did not pass. On Thunder `nc1k4a0g`, the first driver
  used four separate 16-byte final split copies and reported CPU 383.75 ms,
  GPU blind 133.76 ms = 2.87x and blind/clear 1.077; the unchanged clear
  control on the same commit later ran at 44.56 ms = 8.92x, identifying the
  micro-copy path as invalid for a single 64-byte split message. After packing
  that message, a clean run on replacement instance `6mprfo7p` (same A100,
  Xeon Platinum 8470, CUDA toolkit 13.2 / UMD 13.3) reported CPU blind
  258.70 ms, GPU blind 54.60 ms = **4.738x**, blind/clear **1.098**: both
  >=5.48x and <=1.05x gates still fail. The unchanged clear control there was
  CPU 259.83 ms, GPU 58.29 ms = 4.457x. Thus the new CPU is materially faster
  while GPU absolute latency is comparable; the old instance's 5.48x
  sensitivity is not a portable rho denominator, but the fixed preregistered
  gate is still recorded as failed. Preserve all diagnostic JSONs. One
  implementation follow-up is authorized before stopping this lever: replace
  pageable stack destinations for the 22 round messages plus one split
  message with reusable CUDA pinned-host buffers, then rerun the same quick/
  full protocol and unchanged gates. This changes no arithmetic, mask,
  correction, message, challenge, proof byte or transcript round. A final rho
  claim on `6mprfo7p` still requires a fresh native P6 baseline on that box.

- **2026-07-11 (P7 GPU blind LogUp correction plumbing — pre-registered)**:
  extend the already-passed `N=2^22` general-round spike without changing its
  arithmetic or challenge order. Keep the 64-byte device-to-host barrier at
  every one of the 22 rounds. Immediately after each round message reaches
  the host, subtract two pre-expanded one-time F_p^2 masks, account the
  resulting 32 correction bytes, and only then consume the next independent
  verifier challenge. Also generate the layer's two root, four split and
  three product corrections around the same sequence, for **848 bytes total**
  (`32 + 22*32 + 64 + 48`), exactly the current Rust transcript layout.
  Compare every root/round/split/product correction and every folded element
  against an independent 7-thread CPU implementation outside timing. Use one
  warmup + 7 GPU and 3 CPU repetitions. Hard gates: correctness, timing
  sanity, blind whole-sequence GPU/CPU speedup >=5.48x, and paired blind/clear
  GPU overhead <=1.05x. Resident masks are charged to the separate PCG budget;
  no correction-only GPU kernel or extra transcript round is allowed. Scope
  is one general fraction-tree layer: aux-leaf/column corrections and the
  Rust proving-path FFI remain follow-ups. No proof bytes, challenge order,
  domains, PCS, Q/rate, communication formula or protocol change.

- **2026-07-11 (P7 GPU PCS column gather + BLAKE3/Merkle landed)**:
  clean run of record
  `benchmarks/results/p7-gpu-blake3-merkle-2026-07-11-3b0a916.json` on
  Thunder `nc1k4a0g`, exact `P4_LAYER` geometry (1024 rows x 32768 encoded
  columns, 8192-byte leaves, 256 MiB resident row-major matrix). The fused
  gather + unkeyed BLAKE3 leaf pass and full 2^15-leaf Merkle tree match the
  optimized Rust `blake3` root; the independent host implementation also
  matches every leaf and internal node. Median Rust/Rayon reference 43.779 ms
  vs GPU **1.407 ms = 31.10x**, passing the <=75 ms absolute gate. Together
  with the measured 6.386 ms NTT, the measured GPU NTT + hash path is
  **7.793 ms** (71.44x versus the corresponding 556.71 ms CPU components).
  The quick 32x1024 case was also correct and passed at 0.541 ms, retained as
  `p7-gpu-blake3-merkle-quick-2026-07-11-3b0a916.json`. Scope still excludes
  mask-row hashing, selected-column serialization and proving-path
  integration; no hash, root, PCS layout, proof bytes, Q/rate, transcript or
  protocol change. Next: blind correction plumbing, native GPU inference
  anchor and integrated e2e gates.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-b971a93.json`
  (`git_dirty:false`, recommendation
  `proceed-to-blind-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU PCS column gather + blake3/Merkle — pre-registered)**:
  at `P4_LAYER` geometry, hash all 32768 encoded columns of 1024 Goldilocks
  values directly from the resident row-major matrix (gather fused into the
  BLAKE3 leaf kernel), then build the full 2^15-leaf Merkle tree on GPU. Use
  exact unkeyed BLAKE3 flags/tree semantics and cross-check the final root
  against the optimized Rust `blake3` crate; additionally compare every leaf
  and internal hash against an independent host implementation outside the
  timed region. Time 1 warmup + 7 GPU runs with a forced 32-byte root D2H;
  time the actual Rayon/Rust gather+blake3+Merkle reference for 3 runs.
  Because scalar host code is not a fair denominator, the hard performance
  gate is absolute: GPU gather+hash+tree <=75 ms. Together with the measured
  6.39 ms NTT this keeps the P4 layer commitment below 81.4 ms, i.e. >=5.5x
  versus the ~0.45 s cloud CPU commitment. Correctness and timing sanity are
  hard gates. This does not change the hash, commitment root, PCS layout,
  proof bytes, Q/rate, transcript or protocol; mask-row hashing and selected
  column serialization remain integration work.

- **2026-07-11 (P7 GPU PCS row/global arithmetic landed)**: clean run of
  record `benchmarks/results/p7-gpu-pcs-arithmetic-2026-07-11-366ec4a.json`
  on Thunder `nc1k4a0g`, exact `P4_LAYER` geometry. Batched 1024x32768
  Goldilocks NTT (bit reversal + 15 stages, 251.7 M butterflies) matches every
  symbol: CPU 0.51293 s vs GPU 0.006386 s = **80.33x**. `combine_rows` data
  block over 1024x16384 weights matches u_q/u_c exactly: CPU 0.14593 s vs
  GPU 0.001918 s = **76.10x**. Both independently pass >=5.48. Quick small
  geometry was correct but launch dominated and failed, retained as
  `p7-gpu-pcs-arithmetic-quick-2026-07-11-366ec4a.json`. Scope excludes pad
  tail, mask rows, column gather, blake3/Merkle and proving integration; no
  parameter, proof-size or protocol change. Next authorized spike is
  blake3/Merkle plus representative column gathering.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-1b99864.json`
  (`git_dirty:false`, recommendation `proceed-to-blake3-merkle-spike`).

- **2026-07-11 (P7 GPU PCS row/global arithmetic — pre-registered)**:
  implement two exact sm_80 spikes at `P4_LAYER` geometry. (A) Batched
  Goldilocks forward NTT for 1024 rows x 2^15 code symbols, including
  bit-reversal and all 15 butterfly stages with the same root/twiddles as
  `NttPlan`; immutable resident messages are zero-padded at msg_len=16896.
  (B) `combine_rows` data block for 1024x16384 base-field weights, producing
  both u_q and u_c via F_p² x F_p operations. Use 1 warmup + 7 GPU and 3
  7-thread CPU repetitions, forced small D2H completion barriers, and compare
  every output limb bit-for-bit. Hard gates for **each** pass: correctness,
  timing sanity, GPU/CPU speedup >=5.48x. Report bytes, operation counts and
  checksums. This excludes pad-tail addition, fresh mask-row encoding, column
  gather and blake3/Merkle; those remain explicit PCS follow-ups. No PCS
  shape, rate, Q, opening bytes, transcript or protocol change.

- **2026-07-11 (P7 GPU LogUp general rounds/folds landed)**: clean run of
  record `benchmarks/results/p7-gpu-logup-rounds-2026-07-11-e4470bf.json`
  on Thunder `nc1k4a0g`, N=2^22, 22 transcript-ordered rounds, reports every
  round accumulator and every folded element bit-exact. Median CPU 0.38660 s
  vs GPU 0.05714 s = **6.766x >=5.48 PASS**, but only 1.23x headroom over the
  stricter prefill requirement; treat this as a live risk, not a wide pass.
  Quick N=2^16 was correct but round/launch dominated at 1.409x and is kept
  as `p7-gpu-logup-rounds-quick-2026-07-11-e4470bf.json`. The result includes
  a 64-byte D2H message barrier before every challenge/fold and therefore
  does not elide interaction. Blind correction generation and proving-path
  integration remain open; no transcript or proof-byte change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-fd67e64.json`
  (`git_dirty:false`, recommendation `proceed-to-pcs-hash-spikes`).

- **2026-07-11 (P7 GPU LogUp general round/fold — pre-registered)**:
  implement the exact P4 `run_general_rounds` hot loop over four F_p²
  vectors at representative N=2^22: per pair compute the four Gruen round
  accumulators (10 F_p² multiplications), reduce them, force a 64-byte D2H
  round-message barrier, then fold p0/p1/q0/q1 by the deterministic challenge
  (4 F_p² multiplications/pair) and continue to length one. The per-round
  barrier is load-bearing and models the actual transcript challenge order;
  it may not be fused away across rounds. Use 1 warmup + 7 GPU repetitions
  and 3 same-host CPU repetitions. Outside timing, compare every round
  accumulator and every folded element at every depth bit-for-bit. Hard
  gates: correctness, timing sanity, whole-sequence GPU/CPU speedup >=5.48x.
  This clear arithmetic spike excludes blind correction generation and does
  not integrate the Rust proving path; those remain explicit follow-up work.
  No transcript, challenge order, proof bytes, lookup count or protocol change.

- **2026-07-11 (P7 GPU LogUp lookup-tree build landed)**: clean run of
  record `benchmarks/results/p7-gpu-logup-tree-2026-07-11-5f7b443.json`
  on Thunder `nc1k4a0g`, N=2^24, exact P4 structured first combine and all
  general F_p² levels. Every p/q element at every level matches the CPU
  reference; checksum `0x0350749ee82bd237`. Median CPU 0.18934 s vs GPU
  0.002864 s = **66.12x >=5.48 PASS**. The valid quick run at N=2^18
  (`p7-gpu-logup-tree-quick-2026-07-11-5f7b443.json`) was launch-dominated
  and intentionally failed performance at 2.19x while retaining exact
  correctness; this confirms batching at P6 scale is load-bearing. Scope is
  tree build only: sumcheck evaluation/folds, blind correction plumbing and
  proving-path integration remain open. No protocol or communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-959b40b.json`
  (`git_dirty:false`, recommendation `proceed-to-logup-rounds-and-pcs-spikes`).

- **2026-07-11 (P7 GPU LogUp fraction-tree build — pre-registered)**:
  implement the exact dominant lookup-side (`LeafP::Ones`) P4 tree build at
  N=2^24: structured base-field first combine from `LeafQ {a, alpha1}`, then
  every general `(p1*q2+p2*q1, q1*q2)` F_p² level through the root. Inputs
  and all intermediate layers remain GPU-resident during timing; one forced
  32-byte root D2H read is the completion barrier. Use 1 warmup + 7 GPU
  repetitions and 3 CPU repetitions on the same 7-thread quota. Outside the
  timed region, compare **every p/q element at every level** against the CPU
  Goldilocks reference and record root/checksum/counts. Hard gates:
  correctness, sane timing, GPU/CPU tree-build speedup >=5.48x (the stricter
  cloud prefill requirement). This covers tree construction only; LogUp
  sumcheck round-evaluation/fold kernels, blind corrections and proving-path
  integration remain separate open work and must not be implied by a pass.
  No transcript, lookup, soundness, correlation or communication change.

- **2026-07-11 (P7 GPU fused GEMM-MAC epilogue landed)**: clean run of
  record `benchmarks/results/p7-gpu-fused-epilogue-2026-07-11-bde5d7d.json`
  on Thunder `nc1k4a0g`, sm_80, resident pre-expanded PCG masks. Full
  i16xi16->i64 GEMM, frozen requant and same-kernel `delta=x-r` corrections
  match the CPU reference for every output. ABBA medians: shape
  100x768x768 native/fused 0.392/0.396 ms (`rho=1.009`), x2304
  0.517/0.515 ms (`rho=0.996`), x3072 0.579/0.569 ms (`rho=0.983`);
  weighted **`rho_kernel=1.003` <=1.30 PASS**. Corrections remain exactly
  8 bytes/output and there is no correction-only kernel. Valid quick:
  `p7-gpu-fused-epilogue-quick-2026-07-11-bde5d7d.json`. This remains a
  P1-equivalent standalone spike: the Rust proving path is unchanged, PCG
  expansion/setup stays separately budgeted, and e2e GPU rho is still open.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-27cc9a8.json`
  (`git_dirty:false`, recommendation `proceed-to-logup-pcs-kernel-spikes`).
  Next authorized spike is a representative LogUp fraction tree.

- **2026-07-11 (P7 GPU fused GEMM-MAC epilogue — pre-registered)**:
  implement a measurement-only sm_80 CUDA kernel for the three P1 GPT-2
  shapes (100x768x{768,2304,3072}), with exact i16xi16->i64 accumulation and
  frozen round-half-up/clamp requantization. Compare one native kernel
  (requantized i16 output) against the identical GEMM with a **same-kernel**
  fused epilogue that reads a resident F_p mask and writes the 8-byte
  correction `delta=x-r`; no correction-only follow-up pass is allowed.
  Resident masks model the already separate PCG pool/setup budget and do not
  hide any response bytes. Use 2 paired warmups + 9 ABBA rounds, a forced
  16-byte D2H completion read per launch (Thunder trap above), and report
  medians plus weighted `rho_kernel`. Validate every native/fused i16 output
  and every reconstructed field value bit-for-bit against a same-host CPU
  reference. Hard gates: correctness; fused/native weighted rho <=1.30; no
  output/correction layout or count change. This spike does not yet replace
  Rust inference/proving code and cannot by itself establish e2e GPU rho.

- **2026-07-11 (P7 A100 Goldilocks/F_p² roofline landed)**: run of record
  `benchmarks/results/p7-gpu-roofline-2026-07-11-a43d105.json` on replacement
  Thunder instance `nc1k4a0g` (same A100-SXM4-80GB / CPU quota as the
  pre-registered box), clean tree, sm_80, reports full bit-for-bit CPU/GPU
  agreement and timing sanity. Stream 2^24: CPU 0.10688 s, GPU 0.001926 s,
  **55.48x**, 418.0 GB/s and 8.71 G F_p²-mul/s. Dependent chain
  2^20 x 256: CPU 1.9617 s, GPU 0.006518 s, **300.94x** and 41.18 G
  F_p²-mul/s. The raw arithmetic screening gate passes by wide margin over
  5.48x/3.97x, but this is not an e2e go decision. Thunder trap: CUDA events
  and `cudaDeviceSynchronize` returned before provider-observable completion,
  producing an invalid early quick diagnostic
  `p7-gpu-roofline-quick-2026-07-11-5ead965.json` (0 s / impossible
  5.2 TB/s). Timings of record therefore force a 16-byte D2H read after every
  kernel and reject stream bandwidth above 2.5 TB/s; valid quick
  `p7-gpu-roofline-quick-2026-07-11-a43d105.json` passed before the full run.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-14bafb8.json`
  (`git_dirty:false`, recommendation `proceed-to-fused-kernel-spikes`).
  Next authorized spike is the fused GEMM-MAC epilogue; no proving-path or
  protocol change has landed yet.

- **2026-07-11 (P7 GPU Goldilocks/F_p² roofline — pre-registered)**:
  add a standalone CUDA 13 / sm_80 microbenchmark plus a Python JSON
  harness; this is measurement-only and does not enter the proving path.
  Two resident-data kernels mirror `volta-field` exactly: (1) an F_p²
  stream multiply over 2^24 elements (5 base-field multiplications per
  output) to expose the memory/integer-pipeline roofline; (2) a dependent
  chain over 2^20 elements with 256 F_p² multiply-add rounds to expose
  compute throughput. Use 1 warmup + 7 GPU repetitions and 3 same-host CPU
  repetitions, median timing; compile explicitly for `sm_80`; validate every
  output limb bit-for-bit against the CPU Goldilocks reference and report a
  deterministic checksum. JSON must carry the cloud fingerprint, clean-tree
  status, CUDA/device properties, absolute throughput/bandwidth and same-code
  GPU/CPU speedups. Correctness is a hard gate. Performance is a screening
  gate: raw stream and chain speedups must show plausible headroom against
  the measured 5.48x prefill / 3.97x decode requirements before building the
  fused proving kernels; passing it is not itself an end-to-end go decision.
  No protocol, transcript, Q, PCS, correlation, or communication change.

- **2026-07-11 (P7 cloud A100 P6 CPU baseline + sensitivity landed)**:
  clean ABBA run `benchmarks/results/p6-2026-07-11-11e5630.json`
  (`git_dirty:false`, accepted, golden decode true, 7 rayon threads) reports
  native prefill 1.164 s and native decode 2.544 s / 50 tokens; proving
  prefill 31.878 s and response 52.060 s, hence `rho_prefill=27.38` and
  `rho_decode=7.93`; verify 1.056 s; flat-cost last/first 0.970 <=1.5;
  PCS open 1.762 s and verify 0.325 s; peak RSS 3.56 GiB. Communication is
  invariant at 144,820,930 packed response bytes. Post-run inspection found
  no competing process or OOM and only 11.3 s cumulative cgroup throttling
  across 3,221 s CPU usage, so the slower CPU result is retained rather than
  discarded as load contamination. Aggregate
  `benchmarks/results/p7-2026-07-11-11e5630.json` updates the required
  relative prover-vs-native GPU speedup to **5.48x prefill / 3.97x decode**
  for this instance. These values supersede the 3.67x/2.60x local-VM
  sensitivity when judging this A100 box; the old values remain historical,
  not portable gates.

- **2026-07-11 (P7 cloud A100 P1 CPU baseline landed)**: clean run
  `benchmarks/results/p1-2026-07-11-64a8ead.json` on the pre-registered
  Thunder A100 instance (`git_dirty:false`, linux x86_64, 7 worker threads
  visible under the 7.92-core quota). ABBA P1 result: weighted fused-MAC
  `rho_kernel=1.043`; native throughput 29.9--34.9 GMAC/s across the GPT-2
  shapes; epilogue 1.6--2.0 ns/output; verifier fused scan 66.4 ms per 2^20
  values (63.3 ns/value, 0.715 s prefill-100 extrapolation). This is the
  required cloud-host CPU anchor; the A100 was idle and no GPU acceleration
  is claimed by this run.

- **2026-07-11 (P7 cloud A100 baseline — pre-registered before measured
  runs)**: target instance is Thunder Compute `bdthpmts`, provider region
  not exposed by the instance-list API, base template / Ubuntu 22.04.5,
  NVIDIA A100-SXM4-80GB (Thunder `A100XL`), driver 610.43.02, CUDA UMD
  13.3, Intel Xeon Platinum 8352Y with 792000/100000 cgroup CPU quota
  (`nproc=8`), 64 GiB RAM and 100 GB primary disk. Before any quoted rho:
  full workspace tests must pass; P1 and P6 must run from a clean tracked
  tree; P6 native prefill/decode denominators use ABBA paired timing; every
  cloud JSON carries this fingerprint. GPU spike order remains Goldilocks/
  F_p2 roofline, fused GEMM-MAC epilogue, LogUp fraction trees, then PCS
  row/global passes plus blake3. Go/no-go gates remain relative
  prover-vs-native GPU speedup >=3.67x prefill and >=2.60x decode, with
  golden decode, flat-cost <=1.5 and anti-replay unchanged. This entry does
  not change protocol, soundness parameters, Q=200, or communication.

- **2026-07-07 (P7 real-PCG phase B — measurement CORRECTED; supersedes the
  1.602 s entry below)**: review found two defects in the landed phase B.
  (1) **Accounting error**: the phase-B path derived the noise leaves
  directly from the setup digest, silently dropping the GGM PPRF leaf
  expansion — the dominant cost phase A measured — so phase B totalled
  1.602 s, i.e. *faster than phase A despite adding setup*, which is
  impossible for the real protocol. Fixed (commit `a7a2a85`): phase B
  reuses the phase-A GGM expansion with a setup-bound root and reports
  `t_ggm_pprf_s`. (2) **Label overstatement**: `base_vole:"real"` renamed
  to `"setup-cost-model"` — the group operations and bytes are real, but
  both parties run in one process from a shared seed and the base VOLE is
  still dealer-derived; a two-party execution remains future hardening.
  Corrected clean measurement
  `benchmarks/results/p7-real-pcg-2026-07-07-a7a2a85.json`
  (`git_dirty:false`): **total 4.408 s** = base OT 0.021 + OT ext 0.008 +
  base-VOLE 0.016 + **GGM PPRF 1.934** + LPN 2.186 + checks 0.240;
  `setup_comm_bytes` unchanged at 1,081,408 B; consistency `ok:true`;
  `production_ready:false`. The 2026-07-07 numbers of record for the PCG
  line are therefore: expansion ≈ 3.2–4.4 s CPU single-thread
  (load-sensitive VM, trap #6.7), setup compute ≈ 0.05 s, setup comm
  ≈ 1.08 MB/session. Aggregate `benchmarks/results/p7-2026-07-07-a7a2a85.json`.

- **2026-07-07 (P7 real-PCG phase B, pre-registered)**:
  implement `p7_pcg_report --backend phase-b` as an opt-in setup
  measurement: real public-key base OT dependency (`curve25519-dalek`),
  measured OT-extension/GGM-delivery bytes, transcript-bound consistency
  challenge after setup binding, and JSON `base_vole:"real"` with
  `setup_comm_bytes`. This is not a default/backend flip. Production status
  remains false until the WYKW malicious checks and the LPN code/parameters
  are tied to cited WYKW/Ferret tables; docs stay limited to this ledger
  entry plus measured JSON.

- **2026-07-07 (P7 real-PCG phase B clean measurement)**:
  clean run `benchmarks/results/p7-real-pcg-2026-07-07-ec6e4f7.json`
  (`git_dirty:false`) reports `base_vole:"real"`, `setup_comm_bytes:
  1,081,408` B = 16,384 base OT + 1,064,960 GGM OT-extension + 64
  consistency, total **1.602 s** = base OT 0.021 s + OT extension 0.008 s
  + base-VOLE derivation 0.016 s + LPN 1.323 s + checks 0.231 s, peak RSS
  0.361 GB, consistency `ok:true`, `production_ready:false`. Aggregate:
  `benchmarks/results/p7-2026-07-07-ec6e4f7.json`. Remaining blockers are
  exactly the phase-B hardening items above: paper-level malicious checks
  and table-derived LPN/code parameters.

- **2026-07-07 (P7 real-PCG phase A, pre-registered)**:
  implement the §4.4 phase-A backend in-repo before cloud GPU spend. Scope:
  add `volta-pcg` with a WYKW/Wolverine-style Goldilocks subfield VOLE
  expansion model: trusted-dealer base sVOLE stub from the shared seed,
  GGM single-point noise generation, regular-noise local-linear LPN
  expansion, and transcript-invisible consistency-check arithmetic. Mock
  remains the default proving backend and regression baseline; phase A is
  selected explicitly by `p7_pcg_report --backend real`. Pre-registered
  phase-A profile: `p7-phase-a-goldilocks-regular-lpn-v1`, security target
  128 bits, one sub-equivalent output batch covering the P6 volume
  (`8,479,926` sub + `2*176,880` full limbs = `8,833,686` sub-equivalent
  VOLEs), base length `k+t+1`, `k=589,760`, regular noise weight
  `t=1,280`, local-linear fanout `10`, one GGM PPRF single point per
  regular-noise block, GGM depth `ceil(log2(ceil(n/t)))`, and two F_p²
  random-linear consistency checks. Full-field correlations are two
  subfield sVOLEs sharing the same Δ and combined F_p-linearly. JSON must
  be `benchmarks/results/p7-real-pcg-<date>-<sha>.json` with
  `is_real_pcg:true`, `base_vole:"mock-stub"`, setup vs expansion vs check
  timing split, corrs/s for both sides, peak RSS, `setup_comm_bytes`, and
  the LPN parameters. PCG/setup bytes are a separate counted category and
  are not response download. Formal position: Lean still consumes ideal
  VOLE; this PCG is an external LPN/PPRF realization assumption, same
  status as PCS binding in M9; no Lean work in phase A.

- **2026-07-07 (P7 real-PCG phase A landed, dirty local measurement)**:
  new `volta-pcg` crate implements the phase-A Goldilocks PCG expansion
  path and `p7_pcg_report --backend real` measured the P6 volume from
  `p6-2026-07-07-515bb1c.json`: `8,479,926` subfield + `176,880`
  full-field correlations (`8,833,686` sub-equivalent limbs). JSON
  `benchmarks/results/p7-real-pcg-2026-07-07-995bfb7.json`
  (`git_dirty:true`, implementation tree) reports `is_real_pcg:true`,
  `base_vole:"mock-stub"`, `setup_comm_bytes:0`, profile
  `p7-phase-a-goldilocks-regular-lpn-v1`, and consistency `ok:true`.
  Timing: **3.240 s** total = setup stub 0.016 s + GGM PPRF 1.977 s +
  LPN expand 1.017 s + full combine 0.002 s + consistency checks 0.228 s;
  joint throughput 2.73 M sub-equivalent correlations/s; peak RSS
  0.361 GB; expanded pools are 209.2 MB prover + 138.5 MB verifier.
  `scripts/report.py --write-json` refreshed
  `benchmarks/results/p7-2026-07-07-995bfb7.json`, whose
  `real_pcg_spike.status` is now `phase_a_measured_mock_stub`.
  Correctness gate: `p6_report --quick --pcg-backend real` accepted and
  wrote `benchmarks/results/p6-quick-realpcg-2026-07-07-995bfb7.json`
  (`accepted:true`, flat-cost 1.022, `pcg_mock_prepass_counters_match:true`,
  `pcg_allocation_hash_match:true`). Mock remains the default backend;
  phase B still needs real base OTs / OT extension and measured setup
  communication.

- **2026-07-07 (P7 real-PCG phase A clean checkpoint rerun)**:
  after checkpoint `fe4857b`, reran phase A on a clean tracked tree
  (untracked result files ignored by the report's `git_dirty` check).
  Clean JSON `benchmarks/results/p7-real-pcg-2026-07-07-fe4857b.json`
  reports `git_dirty:false`, same P6 volume and parameters as above,
  **3.709 s** total = setup stub 0.019 s + GGM PPRF 2.177 s + LPN expand
  1.279 s + full combine 0.002 s + consistency checks 0.231 s; peak RSS
  0.361 GB; consistency `ok:true`; setup communication remains 0 B because
  base VOLE is still `mock-stub`. Clean correctness gate
  `benchmarks/results/p6-quick-realpcg-2026-07-07-fe4857b.json` reports
  `git_dirty:false`, `accepted:true`, flat-cost 0.993,
  `pcg_mock_prepass_counters_match:true`, and
  `pcg_allocation_hash_match:true`. Refreshed clean aggregate report:
  `benchmarks/results/p7-2026-07-07-fe4857b.json`.

- **2026-07-07 (P7 decision — real-PCG becomes an in-repo implementation,
  supersedes the "cost spike only" scope)**: user decision. Instead of a
  proxy measurement on a foreign field (emp-zk Mersenne-61 / ocelot), a
  WYKW/Wolverine-style subfield VOLE over Goldilocks (m = k + r·Δ, Δ ∈
  F_p², full-field corrs as two sVOLEs sharing Δ) is implemented in a new
  `volta-pcg` crate as the eventual production backend — same rationale as
  the in-house Ligero decision (P3.5 #1). Two phases, each with its own
  pre-registration: **A** (GGM PPRF + LPN expansion, base sVOLE stubbed
  from the mock seed — real expansion cost of record, required before
  cloud GPU spend) and **B** (real base OTs + OT extension + malicious
  consistency checks; first public-key dep, allowed since the "no curves"
  invariant binds the PCS/proof path only). Hard constraints: mock backend
  stays default until measured phase-B parity; CorrIndex domain separation
  and one-time-use counting unchanged; PCG/setup bytes are a NEW counted
  category (`setup_comm_bytes`), never folded into response download; no
  proving-path/transcript change. LPN parameters (≥128-bit) are a security
  assumption to pre-register, same status as PCS binding in M9; no Lean
  work expected (optional future M10 interface lemma). Full work item:
  handoff spec §4.4.

- **2026-07-07 (P7 pre-cloud local complete)**:
  clean full P6 rerun with transcript-label accounting landed as
  `benchmarks/results/p6-2026-07-07-382bb56.json` (`git_dirty:false`,
  accepted, golden decode ✓, flat-cost gate 1.17). It preserves the P6
  communication totals (transcript 137.4 MB, PCS 66.733 MB, packed download
  144.8 MB) and adds `comm_*_by_label`. Decode marginal is
  **22,253,392 B = 445,067 B/token**, with top non-PCS labels:
  `auth_corrections` 20,902,016 B, `logup_round_corrections` 671,168 B,
  `logup_split_corrections` 202,624 B, `logup_prod_corrections` 151,968 B,
  `logup_aux_round_corrections` 141,936 B. This confirms the next
  transcript lever is the formal-touching correction packing / seam reuse
  family, not another PCS-only tweak. The refreshed filtered P7 aggregate
  report `benchmarks/results/p7-2026-07-07-d0812a7.json` carries
  `git_dirty:false`, keeps one measured PCS profile per shape/Q, and includes
  the full decode breakdown. Local P7 work before cloud is complete except
  for a real Ferret/silent-VOLE measurement, which is unavailable in this
  repo and remains an explicit cloud/external budget item.

- **2026-07-07 (P7 decode marginal breakdown, pre-registered)**:
  add transcript-label snapshots to `p6_report` so the 445 KB/token decode
  marginal can be decomposed before any optimization. Scope is accounting
  only: clone the existing `Transcript` byte ledger, snapshot PCS labels
  around the real opening, and report response / prefill / PCS /
  decode-non-PCS marginal by label. No transcript message, challenge order,
  proof content, or communication byte count changes.

- **2026-07-07 (P7 mock-PCG lower-bound spike, pre-registered)**:
  no real Ferret/silent-VOLE implementation or dependency is present in the
  repo. Add a local `p7_pcg_report` binary that reads a P6 JSON's counted
  `corr_sub_corrs` / `corr_full_corrs` and measures the current mock-PCG
  ChaCha expansion over the same element volume. This is explicitly a lower
  bound / plumbing measurement, **not** the real-PCG spike required for the
  final go/no-go; the ledger and JSON must say so. It does not affect any
  proof path or correlation semantics.

- **2026-07-07 (P7 mock-PCG lower-bound landed)**:
  `cargo run --release -p volta-bench --bin p7_pcg_report` measured the
  current mock ChaCha expansion for the clean P6 correlation volume
  (`8,479,926` subfield + `176,880` full-field correlations) and wrote
  `benchmarks/results/p7-mock-pcg-2026-07-07-d16a69c.json` (dirty tree).
  Expanded both prover and verifier sides in **0.351 s** total: prover sub
  0.172 s, verifier sub keys 0.170 s, prover full 0.0046 s, verifier full
  keys 0.0052 s; peak RSS 0.19 GB. This is a lower-bound/plumbing number
  only (`is_real_pcg:false` in JSON), because no Ferret/silent-VOLE
  implementation is present locally. The final P7 go/no-go still requires
  a real-PCG setup+expansion measurement or an explicit external budget.
  `scripts/report.py` now includes these mock lower-bound rows under
  `real_pcg_spike.mock_pcg_lower_bounds`; refreshed report
  `benchmarks/results/p7-2026-07-07-d16a69c.json`.

- **2026-07-07 (P7 Q=150 exploratory profile, pre-registered)**:
  add a non-default `p6_report --pcs-q <Q>` switch to measure the PCS query
  count lever without changing the run-of-record parameters. The default
  remains Q=200 and ~80-bit query error. The exploratory profile uses
  Q=150 at the existing rate/distance, giving ~60.0-bit query error under
  the same `(1-δ/2)^Q` model; `pad=512` still covers the one-response
  hiding headroom. This is **not** an adopted production soundness parameter
  and does not change `P4_LAYER`, `GPT2_FULL`, transcript structure, claim
  stacking, or verifier logic. Any adoption of Q=150 as default requires a
  separate ledger decision and final report update.

- **2026-07-07 (P7 Q=150 exploratory quick measurement landed)**:
  `cargo run --release -p volta-bench --bin p6_report -- --quick --pcs-q
  150` accepted and wrote
  `benchmarks/results/p6-quick-q150-2026-07-07-fa40a1d.json` (dirty tree,
  quick workload only). The JSON records `pcs_n_queries=150`,
  `pcs_query_error_bits=60.013`, and the real PCS path verified with
  `pcs_opening_bytes_total=57,822,904` B vs 66,733,504 B at Q=200 (the
  exact P7 projection). Packed quick-response download was 73.4 MB vs
  ~82.3 MB for the prior Q=200 quick profile on the same schema. The
  default constants remain Q=200; this measurement only validates the
  lever plumbing and byte model.

- **2026-07-07 (P7 report updated with measured PCS profiles)**:
  `scripts/report.py` now includes `measured_pcs_profiles`, so the P7 JSON
  distinguishes modeled scenarios from actual P6/P6-quick measurements.
  Updated local report `benchmarks/results/p7-2026-07-07-5390144.json`
  includes the Q=150 quick profile (`57,822,904` B PCS, `60.013` query-error
  bits) alongside the Q=200 profiles. The P7 go/no-go recommendation is
  unchanged: communication headroom is credible, but final decision still
  requires real-PCG and cloud GPU measurements.

- **2026-07-07 (P7 next step, pre-registered)**: add Rust-side
  accounting-only support for the static-query-cache PCS lever. Scope:
  expose a `MultiOpenProof` byte breakdown and a
  `cached_query_marginal_bytes` count in `volta-pcs`, then thread those
  numbers into future `p6_report` JSONs. This does **not** change
  `open_multi_zk`, `verify_multi_open`, challenge order, transcript bytes,
  proof contents, or soundness parameters; it only computes the marginal
  bytes that would remain if raw data columns plus their commitment Merkle
  paths were served from a verifier cache keyed by the static commitment
  root. Any actual split of setup/per-response proof remains a separate
  protocol-design entry.

- **2026-07-07 (P7 static-query-cache accounting landed)**:
  `MultiOpenProof::byte_breakdown()` now exposes the measured byte
  decomposition of the real PCS proof, and `p6_report` writes
  `opening_cached_query_cut_bytes`, `opening_cached_query_marginal_bytes`,
  and `pcs_cached_query_marginal_bytes_total`. Dirty quick schema check
  `benchmarks/results/p6-quick-2026-07-07-2b3beab.json` accepted the
  response and confirmed the same full-scale PCS accounting as P7 report:
  layer opening 4,293,216 B with a 1,734,400 B conservative static-cache
  cut, embed opening 15,214,912 B with a 13,203,200 B cut, total PCS
  **66,733,504 B → 32,717,504 B marginal**. This is still accounting-only:
  proof contents and transcript bytes are unchanged.

- **2026-07-07 (P7 local report landed)**: `scripts/report.py --write-json`
  produced `benchmarks/results/p7-2026-07-07-754626f.json` (dirty tree:
  ledger/script/test changes plus the pre-existing handoff-spec edit). The
  report consumes the clean P6 run of record
  `p6-2026-07-07-515bb1c.json` and the P7-prep dirty packing source
  `p6-2026-07-07-d71e339.json`; `tests/test_report.py` verifies that the
  PCS formula reproduces the measured 66,733,504 B exactly (4,293,216 B per
  layer opening ×12 + 15,214,912 B embed). Current packed download is
  **144.8 MB**. Projection-only PCS levers: same-rate Q=150 for ~60-bit
  query error → **135.9 MB** packed response; per-tensor RLC 8→4 / 6→3
  claims → **130.9 MB**; Q=150+RLC → **122.0 MB**; embed 2^12-row shape
  → **140.1 MB**; static-query verifier cache marginal → **110.8 MB** and
  cache+RLC marginal → **96.9 MB**. No proving path changed and no
  soundness parameter was adopted. GPU rho sensitivity: CPU P6 rho implies
  the GPU proof kernels must beat native-inference GPU speedup by **4.62×**
  for prefill and **2.54×** for decode to hit rho≤5/≤2. Local
  recommendation is conditional cloud spikes only; final P7 go/no-go remains
  blocked on real-PCG cost and actual GPU roofline/native-baseline
  measurements.

- **2026-07-07 (P7 local plan, pre-registered)**: scope for this VM pass is
  deliberately conservative. Add `scripts/report.py` plus focused tests: it
  consumes `benchmarks/results/*.json`, uses the clean P6 run of record for
  proof/PCS timing and the P7-prep dirty P6 run only for the measured
  public-logits packing delta, writes a non-overwriting `p7-*.json`, and
  prints the rho / communication / PCS-lever tables. PCS changes here are
  projections only: Q/rate alternatives, per-tensor RLC claim merging,
  static-query verifier caching, and embed shape are modeled from the
  checked `MultiOpenProof::bytes()` formula, not enabled in the proving
  path. No Q/rate soundness parameter, commitment layout, PCS transcript, or
  Lean-facing invariant changes in this pass. Real-PCG and cloud CUDA remain
  unmeasured local blockers; the report records the counted correlation
  volume and a conditional go/no-go/sensitivity model instead of pretending a
  GPU run happened.

- **2026-07-07 (P7 prep — public-logits bit-packing landed, measured)**:
  handoff spec §4.6.E implemented: the public band logits (i64, true range
  ≪ 2^64) travel bit-packed (per-row min + fixed-width offsets, "VLPK1"
  codec in `volta-bench/src/logits_pack.rs`); the verifier consumes the
  DECODED matrix (asserted bit-exact) inside `p6_report`'s e2e session, so
  the packed size is the real download and the codec sits on the accepted
  path. Transport-only — nothing enters the transcript, no protocol or
  soundness surface touched. Measured at the P6 workload (accepted e2e,
  golden decode ✓, flat-cost gate 1.18): **public logits 20.50 → 7.41 MB
  (2.77×), total response download 157.9 → 144.8 MB**. JSON schema gains
  `public_logits_packed_bytes` + `total_response_download_packed_bytes`
  (old fields keep their meaning). Dirty-tree measurement
  `p6-2026-07-07-d71e339.json`; the clean-tree run of record lands with
  the commit checkpoint. The §4.2 is_max argmax argument stays logged as
  the deeper lever (would remove the remaining 7.4 MB at ~2.5 M lookups).

- **2026-07-07 (P7 prep — two notes for the record, CLOSED, no P7 action)**:
  1. **Chunking trade is a closed decision.** 5×10 decode chunks prove 23.1 s
     vs 18.7 s for the single deferred Q=50 chunk (+23%, per-chunk fixed
     instance costs). The single deferred chunk is the mode of record
     (`p6_report` run of record; the 5×10 curve exists only as the flat-cost
     gate). Chunking stays available as a latency/streaming knob — never
     per-token (P4 dev. #8) — and is NOT a P7 work item; do not revisit
     unless a streaming product requirement lands.
  2. **`layer_rejects_lying_row_max` dev-profile behavior is documented and
     robust, not a bug.** Pre-existing since P5 (reproduced at commit
     `18e883d`, dev profile): the wires tamper trips the honest-prover
     `debug_assert` in `hadamard_prove` before any proof exists — dev builds
     cannot emulate this cheating prover at the wires level (P4 dev. #10
     caveat). The test (`volta-proto/src/block_proof.rs`) wraps the case in
     `catch_unwind` and counts a prover-side panic as detection; release
     builds exercise the verifier-side reject. No action needed; do NOT
     "fix" by removing the library debug_asserts.

- **2026-07-06 (P6 plan, pre-registered)**: scope, design decisions and gate,
  fixed before implementation (user constraints: still the 11 GB / 4-core VM;
  P7 moves to cloud CUDA; comm up to ~150–200 MB/response acceptable as a
  post-response download, but every saved MB counts):
  1. **Two-phase shared-α LogUp restructure** (the deferred ÷12 amortization,
     P5 closing #2, unified with cross-token batching): phase 1 binds ALL
     element-wise auths model-wide — boundaries, LN/attn vectors, and ONE
     global multiplicity vector per **table content** (content key =
     `Range(shift)` for requant/remainder tables, `Pair(lut)` for exp / gelu /
     ln_rsqrt / softmax_recip; equal-shift range tables merge across sites,
     layers AND phases — the ledger 2026-07-06 #6 freebie). One α per content
     is drawn only after phase 1 (strictly later than every binding it
     depends on — a strengthening of the current per-instance ordering).
     Phase 2 runs the per-site lookup-side trees with the shared α (no
     per-site table side, no per-site mult auth), collecting authenticated
     root fractions per content; per content, ONE table-side tree against the
     global multiplicity vector + an authenticated fraction-sum chain
     (running (P,Q), 3 Π_Prod rows + 3 full corrs per site) ties
     Σ_sites p_s/q_s = p_t/q_t, closed by the existing root cross-check.
     Expected effect at T=100: multiplicity corr 59.4 MB → ~10 MB (one 8 B
     vector per content, ~20 contents), table-side E-mults ÷(sites/content).
  2. **Decode = deferred stacked chunk proving** (P4 dev. #8 verbatim
     constraint): witness generation is autoregressive (prompt 100 + 50
     greedy-argmax tokens, KV cache append-only), proving is deferred to end
     of response and covers each decode chunk (default ONE chunk of Q=50) as
     a batch of Q rows — never per-token instances, never per-token PCS
     claims. Attention generalizes to a **rectangular offset-causal band**:
     queries = the chunk's Q rows (positions t0..t0+Q), keys/values = the
     full cache S = t0+Q, mask `j ≤ t0+i`, rect domains h_pad×Q_pad×S_pad
     (prefill = the degenerate band t0=0, Q=S=T — same code path). All
     row-local machinery (LN, FFN, requant sites, seams, embed requant +
     selection with the wpe window at offset t0) runs unchanged at t=Q.
  3. **Authenticated KV cache across phases** (mirror of M4): decode K/V rows
     are authenticated once per chunk under fresh position-separated domains;
     the band's K̃/Ṽ full-cache openings resolve as weighted streamed MAC
     openings over BOTH segments (prefill auth + chunk auths). Anti-replay
     gate: reusing / mixing a cache row's corrections across positions or
     layers must fail verification (smoke test, cheating-prover emulation).
  4. **Logits at every decode position**: final-LN runs as a t=Q batch on the
     last layer's decode rows; the public logits matrix (Q×V) is bound at one
     random (ρ_v, ρ_q) and reduced by one blind matvec sumcheck to one wte
     claim (same machinery as P5's single-row logits claim); token sampling
     is then a PUBLIC argmax check per position. The response tokens are
     public output, so decode selection S(z) stays public.
  5. **Gate (architectural, CPU)**: per-token proving cost ~flat as the cache
     grows — measured with a chunked run (5 chunks × 10 tokens, cache
     100→150): cost/chunk may grow only by the O(S·d) attention term, never
     O(S²); anti-replay smoke passes; golden check (numpy decode reference,
     50 tokens bit-exact). Recorded, not gated: ρ_decode, verified tokens/s,
     bytes/token with breakdown, PCS opening with stacked prefill+decode
     claims (~2× prefill claims), peak RSS ≤ 11 GB.
  6. Out of scope, logged for P7: real-PCG spike (pre-registered P5 agenda),
     PCS commitment consolidation / query-count levers, per-tensor RLC
     merging of prefill+decode weight claims (the batch opening at
     2.3 ms/claim absorbs ~100 claims fine on CPU).

- **2026-07-07 (P6 CLOSED — run-of-record decisions and open levers)**:
  1. **Gate passed** (see milestone row). Architectural claim confirmed on
     CPU: per-token proving cost is ~flat as the cache grows (chunk curve
     0.236 → 0.263 s/token over cache 100→150 — the O(seq·d) attention term
     only; an O(seq²) design would have doubled immediately). The decode
     marginal ratio ρ_decode = 5.07 (marginal prove / native KV-decode wall)
     is ~4.6× BETTER than ρ_prefill (23.1): decode proving batches 50 rows
     into one stacked chunk while native decode is matvec-bound.
  2. **One code path for prefill and decode**: attention generalized to the
     offset-causal band (`BandShape`, prefill = t0 0 square band) — the P4/P5
     regression suite validates the band machinery directly. Cross-phase
     cache openings are segmented streamed MAC openings (`CacheSegP/K`);
     anti-replay holds by position-separated domains (smoke-tested).
  3. **Chunking trade measured**: 5×10 chunks prove 23.1 s vs 18.7 s for the
     single Q=50 chunk (+23% — per-chunk fixed instance costs). Deferred
     single-chunk proving is the mode of record; chunking is a
     latency/streaming knob, never per-token (P4 dev. #8 upheld: claims per
     response = 2× prefill, one stacked PCS opening).
  4. **Band logits are public response output** (20.5 MB for 50 positions):
     each sampled token is checked as a PUBLIC argmax of the previous
     position's logits row inside `verify_response`. Counted in the download
     total, not in the proof transcript. Lever if it ever matters: an is_max
     argmax argument (P5's row-max machinery reused per vocab row) would
     replace 20.5 MB with ~2.5 M lookups — logged, not scheduled.
  5. **Comm decomposition at 150 tokens: 157.9 MB total download** = 48.4
     (prefill corrections/transcript) + 22.3 (decode marginal, 445 KB/token)
     + 66.7 (PCS opening, 102 claims over 13 commitments) + 20.5 (public
     logits). The PCS opening replaced multiplicity vectors as the single
     largest lever (P7: commitment consolidation, query count, per-tensor
     RLC claim merging — the 2.3 ms/claim model held: open 1.05 s).
  6. Final-LN/logits machinery now runs on ALL band rows (t=q batch) — the
     P5 t=1 duplicated-row deviation stays prefill-only.
  7. Witness-side: band witnesses are SLICES of one full causal re-forward
     (prefix-consistency, asserted bit-exact vs the KV-cached incremental
     decode and vs numpy over 50 tokens); prover accumulators (LN affine,
     gelu multiplicities) are recomputed from boundaries + stats, so bands
     carry no lookup traces.

- **2026-07-07 (P6 in progress — shared-α restructure landed, measured)**:
  the two-phase pipeline (P6 plan #1) is implemented on the prefill path and
  re-measured at T=100 on the frozen artifact
  (`benchmarks/results/p5-2026-07-07-9a19662.json`, accepted e2e with the 13
  real PCS openings): **multiplicity corr 59.4 MB → 2.85 MB** (beats the
  ~10 MB estimate — equal-shift range tables merge more than 12×), **total
  comm 159.6 MB → 101.2 MB/prefill** (projected response 154 MB), prove
  11.2 → 10.1 s, verify 0.65 → 0.32 s, E-mult all-in 100.6 → 93.6/budget
  lookup, peak RSS 2.82 GB. Structural changes: `TableKey` content keys,
  `TableBankP/V` (phase-1 global mult auth + per-content α + per-content
  table side with an authenticated fraction-sum chain over all site roots),
  `prove/verify_layer` split into phase1/phase2, per-instance table sides and
  mult vectors deleted. PCS numbers in this JSON are noisier than the run of
  record (embed commit 6.5 s vs 3.5 s — background load; PCS code untouched).
  Also observed (pre-existing, reproduced at the P5 commit `18e883d` in dev
  profile): `layer_rejects_lying_row_max` trips the honest-prover
  `debug_assert` in `hadamard_prove` before the proof exists — the wires
  tamper cannot be emulated in dev builds; the test now counts a prover-side
  panic as detection (release exercises the verifier reject).

- **2026-07-06 (P5 plan, pre-registered)**: pre-P5 assessment closed with the
  user: **no CPU optimization cycle before P5** — the remaining LogUp/PCS
  levers (helper-column family, padding layout, NEON/lazy reduction) are
  design trade-offs whose payoff depends on the GPU cost model (P7 decides),
  and P5's own amortizations (÷12 tables, batched PCS claims) change the
  numbers first; the dev loop (~10 s/prefill prove) is iterable. Scope:
  1. Work items: (a) `scripts/export_gpt2.py` — one-off HF safetensors
     download, per-tensor pow-2 scales calibrated on the golden prompt, the
     12 LUTs at real scales, `cattn_permuted` weight layout (dev. 2026-07-05
     #7), fixed prompt-token file, quantized format read by Rust via memmap2;
     (b) numpy fixed-point reference (~200 lines, bit-exact vs the Rust
     witness generator; golden check = logits/argmax at the last position);
     (c) full-model driver: embedding, 12 chained layers with x_in
     authenticated once per seam (fixes the single-layer double-count,
     dev. #9), final LN + logits row; (d) **one multiset argument per table
     per model** — table-side LogUp and multiplicity binding lifted from
     per-layer to per-model (÷12, pre-registered in dev. #4); (e) one batched
     PCS opening for all 49 claims, committed-W mode by default;
     (f) `scripts/run_prefill.sh` + `p5_report` — one command, full JSON.
  2. Report schema additions (pre-registered): **PCS opening bytes** (absent
     from the P4 JSON) and **total communication per response** as a
     first-class measured number, broken down (auth corrections /
     LogUp+sumcheck transcripts / multiplicity vectors / PCS opening).
     Analytic estimate to confirm or kill: ≈49 MB corrections with mult ÷12,
     plus opening — the ~55 MB/response ballpark is a product constraint.
  3. Saturation contingency (dev. #5): calibration first tries exponents with
     zero saturations on the golden prompt; if the no-clamp assert fires on
     real weights, the **saturation side-table becomes the first P5 work
     item** (clamp-range side lookup), not a redesign.
  4. **New convention (user)**: prover time may be bought with verifier time
     (verifier is currently cheap, ~NanoZK-level: 0.041 s/layer) but **never
     with final proof size** — communication is already the binding product
     constraint. Applies to all P5+ design choices.
  5. Gate unchanged from the plan of record: one-command reproducible run,
     complete JSON, golden check green; counts vs P0 budget <20% or explained;
     peak RSS ≤ 11 GB. ρ_prefill is recorded and analyzed, not gated (GPU
     target, P7).
  6. Agenda items logged here, NOT P5 scope: (a) real-PCG (silent VOLE)
     setup/expansion cost spike **before the P7 go/no-go**; (b) the P6
     interface requirement is extended from PCS claims to **cross-token
     batching of lookups** (per-model tables already amortize the table side
     across tokens; the lookup-side instances must batch too — never fixed
     per-token instance cost).

- **2026-07-06 (P5 CLOSED — run-of-record decisions and open levers)**:
  1. **Gate passed** (see milestone row). Fixed-point fidelity on real weights
     confirmed end-to-end: numpy reference, Rust witness and the proved
     computation agree bit-for-bit on the full logits vector.
  2. **Table amortization (÷12) DEFERRED to the P6 restructure — motivated
     deviation from the pre-registration.** Merging table-sides per table
     content requires a SHARED LogUp α across instances, i.e. a two-phase
     pipeline (bind all layers' multiplicity vectors before any α). That is
     the same restructure the P6 cross-token lookup batching (already a
     ledger interface requirement) needs — doing it twice would be waste.
     Measured cost of deferring: multiplicity corr 59.4 MB/prefill vs ≈5 MB
     amortized (the single largest comm lever, −54 MB), plus table-side
     E-mults. P6 does both at once.
  3. **PCS cost model updated**: the P3.5 model (0.12 s + 2.3 ms/claim)
     assumed ONE commitment; the 13-commitment baseline pays 13 fixed passes
     → measured open 0.73 s for 51 claims (12 × ~0.035 s + embed 0.30 s).
     Levers: commitment consolidation (needs the non-pow2-rows Ligero
     variant or >11 GB RAM) and session-level batching. Verify stays cheap
     (0.07 s).
  4. **Comm 159.6 MB/prefill measured** (the ~55 MB ballpark is missed 2.9×;
     JSON total = the Transcript byte ledger — corrections and PCS bytes are
     inside it, an earlier draft double-counted). Path back: −54 MB mult
     amortization (P6), −6.9 MB x_in auth reuse, then the 52.8 MB opening
     (query count / rate / consolidation — P7 levers). Product constraint
     stays under watch, not yet killed.
  5. **Selection-identity bug found by the run of record and fixed**: the
     embedding-selection's wpe term must be MASKED to real rows (committed
     block rows t..1023 are nonzero); a direct point claim only worked at
     power-of-two T. Fix: dedicated masked sumcheck (G(w) = [w<t]·eq public).
     The e2e regression now runs at non-pow2 T=20. Lesson logged: pad-domain
     identities must be tested at t ≠ t_pad.
  6. New instances beyond the P0 budget (embed requant, 11 seams, final-LN,
     logits, selection, is_max machinery) are outside `ModelOut.lookups` and
     the budget formulas — noted in the JSON (`embed_lookups_note`),
     E-mult all-in 100.6/budget lookup (P4 layer-only: ≈90).

- **2026-07-06 (P5 in progress — quantization semantics for real weights)**:
  three spec amendments forced by real GPT-2 ranges, decided at export time
  (quantization-spec.md updated in the same commit):
  1. **Stable softmax (shifted exp)**: real attention scores reach ±20+, so a
     direct base-e `exp` LUT saturates. New semantics: `s' = s − c_row` with
     `c_row := max` of the causal row (spec definition; softmax is invariant
     to any row shift in exact arithmetic), exp LUT is base-e, faithful on
     `x ≤ 0`, and its **table content only covers the nonpositive domain** —
     LogUp membership itself range-checks `s' ≤ 0`. Soundness that `c_row` is
     the true max (a malicious shift could saturate/flatten attention):
     `s' ≤ 0` from the table domain + **per-row product-zero check**
     `Π_j s'_j = 0` via the existing Π_Prod machinery (M7/M8) proves
     `c_row = max`. `c_row` itself is bound linearly (`c = s − s'` per entry).
     Pad pairs unchanged (exp[0x8000] = 0 stays the least-index zero); the
     product-zero rows are the real (unpadded) rows only — pad rows are
     excluded by the same public row-selector approach as the causal mask.
  2. **Embedding requant (13th table)**: `wte` is tied (embedding + logits
     weight) and needs its own scale `f_wte` ≫ the residual-stream scale
     `f_res` (real residual maxima are orders larger than |wte|). New
     `requant_embed` table: `embed_out = (wte[tok] + wpe[pos]) >> shift_embed`
     (round-half-up), T·d = 76,800 extra lookups per prefill — a new LogUp
     instance at model level, not in the P0 budget (explained deviation).
  3. **GEMM biases (real GPT-2 has them, P4 synthetic didn't)**: quantized at
     the OUTPUT scale of their op and folded linearly into the accumulator
     (`acc += b << shift_op`) before the requant lookup — same pattern as the
     P4 LN bias. Biases and LN gain/bias are **public** verifier inputs in P5
     (extends P4 deviation #6; the private tensors are the four big matrices
     + wte/wpe via PCS).
  Also fixed: ONE global shift/LUT set for all 12 layers (per-layer scales
  would break the one-multiset-per-table amortization); weight exponents are
  per tensor-type (max |w| across layers); calibration = float ranges on the
  golden prompt + headroom bits, verified by a strict no-clamp fixed-point
  pass (saturation ⇒ side-table contingency, pre-registered).

  **Iteration 2 (same day, measured failure)**: with a single global residual
  scale the calibrated f_res is 1 (late-layer outlier channels reach ~1e3
  while the embedding is ~1e-1) and the fixed-point argmax broke on the
  golden prompt (float ' way' vs fixed '\n') — no saturation, pure precision
  loss in the early layers. Amendments (spec updated):
  4. **Per-layer residual scales** `f_res[l]`, monotone non-increasing, with
     **seam requants** between layers (`x_in(l+1) = ffn_block_out(l) >>
     seam_shift`, shift 0 = free). Only the residual-facing sites go per
     layer (attn_proj/ffn_down requant shifts + seams + embed); LN is
     scale-free w.r.t. its input scale (`dev_int·r_int = x̂·2^R` for any f),
     so the ln_rsqrt table, LN path, qkv/scores/softmax/gelu tables all stay
     global. Extra lookups ≤ 11·T·d ≈ 845k/prefill (~5%).
  5. **Chained requant for shift > 16** (real params already produce 18–19):
     `requant(acc, s) := requant(requant(acc, s−16), 16)` — double-round
     semantics by definition; keeps every remainder table ≤ 2^16 (the naive
     2^19 table would cost a 4 MB multiplicity vector alone).
  6. Amortization freebie (for the P5 prover): remainder range tables with
     equal shift are content-identical ACROSS sites/layers — the multiset
     argument merges per table *content*, so the per-layer shift lists cost
     few distinct tables, not 12× per site.
  7. **PCS memory decision**: one full-model commitment needs a 2^28 message
     (48 layer blocks 163.6M + wte 2^26 + wpe 2^20 → pow2 232M; ≈4 GB encoded
     — over the 11 GB VM with the rest of the pipeline). P5 baseline: **12 ×
     P4_LAYER (2^24) layer commitments + 1 × GPT2_FULL (2^27) embedding
     commitment (wte+wpe, `layout_gpt2_embed`)**, 13 batched openings per
     response. Prover cost is ~unchanged (the dominant fixed cost is the
     O(|W|) proximity pass — same total data either way); consolidation and
     the verifier-side 13× column checks are levers to re-measure, not
     requirements.
  8. **Implementation state (2026-07-06, evening)**: the full-model proof is
     e2e green on the frozen artifact (t=16 smoke): (A) GEMM biases as public
     transport corrections; (B) chained requant (2-stage range sites,
     shift_ln_norm=20 and shift_attn_proj 17/19 exercised); (C) stable
     softmax per #9 below; (D) model driver — 12 layers + seam requants +
     embed requant + final-LN + logits claim + embedding-selection sumcheck,
     ONE model-wide Π_Prod/Π_ZeroBatch closure; 51 committed-tensor claims
     (48 layer + 2 wte + 1 wpe), nothing pending. Known accepted deviations:
     final-LN at t=1 runs as a duplicated-row t=2 batch (machinery needs ≥2
     rows; dup row bound to nothing — sound); x_in is re-authenticated per
     layer (double-auth ≈ +6.9 MB corr vs the budget's once-per-seam
     counting — explained, reuse is a lever); `verify_model` takes the whole
     Gpt2Model but reads only public fields (biases/LN params/luts/tokens) —
     prototype interface, not a leakage.
  9. **Row-max soundness design (stable softmax, refines #1)**: the shared
     scores/exp wire becomes s′ = s − c_row; c_row is an authenticated
     h_pad×T_pad row table; the scores-instance acc transport gains an
     authenticated public-coefficient fold 2^s·⟨gc, c⟩ (gc_i = Σ_{causal y ∈
     row i} eq(pt,y), same cost class as P4's pad-mask term). Existence of
     the row zero (c = max, given s′ ≤ 0 from the table domain): witness
     indicator wire `is_max` carried as a non-membership column of the exp
     instance, with (a) one hadamard-with-claim-0 row (ĩs_max ∘ s̃′ ≡ 0) and
     (b) one rowsum identity (row sums of is_max = 1 on real rows, the
     denominator-rowsum trick). No per-row product gates, no element auth of
     wires; booleanity of is_max is not needed ((a)+(b) already force a zero
     per row).

- **2026-07-05 (P4)**: one full transformer layer (attention + FFN fused
  blocks, LogUp instances, chained GEMMs, hadamard, real Ligero opening)
  proved + verified e2e at T=100. Gate passed; decisions and deviations:
  1. **E-mult gate missed, motivated**: measured 12.20 E-mult/lookup
     lookup-side vs pre-registered target ≤8–10. Attribution (matches the
     cost model to <5%): leaf layers ≈2.8 (base-field + round-0 prescale) +
     upper tree layers ≈7.0 (structural — Gruen doesn't touch the fraction
     combines) + tree build ≈1.7 + suffix eq tables ≈0.5. The 8–10 target is
     unreachable in this protocol family within the bandwidth budget:
     helper-column LogUp reaches 2–4 E-mult but adds 16 B/lookup corrections
     (≈48 MB/prefill — rejected); recounting mul-by-7 as shift-add would
     game the pre-registered `emult_equiv = fp2 + base/5` convention
     (rejected). Convention (pre-registered with the user): gate is
     lookup-side only; table side reported raw (L=1) and /12-amortized.
  2. **Full instance cost of record**: 126.5 M E-mult/layer for the 14 LogUp
     instances all-in (≈42/padded lookup, ≈90/budget lookup) — the bare
     fraction-tree floor (12.2) plus table-side trees, deg-3 aux-claim
     folding, in-field packing closures and multiplicity bindings. Chain
     cost outside instances: 2.2 M E-mult/layer. Wall: prove 0.805 s/layer
     ≈ 23.7× native forward on 4 cores (naive ×12 ≈ 9.7 s prefill vs 0.41 s
     native — the GPU-target ρ story is P7's job, not P4's).
  3. **Rectangular padding (pre-registered)**: witness lookup streams match
     the P0 budget exactly (1,412,000/layer, 0%); the LogUp instances run on
     padded domains (3,016,960/layer, 2.14×) — attention instances expand
     causal-packed wires to h_pad(16)×T_pad(128)×T_pad rectangles with valid
     pad pairs, and pow2 padding elsewhere. Exp pad pair = least LUT index
     with output exactly 0 (0x8000 at default scales), so rectangular row
     sums equal causal ones and the denominator rowsum identity
     `deñoms(ρ) = 2^rb·ẽxp(½..½,ρ)` needs no pad correction.
  4. **Multiplicity binding (not in the P0 budget)**: multiplicity vectors
     are authenticated element-wise per instance — 3.87 MB/layer, the
     largest correction stream (boundary auth is 3.07 MB). Tables are shared
     across the 12 layers ⇒ P5 amortizes to **one multiset argument per
     table per model** (÷12), pre-registered.
  5. **No-clamp assert (pre-registered with the user)**: the synthetic
     witness is asserted at runtime to never saturate any requant; the
     saturation side-table is P5 scope.
  6. **Small-vector simplifications (pre-registered)**: LN per-row stats
     (mean, var, rsqrt_in/out — 8·T_pad values/layer) and attention row
     tables (denoms, recip_in, recips — 3·16·T_pad) are authenticated
     element-wise instead of proved via rowsum/centering sumchecks; the LN
     requant lookup, rsqrt/recip LUT membership, denominator=rowsum and the
     hadamard bilinear step ARE proved. `recip_in = denoms >> 6` is bound
     only by element auth of both vectors (P4-DEVIATION(recip-in) in code).
     LN gain/bias are public verifier inputs in P4 (weights private via PCS).
  7. **c_attn is committed on a permuted layout**: the single qkv requant
     instance runs on a T×4096 domain with `col' = third·1024 + head·64 + l`
     (third/head become bit fields; K/V thirds close via boundary MAC
     openings with boolean selectors, q third via the 12 head aux claims).
     Its chained GEMM therefore claims W̃ on the permuted 768×4096 tensor
     (`cattn_permuted`); `layout_gpt2_layer` commits exactly that layout
     (same 2^22 block, offsets unchanged). One claim per tensor holds:
     4/layer, point lengths 22/20/22/22.
  8. **PCS re-projection (measured P3.5 cost model, 0.12 s + 2.3 ms/claim)**:
     49 prefill claims (4×12 + logits) → **0.233 s**; per-response with
     deferred decode ≈ 2×49 claims → **0.345 s** — replaces P3.5's 220-claim
     0.70 s projection (the per-layer wiring delivered lever (a): 1 claim
     per tensor instead of q_avg≈3.4). Measured at layer scale (2^24):
     open 0.041 s, verify 0.007 s. **P6 constraint (verbatim)**: i
     weight-GEMM del decode si differiscono e si provano impilati a fine
     risposta (claims/risposta ≈ claims/prefill), mai claim PCS per-token.
     P5 girerà e2e in modalità committed-W di default.
  9. Boundary auth measured 5 tensors/layer (x_in, K, V, attn/ffn_block_out)
     vs budget's 4 — x_in is the previous layer's output (embed_out at layer
     0), authenticated once per seam in the full model; a single-layer
     report double-counts it. LUTs are Rust-built at synthetic scales; the
     numpy reference + real weight export land in P5.
  10. Causal-mask soundness is a dedicated blind product sumcheck row
     (public maskAbove·eq(τ) table); the reject test is a wires-level
     cheating-prover emulation (library debug_asserts force witness-honest
     provers, so tampering is injected at the derived-wire layer).

- **2026-07-04 (P3.5)**: static weight PCS implemented and measured at full
  scale (2^27 synthetic i16 coefficients — no weight export yet, that is P5;
  PCS cost is data-independent). Decisions and findings:
  1. **Library decision (closes the open "repo evaluation" risk)**: in-house
     minimal Ligero in new crate `volta-pcs` (~700 lines: Goldilocks NTT,
     blake3 Merkle — the only new external dep — ZK opening, batching). No
     external library (Plonky3 / Binius / p3-basefold) provides the delicate
     part, the ZK opening that resolves into a DV MAC (M9); they would only
     supply NTT+Merkle, each ~150 lines here. Binius is binary-field,
     off-target for Goldilocks.
  2. **Opening architecture iterated once, in-milestone**: the generic
     multi-point → single-point reduction (blind sumcheck over 2^27, path A)
     measured **5.8 s** — E-field O(|W|) work dominates everything. Replaced
     by the **row-local multi-eval opening** (path B, pipeline of record):
     block-aligned claims need masked row combinations over only their
     tensor's Ligero rows; all claims share one column-query set and resolve
     via a single Π_ZeroBatch. **0.70 s** (8.4×), no reduction sumcheck.
  3. **Gate FAILED and re-understood**: 0.70 s = 230% of native prefill
     (gate ≤15%), 38% per 600-tok response (gate ≤3%). Attribution: the
     design-note estimate assumed ONE O(|W|) pass at ~native throughput.
     Measured: (1 + q_avg)·O(|W|) `mul_base` passes with q_avg ≈ 3.4
     claims/tensor; the single global pass alone is 0.11 s = 36% (u64 field
     mults are ~3–5× slower than i16 MACs). **Cost model**: opening ≈ fixed
     0.12 s (proximity pass + columns) + **2.3 ms per claim** (block pass +
     mask row). The "~3% amortized" story therefore holds only if
     claims-per-response stays O(prefill count): naive decode adds ~49
     claims/token ⇒ **cross-token claim reduction is a P6 interface
     requirement**, not an optimization.
  4. **Iteration levers (before/with P4–P6)**: (a) fewer claims/tensor
     upstream (share the q=3 RLC opening points where sound: 220 → ~64
     claims ⇒ ~0.35 s, 21 MB); (b) P6 cross-token claim accumulation;
     (c) session-level batching (fixed part shared over k responses);
     (d) NEON/lazy-reduction engineering of the mul_base passes;
     (e) fallback knob: per-user MAC-auth (option B) breakeven is ~1.4
     responses/GB-of-setup at current numbers — still a deployment knob.
  5. **Leakage**: smoke passed (transcript structure identical across weight
     sets, masked rows uniform, columns pad-randomized). Known limitation
     pre-registered: pad=512 covers ONE opening's ≤200 distinct columns;
     repeated openings accumulate column exposure → larger pad or periodic
     re-commit (P7 line item).
  6. **Soundness parameters pre-registered**: rate 0.516, δ≈0.48, Q=200,
     error ≈ (1−δ/2)^Q ≈ 2^-81 (d/3-style analysis would need Q≈312; pad
     keeps hiding headroom). PCS binding is the explicit M9 hypothesis.
  7. Verifier stays cheap (0.12 s incl. 442 NTT encodes); commit one-off
     3.3 s / 2 GB encoded matrix in RAM; peak RSS 7.3 GB (fits 11 GB).
  8. Correlation use: 220 full corrs (claims) + 220 (s_g) + 1 (ZeroBatch);
     opening communication 73.8 MB (u_g rows dominate), vs 30.1 MB auth
     corrections — drops linearly with claim reduction (lever a).
  P4 does not depend on PCS speed; PCS claim-count levers land with P4's
  per-layer wiring and P6's decode design.

- **2026-07-04 (private weights — supersedes the "no PCS" note of 2026-07-03)**:
  the public-weights assumption was implicit and is now retired: the target
  deployment is a provider that does NOT reveal W. Decision (full analysis in
  `docs/private-weights-pcs.md`): static public commitment `C_W` via a
  field-native code-based PCS (Ligero/Brakedown/Basefold family over
  Goldilocks) + **one batched ZK opening per response** resolving into a
  VOLE-authenticated value (never a cleartext `W̃(r)` ⇒ no per-query weight
  leakage). Per-response cost O(|W|) mults ≈ 1–3 % of native work for
  realistic responses, model-size-independent as a ratio — the prover
  advantage does not erode at 20B. Per-user weight MAC-auth (Mystique-style,
  option B) rejected as architecture (O(|W|)/user correction bandwidth,
  ~160 GB at 20B) but kept as a deployment knob. Consequences: new milestone
  **P3.5**; formal phase reopens for one interface lemma (**M9**,
  opening-into-MAC, composing with M3) — open, not yet scheduled; P0 budget
  and P7 extrapolation gain a PCS line.

- **2026-07-03 (plan amendment, pre-P2)**: risk re-read after P1 — the open
  risk is prover *constant factors* (sumcheck + LogUp), not tensor
  authentication (structurally 0.044% of native work, kernel confirmed by P1).
  Two amendments to the plan of record: (1) new **P2.5** — clear-LogUp
  constant-factor spike (synthetic 16-bit LUT, ~10M lookups, real shapes),
  pulled forward from P4, independent of P2/P3, informative gate
  (ns/lookup, E-mult/lookup pre-registered); (2) **P3 gate decomposed** — the
  clear reference sumcheck is timed, and protocol ρ is recorded as
  t(clear)/t(GEMM) and t(blind)/t(clear) separately, so a bad number is
  attributable to sumcheck itself vs IT-blinding (incl. lazy m_r expansion).
  Milestone order unchanged: P2 remains next (P3 consumes it). Note: phase P
  has **no PCS** — DV setting with public GPT-2 weights; a committed-weights
  variant would be a scope change to be logged separately if pursued.

- **2026-07-04 (P2.5)**: clear-LogUp prover constant measured at 23.2
  E-mult/lookup — ~5× the budget's "O(1) ≈ 4–5" estimate, past the 2×
  iteration trigger. Per the informative gate this does NOT block P3; the
  **iteration plan (before P4)**: (a) Gruen eq-factor split (pull eq out of
  the cubic round evals — saves ~1/3), (b) exploit base-field leaf structure
  (α−f has constant c1; first 2–3 layers can run mostly in F_p — the leaf
  combine already does, extend to their sumchecks), (c) rayon over the round
  loops (spike was single-thread; native anchor uses 4 cores, so wall-ratio
  15.6 → ~4 with parallelism alone). Target ≤ 8–10 E-mult/lookup measured
  in P4's real LogUp. Note the *verifier* is already cheap (0.10 s @ 2^23).
- **2026-07-03 (P1)**: naive sequential timing showed ρ<1 (frequency drift on
  the M2 VM); replaced with ABBA paired timing (`time_paired`), which is the
  measurement of record. Criterion benches kept for CIs.
- **2026-07-03 (P1)**: epilogue draws only the mask `r` (8 B ChaCha) at auth
  time — prover tags `m_r` (16 B/value) are expanded lazily at *opening* time
  (P3), not in the GEMM epilogue. Their cost must be counted in P3's prover
  budget, not here.
- **2026-07-03 (P0)**: correction bandwidth re-based from 2 B to 8 B per value
  (7.5 → 30.1 MB per prefill-100). Reason: M5 covers `F_p`-typed corrections
  (subfield of `E=F_p²` is Goldilocks itself); the 16-bit packing claim in
  `sota/initial-brainstorming.md` needs mod-2^16 masks + an authenticated
  carry bit — deferred, not silently assumed.

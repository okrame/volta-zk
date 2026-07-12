# Prototype Status Ledger (phase P — CPU prototype)

The implementation-phase analogue of the formalization table in
`protocol-sketch.md`. One row per milestone; key numbers land here, raw runs
land in `benchmarks/results/*.json`. Plan of record:
`~/.claude/plans/streamed-hugging-bunny.md` (approved 2026-07-03).

Workload of record: **GPT-2 small (124M, L=12, d=768, h=12, d_ff=3072),
prefill T=100 tokens, causal**, all CPU (aarch64 VM, 4 cores, ~11 GB).
CPU numbers validate architecture and counts; the P7 ρ targets (≤2 decode,
≤10 prefill) remain GPU targets.

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
| P7 report + GPU budget model | **integrated-hybrid full + same-host native anchor complete; resident ABI + forward witness + LogUp/PCS families landed, prover gate open** (2026-07-12) | full T=100+50/Q=200 golden exact ✓; repeated exact attribution ✓; flat-cost 1.363 ✓; packed response 144.821 MB ✓; same-seed differential/fault/reuse/anti-replay ✓; corrected same-host native GPU 7-rep anchor ✓; resident buffer/GEMM, full forward witness, LogUp and PCS contracts A100-tested ✓; resident prover gate open | On `3mq19up4`, native A100 prefill is **20.929±0.389 ms MAD**, decode50 **770.045±8.648 ms**, golden exact; CPU speedups 53.542×/2.901×. Hybrid proof prefill **42.039±1.419 s**, decode marginal **21.975±0.659 s**, so same-host staged ρ_proof is **2008.584/28.537** (diagnostic, not paper). Representative hybrid session: 6.868 H2D + 25.433 D2H + 0.110 kernels + 68.439 CPU; 17.813/5.560 GB transferred, 4.313 GB peak device. Sources `p7-integrated-hybrid-2026-07-12-706d067.json`, `p7-gpu-native-inference-2026-07-12-faa7667.json`; aggregate `p7-2026-07-12-a5d4fa5.json`. Resident infrastructure/kernel checkpoints have no resident e2e number yet. |

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

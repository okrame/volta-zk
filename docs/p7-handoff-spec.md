# P7 handoff spec — for the incoming coding agent

**Audience**: an autonomous coding agent (Codex) taking over VOLTA-ZK from P7
onward. You can and should explore the repo yourself; this document exists to
give you (a) the operating contract with the harness, (b) the state and
numbers of record, (c) the P7 work items with their levers already quantified,
and (d) the invariants and known traps that are NOT derivable from the code.

The former plan of record lived outside the repo (`~/.claude/plans/`); its P7
content is folded into §4 below. From now on, this file plus the ledger ARE
the plan of record.

---

## 1. What this project is, in ten lines

VOLTA-ZK is a **designated-verifier (DV) proving system for transformer
inference**: VOLE-MAC authenticated values + blind GKR/sumcheck + LogUp
lookups + a Ligero-style PCS for private weights, over Goldilocks
(p = 2^64 − 2^32 + 1, extension E = F_p²). The formal phase (M1–M9, Lean
theorems in `lean/`, see `docs/protocol-sketch.md`) is CLOSED and frozen.
The prototype phase P runs GPT-2 small (124M) fixed-point on CPU
(aarch64 VM, 4 cores, 11 GB): P0–P6 are done. The project lives or dies on
**ρ = prover_wall / native_inference_wall**; the final MVP targets ρ ≤ 2
(decode) and ρ ≤ 5 (prefill) are **GPU targets** — CPU numbers validate
architecture and counts, and P7 decides GPU go/no-go by extrapolation.

## 2. Operating contract with the harness (non-negotiable)

1. **`docs/prototype-status.md` is the single source of truth** — one row per
   milestone, gates, key numbers, and a deviations log. Update it at every
   milestone boundary, whenever a measured number lands, and whenever a
   decision deviates from plan. When the implementation needs something the
   Lean theorems don't cover, **log it in the deviations section — never
   silently assume**.
2. **Every bench run writes `benchmarks/results/<milestone>-<date>-<gitsha>.json`**
   (machine, shapes, times, counts, bytes). Never overwrite old runs. A "run
   of record" must have `git_dirty: false`.
3. **Milestone end = commit checkpoint + ledger update.** Pre-register gates
   and metrics in the ledger *before* implementing (see the P5/P6 plan
   entries for the format).
4. **Cost-trade convention (2026-07-06)**: prover time may be bought with
   verifier time (verifier is cheap, ~0.5 s/response), **never with final
   proof size / communication**. Communication is the binding product
   constraint (envelope: 150–200 MB per response as a post-response
   download; currently 144.8 MB packed, 157.9 MB raw). Session setup bytes
   (PCG, §4.4) are a separate counted category, not response download —
   but they must be reported, never hidden.
5. **Bit-exactness**: the Rust fixed-point forward (`rust/volta-gpt2/`) is
   the witness generator and must match the numpy reference
   (`scripts/gpt2_fixed.py`) bit-for-bit. Quantization semantics are frozen
   in `docs/quantization-spec.md`. The golden checks (`golden-p5.bin`,
   `golden-p6.bin`) are load-bearing gates.
6. **Correlations are mock-PCG** (shared ChaCha seed, Δ verifier-only),
   one-time use, domain-separated indices (session, layer, head, position,
   tensor_tag); every consumption is counted. A real Goldilocks silent-VOLE
   backend is a P7 work item (§4.4, decision 2026-07-07); the mock stays the
   default and the test baseline until the real backend reaches measured
   parity.
7. Measured counts are compared against the analytic budget
   (`scripts/budget_p0.py`, table in the ledger); deviations > 20% must be
   explained in the ledger.

## 3. State of record after P6 (2026-07-07, `p6-2026-07-07-515bb1c.json`)

Workload of record: GPT-2 small, prompt 100 tokens + 50 greedy decode tokens,
one two-phase proving session, real 13-commitment PCS with stacked claims.

| Quantity | Value |
| --- | --- |
| prove_response | 18.7 s = prefill 10.5 s + decode marginal 8.2 s |
| ρ_prefill / ρ_decode (CPU, 4 cores) | 23.1 / 5.07 (decode batches 50 rows per chunk) |
| flat-cost gate | curve 5×10 chunks, last/first 1.12 (≤ 1.5) — O(seq·d), no O(seq²) |
| verify | 0.57 s + 0.10 s PCS; verified 2.67 tok/s |
| **total response download** | **157.9 MB** = 48.4 prefill transcript + 22.3 decode marginal (445 KB/token) + **66.7 PCS opening** + 20.5 public band logits; **144.8 MB packed** after §4.6.E logits packing (landed) |
| PCS | 13 commitments (12 × layer 2^24 + 1 × embed 2^27), 102 claims (96 weight + 6 embed), open 1.05 s, commit one-off 9.5 s |
| peak RSS | 3.47 GB (limit 11 GB) |

Architecture facts you should not re-derive:
- **One code path for prefill and decode**: attention is an offset-causal
  band (`BandShape`); prefill is the degenerate band t0=0. The P4/P5
  regression suite validates the band machinery directly.
- **Two-phase shared-α LogUp**: phase 1 binds all auths + ONE global
  multiplicity vector per table *content* model-wide; α per content is drawn
  only after phase 1; phase 2 runs per-site lookup trees with the shared α
  and one table side per content (authenticated fraction-sum chain). This
  took multiplicity corrections 59.4 → 2.85 MB.
- **Decode proving is deferred and stacked**: chunks of Q rows at end of
  response, never per-token instances, never per-token PCS claims
  (claims/response = 2× prefill). Chunking is a latency knob (+23% prove
  for 5×10 vs one Q=50 chunk, per-chunk fixed instance costs); the single
  deferred chunk is the mode of record — **closed decision** (ledger
  2026-07-07 "P7 prep"), not a P7 item.
- **KV cache is authenticated across phases** with position-separated
  domains (mirror of Lean M4); anti-replay is smoke-tested (prefill-row
  replay and position swap are rejected).
- **Band logits are public output** (20.5 MB), checked by public argmax in
  `verify_response`; they are download, not transcript.

Repo map (verified 2026-07-07):
- `rust/volta-field` → `volta-mac` (Authed, Π_Auth/ZeroOpen/ZeroBatch,
  corr streams+counters, transcript) → `volta-gpt2` (fixed-point forward =
  witness gen: `gemm.rs`, `layer.rs`, `model.rs`, `decode.rs`, `band.rs`,
  `luts.rs`) → `volta-proto` (blind sumcheck, Thaler, Π_Prod, LogUp
  `logup.rs`; **`block_proof.rs`**: `TableBankP/V`, band entry points
  `prove/verify_layer_phase{1,2}_band`, `CacheSegP/K`; **`model_proof.rs`**:
  `prove_response`/`verify_response` orchestration) → `volta-pcs` (Ligero:
  `ligero.rs` `commit`/`open_multi_zk`/`verify_multi_open`, `batch.rs`
  claim reduction, `layer_layout.rs`, `ntt.rs`, `merkle.rs`) →
  `volta-bench` (`src/bin/p{1,25,3,35,4,5,6}_report.rs`).
- Build: `source ~/.cargo/env; cd rust; cargo test --workspace`. Report
  binaries: `cargo run --release -p volta-bench --bin p6_report [--quick]`.
  One-command runs: `scripts/run_prefill.sh`, `scripts/run_decode.sh`.
- Weights/golden artifacts in `benchmarks/weights/` are generated
  (`scripts/export_gpt2.py`, `scripts/dump_golden.py --gen 50`), not
  committed.
- Load-bearing tests: `volta-mac/tests/e2e.rs`, `volta-pcs/tests/p35.rs`,
  `volta-pcs/tests/p4_layer.rs`, `golden_check_t100` in
  `volta-gpt2/src/model.rs`, and the gates inside `p5_report`/`p6_report`.

## 4. P7 — scope and work items

P7 has two halves: (A) the **report + GPU budget model** that decides GPU
go/no-go (this was P7's original definition), and (B) the **e2e communication
levers** left open by P6, of which the PCS opening is the dominant one.

**Status 2026-07-07 (pre-cloud local pass complete — see the ledger P7 row)**:
`scripts/report.py` + `tests/test_report.py` exist and the local report of
record is `benchmarks/results/p7-2026-07-07-d0812a7.json`; the PCS byte
formula is verified against the measured opening; the decode marginal is
profiled by transcript label; Q=150 was measured as an exploratory profile
(NOT adopted); the static-query-cache accounting landed in `volta-pcs`
(`MultiOpenProof::byte_breakdown()`). The cloud runbook is
`docs/p7-cloud-runbook.md`. Remaining work, in order: **4.4 phase A
(real-PCG expansion cost) → 4.5 (cloud GPU spikes) → 4.4 phase B**, with
4.1/4.6 levers taken up only when a measured number motivates them.

### 4.1 PCS opening bytes (66.7 MB → target ≈ 25–35 MB)

The opening byte formula (`MultiOpenProof::bytes()`, `ligero.rs`) has been
verified to the byte against the run of record. Per commitment:

```
32 (mask root)
+ 16·msg_len·(n_claims+1)                      # u-vectors (RLC batching term)
+ 16·n_claims (corr_ss) + 32 (tags)
+ n_queries · [ 4 + 8·rows                     # raw queried column  ← dominant
                + 16·(n_claims+1)              # mask column
                + 32·2·code_bits ]             # two Merkle paths
```

Current params: layers `P4_LAYER` (rows 2^10, cols 2^14, pad 512,
code 2^15, Q=200 → 4.29 MB × 12); embed `GPT2_FULL` (rows 2^13, same
otherwise → 15.2 MB). Levers, ranked by measured impact:

1. **Query count Q** (soundness knob): the `8·rows·Q` column term is 88% of
   each layer opening and 98.5% of the embed opening. Q=200 gives
   (1−δ/2)^Q ≈ 2^-81 at rate 0.516, δ≈0.48. Dropping to ~2^-60 (Q≈147) is a
   ~26% cut on the column term; changing the rate changes δ too. **This is a
   pre-registered soundness-parameter decision, not a free knob**: the IOP
   soundness is an assumed hypothesis (Lean M9 takes PCS binding as
   explicit hypothesis), so log the chosen (rate, δ, Q, error) in the ledger
   before measuring. Also: `pad = 512` covers ONE opening's ≤Q distinct
   columns — repeated openings accumulate column exposure (ledger P3.5 #5,
   a standing P7 line item). Any Q/rate change must re-check the pad
   hiding headroom.
2. **Embed commitment shape**: rows=2^13 is why one embed opening costs
   15.2 MB. Reshaping the row/col split (fewer rows, more cols — opening
   bytes scale with `rows·Q + cols·(n_claims+1)`) or splitting wte into
   row-thinner commitments attacks the single largest item. Needs the
   non-pow2-rows Ligero variant or accepts padding waste; measure both.
3. **Commitment consolidation** (12 layer commitments → fewer): kills the
   13× fixed passes (time) and 13× Merkle/mask overhead (small in bytes).
   On the 11 GB VM this was blocked (a 2^28 single commitment ≈ 4 GB
   encoded); **in the cloud phase RAM is no longer the binding constraint**
   — re-evaluate there. Preserve per-tensor/sparse openability for the future
   MoE story; don't go monolithic in a way that breaks the scaling thesis,
   projections, or phase-X mini-spec in `docs/scaling-note.md`.
4. **Per-tensor RLC claim merging** (prefill+decode claims per tensor,
   8→4 / 6→3 per commitment): halves the `16·msg_len·(n_claims+1)` u-vector
   term — worth ~1.2 MB/layer-commitment (~57% of layer bytes is u-vectors)
   but only ~12% of embed. Implementation site: where `weight_claims` /
   `embed_claims` are accumulated in `model_proof.rs` (or a small RLC
   pre-pass in `volta-pcs/src/batch.rs`) before `open_multi_zk`.

Hard invariants for ANY change here (§5): opening resolves into a
VOLE-authenticated value — never a cleartext W̃(r); one batched opening per
response, never per token; field-native transparent hash-based PCS only
(no curves, no trusted setup).

### 4.2 Public logits 20.5 MB (optional, only if the envelope tightens)

Replace the public band-logits download with an is_max argmax argument
(reuse P5's row-max machinery per vocab row): ~2.5 M extra lookups instead
of 20.5 MB. Logged in the ledger (P6 closing #4) as a lever, not scheduled.
The sampled tokens stay public output either way.

### 4.3 Smaller known levers

- x_in re-auth per layer: −6.9 MB (reuse across seams, ledger P5 #8).
- Decode marginal: **profiled** (ledger 2026-07-07, clean rerun
  `p6-2026-07-07-382bb56.json`): 445 KB/token, dominated by
  `auth_corrections` 20.9 of 22.3 MB — i.e. the real lever here is the
  formal-touching 2-byte correction packing (§4.6.B), not a transcript
  tweak. LogUp round/split/prod corrections are ~1.2 MB combined.

### 4.4 Real-PCG: implement silent VOLE over Goldilocks in-repo
**(decision 2026-07-07 — supersedes the earlier "cost spike only" scope)**

Mock-PCG hides the correlation-generation cost, and no off-the-shelf silent
VOLE exists over Goldilocks (emp-zk is C++ over Mersenne-61; swanky/ocelot
is Rust over other primes). Decision: **implement the real PCG in this repo
as the eventual production backend** — same rationale as the in-house
Ligero decision (ledger P3.5 #1): the delicate, field- and
interface-specific part is not importable, and a proxy measurement on
another field would buy a number but no reusable code. The mock ChaCha
lower bound for the P6 volume is 0.351 s
(`p7-mock-pcg-2026-07-07-d16a69c.json`); the real backend replaces that
row with a real one.

**What to build — WYKW/Wolverine-style subfield VOLE, NOT Ferret.** Ferret
is F_2/COT machinery; the correlation consumed here is exactly WYKW sVOLE
(Weng–Yang–Katz–Wang, "Wolverine", IEEE S&P 2021): prover gets
(r ∈ F_p, m ∈ F_p²), verifier gets (k ∈ F_p², global Δ ∈ F_p²) with
**m = k + r·Δ** — the MAC relation `volta-mac` already uses, with Δ chosen
by the verifier during setup as today. Reference implementations to study
for structure (not to vendor): emp-zk (C++), swanky/`ocelot`'s svole
(Rust, MIT). Construction pipeline, per the paper:

1. **Base sVOLE** of small size (~k + t + 1) — from base OTs in phase B,
   stubbed in phase A (below).
2. **Batched single-point sVOLE (SPsVOLE)** via GGM PPRF trees
   (log(n/t) OTs per point) with the paper's malicious-security
   consistency checks.
3. **LPN expansion** (primal LPN, local-linear / regular-noise code) to
   n ≈ 10^7 per iteration; bootstrap iteratively (part of the output seeds
   the next base). LPN (n, k, t, code) parameters: take them from the
   WYKW/Ferret parameter tables at ≥128-bit and **pre-register them in the
   ledger before implementing** — they are a security assumption, logged
   with the same status as PCS binding in M9.
4. **Full-field correlations** (x ∈ F_p²): two sVOLE instances sharing the
   same Δ, combined F_p-linearly (x = x₀ + γ·x₁; MACs add). Volume per
   response (P6 count): **8,479,926 sub + 176,880 full**.

**Phasing** (each phase = its own ledger pre-registration + JSON):

- **Phase A — expansion cost of record (BEFORE cloud GPU spend)**: GGM
  PPRF + LPN expansion + consistency-check arithmetic, with the base sVOLE
  stubbed from the mock shared seed (trusted-dealer base). The expansion
  is the dominant cost at this volume, so phase A yields the real number
  the GPU budget model needs. JSON `p7-real-pcg-<date>-<sha>.json`:
  `is_real_pcg: true`, `base_vole: "mock-stub"`, setup vs expansion timing
  split, corrs/s both sides, peak RSS, and the LPN parameters used.
- **Phase B — real two-party setup (production backend; may overlap with
  4.5)**: base OTs + OT extension for the GGM trees + all consistency
  checks, maliciously secure per the paper (do NOT skip the checks). This
  introduces the repo's first public-key dependency (e.g.
  `curve25519-dalek` for base OTs) — allowed: the "no curves / no trusted
  setup" invariant (§5) constrains the PCS/proof path, not the correlation
  setup; log the new dependency in the ledger. JSON gains
  `base_vole: "real"` and measured **setup communication bytes**.

**Integration contract (hard constraints)**:

- New crate `volta-pcg`. `CorrelationStream`/`VerifierCtx` grow a backend
  abstraction (enum or trait); **mock stays the default and the regression
  baseline** until phase-B parity is demonstrated and a ledger decision
  flips the default.
- CorrIndex domain separation and one-time-use counting are **unchanged**.
  The PCG produces flat per-session pools; the CorrIndex → pool-offset
  allocation must be a deterministic function of the protocol schedule,
  identical on both sides (the mock already relies on schedule agreement);
  add a cheap cross-check (hash of the allocation map exchanged in the
  transcript).
- PCG/setup communication is a **new accounting category**
  (`setup_comm_bytes` per session), counted and reported in the JSON,
  never added to the response download and never silently dropped (§2.4).
- **No change** to transcript messages, challenge order, proof contents,
  or soundness parameters anywhere in the proving path: the backend swap
  must be invisible to `prove_response`/`verify_response` except for where
  correlations come from.

**Correctness gates (pre-register in the ledger)**:

- Unit: the MAC relation m = k + r·Δ holds for every expanded correlation,
  both phases, sub and full.
- e2e: `p6_report --quick` accepted with the real backend, with
  consumption counters identical to the mock-backend run.
- Soundness smoke: tampered-correlation attempt rejected (as in P2).
- Golden decode unchanged (the witness path is untouched — assert anyway).
- Bench: extend `p7_pcg_report` with `--backend real`; report against the
  mock lower-bound row in `scripts/report.py`'s `real_pcg_spike` section
  (drop the "not_measured_in_local_vm" status when phase A lands).

**Formal/Lean position (log as a ledger deviation, no Lean work
expected)**: the Lean theorems consume ideal VOLE correlations; the PCG
realizes that ideal object under the LPN assumption — an explicit external
assumption, same status as PCS binding in M9. An interface lemma (an
"M10") is optional future work, not a P7 blocker. Lean stays frozen.

**Interaction with the budget model**: expansion is input-independent, so
it can be precomputed/pipelined before the response — it hits per-response
**cost/throughput**, not necessarily ρ latency. Decide and pre-register
how it is counted (recommended: a separate "PCG s/response" line in the
report, not folded into ρ) before quoting the phase-A number.

### 4.5 Report + GPU budget model + cloud CUDA (the go/no-go)

1. **`scripts/report.py` — DONE** (ledger 2026-07-07): ρ tables, PCS
   byte-formula check, lever projections, GPU sensitivity model; report of
   record `p7-2026-07-07-d0812a7.json`. Regenerate with
   `python3 scripts/report.py --write-json` whenever a new measured JSON
   lands (tests: `tests/test_report.py`). The go/no-go stays blocked on
   §4.4 phase A and the measured GPU roofline — the sensitivity model says
   the GPU proof kernels must beat the native-inference GPU speedup by
   ~3.7× (prefill) / ~2.6× (decode); note this ratio moved 4.62→3.67
   between two clean CPU runs (VM noise), so re-measure baselines with
   ABBA timing on the cloud box before trusting any single ratio.
2. **GPU state today: zero.** No CUDA/FFI/feature flags anywhere;
   parallelism is rayon throughout (`gemm.rs`, `band.rs`, `logup.rs`,
   `ligero.rs`, `batch.rs` are the parallel hot spots).
   Cloud GPU design sketch: kernels to port are the fused MAC epilogue,
   GEMM-proof sumcheck passes, LogUp fraction trees, and the PCS row/global
   passes + blake3 hashing. Known risks: Goldilocks F_p² arithmetic runs on
   the integer pipeline, not tensor cores (roofline risk); the MAC epilogue
   must stay **fused** with the GEMM or the near-native ρ_kernel (1.06 on CPU)
   is lost.
3. **Cloud environment notes**: `rust/.cargo/config.toml` sets
   `target-cpu=native` — CPU baselines are machine-specific; re-measure the
   native baseline on the cloud box before quoting any ρ (same ABBA paired
   timing as P1, see §6). Weight artifacts regenerate via
   `scripts/export_gpt2.py` (downloads HF safetensors once) +
   `scripts/dump_golden.py`; nothing large needs copying.
4. **Operational cloud choice (2026-07-07)**: do not spend cloud GPU time
   before §4.4 phase A has landed a real expansion number (the PCS bytes
   are already modeled in the report). First option: Thunder Compute.
   Use an H100 PCIe 80GB to measure the CUDA/roofline regime; use an A100
   80GB when the same measurements should be cost-constrained. Document the
   exact instance, region, image, driver/CUDA versions, and availability in
   the ledger and JSON output. Keep RunPod as the fallback provider so P7 is
   repeatable when a Thunder region or GPU SKU is unavailable; fallback runs
   must re-measure the native CPU baseline before quoting any ρ.
5. **Gate (pre-register the exact numbers in the ledger before running)**:
   report published, budget model with explicit assumptions, go/no-go
   recommendation on the ρ targets; if GPU kernels are actually built, the
   flat-cost, golden-decode and anti-replay gates must pass unchanged on
   the GPU path.

### 4.6 Further compression ideas (design suggestions — NOT pre-registered)

Everything in this subsection is a design suggestion from the outgoing
agent, sanity-checked against the run-of-record numbers but not measured
and not decided. Before implementing any of them, pre-register the design
and its soundness argument in the ledger (§2.3); items touching the formal
base are flagged.

**A. Static-commitment query reuse (verifier-cached columns) — the most
DV-native lever, likely the largest.** The dominant opening term
(`8·rows·Q` raw columns ≈ 35 of the 66.7 MB) is independent of the claims
and of the response: `C_W` is static, Ligero proximity is a property of the
committed matrix, and a designated verifier is stateful by definition. Let
the verifier cache the Q queried data-columns (and their Merkle paths)
after the first opening; every later response sends only fresh u-vectors,
fresh mask columns/paths (ZK stays per-response), corr_ss and tags.
Marginal opening per response ≈ 33 MB today, ≈ 17 MB combined with
per-tensor RLC (§4.1.4). Soundness: binding needs the query set to be
unpredictable at commit time only — it was, once, and the commitment never
changes; reusing the SAME set across responses is fine. Leakage: strictly
*better* than fresh queries — cumulative column exposure (the standing
P3.5 #5 concern, `pad=512` covers one opening) stops growing entirely.
Interaction: if columns become one-time setup, the Q-reduction lever
(§4.1.1) loses most of its value — re-rank before spending effort there.
Implementation surface: `open_multi_zk`/`verify_multi_open` split into a
one-time column transcript + a per-response part; verifier state keyed by
commitment root. **Accounting already landed** (2026-07-07):
`MultiOpenProof::byte_breakdown()` measures the cut — PCS 66.7 MB →
32.7 MB marginal, packed response 144.8 → 110.8 MB (96.9 with per-tensor
RLC). The protocol split itself remains a separate pre-registered design
entry.

**B. 2-byte packed corrections with an authenticated carry bit (the
deferred M5 extension) — attacks the 48.4 + 22.3 MB, not the PCS.** The
prefill transcript and the 445 KB/token decode marginal are dominated by
boundary-auth corrections at 8 B/value, but the authenticated values are
i16-ranged. The mod-2^16 packing + authenticated carry bit is already
logged (ledger 2026-07-03) as "deferred, not silently assumed": it is a
~×4 compression on ~45 MB of correction streams (order −25 to −35 MB per
response). **Formal-touching**: this extends M5, so it goes through the
protocol-change path (ledger deviation + a Lean lemma or an explicitly
logged assumption) — it is the one item here that may touch `lean/`.

**C. GPU regime shift: re-derive the code rate, don't just tune Q.** On
GPU, the cost-trade convention (§2.4) plus 10–50× prover headroom means
every (rate, δ, Q) triple should be re-solved for minimum communication at
fixed soundness: a lower rate (longer codeword) raises δ and cuts Q for
the same (1−δ/2)^Q — e.g. rate 0.516 → ~0.25 gives δ ≈ 0.7 and Q ≈ 130
for the same 2^-81, at ~2× encoding cost the GPU absorbs. Further out on
the same axis: a Basefold-style multi-round folding opening (stays
field-native / transparent / hash-based, so compatible with the
`private-weights-pcs.md` constraints and the M9 interface, whose binding
is an explicit hypothesis either way) makes the opening polylog instead of
O(√N) — the asymptotic fix if GPT-2-small ever stops being the target
size. Larger build; prototype against `ligero.rs`'s commit/open interface
before committing to it.

**D. Embed shape: closed-form optimum.** With N = rows·cols fixed and c
claims, opening bytes ≈ `16·(c+1)·cols + 8·Q·rows` (plus small terms) —
minimized at `8·Q·rows = 16·(c+1)·cols`. For the embed (N = 2^27, c+1 = 7,
Q = 200): rows* ≈ 3.1k, cols ≈ 44k → ≈ 9.8 MB vs the current 15.2 MB, from
shape alone (needs the non-pow2-rows variant; moot if A lands, since A
makes columns one-time).

**E. Merkle multi-proof pruning.** The 200 queries per commitment share
path prefixes in a 2^15-leaf tree; a pruned multi-proof saves ~30–40% of
the path bytes (~60–80 KB per commitment — small, but free and
protocol-neutral).

**Anti-suggestions** (things that look like levers and are not):
- **No recursive/SNARK wrapping** of the transcript to "compress" it: it
  breaks the DV/VOLE-MAC model (the transcript resolves into MACs under
  the verifier's Δ, which no public SNARK can consume) and abandons the
  M1–M9 formal base. Out of design space.
- **No generic compression on correction streams**: δ = y − r with r
  (pseudo)uniform makes them incompressible by construction; zstd on the
  transcript will measure ~1.0× on corrections. Only structured public
  data (logits, indices) compresses — see E.

Composed outlook if A + B land on top of E (E is done, baseline now
144.8 MB): marginal response ≈ 45–60 MB (unmeasured, order-of-magnitude),
without touching Q, rate, or the is_max design.

## 5. Invariants you must not break (and where they come from)

- **DV / VOLE-MAC**: openings resolve into MACs under the verifier's Δ;
  no cleartext weight evaluations, ever (`docs/private-weights-pcs.md`,
  Lean M9 `opening_mac_sound`).
- **Protocol code mirrors the Lean theorems** (M2 ZeroBatch, M3 blind
  sumcheck, M4 domain separation, M5 F_p-typed 8-byte corrections, M7/M8
  Π_Prod). Lean is frozen; if implementation outgrows a theorem, ledger
  deviation first.
- **Never per-token**: no per-token proof instances, no per-token PCS
  claims (P4 deviation #8, upheld through P6).
- **Comm is never traded away** for prover time (§2.4).
- **One global shift/LUT set semantics** as frozen in
  `docs/quantization-spec.md` (per-layer residual scales, chained requant
  for shift > 16, stable softmax with row-max product-zero soundness) —
  changing any of it breaks bit-exactness with the numpy reference and the
  content-keyed table merging.
- **Correlation hygiene**: one-time use, domain-separated, counted.

## 6. Known traps (each one cost a debugging session)

1. **Timing**: naive sequential timing on this VM showed ρ < 1 (frequency
   drift). Use ABBA paired timing (`time_paired`) for any measurement of
   record; criterion for CIs.
2. **Pad-domain identities must be tested at t ≠ pow2** — the
   embedding-selection wpe bug only appeared at non-power-of-two T
   (ledger P5 #5). Regression runs at T=20; keep it.
3. **numpy vs Rust rounding**: `np.round` is banker's rounding; the spec is
   round-half-away-from-zero (`round_away` in `gpt2_fixed.py`). Any new
   reference code must respect this or the golden check breaks silently.
4. **Cheating-prover tests in dev builds**: library `debug_assert`s force
   witness-honest provers, so wire-tampering tests can panic prover-side
   before a proof exists; tests count that as detection (release exercises
   the verifier reject). Concrete instance, already settled:
   `layer_rejects_lying_row_max` in `volta-proto/src/block_proof.rs` wraps
   the case in `catch_unwind` — closed in the ledger (2026-07-07 "P7
   prep"), not a bug. Don't "fix" this by removing the asserts.
5. **`target-cpu=native`** makes builds non-portable; benches on a new
   machine are a new baseline, not comparable to old JSONs.
6. **Toolchains are off default PATH**: `source ~/.cargo/env` (Rust),
   `export PATH="$HOME/.elan/bin:$PATH"` (Lean, frozen — only touch if the
   protocol changes). Python: repo-root `.venv`; `pytest` is a global uv
   tool.
7. **PCS numbers are load-sensitive** (embed commit measured 3.5–6.5 s under
   background load); quote runs of record from clean-tree, quiet-machine
   runs only.

## 7. Definition of done for P7

- Ledger row P7 filled: gates, key numbers, JSON pointer(s).
- `benchmarks/results/p7-*.json` (+ GPU-run JSONs if kernels are built)
  with the standard schema plus the new comm-breakdown deltas.
- Deviations log updated for every soundness-parameter change (Q, rate,
  commitment shapes) and every plan deviation.
- Commit checkpoint(s) at every milestone boundary; run-of-record JSONs
  from clean trees.
- A written go/no-go on the GPU ρ targets, with the extrapolation model's
  assumptions explicit.

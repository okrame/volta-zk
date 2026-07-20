# Scaling note — VOLTA beyond GPT-2: dense and MoE

**Status**: X0 analytic design and decisions are preregistered; X1 is PASS,
X2 is an immutable FAIL, and the approved X2b corrected-proxy repeat is PASS
on clean `053d3fc` (2026-07-20).  The 2026-07-13 synthetic shape/memory
sweep remains a formula-only historical artifact.  The executable X0 budget
is `scripts/budget_moe.py`, and `docs/x0-moe-design.md` is the detailed design
record.  Planning targets are **gpt-oss-20b** (24 layers, d=2880, 32 experts
top-4, 3.6B active / 20.9B total, GQA 64/8, alternating full / 128-token
sliding-window attention, RMSNorm, clamped SwiGLU, attention sinks, RoPE and
MXFP4 source expert weights) and a representative Llama-class dense/GQA
point.  X3 now has a separate zero-tolerance, non-power-of-two execution
preregistration and is hard-stopped for explicit approval; no implementation
or verdict exists.  X4 and X5 remain later packages.

## 1. The scaling thesis: ρ is ~scale-invariant; communication is not

**Prover side — ρ holds.** Every prover cost is O(active work) with
constants already measured: MAC epilogue ∝ GEMM (ρ_kernel 1.06), blind
sumcheck/GKR ∝ MACs, LogUp ∝ lookups ∝ activations, witness gen = the
native forward itself. Nothing in the protocol grows super-linearly in
model size, so **ρ = prover/native stays roughly the P6 architecture
constant at 3.6B active or 70B dense** — the GPU targets (ρ ≤ 2 / ≤ 5) are
a constant-factor engineering problem, not a scaling one. (Watch items:
memory bandwidth, and the PCS fixed pass — below.)

**Communication — three terms, three different scalings.** This is where
big models are won or lost, and each term needs its own lever:

| Term | Scales with | Lever that fixes it |
| --- | --- | --- |
| corrections (boundary auth) | **active** dims: L·d per token | **T1 boundary thinning**, after M11 |
| PCS opening, fixed part (proximity + columns) | **TOTAL committed \|W\|** — the anti-scaling term | **X4 folding PCS** |
| PCS opening, per-claim part (u-vectors) | independently evaluated blocks | per-layer commitments with canonical per-expert blocks; only proved same-point batching/reductions |
| public logits | T · vocab | packed codec (done); is_max argument |

**Boundary thinning — amended T1.** Corrections scale with authenticated cut
points, not compute, but the removable stream is not the whole correction
stream: K/V remains authenticated across positions/chunks.  Moreover, an
unauthenticated residual tensor is consumed at independently sampled points
by the residual and normalization relations.  T1 therefore authenticates
every fourth group exit and first performs one affine eq-sumcheck
multi-point-to-single-point reduction for each fan-out pair.  The exact GPT-2
split, 42-reducer cost, challenge order and M11 formal gap are preregistered in
`docs/t1-boundary-thinning-design.md`.  No blind `/k` response projection and
no cross-point linear RLC are valid substitutes.

## 2. Projections across scales (analytic; re-derive in `budget_moe.py`)

`scripts/budget_moe.py` is parameterized by immutable `ModelConfig` and
`Workload` values and reproduces the P0/C1/C3b GPT-2 anchors in self-checks.
The default is prompt 100 plus 50 deferred decode tokens.  It is an analytic
shape/count budget, not a frontend, timing measurement or proof-memory claim.

| Quantity, 100+50 | gpt-oss-20b MoE | Llama-class 8B dense |
| --- | ---: | ---: |
| native integer MACs | 485,359,730,688 | 1,076,133,888,000 |
| committed i16 parameters | 41.800 GB | 16.060522 GB |
| authenticated values, current boundaries | 46,485,064 | 77,135,176 |
| corrections, current boundaries (8 B/value) | 371.881 MB | 617.081 MB |
| authenticated values, analytic k=4 shape | 18,405,064 | 23,682,376 |
| corrections, analytic k=4 shape | 147.241 MB | 189.459 MB |
| logical / padded lookup rows | 417,267,938 / 687,568,448 | 408,291,250 / 586,362,944 |
| exact subfield correlations, current / k=4 | 46,485,064 / 18,405,064 | 77,135,176 / 23,682,376 |
| full-field correlation proxy v2 | 2,858,312, non-gating | 462,339, non-gating |
| per-layer + global commitments | 25 | 33 |
| stacked PCS claims, upper / expected | 3,316 / 3,314.06 | 452 / 452 |

All 20.9B gpt-oss parameters are committed because weights are treated as
private; only top-4 expert compute is active.  Balanced public routes are used
only for padded-domain planning.  The T1-shaped column is a residual-boundary
shape projection, not a claim that the GPT-2 T1 proof transfers unchanged to
MoE.  The v2 full-field count uses exact existing-class/session formulas
validated against X1, GPT-2/C1, GPT-2/T1 and X2, but remains deliberately
non-gating until each non-GPT architecture produces an exact schedule and
allocation digest.  Relative to X0 v1, gpt-oss changes by **-16,416
(-0.5710453302016747%)** and dense by **+91,659 (+24.727258012301714%)**;
all other table entries are unchanged.  No PCS-opening byte projection is
made: the fixed pass over total committed weights is why X4 is a prerequisite.

## 3. MoE-specific design (gpt-oss)

Related work: arXiv:2511.19902 (2025) maps MoE ops onto SNARK components;
VOLTA's DV setting changes the trade-offs — use it as a checklist, not a
blueprint. Three insights:

1. **Routing = public response metadata (decision D1).** The verifier is
   the user and already knows all tokens; publishing per-token expert
   indices makes gather/scatter a PUBLIC permutation, folded into the
   existing sumchecks as public selector terms (same class as the causal
   mask, P4 dev. #10). Leak = the expert-choice trace, a function of private
   weights and known tokens; this leakage is explicitly accepted.  Scores
   and unselected expert weights remain private, and X1 must bind top-4
   correctness and the native tie rule before consuming the public route.
2. **Routing correctness = the row-max machinery generalized.** Top-4-of-32
   reduces to selected ≥ threshold ≥ unselected (is_max pattern of P5
   dev. #9 + range lookups): ~32·24·150 ≈ 115k lookups/response, < 0.1%
   of budget. MoE itself is nearly free for VOLTA.
3. **Granularity (decision D3): per-LAYER commitments with per-expert
   blocks** — each layer commitment has a canonical map for attention,
   router, and aligned expert gate/up and down blocks.  The 24-layer point
   has 25 commitments including global embedding/unembedding material.
   Never use per-expert commitments (multiplying fixed costs) or a model
   monolith (destroying sparse block addressability).  One batched opening is
   retained per response; independently evaluated blocks remain distinct
   claims absent a proved reduction.

Maps for ~free: sliding-window = `BandShape` with a lower edge; GQA
shrinks KV auth; RMSNorm ⊂ LN machinery; SwiGLU+clamp = silu LUT +
hadamard + the saturation side-table pattern; RoPE = public linear fold
(zero lookups, K/V stay authenticated pre-RoPE); sinks = one small
authenticated vector in the softmax denominator; router softmax reuses
exp/recip tables.

**D2 is fixed:** canonically dequantize MXFP4 blocks offline into private i16
weights with explicit per-block power-of-two shift metadata, i64 accumulation,
and the frozen requant/round/clamp semantics.  No 4-bit commitment saving is
credited.  **D4 is fixed:** BF16 attention/router/embed tensors use P5-style
symmetric i16 calibration and the same bit-exact exporter/golden discipline,
including explicit per-layer residual scales.  The committed proof object is
the calibrated i16 block in both cases.

## 4. Harness adaptation

- `volta-gpt2` hardcodes `D`, `L`, `VOCAB` as compile-time consts and the
  layer struct is GPT-2-shaped → introduce a runtime `ModelConfig` (dims,
  n_experts, top_k, band schedule, norm/activation) or a sibling crate
  reusing `gemm`/`luts`/`band`. **`volta-proto` is already model-agnostic
  (instances are built from shapes) — do not fork it.**
- `scripts/export_gpt2.py` → per-architecture exporters sharing the
  calibration/golden framework; numpy reference grows the §3 ops with the
  same bit-exactness contract.
- `budget_p0.py` → `budget_moe.py` parameterized by ModelConfig; the
  ledger gets a phase-X table under the same conventions.

## 5. Phase X milestones and amended prerequisites

The former prerequisite text is retracted.  **Lever A** (verifier-cached PCS
consistency columns) is unsound by the 2026-07-15 ledger §4.6.A attack; its
projections stay retracted.  **Lever B** (Packed16) is shelved: the only sound
costed realization moves about 1.55 GB/session to save about 32.5 MB/response.
They are not Phase-X prerequisites.

The prerequisites for an end-to-end scale claim are now **T1 boundary
thinning** for corrections/correlations and **X4 folding PCS** for openings.
T1 itself is stopped on the M11 proof and user review.  Each implementation
milestone still requires a preregistered gate, append-only JSON, ledger row and
checkpoint.

- **X0** analytic budget (`budget_moe.py`, gpt-oss-20b + one dense point),
  D1--D4, private-weight policy, long-output requirement and provider envelope:
  **design complete; no MoE code**.
- **X1** routing-soundness spike (synthetic): top-k argument + cheating
  smoke (wrong expert set / score swap ⇒ reject). Gate: rejects green,
  E-mult/token-layer vs X0.
- **X2** one MoE block e2e, synthetic small (2 layers, 8 experts, top-2):
  public-gather batched per-expert GEMMs + combine through the TableBank
  session. Gate: counts within 20% of X0.
- **X3** ops pack on the band path (RMSNorm/SwiGLU/RoPE/GQA/sinks/band
  schedule) + extended numpy reference. Gate: zero-tolerance full-array
  bit-exact goldens at non-power-of-two T=7 and hidden d=48, honest proof
  acceptance, permanent op-boundary/pad rejects and exact counter/digest
  parity.  **Preregistered after X2b PASS; HARD STOP before implementation.**
- **X4** folding PCS over the per-layer/expert-block commitment map.  Gate:
  per-response opening no longer contains a fixed pass linear in all
  committed weights; exact soundness, hiding and block-subset measurements
  are preregistered in that later package.
- **X5** gpt-oss-20b e2e on the GPU box: MXFP4 export, golden decode,
  run of record with full comm breakdown + P6-style flat-cost and
  anti-replay gates. Gate: accepted e2e inside a pre-registered envelope,
  only after both T1 and X4 close.

## References

- gpt-oss-20b pinned configuration: https://huggingface.co/openai/gpt-oss-20b/blob/2e8f8052ee2aeee907f76e08c08b9fdde8677ca8/config.json
- gpt-oss model card: https://arxiv.org/abs/2508.10925
- ZK verifiable inference of MoE models: https://arxiv.org/abs/2511.19902

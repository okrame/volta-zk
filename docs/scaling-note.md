# Scaling note — VOLTA beyond GPT-2: dense and MoE

**Status**: design note + mini-spec, NOT pre-registered (2026-07-07, P7
handoff companion to `docs/p7-handoff-spec.md`). The phase sketched in §5
starts only after P7's GPU go/no-go. Planning targets: **gpt-oss-20b**
(24 layers, d = 2880, 32 experts top-4, 3.6B active / 20.9B total, GQA
64/8, alternating full / 128-token sliding-window attention, RMSNorm,
SwiGLU+clamp, attention sinks, RoPE, MoE weights MXFP4 — arXiv:2508.10925)
and Llama-class dense models (a strict subset: §4's ops pack, no MoE
machinery).

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
| corrections (boundary auth) | **active** dims: L·d per token | B (2-byte packing, ÷4); **boundary thinning** (new, below) |
| PCS opening, fixed part (proximity + columns) | **TOTAL committed \|W\|** — the anti-scaling term | A (verifier-cached columns → one-time); longer term Basefold-style folding (polylog) |
| PCS opening, per-claim part (u-vectors) | #tensors (L, experts) | per-tensor RLC; per-layer block commitments |
| public logits | T · vocab | packed codec (done); is_max argument |

**Boundary thinning — the lever this framing exposes.** Corrections scale
with the number of authenticated cut points, not with compute: the fused
blocks already prove attention and FFN with NO internal auth. Fusing
ACROSS layers (authenticate every k-th residual seam instead of every
layer boundary) divides the dominant correction stream by ~k at the cost
of deeper GKR chains — i.e. it buys communication with prover time,
exactly the allowed trade direction (ledger convention 2026-07-06), and
GPU headroom is what pays for it. At 70B-dense scale this is what keeps
corrections/token in the single-digit MB; pre-register the depth/soundness
analysis before implementing.

## 2. Projections across scales (analytic; re-derive in `budget_moe.py`)

Constants from the P6 run of record; corrections @2 B assume lever B;
"opening marginal" assumes lever A + per-layer block commitments + RLC.

| | GPT-2 124M (measured) | Llama-8B dense | gpt-oss-20b (3.6B act) | ~70B dense |
| --- | --- | --- | --- | --- |
| L·d (corr driver) | 9.2k | 131k | 69k | 655k |
| corrections/token @2 B | 0.11 MB | ~1.6 MB | ~0.9 MB | ~8 MB |
| — with thinning k=4 | — | ~0.4 MB | ~0.25 MB | ~2 MB |
| lookups / 150-tok response | 17 M | ~250 M | ~130 M | ~1.2 G |
| committed weights (i16) | 0.25 GB | 16 GB | ~42 GB | 140 GB |
| PCS claims / response | 102 | ~500 | ~2,400 | ~1,300 |
| ρ (architecture) | 23 CPU | ~same | ~same | ~same |

Readings: (a) ρ is flat by construction — the row that matters is
corrections/token, which crosses ~1 MB/token around 10B active unless
thinning lands; (b) the committed-|W| row is why lever A / folding is
structural: a per-response O(|W_total|) pass at 140 GB is dead on arrival;
(c) MoE claim counts exceed dense (every expert is touched at T = 150:
P[idle] = (7/8)^150 ≈ 2·10⁻⁹) — granularity below.

## 3. MoE-specific design (gpt-oss)

Related work: arXiv:2511.19902 (2025) maps MoE ops onto SNARK components;
VOLTA's DV setting changes the trade-offs — use it as a checklist, not a
blueprint. Three insights:

1. **Routing = public response metadata (decision D1).** The verifier is
   the user and already knows all tokens; publishing per-token expert
   indices makes gather/scatter a PUBLIC permutation, folded into the
   existing sumchecks as public selector terms (same class as the causal
   mask, P4 dev. #10). Leak = expert choices (a function of private
   weights on known inputs) — same category as P4's public biases; log it.
2. **Routing correctness = the row-max machinery generalized.** Top-4-of-32
   reduces to selected ≥ threshold ≥ unselected (is_max pattern of P5
   dev. #9 + range lookups): ~32·24·150 ≈ 115k lookups/response, < 0.1%
   of budget. MoE itself is nearly free for VOLTA.
3. **Granularity (decision D3): per-LAYER commitments with per-expert
   blocks** — row-local multi-eval (P3.5 path B) already supports
   block-aligned claims, so touched experts pay block passes only; with
   lever A the marginal is active-proportional. Never per-expert
   commitments (768× fixed costs), never a monolith (kills sparse
   openability).

Maps for ~free: sliding-window = `BandShape` with a lower edge; GQA
shrinks KV auth; RMSNorm ⊂ LN machinery; SwiGLU+clamp = silu LUT +
hadamard + the saturation side-table pattern; RoPE = public linear fold
(zero lookups, K/V stay authenticated pre-RoPE); sinks = one small
authenticated vector in the softmax denominator; router softmax reuses
exp/recip tables.

Remaining decisions to pre-register: **D2** MXFP4→fixed-point semantics
(offline dequant to i16 with per-block shifts first; committing 4-bit
codes + authenticated block scales via Π_Prod is a commitment-size lever
to measure second); **D4** BF16 attention/embed weights → P5-style i16
calibration, expect per-layer residual scales again.

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

## 5. Phase X milestones (after P7; levers A and B are prerequisites)

Each: pre-registered gate, JSON run, ledger row, commit.

- **X0** analytic budget (`budget_moe.py`, gpt-oss-20b + one dense point)
  + D1–D4 + boundary-thinning analysis logged. Gate: pre-registration.
- **X1** routing-soundness spike (synthetic): top-k argument + cheating
  smoke (wrong expert set / score swap ⇒ reject). Gate: rejects green,
  E-mult/token-layer vs X0.
- **X2** one MoE block e2e, synthetic small (2 layers, 8 experts, top-2):
  public-gather batched per-expert GEMMs + combine through the TableBank
  session. Gate: counts within 20% of X0.
- **X3** ops pack on the band path (RMSNorm/SwiGLU/RoPE/GQA/sinks/band
  schedule) + extended numpy reference. Gate: bit-exact golden, non-pow2 T.
- **X4** PCS at expert-block granularity on top of lever A (+ boundary
  thinning if pre-registered). Gate: marginal opening bytes ∝ touched
  blocks, measured by activating subsets.
- **X5** gpt-oss-20b e2e on the GPU box: MXFP4 export, golden decode,
  run of record with full comm breakdown + P6-style flat-cost and
  anti-replay gates. Gate: accepted e2e inside a pre-registered envelope.

## References

- gpt-oss model card: https://arxiv.org/abs/2508.10925
- ZK verifiable inference of MoE models: https://arxiv.org/abs/2511.19902
- GPT-2 → gpt-oss architecture evolution: https://modal.com/blog/gpt-oss-arch

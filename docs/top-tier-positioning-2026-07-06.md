# VOLTA top-tier positioning memo - 2026-07-06

Status: research memo, not a benchmark ledger. Raw prototype numbers remain in
`benchmarks/results/*.json` and `docs/prototype-status.md`.

## Bottom line

The publishable claim should not be "VOLE plus sumcheck" or "GPU zkML". Those
areas are already occupied by LPZK/VOLE-style designated-verifier ZK, by
sumcheck-based ML systems, and by GPU zkML work.

The strongest defensible VOLTA story is narrower and stronger:

1. remove polynomial commitments from per-query activation witnesses in
   transformer inference by keeping GKR/LogUp claims MAC-authenticated under a
   designated verifier;
2. keep private weights in a static PCS only, with batched opening into MAC
   values, so the expensive PCS surface is static and amortized rather than
   per-activation/per-token;
3. make autoregressive decoding stateful through an append-only authenticated
   KV cache, with anti-replay and mix-and-match soundness;
4. prove and measure the transformer-specific fused blocks, rather than
   presenting a generic backend primitive;
5. give an explicit GPU scaling model whose terms are linear in active model
   work, not in all possible wires or all total MoE weights.

The most top-tier-shaped contribution is the stateful verified-decoding system:
`F_VDec` plus authenticated KV cache plus cross-token batching. I did not find
a source-backed prior system with this exact target. Existing LLM ZK systems
focus on one-shot/layerwise/monolithic inference proofs, not persistent
authenticated decoding state.

## What the literature already owns

### zkLLM / zkAttn

zkLLM introduces tlookup and zkAttn, uses CUDA, and reports proving up to
13B-parameter LLMs in about minutes rather than hours. It explicitly handles
LLM tensor operations, attention, non-arithmetic ops, privacy of model weights,
and lookup-based attention. It also uses sumcheck-style matrix multiplication
proofs and commitments to model parameters/tensors.

Implication for VOLTA: "lookup-friendly LLM proof" and "attention-specific ZK"
are not enough. VOLTA must be about the DV trade-off and about removing
activation PCS, not about being the first LLM ZK system.

Source:
https://arxiv.org/abs/2404.16109

Key checked details:
- tlookup and zkAttn are central contributions.
- Matrix multiplication uses dedicated sumcheck.
- Experiments report OPT/LLaMA-2 up to 13B, CUDA on A100, proof sizes under
  200 kB, verifier seconds-scale.

### NanoZK

NanoZK uses a layerwise framework with Halo2 IPA, constant-size layer proofs,
16-bit lookup approximations, and Fisher-guided partial verification. It
reports roughly 6.2-6.3 s per transformer block at GPT-2 width 768 on CPU,
23 ms verification, and 6.9 KB per layer. Full 12-layer GPT-2-Small is reported
as 8.6 min sequential and 3.2 min with 12 parallel workers, including setup.

Implication for VOLTA: a headline comparison can be very strong if P5/P7 holds.
VOLTA P4 is already around 0.800 s per layer on a 4-core aarch64 CPU prototype
for the synthetic GPT-2 layer, but with much larger communication and
designated verification. The honest comparison is prover/native ratio and
deployment trade-off, not proof succinctness.

Source:
https://arxiv.org/abs/2603.18046

Key checked details:
- Layer proof size 6.9 KB across width 64..768.
- About 6.3 s per transformer block at d=768.
- Verifier about 23 ms.
- GPT-2-small end-to-end 8.6 min sequential / 3.2 min parallel, including
  setup.
- Paper itself says proving remains orders of magnitude slower than native.

### Jolt Atlas

Jolt Atlas is a 2026 lookup/sumcheck ML system built around ONNX traces and
BlindFold-style hiding of sumcheck transcripts. It is highly relevant because
it moves close to "hidden sumcheck messages" and reports GPT-2 125M end-to-end
numbers: witness generation 7.5 s, commitment 3.5 s, sumcheck proving 16 s,
reduction opening 7 s, HyperKZG prove 3 s, total 38 s on an Apple M3 MacBook.

Implication for VOLTA: the phrase "the verifier never sees polynomial
coefficients" is no longer unique by itself. VOLTA's distinction is that hidden
values are authenticated under VOLE-style MACs and per-query activation PCS is
removed, with transformer-stateful decoding as the system target.

Source:
https://arxiv.org/abs/2602.17452

Key checked details:
- BlindFold hides polynomial coefficients, intermediate Horner values and
  evaluation values behind commitments.
- GPT-2 125M benchmark total is 38 s.
- The system remains PCS/commitment based and ONNX/trace oriented.

### Mystique

Mystique is the closest ML precedent for conversions between committed and
authenticated values and for efficient matrix multiplication checks. It reports
a 7x improvement for matrix multiplication and ResNet-101 inference proofs in
28 min for private committed model, 5 min for public model.

Implication for VOLTA: Freivalds/MAC matrix multiplication alone is not a new
paper. VOLTA should frame matmul as one component of a fused transformer proof,
with PCS eliminated for activation witnesses and with a persistent KV cache.

Source:
https://www.usenix.org/conference/usenixsecurity21/presentation/weng

### Artemis / Apollo

Artemis/Apollo identify commit-and-prove overhead as a real bottleneck in zkML.
They reduce commitment-check overhead, for example VGG commitment checks from
11.5x to 1.2x in their setting.

Implication for VOLTA: this is good supporting evidence for the problem
statement. VOLTA's answer differs because the common path is designated
verifier and per-query activations use MACs; PCS remains only for static weights
and public accountability.

Source:
https://arxiv.org/abs/2409.12055

### SafetyNets

SafetyNets is early evidence that specialized interactive proofs for neural
network inference can be practical, but it targets arithmetic-circuit neural
networks, not transformer/LLM private-weight stateful decoding.

Source:
https://arxiv.org/abs/1706.10268

### BaseFold / Brakedown PCS line

BaseFold and Brakedown support the static-weight PCS choice: transparent,
field-friendly, code-based commitments are a credible family for Goldilocks-like
systems. BaseFold gives field-agnostic multilinear PCS with O(n log n) prover
time and O(log^2 n) verifier costs. Brakedown gives linear-time,
field-agnostic SNARK machinery over large fields.

Sources:
- https://eprint.iacr.org/2023/1705
- https://eprint.iacr.org/2021/1043

### GPU ZK literature

ZKProphet is useful for the P7 GPU story. It finds that after MSM speedups,
NTT-like kernels can dominate up to 90% of proof-generation latency, and that
ZKP arithmetic often runs on GPU 32-bit integer pipelines with limited
instruction-level parallelism.

Implication for VOLTA: we should not hand-wave GPU speedups. The P7 report must
classify each VOLTA kernel as memory-bound, integer-pipeline-bound, hash-bound,
or tensor-core/native-forward-bound.

Source:
https://arxiv.org/abs/2509.22684

## Current VOLTA benchmark snapshot

Latest clean run found locally:

`benchmarks/results/p4-2026-07-06-8b4ca11.json`

No P5 GPT-2 e2e result exists yet in `benchmarks/results`, and no active
benchmark process was running when checked. P5 is planned but pending.

P4 workload:
- GPT-2 small layer shape, T=100 prefill, synthetic weights.
- Full transformer layer: attention + FFN fused blocks, LogUp instances,
  chained GEMMs, real Ligero opening for four weight tensors.
- CPU: linux aarch64, 4 threads.

P4 key numbers:
- Native layer forward: 0.03285558 s.
- Prove layer: 0.800053365 s.
- Layer prover/native ratio: 24.35x on CPU.
- Verify layer: 0.041236913 s.
- Lookup streams: 1,412,000 budget lookups and witness lookups, exact match.
- Padded LogUp domain: 3,016,960, about 2.14x the witness stream.
- Lookup-side LogUp constant: 12.20 E-mult / padded lookup, missing the 8-10
  target but motivated by the fraction-tree structure.
- Full LogUp instance cost: 126.5M E-mult/layer, about 89.6 E-mult per budget
  lookup after padding, closures, table side and multiplicity binding.
- PCS: 4 weight claims for the layer, measured layer opening 0.035 s;
  projected full prefill opening with 49 claims: 0.233 s on CPU using the
  P3.5 model.
- Communication: 7.64 MB corrections/layer, 10.84 MB transcript/layer in P4.
  P5 is expected to amortize multiplicity/table-side work across 12 layers.

Earlier supporting numbers:
- P1 MAC epilogue: rho_kernel 1.06 weighted; epilogue about 2 ns/element.
- P3 blind GEMM proof: rho_total 3.34 for one `(100x768)*(768x768)` GEMM;
  blind overhead dominated by Freivalds folds and lazy tag expansion, not by
  round messages.
- P3.5 private-weight PCS: full synthetic 2^27 commitment opening with
  220 claims measured 0.696 s and 73.8 MB. Claim reduction in P4 changes the
  projection to 49 prefill claims and 0.233 s.

Reading:
- The current CPU prover bottleneck is LogUp plus padding plus multiplicity
  vectors, not tensor authentication.
- PCS is no longer fatal for GPT-2 if claim count stays O(layers), but it is a
  product constraint because opening bytes remain large.
- The verifier is cheap enough relative to prover in the current prototype,
  and the design convention says prover time can be traded for verifier time
  but not for final proof size.

## Why cloud GPU can plausibly change the P4 bottlenecks

Cloud GPU does not magically fix everything; it fixes the parts whose work is
parallel, streaming, or native to tensor inference. VOLTA has several such
parts.

### 1. Authentication epilogue

P1 already shows the MAC correction epilogue is close to native GEMM on CPU:
rho_kernel 1.06 weighted. On GPU this should be fused into GEMM/attention
epilogues, so the main cost becomes memory traffic for corrections and PCG/tag
material. This is exactly the kind of work that should overlap with native
inference kernels.

Risk: if corrections are written as separate global-memory passes, the gain is
lost. The CUDA implementation must fuse them.

### 2. Blind GEMM checks

P3 shows the blind GEMM proof is small in transcript bytes and dominated by
fold/tag expansion. These are reductions and streaming inner products. They
map naturally to CUDA reductions and can be overlapped with forward tiles.

Risk: extension-field arithmetic over Goldilocks is not tensor-core INT8 GEMM.
It should be implemented as custom integer kernels and measured against the
GPU integer-pipeline roofline, not against tensor-core TOPS.

### 3. LogUp

P4 LogUp is the current main protocol cost. The lookup-side tree is
embarrassingly parallel by table/instance/layer/head and then reduction-heavy.
GPU should reduce wall time substantially, especially for the large padded
instances (`requant_qkv`, `requant_ffn_up`, `gelu`, attention score/exp
rectangles).

Levers:
- one multiset/table per model, not per layer;
- cross-token batching for decode lookup-side instances;
- reduce rectangular causal padding where possible;
- use segmented reductions and precomputed eq/suffix factors;
- keep helper-column LogUp as a last-resort speed/communication knob, because
  P4 rejected it for adding about 16 B/lookup.

Risk: P4's 12.2 E-mult/lookup is a structural floor for this LogUp family, not
an implementation accident. GPU reduces wall time, not algebraic work.

### 4. Static weight PCS

P3.5's original 220-claim opening failed the standalone gate. P4 fixed the
upstream claim shape: one claim per tensor, 49 full-model prefill claims.
On GPU, the row/global passes and hash work in a code-based PCS should be
parallel. The key architectural rule remains:

Never do PCS per token. Batch per response or per finality window.

Risk: for MoE models, a monolithic PCS over all total parameters breaks the
"linear in active work" story. Commitments must be per tensor/expert or in a
sparse-openable layout, and only routed experts should be opened.

### 5. PCG / silent VOLE expansion

The verifier side should stream keys from seeds and never materialize all
MAC keys. The prover side should expand masks/tags in GPU-friendly blocks and
consume them once. P1/P3 suggest tag expansion is visible on CPU; it should be
an explicit P7 microbenchmark, not hidden in "setup".

## Scaling model

A useful first-order formula for a response/window is:

```text
T_prove ~= T_native_quantized
        + c_auth * boundary_values
        + c_logup * padded_lookup_values
        + c_gemmcheck * sumcheck_boundary_work
        + c_pcs * opened_static_weight_values
        + c_pcg * correlations
        + c_hash * PCS_queries
```

For dense GPT-style models, the dominant native term and the dominant proof
terms scale roughly with the same architectural quantities:

- linear/MLP work scales with parameters used by the layer;
- prefill attention scales with the model's attention pattern, often O(L*T^2*d)
  for dense causal attention;
- decode attention with an authenticated KV cache scales with new-token work,
  O(L*T*d_kv), not with re-proving past tokens;
- boundary authentication scales with O(L*T*d), not O(parameters);
- lookups scale with activation elements and attention entries, not with all
  multiplication gates;
- PCS scales with static weights opened in the response/window, and must be
  batched so it does not become per-token fixed cost.

This is why "approximately linear prover time" is plausible, but only under
the right definition:

1. For dense models, prover time should scale roughly linearly with native
   inference work at fixed sequence/generation profile.
2. For MoE models, prover time should scale with active parameters, not total
   parameters, only if weight PCS is partitioned by expert/tensor and openings
   are routed-sparse.
3. For long-context prefill, attention can be superlinear in sequence length
   because native attention is superlinear too. The KV cache claim is about
   decode, not about making dense prefill linear in context.

## gpt-oss-20b implications

OpenAI's official gpt-oss page says:
- gpt-oss-20b has 21B total parameters.
- It activates 3.6B parameters per token.
- It has 24 layers, 32 total experts, 4 active experts per token.
- It uses grouped multi-query attention and alternating dense / locally banded
  sparse attention.
- It supports context lengths up to 128k and is released in MXFP4 for 16GB
  memory devices.

Source:
https://openai.com/index/introducing-gpt-oss/

Consequences for VOLTA:

- If benchmarking the public gpt-oss-20b weights, static-weight privacy is not
  needed; the PCS line can be disabled for an engineering benchmark.
- If using gpt-oss-20b as a proxy for a private MoE model, the PCS must be
  expert-sparse. A single 21B-parameter opening per window would scale with
  total parameters, not active 3.6B parameters/token, and would damage the
  ratio.
- MoE routing becomes part of the proof surface: prove top-k/router selection,
  expert identity, and load/routing metadata. This is new work beyond GPT-2.
- Grouped multi-query attention helps communication because K/V boundary state
  is smaller than full multi-head K/V. Sparse/banded attention helps both
  native and proof costs for long context.

Scaling expectation:
- Dense GPT-2 124M to dense 20B would be roughly linear in parameter/activation
  work if memory and GPU parallelism are sufficient.
- gpt-oss-20b is not dense; the relevant slope is closer to active work
  (3.6B active params/token) plus routing proof plus sparse PCS, not 21B per
  token.
- Multi-GPU cloud scaling is natural across layers, heads, experts, and
  independent LogUp/PCS instances. The hard part is keeping proof windows and
  transcript batching stable so that cross-GPU synchronization is small.

## Publication claim to use

Candidate abstract-level claim:

VOLTA is a designated-verifier proving system for transformer inference that
replaces per-query activation polynomial commitments with VOLE-MAC
authenticated GKR/LogUp transcripts, confines private model binding to a
batched static-weight PCS, and realizes stateful verified autoregressive
decoding through an append-only authenticated KV cache. On GPT-2, the CPU
prototype already proves a full fused transformer layer with real PCS openings
at 0.80 s/layer and 41 ms verification; the GPU target is to bring prover time
to a small constant factor of quantized inference by fusing authentication into
inference kernels and batching LogUp/PCS work across layers and tokens.

## Kill benchmarks

P5:
- one-command GPT-2 small prefill T=100 with real weights;
- exact logits/argmax golden check;
- total communication, including PCS opening bytes;
- compare against NanoZK/Jolt Atlas using prover/native ratio, not only wall
  time.

P6:
- prompt 100 + 50 decode steps with authenticated KV cache;
- `verified_tokens_per_second / native_tokens_per_second`;
- show no per-token PCS claim explosion;
- show cross-token lookup batching;
- replay/mix-and-match negative tests.

P7:
- GPU roofline per kernel: auth epilogue, LogUp, GEMM checks, PCS opening,
  PCG expansion, verifier scan;
- at least one H100/L40S/A100 measurement, not only CPU extrapolation;
- compare memory bandwidth and integer-pipeline utilization.

For top-tier review, P6 is the real differentiator. P5 is necessary credibility;
P6 is the novelty.

## Open risks

1. P5 may reveal that real GPT-2 quantization introduces saturation side tables
   or additional lookups. The current export script anticipates stable softmax
   and an embedding requant table.
2. Communication can become the product blocker. The project convention is
   correct: buy prover time with verifier time if needed, but not with larger
   final proof size.
3. MoE routing and expert-sparse PCS are required before any honest
   gpt-oss-20b private-weight claim.
4. GPU field arithmetic may be integer-pipeline-bound. ZKProphet is the warning
   signal; P7 must measure this directly.
5. Prior LPZK/ILPZK/Phecda/JesseQ-style work can weaken any generic
   "authenticated sumcheck" framing. The paper should cite that line and shift
   novelty to the transformer system, static/private weight interface, and
   stateful decoding functionality.

# Concept Note

## Goal

Design a proving system for transformer inference whose prover time is within a
small constant factor of native quantized inference, while keeping output
accuracy indistinguishable from the baseline quantized model.

The working target is at least a 10x improvement in the ratio:

```text
rho = prover_wall_time / native_inference_wall_time
```

relative to NanoZK-style proving on the same model and generation workload.

## Core Idea

In public zkML systems, a large fraction of prover work is spent committing to
activation witnesses and opening polynomial commitments. In a designated-verifier
setting, the verifier and prover can instead use VOLE-style MAC correlations:

```text
k = m + Delta * x
```

for authenticated witness values. GKR boundary checks usually require opening a
linear functional of a witness tensor:

```text
MLE_x(r) = <eq(r, .), x>
```

Because MACs are linear, the same functional can be checked over authenticated
values by streaming verifier keys and prover MAC tags. This replaces MSM, FRI,
or IPA-style openings with GPU-friendly inner products.

## Transformer-Specific Shape

The system should not authenticate every internal wire. Instead, it should prove
fused transformer regions:

- attention block: Q/K/V projections, QK^T, softmax lookup, AV, output projection
- feed-forward block: up projection, activation lookup, down projection
- normalization and quantization lookup subroutines
- residual-stream boundaries
- authenticated K/V cache entries for autoregressive decoding

Internal nonlinear wires should be handled by LogUp/GKR-style lookup checks and
kept inside the fused proof whenever possible.

## Main Research Bet

The publication-grade contribution should not be "VOLE instead of a PCS" in the
abstract. The stronger claim to investigate is:

1. a blind GKR transcript where round polynomials and MLE evaluations remain
   MAC-authenticated rather than opened in the clear;
2. a streaming verifier that expands PCG keys and computes MLE key inner products
   without materializing keys or equality vectors;
3. transformer-specific fusion that keeps communication near layer boundaries;
4. an append-only authenticated KV cache for long decoding.

## Risks

- Prior art may already cover generic VOLE-opened GKR or commit-and-prove GKR.
- Verifier bandwidth may dominate prefill at larger model scales.
- Lookup volume may dominate after commitment costs are removed.
- Malicious-verifier zero knowledge requires a precise simulation argument.
- Weight binding must separate cryptographic commitment from model identity.
- Ring-native arithmetic is tempting but may add proof complexity; field-first
  Goldilocks arithmetic is the conservative baseline.

## Current Conservative Design Choices

- Use a field-first design, likely Goldilocks plus an extension field, before
  attempting ring-native arithmetic.
- Treat public verifiability as an optional dispute/escalation path, not as the
  common case.
- Authenticate K/V cache entries with domain-separated indices:
  session, query, layer, head, position, tensor tag.
- Optimize first for decoding, where authenticated cache reuse should be most
  visible.

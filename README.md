# VOLTA-ZK

VOLTA-ZK is an early research scaffold for a designated-verifier proving system
for transformer inference.

Working name: **VOLTA**, VOLE-Opened Transformer Attestation.

The project explores whether modern VOLE-style MAC authentication, blind
GKR/sumcheck, LogUp-style lookup arguments, and authenticated KV caching can
reduce the prover/native inference ratio by at least 10x versus NanoZK-style
publicly verifiable proving, while preserving the same quantized model behavior.

## Status

This repository is a placeholder scaffold. No performance claims in this repo
are benchmarked yet.

## Initial Research Hypothesis

NanoZK and related public proofs pay heavily for polynomial commitments and
openings over activation witnesses. In a designated-verifier setting, those
openings may be replaced by VOLE-derived MACs. Since GKR boundary checks need
linear functionals such as multilinear-extension evaluations, the verifier can
stream its MAC keys and check authenticated inner products instead of asking for
succinct public PCS openings.

Key tradeoffs under consideration:

- designated verifier instead of public verification
- proof/communication size linear in selected tensor boundaries
- slower verifier, but streaming and PCG-seeded
- GPU-oriented proving kernels fused with inference kernels
- authenticated append-only KV cache for long autoregressive decoding

## Repository Layout

- `docs/concept-note.md`: current system sketch and open risks
- `docs/protocol-sketch.md`: minimal protocol targets to formalize
- `docs/benchmark-plan.md`: measurement plan and success metrics
- `docs/literature-sweep.md`: prior-art checklist
- `src/volta_zk/`: placeholder Python package
- `tests/`: placeholder tests
- `experiments/`: future prototypes and measurement scripts
- `benchmarks/`: future benchmark outputs and configs

## Immediate Milestones

1. Complete a prior-art sweep on VOLE commitments, designated-verifier GKR,
   QuickSilver/Mac'n'Cheese-style protocols, zkML systems, NanoZK, zkGPT, zkLLM,
   Mystique, SafetyNets, zkAttn, and recent lookup arguments.
2. Write the formal blind-GKR-with-VOLE-MAC opening protocol.
3. Derive exact verifier costs for streaming MLE openings at GPT-2 and 7B scale.
4. Specify fused transformer block circuits and authenticated KV cache semantics.
5. Build a small prototype proving one quantized transformer block.

## License

License is TBD.

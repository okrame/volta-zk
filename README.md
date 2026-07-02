# VOLTA-ZK

Research scaffold for **VOLTA**: VOLE-Opened Transformer Attestation, a
designated-verifier proving system for transformer inference.

No performance claims in this repo are benchmarked yet.

## Layout

- `docs/...`: current system sketch and open risks
- `lean/`: Lean 4 / Lake formalization
- `src/volta_zk/`: Python scaffold
- `tests/`: placeholder tests
- `experiments/`: future prototypes
- `benchmarks/`: future benchmark outputs

## Checks

```bash
pytest
cd lean && lake build
```

First Lean build may need:

```bash
cd lean && lake exe cache get
```

## Status

The Lean target proves the base MAC/OTP/VOLE/ZeroBatch simulation lemmas.
The main blind-sumcheck PMF equality is stated with one expected `sorry`.

## License

TBD.

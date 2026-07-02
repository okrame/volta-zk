# VOLTA-ZK Lean Formalization

Lean 4 / Lake project for the first formal target: perfect simulation of
`Pi_BSC + Pi_ZeroBatch` against a malicious designated verifier in the ideal
`F_sVOLE` hybrid model.

## Build

```bash
lake exe cache get
lake build
```

## Files

- `VoltaZk.Mac`: authenticated values and linearity.
- `VoltaZk.Otp`: uniformity of masked corrections.
- `VoltaZk.Vole`: ideal corrupted-verifier `F_sVOLE` branch.
- `VoltaZk.ZeroBatch`: `Pi_ZeroOpen` / `Pi_ZeroBatch` simulator.
- `VoltaZk.BlindSumcheck`: blind transcript model and main target theorem.
- `VoltaZk.Ideal`: deferred assumptions outside this milestone.

## Status

`lake build` succeeds with one expected `sorry`:

- `VoltaZk.bsc_zeroBatch_perfect_zk`

VOLTA end-to-end soundness, LogUp, product checks, PCS, subfield VOLE,
KV-cache soundness, and UC composition are not proved here.

# VOLTA-ZK Lean formalization

This Lake project contains the M1–M12 formal layer for VOLTA's
designated-verifier protocol: authenticated values, blind sumcheck,
ZeroBatch, sequential composition, authenticated KV-cache anti-replay,
subfield corrections, product checks, the PCS opening-into-MAC interface, and
connection-scoped shared-Delta composition, boundary thinning, and X4d
deferred settlement.

## Build

```bash
lake exe cache get   # first build only
lake build
../scripts/audit_lean.sh
```

The development contains no `sorry` or `admit`. The only declared axioms are
the four named future assumptions in `VoltaZk/Ideal.lean`:

- `FerretRealizesSVOLE`
- `WeightPCSBinding`
- `LogUpGKRSound`
- `UCComposition`

The proved M1–M12 lemmas do not use those placeholders. Their ordinary Lean
axiom footprint is limited to `propext`, `Classical.choice` and `Quot.sound`;
M9 takes PCS binding as an explicit `BindsIntoMac` hypothesis. The audited
output is reproduced by `Audit.lean`; the boundary and theorem-to-file index are maintained in
[`docs/protocol-sketch.md`](../docs/protocol-sketch.md).

## Main files

- `Mac`, `Otp`, `Vole`, `ZeroBatch`, `ZeroBatchSound`: authenticated-value
  and zero-opening foundations.
- `BlindSumcheck`, `BlindSumcheckSound`, `SumcheckMv`: perfect simulation and
  malicious-prover soundness.
- `KvCache`, `Subfield`, `Composition`: replay resistance, correction domain
  and sequential composition.
- `Prod`, `ProdSound`: masked degree-2 product checks.
- `OpeningMac`: M9 PCS opening-into-MAC composition.
- `Connection`: M10 multi-response domain separation, union bound and hiding
  under one connection-scoped `Delta`.
- `BoundaryThinningSound`: M11 late-point and full-vector boundary thinning.
- `X4FoldingPCS`, `X4FoldingPCSV3`, `X4FoldingPCSV4`: the amended X4
  binding, hiding, authenticated-output link and four-event stop rule.
- `X4DeferredSettlement`: M12 exact frozen-claim union, cap bridge, batched
  mask fiber, M9/M10 composition and terminal product state.
- `Ideal`: the four explicitly deferred system assumptions above.

Protocol changes require a ledger deviation before this frozen formal layer
is modified.

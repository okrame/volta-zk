# Documentation — C7.1

Read [current status](c7.1/status.md), then the relevant part of the
[current design](c7.1/design.md). These five files are the living C7.1 documents:

| Document | Owns |
|---|---|
| [status.md](c7.1/status.md) | Goal status, authorization, next step and completion criteria |
| [design.md](c7.1/design.md) | Selected construction, requirements, assumptions and resource contract |
| [security.md](c7.1/security.md) | Exact mathematical protocol, same-W/KV soundness and joint ZK proof |
| [evidence.md](c7.1/evidence.md) | Test scope, latest validation, reproducible commands and immutable run references |
| [decisions.md](c7.1/decisions.md) | B1–B12 dispositions, exclusions, unselected/deferred choices and complete archive map |

Update the file that owns a fact and link to it from the others. Replace
obsolete current statements; do not append a second status ledger or add
historical subtotals to the selected profile. Git preserves revisions.
Goal identifiers, the step harness, scripts and tests are unchanged by
this organization. The legacy status/design/composition paths still resolve.

## Procedures and executable entry points

- [Build and test](procedures/build-and-test.md): toolchains, bounded checks,
  component filter catalog, artifacts and cleanup.
- [RunPod](procedures/runpod.md): authorized provider work, spending and evidence.
- [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py): existing goal harness and
  comparison budget; `--research-screens` is the historical, non-additive inventory.
- [Evidence](c7.1/evidence.md): links to current code, tests and run records.

## Preserved derivations and history

The [archive and migration map](c7.1/decisions.md#archive-and-migration-map)
classifies every former C7.1 dossier. Their paths remain stable so scripts,
sources and old citations keep working. They contain reusable derivations
and stage-specific obligations, not competing current instructions. Only
the dependencies explicitly selected by the active design transfer to B12.

- [C7.1 derivation notebook](c7.1-gemma31b-design.md): body frozen at `9e57199`,
  with a navigation notice; all prior profiles and B1–B12 derivations retained.
- [2026-09-10 ledger snapshot](prototype-status-history-2026-09-10.md): exact
  pre-reorganization status at `9e57199`; checksum in the migration map.
- [2026-09-07 pre-wiki ledger](prototype-status-history-2026-09-07.md): exact
  snapshot at `4f7edf0`, including C7 and C4.1/C6.4 chronology. SHA-256:
  `5dc3bfcf06edc66250741737fb9ac4d2a1b5b650cc607d2dce1ed21968343bb8`.
- [Raw benchmark records](../benchmarks/results/) and [research sources](../sota/):
  immutable originals, including failures; no inherited full-result credit.
- [ROWFOLD review](c7-d126-rowfold-v2-review.md) and
  [two-pass disposition](c7-d126-rowfold-two-pass-disposition.md): preserved
  counterexamples and limits, with reuse scoped by the current design.

All other milestone designs, handoffs, runbooks and reports are historical.
Frozen semantics and Lean lemmas still constrain components that use them;
an old hard stop stays scoped to the failed construction. Historical prose
saying “active”, “next” or “open” refers to its own stage. Snapshots stay
beside their original link base and are not rewritten as current instructions.

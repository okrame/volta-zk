# Documentation — C7.1 working wiki

Start with [current status](prototype-status.md), then read the relevant part
of the [C7.1 Gemma-31B design](c7.1-gemma31b-design.md). This index is a map;
it is not another status ledger.

## Current documents

| Document | Purpose |
|---|---|
| [Status](prototype-status.md) | Active work, evidence, open obligations, authorization and next steps |
| [C7.1 design](c7.1-gemma31b-design.md) | Model/relation, protocol requirements, security and resource accounting |
| [G1 feasibility](c7.1-feasibility.md) | Analytic admission criteria, carrier derivations and counterexamples, next constructive obligation |
| [G2 committed MAC opening](c7.1-committed-mac-opening.md) | Private-verifier bridge, ideal MAC/FS simulation, grouped hash/GKR, exclusions and remaining obligations |
| [A3 recursive RS opening](c7.1-recursive-rs-opening.md) | Fixed-cap encoder, private recursion, bounded sampling, ideal-oracle binding, accounting and concrete-hash compilation gap |
| [W-cut witness](c7.1-cut-witness.md) | Conditional W-free replay theorem, checkpoint storage, KV obligations and remaining GKR/PCS read dependencies |
| [Build and test](procedures/build-and-test.md) | Local checks, toolchains, generated assets and cleanup |
| [RunPod](procedures/runpod.md) | Authorized hardware lifecycle, Git HTTPS and evidence handling |
| [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py) · [tests](../tests/test_c7_1_gemma_plan.py) | Small executable accounting/algebra checks |

Status and design are editable; replace obsolete statements and use Git for
history. Record important decisions with reasons and source links. Add a page
only when there is a distinct topic to maintain; Markdown links and repository
search are sufficient. No parallel JSON graph or per-operation diary is required.

## Historical references and immutable evidence

All other milestone designs, handoffs, runbooks and reports are historical,
including earlier C7/D126 work. Consult them for evidence or component reuse,
not as competing current instructions. Frozen semantics and Lean theorems still
constrain components that rely on them. A historical hard stop remains scoped
to its construction and assumptions; reuse must address the relevant failure.

- [Pre-wiki ledger](prototype-status-history-2026-09-07.md): exact snapshot after merging C7 into main
  and preserving its research sources, at `4f7edf0`. It contains both C7 and
  main's C4.1/C6.4 chronology. Its embedded “active” sections and old resume
  instructions are historical. SHA-256: `5dc3bfcf06edc66250741737fb9ac4d2a1b5b650cc607d2dce1ed21968343bb8`.
- [Raw benchmark records](../benchmarks/results/): immutable measured records,
  including failed runs; C7.1 does not inherit their full-result credit.
- [Research sources](../sota/): preserved originals and same-stem Markdown.
- [Reusable components and proof obligations](c7.1-gemma31b-design.md#2-identità-del-modello-e-pezzi-riutilizzabili):
  entry point for the runtime → lemma → hypothesis → check mapping in §2.1.
- [ROWFOLD review](c7-d126-rowfold-v2-review.md) and
  [two-pass disposition](c7-d126-rowfold-two-pass-disposition.md): historical
  counterexamples and construction limits relevant to C7.1.

The snapshot stays beside the original docs so its relative paths keep their
base. Old prose references to `prototype-status.md` describe this historical
ledger; consult the snapshot, or `git show <commit>:docs/prototype-status.md`
for revision-specific content/line numbers. Historical documents need not be
rewritten just to change their old instructions or citations.

# Documentation — C7.1 working wiki

Start with [current status](prototype-status.md), then read the relevant part
of the [C7.1 Gemma-31B design](c7.1-gemma31b-design.md). This index is a map;
it is not another status ledger.

The evaluated baseline remains stopped after B7. The owner's subsequent
decisions opened B8/B9: a replacement construction and a checked native
component. B10 concludes the premise/lifecycle assessment with integration
not admitted. B11 selects the owner-authorized intermediate finite AES profile under
explicit primitive/resource hypotheses. B12 is active: a conditional bootstrap
resource extension to T80 and a durable finite-pool component are available.
A fresh post-bootstrap seal fixes the row assignment before usable FS prefixes.
The PCS analysis adds a proven unique-radius MCA bound and identifies
unsalted-root privacy loss at mask exhaustion. Its salted replacement now
has an adaptive, bounded-query Merkle hiding argument. A joint mask
translation now covers the claimless matrix transcript and its DV closure.
An opt-in salted matrix
consumer now reaches the durable B11 pool with the unique-radius IOP
geometry and an adaptive MAC-feedback bound. Merkle binding now fixes an
oracle at its commitment prefix. Native FS coin blocks now retain that fixed
opening payload; their merged errors and tape-completion memory are counted.
The fixed-root field matrix has conditional soundness and ZK arguments
for the single-setup profile (about 91 bits), including caller/simulator
and RO tapes within T121/M93. The older 86.8347-bit soundness argument
with broader lifecycle scope remains evidence.
An internal B12 linear-form bridge now connects original caller MACs to one
root/PCS; a real-B11 small case covers matrix, norm and tied embedding.
Public forms cover all 773 P0 endpoints. A new single-setup AES profile
provides up to 5,592,402 Fp3 correlations with 91.022717 conditional
bootstrap bits and a streamed COPE frame. A fraction-tree range caller now
derives W(r)'s original MAC and shares its PCS with a padding check. The
native range/padding composition retains about 91 conditional bits; D35's
82.9944-bit soundness geometry remains physically excluded. P0 + range +
one bridge fits the initial capacity at 312,693 base rows. The complete
correlation census and actual quantized Gemma GKR caller remain open.
The owner now limits the goal to one uninterrupted fixed-root run: renewal,
abort recovery and restart composition are deferred. Full Gemma malicious-verifier ZK,
the root's binding to all of quantized Gemma and the two complete fixed-run
bounds remain open in design §10. Full security and production integration
remain unadmitted.

## Current documents

| Document | Purpose |
|---|---|
| [Status](prototype-status.md) | Active work, evidence, open obligations, authorization and next steps |
| [C7.1 design](c7.1-gemma31b-design.md) | Model/relation, protocol requirements, security and resource accounting |
| [G1 feasibility](c7.1-feasibility.md) | Analytic admission criteria, carrier derivations and counterexamples, next constructive obligation |
| [G2 committed MAC opening](c7.1-committed-mac-opening.md) | Archived, unselected research: private-verifier bridge, ideal MAC/FS simulation and hash/GKR analyses; residual tests integrated, no active goal |
| [A3 recursive RS opening](c7.1-recursive-rs-opening.md) | Fixed-cap encoder/recursion, ideal-oracle binding, IBCS rewinding audit and scoped 256-bit bound exclusion, remaining hash/FS repairs |
| [A4 paired RS opening](c7.1-paired-rs-opening.md) | Fused two-read reduction/opening, arbitrary-fold binding, dyadic tensor forms and conditional GKR composition |
| [A5 wide hash opening](c7.1-wide-hash-opening.md) | Eight-Fp hash/anchor, 32-lane checker, staged costs, finite ROM embedding and explicit matrices; corrected fixed-trail screen, adaptive family security/FS open |
| [W-cut witness](c7.1-cut-witness.md) | Conditional W-free replay, P0 cohorts, exact input selectors/fanout reduction and remaining producer/KV obligations |
| [R1 requantization](c7.1-requantization.md) | Exact RNE, cubic range GKR with source availability, dyadic byte forms, two-visit A4 opening/cache and remaining Gamma/costs |
| [R2 RNE indicators](c7.1-rne-indicators.md) | Degree-7 RNE, one public-function P/S tree, same six B endpoints and explicit replay/arena exclusions |
| [K1 KV transition](c7.1-kv-transition.md) | Exact temporal views, concatenation/prefix MAC reduction, first-state alias, bounded-memory routing and remaining KV PCS/producer obligations |
| [T1 attention products](c7.1-attention-products.md) | Aggregated raw QK/PV, rectangular-view DP, GQA endpoints, source-bound probability contraction and per-layer witness schedule |
| [R3 auxiliary witness](c7.1-auxiliary-witness.md) | Unified B/raw-attention byte source, fresh raw probes/RNE pullbacks, identical striped RS encoder and staged tree-cache repairs; incomplete Gamma/liveness |
| [B9 native bootstrap](../rust/volta-pcg/src/c71_bootstrap.rs) · [bounded runner](../scripts/run_c71_bootstrap.py) | Independent MR19/P-521 and COPE/Fp9 roles, adversarial byte checks and local resources; no production/security admission |
| [B12 durable finite pool](../rust/volta-pcg/src/c71_lifetime.rs) · [salted PCS consumer](../rust/volta-pcs/src/c71_matrix/b12.rs) | Single-setup larger AES capacity with fail-closed termination, joint burns and post-bootstrap seal; legacy persistence evidence; fixed-root PCS component |
| [B12 original-MAC linear bridge](../rust/volta-pcs/src/c71_matrix/linear.rs) · [range caller](../rust/volta-pcs/src/c71_matrix/range.rs) | One batch/PCS on the installed root; private range histogram, fraction-tree GKR and zero padding keep the original W MAC; 773 P0 public-layout identities, full Gemma caller/census still open |
| [B3 native census](../scripts/c71_work_census.py) · [bounded runner](../scripts/run_c71_matrix.py) | Actual Goldilocks arithmetic and phase memory of the reduced B2 matrix path; physical traffic/security remain open in design §10 |
| [Build and test](procedures/build-and-test.md) | Local checks, toolchains, generated assets and cleanup |
| [RunPod](procedures/runpod.md) | Authorized hardware lifecycle, Git HTTPS and evidence handling |
| [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py) · [budget tests](../tests/test_c7_1_baseline_budget.py) · [B8–B12 checks](../tests/test_c71_bootstrap.py) · [algebra tests](../tests/test_c7_1_gemma_plan.py) | Default: single comparison budget, including B4–B7 decisions, B8/B9 construction/component, B10/B11 assessments and B12 resource/PCS analysis with complete security totals still unknown; `--research-screens`: preserved, non-additive research inventory |

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

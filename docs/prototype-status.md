# Current status — C7.1 Gemma-31B

Updated 2026-09-08. Editable working summary; Git preserves revisions.
[Design](c7.1-gemma31b-design.md) · [Documentation index](README.md) ·
[Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

The owner reset the direction of G2: **quantitative baseline comparison and
preparation of a small complete local experiment**, not indefinite analytic
closure before any measurement. G2 is incomplete and paused in the harness;
it has not been marked achieved. The bounded replacement contract is
[B1 in design §10](c7.1-gemma31b-design.md#10-goal-di-confronto-e-stop).

**Fundamental requirements:** lifetime soundness and zero knowledge of at
least 78 bits against malicious prover and malicious verifier. Keep private
weights, same-W/VOLE-MAC boundaries, noninteractive FS, classical ROM,
global Q64 and 2^20 attempts. Do not replace complete security with a
component parameter, honest-verifier privacy or an assumed conclusion.
Goldilocks/DV remain the working choices; the owner wants them definitive
if they deliver a real prover-time advantage, not merely a literature analogy.

**Costs:** 35 MB complete proof and 50 s warm complete prover are alarm
thresholds, not reasons to weaken security or endlessly redesign a component.
The reference remains four proof reads, no spill, the existing memory/setup
budgets and the pinned 100+50 workload. The comparison may price explicit
alternatives, including a fifth read or organized host spill; it must not
claim they meet the reference. Scope and remaining thresholds are in design §1.

**Authorization:** small local checks and a reduced synthetic E2E on this VM.
No RunPod/provider contact, H100/GPU calls, paid resources, weight downloads,
heavy builds or full Gemma E2E. A tiny CPU diagnostic is not evidence about
H100 performance. Follow the [build procedure](procedures/build-and-test.md)
with its explicit local-E2E exception. No spending authorization is pending
because no provider work is part of B1.

## Evidence and open obligations

The prior component derivations, tests, formal lemmas and counterexamples
remain intact. Their dossiers are evidence, not parallel active goals.
This summary no longer repeats their successive subtotals.

- [G1](c7.1-feasibility.md): concluded screens and exclusions of specific
  constructions, not a proof of impossibility or complete admission.
- [G2](c7.1-committed-mac-opening.md),
  [A3](c7.1-recursive-rs-opening.md) and
  [A5](c7.1-wide-hash-opening.md): useful conditional opening/hash/compiler
  analyses; exact model relation, concrete compilation and lifetime FS
  remain undischarged. A5's assumptions are not derived hash security.
- [W-cut/P0](c7.1-cut-witness.md),
  [A4](c7.1-paired-rs-opening.md) and
  [R3](c7.1-auxiliary-witness.md): reusable algebra, source layouts and
  conditional scheduling. Three specified W-subsystem reads are not a
  complete four-read schedule. Later S+Y/operator/checkpoint variants
  remain research alternatives, not additions to the frozen S reference.
- The [index](README.md) locates RNE, RMS, KV, attention and other evidence.
  No need to reload all dossiers to resume B1. Exact quantization/runtime
  correspondence and real-correlation premises remain required when reused.

Three critical-path obligations remain: same-W authenticated opening with
the required security; a complete physical schedule; a complete certificate
and work census. No new off-path kernel is authorized by this work plan.
There is still **no complete C7.1 security, size, timing or memory credit**.

## Next work

The existing [diagnostic](../scripts/c7_1_gemma_plan.py) now defaults to one
compact comparison budget. Unknown totals have admission bound
`"infinity"`, distinct from the known subtotal; they are not predicted
infinite physical costs. `--research-screens` retains the older inventory.
[Focused budget tests](../tests/test_c7_1_baseline_budget.py) check unknown
propagation, reference selection and the absence of inherited fit/security.

The [first comparison and decision](c7.1-gemma31b-design.md#primo-confronto-riproducibile-non-ammissione)
preserve the composed S reference, exclude unchanged monolithic 31B reuse
of the resident WHIR/Ligero references, and prioritize **existing authenticated
WHIR/BLAKE3** for a local reuse check. A5 is not declared broken, but is not
chosen for the prototype; no further custom-hash cryptanalysis is scheduled.
No complete baseline is admitted yet.

The existing fork provenance audit fails on the unregistered
`sumcheck/src/strategy.rs` delta, already present at opening HEAD `7e66968`.
This is an explicit reuse preflight issue, not evidence of a cryptographic
break; do not bypass it by blindly extending its allowlist.

Next is one bounded assessment of that WHIR reuse against the
[small experiment contract](c7.1-gemma31b-design.md#esperimento-ridotto-contratto-non-runner-già-pronto).
The existing CPU diagnostic is interactive/Fp2 with a historical 74-bit
parameter; the later FS entry uses the GPU path. Neither is already the
required local C7.1 experiment. Determine the smallest legitimate
FS/AES/MAC path and its security premises, or reject the baseline for B1.
After this composition, at most two focused commits before that decision;
do not resume G2's open-ended repair loop.

No native build or cryptographic E2E has run for B1. The pre-existing
uncommitted additions in `tests/test_c7_1_gemma_plan.py` belong to the
interrupted G2 work and are preserved separately from this change.

## Documentation decision

Status and design are the only active summaries; the existing index routes
to evidence. This reset removes duplicated progress prose, not source
material or research results. No new C7.1 Markdown dossier is needed.
A fresh conversation can start from this page and design §10 without
importing the full G2 transcript or reopening its suspended obligations.

# Current status — C7.1 Gemma-31B

Updated 2026-09-08. Editable working summary; Git preserves revisions.
[Design](c7.1-gemma31b-design.md) · [Documentation index](README.md) ·
[Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

**B3: native work and memory census on the B2 runner**, authorized by the
owner's next-goal request of 2026-09-08. Arithmetic counters now cover the
actual Goldilocks/Fp3 PCS, PCG, basis changes and codec, with separate phase
RSS and allocator accounts. These B3 obligations now have clean-source
records; physical expanded-array traffic remains open for the concrete
VM limitation below. B2 remains the completed CPU/Fp3 functional port.
G2 stays suspended.

**Connection to C7.1:** this census decides where further work belongs.
The matrix reduction is a small fraction of the reduced path; PCS dominates.
Before optimizing kernels or scaling, the next goal must assess the modified
PCS/lift's complete security and concrete parameters. Its nominal 128-bit
setting and tiny AES/LPN setup do not satisfy the lifetime requirement.

**B1 concluded with a negative reuse decision and its prescribed stop.**
The [assessment in design §10](c7.1-gemma31b-design.md#esito-b1-del-riuso-circoscritto)
rejects the existing authenticated WHIR path for the complete local contract;
it does not reject WHIR as a PCS family. One focused commit after the reset
records the assessment, budget and checks, within the two-commit limit.
That completed assessment is preserved; B2 is the separately authorized port.

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
because no provider work is part of B3.

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
  No need to reload all dossiers to inspect B1. Exact quantization/runtime
  correspondence and real-correlation premises remain required when reused.

Three critical-path obligations remain: same-W authenticated opening with
the required security; a complete physical schedule; a complete certificate
and work census. No new off-path kernel is authorized by this work plan.
There is still **no complete C7.1 security, size, timing or memory credit**.

## B1 disposition and B2 result

The existing [diagnostic](../scripts/c7_1_gemma_plan.py) now defaults to one
compact comparison budget. Unknown totals have admission bound
`"infinity"`, distinct from the known subtotal; they are not predicted
infinite physical costs. `--research-screens` retains the older inventory.
[Focused budget tests](../tests/test_c7_1_baseline_budget.py) check unknown
propagation, reference selection, the negative B1 disposition and preserved
preflight failures. This is source/accounting evidence, not native execution.

The [comparison](c7.1-gemma31b-design.md#primo-confronto-riproducibile-non-ammissione)
preserves the composed S reference and excludes unchanged monolithic 31B
reuse of resident WHIR/Ligero. The bounded WHIR/BLAKE3 reuse check is now
finished. A5 remains unselected research evidence; no custom-hash
cryptanalysis is scheduled. No complete baseline is admitted.

The B2 [source audit](../scripts/audit_c61_p3_fork.py) now passes:
**96 sources, 25 modified and pinned by content**, including the nine-source
Merkle fork selected by Cargo. The original 87-source manifest is unchanged.
The [mutation check](../tests/test_audit_c61_p3_fork.py) rejects changes to
registered and unregistered sources, census drift and loss of claimless
binding. This is provenance/textual evidence, not native or security admission.
B1's failed census is retained separately in the comparison budget.

The pre-existing C61 CPU diagnostic uses an interactive transcript, mock correlations and
Fp2 (75 nominal component bits in the authenticated adapter; 74 in the clear
reference). Its target key is constructed from the witness evaluation, so it
does not prove the requested matrix/output relation. The FS wrapper requires
CUDA, D27/D28, 64 GiB available host memory and 128 GiB available spill;
its generic inner executor still selects only D27/D28 in FS mode.
Switching the transcript/backend alone cannot deliver the D14 contract.
The Fp3 transfer component and AES setup exist separately, without this
complete composition. Lifetime soundness and malicious-verifier simulation
remain undischarged, distinct from standard hash/PCG assumptions.

The [B2 native component](../rust/volta-pcs/src/c71_matrix.rs) now checks the
explicit cubic-basis isomorphism, a CPU D14/Fp3 WHIR replay, and a 48×48
padded matrix relation with two responses under one installed root and an
aborted reserved slot. The verifier derives its PCS target key from the
matrix-output reduction. Three real OT/AES pool pairs feed the
[nine-sVOLE lift](../rust/volta-mac/src/c7_fp3.rs), with tiny LPN tuples
that have no security credit. Merkle opening payloads enter FS before later
draws; the independent matrix replay matches the complete transcript digest.

The strict certificate and lift codecs, concrete Gamma/FS vectors and
three-slot lifecycle now connect this path. Both roles burn the entire
reservation before execution, including codec errors, panic and abort;
a durable model-root lease rejects reset through a new session or reopened
store. Two byte-serialized matrix responses replay independently at n=48
(padding to 64) and n=128. The launcher enforces 2 GiB address space/RSS,
60 s and at most two process threads (one Rayon worker plus main).

The clean-source records at `de73f60` pass:
[48×48](../benchmarks/results/c71-b2-matrix48-20260908-de73f60.json) and
[128×128](../benchmarks/results/c71-b2-matrix128-20260908-de73f60.json), each
with two accepted byte proofs and an abort. The 128 case used 5.75 s wall,
11,288,576 bytes sampled peak RSS and 1,719,534 total protocol bytes,
including setup and both certificates. These are local dev diagnostics
with tiny, insecure LPN tuples. Those B2 records did not census native arithmetic or phase resources.
B3 adds those observations below; the full measurement contract and lifetime
security remain distinct from the functional port.

No native build or cryptographic E2E ran for B1. The pre-existing
uncommitted additions in `tests/test_c7_1_gemma_plan.py` belong to the
interrupted G2 work and are preserved separately from this change.


## B3 census and decision

The existing [launcher](../scripts/run_c71_matrix.py) now has `--census`.
[LLVM accounting](../scripts/c71_work_census.py) reads atomic native entry
counters from unchanged source, including SIMD lanes and delayed-reduction
products. A separate executable fixture checks 244 base products/7 cubic
products, then 2,048 parallel base products. Matrix reduction counts must
match their independent source derivation; both PCS roles and PCG must
contribute, and every phase's allocator balance must reconcile.

The clean records at `84ab36c` pass:
[48 census](../benchmarks/results/c71-b3-census48-20260908-84ab36c.json),
[128 census](../benchmarks/results/c71-b3-census128-20260908-84ab36c.json) and
[128 without coverage](../benchmarks/results/c71-b3-timing128-20260908-84ab36c.json).
The 128 census counts **81,665,640 base products and 6,064,002 cubic products**
over setup, two accepted responses and one abort. These are two views:
base counts include extension internals and cannot be added to cubic counts.
The separate timing run uses **5.586 s, 11,366,400 bytes sampled peak RSS**,
5,554,742 bytes peak requested heap, two threads and 1,724,078 protocol bytes.
Its two prover reductions take about 2.1 ms each; the PCS about 1.16 s each.
This supports prioritizing PCS/security, not optimizing that reduction.
The first dirty diagnostics are retained separately, without promotion.

The [single comparison budget](../scripts/c7_1_gemma_plan.py) now includes
`B3_resource_census`, phase work/resources and the separate timing record.
Five focused Rust checks, native scalar/SIMD/parallel fixtures and six
launcher/budget checks pass; the fork audit is unchanged and passing.
The broad workspace was not built. No Gemma/H100 or security credit follows.

**Physical traffic remains unmeasured:** this VM exposes only software,
tracepoint, breakpoint and probe event sources, with `perf_event_paranoid=3`.
Allocator bytes are allocation requests, not DRAM transfers. No complete
expanded-array read/write total is claimed; its admission bound remains
infinity. Closing that observation requires a suitable authorized measurement
environment and collector, not another analytic multiplier. This does not
block the independent local security assessment or authorize hardware.

**Next B4, tied to admission:** assess proximity with the enlarged initial
mask, the nine-sVOLE projection and the applicability of malicious-verifier
FS/lifetime composition to this exact same-W path. Deliver either justified
concrete parameters with a recomputed budget, or a precise negative reuse
decision. Do not optimize the insecure diagnostic, open another PCS line,
or revive G2 to avoid that decision. Gemma semantics/GKR, physical four-read
scheduling, full certificate and 78-bit lifetime proofs remain C7.1 obligations.

## Documentation decision

Status and design are the only active summaries; the existing index routes
to evidence. This reset removes duplicated progress prose, not source
material or research results. No new C7.1 Markdown dossier is needed.
A fresh conversation can start from this page and design §10 (B3 result and B4 decision) without
importing the full G2 transcript or reopening its suspended obligations.

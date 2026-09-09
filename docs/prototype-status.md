# Current status — C7.1 Gemma-31B

Updated 2026-09-09. Editable working summary; Git preserves revisions.
[Design](c7.1-gemma31b-design.md) · [Documentation index](README.md) ·
[Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

**B6 completed: compare checked alignment with native Fp3 sVOLE and reject
both immediate ports**, requested by the owner's «raggiungi il prossimo
goal per c7.1, in modo coerente con gli altri goal finora raggiunti».
The checked converter has an explicit masked-check argument with ideal
valid pools; native packing needs three sVOLEs instead of nine. The current
real bootstrap does not establish the needed premise: its base sacrifice
uses Fp challenges and one mask, unlike the extension-field check in its
reference, and its selective-failure treatment has no applicable complete
C7.1 argument. This is a scoped source/interface finding, not an E2E attack.
The [B6 decision in design §10](c7.1-gemma31b-design.md#esito-b6-confronto-dei-convertitori-e-confine-del-bootstrap)
contains both-party ideal arguments, costs, source correspondence and gaps.
B5's unchecked-converter exclusion and B4's masked-RS decision remain valid;
B2/B3 remain functional and resource evidence. G2 stays suspended.

**Connection to C7.1:** B3 showed PCS dominates the reduced path; B4/B5
prevent security admission of the current path. B6 locates the prerequisite
below either converter, in base-sVOLE. Next B7 is a bounded native Fp3
bootstrap contract/component with explicit leakage treatment, adversarial
checks and costs before pool/PCS integration. Native is the next candidate,
not an admitted port or measured speedup. Lifetime and trust stay unchanged.

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
because no provider work is part of this goal.

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
  No need to reload all dossiers to inspect B6. Exact quantization/runtime
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

## B4 security decision

The [single budget](../scripts/c7_1_gemma_plan.py) now includes
`B4_security_admission`. It decodes the frozen B2 Gamma, counts the enlarged
RS dimension `M+r`, and applies the Johnson query screen with distinct
positions. The final n=128 oracle has `(M,r,H,t)=(32,67,512,67)`;
the query-term bound gives 82.87 bits, before the other terms and FS.
This is a partial bound, not an attack probability or complete security.
None of the main oracle query terms certifies the nominal 128 bits under
this calculation; mask groups are separately included and pass that screen.

The new [native lift check](../rust/volta-mac/src/c7_fp3.rs) changes both
alignment corrections in each row by a chosen cubic value s. After a
transfer, a purported zero-MAC check has residual `(a-delta0)*s`. For
ideal uniform nonzero Delta and fixed nonzero guess a, it vanishes with
probability `p²/(p³-1)`, about `2^-64`. This refutes an automatic `1/p³`
residual argument for the lift. **It is not an end-to-end matrix forgery**;
the additional PCS/FS constraints still need their own analysis.
The Lean MAC linearity lemma assumes valid inputs and does not prove
active security of these alignment messages.

HVZK-to-FS compilation remains possible in principle. Its application to
the exact claimless same-W relation, joint setup/root-reuse/abort simulation,
MCA/OOD/code-switch terms and concrete lifetime errors is undischarged.
The three-slot lease bounds direct root queries; it is not a lifetime
simulation or renewal procedure. No concrete secure profile is selected.
Four focused Rust tests, including the counterexample and existing AES
check, and five Python budget tests pass; no protocol behavior or frozen
evidence changes, and no broad build, Lean proof or new E2E is claimed.

## B5 converter decision

The [single budget](../scripts/c7_1_gemma_plan.py) now includes
`B5_alignment_admission`. The general residual is
`b+delta0*X+delta1*u*(X+e1)+delta2*u²*(X+e2)`; arbitrary alignment errors
and a transfer realize any 3×3 base-linear map. Its rank can be one,
so full-Fp3 arithmetic alone cannot justify a `1/p³` check error.
The exact affine-fiber count and the runtime's idealized zero-to-one
sampling correction both retain the approximately 64-bit primitive limit.
Canonical bytes, hashing, invertible basis changes, excluding zero
coordinates, stronger LPN alone and repetition of these linear residuals
under the same Delta do not repair it. Additional active checks remain
possible and require their own proof, including malicious-verifier privacy.

The native check covers all nine elementary matrices, rank 1/2/3
acceptance/rejection families and shared-Delta batching. Five focused Rust
checks and six Python budget checks pass. This is an explicit derivation
and native component evidence, without new Lean or E2E claims.
Three distinct guesses under one ideal Delta give `3*p²/(p³-1)` primitive
success; extending conditionally to `2^20` gives about 44 bits. That renewal
is unimplemented, and neither number is a complete matrix/FS bound.

The rejected path reserves 20/23 Fp3 correlations per n=48/128 attempt,
including aborts, and 540/621 raw sVOLE per three-slot capacity. Its
alignment costs 2,956/3,388 bytes including one header; the existing tiny
OT/AES setup costs 145,590 bytes per connection. These are reconciled B2
costs, not secure replacement estimates. Replacement setup, capacity,
certificate and work remain unknown in the complete budget.

The B6 assessment below completes that comparison. No PCS tuning can confer
security on the rejected interface. Gemma semantics/GKR, physical four-read
scheduling, full certificate and 78-bit lifetime proofs remain obligations.

## B6 comparison and next goal

The [single budget](../scripts/c7_1_gemma_plan.py) now includes
`B6_converter_comparison`. With three ideal valid Fp2 pools, two independent
masked alignment checks sacrifice six correlations per capacity and add
235 bytes to the unchecked lift. Their conditional error is
`(p^-2+6/(p²-1))/(1-(p+1)^-3)` for independent nonzero-uniform Fp2 keys
conditioned on nonzero cubic projection. At at most `2^20` setups this is
about 105.19 bits for that ideal converter term alone, without real PCG,
PRG/hash, FS or complete lifetime credit. Fresh masks also give an explicit
ideal malicious-verifier simulation; mask reuse leaks a linear form.

Native packing under one full cubic Delta needs 180/207 data sVOLEs per
three-slot n=48/128 capacity, versus 546/627 including converter sacrifices
for checked alignment. The comparison includes storage, algebraic work,
framing, per-attempt data consumption and separate connection subtotals.
At the existing hardened k0/t0, the paper-form base-L COPE correction
payload alone is 42,261,504 bytes for one Fp3 pool versus 84,516,864 for
three Fp2 pools. These are conditional partial costs, excluding the
leakage treatment and other setup phases; no timing or secure-parameter
credit follows. All incomplete totals retain admission bound infinity.

[Wolverine](../sota/2020-0925-wolverine.md), converted with AnyDoc from the
preserved [PDF](../sota/2020-0925-wolverine.pdf), distinguishes base-LsVOLE
with selective failure from the full leakage-free base construction.
The source audit finds neither the reference's full extension-field
base check nor an applicable leakage argument in the current composition.
A field-type substitution is therefore also rejected. B7 must resolve
this boundary explicitly; stronger LPN tuples or another PCS do not do so.

Nine focused Python checks pass, including the three new B6 checks for
cost/error accounting, masked equations/privacy with exhaustive F7 error
counts, native packing algebra and the source-level bootstrap discrepancy.
The complete default budget emits valid JSON. No Rust/Lean build, native
cryptographic E2E, new benchmark record or runtime change is claimed.
Existing B2/B3 evidence and the unrelated G2 test changes are preserved.

**Next B7:** specify and check the native Fp3 base-sVOLE bootstrap component,
including the exact selective-failure or leakage-free functionality,
challenge/mask dimensions, OT/codec, both-party adversarial checks and local
costs. Select or reject integration only after those premises are assessed;
failure stops the affected integration. The scope remains small local work,
without another PCS, G2, diagnostic tuning, provider contact or hardware.

## Documentation decision

Status and design are the only active summaries; the existing index routes
to evidence. This reset removes duplicated progress prose, not source
material or research results. No new C7.1 Markdown dossier is needed.
A fresh conversation can start from this page and design §10 (B6 decision and B7 scope) without
importing the full G2 transcript or reopening its suspended obligations.

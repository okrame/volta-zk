# Current status — C7.1 Gemma-31B, B12 lifetime work active

Updated 2026-09-09. Editable working summary; Git preserves revisions.
[Design](c7.1-gemma31b-design.md) · [Documentation index](README.md) ·
[Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

**B12 is authorized and remains open.** The owner's latest 2026-09-09 request
requires adversary resources beyond `2^78`, durable single use, one private W
across bootstrap/MAC/PCS/GKR, and a complete lifetime error at most `2^-78`.
[Design §10, B12](c7.1-gemma31b-design.md#b12-risorse-lifetime-e-vincolo-same-w)
extends the **conditional bootstrap** argument to `2^80` adversary work and
memory/advice words with Q64 unchanged. Reduction work stays below `2^121`;
its memory bound rises to `2^93` words. The AES/DDH hypotheses must hold at
that larger memory envelope; they are not proved by B11. The bootstrap
subtotal remains 86.835 conditional bits. This is not yet the full C7.1
reduction, including PCS/GKR and their lifetime simulator resources.

The new opt-in [finite-pool component](../rust/volta-pcg/src/c71_lifetime.rs)
wraps both real B11 roles with a locked durable journal. Setup and joint
root-slot/row burns precede use; reopen preserves counters and accepted head
while losing unused secret capacity. It pins one installed model/semantics/root
and rejects different roots. **Root renewal remains unavailable until its
same-W proof exists.** Five native B12 checks pass, including process exit,
partial records and a real two-role bootstrap-to-MAC transfer; the combined
bootstrap/budget Python checks total 28 passing tests.

The [B12 PCS analysis](c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata)
now proves same-set MCA for a linear code with `3*radius < distance`, hence
unique message decoding. A published ideal IOPP profile retains about 88
conditional bits after a proposed Q* prefix charge at `2^35` cells, but its
monolithic initial codeword alone costs 4 TiB and remains physically excluded.
This profile is not the native B2 fork. Four small algebra/accounting checks
also pin the affine PCS/MAC closing equation and reproduce candidate-W
reconstruction after mask exhaustion in an **unsalted** Merkle commitment.
Under three independent uniform query sets, the B2 n=128 exhaustion event
has probability about `2^-24.0445`; this is a source-level privacy finding,
not a measured native FS attack. The existing salted MMCS is the repair to
instantiate; root/key labels cannot repair this leakage.

PCS hash/FS compilation into the GKR's exact authenticated endpoint, root
renewal, both-role lifetime composition and the complete resource reduction
remain open. The budget keeps both complete security errors unknown; six proposed
error allocations fitting the remaining margin are targets, not proved bounds.
All proofs must bind to **one private W**; durable public identifiers alone
do not establish that relation. No complete 78-bit or production credit.

**B11 selected an intermediate finite AES construction under explicit primitive
hypotheses.** The earlier 2026-09-09 authorization permitted the temporary
global cap of `2^64` u64 work and `2^64` memory/advice words, including
preprocessing, to close B11 and integrate the path. A later reduction must
support adversary work **beyond `2^78`**, including preprocessing and lifetime;
B12's component extension above does not yet close the complete upgrade.
Q64 remains global and `2^20` counts setup
attempts, including preparation, failures and renewals.

The selected path reuses MR19/P-521 and Wolverine Fp9→Fp3 base-sVOLE with
an AES-256 GGM/SHAKE COPE PRF, capped at 207 data rows. It avoids puncture
OT, IKNP, weak equality and LPN. The complete **conditional component**
budget is below `2^-82` (86.835 bits), requiring explicit AES/DDH advantages
at the full reductions' `2^121` work / `2^89` memory envelope. These are
named computational hypotheses, not proven concrete-primitive bounds or
78-bit security for C7.1. [Design §10, B11 intermediate](c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita)
defines the construction, proof, resources and limits. The opt-in native
profile and existing MAC consumer pass the bounded validation: twelve
clean-source B11 records at `8197f42`, including ten rejected byte faults.
**B11 is complete as the authorized conditional intermediate milestone.**

Public labels and even single-use renewal do not repair B10's 128-bit
standalone PRG lower bound. That line remains closed; the wider silent
candidate remains unselected. All proofs must bind to **one private W**
across sessions, key epochs and renewed roots. The new component does not
supply the required PCS/GKR relation or reset the installed model anchor.

**B10 concluded; integration is not admitted.** The owner's new 2026-09-09
instruction authorizes the bounded premise/lifecycle assessment and explicitly
requires all proofs to bind to the same private weights. The assessment
quantifies B9's PRF resources, identifies runtime gaps and specifies the
same-W lifecycle/AES-PCG contract. A seed-search lower bound excludes a
`<=2^-78` standalone PRG advantage for the existing 128-bit GGM at `2^64`
public AES evaluations; this is not a complete PCG or matrix attack.
Its legacy DDH/PRF and extension obligations remain undischarged; B11
selects a separate, explicitly conditional finite profile.
[Design §10, B10](c7.1-gemma31b-design.md#b10-premesse-concrete-e-contratto-di-composizione)
records the derivation and the precise disposition. B8/B9 remain valid
construction/component evidence; no runtime is promoted by this assessment.

**B9 implements and checks the selected native component.** The owner's
2026-09-09 instruction to reach the next goal authorizes the bounded B9
port. Independent prover/verifier roles execute real MR19/P-521 OT, chosen
seeds, keyed-BLAKE3 COPE, the full Fp9 check and Fp3 compression. Native
checks and ten adversarial byte cases pass, including twelve clean-source
records at `fb6c787`. B9 is concluded. [Design §10, B9](c7.1-gemma31b-design.md#b9-componente-nativo-e-confine-di-ammissione)
records the exact source mapping and remaining admission obligations.
Production/security admission and pool/PCS integration remain false.

**B8 concluded with a composable construction selected.** The owner's
2026-09-09 instruction opens replacement-bootstrap work and requires an
ad hoc construction only if reuse cannot supply one. Receiver-first
Masny–Rindal OT, its sender-chosen-message compiler and Wolverine's
leakage-free base-sVOLE supply a published route in the local classical
ROM. The source correspondence, both-role simulators, proposed P-521/Fp9
profile, conditional primitive budgets and wire counts are in
[design §10, B8](c7.1-gemma31b-design.md#b8-bootstrap-componibile-selezionato).
This selects a construction; native/security admission remains false.

**B7 concluded with failed admission; that baseline remains stopped.** The owner
authorized one bounded B7 and required stopping the baseline on failure.
The leakage-free base-sVOLE candidate has a conditional ideal-model path,
but the real OT prerequisite is not established. A native check reproduces
a related-seed relay through the current point KDF and XOR ciphertexts
across two distinct channel bindings, with consistent local transcripts.
The updated Simplest OT source withdraws the old UC claim; its robustness
and composition premises do not follow from this implementation.
Scope, source correspondence, the conditional Fp9 screen and costs are in
[design §10, B7](c7.1-gemma31b-design.md#esito-b7-fallimento-del-prerequisito-ot-e-stop-della-baseline).
This is a failed reusable OT/bootstrap premise, not an E2E matrix attack
or an impossibility result for C7.1, native Fp3 or WHIR.

**Scope after the new owner decision:** B8 supersedes the prohibition on
replacement-bootstrap research. It does not validate the old OT or open
pool/PCS integration, tuning or matrix/Gemma E2E. B2/B3's
functional/resource results and B4–B6's scoped security decisions remain
valid; G2 is archived as unselected research. Security and trust
requirements are unchanged.

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

**Current authorization:** B12's local reduction, durable finite-pool integration,
same-W PCS/GKR research and error composition are authorized by the latest
owner instruction, using narrow local checks. Production/security admission,
matrix/Gemma E2E, provider/GPU access and spending do not follow from a
component result. The final 78-bit requirements and complete adversary-resource
upgrade remain open; no further approval is needed for the authorized local work.

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
  No need to reload all dossiers to inspect B7. Exact quantization/runtime
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

No native build or cryptographic E2E ran for B1.


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

## B6 comparison

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
Existing B2/B3 evidence is preserved.

**B7 mandate, now concluded below:** specify and check the native Fp3 base-sVOLE bootstrap component,
including the exact selective-failure or leakage-free functionality,
challenge/mask dimensions, OT/codec, both-party adversarial checks and local
costs. Select or reject integration only after those premises are assessed;
failure stops the affected integration. The scope remains small local work,
without another PCS, G2, diagnostic tuning, provider contact or hardware.

## B7 failure and baseline disposition

The [single budget](../scripts/c7_1_gemma_plan.py) includes
`B7_bootstrap_admission`, sets the active baseline to
`stopped_after_failed_B7`. At B7 there was no next authorized goal. The owner
explicitly required a single bounded attempt and stopping on failure.

The ideal leakage-free candidate would use Fp9 internally, nine fresh base
masks, 576 COPE choice OTs and a subsequent compression into Fp3. Its
conditional theorem term is compatible with the statistical target;
its real OT premise fails admission. This distinction prevents a positive
field/arithmetic screen from certifying the implemented correlations.
The candidate was not implemented or integrated after that failed premise.

The preserved [updated Simplest OT source](../sota/2015-0267-simplest-ot.md)
explains the withdrawn UC claim and composition issue. The runtime KDF
does not bind session/channel or the OT A/B messages; XOR decryption never
rejects and fails the source's robustness definition. The
[native adversarial check](../rust/volta-pcg/src/phase_b.rs) relays A/B
between two distinct bindings and shifts both ciphertexts by the same
nonzero string, obtaining the shifted selected seed for either choice.
It uses no honest seed/scalar/choice and preserves each channel's transcript
agreement. The test covers 620 OT wire bytes across four channel instances.
It is not the full OT executor, an AES/LPN run or a proof of an attack on
the fixed C7.1 service topology; a direct composition proof is still absent.

The targeted Rust test passes by reproducing the rejection evidence;
**the security admission fails**. Ten Python budget/algebra checks also
pass, including explicit stop enforcement and preservation of earlier
results. The default report remains valid JSON. No broad build, new Lean
theorem, benchmark record, matrix proof or hardware claim follows. Native
build artifacts are removed.

Both B6's smaller base-L subtotal and B7's larger leakage-free payload are
conditional estimates. B7's COPE payload alone is 188,928 bytes for 32
outputs, or 126,812,160 for the 27,511-output k0/t0 screen, before real OT,
checks, framing and lifecycle. Complete setup, capacity, certificate, work,
memory and physical traffic retain admission bound infinity. The existing
MAC/transfer lemmas require valid inputs and do not discharge this bootstrap.

The evaluated baseline is closed with this negative result. B8 is the
separately owner-directed replacement line below, not a revision of B7's result.

## B8 construction decision

The [single budget](../scripts/c7_1_gemma_plan.py) now adds
`B8_bootstrap_selection`. MR19 Figure 8 with receiver first uses Appendix
E.1's UC simulator, not the stand-alone theorem or the one-round variant.
Figure 4/Lemma 3.4 supplies sender-chosen seeds even when a malicious
receiver biases its endemic OT pad. Wolverine Figure 15/Lemma 3 then
realizes COPEe, followed by Figure 5/Theorem 2's Fp9 check and leakage
removal into Fp3. No new OT primitive, trusted setup or observable global
oracle is selected. Goldilocks and the Fp3 MAC remain the reference.

The proposed auxiliary OT group is P-521, with 576 independent instances;
the source's UC loss in adversarial queries is charged explicitly. The
conditional bootstrap error is below `2^-82` only under the stated DDH/PRF
advantage and reduction-resource premises. Those concrete primitive
advantages are not established for a runtime: there is no numerical
security credit, and the complete C7.1 lifetime theorem stays open.

Successful bootstrap wire is **383,065 bytes for 32 base rows** and
**128,984,785 bytes for the 27,511-row k0/t0 screen**, including OT,
nine mask rows, explicit Fp9 challenges, compression, headers and frames.
These are exact sizes of the specified construction, not measurements or
secure LPN parameter selection. Authenticated transport, durable lifecycle,
complete native work/memory/traffic and subsequent PCG remain unpriced.
Connection setup is distinct from the response-certificate alarm.

Four [B8 reference/algebra checks](../tests/test_c71_bootstrap.py) and the
ten prior budget checks pass. They cover P-521 point/codec equations and
both OT choices, exhaustive chosen-message simulation, ideal COPE/Fp9
algebra and mask coverage, conditional arithmetic and preserved B7 stop.
No native build, new Lean theorem, benchmark record, matrix/Gemma proof
or hardware measurement is claimed.

B9 below supplies the bounded native component and checks. Concrete
primitive accounting and lifecycle/PCG composition still precede integration.
B4 masked-RS, same-W/FS lifetime and the complete
physical schedule/certificate remain independent unresolved obligations.


## B9 native component and disposition

The opt-in [`c71-bootstrap`](../rust/volta-pcg/src/c71_bootstrap.rs) feature
has independent roles and no production pool adapter. The
[bounded runner](../scripts/run_c71_bootstrap.py) uses disposable OS-random
secrets and two local Unix endpoints, within 60 s / 2 GiB / two threads.
It checks every base row and native Fp3 packing; the five focused Rust
checks include both OT choices, independent Python curve/hash vectors,
all mask coordinates, malicious point branches and zero-key abort before
the compression frame. Ten endpoint mutations reject at the expected
boundary. Earlier dirty diagnostics and the sandbox socketpair failure
are preserved separately. Clean-source records at `fb6c787` pass:
[3 base rows](../benchmarks/results/c71-b9-3-none-20260909-fb6c787.json),
[32 base rows](../benchmarks/results/c71-b9-32-none-20260909-fb6c787.json)
and all ten adversarial cases listed by the single budget. The 32-row case
uses **3.284 s wall**, **3,362,816 bytes sampled peak RSS** and
**1,153,827 bytes peak requested heap**, including the diagnostic framing
and checks. Five focused Rust and sixteen Python checks pass.

The successful wire remains **247,345 bytes for 3 base rows** and
**383,065 for 32**, with all nine frames. B9 processes both receiver DH/KDF
branches and balances both final public group-hash inputs: native calls
are 2,304 each for fixed/variable scalar multiplication, group hash and
KDF, versus the narrower B8 algebra count. Scalar/Fp samplers consume all
eight candidates. The runner checks actual call counters, both wire views,
allocator balance, RSS and phase elapsed times including waits.

These are component results. Algebra/source checks do not establish the
concrete DDH/PRF advantages, generated-code side-channel behavior, complete
secret-copy erasure, durable burns, authenticated transport or AES expansion
composition. Complete work/physical traffic and connection costs retain
unknown admission bounds. Existing Lean MAC linearity assumes valid inputs;
no new Lean theorem or complete C7.1 security/performance credit follows.
The single budget includes `B9_bootstrap_component`; B10 below concludes
the following assessment, retaining the previous negative decisions and evidence.

## B10 premise assessment and same-W contract

The [single budget](../scripts/c7_1_gemma_plan.py) adds
`B10_composition_admission`. At n=27,511, each COPE key serves 27,520
messages and 1,761,280 XOF bytes. These are source counts, not wire, RSS,
DRAM or measured timing. B8's sum remains conditional on primitive
advantages at explicit reduction resources; Q64 alone supplies no
offline-work or memory/advice bound.

The design derives the GGM seed-search lower bound stated above and
delimits its standalone PRG scope. A different construction or a
protocol-specific game needs its own concrete argument; no large search
or E2E attack was executed.

The source audit also identifies un-erased keyed BLAKE3 state in B9 and
secret-indexed S-box access in portable AES. Field conditions and complete
generated-code behavior remain unaudited. The old expansion still uses
B7 OT seeds for COPE/IKNP, Fp2 pools and the old consistency/equality path.
B9 outputs alone do not replace these prerequisites. No native change or
new build is claimed.

The contract pins **one W across all proofs, sessions, key epochs and root
renewals**, with the PCS endpoint and GKR consuming the same MAC value.
It specifies the sign map `Delta_native=-Delta_B9`, disjoint base packing,
fresh-key epochs, durable setup/stage/proof burns, separate global quotas,
quarantine, accepted-state updates and conservative crash recovery. Existing
stores/leases are reusable pieces, not an implemented joint B9 lifecycle.
G2 contributes NoPeek/fresh-mask simulation and the distinction between a
valid MAC and binding to W; its archived construction stays unselected.

All twenty bootstrap/budget Python checks pass, including four new B10
checks. They cover arithmetic and ideal-model counterexamples, without
claiming a runtime lifecycle or complete same-W/FS theorem. Complete
connection/PCG, work and physical resource costs stay unknown. B11 below
assesses local repairs; integration, PCS tuning, E2E and hardware remain closed.

## B11 intermediate selection and component boundary

The local-repair rejection is preserved: domain separation and renewal
cannot cure the 128-bit seed-space bound, even for a single observed output.
The owner's subsequent authorization selects a finite construction with
32-byte secret AES node keys inside COPE. Original B9 remains available
under its original suite; cross-suite contexts fail before OT. The selected
component needs no silent extension or LPN assumption.

The global adversary model and concrete reduction envelope are now explicit,
including preprocessing, advice and simulators. A depth-eight forest has
at most `1152*255*2^20` internal nodes. The conditional lifetime sum includes
AES PRP, switching, leaf guesses/collisions, MR19/DDH, nonce collisions,
sampler failures and the leakage-free base check/compression. It is below
`2^-82`, with the concrete AES/P-521 hypotheses still assumptions. This
selects the intermediate contract; full runtime/security admission remains
false. The separately specified silent candidate is not selected.

Native tests cover independent OpenSSL/SHAKE vectors, the row/suite boundary,
zero-key rejection and the preserved B9/B7 checks. The diagnostic packs
three disjoint rows per Fp3 and calls the existing native MAC transfer with
`Delta_native=-Delta_B11`; altered values must fail in all three coordinates.
All twelve OS-random B11 cases pass at clean source `8197f42`: n=180/207
(60/69 Fp3) and ten rejected adversarial byte cases at n=3. The measured
protocol wire is exactly 1,075,705/1,202,065 bytes. Complete two-role process
times are 4.733/5.056 s on this local opt-level-2 diagnostic, with sampled
peak RSS 5,447,680/5,857,280 bytes. These include diagnostic checks and are
neither Gemma prover times nor full-connection/PCS or physical-traffic costs.
The [B11 evidence in the design](c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita)
links the two capacities and preserves the initial socketpair-denied result
alongside its successful B9 compatibility rerun. The single budget pins all
twelve B11 records; 26 Python and eight narrow Rust tests pass.

Same-W remains a global quantifier over all accepted proofs. A renewed root
must be linked to the installed W before activation; locally valid MACs
under fresh keys do not prove that relation. B12 implements B10's joint durable
reservation for the fixed-root component; NoPeek and the full consumer remain
obligations. SHAKE-state
erasure and generated-code timing checks also remain open for production.

B12 is active under the latest owner request; its component results and
remaining same-W/PCS/GKR obligations are recorded at the top of this page.
B11 supplies no security credit for the stopped B7/G2 lines or a full runner.

## G2 residual changes: integrated evidence, archived research line

The owner's follow-up asks to resolve the previously uncommitted G2 work.
The patch adds three mathematical checks, with no runtime, OT or pool code:
query sampling can miss a corrupted RS column; exhaustive columns detect
the syndrome in a small row-fold fixture; a synthetic A5 root can differ
while sampled columns agree. They remain valid after B7–B9 because none
assumes the rejected OT or claims real hash/PCS security. They are now
integrated in the existing [algebra tests](../tests/test_c7_1_gemma_plan.py).
The literal A5 size arithmetic is explicitly historical, and 35 MB remains
an alarm. The three focused checks pass.

**G2 is archived as an unselected research line, not queued for completion.**
Its unproved same-W/FS obligations remain requirements of the active design;
archiving does not prove them or assert impossibility. The
[G2 dossier](c7.1-committed-mac-opening.md) retains conditional results with
an explicit historical scope. There is no pending G2 patch, alternate
runtime or second active goal. The single budget records this disposition;
B10 and the conditional intermediate B11 selection are complete; B12 is
the active goal; bounded B11 component validation remains complete.

## Documentation decision

Status and design are the only active summaries; the existing index routes
to evidence. This reset removes duplicated progress prose, not source
material or research results. No new C7.1 Markdown dossier is needed.
A fresh conversation can start from this page and design §10 (B12's remaining
same-W/lifetime obligations, B11 selection and the preserved B7 failure) without
importing the full G2 transcript or treating archived research as active work.

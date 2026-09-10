# Current status — C7.1 Gemma-31B, B12 fixed-run goal active

Updated 2026-09-10. Editable working summary; Git preserves revisions.
[Design](c7.1-gemma31b-design.md) · [Documentation index](README.md) ·
[Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

**B12 is authorized and remains open.** The owner's latest 2026-09-09 request
keeps adversary resources beyond `2^78`, one private W across the entire
Gemma inference and both complete errors at most `2^-78`, while **deferring
renewal, abort recovery and restart composition**. The prototype covers one
uninterrupted sequential run with one model root, key epoch and initial
finite capacity. Error, abort or exhaustion ends the run. Queries to discarded
FS candidates still count, and views up to termination must remain private.
Response count must fit the declared root/correlation capacity; there is no
requirement to complete the old 2^20-attempt lifecycle.
[The fixed-run matrix composition](c7.1-gemma31b-design.md#b12-zk-del-consumer-claimless-nel-run-continuo)
now gives **conditional soundness and malicious-verifier ZK**: about
91.0166 and 91.0227 bits, respectively, at n=48/128 with three total
attempts. Soundness connects the matrix sumcheck, PCS and MAC to one
extracted W; ZK uses a dummy zero-model simulator with the corrupt role's
Delta/keys and a joint mask-translation proof. Both reductions count the
caller and RO tapes within T121/M93, for adversary work/memory 2^80 and
global Q64. AES/DDH advantages at that envelope remain explicit hypotheses.
This covers a field matrix from fresh model installation, not all of Gemma
or simulation for an arbitrary externally fixed root. The earlier 86.8347-bit
soundness argument with broader setup/reopen scope remains valid evidence.

The [finite-pool component](../rust/volta-pcg/src/c71_lifetime.rs) now also
supports one larger initial AES capacity: up to 16,777,206 base rows under
one key, with a conditional bootstrap bound of 91.022717 bits at T121/M93.
The fixed-run profile records its mode before setup and rejects renewal,
continuation after failure and reopen. Setup and joint root-slot/row burns
precede use; the fresh 40-byte post-bootstrap seal fixes row assignment
before usable FS prefixes. COPE streams through a 4,608-byte buffer while
retaining the full frame before the challenge. A 258-row real check crosses
B11's old cap. [Capacity and exact costs](c7.1-gemma31b-design.md#b12-capacità-aes-iniziale-per-il-run-continuo)
include 506.6 MB of setup wire for P0 plus the bridge; smaller buffering
does not remove that cost. The existing crash/reopen evidence for the old
profile remains intact, without creating recovery requirements.

The [PCS analysis](c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata)
proves same-set MCA when 3*radius < distance and fixes the Merkle oracle at
its commitment prefix, charging collisions and deferred preimages. Native
B12 uses one XOF tape between free prover messages, retained across openings
already determined by commitments. Merged-round errors are summed; independent
mask-query groups have a separate bound. A direct scalar-relation proof now
covers the actual native covectors and claimless endpoint. The soundness
tester decodes the installed root once, then checks every accepted public
output against that same padded field matrix. W remains private in the runtime.

The opt-in [salted consumer](../rust/volta-pcs/src/c71_matrix/b12.rs) uses
common-mask unique-radius codes and fresh private salt streams. The earlier native
checks cover FS blocks, geometry, private coins, salting and real B11 roles:
two valid proofs, then a rejected salt alteration whose burn survives reopen.
The new [linear-form bridge](../rust/volta-pcs/src/c71_matrix/linear.rs)
combines the caller's original target MACs and closes one PCS against the
installed root. A real-B11 small case covers matrix, ragged norm and shared
embedding/logits, then rejects a freshly authenticated false norm target and
terminates the run; the same check also passes with the new fixed-run AES
profile. It is an internal component without a standalone codec.
The public-layout compiler maps all 773 P0 endpoints to the same 772 physical
tensors (3,606 cubes), including all 150 lookup rows in one target. It does
not yet connect the actual Gemma GKR execution.
[Design: bridge and capacity](c7.1-gemma31b-design.md#b12-ponte-nativo-dai-mac-originali-a-ununica-root-w).

The new [range caller](../rust/volta-pcs/src/c71_matrix/range.rs) authenticates
a private histogram, proves a fraction tree and derives the original W(r)
MAC from its denominator leaf. That target and a zero-padding form share
one PCS. Native checks accept the symmetric i16 endpoints, reject -32768,
nonzero padding and detached MACs; a 1,746-row real AES run rejects a false
range on its second attempt and terminates. The mathematical caller also
has a NoPeek/QuickSilver simulator. At D12/D14 its composed conditional
soundness/ZK remain about 91 bits. D35 gives 82.9944 soundness bits within
T121/M93, as an analytic geometry only. The joint raw-P0 analysis below
also extends its private-sampler ZK bound; the physical schedule remains excluded.
P0 + range + one bridge needs
312,693 base rows before P0's shared product mask; the complete Gemma census remains open.
[Proof and exact counts](c7.1-gemma31b-design.md#b12-range-simmetrico-e-padding-nello-stesso-mac-della-root).

The [native P0 caller](../rust/volta-pcs/src/c71_matrix/p0.rs) now runs the
quadratic matrix and cubic weighted-product reductions, returning original
C/X/W MAC obligations. A small check executes matrix, weighted norm product
and lookup, closes one ranged W PCS and one private auxiliary C/X PCS,
and rejects a false committed cut or detached input MAC. The auxiliary
root is an additional source with its own costs, now included by the raw-P0
composition below. Adding P0's product mask brings the known subtotal
to 312,696 base rows before auxiliary openings and other Gemma operators.
The [native layout compiler](../rust/volta-pcs/src/c71_matrix/gemma.rs)
now maps the validated DAG's 39,421 weighted invocations into those 773
cohorts and 3,156 W tiles. It preserves terminal-packed file offsets while
using metadata order for the virtual root, and generates the 3,606 native
forms. Its [DAG caller](../rust/volta-pcs/src/c71_matrix/gemma/caller.rs)
now generates all output points after the fixed sources/profile/tokens,
executes P0 and compiles the original C/X claims into one auxiliary layout:
1,375 sources, 1,545 forms and 14,909 cubes. Head rows 99–148 and norm
head reshaping follow the DAG. A tiny executed raw graph closes both PCS
and rejects a wrong row selection; the full 773-cohort zero-vector check
uses no full weights or Gemma forward.
[Caller contract and limits](c7.1-gemma31b-design.md#b12-p0-nativo-e-aperture-originali-dei-tagli).

The [two-source raw-P0 composition](c7.1-gemma31b-design.md#b12-composizione-raw-p0-a-due-sorgenti)
now counts one W installation and three fresh auxiliary roots, including
cross-source hiding collisions and finite private streams. Its D35/D31
analytic profile has conditional soundness/ZK of 82.9944/91.0227 bits
within T121/M93. The known subtotal is 312,981 base rows per attempt,
938,943 for three attempts, before other operators. This proves the raw
P0 relation to the ranged W, not the quantized producers of X/C. The
full auxiliary materialization is excluded: packed cut/input bodies alone
use 6,525,586,944 bytes, exceeding the reference arena. Both dense PCS
sources and the fraction tree remain physically excluded.

The [byte bridge](../rust/volta-pcs/src/c71_matrix/gemma/bytes.rs) now
pulls those original scalar MACs into the biased i48/i32/i16 byte layout,
using public affine shifts only. The same range caller checks the exact
unsigned alphabet 0–255. Its D35/D33 raw-P0 composition includes byte
range and both PCS: 320,808 base rows per attempt, 962,424 for three,
with the same conditional 82.9944/91.0227-bit bounds. The new native
checks reject −1/256 and incorrect bias, including signed extrema and
ragged axes. The auxiliary codeword is 1 TiB and remains excluded.
Byte validity does not prove RNE or the symmetric i16 output restriction.

The [public byte-function caller](../rust/volta-pcs/src/c71_matrix/byte_function.rs)
reuses the range GKR kernel for R2's P/S interpolation. Original function
MACs reduce to an original byte MAC for the same auxiliary PCS, without a
bit or trace commitment. Its 809-row ideal check rejects a false function
and a consistent function of bytes changed after commitment. The native
view cap is D10; the canonical full-DAG caller remains open.

The [native RNE top](../rust/volta-pcs/src/c71_matrix/rne.rs) now proves
one public shift class from original biased-i48 byte MACs to an original
output MAC, including symmetric-i16 overflow rejection. Its degree-seven
recipe reuses R2 and sends its byte functions to the same P/S/PCS.
The 951-row ideal check rejects wrong output, both ±32768 overflows and
changed raw bytes that preserve the rounded output. All 64 shift recipes
and their degree are checked. A complete batch of incoming claims,
calibrated shifts and the remaining operators are still required.
The 411 canonical matrix-byte views now compile to 7,126 cubes. A new
1,355-row ideal graph ties a norm P0's original input MAC directly to RNE
of the preceding matrix's original cut, with the same ranged W and byte A.
It covers ragged row/column padding and rejects inconsistent quantization
or a changed raw getter. It does not prove the norm's RMS denominator.
The native request compiler selects all 240 direct q/k/o/down-projection
inputs of weighted P0 norms, retaining their original MACs and points.
Their [conditional composition](c7.1-gemma31b-design.md#b12-composizione-raw-p0-a-due-sorgenti)
with byte-P0/range/both PCS gives about 82.99443/91.02272 bits within
T121/M93. The known upper is 1,165,368 base rows per attempt, 3,496,104
for three, before other operators. This requires the fixed public shifts
and prescribed dispatch; full calibrated-profile/native execution is open.

The [RMS kernels](../rust/volta-pcs/src/c71_matrix/rms/gkr.rs) and
[canonical dispatcher](../rust/volta-pcs/src/c71_matrix/gemma/rms/caller.rs)
now connect P=X*W, S=sum X² and exact integer RMS to the original W/A
MACs. The [source compiler](../rust/volta-pcs/src/c71_matrix/gemma/rms.rs)
maps all 421 norms, reusing consumer Y and ten global pre-norm K/V aliases.
It adds 50 local V inputs, 300 Y and 421 S sources: 2,146 total sources,
7,091,219,838 bytes, still D33. All 50 local V RNE requests retain the
statistic's original X MAC and point; the known A batch has 3,101 targets
and at most 48,026 cubes, below the 65,536 guard.
A 10,003-row ideal graph closes canonical P0/RMS and three RNE through
the same two ranged PCS. It also binds original embedding-input MACs
directly to W. Altered V with consistent S/Y fails RNE; altered weights
with consistent P/Y fail the installed W PCS. Full metadata checks cover
all source routes without allocating weight bodies or the large circuits.

The [conditional P0/RNE/RMS composition](c7.1-gemma31b-design.md#b12-composizione-raw-p0-a-due-sorgenti)
now covers 290 original matrix-to-i16 RNE tables and all 421 exact norms,
under an explicit public compiler envelope: 128-bit arithmetic, H≤128,
width≤2^14 and ≤2,000,000 public rows per profile. It retains about
**82.99442 soundness / 91.02272 ZK bits** within T121/M93, with the same
primitive hypotheses and global Q*. The known upper is **1,527,909 base
rows per attempt, 4,583,727 for three**, before other Gemma operators.
This is parametric in valid public profiles; actual calibrated parameters,
full-domain execution and the remaining producer relations are still open.
The enormous dense-trace resource upper grants no physical schedule credit;
full A materialization also still exceeds the reference arena.

The [native public lookup](../rust/volta-pcs/src/c71_matrix/lookup.rs) now
reuses the fraction GKR with original X/Y/histogram MACs. Its 600-row
ideal check uses two certified small GELU tables and one ranged A PCS:
wrong output and overflow fail GKR; input and histogram changed together
fail the original PCS. Histograms must be committed before alpha, and
overflow tags cannot equal valid query tags. Public query/table blocks
may interleave; every table row must be covered exactly once.
The [canonical GELU sources](../rust/volta-pcs/src/c71_matrix/gemma/gelu.rs)
now add 60 X, 60 Y and 60 histograms while preserving all P0/RMS IDs.
A has 2,326 sources / 7,881,092,238 bytes, still D33. The three original
lookup forms use 720/720/960 cubes across 1,680 public word blocks.
The canonical dispatcher now binds full certified public tables and the
60 gate RNE pairs before their probes. Both original X probes and raw-byte
MACs close in the same A as lookup X/Y/M, for 3,224 known targets and
52,586 cubes. A 1,356-row ideal P0/table-RNE graph closes both ranged PCS
and rejects changed raw bytes even when the rounded output is unchanged.
The small canonical GELU/one-gate-RNE dispatch uses 1,158 ideal rows;
that larger source-view check has placeholder roots and grants no PCS acceptance.

The conditional `P0_RNE_RMS_GELU_composition` includes 350 matrix RNE
tables, 421 RMS/statistics and all 60 GELU relations. Given certified
public tables and consistent shifts fixed before roots, it retains
**82.98619 soundness / 91.02272 ZK bits** within T121/M93. The known
upper is **1,760,571 base rows per attempt, 5,281,713 for three**.
Reads and hashing of supplied public tables are counted; numerical
profile preparation/calibration remain outside this partial subtotal.
The next subtotal below adds gate-up; other operators and full-domain
execution remain open.

The [gate-up caller](../rust/volta-pcs/src/c71_matrix/gemma/gate_up.rs)
reuses cubic P0 for one joint product over all 60 layers. It preserves
original GELU Y, quantized U, raw R and down-P0 input MACs. Its 1,372-row
ideal check closes product and both RNE with one ranged A PCS, rejecting
wrong product and an operand swap with a consistently changed up raw.
The canonical route check also compares original forms with literal bytes;
its placeholder roots grant no PCS acceptance.
The added 60 U and 60 i48 raw sources make A **9,429,380,238 bytes / D34**,
with 3,407 known targets and ≤59,067 cubes. The conditional subtotal rebases
both-source PCS/range, joint hiding, samplers and decoders at D35/D34:
**82.98618 soundness / 91.02272 ZK bits**, **6,648,624 base rows for three**,
under the same public-profile and primitive hypotheses. The auxiliary
codeword is now 2 TiB; its dense implementation remains excluded.

The [joint raw RoPE kernel](../rust/volta-pcs/src/c71_matrix/rope.rs)
reuses the existing public-linear sumcheck and returns two original R/Y
MACs for the same A. Its 559-row ideal case closes a ranged source PCS,
rejecting a wrong raw and a consistently changed input/raw pair. Public
adjoint checks cover dyadic blocks, absolute positions, full half-head
pairing and inactive pairs. The full D27 arithmetic is 83 Fp3 before
RNE/source closures. The [canonical RoPE source compiler](../rust/volta-pcs/src/c71_matrix/gemma/rope.rs)
now maps all 120 routes to the original q_norm/k_norm Y, with 480 joint
blocks and 120 raw/output RNE pairs. A has 2,686 sources / 10,387,844,238
bytes, still D34; the known batch has 3,649 targets and ≤61,947 cubes.
The conditional subtotal now includes these producers and retains
**82.98618 soundness / 91.02272 ZK bits**, using **7,906,491 base rows for
three attempts**. Q30 tables and consistent public shifts are premises;
numerical profile preparation/calibration and full native execution remain open.

The [raw QK/PV kernels](../rust/volta-pcs/src/c71_matrix/attention.rs)
now use the exact eager rectangles and quotient GQA mapping. PV discharges
its original contracted M through an explicit link to the original Pi;
Pi and V may have different key points. Their 571/572-row ideal checks
close one ranged A PCS and reject changed operands with consistent raw
outputs, wrong GQA/padding and a detached M. The arithmetic is 13,020 Fp3
for 60 QK/PV pairs at O=0/T=150, before integer/source/KV closures.
The [canonical fresh attention sources](../rust/volta-pcs/src/c71_matrix/gemma/attention.rs)
now reuse RoPE Q/K, RMS V and the original o-P0 input. Score probes and
both RNE routes keep the original MACs, bringing A to 2,926 sources /
11,641,220,238 bytes, still D34. The known batch has 4,189 targets and
65,067 cubes; the target guard is now 8,192 with the same cube/domain caps.
The conditional subtotal including fresh QK/PV and both RNE retains
**82.98617 soundness / 91.02272 ZK bits**, with **9,305,451 base rows for
three attempts**. The fourteen Gemma checks cover the canonical routes;
full-domain execution, mask/softmax and ordinary accepted KV continuation
remain open. Deferred recovery/restart composition does not remove KV history.

The [affine zero-form bridge](../rust/volta-pcs/src/c71_matrix/gemma/bytes/affine.rs)
now proves public linear raw identities as a known-bias target in the same
PCS, with no new private MAC. Its 991-row ideal affine/RNE/range/PCS case
rejects a false raw preserving RNE, a detached input and wrong output.
The [canonical residual compiler](../rust/volta-pcs/src/c71_matrix/gemma/residual.rs)
routes all 120 residual sums and 61 public scales through original
embedding/RMS/stream sources and 181 whole-table RNE. The exact public
BF16 scalars are reused; residual exponent alignment is limited to 30.
A now has 3,167 sources / 12,613,738,638 bytes, still D34, with 4,552 targets
and 79,539 cubes. The cube guard is 131,072; the domain cap stays D14.
The conditional subtotal retains **82.98616 soundness / 91.02272 ZK bits**,
with **11,234,187 base rows for three attempts**, given the same fixed
public quantization profile and alignment envelope. The sixteen Gemma
checks cover the new source routes, not a calibrated full-model execution.

Forty B12 algebra/accounting checks include the scalar invariant,
decoder, adaptive Merkle/RS simulation, claimless mask translation and
range/product identities and the joint two-source bounds. The relevant Python checks total 221; the 17
narrow bootstrap/pool checks and forty B12 PCS/caller/layout checks pass.
Native legacy replay and fork provenance remain valid. These are component
checks and mathematical arguments, not new Lean or generated-code proofs.
The CPU cap remains D14/n<=128. The D35 analytic profile retains about 88
PCS-only bits, but its 4 TiB initial codeword remains physically excluded.

Privacy remains separate. Unsalted B2 roots permit candidate-W reconstruction
after mask exhaustion; its ideal n=128 event is about 2^-24.0445, not a
measured native FS attack. B12 now has a bounded-query adaptive hiding
argument for salted Merkle roots and paths, including private coins:
159.15/158.68 bits for the two native geometries and 146.68 for the
excluded D35 geometry. The initial RS rows remain private at all 1,536
permitted adaptive queries. The matrix ZK argument now includes the
correlated claimless messages, the final private shift, finite samplers
and global zero-OOD event. Its simulator preserves the native FS; a check
with DV secrets verifies the complete dummy-model certificate. Acceptance
alone is not the ZK argument. The full Gemma caller still needs its own
NoPeek, relation and resource composition.

**Remaining work:** full Gemma malicious-verifier ZK, the complete quantized
Gemma GKR relation using the range-checked W, full correlation census and
both-role resource composition for the fixed run. The known 11,234,187-row upper
for three byte-backed P0/RNE/RMS/GELU/gate-up/RoPE/fresh-attention/residual attempts fits the initial capacity;
mask/softmax, ordinary KV, public output and other circuits remain uncounted.
The D35 dense PCS and fraction tree remain physically excluded. The earlier 86.8347-bit
soundness bound also included failed setups/key changes; that broader
evidence remains valid without making renewal/recovery new gates. Neither
matrix result yet binds the root to all weights used by the
complete Gemma inference. Both complete security totals stay unknown, and
the six prototype error allocations remain targets. No complete 78-bit or
production credit.

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

**Fundamental requirements:** fixed-run soundness and zero knowledge of at
least 78 bits against malicious prover and malicious verifier. Keep private
weights, same-W/VOLE-MAC boundaries, noninteractive FS, classical ROM,
global Q64 and a finite declared response bound within the installed capacity.
Renewal, abort recovery and restart composition are deferred. Do not replace complete security with a
component parameter, honest-verifier privacy or an assumed conclusion.
Goldilocks/DV remain the working choices; the owner wants them definitive
if they deliver a real prover-time advantage, not merely a literature analogy.

**Costs:** 35 MB complete proof and 50 s warm complete prover are alarm
thresholds, not reasons to weaken security or endlessly redesign a component.
The reference remains four proof reads, no spill, the existing memory/setup
budgets and the pinned 100+50 workload. The comparison may price explicit
alternatives, including a fifth read or organized host spill; it must not
claim they meet the reference. Scope and remaining thresholds are in design §1.

**Current authorization:** B12's local reduction, same-W full Gemma PCS/GKR,
malicious-verifier ZK and fixed-run error composition are authorized by the latest
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

# Build, test and generated artifacts

Read [current status](../prototype-status.md) first. This procedure explains
how to run authorized work; it does not authorize a heavy build or E2E.

## Choose the check

Start with the narrowest relevant check. For C7.1 arithmetic/accounting:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_baseline_budget.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c71_bootstrap.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c7_1_gemma_plan.py
```

Python scripts use the repository `.venv`; `pytest` is the global uv tool.
Use the script/report named by the active design. Historical budget scripts
are reference diagnostics when their specific assumptions are needed.
Documentation changes need link, consistency and diff checks, not Rust/Lean
builds. Existing passing checks need repeating only after relevant changes.

## Rust and resource limits

Rust is installed through rustup. All Cargo commands, including standalone
third-party manifests, share the absolute repository `rust/target`:

```bash
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$(git rev-parse --show-toplevel)/rust/target"
export CARGO_INCREMENTAL=0
cd rust
cargo test --workspace
```

This is the broad workspace command, not the default check for every task.
For the authorized B9 component, run from `rust` with the same absolute
target and `CARGO_INCREMENTAL=0`:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test --offline --locked -j 2 -p volta-pcg --features c71-bootstrap c71_b9 -- --test-threads=1
```

From the repository root, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
scripts/run_c71_bootstrap.py --n 3` runs one OS-random two-role component
case; `--n 32` is the other registered size and `--fault` selects a bounded
adversarial case. It reuses the existing 60 s / 2 GiB / two-thread launcher,
uses only local Unix socketpairs and preserves failures. The script builds
only the `volta-pcg` example at opt-level 2, with no separate Cargo target.
This is not the stopped B7 matrix runner or a full Gemma E2E. The source
tree must be clean for a run of record; a detached temporary worktree can
preserve unrelated edits while sharing the canonical target.

For the owner-authorized B11 intermediate component, the same runner accepts
`--suite b11 --n 180` or `--n 207`, and `--suite b11 --n 3 --fault ...` for
the ten byte faults. It builds only the example with `c71-b11`, including
the existing MAC consumer diagnostic. Limits remain 60 s / 2 GiB / two
threads. Run the narrow native tests using the command above with
`--features c71-b11 c71_b`; this also retains the B7 negative and B9 checks.
The Python bootstrap/budget checks cover the conditional lifetime arithmetic.
These are component checks, with no durable-pool or PCS/Gemma admission.

For the owner-authorized B12 finite-pool component, the same narrow Cargo
command with `--features c71-b11 c71_b12 -- --test-threads=1` checks the
durable journal, completion-seal framing, subprocess crash/reopen and real
two-role MAC transfers. The new fixed-run profile is exercised at 258 base
rows with small IO operations; four AES path vectors cover larger domains
without allocating their capacities. Failure checks reject continuation,
downgrade and reopen. Do not run the 108,201-row or maximum-capacity cases
locally: their diagnostic entries are arithmetic only.
The real role checks need only a local Unix socketpair, as B9/B11 did;
if the sandbox denies it, permit that local test without external access.
No full workspace, matrix/Gemma runner or paid hardware is needed. These
are component tests, not run-of-record benchmarks or complete security evidence.

For the B12 salted PCS consumer, build only `volta-pcs` with the same Cargo
target and profile, `--features c71-b12-pcs --lib`, and run the narrow filters
below with one test thread. After compilation, bound each test invocation
to 60 s and 2 GiB, with `RAYON_NUM_THREADS=1`. Its forty-nine tests cover FS coin-block replay, unique-radius geometry (D35 configuration only), private
coin streams, salted Merkle/codec and three attempts of a 48×48 synthetic matrix using the real
180-row B11 roles and durable journal. The linear-form checks cover aligned
cubes and a 207-row real-B11 capacity: four original target MACs reach one
root/PCS, then a fresh false norm target is rejected and the run ends.
The same check also exercises the new single-setup AES profile, including
continuation after acceptance and termination after rejection.
The ideal-MAC simulator check uses only DV keys, public IO and a dummy
zero-weight PCS; it needs no socket or bootstrap and verifies the complete
certificate. Its acceptance check complements the mathematical ZK argument.
The range checks cover the full symmetric i16 table with ideal MACs, native
QuickSilver signs and a real fixed pool of 1,746 base rows. The latter
accepts [-3,3], rejects a false [-1,1] claim under the same root and ends
the run. These are small D10 cases, not a full Gemma range execution.
Run the `c71_b12_range` and `c71_b12_product_batch` filters separately
from the earlier PCS checks to keep each invocation below 60 seconds.
The `c71_b12_p0` filter executes a small raw matrix/norm/lookup caller
with 357 ideal Fp3 correlations, one ranged W PCS and a separate C/X PCS.
It checks committed false cuts and detached input MACs; no socket is needed.
The twenty-one `c71_b12_gemma` checks cover native metadata/DAG layout and
physical/virtual addresses, including ragged tensor MLEs. The caller check
executes all 773 compact reductions with zero vectors and compiles the
original auxiliary forms; its placeholder roots grant no PCS acceptance.
A tiny actual raw graph uses 365 ideal Fp3 rows, a ranged W PCS and one
canonical auxiliary PCS, rejecting wrong head selection and proof assignment.
These checks read no full weight bodies and perform no Gemma inference
or D35/D31 PCS allocation; no socket is needed.
Run the two `c71_b12_softmax` checks separately. The selected EXP30 path
uses 8,096 ideal Fp3 rows with byte range and one shared A PCS; six faults
cover maximum, lookup, denominator, ratio, detached score and forbidden Pi.
Its kernel uses 2,360 FS draws; total PCS draws vary with public sampler
retries. Metadata cover all three canonical KV contexts and original source
forms; no full Gemma body is allocated. The wide lookup preserves legacy
i16 framing; rerun `c71_b12_lookup` and affected Gemma callers after edits.
The byte bridge checks biased i48/i32/i16 source forms, signed extrema,
physical byte addresses and incorrect affine shifts with 551 ideal Fp3
rows and one ranged byte PCS. The `c71_b12_range_bytes` filter separately
covers every unsigned byte and rejects −1/256 in 542 ideal rows. The
full D33 byte-source geometry remains arithmetic only; no allocation/run.
The `c71_b12_byte_functions` check uses 809 ideal Fp3 rows for public
byte functions, range and one shared PCS. It rejects an incorrect function
at GKR and a consistent function of altered bytes at the original PCS.
After changes to the shared fraction-tree kernel, also rerun the existing
range byte/i16, product and P0/Gemma checks in separate bounded invocations.
The `c71_b12_rne` filter checks all 64 RNE recipes, degree seven and an
executed 951-row ideal case with one ranged auxiliary PCS. It rejects
wrong output, ±32768 overflow and a different raw source with the same
rounded output. This is a single public shift with c<=7 cell bits, not
the full calibrated Gemma RNE caller or a new hardware measurement.
The new `c71_b12_gemma_p0_rne` case uses 1,355 ideal rows and both
ranged PCS. It passes the norm P0's original X MAC to RNE of the preceding
matrix cut, with canonical ragged byte forms; wrong quantization or a raw
getter changed after commitment rejects. The norm remains a raw weighted
product, with no RMS denominator or full Gemma credit.
The full layout check also compiles all 240 direct P0-to-RNE requests
(q/k/o/down projections), checks their original MAC/point identities and
3,840 byte cubes. Only the tiny graph executes RNE; the full-domain
composition and correlation upper remain analytic.
The `c71_b12_rms` filter checks the public exact integer compiler against
five existing Boolean-reference profiles, plus joint authenticated GKR on
weighted/unweighted cells and dummy padding. The 7,299-row ideal case
reduces its ORIGINAL input-bit sum through byte P/S into one ranged PCS.
It rejects wrong Y and changed S preserving the same Y. There is no bit
reauthentication or trace PCS. This proves the RMS predicate on committed
P/S/Y bytes, before the canonical P0/statistic/output source routes;
full calibrated Gemma profiles and the complete composition remain open.
The two `c71_b12_ratio` checks reuse the RMS builder for exact signed
RNE(2^m*P/Z), m=0..14, including ties, overflow and positive-denominator
guards. The 7,164-row ideal case closes the original numerator,
denominator and output through byte P/S, range and one PCS; a changed
numerator preserving Y still rejects. After this shared builder refactor,
also run `c71_b12_rms` separately to retain its exact circuit counts.
The ratio component does not by itself prove the selected EXP30 producer
or execute full-domain normalization.
The `c71_b12_rms_statistic` case uses 7,761 ideal rows for weighted P0,
S=sum X², joint exact RMS and both ranged PCS. One S word per row is
broadcast through the same byte view. A changed statistic preserving Y
fails the square relation; a changed weight getter with consistent P/Y
fails the original W PCS. Full 421-cohort Gemma execution remains open.
The `c71_b12_gemma_rms` check compiles all 421 canonical RMS source
routes, including ten global pre-norm K/V aliases. A literal small byte
view checks head reshape, S broadcast, reused Y and the final selected
rows. It also counts the D33 extension and its 48,026-cube known batch including 50 local V RNE;
no full source body or RMS trace is allocated. The 131,072 public-cube
guard does not change the native D14 source cap. After the shared byte
form refactor, rerun the full `c71_b12_gemma` filter for the existing
P0/byte/RNE cases; actual full-domain dispatch remains open.
The `c71_b12_gemma_rms_dispatch` case executes a canonical small graph
with 10,003 ideal Fp3 rows: P0, all its RMS/statistics, direct q/k RNE,
local V RNE and both ranged PCS. Original embedding-input MACs also
open the same W. V altered with consistent S/Y fails RNE; norm weights
altered with consistent P/Y fail the installed W PCS. The dispatcher
has a 64-cell/eight-profile cap; this is no calibrated full-model run.
The `c71_b12_lookup` filter checks two restricted GELU tables against one
fixed byte source with 600 ideal Fp3 rows, including range and shared PCS.
It rejects wrong output, overflow, and an input/histogram pair changed
coherently after commitment. The v2 check interleaves query/table blocks
and rejects incomplete/duplicate table coverage. The unchanged shared
fraction-tree kernel needs no broad rerun.
The `c71_b12_gemma_gelu_sources` case compares a small extended byte view
and original X/Y/M forms, then counts every pinned GELU route and all
1,680 compact blocks without full bodies. RMS/P0 source IDs are preserved.
It also dispatches the full certified integer (0,0) GELU table and one gate
RNE using 1,158 ideal Fp3 rows. This source-view check uses placeholder roots
and does not execute a D19 or full D33 source PCS. Python compares all
65,535 entries with the exact existing public-table generator.
The `c71_b12_gemma_table_rne` case extends the ragged P0/RNE graph to
an original whole-table X probe with 1,356 ideal Fp3 rows and both ranged
PCS. It rejects wrong output, a changed raw that preserves rounding,
invalid source codecs and insufficient capacity before witness reads/use.
After changes to the shared byte extension, rerun the `c71_b12_gemma`
filter for the existing P0/byte/RNE/RMS cases, within the same small limits.
The `c71_b12_gemma_gate_up` filter executes product and both RNE with
1,372 ideal Fp3 rows and one ranged A PCS. It rejects a wrong raw product
and swapped G/U with a consistently changed up raw. Its separate canonical
view check dispatches a 21-row product and compares forms with literal
bytes, with placeholder roots and no PCS acceptance. Full pinned metadata
checks the 60 original down-P0 demands and D34 counts without source bodies.
Source RNE views accept only biased-i48; matrix view transcripts are preserved.
The `c71_b12_rope` filter checks the joint Q30 public adjoint on aligned
dyadic blocks, full half-head pairing, inactive pairs and absolute positions.
Its 559 ideal Fp3 rows include one ranged A PCS; wrong raw fails the linear
GKR and a coherently changed Y/raw pair fails that original PCS. It also
rejects misaligned blocks and exhausted capacity before witness reads.
Python checks the three active j=0 coefficient pairs against the existing
exact Q30 recipe. The `c71_b12_gemma_rope_sources` case compiles all 120
canonical original RMS/raw/output routes and checks 480 blocks, both raw/Y
forms and 120 RNE pairs, without the full source body. Its synthetic table
bodies check shape/context only; they are not certified Q30 or execution
evidence. It rejects the D27 native call at the existing D15 guard.
After generic non-matrix raw RNE changes, rerun the entire small
`c71_b12_gemma` filter to retain P0/GELU/gate-up behavior.
The two `c71_b12_attention` cases use 571/572 ideal Fp3 rows and an actual
ranged A PCS for QK/PV, including the original contracted-M-to-Pi link.
They reject wrong raw/GQA/query padding, detached M and source operands
changed consistently with the raw. The native dense QK cap is D15;
no full attention, softmax, accepted-KV history or Gemma execution is implied.
After changes to shared P0, rerun `c71_b12_p0`, `c71_b12_gemma` and
`c71_b12_rms_statistic` in separate bounded invocations.
The `c71_b12_gemma_attention` metadata check compiles the fresh O=0 routes
from original RoPE/RMS/P0, all 120 RNE obligations and 4,189 known A targets.
It checks D34/65,067 cubes without source bodies or full-domain attention.
The linear target guard is 8,192; its cube/domain guards remain unchanged.
After the source extension, rerun all small `c71_b12_gemma` checks; the
placeholder-root metadata case grants no source PCS acceptance.
The `c71_b12_gemma_affine` case uses 991 ideal Fp3 rows for a public
zero source form, ragged RNE, byte range and the same PCS. It rejects
wrong raw with the same rounding, a changed input/raw pair detached from
A and wrong output. The form itself uses no private correlation.
The `c71_b12_gemma_residual` metadata case checks all 181 canonical
residual/scale routes, the exact verified public BF16 coefficients and
181 RNE pairs, with a synthetic exponent map and no full witness.
Its 79,539-cube known batch fits the 131,072 guard, with the same D14
native source cap. Rerun the full small `c71_b12_gemma` filter after
source extension; full-domain RNE and calibrated profiles remain separate.
The `c71_b12_gemma_kv` case uses three component attempts with 544/577/610
ideal Fp3 rows, including incoming original K/V MACs, new-source range and
all source PCS. Prior A0/A1 receive fresh current-attempt MACs and PCS;
wrong incoming K or an altered old getter reject without receipt promotion.
It also checks canonical 150-row segment forms at offsets 0/150/300 using
metadata only. These receipts certify component byte/PCS checks, not full
Gemma execution. The `c71_b12_gemma_attention_continuations` metadata case
checks O=0/150/300, absolute RoPE windows, all original K/V routes and
the three A layouts. It rejects stale positions, a substituted current
root and a fourth segment, without allocating full sources. The Python
B12 checks recompose six A openings, 39 streams and 526 trees; full
accepted Gemma state and calibrated execution remain open.
The `c71_b12_gemma_argmax` case proves three public decisions with
unsigned byte slacks and a single ranged PCS (542 ideal Fp3 rows),
rejecting wrong decisions, tie order and slack. Its full-size metadata
check compiles 50 decisions into 56 cubes without allocating A.
Run the Python filter `B12 or gelu or softcap` after changes to the
shared public exponential enclosure: it preserves GELU and checks
softcap's strict tails, overflow and fail-closed public preparation.
The `c71_b12_gemma_output` case now connects raw head RNE, a certified
small softcap table, public argmax, range and the same PCS using 1,112
ideal Fp3 rows. Wrong raw, softcap and tie decision reject at their
respective checks. Its metadata portion compiles all three canonical
output layouts and original P0 raw IDs; no full D24 lookup/RNE runs.
The same case now checks a designated-verifier simulator with zero dummy
raw/X/Y/slack and arbitrary public tokens. It retains the verifier's
public target key using Delta; this is no malicious-prover capability.
Acceptance supports the documented component simulation argument, not
full-Gemma ZK by itself.
After extending output sources, rerun `c71_b12_gemma` within the same
60 s/2 GiB limits. Calibrated full output and Gemma simulation remain open.
The Python `softmax_exp30` filter checks the owner-selected numerical recipe,
including its certified difference from RNE of the real softmax. Its
passing test does not by itself change the B12 security total.
The `c71_b12_gemma_causal_mask` case uses 542 ideal Fp3 rows and a
shared ranged PCS to reject nonzero Pi at a future key or padded query.
Nonzero allowed values pass: the mask acts at Boolean source vertices,
not as a product of two independently extended tables. The metadata
check covers every query/key of O=0/150/300 and all 60 canonical Pi IDs,
with at most 111,306 cubes in the composed A batch. Run `c71_b12_gemma`
after changing these routes, and the Python `B12` filter for the added
FS/cube/resource accounting. No full body or softmax producer is executed.
After byte-function changes, rerun `c71_b12_byte_functions` and
`c71_b12_rne` separately; ordinary lane-mode transcripts are preserved.
This internal bridge uses in-memory proof transport; it is not a Gemma runner
or standalone wire codec. These checks need only local Unix socketpairs.
The existing field/FS checks use `c71_matrix::tests::` with that feature.
The old B7 matrix runner rejects this feature before setup. This is an
opt-in component check, not a complete admitted PCS or Gemma execution.

Before a broad local build, check guest space and confirm at least 60 GiB free
on the host; guest `df` alone does not establish host capacity. Run the full
workspace before a protocol milestone checkpoint when authorized resources
permit; otherwise state the validation gap. Heavy benchmarks and full-model
E2E belong on authorized hardware, not the local VM. The owner's 2026-09-08
exception allows a small synthetic CPU E2E on this VM, within the
[active experiment contract](../c7.1-gemma31b-design.md#esperimento-ridotto-contratto-e-ambito-del-runner).
It does not authorize a broad build, GPU/provider access or paid resources.

Do not create per-crate, top-level or experimental Cargo targets. Remove the
canonical target and ignored nested Cargo targets after a milestone checkpoint
and before leaving the session; keeping a build cache requires owner approval.
`rust/.cargo/config.toml` pins `target-cpu=native`: timing is machine-specific.
Re-measure the registered paired baseline before quoting rates on another CPU.
Reports use `cargo run --release -p volta-bench --bin <report>` with the active
design's report and workload.

## Lean and generated assets

Formal M1–M11 milestones are closed and frozen. Open Lean only when the protocol
statement requires it; if authorized, use `export PATH="$HOME/.elan/bin:$PATH"`,
then `cd lean && lake build`. Remove `lean/.lake` after the checkpoint unless
explicitly retained.

Weights and generated golden artifacts under `benchmarks/weights/` are produced
only by the registered export/dump scripts and are not newly committed as model
assets. Preserve existing tracked fixtures and evidence. The frozen GPT-2
[quantization spec](../quantization-spec.md), `scripts/gpt2_fixed.py` and Rust
forward must remain bit-identical when that baseline is touched. C7.1 requires
its own Gemma semantic/runtime correspondence as specified in design §2.1;
GPT-2 golden success does not validate Gemma.

Raw runs are new files under `benchmarks/results/<milestone>-<date>-<gitsha>.json`.
Keep every failure and all framing/resource costs. A run of record requires a
clean source tree and `git_dirty: false`; corrections go in a new linked record.

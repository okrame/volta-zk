# R1b X1--X3 delta-review handoff

**Status (2026-07-20): assigned externally; review not performed.**

This document hands the post-R1 X1--X3 delta to Kimi3. It describes the
review object and the claims that object puts under test; it is not a review,
a finding disposition, or review assurance.

## 1. Frozen object and handling rules

The review range is immutable:

```text
baseline = f05d7279249fdbe16025ee2d005ef58a18224fbb
target   = 4b349b59f13516ac878446f593d1621fba92bcfc
range    = f05d7279249fdbe16025ee2d005ef58a18224fbb..4b349b59f13516ac878446f593d1621fba92bcfc
```

The baseline is the checkpoint reviewed by R1. The target is the X1--X3
closure HEAD that was current when this handoff was requested. Later R1
disposition commits, including `bc44099`, are deliberately outside R1b; do
not substitute the moving branch tip for the pinned target. The baseline is
the merge base, and the range contains 15 commits, 47 changed paths, 19,987
insertions and 264 deletions.

Use a separate pristine checkout fixed at the target. Treat both endpoints
and every benchmark, fixture and golden as read-only. Do not amend code,
format files, regenerate fixtures, rewrite records, resolve findings, or
change the ledger from the review checkout. Any re-execution must use external
build/cache/output directories and must not turn generated output into
evidence unless its provenance is recorded.

Findings go only into a separate R1b report for product-owner disposition
(suggested import path `docs/r1b-kimi3-report.md`). Use the R1 severity order
CRITICAL / MAJOR / MINOR / NOTE and, for each finding, state the property,
adversary action, file/line or executed evidence, and confidence. Preserve
unverified claims and modeling boundaries explicitly. Do not implement a fix
or silently reinterpret a failed gate.

The range can be verified without trusting this prose:

```bash
git merge-base f05d7279249fdbe16025ee2d005ef58a18224fbb \
  4b349b59f13516ac878446f593d1621fba92bcfc
git log --reverse --oneline \
  f05d7279249fdbe16025ee2d005ef58a18224fbb..4b349b59f13516ac878446f593d1621fba92bcfc
git diff --name-status \
  f05d7279249fdbe16025ee2d005ef58a18224fbb..4b349b59f13516ac878446f593d1621fba92bcfc
```

## 2. Commit sequence

| Commit | Disposition represented by the commit |
| --- | --- |
| `910b0c6` | preregister the X1--X3 harness and hard-stop before implementation |
| `370023b` | introduce the runtime `ModelConfig` foundation and first diagnostic record |
| `e71f6da` | align the foundation comparator with the already-pinned provider contract |
| `9a4c688` | normalize comparison through serialized JSON and produce the clean foundation record |
| `40bf91f` | close the runtime foundation PASS and unlock X1 |
| `6be165f` | implement and run the X1 routing-soundness harness |
| `5375ca6` | close X1 PASS |
| `87ce25b` | implement and run the X2 synthetic MoE proof |
| `b7b3669` | close X2 as immutable FAIL |
| `0ae5111` | preregister the term-by-term X2b corrected proxy |
| `053d3fc` | add the append-only no-execution X2b preregistration record |
| `6c53619` | record and close the approved X2b PASS |
| `f7f0490` | preregister X3 and hard-stop before implementation |
| `7544f36` | implement and run the X3 non-GPT operations pack |
| `4b349b5` | close X3 PASS and the X1--X3 package |

The intermediate X1 foundation records at `370023b` and `e71f6da` are
append-only diagnostics, not gate records. The clean foundation record is
`9a4c688`. X2's FAIL is never replaced by X2b's later PASS.

## 3. Exact changes and claims placed under review

### 3.1 Runtime `ModelConfig` foundation and GPT-2 non-regression

The GPT-2 witness generator was generalized in place around a validated,
canonical runtime `ModelConfig`. The new configuration carries runtime and
non-power-of-two dimensions; per-layer norm, activation, attention, GQA,
expert and shift choices; public routing/tie metadata; block maps; and
boundary-thinning `k`. Generic profiles bind a versioned config digest before
allocation or transcript work. The frozen GPT-2 profile remains a
compatibility wrapper with its existing implicit profile and no new message,
label or challenge.

Allocation, band/decode/model/layer paths were moved from fixed GPT-2
constants to checked runtime geometry. The canonical layout is row-major,
independently pads each logical axis, uses `r_col || r_row`, zeroes arithmetic
pads, and prevents blocks from crossing their declared physical bounds. GQA
keeps canonical K/V storage and uses an explicit public head map rather than
copying K/V into query-head storage.

The report harness gained a reference projection for the foundation gate.
Two retained diagnostics corrected comparator bugs only: session/entropy
digests and hardware AES-dispatch labels are intentionally fresh or
function-equivalent under the existing provider contract, and current JSON is
serialized/reparsed before comparison so equal floating values have the same
representation. Those exclusions must not mask a transcript, counter, proof,
or deterministic schedule change.

Claims under test:

- the refactor preserves the frozen GPT-2 witness and proof semantics rather
  than merely preserving final logits;
- response bytes remain exactly **84,544,352**, split
  **28,778,208 / 12,492,256 / 43,273,888** for prefill, decode marginal and
  PCS;
- correction/reducer/q-bridge bytes remain
  **38,348,720 / 22,848 / 672**; sub/full correlations remain
  **4,793,590 / 181,933**; product/zero closures remain
  **21,667 / 8,170**;
- every operation count, proof-section length, PCS claim/block map,
  deterministic stage-allocation digest, normal/chunked proof, replay check,
  50-token decode and golden remains identical to T1;
- generic config validation, digest binding, zero padding and non-power-of-two
  layout are fail-closed and cannot become prover-selected statement data;
- comparator normalization enforces the pre-existing provider contract and
  does not relax a gate after observing a result.

The clean record is
`benchmarks/results/x1-foundation-2026-07-19-9a4c688.json`, SHA-256
`f9ba96ab6e9133683cafb436ea198972f9a77832a7cd62b06ae9725638058e22`.

### 3.2 X1 routing argument and derived limb bound

X1 adds a router-only proof at `T=31`, `L=4`, `d=48`, 32 experts and public
top-4 routing. Router GEMM, requant, exp/reciprocal, normalized products,
public selectors, packed-selector bridge, Range(16), TableBank and ZeroBatch
are instantiations of existing argument classes. Scores and the cutoff remain
private; the canonical public vector is `[tau,e1,e2,e3]`. The synthetic tie
rule is descending `(score, expert_id)`, so an all-equal row selects
`[28,29,30,31]` with cutoff 28. That rule is explicitly not a claim about a
future real gpt-oss exporter.

For public selected bit `m_j`, cutoff expert `tau` and private threshold
`theta=score_tau`, the proof binds one affine comparison per expert:

```text
c_j = score_j - theta - [j < tau]       if m_j = 1
c_j = theta - score_j - [j > tau]       if m_j = 0.
```

The limb bound is derived from the full signed-i16 output envelope. It gives
`-65,536 <= c_j <= 65,535`, so `B=16`. Honest nonnegative comparisons fit one
u16 limb, while a negative field residue cannot enter that range because for
Goldilocks `p=2^64-2^32+1`:

```text
2^(16*1) + 2^(B+1) = 2^16 + 2^17 < p.
```

Zero limbs cannot represent the valid interval, so one u16 limb is minimal.
This is a distinct derivation from C3b's three-limb private-logit comparison.

Claims under test:

- nonnegativity of all 32 affine comparisons plus cardinality four proves
  exactly the published top-4 set, including the stated boundary-tie rule;
- `theta` is bound to the selected cutoff score and neither score nor
  threshold is opened;
- the one-limb reconstruction is sound over Goldilocks for the complete
  signed bound, with no canonical-field wraparound ambiguity;
- routes, cutoff and multiplicities are fixed before TableBank/content and
  selector challenges;
- wrong-set, score-swap, forged-limb, duplicate/out-of-range, wrong-cutoff and
  crafted-tie attacks reject;
- the isolated comparison bridge's measured/predicted ratio remains inside
  the preregistered inclusive `[0.80,1.20]` band without redefining the work
  being measured.

The clean record is `x1-routing-2026-07-19-6be165f.json`, SHA-256
`b0e337ae513f26631018e5cca7a5e50202f3dbb7172e5f5f3b828ee6196afa8a`.
It records 3,968 logical / 4,096 padded comparisons, measured
707.2774193548387 versus predicted 662.4056199596774 E-mult per token-layer,
ratio 1.0677406683202548, and PASS.

### 3.3 X2 FAIL and the X2b corrected-proxy postdiction

X2 adds a two-layer `T=7`, `d=48`, `d_ff=80`, eight-expert/top-2 synthetic
MoE witness and proof. The public fixed routes touch every expert. Existing
classes perform public gather/scatter, committed expert up/down GEMMs, GELU
and requants, private route-weight products, T1 `k=1`/`k=2` composition, one
response-wide TableBank and one stacked Ligero opening. D3 is instantiated as
three commitments and exactly 40 claims; there is no per-token or per-expert
proof instance.

X2's correctness, golden, proof, PCS, closure, digest and rejection predicates
passed, but its preregistered full-correlation proxy predicted 17,040 for each
`k`. Measured values 12,462 / 12,482 gave ratios
0.731338028169014 / 0.7325117370892019, below 0.80. **X2 is therefore an
immutable FAIL.** The record is `x2-moe-2026-07-19-87ce25b.json`, SHA-256
`ea0be31ecd60c275363292cf506aa7c8b30ae3a0a4f98e99fd9bfc38bdc924cd`.

X2b changes the accounting model, not the X2 verdict or proof statement. Its
`existing-class-session-v2` proxy expands every existing argument class:
one response-wide TableBank, per-content table trees, lookup trees and
aggregation, blind-sumcheck masks, Hadamard masks, scalar claims, local and
shared product masks, PCS claim/component masks, the global ZeroBatch mask,
and the `k=2` T1 reducer/bridge masks. It predicts 12,462 / 12,482 exactly.
Independent self-checks also postdict X1 at 4,714, GPT-2/C1 at 176,880 and T1
at 181,933, each with zero delta.

Claims under test:

- the X2 proof binds route choice, private score use, gather/scatter,
  per-expert computation and the `k=1`/`k=2` seam with identical logical
  outputs and no unproved permutation;
- all claimed operations really instantiate existing proof classes, and the
  single TableBank/PCS session does not omit an expert-local or terminal mask;
- X2's FAIL, original 17,040 predictions and sub-0.80 ratios are preserved
  verbatim rather than post-hoc relabeled;
- the corrected proxy is a term-by-term schedule model, was preregistered
  before X2b execution, and did not change code, fixture, band or exact gates;
- zero-delta postdictions are independently computed from the named source
  records rather than constants copied from the expected outputs;
- X2b PASS means only that the corrected model predicts the unchanged run; it
  does not retroactively validate X2's failed planning proxy.

The no-execution preregistration is
`x2b-prereg-2026-07-20-0ae5111.json`, SHA-256
`eab5ec0b32d6590473f6a70cd06a61f53408ef968565eee9b44a38159456e38e`.
The approved record is `x2b-moe-2026-07-20-053d3fc.json`, SHA-256
`ac04c297aa069cb91b7ed2a27a8236daa8c638ef90398cdbdc9b6eba2ffcf6d8`.

### 3.4 X3 operations pack and non-power-of-two goldens

X3 extends the same synthetic framework with RMSNorm, clamped SwiGLU, public
Q14 RoPE, GQA 6/2, two attention sinks per query head, full/sliding-window-4
attention and final RMSNorm/logits. It uses `T=7`, `d=48`, `d_ff=80`, pads
8/64/128 and vocabulary 97 padded to 128. The implementation maps nonlinear
pieces to existing LogUp, range/saturation, Hadamard/Product and band classes;
public-linear RMS/RoPE/GQA/sink/lower-edge relations close in the trace
ZeroBatch. RoPE must add zero lookup rows. No new Lean theorem, PCS parameter,
PCG/lifecycle behavior or cryptographic argument class is claimed.

The independent numpy exporter emits full intermediate arrays, not only final
outputs or hashes. Source padding is filled with distinct nonzero sentinels;
canonical tensors must overwrite/ignore it, logical outputs must be
poison-invariant, and a claim that admits a sentinel must reject. Nine
permanent adversarial families cover RMS inputs/output, clamp side rows,
SiLU/Hadamard, RoPE coefficient/fold, GQA head substitution, sink denominator,
sliding lower-edge/window and pad admission.

Claims under test:

- Rust matches the independent numpy arrays bit-for-bit at both
  non-power-of-two time `T=7` and hidden dimension `d=48`;
- each newly supported operation is completely constrained by the cited
  existing classes, with no relation hidden only inside the native witness;
- the redundant synthetic full-trace Auth/ZeroBatch binding is honest
  conformance evidence and is not used to claim production cost or a new
  cryptographic theorem;
- pad poison exercises a genuinely nonzero admitted sentinel and fails
  actively, rather than only demonstrating equality on a clean path;
- all nine permanent tamper families target independent relation boundaries
  and reject for the intended reason;
- the preregistration preceded implementation and retained zero tolerance;
  no X3 or X1--X3 closure claim grants X4 or gpt-oss-export authority.

The no-execution preregistration is `x3-prereg-2026-07-20-6c53619.json`,
SHA-256
`c996bd4d2d887d8df113a17df496cf1b2e74a3b149867fb3dfe1f51e74c198e2`.
The clean run is `x3-ops-2026-07-20-7544f36.json`, SHA-256
`6514f00bdbc7a82941d8ac638196d998edbf6b101aa6fcba552b03884310d932`.
It pins a 656,034-byte golden with zero differing bytes, 21,969 / 35,824
logical/padded rows, 91 sites, nine contents, one finalization, and PASS.

### 3.5 Exporter, budget, records and documentation

`scripts/x123_export.py` adds the deterministic toy artifact/config/manifest
and the independent X1/X2/X3 full-array golden generator. `budget_moe.py` is
generalized around `ModelConfig`, adds the X1 geometry and X2/X2b schedule
self-checks, and propagates the corrected proxy into X0 projections. The Rust
report binaries serialize the preregistered operands and exact evidence;
Python tests pin exporter determinism, manifest/hash coherence and analytic
self-checks. The ledger, scaling note, X0 design and X1--X3 design were updated
append-only with preregistrations, diagnostics, exact PASS/FAIL outcomes and
scope boundaries.

Claims under test:

- exporter and Rust do not share implementation in a way that makes the
  goldens circular;
- artifact/config/manifest/golden hashes bind the exact shapes, ordering,
  quantization and public metadata consumed by Rust;
- report schemas cannot overwrite X2 with X2b or convert a preregistration
  into an execution record;
- budget self-checks derive their operands and do not merely assert expected
  totals;
- docs and records faithfully distinguish measurement, projection,
  diagnostic, preregistration and gate verdict.

Key fixture hashes at the target are:

| File | SHA-256 |
| --- | --- |
| `toy-moe-v1.artifact.bin` | `01853c761b625d5f28d210a6e8e81a2b3e1cfecdf1941cf8d296810b0f34f402` |
| `toy-moe-v1.config.json` | `92b1bcad58b466529d45a76391159404e2d47a7ae71679d2c3fdd1ba3f5f59a2` |
| `toy-moe-v1.manifest.json` | `3f302ead9abaa77d1d1a044e8bbd47e71565719ee93953bcb84a73def6e93c23` |
| `x1-router-v1.golden.bin` | `a1335d57e611285685dfa3bc50db35dff0e24c3d878e4f479ddb1f35e07e0431` |
| `x2-moe-v1.golden.bin` | `aa58281a9f54313c6dbdf61e495c112477b06893eaeb68b9c7d8186492fdf713` |
| `x3-ops-v1.golden.bin` | `31b5471f197a1fdb27641f123555fa6f098e30552d35f9e62b0806a37b70fa0c` |

## 4. Exact changed-path manifest

This is the complete `git diff --name-status` manifest for the frozen range;
there are no Lean, `volta-pcs`, `volta-pcg`, production weight, or historical
T1/C3b record changes in it.

```text
A benchmarks/results/x1-foundation-2026-07-19-370023b.json
A benchmarks/results/x1-foundation-2026-07-19-9a4c688.json
A benchmarks/results/x1-foundation-2026-07-19-e71f6da.json
A benchmarks/results/x1-routing-2026-07-19-6be165f.json
A benchmarks/results/x2-moe-2026-07-19-87ce25b.json
A benchmarks/results/x2b-moe-2026-07-20-053d3fc.json
A benchmarks/results/x2b-prereg-2026-07-20-0ae5111.json
A benchmarks/results/x3-ops-2026-07-20-7544f36.json
A benchmarks/results/x3-prereg-2026-07-20-6c53619.json
M docs/prototype-status.md
M docs/scaling-note.md
M docs/x0-moe-design.md
A docs/x123-harness-design.md
M rust/Cargo.lock
M rust/volta-bench/src/bin/p6_report.rs
A rust/volta-bench/src/bin/x1_report.rs
A rust/volta-bench/src/bin/x2_report.rs
A rust/volta-bench/src/bin/x3_report.rs
M rust/volta-gpt2/Cargo.toml
M rust/volta-gpt2/src/band.rs
A rust/volta-gpt2/src/config.rs
M rust/volta-gpt2/src/decode.rs
M rust/volta-gpt2/src/layer.rs
M rust/volta-gpt2/src/lib.rs
M rust/volta-gpt2/src/model.rs
M rust/volta-gpt2/src/resident.rs
M rust/volta-proto/Cargo.toml
M rust/volta-proto/src/block_proof.rs
M rust/volta-proto/src/ffn_schedule.rs
M rust/volta-proto/src/lib.rs
M rust/volta-proto/src/logup.rs
M rust/volta-proto/src/model_proof.rs
A rust/volta-proto/src/x1_routing.rs
A rust/volta-proto/src/x2_moe.rs
A rust/volta-proto/src/x2_proof.rs
A rust/volta-proto/src/x3_ops.rs
A rust/volta-proto/src/x3_proof.rs
M scripts/budget_moe.py
A scripts/x123_export.py
A tests/fixtures/x123/toy-moe-v1.artifact.bin
A tests/fixtures/x123/toy-moe-v1.config.json
A tests/fixtures/x123/toy-moe-v1.manifest.json
A tests/fixtures/x123/x1-router-v1.golden.bin
A tests/fixtures/x123/x2-moe-v1.golden.bin
A tests/fixtures/x123/x3-ops-v1.golden.bin
A tests/test_budget_moe.py
A tests/test_x123_export.py
```

## 5. Scope boundary

Review the delta for statement soundness, implementation fidelity, parser and
preflight strictness, transcript/challenge order, authenticated-value seams,
padding, counter/record integrity and preservation of the baseline's proved
interfaces. A delta may invalidate a baseline-reviewed property even if the
original file did not change; such a regression is in scope.

Do not review or implement X4/X5, real gpt-oss export, PCG/lifecycle changes,
new PCS parameters, or a new Lean proof in this assignment. Performance and
pod timing are not R1b gate claims. The R1 report remains an AI adversarial
review with no independent human-review assurance; R1b, when performed by an
AI reviewer, has the same assurance boundary.

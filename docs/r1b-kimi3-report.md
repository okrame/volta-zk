# VOLTA-ZK R1b — adversarial cryptographic review (delta + two addenda)

**This report is an AI adversarial review.** It was produced by an automated
agent (Kimi) operating under a hostile-cryptographer mandate. It confers
**no independent human-review assurance**. Every finding's disposition
belongs to the product owner.

**Baseline pinned:** commit `9b1ef2d` (R1b checkpoint), reviewed in a fresh
detached worktree (`/home/okrame/projects/volta-zk-r1b-review`), clean tree,
`git status` empty. The delta under review is `f05d727..4b349b5` per the
frozen handoff `docs/r1b-delta-handoff.md`; `4b349b5..9b1ef2d` contains only
R1 dispositions (Merkle/Ligero fixes, audit-script hardening, estimator
patch, docs) and no X1–X3 code change — verified by diff. The prior R1
report (`docs/r1-kimi3-report.md`, checkpoint `f05d727`) stands; nothing
here re-opens it except where explicitly stated.

**Posture:** read-only. No code was modified, no patches written, no commits
made. The ledger and design docs are claims under test, not evidence.

---

## 1. Executive summary

| Mandate | Area | Verdict |
| --- | --- | --- |
| M1 | X1–X3 delta review | **NO CRITICAL/MAJOR findings.** All headline numbers re-derived digit-exact; X2 immutable FAIL preserved; pad-poison reject demonstrates active detection; no new assumption or argument class. One MINOR, one NOTE. |
| M2 | `Ideal.lean` axiom fidelity | R1 leftover item **closed by execution**: the named-assumption audit was re-run at `9b1ef2d` and passes (93/93 theorems, standard axioms only, zero sorry). The four axioms are uninhabited `Prop` placeholders — formally they assert nothing and cannot over-claim. Docstring-level fidelity: one MINOR, two NOTEs. |
| M3 | X4 design-stage hostile read | Advisory only, no gate. All arithmetic re-derived exact (10.7008-TB floor, 106.2496-bit query term, tower identities, block inventory, gates' ceilings). M9 masked-opening seam is sound as specified; D3 cohort layout and N4 domain separation adequate at design level. One MINOR (floor is real but partly self-inflicted by an unexamined packing choice), two NOTEs. |

Findings: **0 CRITICAL, 0 MAJOR, 3 MINOR, 6 NOTE.**

---

## 2. Findings

### MINOR-1 — `Ideal.WeightPCSBinding` docstring names the wrong PCS family and bundles properties no single cited paper proves

- **(a) Property:** fidelity of a named security assumption to the
  construction actually implemented and to the literature.
- **(b) Adversary action:** none directly exploitable today — the axiom is
  an uninhabited placeholder. The hazard is at discharge time: a future
  proof could cite BaseFold/WHIR for a seam that the code implements in
  Ligero, or cite a single paper for the conjunction
  (binding ∧ blinded-ZK ∧ windowed multi-point batch soundness), leaving the
  ZK or batch component unjustified. The 2026-07-15 ledger entry already
  records one unsound batch variant (cross-point linear claim merging), so
  the batch soundness component is precisely where a mis-citation would
  bite.
- **(c) Evidence:** `lean/VoltaZk/Ideal.lean:34-37` ("the public multilinear
  PCS (Basefold/WHIR)"); the implementation is Ligero (`rust/volta-pcs/`,
  R1 area 5; `docs/private-weights-pcs.md:50-59` selects the
  "Ligero/Brakedown/Basefold … family" and obtains ZK from "ZK-Ligero-style
  random codeword rows", citing 2025/1015 for the masking technique).
  Neither Ligero (CCS'17) nor BaseFold (2023/1705) nor WHIR (2024/1586) is
  zero-knowledge as published; ZK is a system composition property here.
- **(d) Confidence:** high on the naming mismatch and on ZK-not-being-a-
  property-of-any-single-cited-paper.

### MINOR-2 — `Ideal.UCComposition` presumes a UC-realizable PCS that the cited constructions do not claim

- **(a) Property:** fidelity of the composition target to what the cited
  literature delivers.
- **(b) Adversary action:** none today (placeholder). At discharge time, the
  `(F_sVOLE, F_PCS)`-hybrid statement requires an `F_PCS` *ideal
  functionality* realized by the hash-based PCS. Ligero and BaseFold are
  proved as arguments of knowledge (IOP + Merkle, ROM/Fiat–Shamir
  analyses), not as UC realizations of a commitment functionality;
  Ferret (2020/924) is UC-proved, the PCS is not. A discharge that
  silently imports ROM extractability into a UC hybrid would overstate the
  composition.
- **(c) Evidence:** `lean/VoltaZk/Ideal.lean:43-45`; contrast with the
  honestly-labeled status line in `docs/protocol-sketch.md` ("PCG/Ferret
  realization, PCS, LogUp, UC | assumed (named axioms)").
- **(d) Confidence:** high that the gap exists in the literature; nil
  severity today because the axiom is deferred content and the file's own
  header says so.

### MINOR-3 (advisory, no gate) — the 10.7008-TB X4 floor is real but partly self-inflicted: the F_p4 code field is forced by an unexamined block-packing choice

- **(a) Property:** honesty/completeness of the design's floor analysis
  (Mandate 3 asks explicitly: "is the floor real, is it avoidable within the
  cited constructions").
- **(b) Adversary action:** not a soundness issue — an over-stated floor
  misleads planning, not verification. The floor is arithmetically exact
  (re-derived: `2·N·32/(1/8) = 512·N` bytes; 41.8 GB × 256 = 10.7008 TB;
  aux `2^17·32·8 = 33,554,432 B`; ×1,658 = 55,633,248,256 B — all
  digit-exact). But the 32-byte symbol exists only because the code field
  is `K = F_p4`, which is needed only because `mu_max = 30` requires a
  `2^34` multiplicative domain and `v2(|E|-1) = 33` (re-derived:
  `v2(p-1)=32, v2(p+1)=1, v2(p^2+1)=1`). `mu_max = 30` comes from packing
  each embedding/unembedding as a single `262,144×4,096 = 2^30` block.
  Splitting each into two `2^29` blocks (a block-geometry choice inside the
  same cited constructions — BaseFold is field-agnostic and the different-
  size batching is already selected) keeps `mu_max = 29`, the `2^33` domain
  fits in `E` (16-byte symbols), and the floor halves to ≈5.35 TB with the
  same rate and query count. The design does not discuss this lever.
- **(c) Evidence:** `docs/x4-folding-pcs-design.md:70-90` (profile),
  `:172-176` (block geometry forcing `mu_max=30`), `:412-419` (floor).
  Independent arithmetic in §5.
- **(d) Confidence:** high on the arithmetic and the existence of the
  alternative; medium on end-to-end feasibility (cohort layout and claim
  geometry would need to absorb twice as many global blocks — a design
  question, not a cryptographic one).

### NOTE-1 — X3 section ids 220/221 collide with prefill embed/final-LN ids in the u8 corr-index section space (standalone-harness-safe, integration trap)

- Evidence: `rust/volta-proto/src/x3_proof.rs:39-42`
  (`X3_TRACE_SECTION=220`, `X3_OP_SECTION=221`) vs
  `rust/volta-proto/src/model_proof.rs:13-14` (prefill embedding id 220,
  final-LN id 221), used at `model_proof.rs:1466,2757`. In the standalone
  X3 harness each proof runs its own bank/stream, so no shared-session
  domain collision exists at this checkpoint (verified: no cross-proof bank
  sharing in `x3_proof.rs`). If X1–X3 sections are ever folded into the
  response proof, 220/221 must be re-mapped first. X1 (`224`, table `239`,
  4 layers → `224..227`), X2 (`216/217/219`) sit in free gaps.
  Confidence: high.

### NOTE-2 — X3 conformance model: the verifier reconstructs the deterministic fixture

The X3 golden equality is against a canonical fixture both sides rebuild;
per-op relations are structural evidence and the glue is the authenticated
trace (`encode_x3_golden`) bound before challenges. This is disclosed in
the record (`redundant synthetic … no production credit/theorem`) and in
the design. It is honest, but reviewers should not read the X3 goldens as
evidence about production witness generation. Confidence: high (disclosed
property, not a defect).

### NOTE-3 — `Ideal.LogUpGKRSound` bundles three sources; any discharge must carry the characteristic hypothesis

- The docstring's "LogUp-GKR (fractional sumcheck)" spans Haböck's LogUp
  ([ePrint 2022/1530](https://eprint.iacr.org/2022/1530)), the
  Papini–Haböck GKR instantiation (ePrint 2023/1284, an *informal note*,
  not peer-reviewed — confirmed via the
  [IACR news item](https://www.iacr.org/news/index.php?next=21419) and the
  Eagen–Haböck follow-up), and the system-specific composition with the
  VOLE-MAC transcript. LogUp's soundness requires field characteristic
  greater than the lookup count; Goldilocks (`p ≈ 2^64`) satisfies this for
  VOLTA's table sizes by a wide margin, but the hypothesis must appear in
  the formal statement when discharged. Evidence:
  `lean/VoltaZk/Ideal.lean:39-41`. Confidence: high.

### NOTE-4 — `Ideal.FerretRealizesSVOLE` is faithful at docstring granularity

Ferret (Yang–Weng–Lan–Zhang–Wang, CCS 2020,
[ePrint 2020/924](https://eprint.iacr.org/2020/924)) proves malicious
UC-security of its correlated-OT extension; the single-point VOLE
subprotocol with selective-failure (leakage) handling is proved internally
and lifted by the consistency check. The docstring's only looseness is
naming the target `F_sVOLE` where Ferret's headline functionality is COT
extension; the corrupted-verifier-branch modeling note
(`VoltaZk.freshCorr`) is internal and consistent with M10's use.
Confidence: high.

### NOTE-5 — X4 ZK masked-sum public relation is a VOLTA adaptation, and the document says so — the G1 target cannot be evaluated before Phase 2

The public relation `h_b = Wext_b(z_b||0) + g_b(u_b)` is not zkDeepFold's
published relation; the document discloses this ("Citing zkDeepFold's
theorem while still sending the individual evaluations is not sufficient",
`docs/x4-folding-pcs-design.md:279-281`) and correctly defers
`masked_aux_hiding_count` and the full response-level composition to
named pre-code Lean theorems. Until Phase 2 produces the specialized
unique-decoding soundness expression, the claim that `ρ=1/8, s=128` meets
the 78.809294874-bit response-wide target is a screen, not a result — the
document itself says exactly this (`:113-121`). Advisory echo; no defect.
Confidence: high.

### NOTE-6 — review-environment caveats (provenance, not code defects)

- The 6.4-GB `c3_weights` smoke test could not be executed on the review
  host (11 GB RAM; process OOM-killed). Its pass/fail at `9b1ef2d` is
  unverified by this review.
- `pytest` initially failed with `FileNotFoundError` because the worktree's
  `.venv` is a checkout-local path; a symlink to the main repo's `.venv`
  resolved it (environment artifact, not a checkpoint defect). After the
  symlink, 9/9 pytest items pass.
- The Lean audit was run against the main checkout's prebuilt `.lake`
  oleans via an explicit `LEAN_PATH` (read-only; lean sources verified
  byte-identical between checkouts). No rebuild was performed.

---

## 3. Per-area verdicts (M1 — X1–X3 delta review)

### M1a — ModelConfig refactor, GPT-2 byte-level non-regression: NO FINDING

Checked: foundation record `9a4c688` matches the T1 reference on every
pinned value (response `84,544,352 B` = `28,778,208+12,492,256+43,273,888`;
`4,793,590` proofs / `181,933` sites; `21,667`/`8,170` zero-list;
`38,348,720`/`22,848`/`672`; PCS `78,80929487391641` bits). The comparator
(`rust/volta-bench/src/bin/p6_report.rs:1435-1615`) projects the full
record, digests blake3 over re-serialized JSON (float-safe via serde/ryu),
and excludes only session digests, AES labels and timings — the boolean
predicates remain compared. `config.rs` validation is fail-closed;
`LegacyImplicit` is reserved to the exact GPT-2 geometry; legacy sessions
get no session digest. `cargo test --workspace --locked` at `9b1ef2d`:
**249 passed, 0 failed, 4 ignored**. The two runnable ignored tests
(`private_logits_response_e2e_and_wrong_token_rejects`,
`c3_embed_two_weight_set_leakage_smoke`) re-executed and pass, the first
byte-identical to its `f05d727` values (`57,840 B`, `157,705,530.0`
E-mult).

### M1b — X1 routing argument: NO FINDING

Checked (`rust/volta-proto/src/x1_routing.rs` read in full): tie rule
descending `(score, expert_id)` selects experts `[28,29,30,31]` for `tau=28`
— matches the native path; the affine form is exact; the router-score bound
`[-65536, 65535]` gives a minimal 1-limb u16 decomposition
(`x1_routing.rs:236` asserts honest comparisons fit one limb); the theta
gather challenge is sampled after the bridge; `add_mult` precedes
`bank.finalize`; the verifier is specular; every cheat test rejects.
Record re-derived: full proof `4,714 B` with `P==V`; E-mult accounting
(`fp2 + base/5`) spot-verified on three rows; `87,702.4/124 = 707.277…`;
predicted `662.4056199596774 = (157,705,530/7,864,320)·4,096/124` — ratio
`1.0677…` inside the preregistered band; geometry `3,968/4,096`; 9/9
smokes; synthetic P4_LAYER PCS with `Q=200` disclosed; both deviations
disclosed; `cryptographic_review_assurance=false` present in the record.

### M1c — X2 immutable FAIL + X2b corrected-proxy postdictions: NO FINDING

Checked: the X2 record remains **FAIL** (`12,462`/`12,482` vs `17,040`,
ratios `0.731338…`/`0.7325117… < 0.80`; all non-proxy gates PASS; 7
deviations; k2 internal-state and chunk-boundary smokes reject).
`rust/volta-bench/src/bin/x2_report.rs:996-1001` writes only `x2b-moe-*`
paths and refuses overwrite; the ledger at `4b349b5` preserves the FAIL
verbatim. Preregistration-before-implementation ordering verified by
`git log --follow` (x2b: `0ae5111` → `053d3fc`; x3: `f7f0490` →
`7544f36`). Independent re-derivation of every X2b term from labels
witnessed by the X2 record itself: TableBank `11,336 = Σ logup_*`
(`181,376 B/16`); blind `644`; hadamard `243`; fresh scalar `131`; product
`64`; pcs+zero `44`; k2 T1 `20 = (288+16+16)/16`; old proxy
`3·(8·584+12·80)+80+64 = 17,040` ✓. Postdictions: X1 `4,714` (terms
`4,511+48+132+12+5+6` ✓); C1 `176,880` (matches
`benchmarks/results/c1-2026-07-15-2a3d731.json` `corr_full_corrs`;
subterms `158,641+10,800+5,343+1,424+556+116` ✓); T1 `181,933` (terms sum;
delta from C1 `= 5,053` ✓). `scripts/budget_moe.py` k1/k2: self-check
PASS, operand derivations (`d²+7d+1+2c`, `d²+6d+2`) match the code.
pytest 9/9 PASS (after the environment symlink, NOTE-6).

### M1d — X3 ops-pack goldens + nine permanent rejects: NO FINDING

Checked: nine tamper families in `x3_proof.rs` tests, all PASS; the reject
names match the preregistration. **Pad-poison demonstrates active
detection, not clean-path passage:** 2,624 distinct nonzero sentinels
(`1,001+index`; `64+64+128+384+1,984` across the five padded tensors);
`layers`/`final_witness` are byte-identical between honest and poisoned
modes (poison-invariant); the mechanism is the authenticated
`encode_x3_golden` trace (beta sampled after), with the weighted opening
checked against the canonical value both parties reconstruct
deterministically — a nonzero row on a zero-claim triggers rejection
(record: `prover_nonzero_zero_claim_detected=true`; the poisoned run with
`15,801` full / `8,780,968 B` — one fewer mask — documents the prover
refusing to open a nonzero ZeroBatch). All `smoke_runs` have
`rejected=true`, `zero_batch_accepted=false`, distinct
`target_trace_byte_index`. Gate record PASS including
`no_new_argument_class` and `rope_new_lookup_rows_exact_zero`. Golden
`656,034 B`, 0 diffs, `21,969`/`35,824`, 91 sites, 9 contents, 1
finalization, `1,065,887`/`15,802`/`6,573`, matching digests,
`8,781,000 B`.

### M1e — no new cryptographic assumption or argument class: NO FINDING (claim holds)

Checked: the delta range touches no `lean/`, `volta-pcs/` or `volta-pcg/`
path (empty diff). `logup.rs` gains exactly 8 lines — `TableKey::Silu` and
`TableKey::Clamp1024` appended to the enum (content data for the existing
LogUp argument class, not a new class; appended, so no discriminant
renumbering). No new transcript/KDF domain strings in the X-files (the
GEMM/Hadamard domains are allocated from the existing `Doms` allocator;
no `fase1/2/3` or new byte-label domains). Section-id occupancy checked
against the whole `u8` space: X2 `216/217/219`, X3 `220/221/222/223`,
X1 `224/239` (4 layers → `224..227`), existing model `0..11`, `16+32c`,
`200..210`, `220/221`, `230/231`, `232`, `240`, tests `236-238/255` — no
shared-session collision at this checkpoint; the X3/prefill `220/221`
overlap is NOTE-1 (standalone harnesses only). The gate record's
`no_new_argument_class=true` is consistent with the code.

---

## 4. Per-area verdicts (M2 — `Ideal.lean` axiom fidelity)

**R1 leftover item 6 is now CLOSED — verified by execution, not by
document inspection.** At `9b1ef2d`:

- `lean/` diff vs `f05d727` is empty; lean sources in the review worktree
  are byte-identical to the main checkout (`diff -r` clean).
- `Audit.lean` re-elaborated against the pinned oleans: **93/93**
  `#print axioms` targets report either "does not depend on any axioms" or
  dependence on exactly `{propext, Classical.choice, Quot.sound}`. No
  `sorryAx`, no `VoltaZk.Ideal`, none of the four named axioms appears in
  any line. `rg '\b(sorry|admit)\b'` over `lean/`: no matches. The
  `Ideal.lean` inventory is exactly four declarations, each
  `axiom X : Prop` (`Ideal.lean:32,37,41,45`).
- Structural point that answers the mandate's "neither stronger nor subtly
  different": each axiom is an **uninhabited `Prop` constant**, not a
  formalized proposition. Formally it asserts nothing, so it cannot
  overstate; the only literature-fidelity content is the docstrings,
  assessed below.

Per-axiom statement-vs-literature verdicts:

| Axiom | Cited source | Verdict |
| --- | --- | --- |
| `FerretRealizesSVOLE` | Ferret, ePrint 2020/924 (CCS 2020) | Faithful at docstring granularity — NOTE-4 only. |
| `WeightPCSBinding` | Ligero (implemented) vs "Basefold/WHIR" (docstring) | **MINOR-1**: wrong family named; ZK and batch soundness are not single-paper theorems. |
| `LogUpGKRSound` | 2022/1530 + Papini–Haböck 2023/1284 (informal) + MAC composition | NOTE-3: bundled sources; characteristic hypothesis must survive discharge. |
| `UCComposition` | Canetti UC composition | **MINOR-2**: hybrid model presumes a UC-realizable PCS the cited hash-based constructions do not claim. |

NO FINDING on the audit mechanism itself: the script's checks (sorry
sweep, per-theorem axiom allow-list, output-count reconciliation, Ideal
inventory pinning) were replicated by hand on the re-run output and all
pass.

---

## 5. Per-area verdicts (M3 — X4 design-stage hostile read, advisory)

Scope: `docs/x4-folding-pcs-design.md` (580 lines, read in full). This is
a Phase-1 preregistration with a HARD STOP; nothing here is a gate.

**Floor arithmetic — re-derived, exact.** `512·N` first-oracle bytes
(2× ZK extension × 32 B `K`-symbol × 8× rate) = 256× an i16 source;
250 MB → 64 GB; 41.8 GB → **10.7008 TB** ✓. Aux `2^17·32·8 =
33,554,432 B`; ×1,658 = 55,633,248,256 B ✓. Query term `(9/16)^128 =
1.0367724023455627e-32 = 2^-106.24959981538402` ✓ digit-exact. Target
`1.8881578818430648e-24 = 2^-78.80929487391641` ✓. Tower identities:
`v2(p-1)=32, v2(p+1)=1, v2(p²+1)=1 → v2(|K|-1)=34` ✓; `v2(|E|-1)=33`
(one bit short of 2^34 — the real reason `K` is needed at `mu_max=30`) ✓;
`-7` is a nonsquare in `F_p` (`p ≡ 6 (mod 7)`, nonresidue) so the
`E[ψ]/(ψ²-φ)` tower is a field ✓. Block inventory `24·69+2 = 1,658`,
claims `3,316` ✓; gate/up `4,096·8,192 = 2^25` ✓; embedding
`262,144·4,096 = 2^30` ✓; `ell_b = ceil(log2(128·30²+1)) = 17` ✓;
`84,544,352 − 43,273,888 = 41,270,464`; G3 ceiling `45,270,464` ✓.
The floor is honestly labeled ("floor, not an upper bound"), the
streaming/recompute escape hatch is disclosed with its accounting
obligations (G6), and no hidden analogous cost was found beyond MINOR-3.

**M9 masked-opening seam — sound as specified.** Re-derived: completeness
holds (`h0 = v + s0`, `h1 = s1` from `h = embed(v) + s` with `embed(v)` in
the ψ-free component); hiding is a genuine one-time pad (uniform `g_b` ⇒
uniform `s_b = g_b(u_b)` at the fixed canonical point, so `h_b` is uniform
in `K` independent of `v`); binding chain is closed (static commitment
binds `Wext`/`g`; masked-sum relation binds `h` before batch/fold/query
challenges; two `E`-MAC transfers authenticate `s0,s1`; the response
ZeroBatch ties `v + s0 − h0 = 0` ∧ `s1 − h1 = 0`; verifier recovers
`Auth(W̃(z)) = Auth(h0) − Auth(s0)`). Correlation allocation `2·B_touch+1`
matches the stated count and introduces no `K`-valued correlation. The
one-opening-per-epoch lifetime boundary is enforced as a protocol rule
("may not rely on operator discipline"). All load-bearing obligations are
correctly deferred to named pre-code Lean theorems; the document
explicitly forbids weakening them. NO FINDING beyond NOTE-5.

**D3 cohort layout — adequate as specified.** Inner-per-coordinate /
outer-per-cohort Merkle layout with distinct canonical absent-slot leaves
blocks slot substitution; descriptors are statement data fixed before any
challenge; the replacement of DeepFold's one-tree-per-polynomial is
disclosed as a VOLTA adaptation with an explicit pre-code binding-theorem
obligation (`:201-207`). Per-block openability is honestly costed
("not … independent of `B_touch`", `:219-223`). NO FINDING.

**N4 domain separation — adequate as specified.** Four distinct BLAKE3
derive-key contexts (PCS leaf/node × manifest leaf/node); frames bind
schema/profile, tree/oracle kind, namespace, cohort, block-slot,
descriptor digest, fold round, indices and lengths; cross-kind and
cross-round replay explicitly rejected; historical roots never regenerated
or byte-compared. Residual design-stage gap (acceptable at Phase 1): the
exact frame grammar is not yet normative — it must be pinned before Phase
3. NOTE-level; folded into NOTE-5's "cannot be evaluated before Phase 2".

**Conjectural-radius hygiene — good.** The design explicitly refuses
DeepFold's list-decoding-radius figures (the ≈34-query/304-KB point) and
credits only the unique-decoding radius `(1-ρ)/2 = 7/16`; it preregisters
the stop rule if the specialized expression misses the 78.809294874-bit
target. Query sampling is uniform-with-replacement from fresh bits, no
modulo reduction — the historical Ligero modulo-bias boundary is not
inherited. NO FINDING.

---

## 6. Claims I could not independently verify

1. **`c3_weights` smoke test at `9b1ef2d`** — exceeds review-host RAM
   (6.4 GB working set, 11 GB host, OOM-killed). Not executed.
2. **The exact unique-decoding soundness expression for zkDeepFold-UD** —
   does not exist yet; the design defers it to Phase 2 by construction.
   Only the screen term `(9/16)^128` was verifiable, and it checks out.
3. **zkDeepFold's published ZK theorem covering the masked-sum variant** —
   the variant is a VOLTA adaptation (disclosed); whether the paper's
   simulator extends to publishing `h = Wext(z||0) + g(u)` while
   simulating given only `h` is a Phase-2 proof obligation, not verifiable
   from the cited papers as-is.
4. **RunPod/A100-referenced numbers in the X4 comparison table** (e.g.
   `0.202467 s` commit) — carried over from earlier milestones' records;
   the review host has no GPU; spot-checked for internal consistency with
   the R1-verified T1 record only.
5. **DeepFold different-size batching / different-point reduction theorem
   statements** (2024/1595, USENIX Sec 2025) — cited correctly at the
   level of "such constructions exist and are proved"; the exact error
   terms are Phase-2 obligations and were not re-derived from the paper.

---

## 7. Execution log

- Worktree: `git worktree add --detach /home/okrame/projects/volta-zk-r1b-review 9b1ef2d`; HEAD verified `9b1ef2d`, clean.
- Range: `git merge-base` = `f05d727`; 15 commits, 47 paths, +19,987/−264.
  All 6 fixture hashes and 7 record hashes from the handoff §3.5 verified
  digit-exact. `git diff 4b349b5..9b1ef2d` contains only R1 dispositions.
- `source ~/.cargo/env`; `CARGO_TARGET_DIR=/tmp/r1b-target cargo test --workspace --locked`: **249 passed, 0 failed, 4 ignored**.
- Ignored tests executed individually:
  `private_logits_response_e2e_and_wrong_token_rejects` PASS (12.70 s,
  `57,840 B`, `157,705,530.0` E-mult — identical to `f05d727`);
  `c3_embed_two_weight_set_leakage_smoke` PASS (10.45 s);
  `c3_weights` smoke **not executed** (OOM).
- pytest: 9/9 PASS after symlinking the worktree `.venv` to the main
  repo's venv (environment fix; initial failures were
  `FileNotFoundError`, not checkpoint defects).
- Lean audit: `LEAN_PATH=<prebuilt oleans> lean Audit.lean` at `9b1ef2d`:
  93/93 targets clean; `sorry/admit` sweep clean; Ideal inventory exactly
  the four named `Prop` placeholders. Lean sources byte-identical to the
  main checkout (`diff -r --exclude=.lake`).
- All X4 arithmetic re-derived with Python (Fraction/exact integers):
  tower v2 identities, `(−7/p)` via quadratic reciprocity, query term,
  floor, aux oracles, block inventory, gate ceilings — digit-exact.
- Web verification of citations: LogUp = Haböck,
  [ePrint 2022/1530](https://eprint.iacr.org/2022/1530); LogUp-GKR =
  Papini–Haböck (ePrint 2023/1284, informal note, per the
  [IACR news item](https://www.iacr.org/news/index.php?next=21419));
  Ferret = Yang–Weng–Lan–Zhang–Wang, CCS 2020 (ePrint 2020/924).

---

*Disposition of every finding belongs to the product owner. This document
is an AI adversarial review and confers no independent human-review
assurance.*

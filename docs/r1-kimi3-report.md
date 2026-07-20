# VOLTA-ZK R1 — adversarial cryptographic review report

**Reviewer:** Kimi (AI agent). **This is an AI adversarial review. It confers
no independent human-review assurance.** In particular it does NOT close the
ledger's criterion (1) ("independent cryptographic review of the
construction/equations/parser/parameters remains external and incomplete",
`docs/prototype-status.md:1115-1116`); that criterion calls for an
independent human reviewer. Disposition of every finding below belongs to the
product owner. Nothing in this report is a fix, a patch, or a refactor
proposal.

**Object under review:** the repository exactly at checkpoint `f05d727`
(the T1 closure), reviewed in the pristine worktree
`/home/okrame/projects/volta-zk-r1-review` (`git rev-parse HEAD` = `f05d727`,
no tracked-file modifications). Commits after `f05d727` were ignored except as
context; the in-flight X1–X3 package was not reviewed. `lean/` is
byte-identical between `f05d727` and HEAD (verified via empty `git diff`), so
the Lean build/audit results quoted below apply to the checkpoint tree.

**Claims under test:** `docs/prototype-status.md` (ledger),
`docs/r1-kimi3-handoff.md`, and the cited design docs. Nothing was accepted as
true because a document asserts it; every number below was re-derived from the
cited papers, the pinned parameters, and the code as it stands, or is listed
under "Claims not independently verified".

**Method:** hostile reading of the seven scope areas, re-execution of the
estimator and test suites, Decimal-arithmetic recomputation of every pinned
bit-security figure, and diff-level comparison of the Lean theorem statements
against the Rust mirrors. Code style, performance, and roadmap were
deliberately not reviewed.

---

## Findings (ranked)

### CRITICAL — none

### MAJOR — none

### MINOR

**M1. `scripts/audit_lean.sh` is stale: the shipped Lean-audit gate exits 1 on
the clean checkpoint tree.**

- (a) Property: gate integrity of the machine-checkable Lean audit — the
  artifact's own tripwire that no `sorry`/`admit` and no deferred named
  assumption has entered the proved M1–M11 boundary.
- (b) Adversary action: the gate is fail-closed (red) on a *clean* tree, so a
  malicious or accidental regression inside `lean/` (a `sorry`, a new deferred
  axiom, a weakened statement) produces no *change* in signal — operator and CI
  already see red. The realistic exploit is social: "fix" the chronically red
  gate by editing the script's expectations instead of the audit, silently
  shrinking the audited set.
- (c) Evidence: `scripts/audit_lean.sh:15-39` hardcodes 23 M1–M10 theorem
  names and `:60-66` requires the standard-axiom output line count to equal
  that hardcoded list length; `lean/Audit.lean:48-116` prints 76 theorems
  (M1–M11). Reproduced at `f05d727`: the script exits 1 with
  `audit_lean: expected 23 audited theorems with only the standard Lean
  axioms; got 76`, while the underlying Lean state is clean: `lake build`
  rc=0 (3246 jobs, matching the ledger), all 76 theorems depend only on
  `[propext, Classical.choice, Quot.sound]`,
  `VoltaZk.response_domains_noncolliding` is axiom-free, zero
  `sorry`/`admit`/`native_decide` in `lean/`, no `sorryAx`/`VoltaZk.Ideal`
  axioms in the audit output, and `lean/VoltaZk/Ideal.lean` declares exactly
  its 4 intended axioms. The script was not updated when M11 joined the audit.
- (d) Confidence: HIGH. Soundness impact at the checkpoint: none (fail-closed
  direction; the true Lean state was verified manually as above).

### NOTE

**N1. The pinned estimator patch does not apply as checked in — the LPN
reproduction path is broken.**

- (a) Property: reproducibility/provenance of the pinned LPN bit-security
  evidence.
- (b) Adversary action: no direct cryptographic exploit; the broken patch
  forces any verifier to hand-edit the estimator, which opens room for a
  substituted or "helpfully fixed" patch that changes the numbers while
  claiming the pinned configuration.
- (c) Evidence: `scripts/estimators/fase_d_hybrid_logsumexp.patch` —
  `git apply --check` fails with `error: corrupt patch at line 15` (hunk
  header `@@ -398,7 +398,9 @@` but only 6 old-side lines). The intended
  one-line change (log-sum-exp accumulation in `hybrid/hybrid_quick.py`,
  ~line 401) is benign; applied manually against Code Estimators
  `969ef60c30cb84c25502d6b7c968f43a362bb438`, every pinned number reproduces
  digit-exact (area 1 verdict below).
- (d) Confidence: HIGH.

**N2. `ConnectionCorrelationSpool` writes live VOLE material as plaintext at
rest, in tension with the ledger's own lifecycle-criterion text.**

- (a) Property: at-rest secrecy of correlations and verifier MAC keys during a
  live connection.
- (b) Adversary action: an adversary able to read host memory/backing store
  during a live connection (co-resident tenant, swap, crash dump, host
  snapshot) recovers prover `(r, m)` tuples and verifier keys `k` from the
  spool and forges authenticated values or recovers `Delta`-adjacent state
  for that connection.
- (c) Evidence: `rust/volta-pcg/src/production.rs:439-524` — the spool writes
  raw 40-byte entries to an anonymous, unlinked, 0600 file and discards page
  cache; the ledger (`docs/prototype-status.md:1110-1112`) states correlation
  pools "should remain protected in memory (or receive an explicit
  encrypted-at-rest policy)". The spool is a documented design decision of the
  fase-D resident profile (the gates even pin
  `correlation_spool_resident_raw_entries == 0`,
  `rust/volta-bench/src/bin/p6_report.rs:4354`), so this is a recorded
  risk-acceptance question for the product owner, not an undocumented defect.
- (d) Confidence: MEDIUM — code behavior verified; exploitability is
  deployment-dependent (host adversary model was never in scope for the
  prototype's declared DV setting).

**N3. `volta-pcs/src/ligero.rs` header comment documents the superseded PCS
configuration.**

- (a) Property: parameter provenance — comments are claims future changes get
  justified against.
- (b) Adversary action: a future modification argued from the stale header
  (rate ≈ 0.516, Q = 200, "query error ≈ 2^-81") would mis-size the soundness
  budget relative to the pinned rate-1/4, Q = 120 configuration.
- (c) Evidence: `rust/volta-pcs/src/ligero.rs:23-29` vs the pinned
  `C3_WEIGHTS`/`C3_EMBED` geometries and `docs/c3-pcs-communication-design.md`
  §2 (selected point: effective rates 0.265625/0.25390625, Q_pin = 120,
  78.809294874 bits).
- (d) Confidence: HIGH (comment drift only; the compiled parameters are the
  pinned ones and were verified).

**N4. Merkle tree has no leaf/internal-node domain separation, and the
verification call sites do not pin the path length.**

- (a) Property: Merkle binding (computational, under the blake3
  collision-resistance assumption already in the design).
- (b) Adversary action: cross-level confusion (presenting an internal node as
  a leaf hash, or a shortened/lengthened path) — exploitable only by finding
  blake3 (second-)preimages, since `verify_path` recomputes the chain and
  compares to the committed root; no statistical forgery vector exists.
- (c) Evidence: `rust/volta-pcs/src/merkle.rs:9-18` (`hash_leaf` = raw
  `blake3(bytes)`, `hash_pair` = `blake3(l‖r)`), `:55-62` (no depth check
  inside `verify_path`), call sites `rust/volta-pcs/src/ligero.rs:882-888`
  and `:1818-1819`.
- (d) Confidence: HIGH that the observation is correct; no known
  exploitability without breaking blake3. Defense-in-depth item only.

**N5. Declared modeling boundaries (consolidated; not defects, listed so the
report's verdicts are scoped honestly).**

- Single-process two-role harness: prover and verifier share one process and
  one memory space in every test and record; the DV deployment separation is
  modeled, not enacted.
- Challenges are verifier-side stream draws (interactive-DV mock), **not**
  Fiat–Shamir: `rust/volta-mac/src/transcript.rs:1-8,20-38`,
  `docs/t1-boundary-thinning-design.md:284-290`. Any non-interactive
  deployment needs a new Fiat–Shamir analysis; nothing in this review
  licenses one.
- The channel is an in-process serialization model for byte accounting:
  `SerializedChannel.receive` parses frames already sliced by `send`
  (`rust/volta-pcg/src/phase_b.rs:470-492`), so network-level truncation/EOF/
  bit-flip fuzzing is outside the model; the design assigns transport to the
  deployment (`docs/c2-packed-lane-pcg-design.md:332-334`).
- The fixed-key AES-128 GGM PRG rests on the registered GKWY
  correlation-robustness assumption (ePrint 2019/074) — an *assumption*,
  registered as such (`docs/fase-d-realpcg-default-design.md:266-268`,
  `docs/prototype-status.md:957`). Verified: BLAKE3 remains the primitive for
  transcripts/KDF/commitments/domain separation; only the GGM PRG changed;
  the BLAKE3 GGM path is explicit-test-only and record binaries require
  `aes128-mmo` (`rust/volta-bench/src/bin/p6_report.rs:2675`).
- Query-index sampling maps a uniform `F_p` element with
  `value() % code_len`; since `p ≡ 1 (mod 2^15)` (and `mod 2^17`), residue 0
  is overweighted by a factor `≈ 1 + 2^-49` per query — negligible against
  the 2^-78.8 response budget (over 120 queries the total bias stays
  ≈ 2^-42 relative).

---

## Per-area verdicts

### 1. fase-B/D sVOLE core — **NO FINDING**

after checking:

- **MAC convention.** `k = m + Delta·x` (equivalently `m = k − Delta·x`) is
  used consistently across `volta-mac`, the PCG expansion, and the proto
  layer; corrections are 8-byte canonical `F_p` values; `ZeroOpen`/`ZeroBatch`
  check `k == m` on zero-claims with fresh full-field masks and 16-byte
  re-centring with the challenge drawn after claims+mask.
- **Base OT → COPEe/IKNP.** CO15 Ristretto base OT (`BASE_OT_COUNT = 128`),
  COPEe, IKNP extension with KOS-style check (`IKNP_CHECK_REPS = 128`,
  one-hot dummies, Fig-5 sacrifice) at `rust/volta-pcg/src/phase_b.rs:42-45`;
  per-rep forgery requires inverting `Delta` (≈ 2^-128).
- **WYKW Fig-7 ordering** in `expand_stage3_batched` verified line by line:
  challenge → x* mask → batches → EqCommit(V→P) → EqResponse(P→V) → verifier
  rejects at `phase_b.rs:2679-2683` **before** EqOpen; prover checks at
  `:2708-2713`; `ConsistencyReport{ok:true}` only after both. Tamper tests
  (GGM leaf, correction, cheating response — on both PRGs) all reject.
- **GGM PRG.** Fixed-key AES-128 MMO `σ(x) = AES_K(x) ⊕ x`, children
  `σ(s)`, `σ(s ⊕ τ_1)`; default `Aes128Mmo`; BLAKE3 GGM explicit-only; the
  GKWY (ePrint 2019/074) registration confirmed in ledger and design doc.
  BLAKE3 remains the transcript/KDF/commitment/domain primitive
  (`wykw_commit`/`derive_seed`/`bind_seed` use distinct length-prefixed
  BLAKE3 domains).
- **LPN tuples** hardcoded exactly as pinned — setup (25,000 / 642,048 /
  2,508), main (589,760 / 10,805,248 / 1,319), fase-D stage-3 (6,520,000 /
  117,440,512 / 1,792) — and `production_preflight` rejects test profiles and
  any tuple deviation before any cryptography runs
  (`phase_b.rs` production entry; test at `:4120-4130`).
- **Estimator re-run (executed).** Code Estimators @
  `969ef60c30cb84c25502d6b7c968f43a362bb438`, patch applied manually (see
  N1). Results, digit-exact against the pinned claims:

  | Tuple | AGB | AGB2 | ISD | HYB | RISD | min |
  | --- | ---: | ---: | ---: | ---: | ---: | ---: |
  | stage-3 (117440512, 6520000, 1792) | 213.85 | 213.85 | 208.85010924741465 | **199.59980442282708** | 227.92519270931604 | 199.599804 ✓ |
  | setup (642048, 25000, 2508) | 143.69 | — | — | **140.64686430760642** | — | 140.646864 ✓ |
  | main (10805248, 589760, 1319) | 164.72 | 164.73 | — | **149.4773339537398** | — | 149.477334 ✓ |

  Six-instance combination recomputed: 197.01484192210592 (claimed
  197.014842 ✓). Connection floor recomputed:
  `-log2(2^-140.64686430760642 + 2^-149.4773339537398 + 6·2^-197.01484192210592)
  = 140.64369866606756` (claimed 140.643699 ✓). `LOG2_Q = 64 ≥ log2(p)` is the
  conservative direction. The AGB category is the EC23 Briaud–Øygarden RSD
  algebraic attack (ePrint 2023/176; `d_wit,(f,mu)` terminology in the
  estimator source); the pinned setup tuple clears it at 143.69 > 140.65, so
  the algebraic attack does not undercut the claimed floor. The AGB shim
  re-checks its winner with 170-digit Decimal (`degree_conjforq` assert) —
  scan fidelity adequate. Logs preserved at `/tmp/r1-est-*.log`,
  `/tmp/r1-fb-*.log`.
- **One-time-use discipline.** `DomainLedger` panics on reuse
  (TAG/FULL/SHADOW reserved bits `1<<63/62/61`); pooled cursors monotone
  non-overlapping; `ConnectionCorrelationScope` re-derives the mock seed per
  `(connection_id, response_nonce)` via BLAKE3 `derive_key`.

### 2. Connection lifecycle (fase-D) — **NO FINDING**

after checking:

- **Durable-store-before-entropy ordering** in
  `rust/volta-pcg/src/production.rs`: the response-nonce marker is reserved
  with atomic `create_new` + fsync at `:1796` **before** `OsRng` sampling at
  `:1800`; the OPEN record is fsynced at `:1875` before the `OsRng` draw at
  `:1878`. Nonce replay after kill/restart is excluded by the append-only
  store + `ConnectionStore::create` burning any non-terminal journal on
  reopen ("restart burned the prior connection").
- **Abort semantics:** one active response at a time; every failure path
  routes to a durable idempotent `terminal_burn`; `Drop` burns if unsynced;
  `ensure_live` re-reads the durable journal and enforces TTL. Selective
  abort across responses cannot bias a later response: each response's
  correlations are freshly scoped (`(connection_id, response_nonce)`), drawn
  after the marker is durable, and any abort burns the whole connection.
- **Correlation reuse across responses:** excluded by scope-derived mock
  seeds plus monotone non-overlapping pool cursors; lifecycle gates pin zero
  repeat base-OT/extension bytes after the first response
  (`p6_report.rs:4310-4314, 4359-4363`).
- **Domain separation:** all ~40 BLAKE3 domain strings across the crates
  enumerated — distinct, length-prefixed; response-bound domains carry
  `connection_id + response_nonce`; digest chains length-prefixed. No
  collision found.

### 3. Lean-vs-Rust fidelity (M10, M11a–c) — **NO FINDING** (one MINOR gate
finding M1 above; modeling gaps named below)

after checking:

- `lake build` rc=0 (3246 jobs, matching the ledger); the 76 audited theorems
  carry only the standard Lean axioms; `response_domains_noncolliding` is
  axiom-free; zero `sorry`/`admit`/`native_decide`; exactly the 4 declared
  `Ideal.lean` axioms (FerretRealizesSVOLE, WeightPCSBinding, LogUpGKRSound,
  UCComposition) — all deferred named assumptions stayed outside the proved
  boundary.
- **M10** (`lean/VoltaZk/Connection.lean`): the R-response union bound, fresh
  offsets, and injective nonces match the Rust connection semantics; the
  nonce-injectivity and terminal-burn hypotheses are discharged to the
  durable store, which was verified in Rust (area 2).
- **M11a–c vs the Rust eq-reducer mirror:** compressed quadratic `[g0,g2]` /
  cubic `[g0,g2,g3]` wires with `g(1) = live_claim − g(0)`
  (`rust/volta-proto/src/sumcheck_blind.rs:1087` prover, `:1120` verifier;
  `logup.rs:1896-1913` round 3); challenge drawn after round corrections;
  `beta` after the `t1_eq_claim_pair` marker
  (`boundary_thinning.rs:154-155`); shared child-bit `t` sampled **after**
  the full child vector is fixed (`logup.rs:1469-1471`; `splits_aux` appends
  all corrections before `t` at `:1960`); `aux_col_claims` full-vector
  pairFold; terminal fresh full-field mask; closure row
  `terminal·coeff_final − final_claim`. The tamper test
  `eq_reducer_matches_m11_and_tamper_leaves_nonzero_closure` rejects a forged
  terminal correction.
- **Accounting:** `8238 − 68 = 8170` zero claims, `21667` product claims
  (`T1_ZERO_CLAIMS`/`T1_PROD_CLAIMS`, `p6_report.rs:133-134`); derivation
  `21·35 + 21·33 = 1428` reducer rows `+ 46` aux leaves (the "delta 46, not
  92" amendment, t1 design:510) reproduced; response-wide soundness
  113.065480 bits recomputed; the run of record
  `benchmarks/results/t1-a100-realpcg-v4-2026-07-19-b14577e.json` carries
  8170/21667.
- **Modeling gaps where theorem hypotheses are narrower than the code
  (named, all explicitly disclaimed in the Lean headers / sketch):**
  (i) Lean embeds the nonce in the domain index; Rust's ledger key is
  `u64`-only, with separation carried by scope-derived seeds and pool
  offsets — equivalent under the verified scope derivation, not the same
  formal object; (ii) Lean challenges are free uniform coins; Rust draws are
  KDF/stream-derived (the declared ideal-sVOLE / interactive-mock boundary);
  (iii) abort/TTL/restart lifecycle is unmodeled in Lean (disclaimed in the
  file header); (iv) the durable store is a hypothesis, verified out-of-band
  in area 2.

### 4. C3b private argmax — **NO FINDING**

after checking:

- **Bound derivation (re-derived):** `|L_j| ≤ 768·32768² = 824633720832 <
  2^40`, so the B=41 envelope covers every reachable logit difference;
  wraparound exclusion `2^48 + 2^42 = 285873023221760 < p` keeps the negative
  residues (`≥ p − 2^42 > 2^48`) outside the 3-limb range `[0, 2^48)`, so a
  forged limb decomposition of a negative `s` cannot pass the shared
  `Range(16)` LogUp; L=2 limbs cannot cover positives up to 2^41, hence 3
  limbs minimal (a coverage argument, as the ledger states).
- **Relation:** the MLE identity `s(r,c) = L_τ(r) − L(r,c) − [c > τ(r)]` is
  enforced per phase at the Hadamard point
  (`rust/volta-proto/src/private_argmax.rs:1169-1175` prover, `:1480-1486`
  verifier); bridge rows bind the packed limbs to the rectangular openings;
  only `s` is ranged, `d` reconstructed, per the amended design. Constants in
  code match the pinned geometry (3 limbs, base 2^16, 50 rows, 64×65536,
  segments 2^21 + 2^19, 2,512,850 real / 2,621,440 packed per limb /
  7,864,320 total).
- **Tie rule:** `[j > τ]` = last maximum, exactly matching the native greedy
  decoder `max_by_key` (last maximum on ties) at
  `rust/volta-gpt2/src/decode.rs:229-230`.
- **Executed tests:** unit tests (crafted tie, forged tie, bound round-trip,
  geometry) and both ignored production tests run at `f05d727` and PASS:
  `private_logits_response_e2e_and_wrong_token_rejects` (12.69 s — the
  wrong-token rejection is exercised, transcript 57,840 B) and
  `t1_full_counter_reconciliation_matches_the_record_geometry` (41.53 s —
  candidate 2,800,595,736.8 / other 114,852,961.2 / core 4,793,590 /
  full 181,933, matching the ledger).
- **Leakage of the masked range argument:** `c3_embed_two_weight_set_leakage_smoke`
  PASS (14.77 s). The masked argument reveals only the ranged `s` column
  inside the LogUp instance; no token identity beyond the argmax output
  crosses to the verifier.

### 5. PCS (Ligero, volta-pcs) — **NO FINDING**

after checking:

- **Pinned parameters in code:** exactly two trees —
  `C3_WEIGHTS {rows 24576, col_bits 13, pad 512, code_bits 15, Q 120}` ⇒
  `r = 8704/32768 = 0.265625`, and `C3_EMBED {rows 2080, col_bits 15, pad
  512, code_bits 17, Q 120}` ⇒ `r = 0.25390625`; `pad = 512 ≥ Q`.
- **Soundness re-derived in 60-digit Decimal arithmetic** from the documented
  formula `ε_tree = (1−(1−r)/2)^Q + (R+G+1)/|E|`, `R=24576, G=96` (weights),
  `R=2080, G=6` (embed), `|E| = p²`:
  `ε_weights = 0.6328125^120 = 1.4223481351468e-24`,
  `ε_embed = 0.626953125^120 = 4.6580974661760e-25`,
  field terms `26760/p² ≈ 7.86e-35`,
  `ε_response = 1.8881578818430647e-24` = **78.809294874 bits** (claimed
  78.809294874 ✓, design-doc value `1.8881578818430648e-24` ✓). The old
  13-tree configuration recomputes to `13·0.7578125^200 = 76.316991844` bits
  (✓ `docs/c3-pcs-communication-design.md:56-67`).
- **Freshness:** queries are drawn after all prover messages for every
  response (`ligero.rs:805`, `:1707-1708` after `m_z`); mask rows committed
  before the proximity challenge; `u_q`/`u_c` blinded; `s` authenticated with
  a fresh full correlation; openings resolve via `ZeroOpen`/`ZeroBatch`
  (`v* + s − ip`) with no cleartext `W̃(r)`.
- **Caching/merging ban:** no verifier column caching and no cross-point
  linear claim merging anywhere — multi-open resolves each claim separately
  at its own point; the verifier is stateless across responses re columns.
  The 2026-07-15 ledger entry (`docs/prototype-status.md:1629-1675`)
  correctly records why both mechanisms are unsound (Q revealed after the
  first response ⇒ forged `u` matching cached columns at every checked
  position; cross-point RLC mixes products and verifies neither claim).
  `cached_query_cut_bytes`/`cached_query_marginal_bytes`
  (`ligero.rs:1009-1010`) are reporting-only projections: the binding gates
  use measured bytes (`packed_response_bytes = rec.comm_bytes +
  rec.public_logits_packed_bytes`, `p6_report.rs:4188-4191`; C3b G1 gate
  `packed_response_bytes <= C3_PACKED_RESPONSE_GATE_BYTES` at `:4348`; G4
  pins `rec.comm_bytes == C3B_TRANSCRIPT_REFERENCE_BYTES` and
  `rec.pcs_opening_bytes == C3_PCS_OPENING_BYTES` at `:4369-4370`).
- **Mask budget:** one batched opening per response per tree; the pad covers
  one response's Q=120 queries with headroom; no re-commit amortization is
  claimed or implemented.

### 6. T1 boundary thinning — **NO FINDING**

after checking:

- **Seam schedule:** multi-point → single-point eq-reducers at fan-out seams
  exactly as `docs/t1-boundary-thinning-design.md` §2–§5 prescribes; K/V stay
  authenticated ("outside thinning", design §2 table) and chains never cross
  a chunk boundary (§3); retained authentications are exactly `X0`, `F3`,
  `F7`, `F11` with `X4`/`X8` as canonical aliases (no new corrections).
- **Forged-intermediate-state enforcement (executed):** the artifact-gated
  `model_proof` tests were run at `f05d727` with the checkpoint-pinned
  weights (SHA-256 verified against `SHA256SUMS`): 5 passed, 1 ignored
  (production-size C3 argmax rectangle — run separately, PASS) — including
  `response_rejects_kv_replay` (a replayed K/V segment is caught),
  `model_e2e_on_frozen_artifact`, `response_e2e_on_frozen_artifact`,
  `identity_alias_preflight_is_canonical_and_fail_closed`, and
  `greedy_preflight_binds_the_first_token_of_each_later_chunk` (chunk-boundary
  binding). The reducer tamper test
  `eq_reducer_matches_m11_and_tamper_leaves_nonzero_closure` rejects a forged
  terminal correction, and the production reconciliation test
  (`t1_full_counter_reconciliation_matches_the_record_geometry`, 41.53 s)
  PASSes against the record geometry.
- **Ordering premises:** `beta` after the sealed claim pair; reducer-round
  `rho_i` after the sealed masked coefficients; `t` after the full child
  vector; the global `Pi_ZeroBatch` challenge after all response claims; aux
  `mu` draws at injective public schedule positions (46 fresh draws, zero
  proof bytes, zero correlations); verifier rejects proof-selected schedules,
  wrong lengths, padding changes, duplicate domains, trailing rows, and
  chunk-crossing chains (design §5, mirrored in code — spot-verified at
  `boundary_thinning.rs:154-155`, `logup.rs:1469-1471,1960`,
  `sumcheck_blind.rs:1087,1120`).

### 7. Channel/parser robustness — **NO FINDING** (within the declared
in-process model — see N5)

after checking:

- **Framing:** `kind:u8 ‖ length:u64_le ‖ payload`
  (`rust/volta-pcg/src/phase_b.rs:448-451`); `receive` enforces exact
  `MessageKind` match (33 kinds enumerated, `:382-416`), canonical length
  (`declared != frame.len() − FRAME_HEADER_BYTES` ⇒ error, `:484-489`), and
  missing-frame errors (`:476-480`); `finish` errors on unconsumed frames
  (trailing/duplicate frames, `:528-531`); the capture-reparse test
  independently walks the wire image and reconciles directional byte counters
  (`:3883-3909`). Non-canonical `F_p` encodings are rejected on read
  (canonical-encoding checks verified in the field-deserialization path).
- **Channel secrecy (executed):**
  `channel_transcript_excludes_delta_and_verifier_private_state`
  (`phase_b.rs:3874-3910`) and
  `fase_d_multi_response_channel_transcript_excludes_connection_secrets`
  (`:4077-4094`) search the captured bytes for `fp2_bytes(Delta)`,
  `PROVER_SEED`, `VERIFIER_SEED`; the runtime audit is fail-closed when
  capture is enabled (`:3209-3213`, `:3619-3622`); `ProverSetup` has no
  `Delta` field by construction (`:549-554`).
- **`delta_bin`:** the C2 packed-lane XOR correlation exists only in the
  design doc (`docs/c2-packed-lane-pcg-design.md`); no Rust implementation
  exists at `f05d727` (grep for `packed_lane`/`PackedLane`/XOR-correlation
  identifiers: none), so there is no serialized byte that could carry it; the
  documented rule "`Delta`, `delta_bin`, branch seeds, and private role seeds
  are forbidden message fields" (`c2-packed-lane-pcg-design.md:329-330`)
  holds vacuously for the binary delta and was verified concretely for
  `Delta` and both role seeds.

---

## Claims not independently verified (and why)

1. **The 126.44-bit Briaud–Øygarden figure for the superseded main tuple
   (k0 = 19,870).** Requires Magma; not available on this host. Immaterial to
   the checkpoint: that tuple is not used anywhere; the AGB category for the
   *current* tuples was reproduced via the pinned Python port (results above).
2. **`c3_weights_two_weight_set_leakage_smoke` (6.4 GB encoded geometry).**
   The review host has ~8 GB free RAM; running it risked OOM-killing the
   review toolchain. The smaller `c3_embed_...` variant (2.2 GB) was run and
   PASSes; the T1 run of record reports both PASS on the A100 pod.
3. **AGB estimator's float pre-scan near-ties.** The shim re-checks its
   winning cell with 170-digit Decimal (`degree_conjforq` assert), which I
   read and consider adequate; a fully independent re-implementation of the
   scan was not done. Immaterial: AGB results (≈ 143–228 bits) sit far above
   the HYB floor that sets the connection bound.
4. **The GKWY correlation-robustness assumption itself** (ePrint 2019/074).
   Registered as an assumption by design; verifying the assumption is a
   cryptanalysis problem outside a code review.
5. **A100/pod timing gates and all wall-clock figures.** CPU-only review
   host; these are performance claims, outside the cryptographic scope of R1
   regardless.
6. **The Lean `Ideal.lean` axioms' faithfulness to the cited papers**
   (Ferret/sVOLE realization, PCS binding, LogUp-GKR soundness, UC
   composition). They are *declared* axioms, inventoried and confirmed to
   number exactly 4 and to stay outside the proved boundary; their
   content-fidelity to the literature is a human-review item (criterion 1).

## Execution log (what was actually run at `f05d727`)

- `cargo test --workspace`: **220 passed, 0 failed, 4 ignored.**
- Code Estimators @ `969ef60c…` (clean copy, patch applied manually): the
  five pinned computations — digit-exact (table in area 1). Logs:
  `/tmp/r1-est-*.log`, `/tmp/r1-fb-*.log`.
- Python/Decimal recomputation: six-instance 197.01484192210592; connection
  floor 140.64369866606756; PCS ε_response 1.8881578818430647e-24 =
  78.809294874 bits; old-config 76.316991844 bits; argmax bound
  `768·32768² = 824633720832`, `2^48 + 2^42 = 285873023221760 < p`.
- `cd lean && lake build`: rc=0, 3246 jobs. `scripts/audit_lean.sh`: rc=1
  (finding M1).
- `cargo test --release -p volta-proto --lib model_proof::tests::`: 5 passed,
  1 ignored (then run explicitly): `response_rejects_kv_replay`,
  `model_e2e_on_frozen_artifact`, `response_e2e_on_frozen_artifact` PASS.
- Ignored/production tests run explicitly, all PASS:
  `private_logits_response_e2e_and_wrong_token_rejects` (12.69 s),
  `t1_full_counter_reconciliation_matches_the_record_geometry` (41.53 s),
  `c3_embed_two_weight_set_leakage_smoke` (14.77 s).
- Worktree hygiene: weights artifact `benchmarks/weights/gpt2s-q.bin`
  SHA-256-verified against the checkpoint-pinned `SHA256SUMS` before use;
  no tracked file modified.

---

*End of report. This review was performed by an AI agent operating as a
hostile cryptographer within the declared scope. It confers no independent
human-review assurance and does not close ledger criterion (1). Disposition
of findings M1 and N1–N5 belongs to the product owner.*

# Prototype Status Ledger (T1 CLOSED; X1 PASS; X2 FAIL immutable; X2b PASS; X3 PASS; X1--X3 CLOSED; R1/R1B DISPOSITIONS CLOSED; X4 AMENDMENT 5 V4 LEAN/RUST + CPU/GPT-2 MIGRATION GREEN; A100 POD PENDING)

The implementation-phase analogue of the formalization table in
`protocol-sketch.md`. One row per milestone; key numbers land here, raw runs
land in `benchmarks/results/*.json`. The repo-local plan of record is
`docs/p7-handoff-spec.md` plus this ledger; no external plan is authoritative.

Workload of record: **GPT-2 small (124M, L=12, d=768, h=12, d_ff=3072),
prefill T=100 + 50 deferred decode tokens, causal, C3b PCS Q=120**, on the
designated RunPod A100 profile. Earlier Q=200 rows are explicitly historical.
P7 is closed; its CPU and rho numbers below are historical. P7b has a valid official PASS at `ab3a03f`, and GPU
optimization is closed by the 2026-07-15 Stop branch. **FLIP-READINESS is
complete** for the fase-B real-PCG candidate. On 2026-07-16 the product owner
approved the mock→real default flip, waived its then-operational criterion
(1) with no replacement obligation for that flip, accepted criterion (4) at
the measured 8.451--8.609 s / 31,261,434 B cost, and confirmed criteria
(2)/(3) satisfied. Fase-D Part A is
preregistered below to implement the default mechanics, recursive scaling,
AES-MMO and connection lifecycle. Lean M10 is proved and audited, satisfying
the Lean-first hard stop before Rust. Part B produced clean G1/G2/G2b/G3 and
pod G4 records with the real default and `pcg_production_ready:true`;
historical records remain untouched. G1, G2, G2b and informative G3 pass. The
preregistered `runpod-a100-realpcg-v2` record passes its maximum absolute
synchronization wall gate at **0.123482 s <=0.150 s**, so fase-D is **closed**
and criterion (5) is enacted by the 2026-07-17 ledger entry plus checkpoint.
Candidate A (Packed16/fase-C) is rejected on product cost. The earlier
`33e5fb4` decode-only FAIL remains an immutable rebaseline result. C3 L1--L4
and the clean CPU/A100 E2E table refresh are complete. C3b closed on clean
`161fc59`: G1/G2/G3/G4 all PASS, including the 11 GiB connection-scoped CPU
record, production leakage smokes and fresh `runpod-a100-realpcg-v3` record.
The post-implementation CUPTI census has zero drops and no new grid-x=1
private-argmax family.  On 2026-07-18 X0 completed its design-only analytic
package.  T1 measured the correction split and preregistered an amended k=4
construction, but exhaustive fan-out analysis required a new M11 package for
the eq-sumcheck late-scalar chain and non-empty LogUp aux transport.  Phase 1
was approved on 2026-07-18.  M11a--c and the concrete full-vector leaf
instantiation are now proved and audited, so the Lean-first stop is cleared.
T1 closed on clean `b14577e` with G1/G2/G3/G4 PASS and the exact schema-10 CPU
and A100 records below.  The user approved the X1--X3 Phase-1 preregistration
and explicitly authorized Phase 2 on 2026-07-19.  The runtime `ModelConfig`
foundation now has its exact clean T1 non-regression PASS on `9a4c688`, and X1
routing closed PASS on clean `6be165f`.  X2 closed **FAIL** on clean
`87ce25b`: every correctness, golden, PCS, smoke and exact-session invariant
passed, but the binding full-correlation ratios were below the symmetric 20%
band.  The user approved the frozen corrected-proxy repeat, and X2b closed
**PASS** on clean `053d3fc` with the same inclusive band and exact full-
correlation ratios 1.0 at k=1 and k=2.  X2 remains an immutable FAIL.  After
explicit approval, X3 closed **PASS** on clean `7544f36`: the zero-tolerance
T=7/d=48 golden, honest proof, nine permanent rejection tests, active
pad-poison rejection and exact session invariants all passed.  The X1--X3
package is closed.  Kimi3's R1 AI adversarial review of detached baseline
`f05d727` returned zero CRITICAL, zero MAJOR, one MINOR and four NOTEs; the
2026-07-20 product-owner dispositions are implemented and closed below.  This
unblocks X4 **design only**.  The X1--X3 additions postdate the review baseline
and were reviewed read-only at detached `9b1ef2d`.  The imported R1b report
finds zero CRITICAL, zero MAJOR, three MINOR and six NOTEs.  Its dispositions
are closed below with the honest label: **AI adversarial review only, no
independent human-review assurance; criterion (1) remains external**.
R1b MINOR-3 is adopted in `docs/x4-folding-pcs-design.md` as
`x4-zkdeepfold-ud-e29-v2`: the two `2^30` global blocks split into four
`2^29` blocks, the PCS moves from `F_p^4` to `E=F_p^2`, the unpadded gpt-oss
first-oracle floor falls to **5.3504 TB**, and the specialized conservative
response bound is **83.30226403378921 bits**.  Final pre-code theorem
statements and the v2 frame grammar are frozen.  On 2026-07-21 the product
owner approved Amendment 2, which repairs the false bare-`Authed.Valid`
premise of `direct_mask_transfer` by requiring MAC validity *and* zero
plaintext on the good tape.  The complete X4 Lean-first package is now proved,
built and audited with no new ideal axiom, so the ordered Rust phase is
authorized subject to every existing hard stop.  The normative v2 codec,
N4-separated cohort Merkle tree, `E` NTT and public strict-UD folding core were
implemented, but concrete M9 discharge exposed a deterministic missing
auxiliary-evaluation-to-MAC link.  X4 is hard-stopped before M9, CPU records,
GPT-2 migration and pod work; no X4 gate verdict has landed.  The product
owner authorized Amendment 3 on 2026-07-21.  Its
`x4-zkdeepfold-ud-e29-v3` design replaces the missing seam with one blind
authenticated-output batch whose correction-created values remain pending
until the commitment's own fold/query checks bind `s_b=g_b(u_b)`.  The v3
design, exact accounting, soundness expression and pre-code theorem
statements are frozen below, with a renewed hard stop before their Lean
proofs and before any v3/M9 Rust.  R1b M3's “sound as specified” sentence is
superseded only on this seam, without blame; the report remains an immutable
AI review with no independent-human assurance, and the amended seam is
mandatory scope for a future R1c review.
On 2026-07-21 the product owner approved the complete v3 freeze at design
SHA-256 `07eb1f832367d84b70095e20addc29c136233a6940e32f56d58ac7251e9ca868`,
affirmed all six Amendment-3 constraints at design level and authorized the
exact frozen Lean statements.  The Lean-first gate is therefore active;
v3/M9 Rust remains forbidden until every statement proves without weakening,
new axioms or hypothesis smuggling and the full build/audit is green.
The exact discharge then stopped before any repository Lean edit:
`authenticated_output_link_produces_bound_aux` and the equality clause of
`bound_aux_has_verified_origin` deterministically conclude
`authS.x=committedAuxEval` from raw link acceptance and terminal closure, but
the separately frozen soundness theorem explicitly permits nonempty
`LinkBad`.  Fixed residuals `R0=1,R1=-1` cancel at the legitimate batching
challenge `beta=1`; a truthful terminal opening can therefore accept while
`authS.x!=g(u)`.  Lean kernel-checks the rational witness.  Adding a good-tape
premise or an `equality OR LinkBad` conclusion is a statement change and needs
an owner-approved Amendment 4.  X4 is hard-stopped; no Lean/Rust/record/pod
work followed.
The product owner then authorized Amendment 4 form (2): the two Bound-output
theorems conclude `authenticated equality OR LinkBad`, and that disjunction
flows into the existing named link-bad event.  The resulting statement-only
freeze is SHA-256
`f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98`.
No protocol, byte, correlation, parameter, coefficient or gate changes; the
exact **83.30226403378921-bit** expression is unchanged because `LinkBad` was
already charged.  The beta-collision witness is now a required permanent
negative audit theorem.  This approval clears only the statement-shape stop
and authorizes direct Lean-first discharge.  That discharge is now green:
all frozen v3/Amendment-4 statements prove, the full build and enlarged audit
are clean, and v3/M9 Rust is authorized.  No implementation record or X4
gate verdict has landed yet; CPU, GPT-2 and pod ordering remain unchanged.
The v3 production preflight subsequently proved G3 infeasible, and Amendment
5 froze `x4-zkdeepfold-ud-e29-v4` at rate `1/8`, `s=111`, model-global
same-domain cohorts and one schema-4 packed opening.  The product owner has
now refused any 5--10% gate exception and authorized exact v4 discharge.  Its
required Rust/Lean event cross-check is complete: the four response-wide
owners remain Fold, ClaimReduce, LinkBad and ZeroBatch, with no fifth event or
new hybrid term, so the explicit re-sum remains
**80.25537016399041 bits**.  The cross-check-annotated design is SHA-256
`c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544`.
V4 Lean-first is now green at checkpoint `d5227f2`: every frozen statement
proves, the 3,252-job build and 209/116 derived audit are green, and no new
axiom or error term appeared.  This clears the ordered schema-4/v4 Rust phase;
that Rust phase and the ordered CPU/GPT-2 migration are now complete at clean
source checkpoint `31fc866`.  The clean production-codec migration measures
exactly **2,683,236 B PCS** and **43,953,700 B response**, so G3 is **PASS**;
golden decode remains bit-exact and historical rows remain immutable.  The
synthetic v4 record makes G5 **PASS** and G6 **PASS in synthetic scope**.
The approximately 32-GB GPT-2 cryptographic oracle was deliberately not
materialized on the CPU VM: full-production G2, G4, physical G6 and the overall
X4 verdict remain **NOT EVALUATED** until the preregistered A100 run.  No new
failure event or soundness term surfaced, so **80.25537016399041 bits** remains
unchanged.  Pod provisioning, including the R1b NOTE-6 `c3_weights` smoke, is
now the next authorized boundary.

## Milestones

| Milestone | Status | Gate | Key numbers |
| --- | --- | --- | --- |
| P0 harness + analytic budget | **done** (2026-07-03) | workspace builds, budget pre-registered ✓ | budget below |
| P1 fused MAC epilogue microbench | **done** (2026-07-03) | ρ_kernel ≤ ~1.3 ✓ **PASSED** | ρ_kernel 1.06–1.11 per shape, 1.06 layer-weighted; epilogue ~2 ns/elem; GEMM 25–31 GMAC/s (4 cores); verifier fused scan 33 ns/elem → 0.37 s prefill-100 (q=3). `benchmarks/results/p1-2026-07-03-5113243.json` |
| P2 authenticated-value layer | **done** (2026-07-04) | e2e auth→open ✓, counters match budget ✓ | Π_Auth/Π_ZeroOpen/Π_ZeroBatch (fresh full-field mask) in `volta-mac`; corrections 8 B/value + 16 B/mask + 16 B/opened tag; soundness smoke 0/1000 forged accepts; P1-epilogue interop test green; counter formula reproduces 3,763,968 auth values |
| P2.5 clear-LogUp constant spike | **done** (2026-07-04) | informative — constant **23.2 E-mult/lookup, >2× budget est. ⇒ iteration plan logged** | 272 ns/lookup @2^23 (single-thread), verify 0.10 s, proof 20 KB; extrapolated prefill-100 LogUp prover 4.6 s vs native 0.30 s (ratio ~15.6 single-thread, ~4 on 4 cores). `benchmarks/results/p2.5-2026-07-04-a13cca4.json` |
| P3 blind sumcheck + Thaler + Π_Prod | **done** (2026-07-04) | GEMM (100×768)·(768×768) proved+verified e2e ✓; ρ decomposed ✓ | ρ_clear 1.49, ρ_blind/clear 2.25, ρ_total 3.34; blind split: fold 3.1 ms + **m_r expand 2.8 ms** + rounds 0.04 ms + Π_Prod 0.01 ms; verify 6.5 ms; proof 352 B (excl. 1.2 MB auth corr); corrs 153,600 sub + 21 full. Attribution: blinding IT ≈ free, cost is Freivalds folds + lazy tag expansion. `benchmarks/results/p3-2026-07-04-cef997d.json` |
| P3.5 static weight PCS (private weights) | **done** (2026-07-04) | opening ≤ 15% native prefill: **FAILED (230%)** — iteration plan logged below; leakage smoke ✓; M9 seam e2e ✓ | In-house Ligero (`volta-pcs`), full 2^27, rate 0.516, Q=200. Commit one-off 3.3 s; opening of record (row-local multi-eval, 220 claims) **0.70 s** = fixed 0.12 s + **~2.3 ms/claim**; verify 0.12 s; 73.8 MB/opening; peak RSS 7.3 GB. Rejected path (generic reduction sumcheck): 5.8 s. `benchmarks/results/p3.5-2026-07-04-1708c66.json` |
| P4 LogUp + fused blocks | **done** (2026-07-05) | one full layer proved+verified e2e (T=100, real PCS opening) ✓ **PASSED**; counts within 20% ✓ (witness streams = budget **exactly**, padded LogUp domains explained); LogUp ≤8–10 E-mult/lookup: **MISSED, motivated (12.20)**; 1 weight claim/tensor ✓ (4/layer) | prove 0.800 s vs native forward 0.033 s (ρ_layer ~24, 4 cores); verify 0.041 s; LogUp lookup-side **12.20 E-mult/lookup** (~34 ns/lookup, 5.4× vs P2.5 spike wall), table-side 3.86 raw → 0.32 /12-amortized; full instance cost 126.5 M E-mult/layer (≈42/padded lookup incl. aux folding + tables + closures); corr bytes 7.64 MB/layer (mult vectors 3.87 MB — see deviations); layer PCS 2^24: commit 0.34 s one-off, **open 0.035 s**, verify 0.006 s; projections (P3.5 cost model, 49/98 claims): prefill **0.233 s**, per-response **0.345 s**. Run of record `benchmarks/results/p4-2026-07-06-8b4ca11.json` (clean tree, `git_dirty:false`; the 07-05 JSON was a dirty-tree run whose sha names the parent commit) |
| P5 GPT-2 e2e prefill 100 tok | **done** (2026-07-06) | one-command run ✓ (`scripts/run_prefill.sh`), golden check ✓ (full logits bit-exact vs numpy at T=100, argmax 835 ' way'), counts vs budget: witness lookups = budget **exactly** (16,944,000) ✓ | **accepted e2e with real weights + 13 real Ligero commitments**: native (witness) 0.459 s, prove 11.0–11.2 s, **ρ ≈ 24** (matches P4's ×12 projection); verify 0.65 s + 0.07 s PCS; PCS open **0.73 s** / 52.8 MB (vs 0.237 s projection — 13× fixed costs, see deviations), commit one-off 7.6 s; **comm 159.6 MB/prefill** (mult vectors 59.4 + PCS 52.8 + boundary 36.9 + rest), projected response 212 MB; E-mult all-in 100.6/budget lookup; peak RSS 2.86 GB. `benchmarks/results/p5-2026-07-06-e52ce79.json` (clean tree) |
| P6 decode + authenticated KV cache | **done** (2026-07-07) | flat cost/token ✓ **PASSED** (curve last/first 1.12 ≤ 1.5, 5×10 chunks, cache 100→150); anti-replay smoke ✓ (prefill-row replay + position swap rejected); golden decode ✓ (50 tokens bit-exact vs numpy) | **accepted e2e, prompt 100 + 50 decode, one two-phase session, real 13-commitment PCS with STACKED claims (96 weight + 6 embed)**: native decode 30.9 tok/s (KV-cached baseline); prove_response 18.7 s = prefill 10.5 s + **decode marginal 8.2 s (0.164 s/token, ρ_decode 5.07 CPU)**; verified 2.67 tok/s; verify 0.57 s + 0.10 s PCS. Comm: transcript 137.4 MB (prefill 48.4 + PCS opening 66.7 + decode marginal 22.3 = **445 KB/token**) + public band logits 20.5 MB → **total response download 157.9 MB** (inside the 150–200 MB product envelope; the PCS opening is now the dominant lever, P7). Shared-α restructure landed with P6: mult corr 59.4 → 2.85 MB. PCS commit one-off 9.5 s; peak RSS 3.47 GB. `benchmarks/results/p6-2026-07-07-515bb1c.json` (clean tree) |
| P7 report + GPU budget model | **complete: resident full e2e + publication artifact; correctness/communication/flat PASS, rho FAIL** (2026-07-13) | T=100+50/Q=200, clean 1+3: golden ✓, proof/verifier ✓, flat 0.950 ✓, packed 144.821 MB ✓, explicit resident cleanup 0 B ✓; same-host exact native anchor ✓; **rho prefill 3707.60 >10 FAIL, decode 95.60 >2 FAIL**; tables/figures, hardware/checksum manifest, synthetic shape sweep and Lean audit ✓ | A100 resident core median: prefill **64.296±0.329 s MAD**, response **121.156±0.373 s**, decode marginal **57.296±0.809 s**. Native GPU: prefill **17.342±0.062 ms**, decode50 **599.346±0.990 ms**. Online-accounted response 121.774 s; full response-session wall 123.928 s; representative session 5.998 s kernels + 89.055 s host residual, 945.442 MB H2D + 138.488 MB D2H, 211,709 sync, 5.405 GB peak GPU. Raw sources `p7-integrated-resident-2026-07-13-1fd5195.json` / `p7-gpu-native-inference-2026-07-13-1fd5195.json`; aggregate `p7-2026-07-13-2c836b3.json`. Mock-PCG remains non-production. |
| P7b iteration 2 resident-A100 orchestration | **closed as superseded diagnosis** (clean quick; no gate verdict) | Historical Thunder count gate retired by the 2026-07-14 provider deviation | Clean schema-6 quick at `61aafe8`: **39,201 sync** (-36.45% vs `bf66c8f`), **12,656,708 B H2D** (-49.19%), prefill 27.154 s, decode marginal 23.628 s. The run remains an immutable, ineligible Thunder diagnostic. Mock-PCG remains non-production. |
| P7b iteration 3 diagnosis | **Phase 0a/0b/0c complete; scheduler phase cancelled as provider-specific debt** (no gate verdict) | Host-call diagnosis closed; no further Thunder coalescing is on the critical path | Clean same-SHA `098b2f1` quick A/B: deferred-events median session wall **54.507 s** versus Thunder wall-only+counters **32.575 s**, event tax **21.932 s / 40.24%**. The RunPod A100 control is **3.768 s** at identical quick geometry and **15.651 s** full session wall; it selected the new provider but is not retroactively a gate claim. |
| P7b RunPod official rebaseline | **official valid FAIL: decode only; diagnosis complete** (2026-07-14) | Clean schema-6/ABI-28 T=100+50/Q=200 on exact `runpod-a100-v1`, counters-only, Rayon=8, 1+3, golden and communication invariants; prefill <=10 s, decode <=4 s, max per-repetition sync-wall/session-wall <=2%, H2D <=100 MB | `33e5fb4`: prefill **7.801 s PASS**, decode **6.794 s FAIL**, session **15.995 s**; sync-wall max **0.768% PASS** with 59,868 sync diagnostic; H2D **28.595 MB PASS**; packed response **144.821 MB PASS**; golden/accepted/flat 1.412 PASS. Separate non-gating `70f64d4` event attribution measures a **6.275 s decode-marginal kernel floor**: GEMM 4.820 s, LogUp 1.098 s, other 0.358 s. Provider-neutral kernel work is required; D2H host-call wall includes queued-kernel waits and is not an additive transfer cost. |
| P7b RunPod matrix-fold iteration | **official valid PASS; complete** (2026-07-14) | Unchanged `runpod-a100-v1` full gate contract after the preregistered ABI-neutral kernel fix | `ab3a03f`: prefill **2.631 s PASS**, decode **2.089 s PASS**, session **5.917 s**; sync-wall max **1.821% PASS** with the unchanged 59,868 sync; H2D **28.595 MB PASS**; packed response **144.821 MB PASS**; golden/accepted/flat 1.281 PASS. Proof, operation, correlation and communication counts are exact against `33e5fb4`; no scheduler, batching or protocol change was needed. Mock-PCG remains non-production. |
| Real-sVOLE fase-B hardening | **full parity candidate for the F_p lanes; default remains mock** (2026-07-15) | Clean P6 quick real accepts; exact counter/allocation/channel digests; mandatory malicious/channel tests reject/hold | `1d63923`: genuine two-party Ristretto OT→COPEe/IKNP→WYKW GGM/regular-LPN setup, hardened cited parameters. Per instance **22.483 s**, **31.261 MB** setup traffic (P→V 28.814 MB, V→P 2.447 MB); setup excluded from rho and response. Run `p6-quick-realpcg-2026-07-15-1d63923.json`. Default-flip criteria are proposed, not enacted. |
| Fase-B FLIP-READINESS | **complete for criteria (2)/(3); superseded by the 2026-07-16 fase-D decision** (2026-07-15) | Host-only setup speed pass ✓; production lifecycle/transport plumbing ✓; clean full T=100+50/Q=200 real-PCG parity record ✓ | `117df7d`: normal-session setup **8.451 s** (GGM 4.632, checks 1.334, OT-ext 0.963, LPN 1.496, base OT 0.025); chunked-session setup 8.609 s. Exactly **31,261,434 B/setup** unchanged. Full golden/normal/chunked/13-PCS/closure/malicious parity passes; packed response exactly **136,526,530 B**. Record `flip-readiness-2026-07-15-117df7d.json`. On 2026-07-16 the operational flip criterion (1) was waived with no replacement for that decision, (4) was accepted, and (5) was reserved for Part B; no independent-human-review assurance was thereby conferred. |
| C1 response-communication reduction | **complete: identity-seam `x_in` reuse only** (2026-07-15) | Clean full T=100+50/Q=200 CPU record; golden, normal/chunked acceptance, PCS/closure, exact bytes/counters and replay/preflight gates | `2a3d731`: **1,036,800** canonical aliases save **8,294,400 B**; transcript **129,119,408 B**, packed response **136,526,530 B**, auth corrections **59,545,008 B**. Prover/verifier sub correlations both **7,443,126**, full both **176,880**; PCS **66,733,504 B**, 96+6 claims, Q=200 unchanged. Median prove **18.653 s** (−0.086 s vs same-machine P6 record), verify **0.522 s** (−0.045 s); flat curve **1.219 PASS**. Record `benchmarks/results/c1-2026-07-15-2a3d731.json`, full SHA `2a3d7314bba35e18229af31c99f226c93ef12416`, `git_dirty:false`. |
| C2 Packed16 typed-lane real-PCG | **Candidate A rejected; Packed16 shelved** (2026-07-15) | Permanent costing record; implementation is not authorized | `docs/c2-packed-lane-pcg-design.md` remains the permanent record: the only sound realization costs about **1.55 GB** recurring setup traffic and **31--46 s** setup wall per session to save 32,486,400 B of response, about **47×** more bytes moved than saved. Revisit only with a cited construction on the order of tens of MB/session, or an explicit product decision that the envelope demands it. |
| Fase-D real-PCG default + scaling | **CLOSED; criterion (5) ENACTED, real default production-ready** (2026-07-17) | M10/AES/connection/default ✓; G1 ✓ G2 ✓ G2b ✓ G3 informative ✓; **G4-v2 PASS** | Tuple `(k3,n3,t3)=(6,520,000,117,440,512,1,792)`, `U3=110,918,718`; estimator min **199.599804 bits**, six-instance **197.014842**, connection floor **140.643699**. CPU G2 **38,371,465 B PASS**, G2b PASS, G3 **665,512,308** gross / **440.856 s** / **1,269,347,424 B** high-water PASS. Pod v2 `e95b839`: prefill **2.728 s PASS**, decode **1.582 s PASS**, H2D **88,139,652 B PASS**, packed **136,526,530 B PASS**, flat **1.219 PASS**, max absolute sync **0.123482 s <=0.150 PASS**; informative max ratio **2.238539%**. Pod G2 **110,918,718 / 38,371,465 B PASS**, setup **48.841 s**. Real/AES is default; mock is explicit test-only. |
| C3 PCS/logits communication | **C3b CLOSED; G1/G2/G3/G4 PASS** (2026-07-18) | G1 response <=115,000,000 B; G2 CPU ABBA <=+15% and pod <=5.6483791 s against pinned 4.911634 s; G3 full capability/adversarial parity; G4 fresh pod profile | `161fc59`: exact response **105,717,632 B**, PCS **43,273,888 B**, public logits **0 B**, L4 **57,840 B / 157,705,530 E-mult**. G1 CPU PASS, peak **8.629 GiB**, spool raw resident 0. G2 CPU **+14.5365% PASS**; pod **4.183011 s vs 5.6483791 s PASS**. G3 workspace/adversarial + both production leakage smokes PASS. G4 v3: prefill **2.536909**, decode **1.652746**, H2D **88,812,564 B**, max sync **0.114894647 s**, flat **1.228451**, all PASS. Post-fix CUPTI: **1,423,901** launches, 69 families, 0 drops; five new `private_argmax_*` families, none grid-x=1. |
| X0 MoE analytic design | **design complete; full-correlation proxy v2 propagated** (2026-07-20) | parameterized budget + D1--D4 + private-weight table + prerequisite/long-output/provider contracts; large-model values remain non-gating | gpt-oss-20b analytic 100+50 point: **485.360G MACs**, **41.800 GB i16 committed**, **371.881 MB** current-boundary corrections / **147.241 MB** k=4 shape, **417.268M / 687.568M** logical/padded lookups, **2,858,312 full**, **3,316** claims. Dense 8B: **1.076T MACs**, **617.081 / 189.459 MB**, **462,339 full**, **452** claims. |
| T1 boundary thinning | **CLOSED; M11 GREEN; G1/G2/G3/G4 PASS** (2026-07-19) | response <=85,000,000 B; corrections <=38,348,720 B; CPU ABBA <=1.05; pod 10 s / 4 s / 100 MB / 0.150 s / 1.5 | Clean `b14577e`: exact response **84,544,352 B**, corrections **38,348,720 B**, reducer/q bridge **22,848 / 672 B**. CPU ABBA **1.005222 PASS**. A100 v4 prefill **2.412064 s**, decode **1.618844 s**, H2D **67,618,556 B**, max sync **0.117210172 s**, flat **1.231125**, all PASS. Sub/full **4,793,590 / 181,933**, closures **21,667 / 8,170**, E-mult buckets **2,800,595,736.8 / 114,852,961.2**, exact. Both production leakage smokes PASS. R1 is deferred to Kimi3 and no review assurance is claimed. |
| X1 runtime foundation + routing soundness | **PASS; complete** (2026-07-19) | GPT-2 T1 byte-for-byte at **84,544,352 B** with exact counters/deterministic schedule digest/golden/workspace ✓; all route cheats reject; isolated E-mult/token-layer ratio in **[0.80,1.20]** ✓ | Foundation clean `9a4c688`. Routing clean `6be165f`: T=31, L=4, d=48, **3,968 logical / 4,096 padded**; measured **707.2774193548387** versus predicted **662.4056199596774 E-mult/token-layer**, ratio **1.0677406683202548 PASS**. One unchanged-P4 commitment/opening, 4 claims; exact sub/full **205,568 / 4,714**; all nine honest/cheating/preflight predicates green; record `x1-routing-2026-07-19-6be165f.json`. |
| X2 synthetic MoE e2e | **official valid FAIL; package stopped** (2026-07-19) | Honest k=1/k=2, identical bit-exact output, one TableBank, 3 commitments/40 claims, PCS/closures/digests/smokes all PASS; binding full-correlation ratios must be in **[0.80,1.20]** and are **0.731338 / 0.732512 FAIL** | Clean `87ce25b`: **316,464 MACs** exact; measured **12,523 logical / 19,346 padded lookup rows** and **82 sites** (same k=1/k=2); sub **350,304 / 349,793 PASS**; full **12,462 / 12,482** vs 17,040 FAIL. Record `x2-moe-2026-07-19-87ce25b.json`. |
| X2b corrected-proxy repeat | **PASS; complete** (2026-07-20) | Frozen `existing-class-session-v2`, same CPU fixture/code/smokes/exact invariants and same inclusive **[0.80,1.20]** band; X2 remains FAIL under its original 17,040 proxy | Clean `053d3fc`: full **12,462 / 12,482** predicted and measured, ratios **1.0 / 1.0 PASS**. MAC **316,464** exact; lookup logical/padded/sites **12,523 / 19,346 / 82**, sub **350,304 / 349,793**, all within band. Record `x2b-moe-2026-07-20-053d3fc.json`. |
| X3 non-GPT ops pack | **PASS; complete; X1--X3 package CLOSED** (2026-07-20) | Zero-tolerance Rust/numpy full-array bit-exact gate at non-power-of-two **T=7** and hidden **d=48**; honest proof accepts, nine permanent tamper/pad smokes reject, exact counter/digest/session predicates | Clean `7544f36`: **656,034 B**, zero differing golden bytes; **21,969 / 35,824** logical/padded lookup rows, 91 sites/9 contents/1 finalization, RoPE delta 0; sub/full/domains **1,065,887 / 15,802 / 6,573**, transcript **8,781,000 B**, E-equivalent **7,109,448.2**. Pad poison actively rejects with a detected nonzero zero-claim. Record `x3-ops-2026-07-20-7544f36.json`. |
| R1 adversarial cryptographic review | **DISPOSITION CLOSED; X4 design unblocked** (2026-07-20) | Report fixed to detached `f05d727`; zero CRITICAL/MAJOR, M1 fixed, N1--N4 disposed, N5 consolidated; report immutable and SHA-pinned | AI adversarial review only: **no independent human-review assurance; criterion (1) remains external**. Report SHA-256 `b4f05cdd19609975c736ca0f4955894f87b7a44150addb520fe4f5a8d7a93eb4`. X1--X3 delta review remains external and unperformed. |
| R1b X1--X3 delta + Ideal/X4 addenda review | **AI REVIEW DISPOSITION CLOSED; no independent assurance** (2026-07-20) | Detached `9b1ef2d`; zero CRITICAL/MAJOR, three MINOR, six NOTE; every finding explicitly disposed; criterion (1) remains external | Byte-identical report `docs/r1b-kimi3-report.md`, SHA-256 `a6d25a55c1220934666bf22f218740be1a9084243370fd031274dea2a222aa9f`. MINOR-1/2 docstrings corrected; MINOR-3 adopted; NOTE-1/3/5/6 actions pinned. The review is automated Kimi adversarial analysis, not human assurance. |
| X4 folding PCS Phase 1 (historical) | **SUPERSEDED BY R1B AMENDMENT 1; immutable design history** (2026-07-20) | Original no-list-decoding/G1--G6 preregistration retained for provenance | Historical `x4-zkdeepfold-v1`: `K`, rate `1/8`, `s=128`, **10.7008-TB** logical floor. Addended SHA-256 `3588d9f360960d46ad219309ba67645bd992a56d89ed1ae627f69f6d7ca9bb44`; original SHA `bb693bb4b1a06244d4f30f4b23cb47a64563dcaa21b5502b74adb044e6284464`. No gate verdict. |
| X4 R1b Amendment 1 + Phase-2 statement freeze | **AMENDED DESIGN/SOUNDNESS/LEAN STATEMENTS FROZEN; HARD STOP pending product-owner review** (2026-07-20) | Exact conservative response bound must prove before X4 Rust; all original G1--G6 and byte/wall gates remain conjunctive; no list-decoding credit | `x4-zkdeepfold-ud-e29-v2`: `E`, rate `1/8`, `s=128`, `mu_max=29`; **1,660 blocks / 3,320 claims**; gpt-oss floor **5.3504 TB**; GPT-2 unpadded first oracle **31,923,699,712 B**; direct M9 `B_touch+1`; `epsilon=8.3853234432654371e-26`, **83.30226403378921 bits, meeting the 78.809294874 target**. Normative v2 frames and separate binding/ZK/batch theorem statements frozen. Design SHA-256 `2f511ac162ed6fdfa88dcb7e43fb749ae7063acf4a4585e2693349c9f023f207`. No Lean proof or X4 gate verdict. |
| X4 Amendment 2 + Lean-first package | **LEAN GREEN; RUST PHASE AUTHORIZED** (2026-07-21) | Frozen statements prove; `lake build`; zero `sorry`/`admit`; derived audit green; no new axiom or `Ideal` dependency | `ResponseZeroBatchValid Delta a := a.Valid Delta /\ a.x=0`; strict rate-1/8 UD, split MLE, exact masked fiber count, one-opening state, canonical frames/cohort binding, scalar reductions, strict-UD folding, separate binding/ZK/batch seams, M9, event cover and LogUp characteristic premise all proved. Exact `x4ResponseError < 2^-83` and the **78.809294874-bit** target theorem are green. Full build **3250 jobs**; audit **132 targets** (39 in the X4 audit block), stdout SHA-256 `4c1c11d09f6da82f732de2455b8fa4ec622934c97103e7c072644ee689f5b83f`; only `propext`, `Classical.choice`, `Quot.sound`. Source SHAs: field `b57cb0acb469b9053ae9dbc65898a3c1437679b09b250fdff65f5d3594a47805`, PCS `d21d4dac4d351636c63b9481349f0fbafeb85e3bacf884c9f76fd362f22be846`. No Rust result or X4 gate verdict yet. |
| X4 Phase-2 concrete PCS discharge | **HARD STOP / FAIL TO DISCHARGE** (2026-07-21) | No weakening or axiom smuggling; `MaskedBatchBindsIntoMac` must be realized before M9 Rust | Deterministic one-block counterexample: `w=3,g=5,h=8,v=4,s=4`; PCS `h=w+g` and Amendment-2 ZeroBatch both accept while `h-s=4!=w`. The scalar MAC transfer authenticates a prover-chosen value but does not bind it to committed `g(u)`. Partial codec/N4/NTT/public-UD code has **22 diagnostic X4 tests** green; the package run executes **51 passed / 0 failed / 2 existing production-size C3 smokes ignored**. Re-audit: **3250 build jobs**, **133 total targets / 40 in the X4 block**, standard axioms only, stdout SHA-256 `de90480a5c17d970b041a6ada881e67a03ace04e24672cb9772485492b9617d2`. Diagnostic PCS source SHA-256 `da1d6b1aa6bd6357deec04bb4be2343ad344eb7b283f818a72370c78753b783a`; amended design SHA-256 `61eba70a23a619c6ab1d209dfa39bbe46c3e4d32387456418dd8654a896a8fa7`. No CPU/GPT-2/pod record and no gate verdict. |
| X4 Amendment 3 authenticated-output seam | **DESIGN/SOUNDNESS/LEAN STATEMENTS FROZEN; HARD STOP BEFORE PROOFS AND V3/M9 RUST** (2026-07-21) | Blind binding must be realized inside the opening; no clear target evaluation, promise, transcript assertion, new ideal axiom or uncounted resource | `x4-zkdeepfold-ud-e29-v3`: correction gives only `PendingAuxEval`; one blind `d<=30` batch proves `2*B_touch` atoms `Wext(z||0)+g(u)-h=0` and `g(u)-authS.x=0`, then the same committed fold/query opening alone yields `BoundAuxEval`. Seam correlations `B_touch+2d+1`, max **1,721**; link frame **1,029 B**, complete seam **107,319 B**; all-maximum X4 screen **98,001** full correlations. Remaining auxiliary fiber `|E|^(2^ell-1)` and max budget `131071>107648`. Exact error remains `3320*(9/16)^128 + 28,522,064,267,253/|E| = 8.3853234432654371e-26`, **83.30226403378921 bits**, margin **4.49296915978921 bits**. Design SHA-256 `07eb1f832367d84b70095e20addc29c136233a6940e32f56d58ac7251e9ca868`. No Lean/Rust/record/gate/pod work in this amendment. |
| X4 Amendment 3 Lean-first discharge | **HARD STOP / UNPROVABLE AS FROZEN** (2026-07-21) | No weakening or hypothesis smuggling; a statement change requires Amendment 4 | The deterministic `authenticated_output_link_produces_bound_aux` conclusion omits exclusion of the explicitly counted `LinkBad` event; `bound_aux_has_verified_origin` inherits the same issue. Fixed residuals `R0=1,R1=-1` cancel at `beta=1`, so the combined link and truthful terminal can accept while `authS.x!=committedAuxEval`. A temporary exact-rational Lean theorem kernel-checks this countermodel. No repository Lean/Rust source changed; baseline audit remains **133/40** and the permanent delta-shift theorem remains. No record, gate verdict or pod work. |
| X4 Amendment 4 statement conditioning | **LEAN GREEN; V3/M9 RUST AUTHORIZED** (2026-07-21) | Exact frozen statements prove; full build, zero-sorry/admit and enlarged derived audit green; no new axiom or hidden equality premise | Design SHA-256 `f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98`. Build **3251 jobs**; audit **163 total / 70 X4** (the historical **133/40** plus 30 v3 targets), stdout SHA-256 `4706e705abc1a8df3eeb96df41388c357f2006671cf90116c9c200f29d36d267`; only `propext`, `Classical.choice`, `Quot.sound`. V3 source SHA-256 `5a3367af7750158ed14c3e469ed58b9c8d918ee272dcf48fe89a1832bdc85dde`. Both permanent negative theorems are audited. Frame bytes **1,029/107,319**, correlations **1,721/98,001**, total coefficient **28,522,064,267,253** and **83.30226403378921 bits** remain unchanged. No Rust/record/gate/pod result yet. |
| X4 v3/M9 Rust + CPU synthetic / GPT-2 preflight | **G3 FAIL; HARD STOP BEFORE PRODUCTION REFACTOR, GPT-2 MIGRATION AND POD** (2026-07-21) | Gates are conjunctive and verbatim; no query/order, grammar, parameter, correlation, soundness or threshold change is permitted without a new amendment | G5/G6 synthetic evidence remains immutable. Clean G3 source `3aa5952`; record `x4-gpt2-g3-preflight-2026-07-21-3aa5952.json`, SHA-256 `a5d2f4ba189c27a7b39e8e0f0c66475057a6f15041483fbe2035bcc69afc4cb9`. With all auxiliary Merkle nodes assigned **zero bytes** and all post-initial polynomials granted one ideal shared chain, query frames alone are **4,021,594 B**; mandatory non-query fields make the strict lower bound **4,089,416 B > 4,000,000 B FAIL**. Projected response **45,359,880 B > 45,270,464 B**. Restoring canonical auxiliary nodes gives an optimistic one-chain shape of **15,814,716 B**. Soundness is unchanged at **83.30226403378921 bits**. G2/G4 and overall production security remain unevaluated; no pod is requested. |
| X4 Amendment 5 global packed opening | **DESIGN/SOUNDNESS/LEAN STATEMENTS FROZEN; HARD STOP BEFORE V4 LEAN-FIRST** (2026-07-21) | No threshold exception; pre-freeze materialized codec screen must pass; v3 seam and Amendment-4 disjunction remain mandatory | `x4-zkdeepfold-ud-e29-v4`: rate `1/8`, `s=111`, model-global same-domain cohorts, one different-size chain and digest-only derived frontiers. Exact error `3320*(9/16)^111 + 28,522,064,267,253/|E|`, **80.25537016399041 bits**, `<2^-80`. Clean screen source `93749b3`; record `x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json`, SHA-256 `ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499`: packed opening **2,615,414 B**, complete PCS **2,683,236 B**, response **43,953,700 B**, headroom **1,316,764 B**. This is pre-freeze eligibility, not a production G3 verdict. Storage/correlations remain **5.3504 TB / 31,923,699,712 B** and **1,721 / 98,001** maxima. Design SHA-256 `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7`. No v4 Lean/production Rust/migration/pod work. |
| X4 Amendment 5 product-owner discharge | **AUTHORIZED; PART 0 RULINGS + BIDIRECTIONAL EVENT CROSS-CHECK RECORDED; V4 LEAN-FIRST AUTHORIZED** (2026-07-21) | Gates verbatim; frozen profile invariants exact; every new failure/error term is re-summed before proof | The proposed 5--10% communication exception is **REFUSED**. V3's honest true-opening estimate remains **15,814,716 B** and raising only the 4-MB PCS cap would not have repaired it. V4 load-bearing invariants are rate `1/8`, `s=111`, response-wide claim union `<=3,320`, and exactly one schema-4 packed opening with **27,564 symbols plus all 67,930 real sibling digests**, with no digest deduplication or compression. The Rust/Lean cross-check has no orphan counter or event disjunct: the only accepting statistical owners remain Fold, ClaimReduce, LinkBad and ZeroBatch; delta-shift/beta-collision are diagnostic subclasses, while leakage/epoch/query-order breaches are named deterministic or ZK failures. The exact re-sum remains **80.25537016399041 bits** versus the **78.809294874-bit** floor; its approximately **1.44607528999041-bit** slack and one-query margin are not a reserve. Cross-check-annotated design SHA-256 `c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544`; the frozen theorem/profile baseline remains `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7`. No production G3 verdict is claimed by this ruling. |
| X4 Amendment 5 Lean-first discharge | **LEAN GREEN; SCHEMA-4/V4 RUST AUTHORIZED** (2026-07-21) | Exact frozen statements; full build; zero `sorry`/`admit`; derived audit; no new ideal axiom or surfaced error term | Checkpoint `d5227f2`: model-global slot/cohort binding, packed-to-explicit equivalence, seal-before-query typestate, one different-size chain, strict-UD `s=111`, separate binding/ZK/batch obligations, blind Pending-to-Bound seam, Amendment-4 `equality OR LinkBad`, permanent delta-shift/beta-collision artifacts, exact bytes/correlations and four-event response soundness all prove. Build **3,252 jobs**; audit **209 total / 116 X4** (46 new v4), standard axioms only. Exact `<2^-80` theorem and **78.809294874-bit** registered target pass with the unchanged **80.25537016399041-bit** expression. No Rust/record/G3/pod verdict yet. |
| X4 Amendment 5 v4 Rust + CPU synthetic | **RUST GREEN; G5 PASS; G6 PASS IN SYNTHETIC SCOPE; A100 PRODUCTION SURFACE PENDING** (2026-07-21) | Normative schema 4; N4 domains; seal-before-query; model-global cohorts; one different-size chain; blind M9; permanent tamper inventory; exact G6 accounting | Clean source `31fc866`. Full workspace tests are green (`volta-pcs` 69; `volta-proto` 109 passed / one historical production-size private-argmax test ignored; `p35` 13 passed / two production-size C3 smokes ignored); all 55 scoped X4 tests and seven report-validator tests pass. NOTE-6 `c3_weights` is not waived and remains first in pod preflight. Clean record `x4-v4-cpu-synthetic-2026-07-21-31fc866.json`, SHA-256 `e7d59d071bcf3f4e4e21458ed6a2dffb749e39e9cd7482c76a849e8e75c49f78`: touched family `1/2/4/8/16`, ABBA unopened-block ratio **1.0038429423095299 <= 1.05**, persisted/recompute responses byte-identical, exact logical traffic, peak RSS **78,823,424 B**, device/file traffic zero as declared. Ligero/v3 remains read-only and is refused by record-producing modes. No GPT-2 G4 or physical-production G6 verdict. |
| X4 Amendment 5 GPT-2 migration | **MIGRATION GREEN; G3 PASS; FULL G2/G4/G6 AND OVERALL X4 PENDING A100** (2026-07-21) | Golden 100+50 unchanged; production codec complete; validators re-baselined; historical rows immutable; exact byte gates | Clean record `x4-v4-gpt2-migration-2026-07-21-31fc866.json`, SHA-256 `d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e`: one schema-4 opening emits exactly **27,564 symbols and all 67,930 real sibling digests**, encoded SHA-256 `7326f1e47d87bf6858b7811a152a45530359b869bcd9abb30e34bcc4c9dd2a9b`; complete PCS **2,683,236 B <= 4,000,000 B PASS**, response **43,953,700 B <= 45,270,464 B PASS**, common headroom **1,316,764 B**. Golden output is bit-exact and every pinned historical artifact hash is unchanged. The **31,923,699,712-B** logical first-oracle floor is pinned but not materialized on CPU; the fresh A100 record must evaluate isolated wall and all physical traffic/RSS/VRAM before an overall verdict. |

Formal side note: **M9 (opening-into-MAC) proved 2026-07-04** —
`VoltaZk/OpeningMac.lean` (`opening_mac_sound`, error ≤ εΩ/|Ω| + 1/|F|,
composes with M3 via `hfin`; PCS binding as explicit hypothesis, axioms clean).
See the M9 row in `protocol-sketch.md`.

Formal side note: **M10 (connection-scoped shared-Delta composition) proved
2026-07-16** — `VoltaZk/Connection.lean` proves cross-response domain
non-collision under injective authorization nonces, transfers scalar M4 to
the enlarged domain, applies an `R`-linear union bound on one shared-Delta
tape after an explicit fixed-rest local-to-global lift, and composes fresh
all-coordinate correction hiding/M6 with a monotone one-time correlation
offset. `lake build` completes 2574 jobs; the audit finds zero
`sorry`/`admit`, no named ideal assumption, and only the standard Lean axioms
where required. See the M10 row and modeling boundary in
`docs/protocol-sketch.md`.

## Analytic budget (P0 pre-registration)

Generated by `scripts/budget_p0.py` — measured counts in P4/P5 are compared
against these; deviations > 20% must be explained here.

| Quantity | Count | Note |
| --- | --- | --- |
| Native integer MACs | 8.63 G | i16×i16→i64, incl. last-position logits |
| Authenticated values | 3,763,968 | boundaries only: K, V, block outputs (0.044% of MACs) |
| Correction bytes | 30.1 MB | **8 B/value, F_p-typed (M5)** — 2-byte packing is an open item, needs an authenticated carry bit |
| VOLE correlations | ~3.77 M | + O(10³) masks (73 GEMM sumchecks + RLC/Π_Prod) |
| Lookups total | 16.94 M | dominated by FFN: requant_ffn_up + gelu = 7.37 M/layer-group |
| — exp / scores / softmax | 2.20 M | causal 5050 pairs/head |
| — LayerNorm | 1.85 M | rsqrt + per-element requant |
| — requant (all GEMMs) | 9.22 M | |
| Verifier F_p² mults | 11.3 M | q=3 opening points via RLC, one streamed pass |
| Lookup / native-MAC ratio | 0.20% | lookups cost O(1) E-mults each (LogUp) |

Reading of the budget: authentication is structurally almost free (0.04% of
native work — the whole game is the *kernel* cost of producing corrections,
hence P1); prover-side protocol cost is dominated by LogUp over 17M lookups
and by the per-GEMM sumcheck passes, both O(few %) of native MACs if the
constant factors hold. That constant factor is what P3/P4 measure.

## Consolidated modeling boundaries (R1, 2026-07-20)

This is the single current inventory of R1's declared modeling boundaries;
historical entries remain append-only evidence, not competing definitions.

- **Single-process harness.** Prover and verifier roles share one process and
  address space in every prototype test and record. Deployment separation is
  modeled, not enacted.
- **Interactive designated verifier.** Challenges are verifier-side stream
  draws. The protocol is not Fiat--Shamir, and this package licenses no
  non-interactive transform.
- **In-process channel model.** The serialized channel accounts and parses
  frames already delimited by its in-process sender. Network truncation, EOF,
  bit flips and transport hardening are deployment concerns outside this
  harness.
- **GKWY assumption.** The fixed-key AES-128 MMO GGM PRG relies on the
  registered GKWY correlation-robustness assumption; that assumption is not a
  theorem proved by this repository.
- **Query-index modulo bias.** Ligero maps a uniform `F_p` draw with
  `value() % code_len`. Because `p = 1 (mod 2^15)` and
  `p = 1 (mod 2^17)`, residue zero is overweighted by approximately
  `1 + 2^-49` per query; over 120 queries the relative bias is approximately
  `2^-42`, negligible relative to but not included in the pinned
  78.809294874-bit response-wide proximity figure.

## Deviations / decisions log

- **2026-07-21 (X4 Amendment-5 v4 Rust, CPU records and GPT-2 migration
  complete; A100 boundary reached)**: clean implementation source checkpoint
  `31fc866631f008c339981e4de9b40862f7979302` implements the normative
  schema-4 grammar before record generation, N4-separated leaf/internal
  hashing, descriptor-ordered model-global same-domain cohorts, one
  different-size chain, and a sealed-chain typestate that makes the exact-bit
  query tape unavailable until every commitment is fixed.  The blind M9 path
  carries `PendingAuxEval` into `BoundAuxEval` through the commitment's own
  fold/query checks and Amendment-4's `equality OR LinkBad`; no clear target
  evaluation, prover promise, second opening or transcript assertion was
  added.  Streaming supports both retained and twice-recomputed
  oracle/Merkle paths with exact G6 counters.  Ligero and v3 remain available
  only for historical read verification and every v4 record-producing mode
  rejects them.

  The permanent Rust inventory covers all 17 bidirectionally registered
  families, including query-before-seal, PendingAuxEval escape/leakage,
  delta-shift and beta-collision.  The full workspace is green: `volta-pcs`
  runs **69 passed**, `volta-proto` runs **109 passed / one ignored**, all
  **55** scoped X4 tests pass, and `pytest -q tests/test_report.py` runs
  **7 passed**.  The `p35` integration target runs **13 passed / two ignored**
  production-size C3 smokes (`c3_embed` and `c3_weights`); the latter carries
  the still-pending NOTE-6 requirement, is not waived and remains first in
  the pod preflight.  PCG allocation and connection lifecycle are unchanged.

  The append-only clean CPU record is
  `benchmarks/results/x4-v4-cpu-synthetic-2026-07-21-31fc866.json`, SHA-256
  `e7d59d071bcf3f4e4e21458ed6a2dffb749e39e9cd7482c76a849e8e75c49f78`.
  Its `1/2/4/8/16` touched-block family has exact serialized/accounting
  equality, its same-process `A/B/B/A` unopened-block ratio is
  **1.0038429423095299 <= 1.05 PASS**, and retained versus recomputed proof
  responses are byte-identical.  Peak CPU RSS is **78,823,424 B**; every
  logical source/oracle/Merkle read/write is reported, while file traffic and
  device traffic are explicitly zero for this in-memory synthetic run.
  Therefore G5 is **PASS** and G6 is **PASS in the synthetic scope** only.

  The append-only clean migration record is
  `benchmarks/results/x4-v4-gpt2-migration-2026-07-21-31fc866.json`, SHA-256
  `d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e`.
  The production encoder/decoder materializes one complete schema-4 response
  envelope with **27,564 symbols**, all **67,930 real sibling digests**, and
  encoded SHA-256
  `7326f1e47d87bf6858b7811a152a45530359b869bcd9abb30e34bcc4c9dd2a9b`.
  The byte counter and serialized length both equal **2,683,236 B**, so the
  **4,000,000-B PCS gate is G3 PASS** with **1,316,764 B** headroom.  Adding
  the frozen **41,270,464-B** non-PCS component gives the measured exact
  **43,953,700-B response <=45,270,464 B PASS**, with the same headroom.
  Golden decode remains bit-exact for prompt 100 plus 50 generated tokens;
  every pinned v3/preflight/Amendment-5 historical SHA is unchanged and no
  historical row or profile was mutated.  Both new report validators accept
  the records from repo-root or absolute paths.

  This work surfaces no fifth accepting event, union member or new hybrid.
  The required re-sum therefore has zero new terms and remains exactly
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`,
  **80.25537016399041 bits**, above the **78.809294874-bit** floor.  G1 is
  **PASS** from the frozen Lean discharge.  Migration/golden and synthetic
  G2 checks pass, but the full-size authenticated GPT-2 opening was not
  falsely simulated on the CPU VM: full-production G2 is pending.  G4 is
  **NOT EVALUATED**; production physical G6 is **PARTIAL/PENDING** because
  the **31,923,699,712-B** first oracle has not yet been materialized; overall
  X4 is **NOT EVALUATED UNTIL THE A100 RECORDS**.

  Before any pod measurement, the fresh profile is preregistered as
  `runpod-a100-x4-v1`.  It inherits the official `runpod-a100-v1` A100-SXM4
  80GB hardware/software envelope and uses `RAYON_NUM_THREADS=8`, a clean
  tree, wall-only+counters with no CUDA-event timing, one warmup plus three
  recorded candidates, and the unchanged Section-5.3 ceilings: isolated
  commit/open/verify **15 s / 1.50 s / 0.25 s**, resident prefill/decode
  **10 s / 4 s**, H2D **100 MB**, maximum synchronization **0.150 s**, and
  flatness **1.5**.  It is bound to profile
  `x4-zkdeepfold-ud-e29-v4`, design SHAs
  `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7` /
  `c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544`,
  implementation baseline `31fc866`, the two record hashes above, exact response
  **43,953,700 B**, PCS **2,683,236 B**, `rate=1/8`, `s=111`, and the
  complete `27,564/67,930` opening.  The artifact policy is to persist
  coefficients and roots, rebuild and root-check queried model-global
  cohorts, and report every physical artifact/host/H2D/D2H/RSS/VRAM byte and
  wall; no hidden whole-model GPU oracle is allowed.  NOTE-6 runs first.
  Any later pod-harness-only descendant must be clean and SHA-pinned in the
  ledger before its first measurement; a protocol/codec/reference change
  reopens preregistration.
  Provisioning requires the A100 profile and at least **100 GB** of persistent
  volume for weights, the approximately 32-GB oracle and scratch artifacts.

  Named backlog, mandatory after X4: **R1c -- Kimi3-style adversarial review
  of the new PCS code, against a frozen baseline and with a hostile mandate**.
  Its scope includes the entire v3/v4 seam and Amendment-4 episode already
  pinned above.  It remains honestly labeled AI adversarial review with no
  independent-human assurance; after X4 this PCS is the only cryptographic
  surface not yet inspected by hostile eyes.

- **2026-07-21 (X4 Amendment-5 exact Lean-first checkpoint GREEN; schema-4
  v4 Rust gate opens)**: `lean/VoltaZk/X4FoldingPCSV4.lean` proves the exact
  Section-0.12.6 freeze against the unchanged frozen baseline SHA-256
  `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7`
  (cross-check annotation SHA-256
  `c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544`).
  The proof set covers `s=111` and the field/mask budgets; schema-4
  round-trip, canonicality and kind separation; derived packed schedules and
  compact-to-explicit leaf-hash/verification equivalence; the sealed-chain
  query-order typestate; model-global cohort and descriptor-slot binding; the
  same-domain reduction and one different-size global chain; strict-UD
  folding; and separate binding, ZK and different-size batch obligations.

  The authenticated-output seam retains raw verification semantics and the
  Amendment-4 `authenticated equality OR LinkBad` conclusions.  The good-tape
  theorem excludes the complete delta-shift class, while accepted shifts flow
  into exactly link, fold/query or response-ZeroBatch bad events.  Both the
  delta-shift and beta-collision negative artifacts remain permanent audit
  targets.  The response cover contains exactly Fold, ClaimReduce, LinkBad
  and ZeroBatch, matching the pre-proof two-way table.  No fifth event,
  union-bound member or hybrid step surfaced, so the mandatory re-sum remains
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`, or
  **80.25537016399041 bits**.  The exact `<2^-80` theorem and the
  **78.809294874-bit** registered-target theorem are kernel-checked; no slack
  was silently consumed.  Closed arithmetic also proves **2,615,414 B**
  packed opening, **2,683,236 B** complete PCS, **43,953,700 B** response and
  the unchanged **1,721 / 98,001** correlation maxima.

  `lake build` completes **3,252 jobs**.  Repository Lean sources contain
  zero `sorry`/`admit`; the v4 file adds no `axiom` or `opaque`, and
  `Ideal.lean` is unchanged.  The derived audit is green at **209 total /
  116 X4 targets**, retaining the historical **163/70** set and adding 46 v4
  targets.  Its normalized complete stdout SHA-256 is
  `bebd24b6ae82e0716fa4fa5d5c3d8b5c69e31da0b95c5536503dd78f43fed43a`;
  dependencies are limited to `propext`, `Classical.choice` and `Quot.sound`,
  with no `Ideal` dependency.  The audit harness now losslessly joins a
  pretty-printer line wrap inside the long permanent beta-collision axiom
  list before applying the same exact-name dependency checks; this is a
  parser repair, not a relaxed audit rule.

  Source SHA-256 values are
  `ef31e29bece594e60550e32ef26dca1fbd0d0ef0bb97d8ea0e22f5aa92f51a82`
  for `X4FoldingPCSV4.lean`,
  `0e63b38497d07c9a8351e6de38b420acbf294151e88266fe1e5185f57d5b8575`
  for `Audit.lean`,
  `b77b40f133715cab77469120d41f10b600b6f77690c6a41b40101e212bdeba05`
  for the aggregate import and
  `be363037aa346cbf58aa66ad5068d00a525e194dba4086afb061e40681e7ca86`
  for the derived-audit script.  The Lean checkpoint is
  `d5227f2904dbaad5dcfac3c68d2aa6379b2a557a`.  This clears only the ordered
  normative-grammar/v4 Rust phase.  No CPU, GPT-2, production G3 or pod result
  is claimed; pod and NOTE-6 ordering remain unchanged.

- **2026-07-21 (Amendment-5 discharge authorized; product-owner rulings
  recorded before Lean/Rust work)**: the requested 5--10% communication-gate
  exception is **REFUSED**.  V3 remains an honestly measured superseded
  candidate: its strict zero-sibling lower bound is **4,089,416 B**, while its
  optimistic canonical true-opening shape is **15,814,716 B**.  Raising only
  the 4,000,000-B PCS cap would not have repaired that candidate, and neither
  the PCS cap nor the **45,270,464-B** absolute response ceiling moves.
  Amendment 5 is the sole authorized resolution; gates are never relaxed.

  The frozen `x4-zkdeepfold-ud-e29-v4` profile has the following
  load-bearing invariants: rate exactly `1/8`; query count exactly `s=111`;
  response-wide claim-count union bound at most `3,320`; and exactly one
  schema-4 packed opening containing **27,564 `E` symbols and every 67,930
  real sibling digest**.  The grammar permits no digest deduplication,
  compression, zero-byte authentication path or alternate count.  A breach
  of any listed invariant reopens preregistration and may not be absorbed as
  an implementation detail.

  The exact pinned expression is
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`, evaluating to
  **80.25537016399041 bits** against the **78.809294874-bit** response-wide
  floor.  Its approximately **1.44607528999041-bit** margin and the fact that
  `s=111` is exactly one query above the minimum are not an implicit error
  budget.  Every additional failure event, union-bound member or hybrid step
  surfaced during Lean discharge must first be named and re-summed in the
  design document against the same floor.  A re-sum below the floor is a
  hard stop, never a rounding disposition.

  **Mechanical two-way event table (completed before proof effort).**  The
  source inventory is the existing v3 `FrameError`, `FoldingError`,
  `AuthenticatedOutputError`, security metrics and permanent tamper tests,
  extended by the frozen schema-4 packed/global-chain classes.  The complete
  per-subclass table and reverse pass are in Section 0.12.8 of the design;
  the ledger-level bijection is:

  | Rust accepting-event counter | Lean response disjunct | Exact charge |
  | --- | --- | ---: |
  | `fold_query_bad` | `X4FoldBadV4` (and `X4FoldQueryBadV4` in the delta cover) | `3320*(9/16)^111 + 28,522,064,111,120/q` |
  | `claim_reduce_bad` | `X4ClaimReduceBadV4` | `151,060/q` |
  | `auth_link_bad` | `LinkBadV4` / `X4AuthenticatedOutputLinkBadV4` | `3,412/q` |
  | `response_zero_batch_bad` | `X4ResponseZeroBatchBad` | `1,661/q` |

  Reverse checking finds every event disjunct in both Bound-output theorems,
  `accepted_delta_shift_event_cover_v4`,
  `x4_wrong_response_event_cover_v4` and `x4_response_soundness_v4` in this
  table.  `delta_shift_attempt` maps to the already counted
  link/fold/ZeroBatch disjunction; `beta_collision_witness` maps to
  `auth_link_bad`.  `pending_escape_reject`, `target_eval_leak_reject`,
  `correlation_view_reject`, `epoch_reuse_reject`, frame/packed/N4 rejects
  and query-before-seal rejects are pre-acceptance typestate, canonicality or
  ZK invariants and add no rational term.  There is no fifth accepting event
  and no newly surfaced hybrid.  The mandatory re-sum is therefore unchanged:

  `3320*(9/16)^111 + (28,522,064,111,120 + 151,060 + 3,412 + 1,661)/q`
  `= 3320*(9/16)^111 + 28,522,064,267,253/q`, or
  **80.25537016399041 bits**, still **1.44607528999041 bits** above the floor.
  The cross-check changes no statement shape, protocol, parameter, byte,
  correlation or gate.  The annotated design SHA-256 is
  `c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544`;
  the frozen Amendment-5 theorem/profile baseline remains SHA-256
  `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7`.
  Section 0.12.6 itself is byte-identical before/after the annotation, with
  subsection SHA-256
  `c9f1246b32e5f20459ba00652cf1d1554face1da2cdc3b01c487671a39860aaa`.
  V4 Lean-first is now authorized under the standing exact-statement rule.

- **2026-07-21 (Amendment 5 authorized; v3 is a superseded infeasible
  candidate, not a near pass)**: the v3 G3 verdict and evidence remain
  unchanged: clean record
  `benchmarks/results/x4-gpt2-g3-preflight-2026-07-21-3aa5952.json`, SHA-256
  `a5d2f4ba189c27a7b39e8e0f0c66475057a6f15041483fbe2035bcc69afc4cb9`,
  proves a **4,089,416-B strict lower bound > 4,000,000 B** before any real
  auxiliary Merkle-node bytes.  Its permanent negative test and the
  production late-query defect remain audit artifacts.  The frozen
  `x4-zkdeepfold-ud-e29-v3` candidate is therefore **SUPERSEDED FOR DESIGN
  EVALUATION** and receives no “near pass” or implementation credit.

  No 5% or 10% communication exception is taken.  The lower bound deletes
  the dominant authentication paths, the optimistic canonical one-chain
  shape is **15,814,716 B**, and the absolute **45,270,464-B** response
  ceiling remains untouched; relaxing only the 4-MB component cap would not
  make the real candidate viable.  Amendment 5 instead authorizes a new
  candidate configuration inside the cited strict-unique-decoding
  BaseFold/DeepFold family.  The design evaluation must itemize leaf payload,
  path/aux-node bytes and the `s=128` multiplier; screen the suspended
  commit-before-query typestate, globally shared canonical cohort/fold
  machinery and a `(rate,s)` re-resolution in the allowed direction of more
  oracle/prover work for less communication; and run the closed byte model
  against the normative codec before selecting a candidate.

  Every screen recomputes response-wide soundness from scratch at no less
  than **78.809294874 bits**, uses only strict unique decoding, and re-derives
  all block, root, frame, correlation, storage and traffic counts.  The v3
  `PendingAuxEval -> BoundAuxEval` binding semantics and Amendment-4
  `authenticated equality OR LinkBad` conclusions remain mandatory or must
  be separately re-proved.  No Lean proof, production Rust, benchmark
  reference, historical record, PCG/lifecycle change or pod work is
  authorized during the amendment.  After the Amendment-5 design and
  pre-freeze byte check are recorded, work hard-stops for review before
  Lean-first.  Any future pod remains after green Lean, amended M9, CPU
  records and GPT-2 migration, with NOTE-6 `c3_weights` first in preflight.

  The comparative pre-freeze screen is preregistered before execution.  It
  evaluates inverse-power-of-two rates `1/8`, `1/16` and `1/32`; for each row
  it first derives the smallest integer `s` meeting the complete response-wide
  bound, then also reports the next integer as a margin row.  The corresponding
  maximum physical-block variables are `29`, `28` and `27`, so that
  `mu+1+rate_log2=33` and no unavailable root of unity is assumed.  Query
  tapes use BLAKE3 XOF derive-key context
  `volta-zk/x4/amendment5-gpt2-preflight/v1` and input
  `candidate-id|gpt2-small|102-claims|2026-07-21`, with one exact
  `max_domain_log2`-bit little-endian draw per repetition.  A candidate uses
  model-global, descriptor-ordered same-domain cohorts and the Section-5.1
  different-size activation rule to obtain one fold chain.  The compact
  opening encoding may elide only indices, leaf metadata and auxiliary-node
  positions deterministically reconstructed from the committed manifest,
  transcript query multiset and round schedule.  It must serialize every
  opened `E` symbol at 16 bytes and every required Merkle sibling digest at 32
  bytes; it receives no cross-tree digest deduplication, zero-byte path,
  list-decoding or compression credit.  Exact byte vectors, a closed-form
  cross-check, per-term counts and ordered-draw digests are required in the
  append-only preflight record before a row can be frozen.

  **Freeze result.**  Amendment 5 selects the next-integer margin row
  `x4-zkdeepfold-ud-e29-v4`, `rho=1/8`, `s=111`; the mathematical minimum is
  `s=110`, while `s=109` fails the response-wide floor.  The selected exact
  expression is
  `3320*(9/16)^111 + 28,522,064,267,253/|E|`, evaluates to
  **80.25537016399041 bits** and proves the clean `<2^-80` target.  Lower
  rates are rejected: `1/16,s=101` saves only 57,600 B while doubling the
  first-oracle floor, and `1/32,s=96` saves only 95,509 B while quadrupling
  it.

  V4 explicitly overrides D3's physical per-layer cohort-root choice with
  model-global same-domain roots; logical namespaces, descriptor identities,
  expert-block openability and touched-block proportionality remain.  One
  DeepFold different-size activation chain is sealed before queries.  The
  schema-4 packed opening serializes all 27,564 selected-tape symbols and all
  67,930 required sibling digests, while deriving their coordinates and
  typed leaf/node metadata.  It gives **2,615,414 B** plus the unchanged
  **67,822 B** non-query material: **2,683,236 B PCS** and
  **43,953,700 B response**, both with **1,316,764 B** headroom.  There is no
  cross-root deduplication or zero-byte path credit.

  The clean source is
  `93749b3878ea517602eee06a8d46a201b7cb3346`; append-only record
  `benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json`
  has SHA-256
  `ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499`.
  The reference encoder is design-only, so this is mandatory pre-freeze
  eligibility rather than a production G3 verdict.  The frozen design and
  exact v4 Lean statements have SHA-256
  `1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7`.
  Maximum mask budget is **93,351 < 131,071**; correlations, first-oracle
  floors, blind `PendingAuxEval -> BoundAuxEval` semantics and Amendment-4
  `equality OR LinkBad` flow are unchanged.  R1c now explicitly includes the
  physical-layout override, compact-to-explicit hash equivalence, global
  activation/late-query episode and this parameter screen.  Work hard-stops
  before v4 Lean-first.  The pod order and NOTE-6 smoke remain unchanged.

- **2026-07-21 (X4 GPT-2 G3 FAIL; frozen profile hard stop before production
  refactor/migration/pod)**: clean source
  `3aa5952ae0c07f2e933f2f1d5d8a8d9006ed4815` produced append-only record
  `benchmarks/results/x4-gpt2-g3-preflight-2026-07-21-3aa5952.json`, SHA-256
  `a5d2f4ba189c27a7b39e8e0f0c66475057a6f15041483fbe2035bcc69afc4cb9`
  (`git_dirty:false`).  The preregistered 128-draw XOF schedule has ordered
  draw-vector BLAKE3 digest
  `26414df2b8fc443cc3171e762eca23788e0bfc7c48016cc250be42a115d0d02b`.
  The production geometry is **51 physical blocks / 102 fixed claims / 26
  cohort ids / 52 initial weight-or-auxiliary roots**; the two tied-WTE roles
  remain separate descriptor slots so no block exceeds two phase claims.

  The screen grants more compression than any implemented proof: all 52
  mandatory initial roots remain, but every post-initial polynomial receives
  one shared maximum-depth fold chain and every 50-byte auxiliary Merkle-node
  entry is deleted.  The resulting initial query frames are **3,140,532 B**
  and the one ideal shared chain's query frames are **881,062 B**.  Thus the
  query frames alone have strict lower bound
  `3,140,532 + 881,062 = 4,021,594 B`, already **21,594 B** above G3.  The
  mandatory envelope/descriptors/manifest/claims/`h`/M9/link/fold/ZeroBatch
  fields add **67,822 B**, giving
  **4,089,416 B > 4,000,000 B FAIL** by **89,416 B** and an absolute response
  lower bound **45,359,880 B > 45,270,464 B FAIL** by the same amount.
  Restoring the exact canonical auxiliary-node counts gives an optimistic
  one-chain shape projection of **15,814,716 B**; it is not mislabeled as a
  serialized honest production proof and is not needed for the verdict.

  `cohort_multiproof_byte_count` is checked byte-for-byte against the
  normative v3 codec and an actual small N4 cohort opening.  A permanent
  preflight test pins the query digest and all three lower-bound totals.
  `cargo test --workspace` is green, including **48/48** `volta-pcs` tests,
  the delta-shift and beta-collision negative artifacts, the new accounting
  tests and both GPT-2 golden checks; the two production-size C3 leakage
  smokes remain deliberately ignored on this host.  Targeted clippy adds no
  warning in the new X4 files; repository-historical warnings prevent a
  workspace `-D warnings` claim.

  This is a gate verdict, not a parameter amendment.  `rho=1/8`, `s=128`,
  field `E`, all frame widths, correlations, PCG/lifecycle and the exact
  response-wide expression remain unchanged; the record reproduces
  **83.30226403378921 bits**.  Because gates are conjunctive, the frozen v3
  candidate cannot proceed.  The late-query typestate defect therefore
  remains recorded but is not refactored into a product path that already
  fails G3.  GPT-2 roots/references and historical rows remain untouched;
  G2/G4 and overall production security are not evaluated.  No pod is
  requested, and NOTE-6's `c3_weights` smoke remains first in preflight only
  if a future authorized amendment produces a viable candidate.

- **2026-07-21 (X4 implementation audit I3; production opening reopened before
  GPT-2 migration)**: read-only migration preflight found that
  `prove_authenticated_output_link_production` received complete
  `UdChallenges`, including all query draws, before it constructed the fold
  roots.  Although the honest function happened to compute roots before
  reading those fields, the API could not realize the frozen interactive
  order `fold commitments < exact verifier query draws`; an adaptive prover
  was structurally given the query set too early.  The schema-3 design already
  requires late queries, so the authorized repair is an implementation
  typestate split: first fix every link/fold commitment, then release exact
  fresh verifier bits, then produce query answers.  No frame, byte field,
  correlation, parameter, soundness coefficient or Lean statement may move.
  The source checkpoint `c56acd7` is therefore superseded as a
  security-complete implementation checkpoint, while its tests and the clean
  CPU record remain immutable evidence.

  The same preflight instantiated the frozen GPT-2 constraints before any
  migration code: 102 fixed claims and `claimCount<=2` imply **51 logical
  blocks** (48 layer blocks plus token embedding, positional embedding and a
  separate tied-unembedding role), with **26** namespace/size cohort ids and
  **52** weight/auxiliary roots when oracle kind is counted.  The current
  one-fold-chain-per-root layout projects about **42.8 MB** before the small
  envelope categories, far above G3's 4,000,000-B ceiling and not the frozen
  cross-cohort batch.  This number is a diagnostic obstruction, not a gate
  verdict or a new reference.  The implementation must share the permitted
  fold/query machinery across cohorts and then serialize the exact canonical
  preflight.  If the conforming closed formula still exceeds 4,000,000 B,
  G3 is recorded FAIL and work stops before provisioning a pod; the threshold
  will not be tuned or reinterpreted.

  The decisive preflight challenge schedule is preregistered before its
  implementation: read 128 consecutive little-endian `u32` words from the
  BLAKE3 derive-key XOF with context
  `volta-zk/x4/gpt2-g3-preflight/v1` and input
  `x4-zkdeepfold-ud-e29-v3|gpt2-small|102-claims|2026-07-21`, then retain the
  low 30 bits of each word.  Lower domains use the corresponding low exact
  bits, preserving uniform-with-replacement semantics.  This is a fixed,
  reproducible admissible query witness for the absolute “at most” gate, not
  a replacement for fresh production verifier randomness.  The first screen
  deliberately gives the protocol every advantage: one shared maximum-depth
  post-initial fold chain and **zero bytes for every auxiliary Merkle node**.
  It counts only canonical frame structure and opened leaf payloads.  If even
  that strict lower bound exceeds 4,000,000 B, no v3 implementation can pass
  G3 without a protocol/grammar/parameter amendment, so the late-query Rust
  refactor and all later migration/pod work stop.

  The clean synthetic record remains valid for its stated scope: its honest
  roots were fixed before its measured answers, its byte/G6 formulas and
  ABBA observation do not depend on adversarial query unpredictability, and
  it claimed neither G1/G2 production security nor GPT-2 G3/G4.  No
  historical JSON, root or profile is mutated.

- **2026-07-21 (X4 clean CPU synthetic record; G5/G6 PASS)**: clean SHA
  `12bfbe2d150f8e4c3cf32f619b49671f47024045` produced append-only record
  `benchmarks/results/x4-cpu-synthetic-2026-07-21-12bfbe2.json`, SHA-256
  `da2a09a69224df5b17c05bfc5d085604ab8345a9da5f7492090eecc78f0a8bfa`
  (`git_dirty:false`, four Rayon workers, Apple Virtualization Generic
  Platform, strict rate 1/8, `s=128`).  The record preserves design SHA
  `f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98`,
  the exact response-wide expression and **83.30226403378921 bits**.

  **G5 PASS.**  The canonical one-envelope lengths for `1,2,4,8,16`
  touched blocks are respectively **996,187 / 1,014,489 / 1,076,814 /
  1,227,185 / 1,553,648 B**.  Every component sum equals the serialized
  length.  Source reads are exactly the canonical touched coefficients;
  extension, ZK auxiliary, encoded and folded traffic are separate fields.
  At eight touched blocks, doubling only total blocks from 16 to 32 changes
  serialized length by exactly **25,721 B**: 121 manifest bytes plus 25,600
  cohort-query path bytes, with every other component unchanged.  One warmup
  per side and three same-process A/B/B/A cycles give upper medians
  **0.0424917535 / 0.042936816 s**, ratio
  **1.0104740911668897 <= 1.05 PASS**.

  **G6 PASS for the recorded synthetic scope.**  The 16/32-block logical
  first-oracle totals are **4,194,304 / 8,388,608 B**, Merkle digests
  **17,301,440 / 34,078,656 B**, retained logical payload
  **26,214,400 / 51,904,512 B**, and largest-cohort working sets
  **13,369,312 / 26,476,512 B**; exact formulas reconcile.  Persisted,
  recomputed, host-transfer and device-transfer fields are explicitly zero
  because this fixture retains both in-memory CPU cohorts; the permanent
  recompute test proves root and proof byte identity.  Measured peak RSS is
  **0.101108551 GiB**.  This record grants no GPT-2 G2/G3/G4, production
  wall, full-model storage or overall X4 verdict.  The next authorized step
  is the append-only GPT-2 migration on the same frozen semantics; pod and
  `c3_weights` preflight remain later.

- **2026-07-21 (X4 v3/M9 Rust checkpoint GREEN; manifest inclusion
  clarification I2)**: checkpoint `c56acd7` implements the frozen schema-3
  frame grammar, strict rate-1/8 weighted UD fold/query opening, the blind
  authenticated-output link, opaque `PendingAuxEval`/`BoundAuxEval`
  typestate, one-opening `(model_root,epoch)` permit, response ZeroBatch,
  G6 persist/recompute accounting and a CPU synthetic record harness.  The
  commitment's own weighted query verification returns only the aggregated
  terminal value; no individual `W`, `g`, `v` or prover-supplied `s` is a
  proof field or a Bound constructor input.  The M9 link consumes exactly
  `B_touch+2*d+1` full correlations including response ZeroBatch and keeps
  the frozen 1,029/107,319-byte maxima and 83.30226403378921-bit expression.

  The normative `0x04`/`0x05` grammar contains descriptor leaves and Merkle
  nodes but no separate wire kind for a layer-root carrier.  The concrete
  fail-closed interpretation is therefore one canonical ordered model
  manifest over the verifier-known complete descriptor list; each leaf binds
  its complete descriptor digest and ordered cohort roots, while namespace,
  layer and cohort identity remain inside the descriptor and cohort trees.
  `model_root` is that manifest root.  The prose's layer manifests are logical
  namespace groupings, not an additional unencoded tree level.  Verification
  now reconstructs depth/index from the complete ordered statement, requires
  every touched descriptor leaf and a deduplicated exact ancestor set, and
  rejects leaf/node/type/depth/index/root substitutions.  This closes an
  inclusion-check gap in the earlier diagnostic code; it adds no frame,
  field, transcript message, parameter, correlation, soundness term or byte
  category and does not change the frozen design SHA.  R1c seam scope includes
  this concrete model-root interpretation.

  `cargo test -p volta-pcs x4::` is green at **32/32**, including public-h,
  descriptor, M9 correction, round-domain/correction, terminal tag,
  fold/query, auxiliary root, response ZeroBatch, whole-class sampled
  delta-shift and beta-collision artifacts.  `cargo test --workspace` is
  green, including the existing GPT-2 T=100/decode goldens and unchanged
  PCG/lifecycle suites.  Clippy reports no new X4 warning; twelve warnings in
  historical Ligero code remain outside this checkpoint.  Source SHA-256
  values are `4e669c41eaa76f045f59a18febb23ef4d339b9211d7c9d21d6c243d522dbb219`
  for `frame.rs`,
  `018ab6813d67c196912809ad6d015d27e280a101bd401f58a1c7893cf5af0951`
  for `folding.rs`,
  `31fa133d626f47e4439e542d317da596c0000454de864e10eabd8e7002352559`
  for `authenticated_output.rs`,
  `5276e8e8ba25666e24ae2053d6a5b2ff50d46c62bf04efb5ed393a9e3d7c3d73`
  for `artifacts.rs`, and
  `c1bc895976d03fb855a3c15f72af2b90cc3c6a04c6db16f2a87133f193e2e395`
  for `manifest.rs`.  A pre-checkpoint tracked-dirty quick run reported exact
  formulas, synthetic G5/G6 PASS and same-process ABBA
  `0.9908910332983634 <= 1.05`; it is diagnostic only.  The next step is a
  clean append-only CPU synthetic record, followed by the frozen GPT-2
  migration.  No X4 gate or pod verdict is claimed, and the production-size
  `c3_weights` smoke remains deferred to the later pod preflight.

- **2026-07-21 (X4 Amendments 3--4 exact Lean-first checkpoint GREEN; v3/M9
  Rust gate opens)**: the new module `lean/VoltaZk/X4FoldingPCSV3.lean`
  proves the frozen correction-view bijection and unique preimage, conditioned
  auxiliary-fiber count, entropy budget, blind link ZK composition,
  Pending-to-Bound origin, Amendment-4 `equality OR LinkBad` conclusions,
  one-batch soundness, schema-3 codec, cohort/strict-UD binding, whole-class
  delta-shift exclusion and named-event cover, MAC transfer, separate full ZK
  composition, exact byte/correlation arithmetic, four-event response cover
  and the response-wide soundness target.  Raw
  `VerifyAuthenticatedOutputLink` still checks only actual acceptance/order;
  neither equality nor `not LinkBad` was folded into it.

  Both negative artifacts are permanent audit targets:
  `masked_sum_zeroBatch_link_counterexample` documents the original missing
  auxiliary link, and
  `authenticated_output_batch_beta_collision_counterexample` documents why
  deterministic equality is false for an RLC-batched verifier.  The good-tape
  theorem excludes the entire nonzero delta-shift class, while accepted shifts
  flow into link, fold/query or response-ZeroBatch bad events.  Binding, ZK
  and batching remain separate theorem carriers; no new declaration was added
  to `Ideal.lean` and the LogUp characteristic-bearing theorem is unchanged.

  `lake build` is green at **3251 jobs**.  Repository Lean sources contain
  zero `sorry`/`admit` outside the four already declared `Ideal.lean` axioms.
  The derived audit is green at **163 total targets / 70 X4 targets**: it
  retains the complete historical **133/40** set and adds exactly 30 v3
  targets.  Its complete stdout SHA-256 is
  `4706e705abc1a8df3eeb96df41388c357f2006671cf90116c9c200f29d36d267`;
  dependencies are limited to `propext`, `Classical.choice` and `Quot.sound`.
  Source SHA-256 values are
  `5a3367af7750158ed14c3e469ed58b9c8d918ee272dcf48fe89a1832bdc85dde`
  for `X4FoldingPCSV3.lean`,
  `03dcd13338d206866893bd1e9d134b6ccef8e2794cd83b77bd4569e42b467203`
  for `Audit.lean`, and
  `e4934964f6b0985a3bbb82f72e14f9c31f02fdaa51fea71301b324d73a75a443`
  for the aggregate import.

  Amendment 4 changed statement conditioning only.  The kernel proves the
  unchanged exact target `x4ResponseErrorV3 < 2^-83`; the registered
  expression remains `8.3853234432654370979010519467789577e-26`, or
  **83.30226403378921 bits**, with `C_authlink=3,412` already charging
  `LinkBad`.  No protocol, frame, byte, correlation, parameter, coefficient,
  benchmark, gate or pod value moved.  This checkpoint clears v3/M9 Rust;
  CPU records, GPT-2 migration and the later pod/NOTE-6 stop remain in their
  frozen order.  The Lean-first source/audit checkpoint is
  `3ca2a05ce2ba9afaaecddd323bbefbbb52a408bd`.

- **2026-07-21 (X4 Amendment 4 authorized and frozen; statement conditioning
  only; direct Lean-first resume)**: the product owner selects repair form
  (2).  Section 0.11 of `docs/x4-folding-pcs-design.md`, SHA-256
  `f80da5b943b986aa1d849f53b83780aa067d77e7cb9dcfd538dd7931f6ae1a98`,
  changes the conclusions of `authenticated_output_link_produces_bound_aux`
  and `bound_aux_has_verified_origin` to
  `authenticated equality OR LinkBad`.  It is still forbidden to define
  `VerifyAuthenticatedOutputLink` as containing equality or `not LinkBad`.

  Every consumer follows the disjunction: the equality branch continues to
  the ordinary response transfer, while the other branch enters the already
  named `X4AuthenticatedOutputLinkBad` event through
  `AuthenticatedOutputLinkTransfersAllTouchedEvalsOrBad`.  The good-tape
  delta-shift exclusion and transfer theorem retain deterministic equality
  because their hypothesis excludes the bad event.  The fixed rational
  `R0=1,R1=-1,beta=1` collision becomes the permanent theorem
  `authenticated_output_batch_beta_collision_counterexample` in the derived
  audit beside the original delta-shift artifact.

  This is a statement-shape correction only.  There is no protocol,
  transcript, grammar, byte, correlation, parameter, soundness-coefficient,
  gate or implementation-plan change.  `LinkBad` was already charged by
  `C_authlink=3,412`, so the exact response expression remains
  `3320*(9/16)^128 + 28,522,064,267,253/|E| =
  8.3853234432654370979010519467789577e-26`, or
  **83.30226403378921 bits**, with the same **4.49296915978921-bit** target
  margin.  R1c mandatory scope now explicitly includes this episode and the
  non-circular verifier definition.  Approval authorizes immediate Lean-first
  work without another design stop; v3/M9 Rust remains gated on exact proofs,
  green full build, zero `sorry`/`admit` and green derived audit.  Pod ordering
  and the NOTE-6 `c3_weights` smoke are unchanged.

- **2026-07-21 (X4 Amendment-3 Lean HARD STOP; frozen deterministic Bound
  theorem omits the counted `LinkBad` event)**: discharge stopped before
  editing any repository Lean source.  The frozen statement
  `authenticated_output_link_produces_bound_aux` assumes fixed claims, raw
  `VerifyAuthenticatedOutputLink` acceptance and a terminal closed by the
  unique committed fold/query oracles, then concludes for every block that
  the returned authenticated plaintext equals `committedAuxEval`.
  `bound_aux_has_verified_origin` repeats the same unconditional equality.

  That implication is false for a probabilistically sound batch verifier.
  Take one block over `Q` with committed `W=3`, committed `g=5`, public
  `h=7`, authenticated `s=6`, and batching challenge `beta=1`.  The two fixed
  frozen residuals are

  ```text
  R0 = W + g - h = 1
  R1 = g - s     = -1
  R0 + beta*R1   = 0,
  ```

  while `s!=g`.  The prover can run the honest blind sumcheck for this zero
  combined claim and close its terminal against the true committed `W/g`
  fold/query values.  All raw checks accept on this challenge, yet the
  requested equality is false.  A temporary theorem using exactly these
  rationals was accepted by Lean's kernel.  This is not an uncounted new
  attack: it is precisely a tape in `LinkBad`, whose nonzero cardinality the
  separately frozen theorem bounds by
  `(relationCount+3*rounds+2)/|E|`.  A nonzero soundness term and deterministic
  accept-implies-truth cannot both describe the same verifier.

  A sound statement must either add an explicit good-tape/`not LinkBad`
  premise to the two Bound-output theorems, or conclude
  `committed equality OR LinkBad`; the actual typestate may mark verifier
  acceptance, while semantic equality remains conditional on the good event.
  Either repair changes frozen hypotheses or conclusions and therefore
  requires an explicit owner-approved Amendment 4.  Defining
  `VerifyAuthenticatedOutputLink` to include the desired equality would be
  the forbidden hypothesis smuggling.  No statement was weakened, no axiom
  was added, and no repository Lean or Rust file, audit target, benchmark,
  reference, gate or pod state changed.  The permanent v2 delta-shift theorem
  and R1c scope remain untouched.  Baseline audit remains 133/40; Rust and all
  later phases stay gated.
  Obstruction checkpoint:
  `304a768ac18e5f0d2f8f3c4717587ff246e6167f`.

- **2026-07-21 (X4 Amendment-3 freeze approved; exact Lean-first discharge
  authorized)**: the product owner confirms that all six design constraints
  are satisfied and approves the v3 freeze at SHA-256
  `07eb1f832367d84b70095e20addc29c136233a6940e32f56d58ac7251e9ca868`.
  Authorization is limited first to proving exactly the Section-0.10.6
  statements.  Names, hypotheses, conclusions and coefficients may not be
  weakened; no new axiom beyond the declared Ideal set or hidden premise is
  permitted.  `masked_sum_zeroBatch_link_counterexample` remains a permanent
  negative audit target.  Any unprovable obligation triggers an immediate
  hard stop and requires a separately approved amendment entry.

  Only a green `lake build`, zero `sorry`/`admit` and green derived full audit
  clears v3/M9 Rust.  After that gate, the frozen order is normative grammar
  and authenticated-output implementation, permanent tests for every named
  event class including the delta-shift mirror, CPU records, then the frozen
  GPT-2 migration ritual.  All gates remain verbatim.  R1c mandatory v3-seam
  scope remains pinned.  The A100 pod and NOTE-6 `c3_weights` smoke remain
  deferred until Lean, v3/M9, CPU records and GPT-2 migration are complete.

- **2026-07-21 (X4 Amendment 3 authorized and frozen; second design hard
  stop)**: the product owner authorized a repair only if binding is realized
  blindly inside the opening machinery, hiding and entropy are re-proved, the
  permanent Lean counterexample is generalized to the entire nonzero
  delta-shift family, all correlations/bytes/error are recomputed, and work
  stops again before proofs or M9 Rust.  Section 0.10 of
  `docs/x4-folding-pcs-design.md`, SHA-256
  `07eb1f832367d84b70095e20addc29c136233a6940e32f56d58ac7251e9ca868`,
  is the resulting normative `x4-zkdeepfold-ud-e29-v3` amendment.

  An ordinary M9 correction now creates only `PendingAuxEval`.  After every
  correction is fixed, one blind degree-two batch at `d<=30` proves the
  ordered relations `Wext_b(z_b||0)+g_b(u_b)-h_b=0` and
  `g_b(u_b)-authS_b.x=0` for every touched block.  Its fresh-common-point
  terminal is closed by the same committed zkDeepFold fold transitions,
  exact 128 queries and canonical cohort multiproofs.  Only that verified
  path constructs `BoundAuxEval`; neither a prover promise nor a transcript
  assertion can do so.  The frozen theorem set includes a verified-origin
  theorem and both a good-tape exclusion and named-event cover for every
  shift `delta!=0`, while
  `masked_sum_zeroBatch_link_counterexample` remains permanent.

  For fixed `Delta,x`, `(a,m) -> (m+Delta*a,x-a)` is a bijection on `E^2`.
  Product correction views therefore impose no equation beyond public `h`;
  the remaining auxiliary fiber is exactly `|E|^(2^ell-1)`.  The amended
  interpolation budget is `2^ell-1>128*mu^2`, with
  `131071>107648` at `mu=29`, so neither `g(u)` nor `v` is revealed and no
  parameter changes.  The seam consumes exactly `B_touch+2d+1` full
  correlations, max **1,721**; the deliberately all-maximum whole-X4 screen
  is **98,001**.  Its v3 link frame is `69+32d`, max **1,029 B**, and the
  complete framed seam is `64*B_touch+119+32d`, max **107,319 B**.  Expanded
  local seam correlation material is **55,072 B prover / 27,536 B
  verifier**; it is not transcript or setup traffic.

  The realized owner of the former different-point slot is now
  `C_authlink=3320+3*30+2=3,412`; `C_fold`, `C_claim` and `C_zero` stay
  separate.  The exact response-wide expression is consequently unchanged
  but no longer conditional on the unrealizable seam:
  `3320*(9/16)^128 + 28,522,064,267,253/|E| =
  8.3853234432654370979010519467789577e-26`, or
  **83.30226403378921 bits**, which clears the **78.809294874-bit** floor by
  **4.49296915978921 bits**.  Rate `1/8`, `s=128` and strict unique decoding
  remain fixed; no list-decoding radius is used.

  R1b M3's “M9 masked-opening seam — sound as specified” disposition is
  **SUPERSEDED ON THIS AUXILIARY-TO-MAC POINT ONLY**.  This is a limitation of
  the immutable AI adversarial review, carries no blame, grants no
  independent-human assurance and leaves criterion (1) external.  Future
  R1c mandatory scope includes the pending-to-bound order, dual relation and
  terminal closure, whole delta-shift class, correction/fiber hiding,
  correlation and byte counts, response coefficients, and separately cited
  binding/ZK/batch obligations.  Amendment 3 changes no Lean or Rust source,
  diagnostic v2 artifact, benchmark/reference, gate verdict or pod state.
  The read-only derived Lean audit remains byte-identical at **133 targets / 40
  X4 targets**, stdout SHA-256
  `de90480a5c17d970b041a6ada881e67a03ace04e24672cb9772485492b9617d2`,
  confirming zero proof-state change.
  Work is hard-stopped before Amendment-3 Lean proofs and v3/M9 Rust; the pod
  remains later than M9 plus CPU and GPT-2 records.  The frozen design and
  ledger decision are checkpointed at
  `b542edb07975f2de19366ed30a229b86a6877839`; this checkpoint itself carries
  no proof, implementation, record or gate credit.

- **2026-07-21 (X4 Phase-2 HARD STOP; concrete auxiliary-to-MAC binding
  cannot be discharged)**: implementation reached the M9 boundary after the
  canonical v2 codec, N4-separated two-dimensional cohort tree, amended-field
  NTT and public strict-UD folding core.  The required concrete premise
  `MaskedBatchBindsIntoMac` is false for the frozen masked-sum/MAC composition:
  choose committed evaluations `w=3`, `g=5`, public `h=8`, wrong GKR claim
  `v=4`, and authenticate prover-chosen `s=h-v=4`.  Both `h=w+g` and the
  corrected zero residual `v+s-h=0` hold, while the recovered evaluation is
  `h-s=4`, not committed `w=3`.  An ordinary full correlation authenticates
  any chosen `s`; it supplies no proof that `s=g(u)`.

  This exact witness now appears as
  `masked_sum_zeroBatch_link_counterexample` and kernel-checks without a new
  axiom.  It does not contradict the prior abstract Lean package: that package
  explicitly assumes the unavailable binding premise and its good-tape
  negation.  It does overturn R1b's design-level assertion that the chain was
  closed.  The statistical arithmetic remains a correct conditional bound,
  but cannot be claimed for the concrete protocol.  Section 0.9 of the design
  records the obstruction.  X4 stops before M9 Rust, CPU synthetic records,
  GPT-2 migration, references and all pod work.  Repair requires an explicit
  owner-approved amendment plus new Lean-first statements; revealing `s`,
  assuming equality, adding an ideal axiom, or silently increasing correlation
  use is forbidden.  No X4 gate receives PASS or FAIL from this partial work.

  The post-diagnosis `lake build` remains green at **3250 jobs**.  The derived
  audit now checks **133 total declarations**, of which **40** are in its X4
  block, with zero `sorry`/`admit`, no `Ideal` dependency and only `propext`,
  `Classical.choice` and `Quot.sound`; complete stdout SHA-256 is
  `de90480a5c17d970b041a6ada881e67a03ace04e24672cb9772485492b9617d2`.
  The prior Lean-checkpoint prose said 41 X4 targets; direct counting shows
  that its pinned 132-target audit contained 39 in that block.  This
  bookkeeping correction changes neither the prior stdout nor any theorem or
  gate.  Adding the counterexample makes the current counts 133 and 40.
  Current source SHA-256 is
  `da1d6b1aa6bd6357deec04bb4be2343ad344eb7b283f818a72370c78753b783a`
  for `X4FoldingPCS.lean`; the Section-0.9 design SHA-256 is
  `61eba70a23a619c6ab1d209dfa39bbe46c3e4d32387456418dd8654a896a8fa7`.

  Before the obstruction, the allowed public pieces accumulated 22 synthetic
  X4 tests: canonical v2 frames, N4-separated cohort Merkle proofs, amended-
  field NTT/encoding and public strict-UD folding.  `cargo test -p volta-pcs`
  executes **51 passed / 0 failed** package tests; the only two ignored tests
  are pre-existing production-size C3 leakage smokes.  These are diagnostic
  checks, not CPU records and not an X4 gate verdict.  The broader
  `cargo test --workspace` non-regression run also completes with **271
  passed / 0 failed / 4 existing production-size tests ignored**.  The
  diagnostic implementation and hard-stop evidence are frozen at checkpoint
  `8578bfd06baa0f21aba74a82992fc7b3873e43e2`.

- **2026-07-21 (X4 implementation clarification I1 registered before folding
  code; no format or parameter amendment)**: Section 0.8 of
  `docs/x4-folding-pcs-design.md` makes the frozen `fold_round`, message and
  multiproof fields operationally unambiguous.  Round zero retains the full
  descriptor-pinned cohort.  Each later, shared aggregate-fold oracle uses a
  singleton structural slot anchored by the canonical slot-zero descriptor;
  the verifier first recomputes the transcript-bound aggregate from every
  touched round-zero symbol.  Each fold frame commits its output root and
  carries the two parallel claim-line values; the final frame also carries the
  scalar, and the rate-1/8 length-eight constant oracle is committed and
  queried rather than represented by a sentinel.  The exact 128-query ordered
  multiset remains transcript-derived, while each canonical multiproof carries
  only its strictly increasing deduplicated `+beta/-beta` set.  This completes
  previously unspecified schedule semantics using existing bytes.  It changes
  no v2 grammar, `E`, `rho=1/8`, `s=128`, block/claim count, `B_touch+1`
  correlation allocation, soundness term or G1--G6 threshold.
  Clarified-design SHA-256 is
  `457ee75fb6693de95b4a44d28908ed9fea2b4c889b91163da5e62411793866f1`.

- **2026-07-21 (X4 Lean-first hard stop cleared; Rust phase authorized)**:
  `lean/VoltaZk/X4Field.lean` and `lean/VoltaZk/X4FoldingPCS.lean`
  prove the complete Amendment-1/2 pre-code statement set.  The concrete
  Goldilocks primality fact uses a kernel-checked Proth witness and a 63-step
  square-and-multiply certificate, not `native_decide`; the resulting
  `E=GF(p^2)` cardinality, exact 2-adicity 33 and domain-root existence are
  proved.  The strict rate-`1/8` unique decoder, split-block reconstruction,
  exact `|E|^(2^ell-1)` mask-fiber count, one-opening epoch rule, Amendment-2
  direct M9 transfer, canonical v2 frame codec, cohort binding, scalar claim
  reductions, strict-UD folding bound, separate PCS binding/ZK/batch
  interfaces and full response event cover all compile at their frozen
  conclusions.  The three current-Ligero discharge theorems remain separate;
  conditional UC composition has both realization premises; the discharged
  LogUp statement explicitly assumes `[CharP F p]`, prime `p`, and
  `lookupCount < p`.

  The exact response expression is proved as
  `x4ResponseError < (1:Q)/2^83`, followed by the registered real-exponent
  target theorem, so the **78.809294874-bit** stop rule clears without changing
  rate `1/8`, `s=128`, any coefficient or any gate.  `lake build` completes
  **3250 jobs**.  `scripts/audit_lean.sh` finds zero `sorry`/`admit`, audits
  **132 declarations** including 41 X4 declarations, and reports only
  `propext`, `Classical.choice` and `Quot.sound`; its complete stdout SHA-256
  is `4c1c11d09f6da82f732de2455b8fa4ec622934c97103e7c072644ee689f5b83f`.
  No new declaration was added to `Ideal.lean` and no deferred named ideal
  assumption entered an X4 proof.  Source SHA-256 values are
  `b57cb0acb469b9053ae9dbc65898a3c1437679b09b250fdff65f5d3594a47805`
  for `X4Field.lean` and
  `d21d4dac4d351636c63b9481349f0fbafeb85e3bacf884c9f76fd362f22be846`
  for `X4FoldingPCS.lean`.  This clears only the Lean-first hard stop and
  authorizes the already ordered Rust implementation.  It is not an X4 gate
  verdict, CPU record, pod record or independent review assurance.

- **2026-07-21 (X4 Amendment 2 approved before Lean/Rust; direct-mask
  good-tape premise corrected)**: the product owner approved the normative
  Section 0.7 amendment in `docs/x4-folding-pcs-design.md`, SHA-256
  `31828e41d0da09a8e331603a693c8d11e4d3582ec45a38d7adba2cb53c12022b`.
  The frozen Amendment-1 `direct_mask_transfer` used existing
  `Authed.Valid` as though it asserted a zero plaintext.  A checked generic-
  field Lean counterexample takes `authS=0`, `authV=authPublic 1`, `h=0`:
  both MAC invariants hold but the conclusion is `1=0`.  The required hard
  stop occurred with the repository still clean at `fc05f10`.

  Amendment 2 defines `ResponseZeroBatchValid Delta a` as the conjunction of
  the existing MAC invariant and `a.x=0`, and uses that predicate in the
  deterministic transfer theorem.  Mere adversarial verifier acceptance is
  not identified with this good-tape fact: accepted bad tapes remain bounded
  by `masked_batch_opening_mac_sound` and the existing scalar ZeroBatch
  theorem.  This is a strengthened semantic premise and no theorem conclusion
  is weakened.  There is no new axiom and no change to `E`, rate, `s`, block
  geometry, frame grammar, `B_touch+1` allocation, `C_M9=1,661`,
  `C_total=28,522,064,267,253`, the exact `<2^-83` stop rule or any G1--G6
  gate.  The owner authorizes Lean-first execution, then the already ordered
  implementation and CPU synthetic records if the audit is green; any other
  unprovable frozen statement still hard-stops.  Pod work remains deferred
  until the mandatory post-CPU provisioning stop.

- **2026-07-20 (R1b AI-review disposition: CLOSED; honest assurance label
  retained)**: the Kimi R1b report produced against detached checkpoint
  `9b1ef2d` is imported byte-identically as `docs/r1b-kimi3-report.md` and
  pinned by SHA-256
  `a6d25a55c1220934666bf22f218740be1a9084243370fd031274dea2a222aa9f`.
  `cmp` against the review-worktree source is exact.  The R1 and R1b review
  worktrees remain untouched.  The verdict is **zero CRITICAL, zero MAJOR,
  three MINOR and six NOTE findings**.  This is an automated AI adversarial
  review, **not independent human-review assurance**; review criterion (1)
  therefore remains external.

  **Finding dispositions.**  MINOR-1 and MINOR-2 are closed by docstring-only
  edits in `lean/VoltaZk/Ideal.lean`: the implemented current family is named
  Ligero, binding/ZK/batch are explicitly unbundled, and the missing UC PCS-
  realization premise is explicit.  The declarations and proof states did
  not change: the complete derived-audit stdout SHA-256 was identically
  `9b501c8793c0bdb978a72af303d03a82359566ec971b300a42fc4a741dfbf5bf`
  before and after the edit and rebuild; `lake build` and the two audit
  regressions are green.  Discharge time requires three separately named
  current-Ligero theorems and separately owned citations for binding,
  VOLTA-specific blinded ZK and common-point batch soundness; conditional UC
  composition has explicit `F_sVOLE` and `F_PCS` realization premises.
  MINOR-3 is adopted by X4 Amendment 1 below.  NOTE-1 is removed cheaply now:
  X3 sections are remapped from `220..223` to the reserved `212..215` range,
  disjoint from X2 `216..219` and prefill `220/221`; all 13 focused X3 tests
  pass.  NOTE-2 remains the already disclosed synthetic-fixture boundary and
  receives no production-witness credit.  NOTE-3 is pinned as an explicit
  `lookupCount < p` premise under `[CharP F p]` and `[Fact (Nat.Prime p)]` in
  every discharged LogUp--GKR theorem.  NOTE-4 requires no change: the
  existing Ferret docstring remains faithful at its declared granularity.
  NOTE-5/N4's residual is closed at design level by the normative v2 frame
  grammar, exact canonical decoder and separate leaf/node/type hash domains
  below.  NOTE-6 schedules the previously unverified production-size
  `c3_weights` leakage smoke as a mandatory preflight in the next pod session,
  recording command, peak RSS/VRAM, status and verdict before any X4 record.

- **2026-07-20 (X4 R1b Amendment 1 and Phase-2 statement freeze; HARD STOP
  pending product-owner review)**: the amended plan of record is
  `docs/x4-folding-pcs-design.md`, SHA-256
  `2f511ac162ed6fdfa88dcb7e43fb749ae7063acf4a4585e2693349c9f023f207`.
  The profile `x4-zkdeepfold-ud-e29-v2` splits each global `2^30` embedding
  block on its high Boolean variable into two ordered `2^29` blocks and
  adopts the split reconstruction identity as a pre-code theorem.  Thus
  `mu_max=29`, the largest rate-`1/8` code domain is `2^33`, and
  `v2(|E|-1)=33` lets the PCS use the existing 16-byte field `E=F_p^2` with
  no `F_p^4` tower.  The inventory is **1,660 physical blocks / 3,320 maximum
  claims**; the unpadded first-oracle floor is **5.3504 TB** at the 41.8-GB
  gpt-oss point and **31,923,699,712 B** for measured GPT-2 weights.  The
  global cohort has four ordered split slots, split claims are affinely
  reconstructed before challenges, and the direct `E` masked seam removes
  the tower trick and costs exactly `B_touch+1` full correlations.  The
  optional `mu_shard<=25` hierarchy is updated to 1,720 slots, `+60` or
  `+3.614457831%`, and remains conditional with no gate credit.

  **Specialized soundness.**  The amendment retains strict unique decoding,
  rate `1/8`, `s=128`, `ell<=17`, forbids conjectural list-decoding credit and
  replaces the paper's unnamed finite-field polynomial by a conservative
  explicit reduction that must be proved before code.  With `q=p^2`,
  `P=3,320`, `n_W=2^33`, `n_g=2^20`, `B=1,660`:
  `epsilon_prox=P*(9/16)^128`, `C_fold=28,522,064,111,120`,
  `C_claim=151,060`, `C_mpoint=3,412`, `C_M9=1,661`, and
  `C_total=28,522,064,267,253`.  Therefore
  `epsilon_X4=epsilon_prox+C_total/q =
  8.3853234432654370979010519467789577e-26`, or
  **83.30226403378921 bits**, a **4.49296915978921-bit** margin over the
  required 78.809294874 bits; the exact frozen Lean stop rule is
  `epsilon_X4 < 2^-83`.  Rate and query count therefore remain unchanged.

  **Statement and authority boundary.**  The document freezes separate named
  pre-code statements for the `E` cardinality/domain and strict RS-UD facts;
  split geometry; masked-sum equal-fiber hiding, one-opening epoch enforcement
  and simulator-based ZK; canonical frames and cohort binding; scalar claim
  reduction; different-point batching; strict-UD cohort folding; separate PCS
  binding/ZK/batch obligations; direct masked M9 transfer; full response event
  cover, composition and exact inequalities; current-Ligero discharge;
  conditional UC composition; and characteristic-bounded LogUp--GKR.  G1--G6
  and every existing byte/wall gate remain verbatim and conjunctive.  This is
  a preregistered expression and theorem-statement freeze, **not a Lean proof,
  security verdict, implementation, benchmark or gate verdict**.  No X4 Lean
  proof, X4 Rust, reference mutation, pod run or X5 work is authorized before
  explicit product-owner approval.

- **2026-07-20 (X4 first-oracle mitigation addendum frozen; original hard
  stop preserved)**: at the pre-approval hard stop, the product owner
  requested a design-only disposition of the **10.7008-TB** raw first-oracle
  screen. Section 5.1 of `docs/x4-folding-pcs-design.md` is the resulting
  addendum. Addended design SHA-256 is
  `3588d9f360960d46ad219309ba67645bd992a56d89ed1ae627f69f6d7ca9bb44`;
  the original pre-addendum document hash
  `bb693bb4b1a06244d4f30f4b23cb47a64563dcaa21b5502b74adb044e6284464`
  remains historical.

  **Floor boundary and parameter screens.** For an unpadded i16 source of
  `S=2*N` bytes, zkDeepFold's equal-size random extension and an RS code over
  `b`-byte symbols at rate `rho` give the logical first-oracle identity
  `F0=S*b/rho`. The frozen `K`, 32-B, rate-`1/8` profile is therefore
  irreducibly `256*S=10.7008 TB` when materialized. This is not a universal
  persistent-storage lower bound: coefficient caching moves the cost to
  regeneration and Merkle-path reconstruction. The addendum pins
  same-query-margin alternatives: `K-1/4` **5.3504 TB, s=157**;
  `K-1/2` **2.6752 TB, s=256**; `E-1/8` **5.3504 TB, s=128**;
  `E-1/4` **2.6752 TB, s=157**; and `E-1/2` **1.3376 TB, s=256**.
  Every `E` row remains conditional on exact 128-bit-field response-wide
  security and a revised one-component M9 seam. None is selected.

  **Streaming and hierarchy costs.** Canonical `2^18`-coordinate cohort
  strips cap raw full-layer 69-slot symbol buffers at **552 MiB** for `K` or
  **276 MiB** for `E` without changing roots or opening bytes, but persistent
  frozen artifacts still write at least 10.7008 TB. Meeting the current 15-s
  comparison ceiling would require **713.386667 GB/s** before
  encoding/hashing. This uses the GPT-2 ceiling only as a scale comparison,
  not a gpt-oss wall gate. The alternative
  source/random cache is already **710.6 GB before block padding**; adding the
  deliberately loose all-max auxiliary screen gives **717.554156032 GB**,
  while the exact padded cache can be larger. Worst-case near-all-touched
  reconstruction within 1.50 s would require **7.133867 TB/s** of generated
  first-oracle bytes before encoding/hashing; this too is a comparison, not a
  gpt-oss verdict. X5 would require a separately preregistered wall envelope.
  A two-level logical-block/transport-shard screen at `mu_shard<=25` changes
  1,658 logical blocks into **1,720 transport slots (+62, +3.739445% in
  shard-linear terms)** and caps a raw shard at **16 GiB** for frozen
  `K-1/8` or **4 GiB** for `E-1/4`; `mu_shard<=24` would use 2,552 slots
  (**+53.920386%**) and is contingency-only. Sharding does not reduce `F0`.
  Sharing one logical zkDeepFold auxiliary across shards is a new pre-code
  proof obligation; without it, `H25` adds 124 full `K` mask transfers and
  their auxiliary proof material.

  **Gate and authority disposition.** The gpt-oss analytic PCS gate remains
  exactly **<=35,000,000 B**. Rate/field query and path effects, all transport
  slots, masks, roots and descriptors must enter its closed formula; storage
  cannot net against response bytes. The first conditional paper screen, if
  separately authorized, is `E-1/4 + H25`; this ordering is not candidate
  approval. If no row passes security, bytes, wall and G6 honesty together,
  the cited BaseFold/zkDeepFold family is recorded unsuitable rather than
  relabeling a peak reduction as removal of the floor. The frozen candidate
  remains `x4-zkdeepfold-v1`. No security-arithmetic phase, Lean, Rust,
  reference, benchmark or X5 work is authorized; the product-owner-review
  hard stop remains active.

- **2026-07-20 (X4 Phase-1 folding-PCS design frozen; HARD STOP pending
  product-owner review)**: `docs/x4-folding-pcs-design.md` replaces the
  original X4 lever-A premise, which remains UNSOUND, with the
  `x4-zkdeepfold-v1` candidate. Design SHA-256 is
  `bb693bb4b1a06244d4f30f4b23cb47a64563dcaa21b5502b74adb044e6284464`.
  This is a preregistration, not a security proof, implementation, benchmark
  or gate verdict.

  **Candidate and security screen.** X4 selects the published zkDeepFold
  construction and different-size/different-point batching in the BaseFold
  family, specialized to the proved unique-decoding radius; it takes no
  credit for DeepFold's conjectural list-decoding 34-query/304-KB point.
  Authenticated evaluations stay in
  `E=F_p[phi]/(phi^2-7)` while PCS code/folding uses the exact tower
  `K=E[psi]/(psi^2-phi)`. The profile pins RS rate `1/8`, `s=128`, distance
  `7/16`, query term `(9/16)^128 = 1.0367724023455627e-32`
  (**106.24959981538402 bits**), `14 <= mu_b <=30`, and
  `ell_b=ceil(log2(128*mu_b^2+1)) <=17`. The complete unique-decoding,
  cohort-layout, masked-relation ZK and `E`/`K` response-wide arithmetic must
  prove at least **78.809294874 bits** before Rust. A failure stops for a new
  preregistration; no post-benchmark parameter tuning is allowed.

  **D3 openability and M9 seam.** The 24-layer/32-expert/41.8-GB sizing map
  has 69 blocks/layer plus two global blocks, **1,658** physical blocks and
  **3,316** stacked claims. Per-layer cohort trees use inner block-slot
  multiproofs and outer codeword paths, so serialized marginal cost is
  proportional to touched blocks and exact path depth, with one response
  envelope and no `N_total`/`N_touch` byte term. The auxiliary zkDeepFold
  polynomial is also the one-time evaluation pad: the public `K` value is
  `h=embed(W_tilde(z))+g(u)`. Its two `E` tower components consume exactly
  `2*B_touch` existing full correlations, and one response ZeroBatch checks
  both components; `W_tilde(z)` is never public. This changes only the PCS/M9
  transfer count/formula, not the PCG generator, tuple, setup, spool, pool,
  reuse or lifecycle. M9 reopens proof-before-code for the masked auxiliary
  identity/hiding count, `E`-into-`K` evaluation, tower transfer, ordered
  batch reduction, binding-into-MAC, transfer and response-composition
  lemmas. The derived audit must remain green with no new ideal axiom.

  **N4(ii), costs and gates.** The new commitment format pins distinct BLAKE3
  derive-key contexts for PCS leaves/nodes and manifest leaves/nodes, exact
  inner/outer depth and canonical multiproofs. New roots are required;
  historical C3/C3b/T1 roots and rows remain untouched. GPT-2 compares to
  immutable Ligero **43,273,888 B**, CPU commit/open/verify
  **10.785629/0.767759/0.080496 s** and A100
  **0.202467/0.294423/0.079365 s**. X4 gates PCS bytes at **4,000,000 B** and
  full response at **45,270,464 B**, with CPU
  **180/15/0.50 s** and A100 **15/1.50/0.25 s** commit/open/verify ceilings,
  plus inherited pod gates. The gpt-oss analytic PCS screen is
  **<=35,000,000 B**, but the honest `Fp4` ZK/rate screen exposes a
  **10.7008-TB source-equivalent first-oracle floor** before padding and
  later oracles; no gpt-oss measurement is claimed. G1--G6 also require
  adversarial strictness, touched-block proportionality, exact storage/I/O
  accounting and append-only clean rebaselining. X5/export, PCG/lifecycle,
  non-PCS proof changes and multi-response claims remain out of scope. No
  Lean, Rust, reference, benchmark or X5 work is authorized until explicit
  review and a later phase authorization.

- **2026-07-20 (R1b X1--X3 delta-review handoff frozen; no review
  performed)**: `docs/r1b-delta-handoff.md` pins the immutable read-only range
  `f05d7279249fdbe16025ee2d005ef58a18224fbb..4b349b59f13516ac878446f593d1621fba92bcfc`,
  the X1--X3 closure HEAD that existed before the R1 disposition work. It
  enumerates all 15 commits and all 47 changed paths, the `ModelConfig` and
  GPT-2 non-regression claims, X1 routing/limb argument, immutable X2 FAIL,
  preregistered X2b corrected-proxy postdictions, and X3 operations/non-power-
  of-two golden claims. Handoff SHA-256 is
  `21495b7d2d508b8e7ae65997f81b7a4b2a103831e9b4ea192727efd38f660436`.
  Kimi3 is assigned by the product owner; the current package does not perform
  that review. Findings belong in a separate report only. Later R1 disposition
  commit `bc44099` is outside the frozen delta. No R1b verdict, independent
  human-review assurance, X4 implementation authority or gate credit follows.

- **2026-07-20 (R1 product-owner disposition: CLOSED; X4 design
  UNBLOCKED)**: `docs/r1-kimi3-report.md` is accepted as the immutable report
  of an AI adversarial review of detached baseline `f05d727`; its SHA-256 is
  `b4f05cdd19609975c736ca0f4955894f87b7a44150addb520fe4f5a8d7a93eb4`.
  It found **zero CRITICAL, zero MAJOR, one MINOR (M1), four NOTES (N1--N4)**
  and the declared modeling boundaries N5. This label is deliberately honest:
  the report **confers no independent human-review assurance** and criterion
  (1) remains external. The post-baseline X1--X3 delta has not been reviewed.

  **M1 fixed at the drift class.** `scripts/audit_lean.sh` now derives its
  complete theorem inventory from every `#print axioms` directive in
  `lean/Audit.lean`, rejects a duplicate or empty inventory, requires exactly
  one result per derived theorem, permits only `propext`,
  `Classical.choice`, and `Quot.sound`, rejects `sorry`/`admit` and every
  deferred named assumption, and independently pins exactly the four declared
  `Ideal.lean` axioms. A synthetic-name regression test proves that new or
  renamed audit targets are derived rather than hardcoded. The gate and test
  are green on the current tree.

  **N1 reproduced.** The estimator patch was regenerated against Code
  Estimators commit
  `969ef60c30cb84c25502d6b7c968f43a362bb438`; patch SHA-256 is
  `26b59a7d21bcf02938ebfb3565649a16e46bc6c97b653b26b294e83667ba033d`.
  From a fresh detached checkout, `git apply --check` and `git apply` pass and
  the documented offline path emits digit-exact AGB **213.85**, AGB2
  **213.85**, ISD **208.85010924741465**, HYB **199.59980442282708**, and
  regular-ISD **227.92519270931604**; their minimum is digit-exact
  **199.59980442282708**.

  **N2 accepted with a named hardening backlog.** Plaintext spool at rest is
  **ACCEPTED** for the prototype's declared designated-verifier model; a host
  adversary is out of scope. No code changes now. Future hardening backlog:
  **"spool encryption under an in-memory session key"**.

  **N3 corrected.** The Ligero module header now states the pinned C3
  effective rates **0.265625 / 0.25390625**, **Q=120**, and
  **78.809294874 bits response-wide**. Compiled parameters did not change.

  **N4 split.** Part (i) is closed now as verifier strictness only: all four
  `verify_path` call sites pin `params.code_bits`, the verifier rejects short,
  long and out-of-range paths, and a legacy-root fixture plus the exact
  **43,273,888 B** projection regression is green. Hash construction,
  commitment serialization and proof serialization are untouched. No
  benchmark/reference file changed: representative immutable SHA-256 values
  remain C3b CPU
  `e0921daf7de81a9cdb5bdc08a84b195c6afa4f9880840dadb162bc5fa23caab1`
  and T1 CPU
  `7fe5eeaec1601ab3af9951129a7684de6bdf81b8ec8ac4afe94fc8369fe6febb`.
  Part (ii), leaf/internal-node domain separation, necessarily changes roots
  and is **DEFERRED to X4's new commitment format**.

  **N5 consolidated.** The five modeling boundaries now live in the single
  ledger section immediately above this log. With all findings disposed, R1
  is closed under its preregistered rule and X4 is unblocked for a design-only
  Phase-1 package; this entry grants no X4 Lean or Rust work.

- **2026-07-20 (X3 approved clean execution: PASS; X1--X3 package
  CLOSED)**: the explicitly approved X3 gate ran once from clean source
  `7544f36b2392e4ea091f2e71803baa6598aeec91` on the four-core CPU VM with
  `RAYON_NUM_THREADS=4`; no pod was provisioned or contacted.  The frozen
  tolerance remained exactly zero and no preregistration, threshold or proof
  model changed between approval and execution.  **Gate verdict: PASS.**
  The append-only record is
  `benchmarks/results/x3-ops-2026-07-20-7544f36.json`, **12,719 B**, SHA-256
  `6514f00bdbc7a82941d8ac638196d998edbf6b101aa6fcba552b03884310d932`;
  it has `git_dirty:false` and cites preregistration SHA-256
  `c996bd4d2d887d8df113a17df496cf1b2e74a3b149867fb3dfe1f51e74c198e2`.

  **Frozen shape and bit-exact evidence.**  The run used T/pad **7/8**,
  layers 2, d/pad **48/64**, d_ff/pad **80/128**, vocabulary/pad **97/128**,
  eight experts/top-2, Q/KV heads **6/2** with group size 3 and head width 8,
  score shift 22, `thin_k=2`, and `[full_causal, sliding_window_4]`.  Model
  config BLAKE3 is
  `fcfe6244248d5d160166eef3c15b4ab5f757afe994d21c4dcce0a554f9f72426`.
  The independent numpy golden is **656,034 B**, SHA-256
  `31b5471f197a1fdb27641f123555fa6f098e30552d35f9e62b0806a37b70fa0c`,
  with **0 differing bytes**.  Config/artifact/exporter SHA-256 values are
  respectively
  `92b1bcad58b466529d45a76391159404e2d47a7ae71679d2c3fdd1ba3f5f59a2`,
  `01853c761b625d5f28d210a6e8e81a2b3e1cfecdf1941cf8d296810b0f34f402`
  and `db2f8b430c9d717af17b02aaedef9b9ab50d513faff592d11873cb03ed2d6182`.
  Exact native operation counts are QKV **53,760**, RoPE QK **2,400**, GQA
  AV **2,400**, attention output **32,256**, expert gate/up **215,040**,
  expert down **107,520** and logits **4,656**.

  **Honest proof/session evidence.**  Native, proof, product batch and zero
  batch all accepted in one two-phase TableBank session.  Logical/padded
  lookup rows are **21,969 / 35,824**, with **91** sites, **9** contents and
  **1** finalization; RoPE adds exactly **0** rows.  Instance work is
  **6,292,709 F_p2 mults + 4,083,696 base mults = 7,109,448.2 E-mult
  equivalent**; other counters are exactly zero.  Prover and verifier each
  consume sub/full/domain correlations **1,065,887 / 15,802 / 6,573**.
  Their allocation digest is
  `617548ab5502f979476a3b1ad41c8fd3d571a5153f5cca364349175ee20ab9f6`
  and channel digest is
  `a1a87c61676d5aaa832b1baa6237e571d44197b005901f1b56946ca909490e36`,
  with exact parity.  Transcript size is **8,781,000 B**: auth 8,527,096;
  blind-round 11,840; Hadamard-claim 1,680; Hadamard-round 14,112; LogUp
  aggregate/aux/column/cross/product/root/round/split
  **3,936 / 29,904 / 5,824 / 576 / 40,032 / 3,200 / 86,240 / 53,376**;
  mask 16; product-check 2,112; W-claim 1,040; zero-batch tag 16.  Diagnostic
  prove/verify/closure walls are **0.097576751 / 0.060557003 / 0.000209834
  s** and peak RSS is **0.06461715698242188 GiB**.  X3 has no timed ratio,
  so no ABBA ratio operand exists.

  **Permanent rejection evidence.**  All nine named tests reject:
  RMS mean-square/rsqrt-input, RMS output, SwiGLU clamp side row,
  SiLU/Hadamard product, RoPE coefficient/fold, wrong GQA KV head, attention
  sink/denominator, sliding lower edge/out-of-window and pad-sentinel
  admission.  The clean and poisoned logical layer/final outputs are equal;
  all **2,624** distinct source-pad sentinels are nonzero, canonical pads are
  zero, and the poisoned proof is actively rejected after detecting a
  nonzero canonical-padding zero-claim.  Thus the pad gate is detection, not
  merely clean-path acceptance.

  **Logged deviations and assurance boundary.**  The synthetic statement
  redundantly binds the full named trace with existing `Pi_Auth` /
  `Pi_ZeroBatch` so every golden field and sentinel is independently
  tamperable; this is not projected as production cost.  Deterministic toy
  weight evaluation claims close publicly in this spike; no PCS parameter,
  opening, lifecycle or proof-path machinery changed and no production PCS
  credit is claimed.  `Clamp1024` and Q10 SiLU are only new TableBank
  contents using existing LogUp.  Shift 22 uses the existing P5 chained
  schedule `(6,16)`, while RoPE adds zero lookup rows.  Fixed RMS division,
  RoPE fold, GQA selection, sink denominator and lower-edge relations close
  through the existing trace ZeroBatch, with nonlinear components using the
  existing lookup/Hadamard/band machinery.  No new argument class, Lean,
  PCG or cryptographic change landed.

  This closes X1--X3 while preserving the original X2 FAIL and later X2b
  PASS.  The additions postdate Kimi3's detached `f05d727` review baseline
  and require a later delta review; no cryptographic-review assurance is
  claimed.  X4 and any real gpt-oss export remain separate, unauthorized
  future packages, and X4 is gated on the pending R1 verdict.

- **2026-07-20 (X3 execution preregistered after X2b PASS; HARD STOP before
  implementation)**: X2b's clean `053d3fc` proof record and `6c53619`
  closure checkpoint satisfy the dependency, while the original X2 FAIL
  remains immutable.  This entry and the append-only machine-readable record
  preregister X3 only: **no X3 implementation was started, no X3 fixture or
  golden was generated, no proof was executed, and no gate verdict exists**.
  Explicit user approval is required before any of those actions.

  **Frozen synthetic configuration.**  The integrated two-layer MoE fixture
  uses non-power-of-two **T=7**, **d_model=48**, and **d_ff=80**, with physical
  pads 8, 64 and 128; vocabulary 97 is padded to 128.  It retains eight
  experts/top-2, GQA 6 query / 2 KV heads of width 8 and `thin_k=2`.  Layer 0
  is full causal; layer 1 is sliding-window 4, with exact real lengths
  `[1,2,3,4,4,4,4]`.  Norm is RMSNorm.  Activation is SwiGLU with both gate
  and up clamped to **[-1024,1024]**, Q10 SiLU and Q10 product requant; the
  fixture must contain below/inside/above-clamp lanes.  RoPE covers all eight
  head coordinates with base 10000, frequency scale 1 and Q14 public
  coefficients; its relative-position public fold makes the existing score
  requant's total shift 22 and adds exactly **zero lookup rows**.  K/V remain
  authenticated in their canonical pre-RoPE, two-head representation.  The
  public GQA map is `[0,0,0,1,1,1]`.  Each layer has an authenticated `6 x 2`
  sink-score vector; sink exponentials enter every denominator and no sink
  contributes a V row.

  **Existing-class coverage and stop.**  RMSNorm instantiates the existing
  LayerNorm square/Hadamard subset, scalar stats, rsqrt/requant LogUp and
  product/zero closures.  SwiGLU instantiates committed GEMMs, a content-keyed
  SiLU table, the existing saturation/range side-table pattern, Hadamard,
  `Pi_Prod` and `Pi_ZeroBatch`.  RoPE is a public-coefficient fold inside the
  existing blind QK sumcheck plus its existing score requant.  GQA uses
  `CacheSeg`, a public selector and existing band QK/AV arguments.  Sinks use
  existing authentication, exp LogUp, row-sum zero and Hadamard/product
  machinery.  Sliding attention is `BandShape` with its existing lower-edge
  selector and cache/band arguments.  Discovery that any exact contract needs
  a new argument class is an immediate FAIL/STOP report; no new class may be
  added in X3.

  **Binding X3 gate.**  `scripts/x123_export.py` is extended as the independent
  numpy reference, and `x3-ops-v1.golden.bin` carries full arrays rather than
  only hashes.  Rust must equal numpy bit-for-bit with tolerance **zero** for
  every RMS statistic/output, clamp/saturation/SiLU/Hadamard/down tensor,
  RoPE relative-pair term and QK score, grouped K/V read, sink exp/denominator/
  weight, lower-edge mask/QK/AV tensor, and integrated layer/seam/final-
  RMSNorm/logit tensor.  The honest native/proof path must accept.  Prover and
  verifier counters must match exactly, as must allocation and channel
  digests; the run uses one two-phase TableBank session.  RoPE's new lookup-row
  delta must be exactly zero.

  Padding is deliberately poisoned with distinct nonzero sentinels at time
  row 7, **wpe row 7** (the P5 failure class), hidden columns 48--63, FFN
  columns 80--127 and vocabulary rows 97--127.  Canonical construction must
  ignore/overwrite them with zero, logical Rust/numpy arrays must be unchanged,
  and admitting any one sentinel into a mask or claim must reject.  A power-
  of-two companion test cannot satisfy the gate.  Nine permanent tamper tests
  cover RMS stats/output, SwiGLU clamp and SiLU/product, RoPE coefficient/QK
  fold, wrong GQA KV head, sink/denominator, sliding lower edge/out-of-window
  admission and pad-sentinel admission.  **PASS** requires every exact
  predicate; otherwise X3 records immutable **FAIL** and stops without gate
  relaxation or same-package retuning.

  The future clean evidence is append-only
  `benchmarks/results/x3-ops-<date>-<gitsha>.json`; it must include all exact
  counters, artifact/config/exporter/golden hashes, every deviation and the
  verbatim verdict.  Closure requires the scaling-note section-5 sequence:
  gate, JSON, ledger row/entry, checkpoint.  Any timed ratio is eligible only
  if same-process ABBA/`time_paired`.  The append-only no-execution prereg is
  `benchmarks/results/x3-prereg-2026-07-20-6c53619.json`, **9,676 B**, SHA-256
  `c996bd4d2d887d8df113a17df496cf1b2e74a3b149867fb3dfe1f51e74c198e2`.
  CPU-only/no-pod, X4/X5/export, frozen PCG/PCS/Lean/soundness and no-review-
  assurance boundaries remain unchanged.  Kimi3's detached `f05d727`
  worktree was not accessed; main was neither rebased nor force-pushed.

- **2026-07-20 (X2b approved clean execution: PASS; X2 FAIL remains
  immutable; X3 not started)**: the user explicitly approved execution of
  the frozen X2b preregistration.  The harness ran once from clean source
  `053d3fcdcc34bf403454618ce3b2239f76d3a872` on the four-core CPU VM with
  `RAYON_NUM_THREADS=4`; there was no proxy, preregistration, code, band or
  fixture change between approval and execution.  **Gate verdict: PASS.**
  The inclusive band remained exactly **[0.80,1.20]**.

  | Binding operand | Predicted | Recorded measurement | Measured / predicted | Verdict |
  | --- | ---: | ---: | ---: | --- |
  | native MACs | 316,464 | 316,464 | 1.0 | PASS |
  | logical lookup rows | 12,495 | 12,523 | 1.0022408963585434 | PASS |
  | padded lookup rows | 19,313 | 19,346 | 1.001708693626055 | PASS |
  | TableBank sites | 80 | 82 | 1.025 | PASS |
  | sub correlations, k=1 | 330,820 | 350,304 | 1.058896076416178 | PASS |
  | sub correlations, k=2 | 330,484 | 349,793 | 1.0584264291160843 | PASS |
  | full correlations, k=1 | 12,462 | 12,462 | 1.0 | PASS |
  | full correlations, k=2 | 12,482 | 12,482 | 1.0 | PASS |

  The labels **12,495 / 19,313** remain analytic **logical / padded** rows,
  common to k=1/k=2.  Both honest proofs accepted; native k=1/k=2 outputs
  were identical and golden-bit-exact.  Each path used exactly one TableBank
  finalization, three commitments, one response opening session, three
  sequential component MultiOpen proofs and 40 claims.  PCS proof bytes were
  **17,256,480** for each path; transcript bytes were **20,258,656** at k=1
  and **20,254,888** at k=2.  Prover/verifier correlation counters and all
  allocation/channel digests matched.  All seven permanent smokes passed:
  wrong expert set, score swap, forged limb, crafted all-equal higher-id tie,
  lower-ranked substitution, k=2 internal-state substitution and chunk-
  boundary substitution.  Peak RSS was **0.3272056579589844 GiB**.  Absolute
  diagnostic prove/verify/closure times were **0.051844588 / 0.019464955 /
  1.13719776 s** at k=1 and **0.046366566 / 0.01985129 / 1.080787317 s** at
  k=2; no timing ratio is a gate operand, so no unpaired timing ratio is
  claimed.

  **Required postdiction table (verbatim in the run record as well):**

  | Anchor | Postdicted full correlations | Recorded measurement | Delta | Source record |
  | --- | ---: | ---: | ---: | --- |
  | X1 | 4,714 | 4,714 | 0 | `benchmarks/results/x1-routing-2026-07-19-6be165f.json` |
  | GPT-2/C1 | 176,880 | 176,880 | 0 | `benchmarks/results/c1-2026-07-15-2a3d731.json` |
  | closed T1 | 181,933 | 181,933 | 0 | `benchmarks/results/t1-cpu-real-2026-07-19-b14577e.json` |
  | X2 k=1 | 12,462 | 12,462 | 0 | `benchmarks/results/x2-moe-2026-07-19-87ce25b.json` |
  | X2 k=2 | 12,482 | 12,482 | 0 | `benchmarks/results/x2-moe-2026-07-19-87ce25b.json` |

  The append-only schema-2 evidence is
  `benchmarks/results/x2b-moe-2026-07-20-053d3fc.json`, **13,610 B**, SHA-256
  `ac04c297aa069cb91b7ed2a27a8236daa8c638ef90398cdbdc9b6eba2ffcf6d8`.
  The required table was copied from those immutable sources after the
  frozen execution and before the newly created record was sealed; no
  measured value, prediction, band, gate operand or verdict changed.  The
  prior X2 record and FAIL verdict remain untouched.  This closure starts no
  X3 implementation.  R1 is still external and pending, so no cryptographic-
  review assurance is claimed; Kimi3's detached worktree at `f05d727` was
  not accessed, and main remains append-only with no rebase or force-push.

- **2026-07-20 (X2 FAIL diagnosis complete; corrected proxy propagated; X2b
  preregistered; HARD STOP before execution)**: the user confirmed that the
  clean `87ce25b` X2 record and its FAIL verdict are immutable and that the
  inclusive **[0.80,1.20]** band is not relaxed.  The labels **12,495 /
  19,313** mean analytic **logical / padded lookup rows**, respectively, and
  are common to k=1/k=2.  No X2b proof run or verdict exists in this entry;
  X3 remains blocked until an explicitly approved X2b run returns PASS.

  **Tie rule scope.**  X1/X2b retain descending `(score, expert_id)`, so the
  higher expert id wins a tie and every crafted-tie accept/reject test remains
  permanent.  This is now explicitly a **synthetic-phase convention**.  X5
  must re-derive and repin the rule from the real gpt-oss router: its
  `torch.topk` path favors the **lower** expert index.  No synthetic tie rule
  may be silently transferred to X5.

  **Term-by-term cause of the -27% gap.**  The retired 17,040 proxy was 16,896
  coarse LogUp + 80 two-per-claim PCS + 64 opaque chain/closure masks.  The
  canonical existing-class k=1 schedule is instead **11,336 TableBank/LogUp +
  644 blind-sumcheck + 243 Hadamard + 131 fresh scalar-claim + 64 local/shared
  product + 44 PCS/component/global-zero = 12,462 full**.  k=2 adds exactly
  **20** T1 reducer/terminal/q-bridge masks, giving **12,482**.  For LogUp,
  lookup trees cost `d^2+7d+1+2c`, table trees cost `d^2+6d+2` once per
  content, fraction aggregation costs `3*(sites-contents)` once per TableBank,
  and cross checks cost `4*contents` once per TableBank.  Its exact 11,336
  subtotal is analytic lookup trees 8,950 + rectangular band correction 144
  + two route-weight Range(8) trees/aggregation 104 + final-rsqrt two-leaf
  correction 8 + one shared table side 1,884 + base aggregation 222 + crosses
  24.  PCS uses one full per claim plus one zero mask per component; the main
  `Pi_Prod` and `Pi_ZeroBatch` closures are shared per session.  The old model
  therefore overcharged LogUp/PCS by **5,596** while omitting **1,018**
  algebraic masks: net **-4,578 (-26.86619718309859%)** at k=1 and **-4,558
  (-26.748826291079814%)** at k=2.

  **Required independent postdictions.**  `scripts/budget_moe.py` now labels
  this formula `existing-class-session-v2` and permanent tests reproduce clean
  X1 at **4,714 / 4,714 full**, the requested frozen GPT-2/C1 base schedule at
  **176,880 / 176,880**, the closed T1 response at **181,933 / 181,933** (the
  base plus its exact 5,053 delta), and X2 k=1/k=2 at **12,462 / 12,482**, all
  with zero delta.  This is a schedule/class postdiction, not a new
  cryptographic claim or a reinterpretation of X2.

  **X2b gate.**  X2b repeats the identical CPU-only witness/proof code, all
  permanent smokes, 3 commitments, 40 claims, one response opening session,
  one TableBank finalization and both k paths.  Only the full predictions
  change to **12,462 / 12,482**.  MAC, logical/padded/site and sub predictions
  remain **316,464**, **12,495 / 19,313 / 80**, and **330,820 / 330,484**;
  every counter retains inclusive **[0.80,1.20]**, and all exact digest/golden/
  session predicates remain unchanged.  The future append-only schema-2 run
  is `x2b-moe-<date>-<gitsha>.json`; the harness cannot overwrite `x2-moe-*`.

  The append-only machine-readable preregistration is
  `benchmarks/results/x2b-prereg-2026-07-20-0ae5111.json`, **6,865 B**, SHA-256
  `eab5ec0b32d6590473f6a70cd06a61f53408ef968565eee9b44a38159456e38e`.
  It records `proof_execution_performed:false`, `gate_verdict:null`, the clean
  source commit `0ae5111`, every corrected term/postdiction/X0 delta, and the
  future schema-2 run contract; it is not a gate result.

  **X0 propagation; every changed number.**  At the default 100+50, k=4
  point, gpt-oss changes from **2,874,728** to **2,858,312 full**: old coarse
  LogUp/PCS/chain **2,866,560 / 6,632 / 1,536** become TableBank **2,578,270**,
  blind **158,616**, Hadamard **86,529**, scalar **18,917**, product **9,362**,
  PCS/zero **3,342**, and T1 reducer **3,276**; total delta **-16,416
  (-0.5710453302016747%)**.  Dense changes from **370,680** to **462,339**:
  old **367,728 / 904 / 2,048** become TableBank **366,389**, blind **65,816**,
  Hadamard **11,961**, scalar **8,965**, product **4,354**, PCS/zero **486**,
  and T1 reducer **4,368**; total delta **+91,659 (+24.727258012301714%)**.
  All X0 MAC, auth/correction, lookup-row, commitment and PCS-claim values are
  unchanged; both new totals remain non-gating projections.

  R1 remains external and pending with no cryptographic-review assurance.
  Kimi3 is reviewing detached worktree `f05d727`; main remains append-only:
  no rebase, no force-push, and that worktree is untouched.

- **2026-07-19 (X2 synthetic MoE e2e closed on clean `87ce25b`; gate
  verdict: FAIL; package stopped before X3)**: the append-only CPU-only run of
  record is `benchmarks/results/x2-moe-2026-07-19-87ce25b.json`, schema 1,
  **11,803 B**, SHA-256
  `ea0be31ecd60c275363292cf506aa7c8b30ae3a0a4f98e99fd9bfc38bdc924cd`,
  full SHA `87ce25b43b6946c528ddb71108539ad711ced64e`, `git_dirty:false`, four
  Rayon workers on the four-logical-CPU VM.  The shape is exactly T=7, L=2,
  d=48, d_ff=80, six query/two KV heads of width eight, eight experts/top-2
  and vocabulary 97.  Rust and the independent numpy exporter match the
  402,774-B `x2-moe-v1.golden.bin` byte-for-byte, k=1 and k=2 have identical
  native outputs, and no real gpt-oss export ran.

  **Binding 20% counter gate.**  Native work is exactly **316,464 / 316,464
  MACs**, ratio **1.0 PASS**.  The ledger labels `12,495 / 19,313` are
  unambiguously analytic **logical / padded lookup rows**, respectively, and
  apply equally to k=1 and k=2.  Both measured paths are **12,523 logical /
  19,346 padded / 82 sites**, versus 12,495 / 19,313 / 80: deltas
  **+28 / +33 / +2**, ratios **1.0022408963585434 /
  1.001708693626055 / 1.025 PASS**.  Sub correlations are **350,304** at k=1
  versus 330,820 (**+19,484**, ratio **1.058896076416178 PASS**) and
  **349,793** at k=2 versus 330,484 (**+19,309**, ratio
  **1.0584264291160843 PASS**).  Full correlations are **12,462** at k=1
  versus 17,040 (**-4,578**, ratio **0.731338028169014 FAIL**) and **12,482**
  at k=2 (**-4,558**, ratio **0.7325117370892019 FAIL**).  These two values
  are below the inclusive lower bound 0.80.  The preregistered symmetric band
  is not relaxed merely because the canonical existing-class schedule used
  fewer full correlations than the planning proxy; the milestone verdict is
  therefore verbatim **FAIL**.

  **Correctness and composition evidence.**  Both honest proofs, verifiers,
  `Pi_Prod`, `Pi_ZeroBatch` and all three PCS components accept.  Prover and
  verifier correlation vectors agree exactly, as do allocation and channel
  digests.  k=1 uses **350,304 sub / 12,462 full / 4,922 domains**; k=2 uses
  **349,793 / 12,482 / 4,933**.  The one two-phase TableBank session contains
  exactly **82 sites / 6 contents / 1 finalization**.  The D3 session has
  exactly **3 commitments / 40 claims** and three sequential existing
  `MultiOpen` component proofs under unchanged `P4_LAYER`; this is one
  response opening session and keeps the CPU peak at
  **0.3265571594238281 GiB**.  Each PCS proof is **17,256,480 B**.  Transcript
  bytes are **20,258,656** at k=1 and **20,254,888** at k=2; PCS proof bytes
  are a labeled subset of those transcript totals, not an additional response
  amount.

  Instance counters are **5,203,276 Fp2 + 3,308,230 base = 5,864,922.0
  E-mult** for both paths; k=1 has zero other-counter work and k=2 adds
  **3,067 Fp2 = 3,067.0 E-mult** for the existing T1 reducer.  Clean timings
  are k=1 prover/verifier/closure **0.053704982 / 0.019513061 / 1.021350117
  s** and k=2 **0.047056557 / 0.018261011 / 0.998960699 s**.  PCS
  commit/open/verify totals are **0.878154763 / 0.103166348 / 0.032662452 s**
  at k=1 and **0.867306513 / 0.092889063 / 0.032393240000000004 s** at k=2.

  Wrong expert set, authenticated score swap, forged comparison limb,
  lower-ranked expert-5 substitution, k=2 internal-state substitution and
  chunk-boundary substitution all reject.  The permanent crafted all-equal
  native row returns D1 `[6,7]`; the already-closed X1 proof smoke remains the
  proof-level tie regression.  The native rule is descending
  `(score, expert_id)`, so the higher expert id wins ties.

  **Logged deviations, none cryptographic.**  The existing LogUp engine pads
  the one-row final rsqrt site to two rows.  Explicit route-weight requant
  proof adds 28 logical / 32 padded rows and two sites, and router denominator
  authentication adds eight values/layer.  Non-power-of-two Q/K/V slices use
  explicit public-weight openings; vocabulary row 7 is the canonical zero
  embedding pad.  Every small synthetic weight block occupies one distinct
  P4 row and extends its source MLE point to 14 variables with public-zero
  high coordinates, exactly the X1 outer-padding pattern.  The three PCS
  components run sequentially for memory containment, and the existing P4
  reciprocal-input-floor deviation is reused.  No new argument class, PCS
  parameter/opening semantic, Lean, PCG/setup/lifecycle, pod, X4/X5 or real
  model artifact was introduced.

  The constrained full Rust workspace is green (`-j 2`, serial test threads;
  `volta-proto` **96 passed / 1 production-size ignore**), Python is **23/23**,
  both X2 budget profiles pass their self-checks, and all X2 permanent tests
  pass.  Kimi3 R1 remains external and no cryptographic-review assurance is
  claimed.  Section 7.3 makes any milestone FAIL a hard stop, so X3 has not
  begun; resumption needs an explicitly approved new preregistration.

- **2026-07-19 (X1 routing soundness closed on clean `6be165f`; gate
  verdict: PASS; X2 unlocked)**: the append-only CPU-only run of record is
  `benchmarks/results/x1-routing-2026-07-19-6be165f.json`, schema 1,
  `git_dirty:false`, four Rayon workers on the four-logical-CPU VM.  The
  fixture is exactly T=31, L=4, d=48, 32 experts/top-4: **3,968 logical /
  4,096 padded** comparison cells.  Router scores are signed i16, so the
  C3b-style affine comparison is in `[0,65535]`, pins `B=16`, and uses exactly
  one u16 range limb per expert/token.

  **Binding comparison gate.**  The isolated comparison plus public-selector
  bridge measures **77,056 Fp2 + 53,232 base multiplications = 87,702.4
  E-mult total**, or **707.2774193548387 E-mult/token-layer**.  Against the
  frozen **82,138.296875 total / 662.4056199596774 per-token-layer** analytic
  prediction, measured/predicted is **1.0677406683202548**, inside the inclusive
  `[0.80,1.20]` interval: PASS.  This counter includes the actually executed
  equality-table construction, public-weight tag folds and nonzero Fp2-by-Fp
  value folds; no threshold or prediction changed after measurement.  The
  remaining router instances are **251,804 Fp2 + 115,968 base = 274,997.6
  E-mult**; all TableBank-closed instances total **3,253,015 Fp2 + 2,078,320
  base = 3,668,679.0 E-mult**.

  **Soundness/composition evidence.**  Honest, unchanged-P4 PCS, Pi_Prod and
  Pi_ZeroBatch acceptance are all true.  Wrong expert set, authenticated-score
  correction swap, forged comparison root/limb, tied expert-27 substitution,
  worse tied cutoff, duplicate id and out-of-range id all reject.  The
  all-equal crafted tie accepts exactly D1 `[28,29,30,31]`, confirming the
  native descending `(score, expert_id)` rule in which higher expert id wins.
  Prover/verifier correlations are exactly **205,568 sub / 4,714 full / 1,896
  domains** on both sides; allocation digests and post-protocol channel-probe
  digests match exactly.  Transcript size is **4,918,992 B**.

  Static router weights use one commitment and one batched opening under the
  unchanged `P4_LAYER` parameters `(rows=1024, col_bits=14, pad=512,
  code_bits=15, Q=200)`, with four claims and a **3,199,008-B** PCS proof.
  The only layout deviation is explicit: each 2^11 router claim occupies the
  first sub-block of one P4 row and is extended by three public-zero high
  coordinates; no PCS parameter or opening semantics changed.  The existing
  P4 reciprocal-input deviation is reused and logged in the JSON; no new
  argument class, cryptographic/Lean/PCG/setup/lifecycle change was made.

  Rust and independent numpy bytes match the committed
  `x1-router-v1.golden.bin`; the toy architecture exporter exercises D2/D4
  framework contracts and records `real_gpt_oss_export:false`.  Clean-record
  timings are prover **0.02821949 s**, verifier **0.010159865 s**, closure
  **0.335487867 s**, PCS commit/open/verify **0.303313581 / 0.025567098 /
  0.005477533 s**, peak RSS **0.27573394775390625 GiB**.  The full Rust
  workspace passes with `-j 2` and serial tests (`volta-proto` **91 passed /
  1 production-size ignore**); `pytest -q` is **22/22** and
  `budget_moe.py --model all --json` reports `self_checks.all_pass:true`.
  Kimi3 R1 remains external and pending, so this PASS claims no cryptographic
  review assurance.

- **2026-07-19 (runtime `ModelConfig` foundation closed on clean `9a4c688`;
  gate verdict: PASS; X1 routing unlocked)**: the append-only run of record is
  `benchmarks/results/x1-foundation-2026-07-19-9a4c688.json`, schema 10,
  `threads:4`, with `git_dirty`, `git_dirty_before_benchmark` and
  `git_dirty_before_serialization` all false.  The official T1 validator and
  the X1 compatibility gate both PASS.  Reference/observed projection digests
  are identically
  `e02838130d35cead251d5dddbafbe20389a098d0107cdb30d7cc3cc897d0648c`,
  the mismatch vector is empty, normal/chunked proofs accept, and the full
  50-token greedy decode is bit-exact.

  **Binding byte/counter reproduction.**  Response is exactly
  **84,544,352 B**, split **28,778,208 / 12,492,256 / 43,273,888 B** across
  prefill/decode-marginal/PCS.  Authentication/reducer/q-bridge bytes are
  exactly **38,348,720 / 22,848 / 672 B**.  Sub/full correlations are exactly
  **4,793,590 / 181,933**; product/zero closures are exactly
  **21,667 / 8,170**; E-mult buckets are exactly
  **2,800,595,736.8 / 114,852,961.2**.  The deterministic stage allocation
  digest remains
  `8af19ba8054ecd33f8e220100567890068c1a4b92bdeb6e171d3c3adb105fc40`,
  and every mock/real-prepass and prover/verifier allocation/channel parity
  predicate is true.

  **Measured CPU diagnostics.**  Same-process warmup plus three-round ABBA G2
  gives C3b **19.056046518 s**, T1 **19.123072303 s**, delta
  **+0.35172975116685745%**, below the **20.0088488439-s / +5%** ceiling:
  PASS.  Three measured proof-response samples are
  **18.366054831 / 18.129569691 / 18.303896849 s**; reported medians are
  prefill **9.917698995 s**, response **18.303896849 s**, decode marginal
  **8.339792816 s**.  The five 10-token chunk times are
  **1.866452928 / 1.851418687 / 2.222941866 / 2.257193954 /
  2.246878238 s** and last/first is **1.203822611485651 <= 1.5**: PASS.
  Peak RSS is **8.343120574951172 GiB**.  The disk-backed fase-D spool is
  exactly **114,611,091 entries / 4,584,443,640 B**, written in
  **7.489389043 s**, with `resident_raw=0` and heap trim true.

  `cargo test --workspace -q` exits zero (`volta-gpt2` **17/17**;
  `volta-proto` **88 passed / 1 preregistered production-size ignore**),
  `pytest -q` is **18/18**, `budget_moe.py --model all --json` reports
  `self_checks.all_pass:true`, and `git diff --check` is clean.  The runtime
  refactor is therefore the required foundation checkpoint; X1 routing may
  begin, but this entry makes no X1 routing, X2 or X3 verdict.  No pod,
  cryptographic/Lean/PCS/PCG change, real gpt-oss artifact or review-assurance
  claim is involved.

- **2026-07-19 (X1 foundation storage incident and provider-contract
  comparator correction; verdict still pending)**: the first production-size
  foundation attempt placed the **4,584,443,640-B / 114,611,091-entry** fase-D
  correlation spool below `/tmp`.  On this VM `/tmp` is a 5.9-GiB tmpfs, so
  the spool consumed RAM and the process ended after its authorization had
  been durably burned.  It emitted no JSON, the connection/authorization is
  not reused, and no protocol state was recovered.  All subsequent
  production-size CPU records use a fresh durable store and disk-backed
  `TMPDIR` below `/var/tmp`; this is a storage-only correction and the
  four-worker protocol schedule is unchanged.

  The next clean `370023b` execution completed and is retained append-only as
  `x1-foundation-2026-07-19-370023b.json`.  Its existing T1 gates are green:
  accepted/golden/chunked, exact **84,544,352 B** response,
  **38,348,720 B** authentication corrections, **4,793,590 / 181,933**
  sub/full correlations and G1/G2/G3 exact-counter predicates all pass.  The
  newly added X1 cross-run comparator nevertheless reported false.  Before
  assigning a foundation verdict, inspection found three harness errors: it
  compared lifecycle/setup digest hex strings that the frozen provider
  contract deliberately seeds from a fresh connection/response binding; it
  compared the hardware dispatch label `aes-ni` against function-identical
  `armv8-ce`; and direct `serde_json::Number` equality distinguished parsed
  and in-memory representations of equal floating-point values.  The
  deterministic per-stage allocation-schedule digest is unchanged at
  `8af19ba8054ecd33f8e220100567890068c1a4b92bdeb6e171d3c3adb105fc40`,
  and all existing mock/real-prepass plus prover/verifier allocation/channel
  parity predicates are true.

  The X1 compatibility projection is therefore corrected to the already
  binding provider semantics: exact output bytes, labels, counters, PCS map,
  proof sections and deterministic stage schedule; exact true parity
  predicates within the fresh session; no literal cross-run equality for
  session/entropy-derived digests or hardware dispatch names.  Section-level
  comparison uses canonical serialized JSON bytes.  The retained diagnostic
  projects identically to the T1 reference under that contract, and a
  permanent regression test pins the projection digest.  This restores the
  preregistered provider contract rather than rebaselining or relaxing any
  byte/counter gate.

  The fresh-store rerun at `e71f6da` is likewise retained append-only as
  `x1-foundation-2026-07-19-e71f6da.json`.  Disk-backed spooling completed in
  **8.364 s** with `resident_raw=0`; the official T1 validator passes, G2 is
  **+0.386%** and the flat ratio is **1.23**, with every byte/counter/golden
  invariant exact.  Its custom flag still named the two scalar-soundness
  floats as mismatches even though the emitted decimal strings are identical.
  The remaining harness cause is that `serde_json::to_value` preserves a
  different intermediate `Number` representation for an in-memory `f64`
  than parsing the reference bytes; both final files parse to identical
  provider projections.  The comparator now normalizes the current report by
  serializing and reparsing the exact JSON representation that will be
  written.  This is again report-only: neither soundness computation nor any
  gate operand changed.  A third clean run from a fresh store is required
  before a foundation PASS or any X1 routing code.

- **2026-07-19 (X1--X3 Phase 2 explicitly approved; foundation starts;
  review clarifications pinned)**: the user approved Phase 2 under the existing
  CPU-only/no-pod and no-new-argument-class boundaries.  The router's native
  cutoff tie rule is descending `(score, expert_id)`: at equal score the
  larger expert id wins, matching C3b last-maximum.  The permanent all-equal
  crafted tie therefore selects `{28,29,30,31}`, encodes the D1 vector as
  `[28,29,30,31]` with cutoff 28, and rejects a substituted expert 27.  X2's
  `12,495 / 19,313` labels mean **logical / padded lookup rows**, respectively,
  and both counts are identical for k=1 and k=2; only the pinned sub-correlation
  totals differ.  Implementation begins with `ModelConfig` and cannot enter X1
  routing code until the exact GPT-2 T1 compatibility gate PASSes.

- **2026-07-19 (X1--X3 Phase-1 preregistration complete; HARD STOP for user
  review; no Phase-2 authorization or verdict)**: authorization was limited
  to `docs/x123-harness-design.md`, this ledger preregistration, and the
  analytic synthetic profile/counter anchors in `scripts/budget_moe.py`.  No
  Rust/prover implementation, clean milestone record, pod action, gpt-oss
  download/export, X4/X5 work, Lean/PCS/PCG change or cryptographic review was
  performed.

  **Runtime foundation and binding compatibility gate.**  The selected design
  generalizes `volta-gpt2` in place around a validated runtime `ModelConfig`;
  `volta-proto` remains one model-agnostic crate and is not forked.  Config
  fields cover runtime/non-power-of-two dimensions, layers, experts/top-k,
  explicit GQA mapping, attention window schedule, norm/activation, sinks,
  RoPE, all per-layer/operator/block shifts and T1 `thin_k`.  Matrix MLEs are
  zero-padded row-major with column variables LSB-first and points
  `r_col || r_row`; aligned PCS blocks retain the existing `BlockClaim`
  invariants.  Before any X1 code, the GPT-2 T1 path must reproduce the clean
  reference byte-for-byte at **84,544,352 B**, including the exact
  28,778,208 / 12,492,256 / 43,273,888-B phase/PCS split, all counters,
  deterministic allocation-schedule digest, all existing within-session
  allocation/channel parity predicates, 50-token golden and full workspace.
  Fresh connection/response and entropy-derived digest hex strings are
  required to be fresh rather than cross-run-equal, per the frozen provider
  contract.  The gate has zero tolerance and cannot be rebaselined inside X1.

  **Exporter contract.**  Per-architecture adapters share one calibration,
  canonical-artifact and golden framework.  A deterministic toy adapter will
  exercise synthetic MXFP4-block and BF16 source interfaces only.  D2 remains
  canonical offline MXFP4 dequantization to private i16 plus explicit
  per-block power-of-two shifts, with no 4-bit credit.  D4 remains P5-style
  BF16-to-i16 calibration and bit-exact golden validation.  No real gpt-oss
  decoder, artifact or onboarding time is claimed or authorized.

  **D1 leakage and X1 statement.**  Public response metadata contains exactly
  four distinct selected expert ids in canonical `[cutoff, remaining three in
  ascending-id order]` form.  The cutoff is therefore a designated slot in
  D1's public four-id vector, not an extra field.  The accepted leakage is the
  complete expert-choice trace, a function of private router weights and known
  tokens; router scores, threshold and unselected weights remain private.  The
  native tie rule ranks descending `(score, expert_id)`, so the larger id wins
  a tie.  Scores are produced through the existing
  router GEMM/requant/exp/reciprocal path and
  conservatively pinned to the signed-i16 envelope `[-32768,32767]`.  For
  cutoff `tau`, threshold `theta`, and public
  selected bit `m_j`, X1 range-checks exactly one value per expert:

  ```text
  score_j - theta - [j < tau]   if selected
  theta - score_j - [j > tau]   otherwise.
  ```

  The affine comparison lies in `[-65536,65535]`, giving **B=16**.  One u16
  limb is derived as minimal: honest nonnegative values fit below `2^16`,
  while a bounded negative residue cannot enter the limb range because
  `2^16 + 2^17 < p`.  Every relation maps to existing committed GEMM,
  public-selector/private-argmax, range limb, LogUp/TableBank,
  Hadamard/`Pi_Prod` or `Pi_ZeroBatch` machinery.  A required new argument
  class is a hard stop.

  The X1 fixture is T=31, L=4, d=48, 32 experts/top-4: **3,968 logical** and
  **4,096 padded** comparisons.  Scaling the measured C3b comparison class
  gives **82,138.296875 E-mult** total and
  **662.4056199596774 E-mult/token-layer**.  The binding inclusive acceptance
  ratio is **[0.80,1.20]**, or
  **529.924495967742..794.8867439516129 E-mult/token-layer**, measured as the
  isolated comparison/selector `ctr_instances` delta.  Wrong expert set,
  score swap, forged limb and last-index tie forgery are permanent rejects;
  the honest all-equal row selects `[28,29,30,31]` with cutoff 28.

  **X2 shape and 20% counter gate.**  The added analytic profile is T=7,
  L=2, d=48, d_ff=80, 6 query/2 KV heads of width 8, 8 experts/top-2,
  vocabulary 97 and full-causal attention.  X2 uses the existing GELU expert
  body so SwiGLU remains ordered in X3.  Its fixed routes touch every expert
  with a balanced `[2,2,2,2,2,2,1,1]` row histogram.  Script anchors are
  **316,464 MACs**, **12,495 logical / 19,313 padded lookups**, **80 sites**,
  sub correlations **330,820 / 330,484** for k=1/k=2, full-correlation proxy
  **17,040**, and **3 commitments / 40 stacked claims**.  Prover and verifier
  must agree exactly; each predicted counter ratio must be inside inclusive
  **[0.80,1.20]**.  Three commitments, 40 claims, one batched PCS opening and
  one TableBank phase-1 finalization are exact invariants.  Both k paths must
  have identical native outputs and retain the X1 and T1 cheating smokes.

  **X3 op/golden gate.**  X3 overlays RMSNorm, clamped SwiGLU, public-linear
  zero-new-lookup RoPE, GQA 6/2, two authenticated sinks/query-head and layer
  windows `[full, sliding(4)]` on T=7, d=48/d_ff=80.  Each piece is mapped in
  the design to existing LN/Hadamard, LogUp/range/saturation, public
  sumcheck, CacheSeg/BandShape and closure classes.  Rust and numpy must match
  full arrays op-by-op and e2e.  The permanent pad-poison test targets row 7,
  hidden columns 48--63, FFN padding and vocabulary padding; canonical pads
  are ignored/zeroed and admitting one sentinel rejects.  Any op requiring a
  new proof relation hard-stops X3.

  **Records and closure discipline.**  Append-only clean CPU records are
  `x1-foundation-*`, `x1-routing-*`, `x2-moe-*` and `x3-ops-*`.  Each milestone
  requires its gate, JSON, verbatim PASS/FAIL ledger row and commit checkpoint
  before the next starts.  Timed ratios use same-process ABBA only.  X4, X5
  and real gpt-oss export remain out of scope.  R1 is still pending externally
  with Kimi3, so this preregistration claims no cryptographic-review assurance.

- **2026-07-19 (T1 CLOSED on clean `b14577e`; G1/G2/G3/G4 PASS)**:
  the exact post-thinning correction split is residual seams **3,686,400 B**
  + architecture-specific, non-thinnable GPT-2 MHA K/V **22,118,400 B** +
  other **12,543,920 B** = **38,348,720 B**.  Against C3b, all
  **21,196,800 B** saved bytes come from residual seams; K/V and other are
  unchanged.  GQA 64/8 remains phase-X context only and does not enter this
  GPT-2 verdict.

  **G1 PASS verbatim.**  Response **84,544,352 B <= 85,000,000 B**;
  authentication corrections **38,348,720 B <= 38,348,720 B**; reducer
  transcript **22,848 B**; q bridge **672 B**; PCS **43,273,888 B**.  The
  measured response is identical to the approved projection and is now the
  exact pinned reference.  Counters are exact: sub/full
  **4,793,590 / 181,933**, product/zero **21,667 / 8,170**,
  `ctr_instances=2,800,595,736.8`, `ctr_other=114,852,961.2`.

  **G2 PASS verbatim.**  Four-worker same-process CPU ABBA measures frozen
  C3b **38.118634535 s** and T1 **38.317683641 s**, ratio
  **1.005221832 <= 1.05** (+0.522183%).  The A100 wall-only+counters record
  measures prefill **2.4120642 s <= 10 s**, decode marginal
  **1.618844210 s <= 4 s**, H2D **67,618,556 B <= 100,000,000 B**, maximum
  absolute synchronization **0.117210172 s <= 0.150 s**, and flat
  **1.231125469 <= 1.5**.  Its response-session prove wall is
  **4.031071209 s**.  Every pod absolute gate passes.

  **G3 PASS verbatim.**  Golden 50-token decode is bit-exact; normal and
  chunked responses accept; mock/real counters, channel ledger and allocation
  digests match; permanent forged-reducer/seam, chunk-entry, malicious,
  replay/position and non-power-of-two tests are green.  `cargo test
  --workspace` and `pytest -q tests/test_report.py` are green, as are the two
  explicit production-size `c3_weights_two_weight_set_leakage_smoke` and
  `c3_embed_two_weight_set_leakage_smoke` runs (**2/2 PASS**).  The record's
  `t1_exact_counter_pass` and `t1_g3_pass` are true.

  **G4 PASS verbatim.**  Both schema-10 files have full SHA `b14577e12f35276c31482cf24dba41b6478905f9`,
  `git_dirty:false`, real-PCG/AES, Q=120, one connection setup and five
  completed response ordinals with zero repeat base-OT/extension bytes.  Both
  pass the new fail-closed validator; historical validators and records are
  unchanged:

  - `benchmarks/results/t1-cpu-real-2026-07-19-b14577e.json`, SHA-256
    `7fe5eeaec1601ab3af9951129a7684de6bdf81b8ec8ac4afe94fc8369fe6febb`;
  - `benchmarks/results/t1-a100-realpcg-v4-2026-07-19-b14577e.json`, SHA-256
    `1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`.

  The RunPod record identifies `us-md-1`, A100-SXM4-80GB, driver
  `580.126.16`, CUDA `12.8`, Ubuntu `24.04.3 LTS`, EPYC 7742, 2,004 GiB RAM
  and 128 vCPUs.  Setup traffic is **38,371,465 B** in both records; CPU/GPU
  setup walls are **65.470727 / 38.845157 s**, and their unlinked persistent-
  volume spools are **4,584,443,640 B**, `resident_raw=0`.

  **Recorded operational deviations, no gate credit.**  The first local-VM
  CPU attempt was killed with exit 137 after spooling because that host had
  insufficient memory; it wrote no JSON and its one-time stores were never
  reused.  Per the product-owner steering, both official records were rerun
  on the authorized pod.  The pod's network FUSE volume handled checkout,
  stores, spool, staging and sequential Cargo artifacts, but repeatedly left
  small-file Cargo test/build finalizers waiting after their compiler child
  exited.  No such wrapper produced a test verdict or consumed a record
  store.  The native production runner was therefore built in a temporary
  Cargo target on the same pod; its **139-MB archive** was written to the
  persistent volume (archive SHA-256
  `a4ce55ed33b68a37a879c1a5e4778c2e6c34f3b1d2986003d78a23c7fcf65614`),
  copied there as a standalone binary (SHA-256
  `cb4f3fe4a4829a21b34689894d2d37d14b41cda7baa88fa056db503814e3b10f`),
  and the temporary target was removed before the run.  The CUDA ABI-28
  library SHA-256 is
  `3006acee18830bdad2fe2a4f73bea28c190bebfcfe072d4a3b768b9eb391893f`.
  The full resident record itself provides the production CUDA end-to-end
  verdict; local workspace and CUDA compile checks were already green at the
  checkpoint.  This storage workaround changes no source, protocol, timing
  policy, counter, record byte, or gate.

  R1 remains explicitly outside this closure and deferred to Kimi3 under the
  immediately following product-owner decision.  T1 therefore closes with no
  independent/adversarial cryptographic-review assurance.

- **2026-07-19 (R1 removed from the current operational package; deferred to
  Kimi3)**: the product owner removed the implementing assistant's R1
  cryptographic review because it does not have the required trusted-access
  posture.  X0/T1 implementation, records and closure continue under the
  approved gates, but this package makes **no independent or adversarial
  cryptographic-review assurance**.  Kimi3 will perform the original R1 scope
  a posteriori, explicitly including M11a--c statement-vs-implementation
  fidelity and the Rust eq-reducer mirror.  The concise handoff is
  `docs/r1-kimi3-handoff.md`.  This entry supersedes only the operational R1
  assignment in the 2026-07-18 authorization; it does not alter any T1 gate,
  theorem statement, test, counter or historical record.

- **2026-07-18 (T1 Phase-2 development instrumentation; counter-model
  reconciliation, not a gate record)**: one full T=100+50/Q=120 mock-backed
  development run measures the binding communication geometry exactly:
  response **84,544,352 B**, authentication corrections **38,348,720 B**,
  reducer transcript **22,848 B**, q-bridge corrections **672 B**, protocol
  sub/full correlations **4,793,590 / 181,933**, and product/zero closure
  lengths **21,667 / 8,170**.  These match the approved Phase-1 package to the
  byte and claim.  The run is intentionally not a clean CPU/pod record and
  carries no gate verdict.

  The run also exposes one non-binding cost-model arithmetic deviation.  The
  preregistered auxiliary-root formula `11*N/2 + 2*(n-1) - 6` subtracted six
  operations that had already been accounted, once per each of 46 claims.
  The implemented counter mirror therefore measures **24,872,338**, exactly
  **276** above the preregistered **24,872,062**.  Keeping the historical
  report buckets distinct, `ctr_instances` changes
  **2,775,723,398.8 -> 2,800,595,736.8** (+24,872,338) and `ctr_other`
  changes **90,080,563.2 -> 114,852,961.2** (+24,772,398 for reducers and
  q-evaluations).  The combined measured delta is **49,644,736**, versus the
  preregistered **49,644,460**.  This 276-operation reconciliation changes no
  transcript, correlation allocation, soundness bound, witness semantics, or
  binding gate; clean CPU/pod records still must pin the gate measurements.

- **2026-07-18 (M11 Lean package GREEN; T1 Phase 2 unlocked)**: the
  Lean-first stop is cleared.  `VoltaZk/BoundaryThinningSound.lean` proves
  M11a (`lateClaimAt_valid`, the pointwise verifier-key mirror, and
  `clear_of_late_claims_zero`), M11b
  (`affine_late_atoms_then_chain_sound`), M11c
  (`shared_pair_collapse_then_chain_sound`), and the concrete
  `C=2+n_cols` full-vector `layer_leaf_ones_aux` instantiation, including its
  exact terminal, child-fold, degree-three compressed-wire, and affine-chain
  obligations.  `lake build` completes **3,246 jobs**; `Audit.lean` runs a
  `#print axioms` audit on every new theorem, with only Lean's standard
  logical axioms where needed.  The source contains zero `sorry`/`admit`, no
  new `axiom`, and no `Ideal.LogUpGKRSound`.  The four M11 rows in
  `docs/protocol-sketch.md` are marked proved.  This satisfies the product
  owner's prerequisite exactly and starts the already authorized Rust phase;
  it is not a T1 gate verdict.

- **2026-07-18 (T1 Phase 1 approved; M11 Lean authorized before Rust)**:
  the product owner accepts the honest **84,544,352 B** projection in place of
  the former ~75-MB aspiration.  Binding Phase-2 gates are response
  **<=85,000,000 B**, corrections **<=38,348,720 B**, same-process CPU ABBA
  T1/C3b **<=1.05**, and the unchanged pod absolute contract.  Closure must
  pin the exact measured response reference rather than silently retaining the
  projection.

  M11a--c, `lateClaimAt_valid`, the pointwise verifier-key mirror, and the
  concrete `C=2+n_cols` full-vector LogUp leaf instantiation are authorized;
  no Rust may begin until `lake build`, zero-sorry and `#print axioms` audits
  are green without `Ideal.LogUpGKRSound` or a new axiom.  A green M11 directly
  authorizes T1 Phase 2 and then R1.  An M11 failure is a hard stop whose report
  must also analyze whether the discarded common-point restructure avoids the
  specific failed obligation; only the user may revive that design.

  The correction categories reconcile exactly:
  `24,883,200 + 22,118,400 + 12,543,408 = 59,545,008 B` at C1 and
  `24,883,200 + 22,118,400 + 12,543,920 = 59,545,520 B` at C3b.  The full
  **512-B** delta is selected-row authentication in `other`.  Context, not an
  excuse: GPT-2 MHA pays the full **22,118,400-B** K/V stream; same-query-width
  GQA 64/8 reduces that architecture-specific stream by about 8x for the
  phase-X gpt-oss target.

- **2026-07-18 (T1 boundary thinning, amended Phase-1 preregistration;
  HARD STOP on M11 and user review)**: authorization was limited to the X0/T1
  design package.  No Lean proof, Rust/protocol change, validator rebaseline,
  benchmark record, pod action, or R1 review was performed.

  **Measured split first.**  The requested C1/core stream is **59,545,008 B**;
  the immutable current C3b stream is **59,545,520 B**, with the exact 512-B
  difference from selected-row authentication.  Current C3b divides into
  residual/block seams **24,883,200 B**, K/V **22,118,400 B** and other
  **12,543,920 B**.  K/V is not thinnable: every layer's cache feeds later
  positions and later chunks through M4/CacheSeg.  The k=4 schedule keeps X0
  plus F3/F7/F11 per phase, with X4/X8 as canonical aliases; it removes 23
  residual matrices per phase and projects **38,348,720 B** corrections.
  The reconciliation is exact:
  `24,883,200 + 22,118,400 + 12,543,408 = 59,545,008 B` at C1 and
  `24,883,200 + 22,118,400 + 12,543,920 = 59,545,520 B` at C3b.  The entire
  **512 B** delta is the 64 selected-row Fp corrections in `other`; there is no
  residual discrepancy.  Context only: GPT-2 MHA pays full-width K/V auth,
  while same-query-width GQA 64/8 reduces that architecture-specific stream by
  about 8x on the phase-X gpt-oss target.  This does not relax the GPT-2 T1
  corrections gate.

  **All blockers and amended construction.**  Every ABO has independent FFN-
  residual and LN2 consumers; every internal X at layers
  `{1,2,3,5,6,7,9,10,11}` has independent attention-residual and LN1
  consumers; every removed internal FBO also needs downstream-to-upstream
  claim transport.  Nonzero seams, zero-shift canonical wires, proof order,
  padding, public scheduling/domains, group/chunk endpoints and K/V fan-out
  are enumerated with file:line evidence in
  `docs/t1-boundary-thinning-design.md`.  T1 selects the 2026-07-15 §4.1.4
  sound alternative: after both consumer claims are sealed, sample a fresh
  affine challenge and run one degree-two eq sumcheck to yield a single
  post-rho claim for upstream chaining.  Forcing heterogeneous residual and
  LN/LogUp relations into one common-point instance would require a larger
  selector/scheduler rewrite and is not covered by P7 homogeneous batching.

  **Formal coverage and hard stop.**  M1 covers the public affine algebra; M2
  covers the exact response-wide zero list; M3 supplies the degree-sum method
  but its present final opening is fixed before rho; M6 covers fresh-window
  ZK; M10 supplies the generic fixed-rest connection union bound.  M4 remains
  load-bearing for K/V; M5 and M7--M9 keep their existing roles.  None proves
  the recursive late scalar, its compressed blind-to-clear bridge, or the
  concrete non-empty LogUp auxiliary transport through the full vector of
  base/column split pairs and the shared child-bit challenge.  The document
  therefore records the minimal M11a--c package: an exact authenticated
  late-row bridge, a generic affine vector-terminal sumcheck theorem, one
  shared-pair-vector collapse theorem, and the full Rust LogUp instantiation
  obligation.  These cover the degree-two eq and degree-three aux cases.  M11
  is statement-only and unproved; its proof, build and
  `#print axioms` audit must precede any Rust.  `Ideal.LogUpGKRSound` may not be
  imported.

  **Exact soundness/counter map.**  Per phase the claim-driven rewrite retires
  `12+12+9+9+4+9=55` legacy rows (FFN residual, LN2/ABO, internal
  attention/X, internal LN1/X, nonzero seam endpoints, identity seams) and
  adds 21 reducer terminal rows.  For one prefill plus one decode chunk,
  `closure_zero_claims` is therefore **8,238 -> 8,170**; the product list stays
  **21,667**.  The explicit reducers contribute `21*35+21*33 = 1,428`, and
  the 46 newly non-empty aux lists add 46 affine-collapse roots; the
  incremental M11 numerator is therefore **1,474**.  The tracked closure-plus-
  T1 subtotal is **21,669 + 8,171 + 1,474 = 31,314**, a net
  **+1,406/|E|** over the corresponding C3b subtotal and 113.065480 bits for
  that subtotal alone.  This is not an absolute protocol bound: existing
  degree-three, shared-child and downstream base terms remain in the pinned
  C3b bound.  M10 lifts the exact increment R-linearly without an independence
  assumption; PCS remains the separately pinned 78.809-bit term.

  **Cost and gates.**  The 42 reducers add **22,848 B**, **1,428** full
  correlations and **20,643,672** charged E-mults.  Retargeting 23 relation
  outputs per phase into existing aux paths adds no round messages or
  correlations but was preregistered at **24,872,062** E-mults.  The 42 required q-column
  evaluations add **672 B**, **42** full correlations and **4,128,726**
  E-mults.  The preregistered total charged delta is therefore
  **49,644,460** (1.788523%) and fold-inclusive vector work is
  **57,901,912** (2.086012%).  The later Phase-2 instrumentation entry above
  preserves and explicitly reconciles the 276-operation deviation rather
  than rewriting this preregistration.  The exact
  response projection is prefill **28,778,208 B**, decode50 **12,492,256 B**,
  PCS **43,273,888 B**, total **84,544,352 B**.  It plainly
  **does not clear ~75 MB** because K/V and PCS remain.  The 2026-07-18 product
  decision accepts this projection and binds G1 at **response <=85,000,000 B**,
  with the exact measured reference to be pinned at closure; corrections stay
  bound at **38,348,720 B**.
  G2 proposes fresh same-process CPU ABBA T1/C3b `<=1.05` and keeps pod
  prefill/decode/H2D/max-sync/flat at `10 s / 4 s / 100 MB / 0.150 s / 1.5`;
  G3 requires bit-exact golden, malicious/replay/leakage/non-pow2/parity tests
  and exact counters; G4 requires append-only CPU/pod records and a new profile
  only after M11, explicit Phase-2 authorization, and separate paid-pod
  confirmation.

- **2026-07-18 (X0 MoE design complete; no MoE implementation authorized)**:
  `scripts/budget_moe.py` adds the ModelConfig/Workload analytic budget in P0
  style, with standard-library text/JSON output and self-checks against P0,
  C1, C3b and the T1 correction split.  For prompt 100 + deferred decode 50,
  gpt-oss-20b projects **485,359,730,688 MACs**, **46,485,064** current /
  **18,405,064** k=4 authenticated values, **371.881 / 147.241 MB**
  corrections, **417,267,938 / 687,568,448** logical/padded lookup rows,
  **25** commitments and **3,316** stacked PCS claims upper bound.  The dense
  8B/GQA point projects **1,076,133,888,000 MACs**, **617.081 / 189.459 MB**
  corrections, **408,291,250 / 586,362,944** lookup rows, **33** commitments
  and **452** claims.  The full-correlation columns are explicitly non-gating
  planning proxies; no PCS byte/timing or gpt-oss onboarding measurement is
  fabricated.

  **D1--D4 are closed for design.**  D1 publishes the expert-choice trace as
  response metadata, accepting that leakage while requiring X1 to bind
  top-4/ties.  D2 canonically dequantizes MXFP4 to private i16 plus explicit
  per-block power-of-two shifts under frozen requant semantics, with no 4-bit
  credit.  D3 uses one commitment per layer with canonical per-expert blocks,
  plus global embedding/unembedding, and one batched response opening.  D4
  exports BF16 attention/router/embed material through P5-style symmetric i16
  calibration and bit-exact golden validation.

  **Private-weight decision (authoritative):** gpt-oss-20b is treated as if
  proprietary and current PCS hiding is the target.  The closed table is:

  | Backend | Use case | Comm/response | Assumption |
  | --- | --- | ---: | --- |
  | PCS hiding (current) | proprietary weights | 105.7 MB | binding |
  | Direct evaluation | open weights, client can store | ~62.4 MB | none (info-theoretic) |
  | Non-hiding PCS, public root | open weights too large | ~105 MB | binding |

  **Prerequisite amendment.**  Scaling-note lever A, verifier-cached PCS
  consistency columns, is UNSOUND under the 2026-07-15 §4.6.A attack; lever B,
  Packed16, is shelved on its ~1.55-GB/session cost.  They are not Phase-X
  prerequisites.  The prerequisites are now **T1 boundary thinning** for
  corrections/correlations and **X4 folding PCS** for openings.  X1--X3 and X4
  are later packages.

  **Long-output product requirement.**  Responses are arbitrarily long;
  download is linear in `T_dec`, and full-attention prover work per token is
  linear in context (window-bounded on sliding layers), matching native shape.
  The per-token budget of record is:

  | Per generated token | Budget / exact reconciliation | Required shape |
  | --- | ---: | --- |
  | corrections/proof | **~445 KB/token** product budget; C3b exact **390,928.64 B/token**; T1 projected **249,845.12 B/token** | download linear in `T_dec` |
  | private argmax | **~1.2 KB/token**; exact **1,156.8 B/token** | download linear in `T_dec` |
  | variable download | **~446.2 KB/token** standing product budget | download linear in `T_dec` |
  | prover | full attention linear per token in context; sliding layers window-bounded | same asymptotic shape as native |

  The caps to clear later are the five-chunk domain scheme
  (`layer_dom_base=16+32*c`), flat-cost validation only through context 150,
  and one 110M connection at about 2.2k current token-equivalents.  None may be
  hidden by correlation reuse or per-token proof/PCS instances.

  **Provider envelope (four integration quantities).**  Setup is
  **48.838774638 s + 38.371465 MB/connection**; current response is
  **105.717632 MB + 0.39092864 MB/token marginal**, with T1 preregistered at
  **84.544352 MB + 0.24984512 MB/token**; current rho is
  **3.486621672 prefill / 0.842661976 decode**; onboarding is
  **t_export + t_calibration + t_commit** with exporter/golden/calibration/
  block-map/root binding.  Only the GPT-2 one-off commit component,
  0.202467381 s, is measured; the gpt-oss total is honestly unmeasured.
  `docs/x0-moe-design.md` is the one-page contract and detailed rationale.

- **2026-07-18 (C3b CLOSED; G1/G2/G3/G4 PASS)**: clean implementation SHA
  `161fc59acf6fff2f221a0c5bd2cf2148bde0d09f` closes the efficiency
  iteration without changing L1, PCS soundness, correction streams, Lean,
  setup tuple or lifecycle semantics.

  **G1 PASS.** The full 11 GiB CPU VM record uses real/AES connection mode,
  one warmup plus three measurements and Q=120. Golden, normal/chunked,
  verifier, PCS and digest checks accept. Transcript and packed response are
  exactly **105,717,632 B <=115,000,000 B**, including **43,273,888 B** PCS,
  with **0 B** public logits and exact label/category sums. Peak RSS is
  **8.628704 GiB**. The 114,611,091-entry connection pool is held in a
  4,584,443,640 B anonymous spool with zero resident raw entries after
  spooling; D4 is resolved without per-response-pool fallback. Record:
  `c3b-cpu-real-2026-07-18-161fc59.json` (SHA-256
  `e0921daf7de81a9cdb5bdc08a84b195c6afa4f9880840dadb162bc5fa23caab1`).

  **G2 PASS on both hosts.** CPU same-process ABBA measures fase-D
  **17.288045940 s** and C3b **19.801130069 s**, delta **+14.536542% <=+15%**
  and ceiling 19.881252831 s. The pod uses only the pinned **4.911634 s**
  denominator: C3b is **4.183010942 s**, delta **-14.834637%**, below the
  exact **5.6483791 s** ceiling. No alternative denominator is used.

  **G3 PASS.** `cargo test --workspace` is green. The production private
  argmax test accepts honestly and rejects wrong-token/forged-limb proofs;
  crafted-last-tie accepts and an earlier tied token rejects. Exact geometry
  is three limbs, six Range(16) jobs, 2,512,850 real and 2,621,440 padded
  entries/limb. The registered production leakage smokes were run
  sequentially on the 11 GiB VM: weights PASS in 32.58 s and embed PASS in
  9.58 s. Evidence: `c3b-g3-2026-07-18-161fc59.json` (SHA-256
  `c7efe6bfa12de26e1081930e4b2e0d2794cad1bc96e126501c5a74f5cf307c4a`).

  **G4 PASS.** Fresh `runpod-a100-realpcg-v3`, A100-SXM4-80GB, Rayon=8,
  ABI-28, wall-only+counters and real/AES records prefill
  **2.536908629 s <=10**, decode **1.652745976 s <=4**, maximum H2D
  **88,812,564 B <=100,000,000**, maximum absolute sync
  **0.114894647 s <=0.150**, flat **1.228450597 <=1.5**, exact
  105,717,632 B response, zero public logits, golden/acceptance/counter/
  allocation/channel parity and explicit resident cleanup 0 B. Record:
  `c3b-a100-realpcg-v3-2026-07-18-161fc59.json` (SHA-256
  `fe016a033cc076c3c1e7a063e528d6b79129992414ddd3309bfc3bbbd2f03c58`).

  The exact L4 measurement is **157,705,530 E-mult equivalents**, versus the
  amended 222,570,169.125 central projection and 260M ceiling; its transcript
  is **57,840 B**. The post-implementation CUPTI census records **1,423,901**
  launches, 69 families and zero drops. Five `private_argmax_*` families are
  new; their grid-x values are 64--16,384 and none is degenerate. Artifact:
  `c3b-postimpl-cupti-kernel-census-2026-07-18-161fc59.json` (SHA-256
  `cf92e16736d5b3d6e527fe58f04a07adea5e422f0908cb4baf8a750a2b5aeb0c`).
  The diagnostic L4-off/public-logit flag is absent from the source and CLI;
  no record mode can republish logits. Historical C3 `5a2edbe` measurements
  and fase-D/P7b references remain immutable.

- **2026-07-18 (C3b Phase 1 diagnosis + preregistration amendment; Phase 2
  subsequently authorized)**: the product owner authorized the paid pod
  diagnosis. Phase 1 completed at its hard stop; after reviewing this entry
  and `docs/c3-pcs-communication-design.md`, the user explicitly authorized
  Phase 2 in the same session.

  **H2D audit.** Current L4 builds the Range(16) histogram and all six
  2^22-entry limb columns on the host. Per response it uploads one 262,144 B
  `u32` histogram, six 33,554,432 B packed-u64 leaves, six 67,108,864 B
  F_p2 aux columns, and 27,756 B of challenge/aux point/id/weight vectors:
  **604,269,676 B** direct. Private weighted-row logit openings add a net
  **720 B**, reconciling the same-host L4 on/off H2D delta exactly at
  **604,270,396 B**. Against the same-host fase-D geometry, total C3 H2D
  delta is 604,916,316 B; L4 explains **99.8932%**. This confirms D2.

  **Pod diagnosis.** The fail-closed CUPTI trace at clean source
  `5a2edbed63c7a32bfc11edf826ce05f6e711c36b` records **1,414,565** kernels,
  64 families and **0 dropped records**. One stdout-JSON interleaving was
  losslessly reconstructed before parsing. C3 adds no CUDA/`volta-accel`
  family; grid-x=1 records remain existing reduction tails, scalar helpers
  and the legacy small-term matrix-fold path, not a new P7b-style family.
  Exact families and grids are append-only in
  `c3b-cupti-kernel-census-2026-07-18-5a2edbe.json` (SHA-256
  `3621119b04733d34988edf36cc4f86b9559d816eda7b701519b3b5e40175a098`).
  CUPTI absolute walls are non-gating.

  The same-host wall-only+counters mock experiment uses one warmup + three
  measured repetitions. Fase-D geometry proves in **4.911634 s**; C3 geometry
  with L4 disabled (dirty diagnostic, logits explicitly published) proves in
  **4.801484 s**; C3 L4-on proves in **9.776394 s**. Thus isolated L4 is
  **+4.974910 s**, while C3 L1/L3 geometry without L4 is **-2.243%** versus
  fase-D (prefill -2.743%, decode marginal -1.466%). No hidden L1/L3 GPU
  regression is found. The diagnostic artifact is
  `c3b-l4-ablation-diagnostic-2026-07-18-5a2edbe.json` (SHA-256
  `d073e6e14cedb361105b6855c2ba90ad2a117302b6bd1b6a97c24040ee5939e9`);
  it is never a gate record.

  **Soundness/ties.** The frozen tied-wte operands obey
  `|L_j| <= 768*32768^2 < 2^40`; C3b conservatively pins B=41. For bounded
  comparison value x, a 16L-bit unsigned range excludes a negative field
  residue when `2^(16L)+2^(B+1)<p`. L=3 satisfies
  `2^48+2^42<p`; L=2 cannot cover valid positive differences up to the
  pinned bound. Three limbs are therefore minimal. C3b ranges only
  `s_j=L_tau-L_j-[j>tau]` and reconstructs `d_j=s_j+[j>tau]`, replacing the
  current duplicate three-limb d + three-limb s representation without
  weakening the last-maximum statement. It never truncates or requantizes
  logits. A crafted equal-max row must accept only Rust's last tied index; a
  forged earlier tie, wrong token or forged limb must reject.

  **Packing/cost.** Five positions occupy 251,285 real entries in a 2^18
  public segment. Ten segments are scheduled per limb as 2^21 + 2^19, so
  padded/real is **2,621,440 / 2,512,850 = 1.043213881**. Three limbs total
  **7,864,320** entries, exactly 0.3125 of C3's 25,165,824. This is one
  logical flat batch per limb with two power-of-two jobs, six jobs total and
  never per-position instances. All use the existing shared Range(16)
  TableBank multiplicity and alpha, bound in protocol phase 1. The central projection
  is **222,570,169.125** L4 `ctr_instances` E-mult; the amended projection
  ceiling is **260,000,000** (9.931% of the 2,618,017,868.8 C1 reference).

  The old L4 allowance is amended from 65,536 B to the honest measured
  **66,016 B**; no work is authorized merely to recover 480 B. Three limbs
  and shallower jobs project packed response no larger than the immutable C3
  **105,725,808 B**, with binding ceiling **115,000,000 B**. L1 remains
  PINNED: nominal 1/4, Q=120, 78.809294874 bits, 43,273,888 B. No PCS
  parameter, correction stream, Lean theorem, setup/PCG tuple, lifecycle or
  capability changes.

  **Phase-2 resident/D4 contract and result.** Resident logits feed device kernels
  for diffs, selectors, three limbs, is-max and multiplicity histograms; no
  witness-derived steady-state H2D or repetition re-upload is allowed. L4
  buffers join workspace accounting and cleanup is 0 B. Full real response
  H2D measures 88,812,564 B, below 100,000,000 B. The post-fix CUPTI census
  has zero drops and no new degenerate family outside the legacy
  terms<256/terminal path.
  CPU uses Rayon over blocks/limbs. The connection harness reuses fase-D's
  `CanonicalBatchLift`/two-batch stage-3 machinery under the 4 GB cap and
  exposes canonical bounded correlation chunks so the full 110M pool never
  co-resides with PCS scratch. Allocation/channel digests, one-time domains,
  Delta, setup traffic and burn semantics stay exact. The true connection
  run fits the 11 GiB VM at 8.628704 GiB; no per-response-pool fallback is
  present.

  **Binding Phase-2 amendments made before implementation.** For the pod G2,
  the sole denominator is pinned to the 2026-07-18 same-host fase-D ablation
  control, **4.911634 s**. The <=+15% gate is computed only against it, giving
  the exact ceiling **5.6483791 s** (reported **5.648379 s**); no later or
  historical denominator may replace it. The diagnostic L4-off/public-logit
  switch was removed before closure; no record-capable mode can disable L4 or
  republish logits.

  **Phase-2 implementation, before clean records.** Resident logits now feed
  device-side strict differences, public selectors, three-limb decomposition
  and the shared Range(16) histogram; the six 2^21/2^19 jobs enter one
  round-synchronous batch and the existing TableBank alpha. The exact
  production geometry measures **157,705,530** L4 E-mult equivalents (PASS
  versus 260M), **57,840 B** L4 transcript and **105,717,632 B** total
  transcript with 43,273,888 B PCS and zero public logits. The L4-off mode is
  absent from the source and record CLI. All error paths free the new device
  owners and explicit resident cleanup remains 0 B.

  The true connection path serializes the terminal 110M correlation pool to
  an anonymous unlinked 0600 file in 2^16-entry chunks, drops the raw heap
  vectors, and range-reads only each response allocation into its final pool;
  page-cache ranges are discarded after write/read. The full workspace is
  green. The ignored production-size private-argmax test was run explicitly
  and accepts the honest proof while rejecting wrong-token and forged-limb
  variants. Both registered production leakage smokes were also run
  explicitly on the 11 GiB VM: weights PASS in 33.90 s and embed PASS in
  8.92 s, after fixing their previously unexercised power-of-two padding and
  PCS-scratch co-residency.

  A full dirty/mock pod diagnosis (1+3) measures prove-response **4.924231 s**,
  maximum H2D **29,267,044 B**, maximum absolute sync **0.120330433 s**, flat
  **1.246401384** and explicit resident cleanup **0 B**. These values confirm
  the intended direction but are not G2/G4 evidence. Clean real/AES CPU/pod
  records and the post-implementation CUPTI census remain mandatory.

  **Binding closure gates, reconfirmed verbatim.** G1: clean full T=100+50
  real-default connection-mode CPU run, packed response <=115,000,000 B,
  exact categories, zero public logits, then current validators rebaselined
  to the new exact reference while historical references remain untouched.
  G2: paired same-host prove-response delta <=+15% on CPU (ABBA), and pod
  prove-response <=5.648379 s under wall-only+counters against the pinned
  4.911634 s denominator. G3: full capability/adversarial parity including
  crafted/forged ties, wrong token, forged limb, exact counters and both
  production-size leakage smokes actually run. G4: fresh
  `runpod-a100-realpcg-v3`, prefill <=10 s, decode <=4 s, H2D
  <=100,000,000 B, max absolute sync <=0.150 s, flat <=1.5,
  golden/acceptance/counter/digest parity and response bytes equal to the new
  exact G1 reference. Append-only artifacts are `c3b-*.json`. Any failure is
  recorded honestly with its census and stops the iteration; no gate is
  relaxed, response bytes are not traded back and L4 is not disabled to pass.

- **2026-07-17 (C3 L1--L4 implementation and E2E table refresh)**: Phase 2 wired the selected
  PCS geometries and private last-maximum proof into both host and resident
  response paths. The report has explicit `--c3`/`--c3-record` modes, emits
  zero public-logit bytes and leaves immutable historical profiles unchanged.

  Exact accounting finds **66,016 B** of L4 transcript, 480 B above the
  preregistered allowance; clean CPU/A100 real-PCG table runs now measure the
  packed response at **105,725,808 B**, with **43,273,888 B** PCS and no public
  logits. CPU response/session medians are **20.880/36.120 s**; A100 medians
  are **9.101/10.362 s**. Setup remains the unchanged connection record:
  **69.328 s CPU / 48.841 s pod** and **38,371,465 B**.

  The full 64x65,536 six-limb range argument adds **712,224,541.2** measured
  E-mult equivalents in `ctr_instances` alone, superseding the +9.656%
  estimate. Response proving rises **25.17% CPU / 112.17% A100** against the
  preceding table; A100 maximum H2D is **693,055,968 B** and maximum sync wall
  is **0.150158884 s**. These diagnose material G2/G4 risks but are not a
  formal gate verdict: the table runs use real per-response pools to isolate
  online wall, because the connection-scoped C3 harness OOMs when its 110M
  setup allocation co-resides with PCS scratch on the 11 GiB CPU VM. No G1
  validator rebaseline or paired G2 record has landed.

  Raw real records are `c3-table-cpu-real-2026-07-17-5a2edbe.json`
  (SHA-256 `399934ff895f0129430fa86cd9cc15ef53b9b714241e592fd3c9a391d741195c`)
  and `c3-table-a100-real-2026-07-17-5a2edbe.json`
  (`c2520b2f1310f67352ef82574e1988fb58e320bc4bc6d77da012a74aef08a6ec`).
  The authoritative table and remaining G1--G4 contract are in
  `docs/c3-pcs-communication-design.md`.
  Local `cargo test --workspace` is green; the production-size private-logit
  e2e also passes explicitly. The two production-size leakage smokes are
  registered but remain unrun, so G3 is not yet claimed.

- **2026-07-17 (fase-D CLOSED; G4-v2 PASS; mock→real criterion (5)
  ENACTED)**: the absolute-sync amendment was committed before implementation
  and measurement at `121f3ed`; the fail-closed v2 harness was then implemented
  and locally tested at clean full SHA
  `e95b839ea2922b789532e2e7744eaa8a47ea5850`. The implementation changes only
  report/profile selection and validation: no CUDA primitive, proving path,
  protocol message, challenge order, Lean theorem, correlation allocation or
  byte count changes. Local evidence is **206/206 Rust tests** and **6/6
  Python report tests**; pod ABI-28 accelerator preflight is **34/34**.

  The append-only non-gating quick
  `runpod-a100-realpcg-v2-quick-2026-07-17-e95b839.json` reports prefill/
  response/decode **1.483749 / 2.443617 / 0.959868 s**, response-session
  **3.033199 s**, absolute sync **0.079527509 s**, informative fraction
  **2.621902%**, H2D **23,450,996 B** and flat **1.048976**. Its pod G2 setup
  is **48.645252 s**.

  **G4-v2 PASS.** The full clean
  `runpod-a100-realpcg-v2-2026-07-17-e95b839.json` is accepted by the local and
  remote fail-closed selector with `p7b_all_gates_pass:true`. The three
  response-session walls are **5.516184 / 5.535013 / 5.466491 s**. Their
  absolute synchronization walls are **0.123481929 / 0.123237276 /
  0.119906904 s**; maximum **0.123481929 <=0.150000000 s PASS**. The still-
  mandatory informative fractions are **2.238539% / 2.226504% / 2.193490%**,
  proving that v2 did not silently apply the retired 2% ratio. All sessions
  retain exactly **59,850** host-output boundaries.

  Every carried gate passes: upper-median prefill **2.728029 s <=10**, decode
  marginal **1.581874 s <=4**, H2D **88,139,652 B <=100,000,000**, exact
  packed response **136,526,530 B**, flat ratio **1.218719 <=1.5**, frozen
  50-token golden decode, normal/chunked acceptance, 13/13 PCS, anti-replay,
  protocol closure and mock/real counter/allocation/channel-digest parity.
  The three measured prove-response samples are **4.289535 / 4.309903 /
  4.243821 s**. CUDA-event timing calls remain zero.

  Pod-host G2 also passes: stage-3 usable **110,918,718**, total allocatable
  **114,611,091**, exact setup traffic **38,371,465 B** = base OT **16,411** +
  OT extension **38,217,099** + GGM **134,910** + consistency **3,045**,
  directionally **31,581,007 B P→V / 6,790,458 B V→P**. Setup is
  **48.841262 s**: prelude **10.666108 s** (base OT **0.029500**, OT extension
  **1.525290**, path **3.040952**, recursive GGM/check/LPN **0.022265 /
  0.035441 / 0.179805**, main **0.418383 / 0.578481 / 4.225368 s**) and stage-3
  GGM/check/LPN **11.494012 / 6.270755 / 18.276588 s**. Prover high-water is
  **3,880,267,768 B** under 4 GB.

  Flip criteria are now final: **(1) REMOVED** by product-owner decision with
  no replacement obligation; **(2)/(3) SATISFIED** by
  `flip-readiness-2026-07-15-117df7d.json`; **(4) ACCEPTED** at the measured
  8.451--8.609 s / 31,261,434 B fase-B costs; **(5) ENACTED** by this ledger
  entry and its checkpoint after clean CPU and G4-v2 gates. Real/AES is the
  default backend and new records carry `pcg_production_ready:true`; historical
  records are untouched and mock is demoted to an explicit test/diagnostic
  backend refused by record modes.

  The registered GKWY fixed-key-AES assumption and Delta-per-connection
  whole-connection-burn semantics remain exactly as documented. The M10
  amendment remains the proved theorem set `response_domains_noncolliding`,
  `connection_response_sound_scalar`, `response_bad_card_le`,
  `connection_m4_soundness_union_bound`, `connection_corrections_uniform`
  and `connection_responses_perfect_zk`; this closure does not change its
  modeling boundary. Backlog: boundary thinning and pool prewarming only if
  later product measurements justify them; Packed16 remains blocked. G3 passed, so
  no 600M binding-gate promotion is opened. After result copy/checksum
  verification, terminating PID 1 was observed to restart the container and
  is explicitly not counted as a billing stop. From the authenticated SSH
  session, the pod-scoped credential then submitted the official GraphQL
  `podStop` mutation for `qg71cf7i8bsn66`; the RunPod control plane returned
  `desiredStatus:"EXITED"`, after which direct SSH returned `Connection
  refused`. Raw SHA-256: quick
  `a6be1e5a81e85a17b5e38b0b720ff8c763b397cf4dcbc90508206504ee2f6609`;
  full `8b2b3cdc1a4ac50f81f8e641d3e580f2d6c9449f26ac876c80b12bbbd2184f42`.

- **2026-07-17 (G4-v2 amendment preregistered before implementation/run)**:
  two clean v1 records did not meet their original ratio gate and remain only
  as immutable raw/audit evidence; they are not reclassified. The prospective
  `runpod-a100-realpcg-v2` profile replaces only that denominator-sensitive
  ratio with maximum absolute synchronization wall **<=0.150000000 s**. The
  fraction remains informative and every other gate is unchanged. Exact v1
  measurements, probe results, rationale and hashes live in
  `docs/fase-d-g4-sync-gate-amendment.md` and the append-only result JSONs.

- **2026-07-16 (fase-D Part B interim clean records; closure withheld)**: all
  preregistered records were executed without
  changing their gates. New records use the real default, AES-128-MMO and
  `pcg_production_ready:true`; historical records are untouched and mock is
  still refused by record-producing modes. This entry records measurements
  and a negative binding verdict. It is **not** the requested fase-D closure
  and does **not** enact criterion (5).

  **CPU G1 PASS.** Clean full T=100+50/Q=200 record
  `fase-d-2026-07-16-cad1c09.json` at full SHA
  `cad1c09aebe04a648db4c53482e609aa79d91136` passes the frozen 50-token
  decode, normal/chunked acceptance, 13/13 PCS checks, closure, real/mock
  counter/allocation/channel-digest parity and exact packed response
  **136,526,530 B**. Flat last/first is **1.173506**. Median prefill/response/
  decode-marginal are **10.028513 / 16.681091 / 6.582644 s**. One fase-D
  connection serves all five warmup/measured/chunk sessions: only response 1
  records base OT **16,411 B** and OT extension **38,217,099 B**; responses
  2--5 repeat zero. Its terminal counters record stage-1 generated
  **110,918,718**, consumed **39,370,258**, burned **71,548,460** and no
  available/reserved output after explicit close.

  The G1 setup is **69.327875 s** total on the 4-core aarch64 host. Prelude is
  **9.057823 s**: base OT **0.025370**, OT extension **1.316318**, path
  preprovision **3.314632**, recursive GGM/check/LPN **0.055752 / 0.076162 /
  0.092536**, and main GGM/check/LPN **0.982760 / 1.243136 / 1.865916 s**.
  Stage 3 is GGM/check/LPN **31.727262 / 13.650124 / 13.073428 s**. Exact
  traffic is **38,371,465 B** = base OT **16,411** + OT extension
  **38,217,099** + GGM **134,910** + consistency **3,045**, directionally
  **31,581,007 B P→V / 6,790,458 B V→P**. High-water is
  **3,863,490,552 B** under the 4,000,000,000 B cap.

  **CPU G2 PASS.** `fase-d-scale110m-2026-07-16-cad1c09.json` reports
  stage-3 usable **110,918,718** and terminal-one total allocatable
  **114,611,091** with the same exact **38,371,465 B** setup traffic. Total
  setup is **67.797930 s**; prelude **9.009579 s** and stage-3 GGM/check/LPN
  **31.033474 / 13.539857 / 11.877418 s**. The exact prelude sub-split is base
  OT **0.025768**, OT extension **1.319349**, path **3.099505**, recursive
  GGM/check/LPN **0.057623 / 0.075840 / 0.092274**, and main GGM/check/LPN
  **1.091809 / 1.284039 / 1.809511 s**.

  **CPU G2b PASS.** `fase-d-connection-2026-07-16-877411b.json` at full SHA
  `877411b2432afd1ede80d0082d0403a75f9f4614` serves three accepted responses
  in one active connection; responses 2/3 repeat **0 B** base OT and **0 B**
  OT extension. The success-connection setup is **64.550697 s**. A separate
  connection accepts response 1, injects malicious-check abort on response 2,
  records **0 B** repeated base traffic, terminally burns, and rejects durable
  reopen with `connection identity is terminally burned; resume rejected`;
  its setup is **73.035204 s**. The first attempt stopped before JSON because
  the reporter-only MAC assertion had its sides reversed (`m == k + Δr`
  instead of `k == m + Δr`); commit `877411b` corrected the harness and the
  clean official rerun passed. No protocol output or gate was changed.

  **CPU G3 informative PASS.** `fase-d-scale600m-2026-07-16-877411b.json`
  generates **665,512,308** gross stage-3 outputs across six stages, reserves
  **32,608,970** as child bases and leaves **632,903,338** stage-3 plus
  **3,692,373** main-residual allocatable correlations. Total wall is
  **440.855595 s**. Exact traffic is **38,587,700 B** directionally
  **31,653,062 B P→V / 6,934,638 B V→P**. Maximum observed prover buffer is
  **1,269,347,424 B**, well under 4 GB. Per-stage GGM/check/LPN seconds are:
  (1) **43.868002 / 17.288003 / 12.284511**, (2) **44.722928 / 16.722612 /
  11.833508**, (3) **42.458874 / 16.393455 / 11.929678**, (4) **42.842001 /
  16.700760 / 11.784448**, (5) **43.116702 / 16.647698 / 11.901108**, and
  (6) **43.311286 / 16.604363 / 11.824091**.

  **Pod interim record.** The clean v1 run passed every correctness,
  communication, proving and pod-host G2 check but did not close the then-
  binding synchronization ratio gate. Exact measurements remain in the raw
  JSON and the later G4-v2 amendment rather than being duplicated here.

  Criteria remain resolved exactly as preregistered: **(1) REMOVED** by the
  product owner with no replacement obligation; **(2)/(3) satisfied** by
  `flip-readiness-2026-07-15-117df7d.json`; **(4) ACCEPTED** at the historical
  8.451--8.609 s / 31,261,434 B costs; **(5) NOT ENACTED** in this interim
  entry. M10 remains the proved theorem set
  `response_domains_noncolliding`, `connection_response_sound_scalar`,
  `response_bad_card_le`, `connection_m4_soundness_union_bound`,
  `connection_corrections_uniform`, and `connection_responses_perfect_zk`.
  The registered GKWY fixed-key-AES assumption and Delta-per-connection whole-
  connection-burn semantics are unchanged. Boundary thinning, pool prewarming
  and Packed16 remain out of scope. G3 passed, so no
  600M binding-gate promotion backlog is opened.

  Raw SHA-256: G1 `5c4090a7296a791ab1e205ce85584327a31ce308f392926340d13d28ab3be9d4`;
  G2 `501e0b44e4ea47f352700d4d725920f2a31c2675589da6d16a5caffacd5cab00`;
  G2b `78cac4d46d3e0f2e434cd01f1a59213afd12863182f67c4d678537bdf03af6d3`;
  G3 `25bfe81f3f4a2fe407d53b192a90538faa7121dcd13672fcdac51e7da1da6100`;
  pod quick `278018abaaab434a9b92413b3464365304c97e1b5146e54009b5b818fe08ea80`;
  pod full `f0abfe7d04e8989e7687507c6ae6d1e34743aa27f23f54daafa88237352dd8f9`.

- **2026-07-16 (fase-D Part A implementation checkpoint; explicitly not the
  clean-run closure or criterion (5))**: the preregistered design is now
  implemented after the green M10 checkpoint. No official record was run, no
  pod was accessed or provisioned, and every report path still emits
  `pcg_production_ready:false`.

  `volta-pcg` accepts only the exact production setup/main/stage-3 tuples and
  rejects every `TEST_ONLY_INSECURE_*` tuple before cryptography. One
  connection performs one base OT + COPEe/IKNP phase containing all six
  stage-3 path slices, keeps one verifier-only `Delta`, and activates one or
  six ordinal-domain refill stages. Each stage performs fresh beta/GGM
  corrections and a full WYKW malicious consistency check. Stage 3 streams
  two 896-block batches, fills terminal output directly in canonical order,
  or hashes/counts/releases chain-six output after reserving the next
  `B3=6,521,794` tail. Actual Vec capacities, batch tags, predecessor/child
  bases and per-worker tree/check scratch are included in a fail-closed
  4,000,000,000 B account; the effective Rayon worker count is reduced on a
  high-core host rather than exceeding the cap. The Part-B
  `fase_d_report` harness records physical/logical cores, effective setup
  workers, exact directions/categories, prelude and per-stage wall splits,
  high-water, capacity, counter/digest closure and G2/G2b/G3 fields.

  GGM node expansion now defaults to the registered fixed public AES-128 key
  with `sigma(x)=AES_K(x) XOR x` and exact `tau_0/tau_1` children. Runtime
  dispatch uses AES-NI or ARMv8-CE where detected and a function-identical
  portable AES implementation otherwise; it never silently selects BLAKE3.
  The explicit `ggm_prg:"blake3"` diagnostic path remains tested. Only GGM
  seeds/nodes changed to 16 B: BLAKE3 remains in transcript, KDF/root,
  commitment, coin/pad, hash-to-field and LPN-matrix roles. Fase-B's frozen
  31,261,434 B record remains historical; fase-D code asserts only byte
  reconciliation until Part B supplies its new exact measured categories.

  `ConnectionStore` uses immutable connection identities and append-only,
  file/directory-fsynced journals. OPEN precedes independent OsRng role
  sampling; active setup can occur once. Each response still burns its
  authorization nonce before allocation and binds the complete
  `(connection_id,response_nonce,layer,head,position,tensor_tag)` domain.
  Response and connection allocation/channel digests advance separately.
  Generated/consumed/reserved-as-base/burned/available classes reconcile per
  stage; chain-six release-sink output is explicitly moved to `burned`, not
  merely hidden by the high-level API. Success keeps the connection active.
  Malicious failure, malformed frame, EOF, explicit abort, TTL, close, Drop,
  or crash-detected reopen terminally burns every residual pool and refuses
  resume. A response can obtain owned sub/full PCG pools from one canonical
  raw allocation without changing logical order.

  Real/AES is the default in P5, P6 and the PCG report; mock and BLAKE3 require
  explicit diagnostic mode, which cannot write a result artifact. Production
  paths require durable authorization state and use fresh OS identities; the
  P6 resident path now runs its real backend for the full preregistered 1+3
  repetitions rather than silently falling through the non-resident helper.
  The new `runpod-a100-realpcg-v1` report profile carries the wall-only,
  decode, H2D and sync-wall gates, requires the exact C1 packed response
  136,526,530 B plus mock/real counter/allocation/channel parity, and records
  the new host's CPU inventory without inheriting the old pod's CPU/region/RAM
  identity or its 144,820,930 B binding. Setup wall remains informative.

  Local tests cover production-tuple rejection, exact capacity and canonical
  batches, buffer fail-closed behavior, AES portable/hardware equivalence and
  FIPS vector, both PRGs, terminal-one and chain-six, every malicious
  GGM/correction/WYKW fault at every one of six stages, one-time response
  domains, mock/real logical counter and allocation-digest parity,
  reserved-as-base exclusion, explicit release-sink burns, three successful
  responses, response-2 whole-connection abort, kill/restart rejection,
  nonce restart rejection, TTL/close/malformed/EOF burns and channel secrecy.
  The workspace suite and the unchanged frozen model e2e tests are green.
  Non-record toy sanity on this host measured AES/BLAKE terminal-one at
  **0.289576/0.294365 s**, each **60,097 B** (45,399 B P→V, 14,698 B V→P,
  19,744 B high-water), and chain-six at **0.311647 s**, **62,252 B**,
  1,284 gross toy stage outputs, 210 reserved and 12,256 B high-water. These
  toy values are functional smoke only, not security, G2/G3, cost or gate
  evidence.

- **2026-07-16 (fase-D Part A preregistered before Lean and Rust; no clean
  record or criterion-(5) closure in this package)**: the complete design and
  gate contract is `docs/fase-d-realpcg-default-design.md`. The product-owner
  criteria resolution is recorded verbatim:

  > The mock→real default flip is APPROVED. Flip criterion (1) — independent
  > external cryptographic review — is REMOVED from the criteria list by
  > explicit product-owner decision. Record the removal as a decision; do not
  > record any replacement review obligation. Criterion (4) is ACCEPTED with
  > the measured costs (8.451–8.609 s setup, 31,261,434 B setup traffic on the
  > 4-core aarch64 VM). Criteria (2)/(3) are already satisfied
  > (flip-readiness-2026-07-15-117df7d.json). Criterion (5) — the ledger
  > decision + checkpoint enacting the flip — happens in Part B, after clean
  > runs, NOT in this part.

  Part A therefore implements real as the default for current binaries,
  benches and e2e, makes mock explicit and refuses it in record modes, but
  every Part-A artifact remains `pcg_production_ready:false`. This entry is a
  preregistration, not criterion (5) and not a production verdict.

  **Lean-first hard stop satisfied before Rust.** M10 is proved in
  `lean/VoltaZk/Connection.lean`: injective response nonces separate the full
  connection domains; scalar M4 transfers unchanged per response; a finite
  tape equivalence lifts the local scalar-M4 bound for every fixed assignment
  of the other response coins, after which the union bound loses only factor
  `R` on the common shared-Delta tape without assuming independence; fresh
  masks make all finite response/correction coordinates jointly uniform; and
  M6 gives perfect multi-response simulation with one monotonically increasing,
  one-time correlation offset. `lake build` completes 2574 jobs and
  `scripts/audit_lean.sh` reports zero `sorry`/`admit`, no named ideal axiom,
  and only `propext`, `Classical.choice`, `Quot.sound` where required. This
  authorizes Task 2 implementation; it is not a PCG realization proof, gate
  verdict, criterion-(5) closure, or production-ready flip.

  **Third stage and estimator.** Pin regular Goldilocks
  `(k3,n3,t3)=(6,520,000,117,440,512,1,792)`, 1,792 disjoint 65,536-entry
  blocks, GGM depth 16, one uniform nonzero error at one uniform position per
  block. It has `n/k=18.012348...`, consumes `k3=6,520,000` LPN bases and the
  complete `B3=k3+t3+2=6,521,794` raw input split, both below the existing
  main `U2=10,214,167`, and produces
  `U3=n3-k3-t3-2=110,918,718` usable raw outputs.

  The public Code Estimators suite at commit
  `969ef60c30cb84c25502d6b7c968f43a362bb438`, regular-noise path with its
  `q=64` log2-field argument, reports AGB **213.85**, ISD
  **208.85010924741465**, HYB **199.59980442282708**, regular-ISD
  **227.92519270931604**, and AGB2 **213.85**; HYB is the minimum. Six
  stage-3 instances subtract `log2(6)` to **197.01484192210592** bits. One
  weakest-instance estimate minus `log2(8)` gives the deliberately crude
  eight-instance floor **137.64686430760642**. One
  recursive setup at 140.64686430760642, one main at 149.4773339537398 and
  all six stage-3 instances give the summed-work-factor floor
  **140.64369866606756** bits, 12.64369866606756 above 128.

  The pinned upstream Python overflows in HYB, evaluates an invalid
  `mu=beta` Decimal endpoint, and would allocate about 5.64 GB of dense AGB2
  zero caches at this tuple. The audit uses only formula-identical base-2
  log-sum-exp, the mathematical `mu<beta` domain, sparse same-key/value AGB2
  caches, and a vectorized full legacy-AGB candidate scan followed by a
  170-digit Decimal recheck. The AGB minimizer is `(f,mu)=(1792,2141)`, degree
  2, `213.846752631460719897576401...` bits. Control calls reproduce the
  fase-B 140.646864/149.477334 minima. Reproduction is checked in under
  `scripts/estimators/`, pins NumPy 2.5.1/SciPy 1.18.0, and is hashed in the
  design document. These numerical execution shims, the
  tuple, noise model, six-instance maximum and estimator commit are pinned;
  changing any reopens preregistration.

  One connection pre-extends exactly six stage-3 path-OT slices inside its
  single base OT + COPEe/IKNP phase. Setup/main/six-stage path choices total
  `20,064 + 17,147 + 172,032 = 209,243`; one global IKNP check covers them.
  Later refills consume predecessor outputs reserved before allocation, retain
  the same verifier-only connection `Delta`, and run fresh ordinal-domain
  WYKW checks. A `terminal-one` plan exposes all 110,918,718 stage-3 outputs;
  a `chain-six` plan reserves `B3` from stages 1--5 and exposes 632,903,338
  stage-3 outputs plus 3,692,373 main residual, **636,595,711** total. A
  seventh stage is forbidden.

  **GGM amendment.** Register the GKWY ePrint 2019/074 fixed-key
  random-permutation/correlation-robust assumption. GGM seeds are 16-byte AES
  blocks, public key `000102030405060708090a0b0c0d0e0f`, and
  `sigma(x)=AES_K(x) XOR x`; children are
  `sigma(s XOR tau_b)` for all-zero `tau_0` and little-endian-one `tau_1`.
  Runtime detection records AES-NI, ARMv8-CE or portable. BLAKE3 GGM remains
  only as an explicit configuration, and every JSON records
  `ggm_prg:"aes128-mmo"|"blake3"`. BLAKE3 remains unchanged for transcripts,
  KDF/root derivation, commitments, coin/choice pads, hash-to-field and LPN
  matrix derivation.

  The 16-byte node width is binding to the traffic design. With six path-OT
  slices preprovisioned, the serialization model is
  `30,070,682 + 1,376,256*M + 43,247*A` bytes: `M=6,A=1` projects
  **38,371,465 B** and `M=6,A=6` projects **38,587,700 B**. The latter plans
  31,653,062 B P→V and 6,934,638 B V→P: base OT 16,411, OT extension
  38,217,099, GGM 350,040 and checks 4,150 B. These are calculations, not
  measurements or inherited assertions. Fase-D defines new exact category and
  direction assertions only after Part-B measurement; the frozen
  31,261,434 B assertion remains fase-B-only. Seven stages would project
  40,007,203 B and 32-byte GGM nodes would fail the gate.

  Each stage-3 instance streams exactly two canonical batches of 896 GGM
  blocks (58,720,256 rows each) under a strict 4,000,000,000 B live
  prover-correlation cap. Naive noise/output/base materialization is already
  at least 4,697,620,480 B and is forbidden. Batches are WYKW-accepted before
  publication, lifted in `(stage,row)` allocation order, digested/counted and
  released; the 600M informative path uses a release sink rather than a 15 GB
  flat pool.

  **Connection lifecycle.** Durable `create_new` plus file/directory-fsync
  connection records bind explicit connection and authenticated-channel
  identities before fresh independent OsRng role samples, verifier `Delta`, or
  the one base phase. Per-response nonces retain durable burn-before-use.
  Domains include `(connection_id,response_nonce,layer,head,position,
  tensor_tag)`; each response has its own allocation/channel digest and fresh
  masks/corrections. Per-stage counters record generated, consumed,
  reserved-as-base and burned outputs; reserved material is never response
  allocatable. Any malicious failure, malformed frame, EOF, process kill,
  explicit abort or proof failure terminally burns the connection, all pools
  and all base reservations. Reopen crash-burns an unterminated record and
  refuses resume. Success burns only the response nonce; explicit close/TTL
  burns residual pools. Wire framing remains
  `kind:u8 || length:u64_le || payload`, with Delta/delta-equivalents/role
  seeds forbidden and multi-response channel secrecy tested.

  **Part-B gates pinned now.** G1 is full CPU T=100+50/Q=200 with real/AES as
  default: frozen golden, normal/chunked, 13 PCS, closure/malicious suite,
  packed response exactly **136,526,530 B**, and mock/real logical counter plus
  allocation/channel digest parity. G2 is at least 110,000,000 usable raw
  correlations and total setup traffic <=40,000,000 B, with exact directional/
  category bytes and informative per-stage wall on both hosts. G2b serves at
  least three responses with zero repeated base-OT/OT-extension bytes and
  proves abort-on-response-2 durable whole-connection burn. G3 informatively
  generates about 600M under the 4 GB cap; failure is logged and nonblocking.
  G4 creates `runpod-a100-realpcg-v1`: prefill <=10 s, decode <=4 s, H2D
  <=100 MB, sync wall <=2%, wall-only+counters/no CUDA events, response exactly
  **136,526,530 B**, golden, flat <=1.5, replay/digest parity, plus pod-host CPU
  real-PCG physical/logical core inventory, explicit
  `pcg_setup_rayon_threads`, and informative first setup wall/traffic baseline.
  G2 host reports carry the same core inventory and PCG-worker field, separate
  from any prover Rayon setting.

  Boundary thinning, pool prewarming, Packed16/C1 Phase 2, proving path,
  proof/transcript/response/PCS bytes, Q/rate/claims/challenge order, correction
  width, golden/witness/CUDA semantics, per-token proofs/PCS claims and all old
  provider profiles/results remain unchanged. Prover time may still be traded
  for verifier time, never for final proof/response bytes or communication.
  Part A may run only tests and
  quick non-record sanity checks: no official records, pod provisioning,
  closure entry or `pcg_production_ready:true`.

- **2026-07-15 (fase-B FLIP-READINESS closed for criteria (2) and (3);
  mock default unchanged)**: checkpoint
  `117df7d5d30befefe280a995d6aee3d905d98f9e` implements the preregistered
  host-only setup pass and production provisioning/lifecycle boundary. The
  clean append-only record is
  `benchmarks/results/flip-readiness-2026-07-15-117df7d.json`, SHA-256
  `f9105c1060581a28c3f0ef496b74dd7db20132f33e5ca23605d8c45bfdd717cd`;
  it records the unchanged full geometry T=100+50/Q=200 and
  `git_dirty:false` before setup and before serialization.

  **Setup performance.** Rayon now expands the independent GGM trees,
  reconstructs punctured trees and evaluates the batched WYKW block products
  in parallel, while collecting blocks in canonical order. The normal full
  response setup measured **8.451112 s**: base OT **0.025049 s**, OT extension
  **0.963487 s**, GGM **4.632134 s**, regular LPN/output expansion
  **1.495709 s**, and malicious checks **1.334213 s**. The separately
  authorized chunked session measured **8.608849 s**; the JSON also records
  their two-instance aggregate **17.059961 s**. Against the fase-B setup
  record, the directly comparable fixed work moved GGM **16.125939 →
  4.632134 s** (−71.3%) and checks **4.978960 → 1.334213 s** (−73.2%) on this
  4-core aarch64 VM. Full-output LPN is larger than the old quick workload and
  is therefore reported, not presented as an apples-to-apples speedup. BLAKE3
  remains the PRG/KDF; no fixed-key-AES assumption or implementation entered.

  Only wall time moved. Each setup still serializes exactly **31,261,434 B**:
  **28,814,084 B prover→verifier** and **2,447,350 B verifier→prover**;
  categories remain base OT 16,411 B, OT extension 31,150,315 B, GGM 91,884 B
  and checks 2,824 B. The harness asserts these per-instance values before
  accepting a timing. Frame kinds, payload lengths, order, message schedule,
  transcript/proof paths, response bytes and allocation/challenge order are
  unchanged.

  **Criterion (2) — SATISFIED.** Production role seeds are independent
  256-bit reads from Rust `rand` 0.8 `OsRng`, whose standard build is backed by
  `getrandom`; on Linux this reaches the OS CSPRNG and blocks until its pool is
  initialized ([rand 0.8.5 feature documentation](https://docs.rs/crate/rand/0.8.5),
  [Linux `getrandom(2)`](https://man7.org/linux/man-pages/man2/getrandom.2.html)).
  The role seeds are separately domain-bound to the caller-supplied session
  identity, authenticated-channel identity and response authorization nonce.
  Both role transcripts and the channel digest start from the same binding;
  an identity mismatch is rejected before setup. No identity field was added
  to the wire.

  `ResponseAuthorizationStore` performs an atomic `create_new` of a
  nonce-keyed append-only marker, writes it and syncs both file and directory
  **before** entropy sampling or correlation generation. Markers are never
  removed on success or abort. The same nonce is therefore rejected after a
  reconnect, retry, claimed identity change, process kill or store reopen; an
  unavailable/non-durable store fails capability preflight. Tests cover
  reconnect/retry rejection, nonce reuse under changed identities,
  burn-on-error, kill/restart, and distinct seed commitments/correlations in a
  fresh restarted session. The channel-secrecy test reparses all frames and
  still finds neither role seed nor verifier `Delta`; mismatched
  session/channel identities fail closed. `cargo test --workspace` passes,
  including all 12 `volta-pcg` tests and the three existing malicious GGM/WYKW
  rejection cases.

  **Criterion (3) — SATISFIED.** The clean full real-backend record has frozen
  50-token golden decode, normal acceptance, 5×10 chunked acceptance (flat
  ratio **1.197141**, PASS), all **13/13 PCS verifications**, 96 weight + 6
  embed claims at Q=200, and product/zero protocol closure. Prover and verifier
  counters are exactly **7,443,126 sub + 176,880 full**. Real versus mock
  counter, logical allocation-digest and channel-ledger-digest comparisons are
  all true; the two real roles' allocation and channel digests also agree.
  Transcript **129,119,408 B**, PCS **66,733,504 B**, packed logits
  **7,407,122 B**, and packed response exactly **136,526,530 B** match C1.
  The JSON explicitly retains `pcg_production_ready:false`.

  **Criterion (4) — decision material only; still OPEN.** On this machine a
  response consumes one session-bound setup taking **8.45--8.61 s** and moves
  **31.26 MB** of setup traffic in addition to, and before/alongside, the
  136.53 MB packed response. At 1 Gbit/s the raw setup bytes alone are about
  0.25 s, so compute dominates this measured VM cost. If setup is synchronous,
  it is direct request latency. Once the authenticated channel and single-use
  response nonce exist, it can start before proving and overlap model loading,
  witness work or network admission; on this 4-core host the Rayon setup uses
  all cores, so useful overlap needs spare/dedicated cores or a setup worker.
  It cannot be safely reused across requests or restarted after abort: all
  generated/unused correlations and `Delta` are session-bound and burned.
  The durable authorization marker is only tens of bytes plus filesystem
  metadata per request, but it is append-only operational state and must share
  the authorization service's durability/retention policy. Correlation pools
  should remain protected in memory (or receive an explicit encrypted-at-rest
  policy) and be destroyed at the terminal session state. The product owner
  has not yet accepted these latency, traffic and lifecycle/storage costs.

  **Still open.** Criterion (1), independent cryptographic review of the
  construction/equations/parser/parameters, remains external and incomplete.
  Criterion (5), a new user-authorized ledger decision/checkpoint changing the
  default, remains incomplete. Mock is still the default and real is still
  explicit opt-in; every historical reference and verdict is unchanged. No
  C3/PCS lever, proof/message-format change, Packed16, GPU/provider work or
  Lean change entered this package.

- **2026-07-15 (fase-B FLIP-READINESS preregistered before coding; no
  default flip)**: this package is authorized to complete everything locally
  available for the five proposed mock→real criteria: implement and test
  criterion (2), land one clean full real-backend record for criterion (3),
  and write the measured operational-cost material for the product-owner
  decision in criterion (4). Criterion (1), independent cryptographic
  review, is external and remains open. Criterion (5), the ledger decision
  and checkpoint that actually change the default, remains an explicit user
  decision and is out of scope. The default remains mock throughout;
  `pcg_production_ready:false`, the explicit mock test backend, and every
  historical verdict/reference remain unchanged.

  The performance pass is host-side real-PCG setup only. Parallelize the
  genuine GGM tree expansion and batched malicious checks with Rayon on both
  roles. The baseline per setup is **22.483177 s**, split as base OT
  0.025174 s, OT extension 0.964754 s, GGM 16.125939 s, regular LPN
  0.387947 s and malicious checks 4.978960 s. No protocol equation, message
  field, frame, ordering, transcript schedule, response/proof path, allocation
  or challenge order may change. Serialized setup communication is frozen at
  exactly **31,261,434 B** per setup (**28,814,084 B prover→verifier,
  2,447,350 B verifier→prover**) and must be asserted before accepting a new
  timing. The new phase split is informative, not a gate, and must report the
  honest result from this 4-core aarch64 VM. BLAKE3 stays the GGM PRG unless
  profiling specifically establishes the PRG as the dominant residual. A
  fixed-key-AES substitution would require a separate, prior ledger amendment
  registering a cited correlation-robust fixed-key (GKWY-style) modeling
  assumption; this entry does not authorize such a substitution.

  Criterion (2) requires fresh, independent prover and verifier role seeds
  from the documented OS CSPRNG; explicit session and channel identities
  bound into setup derivations/transcripts/frames; and one single-use response
  authorization nonce consumed terminally on success **or every abort**. A
  response request cannot reconnect, retry, resume, or start a replacement PCG
  session. A killed session and any restarted process must not be able to
  reuse correlations for that authorization. Capability preflight fails
  closed if the lifecycle store cannot durably reserve/burn the nonce. Tests
  must reject reconnect/retry and nonce reuse, prove correlation non-reuse
  across kill/restart, and keep the existing channel-secrecy assertion green:
  neither `Delta` nor a role seed occurs in serialized channel bytes.

  Criterion (3) requires one append-only, clean-tree, full CPU record at
  T=100+50 and PCS Q=200 with `--pcg-backend real`: frozen 50-token golden
  decode, normal and chunked acceptance, all 13 PCS verifications, protocol
  closure, malicious tests, and exact mock/real equality of logical counters,
  allocation digests and channel digests. Packed response bytes must be
  exactly the C1 reference **136,526,530 B**. The JSON name is
  `benchmarks/results/flip-readiness-<date>-<gitsha>.json`; it must include
  the setup wall split, exact directional setup bytes, and retain
  `pcg_production_ready:false`. Setup wall/traffic stay separate from rho and
  response download. Closure records evidence for criteria (2)/(3), the
  post-parallelization numbers, and a plain-language criterion-(4) cost note
  covering per-session setup latency, 31.26 MB setup traffic,
  preprocessing/overlap and lifecycle/storage implications. C3/PCS levers,
  proof/message-format changes, Packed16, GPU/provider work and Lean remain
  out of scope.

- **2026-07-15 (C1 descoped Phase 2 closed; communication reference
  re-baselined)**: the clean full CPU record is
  `benchmarks/results/c1-2026-07-15-2a3d731.json`, produced from unchanged
  full SHA `2a3d7314bba35e18229af31c99f226c93ef12416` with `git_dirty:false`,
  T=100+50, Q=200, one warmup and three measured repetitions on the same
  4-core aarch64 machine class as the frozen P6 timing baseline.  Golden
  50-token decode, normal acceptance, chunked acceptance, all 13 PCS
  verifications, protocol closure and the flat-cost gate pass; the measured
  last/first chunk ratio is **1.218943** (<=1.5).

  Exactly nine public `shift==0` seams per phase use the canonical preceding
  layer's `ffn_block_out` authentication.  The proof contains no selectable
  alias source: the verifier derives the same-session, same-phase/chunk,
  adjacent-layer and exact-row source before consuming transcript or
  correlations.  The old `x_in` domain slot remains a tombstone, so unrelated
  K/V and layer numbering is unchanged.  Preflight rejects an empty `x_in`
  correction vector at layer 0 or either nonzero seam, and rejects any fresh
  correction vector or malformed length at an identity seam.  The existing
  position/chunk replay suite remains green; CPU and resident paths emit the
  same proof representation and the resident differential continues to bind
  proof, transcript ledger, counters and verifier result with no fallback.

  The exact measured accounting is:

  ```text
  identity aliases                    9 * 150 * 768 = 1,036,800 values
  response saving                     8 * 1,036,800 = 8,294,400 B
  transcript                          137,413,808 - 8,294,400 = 129,119,408 B
  auth_corrections                     67,839,408 - 8,294,400 =  59,545,008 B
  packed response                     144,820,930 - 8,294,400 = 136,526,530 B
  prover/verifier sub correlations      8,479,926 - 1,036,800 =   7,443,126
  prover/verifier full correlations                                      176,880
  ```

  PCS opening **66,733,504 B**, Q=200/rate, 96 weight + 6 embed claims,
  challenge order, one-time correlation semantics and packed logits
  **7,407,122 B** are unchanged.  There are zero typed lanes, no Lean change
  and no second fase-B shard; 7,443,126 remains below one shard's 10,214,167
  usable capacity.  Median prove response is **18.652767 s**, delta
  **−0.085864 s (−0.46%)** against the same-machine P6 record; median verify is
  **0.521739 s**, delta **−0.045404 s (−8.01%)**.  These timing deltas are
  informative, not new gates.

  Rust and Python validators now carry **136,526,530 B** as the C1
  communication reference.  Historical `runpod-a100-v1` rows and validators
  remain bound to exactly **144,820,930 B**; no old result/profile is mutated.
  Any later official GPU run still requires a separately preregistered gate
  profile.  Packed16, PCS Q/rate changes, argmax, GPU kernels, the sVOLE
  default flip and provider profiles did not enter C1.

- **2026-07-15 (C2 review complete: Candidate A rejected; C1 descoped and
  authorized)**: `docs/c2-packed-lane-pcg-design.md` is accepted as a valid,
  honest costing, and remains the permanent record of the decision.  Its only
  sound realization would add about **1.55 GB** setup traffic and **31--46 s**
  setup wall per session to save **32,486,400 B** of response: roughly **47×**
  more recurring bytes moved than saved.  Candidate A is rejected at this
  scale.  The `Packed16` typed lane and C1 correction packing are shelved:
  landing a proof format only the mock backend can serve, with a known
  impractical real realization, is mock-forever debt.  The typed-lane
  authorization is withdrawn.  Revisit requires a cited construction with
  setup on the order of tens of MB/session, or an explicit product decision
  that the envelope demands it.

  Fase-B returns to **full parity-candidate** status for its existing `F_p`
  lanes, without a Packed16 asterisk.  The proposed mock→real default-flip
  criterion (6), which existed only for the typed lane, is removed; criteria
  (1)--(5) are unchanged.  Mock remains the default and
  `pcg_production_ready:false` remains unchanged.

  C1 Phase 2 is authorized **only** for C1 design §4 identity-seam `x_in`
  reuse.  It adds no correlation type and opens no Lean scope.  For T=100+50,
  nine `shift==0` seams alias the producer authentication and retain their
  tombstone domain slots, saving `8 * 9 * 150 * 768 = 8,294,400 B`; projected
  packed response is `144,820,930 - 8,294,400 = 136,526,530 B`.  The one-shard
  phase-B demand is `8,479,926 - 1,036,800 = 7,443,126` sub correlations,
  below its `10,214,167` usable capacity: no second shard is needed.  PCS
  Q=200/rate/claims, challenge order, one-time correlation semantics, GPU
  kernels, provider profiles, argmax and the sVOLE default flip remain out of
  scope.  This entry supersedes the C1/C2 preregistration entries below where
  they describe C1 as blocked or Packed16 as authorized.

- **2026-07-15 (C1 §3.4 interpretation approved with a fase-C
  precondition; C1 Phase 2 remains BLOCKED)**: “frozen correlation
  semantics” means the MAC equation, verifier-only `Delta`, one-time use,
  domain separation and exact counting.  The plaintext-distribution
  catalogue is **not** frozen: the typed `(uniform u16, uniform bit)`
  `Packed16Corr` lane is authorized as an extension of the ideal correlation
  interface.  This decision does not claim that the real backend realizes
  the lane and does not authorize C1 implementation.  C1 Phase 2 remains
  **BLOCKED** until a complete fase-C design for the lane's real-PCG
  realization is separately preregistered and user-reviewed.

  The fase-B status is amended to **“parity candidate for the F_p lanes;
  Packed16 lane unrealized”**.  Its proposed mock→real default-flip criteria
  remain unfulfilled and gain item (6): **a separately preregistered and
  implemented fase-C realizes the typed lane before any flip**.  Items
  (1)--(5) in the fase-B closure entry remain unchanged.  The immediate next
  task is fase-C **design only**, with a hard stop for user review and no
  Rust, CUDA, Lean, PCG, proof-path or C1 Phase-2 implementation.

- **2026-07-15 (C2 fase-C Packed16 real-PCG design preregistered; mandatory
  user-review hard stop)**: the complete design is
  `docs/c2-packed-lane-pcg-design.md`.  This entry records a design proposal,
  not approval or implementation.  C1 Phase 2 remains **BLOCKED**, fase-B
  remains a parity candidate only for the `F_p` lanes, mock remains the
  default, and `pcg_production_ready:false` remains unchanged.

  **Selected proposal.**  Add an auxiliary malicious Ferret-Uni COT lane,
  then lift each binary COT into the existing arithmetic MAC under the same
  verifier-only session `Delta` with one canonical `F_p^2` correction and
  linearly compose sixteen authenticated bits into each uniform u16.  The
  2026-07-07 “not Ferret” decision applied to the main `F_p` sVOLE; using
  Ferret for this auxiliary bit lane is an explicit new decision proposed for
  review, not a reinterpretation of that decision.  Per COT batch, a
  transcript-bound 256-bit commit/open coin toss masks even adversarial COT
  receiver choices.  The typed plaintexts are uniform before an abort
  decision if either role is honest; a corrupt party cannot set them without
  aborting.  Because two-party fairness cannot prevent selective-abort bias,
  the design requires a single-use response-authorization nonce that is
  consumed on success or abort.  The same response cannot retry or resume;
  the entire session and all its allocations are burned.

  Exact demand is `16 * 5,529,600 + 5,529,600 = 94,003,200` authenticated
  source bits.  Ten 10,000,000-output Ferret-Uni batches reserve 100,000,000,
  leaving 5,996,800 COTs (6.379% over demand) as counted, burned headroom.
  The already-recorded `F_p` capacity defect is closed literally rather than
  erased by reclassification: two independently seeded fase-B main shards,
  under the same private session `Delta`, provide `2 * 10,214,167 =
  20,428,334` usable sub-equivalent slots.  Against C1's 13,326,486 demand
  plus six typed-lane check masks, headroom is 7,101,842 slots; the old
  3,112,319 shortfall is closed.

  The Ferret-Uni tuples are setup `(k,n,t)=(37,248,616,092,1,254)` and main
  `(588,160,10,616,092,1,324)`, exact/uniform binary noise.  The public Code
  Estimators suite at commit
  `969ef60c30cb84c25502d6b7c968f43a362bb438` reports minima 142.658999 bits
  (setup) and 153.876937 bits (main); ten-main union accounting gives
  150.555009 bits, and setup plus all ten mains gives 142.652955 bits, a
  14.652955-bit margin over 128.  Ferret-Reg is not substituted: its paper
  setup tuple estimates at only 126.591702 bits.  The two unchanged fase-B
  shards conservatively union to 139.643698 bits overall, an 11.643698-bit
  margin.  These are pinned known-attack estimates and external assumptions,
  not reductions or gate verdicts.

  Malicious security retains Ferret's complete checks and fase-B's explicit
  `kind:u8 || length:u64_le || payload` channel.  After every arithmetic-lift
  correction is transcript-bound, three independent masked random-linear MAC
  checks per typed lane give algebraic error at most `1/p^3` per lane.  Every
  malformed frame, commitment/open, check, allocation digest, counter, EOF or
  seal fails closed and burns the session.  The C1 §5 ordinary/u16/carry/full,
  row, alias and allocation-digest labels remain exact; added internal
  counters record 94,003,200 consumed, 100,000,000 generated, 5,996,800
  burned, two `F_p` shards and six check masks.

  Cost is registered honestly on top of the measured one-shard
  22.483177 s / 31,261,434 B baseline.  A second complete fase-B shard adds
  the same measured amount; the literature Ferret-Uni projection adds about
  3.786 s / 10,635,000 B; the arithmetic lift sends exactly
  `94,003,200 * 16 = 1,504,051,200 B` verifier→prover.  Including typed-row
  frame headers and 1 MiB control headroom gives a sequential component-time
  subtotal of 53.752354--68.752354 s and a setup-communication envelope of
  about 1,578,387,244 B, deltas of 31.269177--46.269177 s and about
  1,547,125,810 B over baseline.  All of this remains
  `pcg_setup_comm_bytes`, never response download or proof bytes.  At 1 Gbps,
  raw serialization alone is at least 12.627 s for the full envelope; the
  conservative non-overlapped 1-Gbps setup-wall projection is
  66.294--81.294 s, or +43.811--58.811 s over baseline.

  Alternatives were rejected explicitly.  `F_p` sVOLE plus authenticated
  bit-decomposition/truncation is circular under the current product
  discipline: 94,003,200 bitness relations would optimistically consume
  188,006,400 sub-equivalent limbs before candidate authentication and range
  bookkeeping.  Half-Tree-style subfield VOLE cannot take `F_2` as a subfield
  of the odd-characteristic `F_p^2`; a cross-characteristic conversion returns
  to the selected OT lift or the circular range machinery.

  Fase-C changes no proving path, proof/response/PCS bytes, C1 wire format,
  proof challenge order, Lean theorem, mock default, GPU kernel, orchestration,
  provider profile, gate or historical verdict.  The frozen 144,820,930 B
  response remains the reference and C1's 104,040,130 B remains a projection.
  This task stops here for review: it authorizes no Rust, CUDA, Lean, PCG, C1
  Phase-2, benchmark, artifact or default-backend work.

- **2026-07-15 (C1 Phase 1 response-communication design preregistered;
  mandatory stop before code)**: the complete design and Phase-2 contract are
  in `docs/c1-response-communication-design.md`.  This entry authorizes only
  that note and this ledger update.  No Rust, CUDA, PCG, benchmark, proof
  format or Lean implementation is authorized until the user reviews the
  design.  Scope is exactly handoff §4.6.B plus the sound subset of §4.3.
  Cached columns (§4.6.A), linear per-tensor RLC merging (§4.1.4), PCS Q/rate
  or shape changes, §4.2 argmax, GPU kernels, provider profiles, the real-PCG
  default flip and Lean beyond the named M5 extension remain excluded.

  **Packed16 boundary**: C1 packs only the four P0 i16 boundary matrices K,
  V, `attn_block_out` and `ffn_block_out` in all 12 layers over prefill 100
  plus deferred decode 50.  That is 5,529,600 values / 44,236,800 current
  bytes.  Each response batch sends a canonical little-endian u16 delta plus
  one LSB-first masked-carry bit, `2N + ceil(N/8)` bytes; public proof shape
  supplies N and unused bitmap bits must be zero.  At this geometry the new
  payload is 11,750,400 B, a **32,486,400 B** reduction.  `x_in`,
  embedding/final-LN special auths, every arbitrary-F_p vector and every
  F_p²/LogUp/PCS correction stay on the current format.

  For `B=2^16`, `H=2^15`, signed x is biased to `z=x+H`.  A typed packed
  correlation supplies independently authenticated `a` uniform in `[0,B)`
  and a uniform bit `b`, under the unchanged F_p² MAC/Delta.  P sends
  `d=(z-a) mod B` and `e=c xor b`, where `c=1` iff `a+d>=B`; both parties
  derive `[c]=e+(1-2e)[b]` and `[x]=[a]+d-B[c]-H`.  The bounded integer
  identity `z=a+d-Bc` removes the mod-2^16/mod-p ambiguity, and substitution
  in the MAC equations gives the same F_p-authenticated value consumed by
  M3/M4/M7/M8.  Uniform a makes d uniform, and independent uniform b makes e
  uniform even conditioned on d, so the two-part wire is perfectly hiding.
  Truncating the current uniform-F_p mask, accepting an unchecked prover bit,
  or reusing either lane is explicitly forbidden.

  For arbitrary canonical a,d and a bit c, the decoded integer lies in
  `[-98304,98302]`; it is in the signed-i16 interval iff c is the unique true
  carry.  A noncanonical carry therefore binds the prover to x plus or minus
  2^16 and cannot alias a second i16 value; Goldilocks embeds this whole
  interval injectively.  As in existing Pi_Auth, the correction authenticates
  the value it selects rather than independently proving witness membership.
  The existing requant/residual closures must reject the out-of-range value,
  and Phase 2 includes both a wire-flip test and a maliciously recomputed
  wrong-carry test.  No run may be promoted if composition introduces a new
  unproved range assumption.

  `Packed16Corr` is a typed extension of the ideal correlation interface: the
  MAC equation, verifier-only Delta, domain separation, one-time consumption
  and allocation digest are unchanged, but the restricted plaintext
  distributions and their counters are explicit.  The mock backend may test
  the functional path and remains non-production.  The closed real phase-B
  candidate does not realize this lane and C1 neither reopens nor resizes it;
  real packed mode must fail closed.  Logical accounting becomes 1,913,526
  ordinary subfield correlations + 5,529,600 u16 masks + 5,529,600 carry pads
  = **12,972,726**, with 176,880 full correlations unchanged.  Conservatively
  charging bit pads as subfield correlations gives 13,326,486 sub-equivalent
  limbs including full-correlation limbs, 3,112,319 above phase B's current
  capacity.  No parity/production claim follows from C1.

  This is an explicit user-review point, not a silent interpretation of the
  Phase-2 freeze: if “no change to correlation semantics” freezes the current
  uniform-F_p `SubCorr.r` distribution, Packed16 is impossible because its
  correction is uniform over F_p and cannot be losslessly represented in 16
  bits.  The preregistered design preserves the MAC/Delta/freshness/domain/
  counting semantics while adding the typed distribution required by the M5
  extension.  Phase 2 needs user approval of that boundary; otherwise §4.6.B
  stops and only identity-seam reuse remains eligible.

  **M5 plan**: Phase 2 must first add only
  `lean/VoltaZk/PackedCorrection.lean`.  Its named implementation theorem is
  `packed16_correct_valid`: valid typed u16-mask and bit-pad correlations plus
  the canonical `(d,e)` update yield a valid `SubAuthed Fp E` for the signed
  i16 plaintext.  Companion theorems `packed16_reconstruct`,
  `packed16_carry_iff_signedRange`,
  `packed16_wire_uniform` and `packed16_zeroOpen_sound` cover integer/field
  reconstruction and range, exact transcript distribution and transfer of the
  existing `1/|E|` opening bound.  Field-facing statements carry an explicit
  characteristic lower bound; they must enter the named audit with no new
  axiom and only the standard Lean axioms.  No other formal topic opens.

  **`x_in` correction to the roadmap estimate**: the frozen real artifact has
  seam shifts `[3,2,0,0,0,0,0,0,0,0,0]`, so direct auth reuse is sound only
  at nine identity seams.  Each consumer references the producer's existing
  `ffn_block_out` auth under its full session/phase/chunk/layer/row identity;
  it draws no second correlation.  Public domain slots remain tombstones so
  unrelated indices do not shift.  The two requant seams stay fresh; fusing
  them would be another protocol/formal change.  Across 100+50 rows this
  removes 1,036,800 values / **8,294,400 B** (**5,529,600 B** prefill and
  **2,764,800 B** decode), rather than silently repeating the old pre-decode `-6.9 MB`
  estimate.  Alias preflight forbids cross-session, prefill/decode, chunk,
  layer or position substitution; this is a canonical second read of one
  authenticated write, not correlation reuse, and preserves the M4 mirror.

  The two non-overlapping formulas project transcript **96,633,008 B** and,
  with unchanged packed logits 7,407,122 B, packed response
  **104,040,130 B**.  PCS stays exactly 66,733,504 B.  The measured mock-PCG
  and P3 tag-expansion rates project a bounded **+0.2--0.6 s** prover delta
  (about 1--3% of the 18.7 s CPU response); all timing remains informative,
  and a measured increase above 10% forces ledger review rather than a byte
  or soundness regression.

  **Phase-2 acceptance, preregistered now**: after explicit user approval,
  the named Lean extension and audit pass; frozen prefill/decode golden output
  is unchanged; normal/chunked acceptance, PCS, closure, anti-replay and
  tamper/overflow soundness smokes pass; ordinary/packed/carry/reuse counters,
  domains, allocation digests and byte formulas reconcile on both parties;
  CPU and CUDA use one byte-identical packed proof and land together; challenge
  order, PCS Q=200/rate/claims and all non-C1 correlation semantics remain
  unchanged.  Then and only then run one clean full T=100+50/Q=200 CPU record
  into append-only `benchmarks/results/c1-<date>-<gitsha>.json`, including
  measured byte and prover/verifier deltas and `git_dirty:false`.

  C1 **re-baselines** communication: the historical `runpod-a100-v1` profile
  and all its JSONs remain frozen at exactly **144,820,930 B**.  Rust and
  Python validators may be updated together only after the clean C1 number
  lands.  Any later official GPU run requires a newly preregistered gate
  profile carrying that measured communication reference; no old verdict is
  mutated or retroactively reinterpreted.

- **2026-07-15 (real-sVOLE fase-B hardening closed: parity candidate for the
  `F_p` lanes; Packed16 lane unrealized; default unchanged)**: checkpoint
  `1d63923` replaces the shared-seed setup
  cost model with independent `ProverSetup` and `VerifierSetup` machines and
  an explicit canonical wire format (`kind:u8 || length:u64_le || payload`).
  The channel is secret-agnostic; each role derives challenges from its own
  copy of the complete framed transcript.  Ristretto base OT feeds checked
  IKNP and COPEe, the verifier alone samples `Delta`, and neither `Delta`, its
  bit decomposition nor either role seed is a message field.  The direct
  base-sVOLE sacrifice and the transcript-bound **WYKW batched
  single-point-sVOLE consistency check** (Wolverine §5.1, Figure 7 steps
  4--6, optimization 3) both fail closed.  No proof-path, proof-transcript,
  challenge-order, response-byte, correlation allocation/digest/counter,
  CUDA, provider or default-backend change landed.

  Mandatory adversarial and channel tests pass: a tampered non-punctured GGM
  leaf, corrupted GGM correction and cheating equality response are each
  rejected; the captured channel reparses to the exact directional counters
  and contains neither the verifier seed nor serialized `Delta`.  Full
  `cargo test --workspace` passes (including 9 `volta-pcg` tests).  The clean
  honest record is
  `benchmarks/results/p6-quick-realpcg-2026-07-15-1d63923.json`, SHA-256
  `f048949b3f813009ec990550528d65ee90f2a674100c87535e5ab0c1acb67371`:
  `accepted:true`, `chunked_accepted:true`, flat ratio `1.001764`, mock
  prepass counters identical, allocation digests equal and channel
  transcripts equal.  It records `git_dirty:false` both before the benchmark
  and before serialization.

  The quick report performs two independent setup instances (the measured
  response and the no-PCS flat-cost curve), so its append-only totals are
  **44.966353 s** and **62,522,868 B**.  Per setup instance this is
  **22.483177 s**: base OT 0.025174 s, OT extension 0.964754 s, GGM
  16.125939 s, LPN 0.387947 s and malicious checks 4.978960 s.  Serialized
  setup traffic per instance is **31,261,434 B**: prover→verifier
  28,814,084 B and verifier→prover 2,447,350 B; by category, base OT
  16,411 B, OT extension 31,150,315 B, GGM corrections 91,884 B and checks
  2,824 B.  The earlier 4.408 s CPU cost-model number is reported only as the
  requested informative reference; genuine execution is slower and this is
  not a gate.  Setup wall remains a separate report line and is absent from
  rho; setup traffic remains `pcg_setup_comm_bytes` and is absent from the
  84,574,504 B response download.  `pcg_production_ready:false` remains set.

  **PROPOSED mock→real default-flip criteria (not enacted)**, for a separate
  user decision: (1) an independent cryptographic review reproduces the
  base-OT/IKNP/COPEe and WYKW equations, transcript schedule, message parser
  and the pinned 140.646864/149.477334-bit LPN estimates; (2) production
  entropy/transport plumbing supplies fresh independent role seeds, preserves
  verifier-only `Delta`, authenticates session/channel identity and proves
  correlation non-reuse across reconnect/retry; (3) a clean full
  T=100+50/Q=200 real-backend run passes golden output, proof verification,
  exact counter/allocation/channel digests and the same malicious suite; (4)
  the product owner explicitly accepts the measured per-verifier setup wall,
  31.26 MB setup traffic and lifecycle/storage policy; (5) a new ledger
  decision and checkpoint flips the default while retaining mock as an
  explicit test backend; and (6) a separately preregistered, user-reviewed
  and implemented fase-C realizes the typed `(uniform u16, uniform bit)`
  Packed16 lane, with its malicious, uniformity, exact-counter,
  allocation-digest and non-reuse requirements, before any flip.  Until all
  six are recorded, real remains opt-in and this closure authorizes no default
  flip.

- **2026-07-15 (real-sVOLE fase-B LPN preregistration amended before the
  production run)**: the implementation boundary, transcript/check design,
  acceptance tests and frozen out-of-scope surfaces in the entry below are
  unchanged.  Its one-time Wolverine Table-2 tuple is superseded before any
  clean measurement: Briaud--Øygarden, *A New Algebraic Approach to the
  Regular Syndrome Decoding Problem and Implications for PCG Constructions*
  (ePrint `2023/176`, §5), estimate only **126.44 bits** for
  `(n0,k0,t0)=(642,048,19,870,2,508)` over the 61-bit field.  Their published
  Magma estimator at commit `c021b90140bf30b2a435e07d0039d5f22630ac7b`
  reproduces `126.443932`; the earlier >=128-bit claim therefore cannot be
  retained.

  Replacement assumption (external, with the same preregistered status as PCS
  binding in M9): keep the cited regular-noise structure, `n0=642,048`,
  `t0=2,508`, 256-entry blocks and 10-local public code, but raise
  **`k0=25,000`**.  The current public Code Estimators suite
  (`https://github.com/1234wangtr/Code_estimators`, commit
  `969ef60c30cb84c25502d6b7c968f43a362bb438`) run as regular LPN with
  `log2(q)=64` reports a minimum **140.646864 bits** (hybrid attack; the same
  sweep reports algebraic 143.69, ISD 181.864603, regular-ISD 201.466850 and
  AGB2 143.69), for a **12.646864-bit margin** over 128.  The recursive setup
  capacity is `n0-k0-t0-2=614,538` versus the main-stage need
  `k+t+2=591,081`, leaving 23,457 correlations.

  The main tuple remains Wolverine's published
  `(k,n,t)=(589,760,10,805,248,1,319)`, regular 8,192-entry blocks and
  fanout 10.  The same pinned estimator's hybrid attack reports
  **149.477334 bits**; Esser--Bellini, *Not Just Regular Decoding* (ePrint
  `2023/1568`, Table 7) independently reports 157 bits for regular ISD on
  this exact tuple.  The conservative registered estimate is therefore
  **149.477334 bits**, a **21.477334-bit margin**.  These are concrete
  known-attack estimates, not reductions or gate verdicts.  Any lower attack
  estimate or change to `(k,n,t)`, block structure, field-size model or
  fanout reopens this assumption before coding; no citation is to be stretched
  to cover a different tuple.

- **2026-07-15 (real-sVOLE fase-B hardening, preregistered before coding)**:
  scope is host-side setup only. Replace the `setup-cost-model` path with two
  independent `ProverSetup` / `VerifierSetup` state machines whose only shared
  state is an explicit length-delimited serialized channel. Each role has
  independent private randomness; the verifier samples the Goldilocks
  `Delta` locally, and neither `Delta` nor a verifier RNG seed is a channel
  field. Count serialized bytes in each direction and by setup phase. The
  prover path, proof transcript and bytes, challenge order, correlation
  allocation/digest/counter semantics, CUDA backend, and mock default are
  frozen. Handoff §4.6.A cached columns, §4.1.4 claim merging, all other
  communication levers, Lean, kernels, orchestration and provider profiles
  remain out of scope.

  Construction boundary: instantiate the OT-based COPEe/base-sVOLE bootstrap
  of Weng--Yang--Katz--Wang, *Wolverine* (IEEE S&P 2021, DOI
  `10.1109/SP40001.2021.00056`, ePrint `2020/925`), §5 Figure 5 and Appendix
  B.1 Figure 15, then its single-point sVOLE and regular-LPN extension (§5.1
  Figure 7 and §5.2 Figure 8). Base OTs use the already-locked Ristretto
  dependency and feed the real COPE/OT extension; no shared-seed or
  trusted-dealer base correlation is permitted. The malicious GGM check is
  the **batched single-point-sVOLE consistency check** from §5.1, Figure 7
  steps 4--6 with optimization 3: derive its random-oracle coefficients from
  the complete serialized setup transcript plus a fresh verifier challenge,
  then run the commit/open equality check fail-closed. The direct base-sVOLE
  correlation check from Figure 5 steps 3--4 is also mandatory.

  Parameter assumption (external, like PCS binding in M9): pin the public
  10-local linear code and regular-noise distribution to Wolverine §5.2
  Definition 1 and §6.1 Table 2. The one-time recursive setup is
  `(k0,n0,t0)=(19,870,642,048,2,508)` with 256-entry blocks; the response
  extension is `(k,n,t)=(589,760,10,805,248,1,319)` with 8,192-entry blocks.
  Each of the `t` disjoint blocks contains exactly one uniformly located,
  uniform nonzero `F_p` error. WYKW report that these parameters make all
  known LPN attacks cost at least `2^128`; applying the same tuple over the
  larger Goldilocks base field is preregistered as a conservative >=128-bit
  assumption, with **zero additional claimed bit margin**. Reserving two
  base correlations for the `F_p^2` check leaves `n-k-t-2=10,214,167`
  usable correlations versus the P6 requirement `8,833,686`, a capacity
  margin of `1,380,481` (15.63%). Any future parameter change requires a new
  citation or estimator run before coding.

  Mandatory acceptance before calling the result a parity candidate: honest
  `p6_report --quick --pcg-backend real` accepts with mock-prepass counters
  identical and allocation digests equal; unit/integration tests reject a
  tampered GGM leaf, a corrupted GGM correction and a cheating consistency
  response; a channel-transcript test verifies independent role seeds,
  direction-exact byte accounting and absence of serialized `Delta`. Land one
  append-only clean JSON with setup wall split into base OT, OT extension,
  GGM, LPN and malicious checks and with setup communication per direction.
  Setup bytes remain outside response download and setup wall remains outside
  rho. The corrected 2026-07-07 4.408 s single-thread CPU cost-model result is
  informative only, not a gate. This entry authorizes no mock-to-real default
  flip; closure must record separately proposed flip criteria for user review.

- **2026-07-15 (§4.6.A verifier-cached-columns: soundness defect identified
  before any implementation; comm-lever projections retracted)**: review of
  handoff-spec suggestion §4.6.A (the designated verifier caches the Q Ligero
  data columns after the first opening; later responses send only fresh
  u-vectors) found its soundness note incorrect. Query unpredictability at
  commit time protects **proximity** — a static property of the committed
  matrix, and that part is indeed reusable — but each opening's
  **consistency check** (`Enc(u)[j] = r^T·col_j` at `j ∈ Q` against cached
  columns) is a fresh statement about a fresh prover message, and its
  soundness rests on the prover not knowing the checked positions when it
  chooses `u`. The first response reveals Q. From then on, for any later
  challenge, a malicious prover can solve the |Q| = 200 linear agreement
  constraints inside the msg_len = 2^14-dimensional u-space (2^14 − 200
  degrees of freedom), sending a forged u that matches the cached columns
  exactly at every checked position while encoding an arbitrary false
  evaluation. Every response after the first is forgeable; fresh ZK mask
  commitments do not help (the prover crafts them knowing Q), and the M9
  composition inherits the break because PCS binding is its explicit
  hypothesis. Consequence: per-response consistency queries cannot be
  amortized by caching, only the proximity role can; the
  **144.8 → 110.8 MB marginal-response projection is retracted** and §4.6.A
  may not be preregistered without a repaired mechanism. Its leakage
  observation (cumulative column exposure stops growing) is correct but
  moot until a sound mechanism exists.

  Related correction to §4.1.4 (per-tensor RLC claim merging): claims on
  the same tensor at *different* evaluation points do not merge through a
  linear RLC pre-pass — with u* = (b₁+ρb₂)^T·M the products ⟨u*, a₁⟩ and
  ⟨u*, a₂⟩ mix cross terms and verify neither original claim. The sound
  version is a multi-point-to-single-point reduction (eq-combined sumcheck
  per tensor), i.e. a protocol change with real prover cost and its own
  formal seam — a permitted trade direction (prover time for bytes), but
  not the "small RLC pre-pass in batch.rs" the spec sketches. The
  **96.9 MB figure is likewise retracted** pending a designed mechanism.

  Sound communication levers, unaffected and available to a future
  preregistered comm milestone: §4.6.B 2-byte packed corrections with an
  authenticated carry bit (−25 to −35 MB, formal-touching M5 extension —
  the honest largest lever), §4.3 x_in re-auth reuse (−6.9 MB), §4.2
  is_max argmax replacing the public band logits (−20.5 MB for ~2.5 M
  extra lookups). Together they reach a similar envelope to the retracted
  projections without touching PCS query policy. The Mystique-style
  one-time per-verifier weight MAC (documented deployment knob) remains
  the only known sound "pay once, then cheap" DV mechanism; its O(|W|)
  per-verifier setup (~1 GB at GPT-2 scale) and the 20B-scale rejection
  stand. No implementation is authorized by this entry; the next work item
  remains real-sVOLE fase-B hardening per the Stop-branch entry below.

- **2026-07-15 (P7b post-fix CUPTI census landed; non-gating
  measurement)**: the preregistered clean `25dfc3c` run completed the exact
  `runpod-a100-v1` full T=100+50/Q=200 counters-only 0+1 geometry with eight
  Rayon workers and the standard flat-cost curve.  Acceptance, frozen golden
  decode, communication and flat cost **1.221415 <= 1.5** pass;
  `p7b_gate_evaluated:false`.  CUPTI emitted 1,401,747 concurrent-kernel
  records and 35 fail-closed dropped-record queries summing to **zero**.
  The twelve preregistered proof-algebra families match 206,649 physical
  launches; the matrix-fold family includes the ABI-internal
  `matrix_fold_parts_kernel` and `matrix_fold_finish_kernel` symbols created
  by `ab3a03f`, with physical-symbol rows retained separately.  The append-
  only census is `p7b-cupti-kernel-census-2026-07-15-25dfc3c.json`
  (SHA-256
  `00f7e0eeee36bd56bd20a1d75947bd166ff8e508b4fd4a924b1a440b850183c1`).
  Raw trace, application log and application report remain outside the
  checkout, with SHA-256 values
  `8e091aa6ab9dceea531f6449c7887dc75a928e62f26836332a786d72cf8b0650`,
  `92184bce0b657f4f307b4ca835d7b6cef397bceaf56c25ad2735f3cf3354b6e6`
  and `3563fa17d4f72af4f2c14cc25255bfd430cd08a3170a0e65e981b397aca4b00d`;
  every remaining build/parser checksum is recorded in the census JSON.

  The post-fix ranking is matrix fold **54.392625%**, then
  `reduce_product_round` **17.620830%**,
  `reduce_triple_product_round` **12.465584%**,
  `fp2_product_round_terms` **6.799738%**,
  `fp2_triple_product_round_terms` **4.681506%** and `reduce_dot`
  **2.326605%**; all other families are below 0.54%.  This is no longer the
  old 98.26% single-defect profile.  Within the leading family, the remaining
  legacy `matrix_fold_kernel` grid-x=1 slice is 7,410 launches / 39.966503%
  of matched time, but every such launch is on the intentional `terms < 256`
  path and its maximum is 140,062 ns; the new parts path reaches grid-x=1,536.
  The trace therefore shows many bounded launches and time spread across
  reduction families, not another large-vector grid-x=1 occupancy collapse.
  CUPTI absolute durations remain ineligible; this conclusion uses only the
  within-census rank, dispatch condition and launch/grid evidence.

  The preregistered headroom warning is now concrete against that ranking:
  max official synchronization wall 0.109869589 s and the v1 2% ratio bind at
  a 5.493479450 s session, only **7.157763%** below the current official
  5.917004617 s.  That small certifiable compute headroom does not turn the
  distributed small reductions or bounded matrix-fold launches into a
  qualifying internal defect; a larger pure compute win would instead trip
  the v1 denominator artifact.

- **2026-07-15 (post-fix census decision rule evaluated; Stop branch)**:
  the concentration predicate is true (matrix fold 54.392625% >= 50%), but
  the required kernel-internal mapping/occupancy-defect predicate is false.
  The preregistered **Stop branch** therefore applies: GPU optimization stops
  with **zero CUDA/Rust/protocol code change**, no `runpod-a100-v2` profile is
  preregistered, and no graph, scheduler, batching or synchronization work is
  opened.  The next work item is real Goldilocks sVOLE fase-B hardening:
  real two-party base OTs, the WYKW malicious consistency check and cited LPN
  parameters.  The `ab3a03f` PASS and all earlier verdicts remain unchanged.

- **2026-07-15 (P7b post-fix kernel census preregistered; diagnosis only,
  with an explicit stop rule)**: purpose — the `1a319db` census is obsolete.
  It ranked `matrix_fold_kernel` at 98.264387% of traced proof-algebra time
  with the second family at only 0.700790%, and that kernel has since been
  rewritten (`ab3a03f`). Whether even one more kernel optimization is worth
  doing before phase A depends entirely on the post-fix ranking, which is
  currently unknown. This census answers only that question; it changes no
  code and selects no optimization by itself.

  Method — identical to the 2026-07-14 CUPTI fallback census. Nsight Compute
  remains denied on RunPod (`ERR_NVGPUCTRPERM`), so use the
  already-checksummed patched `cupti_trace_injection` build outside the
  checkout, injected via `CUDA_INJECTION64_PATH`, with
  `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL` only and fail-closed dropped-record
  queries that must sum to exactly zero. Geometry: full T=100+50/Q=200,
  counters-only, zero warmups plus one measured repetition,
  `RAYON_NUM_THREADS=8`, exact `runpod-a100-v1` machine profile, clean tree
  at the commit containing this entry. Acceptance, golden decode and the
  flat-cost curve remain mandatory; `p7b_gate_evaluated:false`. Filter the
  same twelve proof-algebra kernel names. Keep the raw trace and logs outside
  the checkout, record every SHA-256, and land one append-only parsed census
  JSON in `benchmarks/results/` (per-kernel launches, summed durations,
  percentage shares, grid-dimension distribution of the top family,
  matched/total kernel counts, dropped=0, provenance). Interpretation limits
  are unchanged: absolute profiler walls are ineligible; only within-census
  ranking and launch/grid evidence may select work; the run is a
  decode-emphasized whole-application aggregate, not a decode-marginal
  duration.

  Gate-headroom arithmetic this census must be read against: absolute
  synchronization wall in the official PASS is 0.102956132–0.109869589 s per
  repetition, and kernel-internal fixes do not change it (it was count-exact
  across the matrix-fold fix). The `runpod-a100-v1` ratio gate
  (sync/session <= 2%) therefore binds at a session wall of ~5.49 s
  (0.1099/0.02); from the current 5.917 s that is only ~7.2% headroom. A
  compute-only improvement larger than ~7% is thus predicted to produce a
  valid official FAIL on the ratio gate — not because synchronization got
  worse, but because the denominator shrank. The ratio gate was adopted to
  show that sync-count targets were provider debt; failing a pure compute
  speedup is a denominator artifact, not its intent.

  Preregistered decision rule, evaluated on the landed census before any
  code change:
  - **Fix branch** — if one kernel family holds >= 50% of traced
    proof-algebra seconds AND its launch/grid evidence shows a
    kernel-internal mapping/occupancy defect (as grid-x=1 did for
    `matrix_fold_kernel`): preregister exactly one ABI-neutral
    kernel-internal boundary against that family, together with a
    `runpod-a100-v2` gate profile that keeps every other gate and invariant
    identical but replaces the sync ratio with an absolute bound — maximum
    per-repetition synchronization wall <= 0.150 s, fail-closed. The
    absolute bound is stricter in intent (sync may no longer grow
    proportionally with session wall) and removes the denominator artifact.
    Quick stop gate: >= 10% upper-median response-session reduction versus
    the 3.089308298 s `ab3a03f` quick reference, i.e. <= 2.780377468 s, with
    unchanged proof/counter/communication invariants; failure stops the
    line. The 50% bar is deliberate: with ~7% certifiable headroom under v1
    and the cost of a v2 preregistration, only a concentrated defect
    justifies one more iteration before phase A.
  - **Stop branch** — otherwise (flat profile, or the dominant signal is
    launch/sync/host residual rather than kernel-internal work): GPU
    optimization stops with zero code change, and phase A (real Goldilocks
    sVOLE) is the next work item per the same-date direction entry below.
    Orchestration mechanisms (CUDA graphs, scheduler expansion, sync
    coalescing, scalar-RLC batching) remain unauthorized and may be
    reconsidered only after phase A under their own preregistered boundary.

  At most one fix may result from this census; no stacking. The `ab3a03f`
  PASS and every earlier verdict are unaffected.

- **2026-07-15 (post-P7b direction: rho targets re-scoped and work ordered
  around phase A; decision, no measurement)**: against the P7 native GPU
  anchors (prefill 17.342 ms, decode50 599.346 ms — measured 2026-07-13
  under the P7 profile; same A100-SXM4-80GB GPU model as RunPod, so
  indicative here, and any future rho-gated milestone must re-anchor native
  time on its own profile), the `ab3a03f` PASS corresponds to
  **rho_prefill ~151.7** and **rho_decode ~3.49** versus the concept-note
  GPU targets of <= 5 and <= 2. The two gaps mean different things.

  rho_decode ~3.49 is a real gap in provable decode work: the target needs
  decode marginal <= 1.198692 s from the current 2.089288042 s, a ~42.6%
  reduction. It stays the operative performance target at this scale, but
  any milestone chasing it must bring its own preregistered gate contract
  (see the census entry above for why the v1 ratio gate cannot certify it).

  rho_prefill ~152 mostly measures model/hardware mismatch, not protocol
  overhead: native prefill executes 8.63 G MACs in 17.342 ms (~0.5 GMAC/ms,
  well under 1% of an A100's integer tensor throughput) because a
  124M-parameter model at T=100 is latency-bound and leaves the device
  idle, while the prover kernels are throughput-bound and actually use it.
  On a deployment-scale model or batched workload the native denominator
  grows far less in time than in work, so the ratio compresses by itself.
  **Decision**: rho_prefill <= 5 is re-scoped as a deployment-scale
  extrapolation target; it is not a GPT-2-small/A100 pass/fail number and
  must not drive kernel work at this scale. No historical verdict is
  reinterpreted.

  Work-ordering decision (robust versus fragile under phase A): the
  proof-algebra kernels consume correlations and are indifferent to how
  they were generated, so kernel-internal efficiency work (occupancy,
  Goldilocks limbing, memory layout) survives the switch from mock-PCG to
  real sVOLE and transfers across model shapes. Orchestration work (CUDA
  graphs, epoch scheduling, sync coalescing, gate-margin tuning) is tuned
  to the current session composition, which phase A will change: really
  expanding ~3.77 M WYKW correlations adds measurable host work and shifts
  traffic/blocking patterns. Order of work is therefore: (1) the census
  above; (2) at most one robust kernel-internal fix if its rule selects
  one; (3) **phase A — real Goldilocks sVOLE (WYKW) as production backend,
  removing the mock-PCG non-production label** (fase A GGM+LPN expansion is
  already landed and measured at 3.7 s CPU, `fe4857b`; what remains is the
  fase-B hardening: real two-party base OTs, WYKW malicious consistency
  check, cited LPN parameters); (4) only after phase A, reconsider
  orchestration under a new preregistered boundary. Standing exclusions
  remain binding throughout, including no prover speed bought with proof
  size or communication.

- **2026-07-14 (P7b RunPod official gate PASS; matrix-fold iteration
  closed)**: after the preregistered quick stop gate passed, the unchanged
  `ab3a03f` executable completed a clean schema-6/ABI-28 T=100+50/Q=200
  counters-only official run on `runpod-a100-v1`, exactly one warmup plus
  three measured repetitions and eight Rayon workers.  The raw append-only
  result is
  `p7b-integrated-resident-wall-only-counters-2026-07-14-ab3a03f.json`
  (SHA-256
  `081007df74b70396b9c7ed20838d3d8209a23d6968bf17f106e66818756a3414`).
  Both the remote and local fail-closed official validators accept it.

  The new official verdict is **PASS**: prefill upper median
  **2.630975566 s <= 10 s**, decode-marginal upper median
  **2.089288042 s <= 4 s**, and response-session upper median
  **5.917004617 s**.  Against the immutable `33e5fb4` rebaseline these are
  reductions of 66.2745%, 69.2461% and 63.0069%, respectively.  Every
  repetition accepts; frozen 50-token golden decode matches; the chunked
  proof accepts with flat-cost ratio **1.281195 <= 1.5**.  The maximum
  per-repetition synchronization/session fraction is **1.821491% <= 2%**;
  the three absolute synchronization values are 0.109869589 s,
  0.102956132 s and 0.104161412 s.  H2D is **28,594,644 B <= 100 MB** and
  the packed response is **144,820,930 B**, inside the product envelope.
  CUDA-event timing API calls remain zero in every measured repetition.

  The 59,868 synchronization count, H2D bytes, every operation-call count,
  proof/correlation counts and every communication field are byte/count
  exact against `33e5fb4`.  The gate therefore closes through a
  provider-neutral occupancy correction wholly below the existing ABI and
  protocol, not by moving work, increasing communication or adding a
  Thunder-shaped scheduler.  Scalar-RLC batching, retained graphs and the
  epoch scheduler are not on the critical path and are not authorized by
  this PASS.  The mock-PCG label and non-production status are unchanged.

- **2026-07-14 (P7b matrix-fold quick stop gate passed; official full
  authorized)**: implementation checkpoint `ab3a03f` stays inside the
  preregistered ABI-neutral boundary.  The legacy output-parallel launch is
  retained for `terms < 256` or more than 1,024 real outputs; narrow folds
  use the deterministic 256-thread term-parallel reduction with the bounded
  slot-15 workspace.  The exported ABI, Rust API, operation accounting and
  proof protocol are unchanged.  Local workspace and all-feature tests,
  17 Python tests, the frozen Lean audit and shell syntax checks passed.  On
  the designated RunPod A100, the targeted base/Fp2 row/window/padding
  differential and the complete `VOLTA_REQUIRE_CUDA=1` all-feature workspace
  passed, including all 34 backend tests and all 100 protocol tests.

  The clean counters-only quick 1+3 result is
  `p7b-integrated-resident-quick-wall-only-counters-2026-07-14-ab3a03f.json`
  (SHA-256
  `23504e1f6d8bcefcea5a8c83282f6171d3f8233f3f47b76ee0033131152e1bdf`).
  Its response-session upper median is **3.089308298 s**, a **17.9838%**
  reduction from the 3.766704220 s `33e5fb4` reference and below the
  preregistered **3.390033798 s** stop bound.  Prove-only upper medians are
  1.395620036 s prefill, 2.454372967 s response and 1.058752931 s decode
  marginal.  All three repetitions accept; the chunked proof accepts and
  flat cost is 1.069873.  The 39,201 host-output synchronizations, operation
  calls, proof/correlation counts and every communication byte field are
  exact against the reference.  H2D decreases by 131,072 B to 12,525,636 B:
  unlike the 0+1 reference this preregistered run has a warmup, and every
  measured repetition has the same counters with 96 additional allocator
  reuse hits.  No measured repetition makes a CUDA-event timing API call.

  This quick has `p7b_gate_evaluated:false`; it is the optimization stop gate,
  not an official verdict.  Its shorter denominator puts the diagnostic
  max synchronization/session fraction at 2.380086% even though absolute
  synchronization is only 0.067767--0.074373 s.  Do not waive or reinterpret
  the official 2% gate: the newly authorized full T=100+50/Q=200 1+3 run must
  enforce the unchanged max-per-repetition bound through the schema-6
  validator.  No second optimization may be stacked before that verdict.

- **2026-07-14 (P7b CUPTI census landed and matrix-fold occupancy fix
  preregistered before implementation)**: the clean `1a319db` CUPTI activity
  run completed the full T=100+50/Q=200 counters-only 0+1 report and its
  standard flat-cost curve on `runpod-a100-v1`, eight Rayon workers.  It had
  1,398,147 kernel records, **zero dropped records**, acceptance, golden
  decode and flat-cost PASS.  Absolute CUPTI wall/durations are profiler-
  perturbed and remain ineligible.  The append-only application result is
  `p7b-integrated-resident-wall-only-counters-cupti-2026-07-14-1a319db.json`
  (SHA-256
  `0fe8ae168036734ef29eea7dc0d9dbabf88e8d5b38e83fcaa8ebcc2f625a38bc`);
  the parsed census is
  `p7b-cupti-kernel-census-2026-07-14-1a319db.json` (SHA-256
  `97b895d63ff667190d485e009fac6dfc89bcdf7493cdc4790181ac55ab1742a3`).
  Raw trace/application-log SHA-256 values are
  `c4a6fa32aa5af578fc898086c08954253327ab4a59e312b4922d654f9c69b843`
  and `bb0966cd1f63d55e97535075cd9f2d2474e3acd8c37c2390edb4275be0c5df06`;
  the 550 MB trace stays outside the source checkout and is not a benchmark
  artifact.

  Across the twelve preregistered proof-algebra families, 203,049 launches
  account for 25.959938654 traced seconds.  `matrix_fold_kernel` alone is
  **11,877 launches / 25.509374475 s / 98.264387%**.  Of those, 10,977 use
  grid-x=1 (one 256-thread block) and account for 24.577730140 s; the worst
  single launch is 142.648825 ms.  The next family is only 0.700790%.
  This census spans prefill, response and the decode-emphasized flat curve,
  so its seconds cannot be subtracted from the 6.275 s event-attributed
  decode kernel floor.  Its ranking is nevertheless decisive and directly
  explains the occupancy defect: the current kernel assigns one thread to
  each output and serially scans every folded term, collapsing scalar MLEs
  over large vectors to one block.  This is a provider-neutral kernel mapping
  defect below the protocol/ABI, not justification for scheduler complexity,
  algebraic batching or a new proof variant.

  **Single authorized implementation boundary**: keep the exported
  `volta_cuda_matrix_fold_device`, Rust API, scalar kinds, row-major/window
  semantics and `Operation::Gemm` call accounting unchanged.  For
  `terms >= 256` and at most 1,024 real outputs, replace only the internal
  launch with a deterministic term-parallel two-stage reduction.  Use 256
  threads/block and
  `parts = min(ceil(terms/256), ceil(1024/real_outputs))`; each first-stage
  block scans its strided term subset, performs an Fp2 shared-memory
  reduction and writes one partial.  With one part it writes the final output
  directly (including canonical zero padding); otherwise one final block per
  output reduces the partials and writes padding.  Reuse previously unused
  workspace slot 15, bounded here by 2,046 Fp2 values / 32,736 bytes.  Retain
  the existing output-parallel kernel for smaller terms or more outputs.
  Every per-term multiplication is unchanged; regrouping additions is exact
  in F_p2 and cannot change the canonical result.  No atomic, transcript,
  challenge, correlation, proof, communication, scheduling, public API or
  ABI change is permitted.

  Add CUDA differentials that force the parallel path for base and Fp2
  inputs, both axes, a strided column window and padded outputs.  Require
  local workspace/all-feature/Python/Lean checks and all real-CUDA tests.
  Before another full run, execute a clean counters-only quick 1+3 on the
  exact new SHA.  It must preserve acceptance, proof/counter/communication
  invariants and reduce upper-median response-session wall by at least 10%
  versus the stable 3.766704220 s `33e5fb4` quick reference, i.e. to
  **<=3.390033798 s**.  Failure stops this implementation line; do not stack
  another optimization.  On a pass, run one new official full 1+3 under the
  unchanged `runpod-a100-v1` contract; its valid verdict may pass or fail.

- **2026-07-14 (P7b CUPTI census fail-closed correction; preregistered before
  the first CUPTI run)**: pre-run source audit found that NVIDIA's unmodified
  helper never calls `cuptiActivityGetNumDroppedRecords`; it therefore cannot
  satisfy the dropped-record gate preregistered immediately below.  No CUPTI
  run occurred under that incomplete boundary.  Supersede it with a minimal
  scratch-only patch, never copied into this repository or the CUDA backend:
  (1) select only `CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL`, removing unrelated
  API/memory/NVTX activities; (2) after every completed buffer, query and print
  `cuptiActivityGetNumDroppedRecords(context, stream)` fail-closed.  The
  patched injection source and helper SHA-256 values are
  `2966efecd3d767e9fb3fb62f7683971b5ee0ef10cd6e72f0db274196ddafb34b`
  and `8590bba68b4ec975d4243c422c4ce5313afa4bb496903c417f4c334202e894ec`;
  the original Makefile remains
  `d6e6b3a0fdc3f757d66e48b47b106dae369deebea865ee0c3e44377235b10717`.
  Its unchanged companion `helper_cupti.h` is also a build input, SHA-256
  `aedb286fe6bc0af1893e4d42cff5b3f0b9c1ef120bb5d2f051c1cdb6ad4440bf`.

  All other geometry, source/profile, output and interpretation constraints
  below remain unchanged.  Sum every emitted dropped-record count and require
  exactly zero.  The trace must contain all twelve filtered names that have a
  source-level launch in this workload, or explicitly record zero invocations
  only when the report's path cannot call that family; any unexplained absence
  fails the census.  This correction is diagnostic hygiene only, not new
  maintained instrumentation.

- **2026-07-14 (P7b kernel-census profiler fallback; preregistered after the
  Nsight refusal and before the fallback run)**: the exact preregistered
  Nsight Compute 2025.1.1 invocation attached to clean `8adbead`, but RunPod
  denied GPU performance-counter access with `ERR_NVGPUCTRPERM`, including
  for root.  It collected no kernel metric and produced no `.ncu-rep`.
  The error CSV SHA-256 is
  `542a25cbac0fd849f50d625680f8ace0c2a3657d2f134d20b7676100d8883481`.
  The application nevertheless completed acceptance, golden decode and the
  flat-cost check, producing the explicitly ineligible append-only
  `p7b-integrated-resident-wall-only-counters-ncu-denied-2026-07-14-8adbead.json`
  (SHA-256
  `4127171cbc96552fd54c3bb7918163edca37d23752c15e773b5df580ce004c8b`).
  Its NCU-perturbed wall values are discarded, not a gate observation or a
  profiler result.  Do not mutate/reload the provider's NVIDIA kernel module
  to obtain privileged counters.

  The one permitted fallback is NVIDIA's unmodified CUDA-12.8
  `cupti_trace_injection` sample already installed on the same image.  Source,
  Makefile, shared helper and `libcupti.so.2025.1.1` SHA-256 values are,
  respectively,
  `2fcc5cc819cc903f1715fb6615a406389c2f98e9c3b62d95bda54b2a4f0bf141`,
  `d6e6b3a0fdc3f757d66e48b47b106dae369deebea865ee0c3e44377235b10717`,
  `7a364cc51e21daff55f72523c1955f5ff964f94d6ab4f8b3f7dd96af3618f606`,
  and `fccdc5fcc7c32f8cf4b3ed9b17f7f187a185a6fa0a5bcc06e3434cbd1687c808`.
  Build a copy outside the source
  checkout, inject it only via `CUDA_INJECTION64_PATH`, and rerun the same
  clean full T=100+50/Q=200 counters-only 0+1 report with eight Rayon workers.
  CUPTI activity timestamps require no privileged performance counters and
  do not alter the repository/backend ABI.  Keep trace stdout, application
  stderr and generated report outside the checkout and record all checksums.

  The unmodified sample also reports CUDA API/memory activity and the report
  executes its standard flat-cost curve after the measured session.  The
  summary must therefore filter only the same twelve proof-algebra kernel
  names preregistered above and aggregate the entire application as a
  **decode-emphasized ranking census**, not claim a decode-marginal duration
  or compare its absolute time with CUDA events.  Land one append-only JSON
  with each matching kernel's invocation count and summed activity duration,
  plus matched/total kernel counts, dropped-record count, provenance and raw
  trace checksums.  If CUPTI reports dropped activity records, an unmatched
  proof-algebra family, or an application correctness failure, stop without
  selecting an optimization.

- **2026-07-14 (P7b RunPod proof-algebra kernel census; preregistered before
  profiling or CUDA changes)**: run one non-gating Nsight Compute 2025.1.1
  census on the exact `runpod-a100-v1` profile with eight Rayon workers and
  the clean commit containing this entry.  Geometry is full T=100+50/Q=200,
  counters-only, zero warmups and one measured repetition.  Acceptance and
  golden decode remain mandatory, but `p7b_gate_evaluated:false`; profiler
  wall time and the report JSON are not performance or gate observations.

  Invoke the already-built `p6_report` binary directly under `ncu`, with
  `--target-processes application-only`, kernel replay, cache and clock
  control both `none`, rules disabled, and only
  `gpu__time_duration.sum`.  The exact function-name filter is the complete
  proof-algebra subset currently charged to `Operation::Gemm`:
  `subfield_corrections_kernel`, `pad_base_vector_kernel`,
  `matrix_fold_kernel`, `fp2_dot_terms`, `reduce_dot`,
  `fp2_product_round_terms`, `reduce_product_round`,
  `fp2_triple_product_round_terms`, `reduce_triple_product_round`,
  `ln_hadamard_factors_kernel`, `base_broadcast_fp2_kernel`, and
  `attention_above_mask_kernel`.  Fixed-point witness kernels and LogUp/PCS
  kernels are deliberately excluded: the former run before timed proving,
  while the latter already have separate event categories.  Preserve the
  raw profiler CSV outside the source checkout, record its SHA-256, and land
  an append-only JSON summary containing provenance, per-kernel invocation
  count and summed duration.  The CSV is diagnostic input, not a repository
  run of record.

  Nsight perturbs launch order and duration, so only the within-census rank
  and occupancy/launch evidence may select work; absolute profiler wall and
  cross-mode latency are inadmissible.  Do not edit CUDA until the census is
  written into this ledger and reconciled with the deferred-event broad-GEMM
  total.  Then preregister at most one provider-neutral implementation
  boundary against the dominant exact kernel family.  The boundary may
  change reduction/limb implementation below the ABI only; it may not change
  transcript order, proof bytes, challenge visibility, correlation use,
  scheduling, communication or public API.

- **2026-07-14 (P7b RunPod decode diagnostic closed; non-gating result)**:
  the preregistered full deferred-event diagnostic ran on the exact
  `runpod-a100-v1` hardware/software profile with eight Rayon workers,
  T=100+50, Q=200, one warmup and one measured repetition.  Its clean source
  checkpoint is `70f64d4b2c01f672b74684525b42e638a7398793`; that checkpoint
  differs from official source `33e5fb4` only by documentation and the two
  already-recorded raw official JSONs, not executable code.  The append-only
  diagnostic is
  `p7b-integrated-resident-2026-07-14-70f64d4.json` (SHA-256
  `dc6b75a766db56d12e7b56543b5286df4c9ca4d8614b3a8202877eecabe3e8ed`),
  with schema 6, CUDA ABI 28, `git_dirty:false`, acceptance and golden decode
  true, and `p7b_gate_evaluated:false`.  It is attribution evidence only and
  does not replace or amend the official counters-only verdict.

  Deferred events raise observed prefill from the official upper median
  7.801156381 s to **9.673567059 s** (+1.872411 s, +24.00%), decode marginal
  from 6.793572543 s to **8.478508650 s** (+1.684936 s, +24.80%), and session
  wall from 15.994870539 s to **19.493344560 s** (+3.498474 s, +21.87%).
  These are indicative instrumentation-tax comparisons rather than a
  same-SHA repetition, but the executable is unchanged and the magnitude
  reconfirms that official runs must remain counters-only.  The diagnostic
  itself issued 229,554 elapsed-event queries and 887,698 timing-event API
  calls over the response session.

  Event attribution measures **13.166116504 s** response-session kernel time
  minus **6.890863665 s** prefill kernel time = **6.275252839 s** of
  decode-marginal kernel work.  Its exact operation split is GEMM
  **4.819555111 s (76.80%)**, LogUp **1.097967857 s (17.50%)**, PCS
  **0.255029525 s (4.06%)**, authentication **0.055084417 s (0.88%)**, and
  mailbox **0.047615929 s (0.76%)**.  Thus kernel time alone exceeds the 4 s
  decode gate by **2.275252839 s**: even under the impossible assumption of
  zero non-kernel overhead it needs at least a **36.26%** reduction, and the
  broad GEMM category alone is 0.819555111 s above the complete gate budget.

  **Corrected host-call model**: response-minus-prefill blocking D2H host-call
  wall is 10.589072882 - 5.530127451 = **5.058945431 s**, but the corresponding
  CUDA-event transfer duration is only 1.003848378 - 0.527549949 =
  **0.476298429 s**.  A blocking D2H copy is also the completion barrier for
  previously queued kernels, so its host wall contains their wait and cannot
  be added to the event-attributed kernel total.  The official ABI-28 host-call
  counter exposed where the host waits, not an independent 5 s transfer
  bottleneck.  Explicit synchronization remains immaterial on RunPod.

  **Decision boundary**: diagnosis is closed and provider-neutral kernel
  optimization is mandatory.  No epoch-scheduler expansion, boundary-count
  target, transcript change, algebraic batching or proof-size trade is
  authorized by this result.  Before changing CUDA, identify the exact
  kernels hidden by the broad `gemm` attribution using a separately
  preregistered non-gating profiler census on this same profile.  Then
  preregister one narrow implementation boundary, preserve ABI/proof bytes
  and CUDA byte-identical differentials, and require a quick measured
  cost-model confirmation before another official 1+3 run.

- **2026-07-14 (P7b first `runpod-a100-v1` official verdict; measured valid
  failure)**: the exact clean source is
  `33e5fb4d0baf9726eb09b3876adcc08d97b4f5c8`, CUDA ABI 28, eight Rayon
  workers and the fully matched RunPod manifest.  Real remote CUDA
  differentials passed with `VOLTA_REQUIRE_CUDA=1` (including all 33 backend
  tests) before measurement.  The current SSH mapping retained the pinned
  control checkout and exact hardware/software manifest, so the existing pod
  identity `mkhzglt1crcain` / `eur-is-1` remains the serialized attribution.

  The append-only quick diagnostic is
  `p7b-integrated-resident-quick-wall-only-counters-2026-07-14-33e5fb4.json`
  (SHA-256
  `82c489ff6d52fd6528d3bcf19691edaaf58ee2a18df137b5eaf8605d2849d9bc`):
  prefill **1.958648334 s**, decode **1.168009144 s**, response-session wall
  **3.766704220 s**, 39,201 sync, sync-wall fraction **1.817183%**, H2D
  12,656,708 B, accepted and flat-cost 1.051.  As preregistered, 0+1 quick
  geometry has `p7b_gate_evaluated:false` and is not a verdict.

  The official raw result is
  `p7b-integrated-resident-wall-only-counters-2026-07-14-33e5fb4.json`
  (SHA-256
  `1d228a66df9f332adcffde189efb64a5fb09423a308edd710abf760f4020f7df`),
  T=100+50, Q=200, one accepted warmup and three accepted measured
  repetitions.  Prefill samples are **7.801156381, 7.772146461,
  7.817114100 s** (upper median **7.801156381 s**, MAD 0.015957719): PASS
  <=10 s.  Decode-marginal samples are **6.789678313, 6.893654885,
  6.793572543 s** (upper median **6.793572543 s**, MAD 0.003894230): **FAIL
  >4 s**.  Response-session wall upper median is **15.994870539 s**.  Golden
  decode, acceptance, flat-cost 1.411550, communication/no-growth at exactly
  144,820,930 packed bytes, H2D max 28,594,644 B, cleanup/accounting and
  mock-PCG non-production labeling all pass.

  The retired raw sync count is 59,868 in every repetition.  Explicit sync
  wall is only 0.105950, 0.122980 and 0.112825 s; the maximum session fraction
  is **0.768161%**, so the new <=2% gate passes with margin and confirms that
  a <=5,000 count gate would be provider-driven debt.  However, the new
  ABI-28 host-call counters expose a different bottleneck: response-session
  D2H call wall is **10.388801, 10.426275, 10.402024 s** across 8,901 calls
  and 138,490,068 B.  Prefill alone is 5.430663–5.454171 s across 4,574 calls
  and 49,012,724 B; the response-minus-prefill deltas are therefore
  **4.934630–4.995612 s**, 4,327 calls and 89,477,344 B.  H2D host-call wall
  remains only 0.031–0.033 s/session.

  **Verdict and next gate**: this is a complete official P7b FAIL solely on
  decode latency, but counters-only data contradict the assumption that the
  remaining gap is purely Goldilocks kernel time.  No kernel floor is claimed
  from a mode where event attribution is intentionally unavailable.  Before
  changing kernels or batching, run the already-permitted separate,
  non-gating full diagnostic on the same eight-thread profile with deferred
  event attribution (one warmup + one measured repetition), and use it only
  to split operation kernel time from D2H/host wall.  If D2H remains the
  binding term, instrument or restructure only provider-neutral materialized
  output boundaries; do not revive a global <=5,000 scheduler target or
  extend epoch machinery blindly.  Any transcript-scheduling or algebraic
  batching change still requires its own preregistered boundary.

- **2026-07-14 (P7b RunPod implementation-readiness checkpoint; no gate
  verdict)**: the profile migration, fail-closed schema-6 writer/selector,
  exact quick+official runner and targeted dead-API cleanup are committed
  through `b424e36`.  The clean local checkpoint passes `cargo test
  --workspace`, `cargo test --workspace --all-features`, all 17 Python tests,
  syntax checks for every repository shell script and the frozen Lean audit.
  The working tree remained clean.  A complete source bundle and the existing
  weight/golden artifacts are available for checksum-matched transfer; their
  canonical artifact checksums remain unchanged.

  No remote measurement is claimed.  SSH to the user-supplied RunPod endpoint
  returned `connection refused`, and the local `RUNPOD_API_KEY` is unset, so
  no active endpoint can be discovered without user input.  No provider
  mutation, resume or provisioning was attempted, and Thunder was not
  contacted.  Resume only after an already-running exact
  `runpod-a100-v1` pod and its current SSH mapping are supplied; then require
  real CUDA differentials before quick 0+1 and official 1+3.  Until those
  append-only JSONs exist, `p7b_gate_evaluated` has no new observation and
  P7b has no official verdict.

- **2026-07-14 (P7b targeted AI-slop/dead-code audit checkpoint)**: the
  preregistered repository-only cleanup boundary is complete.  An exact
  symbol-occurrence audit over every Rust `pub fn` / `pub(crate) fn` and every
  Python script function found six Rust API surfaces with no call site, test,
  documentation reference or published consumer: the verifier's two unused
  single-range reservation wrappers, three unused LogUp backend/aux wrappers
  that only forwarded to the already-canonical internal implementation, and
  `SchedulePlan::site_correlations`.  They are removed (**86 lines**) without
  changing a protocol implementation, transcript operation, proof type,
  schedule, counter or backend ABI.  Re-running the public-function inventory
  leaves no definition-only Rust function.

  The four explicit Rust `dead_code` suppressions were inspected rather than
  deleted: three protect standalone resident proof entry points exercised by
  CUDA byte-identical differentials, while `ResidentLayerP1::fulls0` feeds the
  same compatibility accounting path.  CUDA-only buffer/context members,
  ABI-28 host-call diagnostics, `SiteId`/`SchedulePlan`, historical Thunder
  tools and append-only results are likewise retained intentionally.  The
  targeted `volta-mac` + `volta-proto` all-feature suites pass (19 MAC
  unit/integration tests and 100 protocol tests).  Workspace-wide Clippy was
  attempted; the repository has a pre-existing lint baseline dominated by
  cfg-branch `needless_return`, protocol API argument counts and the explicit
  field-method/operator dual API, so those stylistic warnings were not
  converted into a broad mechanical refactor.  Full regression and remote
  CUDA execution remain mandatory before measurement.

- **2026-07-14 (P7b RunPod official-provider and gate-profile migration;
  preregistered before implementation or new measurement)**: the clean
  same-commit control demonstrates that the `<=5,000` synchronization-count
  gate encoded Thunder's CUDA-over-TCP cost rather than a protocol
  requirement.  At `098b2f1`, identical quick work and exactly 39,201
  host-output synchronizations take **32.575313301 s** median session wall on
  Thunder but **3.767662096 s** on co-located RunPod.  The RunPod full control
  has 59,868 synchronizations whose representative host wall is only
  **0.095070132 s** in a **15.650884654 s** session.  Across its three
  measured sessions, synchronization-wall/session-wall is **0.607443%,
  0.616840%, 0.746639%**.  A provider-specific count target would therefore
  force scheduler complexity without a material co-located cost.

  **Provider decision**: RunPod becomes the sole official P7b verdict
  provider under a new explicit schema-6 gate profile
  `runpod-a100-v1`.  Thunder results and microbenchmarks remain immutable
  comparative artifacts but are no longer gate inputs or dependencies; the
  Thunder instance may be terminated.  No existing RunPod ABI-27 control is
  promoted retroactively.  A new official result must use the current CUDA
  ABI, a clean unchanged source SHA and the exact profile below.

  **Gate contract**: retain prefill core **<=10 s**, decode marginal
  **<=4 s**, session H2D **<=100,000,000 B**, the packed-response
  communication/no-growth invariants, acceptance, golden decode, flat cost
  and mock-PCG non-production label.  Retire the numerical synchronization
  count gate and retain the raw count only as a diagnostic.  Its replacement
  is the **maximum over all measured repetitions** of
  `accelerator_session.synchronization_s /
  t_response_session_wall_s <= 0.02`.  A missing, non-finite, negative or
  zero-denominator sample fails closed.  Schema remains version 6, but every
  new official row must carry `p7b_gate_profile: "runpod-a100-v1"`, explicit
  retirement of the count gate, the per-run ratios, their maximum, the 0.02
  threshold and the corresponding verdict.  Historical schema-6 rows without
  that profile cannot become official under the new selector.

  **Reproducible machine profile**: provider `RunPod`, region `eur-is-1`,
  image `Ubuntu 24.04.3 LTS`, driver `580.159.04`, CUDA `12.8`, GPU exactly
  `NVIDIA A100-SXM4-80GB`, CPU `AMD EPYC 7713 64-Core Processor`, RAM metadata
  `1008` GiB and provider vCPU metadata `255`.  The proving process must set
  `RAYON_NUM_THREADS=8`, and the serialized `threads` field must equal 8;
  provider vCPU inventory is not a substitute for actual worker count.  The
  earlier control serialized 27 Rayon threads versus 7 on Thunder, so its
  latency is evidence for provider selection but not the official
  standardized denominator.  Any unavailable exact profile field makes the
  run ineligible; an instance id is recorded but is not pinned.

  **Implementation and cleanup boundary**: first update the Rust writer and
  Python run-of-record validator together, preserving schema-6 historical
  readability and making every new field fail closed.  Freeze further epoch
  scheduler/coalescing expansion: the existing `SiteId`, `SchedulePlan` and
  scheduled proof paths remain because they are used correctness machinery,
  but they are no longer a prerequisite for an official run.  Audit AI slop
  and dead code only inside this repository.  Remove a path only when
  all-target/all-feature builds, call-site inspection and differentials show
  it is unused or unjustifiably duplicated.  Intentional compatibility
  wrappers, formal seams, CUDA differentials, ABI-28 host-call diagnostics,
  append-only JSONs and historical Thunder reproduction tools are not dead
  merely because they are off the critical path.  Cleanup lands in isolated
  commits and may not change proof bytes, challenge order, communication,
  golden output or resource accounting.

  **Measurement order**: after local workspace/no-CUDA tests, report tests,
  CUDA all-feature differentials and cleanup checks pass, run one clean
  standardized RunPod quick smoke.  Only then run T=100+50/Q=200 with at
  least one warmup and three measured repetitions, counters-only timing,
  golden decode and full schema-6/current-ABI discipline.  The official
  result is valid whether performance passes or fails.  If decode remains
  above 4 s, perform separate non-gating profiling on the same eight-thread
  profile and prioritize provider-neutral Goldilocks multiplication limbing,
  occupancy and kernel fusion.  Use formally bounded batching only after a
  measured diagnosis and its own preregistered boundary.  No optimization is
  bought with proof size/communication, and no retained CUDA graph may cross
  a verifier-challenge barrier.

- **2026-07-14 (P7b iteration 3 diagnosis-first plan; preregistered before
  implementation or new measurement)**: iteration 2's first clean scheduler
  diagnostic is internally correct but does not support another blind
  coalescing step.  In the immutable `61aafe8` quick session, the
  **52.146336769 s** response-session wall contains **20.179340213 s D2H**
  (81,518,420 B across 39,201 host-output boundaries),
  **12.261196475 s explicit synchronization**, **0.203084724 s H2D**, and
  **19.371403444 s unattributed host residual**.  At this checkpoint that is
  about **514.76 us/D2H** plus **312.78 us/explicit sync** at each host-output
  boundary.  The residual is also 122.37 us for each of the 158,305 deferred
  CUDA elapsed-time queries if attributed entirely to that remote-call
  surface.  Yet versus the clean `bf66c8f` quick baseline, prefill changes
  only 27.868 -> 27.154 s and decode marginal regresses 23.425 -> 23.628 s
  despite 22,487 fewer synchronizations and 49.19% less H2D.  The explicit
  synchronization term alone predicts about **7.035 s** saved at the new
  per-sync cost.  This unexplained flat-wall anomaly blocks any further
  scheduler/coalescing measurement until Phase 0 closes.

  This plan is accepted as an architectural diagnosis/refactor, not a new
  permanent proving variant, under the following hygiene boundary.  Event
  attribution is one measurement policy selected at the resident backend
  boundary; it must not duplicate or condition the protocol/proving path.
  The counter-only policy bypasses CUDA event creation, recording and elapsed
  queries, so its operation/sync/traffic counters are host-side increments
  and it adds **zero remote timing calls**.  Host wall around required H2D,
  D2H and synchronization calls remains measured.  Event-derived kernel and
  coarse-interval attribution is explicitly unavailable under this policy
  (identified by the serialized timing method), never presented as a
  measured zero.  The existing reason-sum, byte, ownership, cleanup and
  poisoning invariants remain common to both policies.  This keeps the mode
  a removable observation concern rather than architectural debt.

  **Phase 0a -- instrumentation-tax A/B (mandatory first measurement)**:
  implement the policy seam and exact tests that counter-only mode performs
  no CUDA event calls/queries while preserving operation, byte, explicit
  synchronization, reason, allocation and cleanup counters.  On the
  designated Thunder A100, use quick T=16+8/Q=200 only, one clean pinned SHA,
  identical seeds/inputs, and three measured repetitions per policy.  Runs
  are counterbalanced in order (`events, counters, counters, events, events,
  counters`) and emitted as immutable append-only JSONs; no sample may be
  discarded.  Record response-session wall plus prefill/decode walls and all
  available host-call categories for every repetition.  Define event
  instrumentation tax as
  `(median(events wall) - median(counters wall)) / median(events wall)`.
  If it is >=10%, append a ledger decision before an official run making
  `wall-only + counters` the gate-run policy; full event attribution is then
  confined to separately labelled diagnostics.  Otherwise event timing
  remains the official policy.  A mode with any nonzero event-call/query
  counter is invalid as the counter-only arm.

  **Phase 0b -- flat-wall anomaly closure (blocks Phase 1)**: using only the
  immutable clean `bf66c8f` and `61aafe8` JSONs plus the Phase-0a JSONs,
  reconcile the wall delta by an explicit category-delta table for D2H host
  wall, explicit synchronization host wall, H2D host wall, unattributed host
  residual, event-query count/tax and residual remote variance.  Do not add
  overlapping coarse CUDA intervals to host-wall categories.  Correct the
  per-boundary model to distinguish (1) an explicit stream-sync round trip,
  (2) the blocking D2H round trip and payload, and (3) optional event
  instrumentation calls.  Append the quantitative explanation and corrected
  model here before any Phase-1 code begins.  If the observed deltas cannot
  close within the Phase-0a run dispersion, iteration 3 stops as unresolved
  remote variance rather than treating coalescing as validated.

  **Phase 0c -- co-located attribution control preparation, then explicit
  stop**: after 0a/0b, prepare but do not execute a checksum-matched source
  bundle for the same pinned checkpoint, exact CUDA/build commands, quick and
  full timing-off invocations, and an expected-output/cleanliness checklist
  for a co-located A100.  No provider is to be provisioned, enrolled or
  accessed without user-supplied instance access.  A Lambda/RunPod or other
  co-located result is an **attribution artifact only**, never a gate claim:
  Thunder remains the target and sole official-verdict provider.  Stop at
  this checkpoint and request access.

  **Phase 1 -- Thunder epoch scheduler (only after written 0a+0b closure;
  co-located access is not a dependency)**: extend the existing sealed
  role-antichain/heterogeneous mailbox scheduler to non-GELU LogUp sites,
  blind-sumcheck product rounds and Hadamard rounds.  The audited target is
  about 2,446 LogUp epochs and 3,100--4,200 total response barriers.  Fold
  each mailbox read into its barrier: one blocking D2H memcpy is counted as
  the synchronization and there is no preceding explicit stream sync.  This
  changes backend execution/accounting only; the sealed `SiteId`, public
  `SchedulePlan`, preflighted membership/depth/family, exact disjoint
  correlation reservation, active-set shrink-only rule and canonical order
  remain unchanged.  CPU-scheduled and resident-scheduled proofs must remain
  byte-identical, with unchanged proof structs, labels, counts, verifier
  behavior and communication.  Before a measured run, publish the exact
  quick-geometry barrier bound derived from `SchedulePlan` and its
  T=100+50 projection.  The first quick run is accepted as model-confirming
  only if its median wall reduction is compatible with `removed round trips
  x the Phase-0b measured round-trip cost`, allowing the larger of 20% of the
  projection or twice the Phase-0a median absolute dispersion.  Otherwise
  stop and return to diagnosis; do not iterate coalescing blindly.

  **Phase 2 -- kernel work plus official gate run (only if Phase 1 confirms
  the model and projects <=5,000 barriers at T=100+50)**: before the official
  run, treat Goldilocks kernel work as required scope, with multiplication
  limbing and occupancy changes isolated below the protocol boundary and
  guarded by CPU/CUDA field and full scheduled-proof differentials.  The
  decode <=4 s gate has only 1.14 s above the existing 2.860 s kernel floor,
  so this is not a stretch item.  Publish feasibility arithmetic as
  `prefill = 3.138 s kernel floor + epochs * measured RTT + true host
  residual`, using the corrected 0a/0c attribution rather than coarse event
  intervals.  Then run T=100+50/Q=200 on Thunder with at least one warmup,
  at least three measured repetitions, golden decode, clean identical full
  SHA before benchmark and serialization, the Phase-0a-selected timing
  policy, and all schema-6 provider, acceptance, flat-cost, communication,
  cleanup, mock-PCG and four-gate invariants.

  **Phase 3 -- conditional only on a measured Phase-2 gate failure**: first
  implement the already-proved and preregistered scalar-RLC round batching at
  its existing formal boundary, including the extra fresh domain-separated
  challenge and CPU reference differential; then consider retained CUDA
  graphs only for fixed device-only segments and never across a challenge
  barrier.  No Phase-3 work begins after a Phase-2 pass.

  Standing exclusions remain binding in every phase: no device transcript
  hashing; no verifier challenge seed, future challenge, or `Delta` on the
  prover/GPU; mock-PCG remains labelled non-production; no per-token proof or
  PCS opening; append-only results and clean-tree discipline; and no prover
  speed bought with proof size or communication.

  **Phase-0a access preflight (2026-07-14; no benchmark run)**: the
  user-supplied replacement Thunder endpoint identifies itself as
  `instance-rk6i1r0o-main`, but `nvidia-smi` reports **NVIDIA RTX A6000**
  (driver 610.43.02), not an A100.  It also has no existing
  `/home/ubuntu/volta-zk` checkout.  The endpoint may be used only to compile
  and smoke-test ABI 27; it is ineligible for the preregistered 0a A/B and for
  every P7b gate.  No timing sample was taken or discarded.  Phase 0a remains
  blocked pending a Thunder A100 endpoint, so 0b and later phases have not
  started.

  The ABI-27 implementation checkpoint is clean source `c4a8ced` (bundle
  SHA-256 `ba11353f72b7f429353b65f5c796db4761beeab99907d2d1a5f4840247a58f90`).
  On the ineligible A6000 it compiles with CUDA 13.0/sm_86 and the complete
  `volta-accel --features cuda` suite is **33/33** green, including the
  event-on/counter-only differential.  That differential confirms identical
  output, operation calls, traffic and synchronization reasons while the
  counter-only arm has zero timing records, elapsed queries and aggregate
  CUDA-event API calls.  This is implementation evidence only and carries no
  latency or P7b gate claim.

  `scripts/run_p7b_instrumentation_ab.sh` is the fail-closed 0a runner.  It
  executes the preregistered events/counters/counters/events/events/counters
  order as six isolated one-repetition quick reports, requires one unchanged
  clean full SHA, stages each result outside the repository between samples,
  and restores all six append-only JSONs only after the final clean-tree
  check.  This prevents an earlier result artifact from dirtying a later arm.

  **Phase-0a execution correction (2026-07-14; cohort not yet started)**:
  the first runner attempt at clean `40aa1a9` failed before proving because
  the report build omitted the Cargo `cuda` feature and emitted no JSON.  At
  clean `7077636` the first event arm completed with an accepted **49.79 s**
  response, but the runner then failed closed while staging it: its initial
  destination collided with the report's temporary basename and the two
  arms would not have had distinct final basenames.  That singleton is
  quarantined outside the repository and is excluded from 0a because the
  six-sample same-SHA cohort did not complete; it is neither silently
  discarded nor used to choose timing policy.  Before restarting, final
  names are made injective in `(policy, repetition)` and the entire six-run
  counterbalanced sequence restarts from sample 1 on one new clean SHA.

  **Phase 0a result and timing-policy decision (2026-07-14; clean quick,
  not a gate verdict)**: the complete counterbalanced cohort ran on Thunder
  A100 `instance-8mxkk5r7-main` at one clean full SHA
  `098b2f128b7152cf7a4c701cba6dd0d8a876e578`, in the registered order.
  Deferred-events response-session walls were **55.324175101,
  54.507356839, 53.568020169 s** (median **54.507356839 s**, MAD
  **0.816818262 s**); wall-only+counters walls were **33.605737162,
  32.575313301, 32.303299563 s** (median **32.575313301 s**, MAD
  **0.272013738 s**).  The registered tax is therefore
  **21.932043538 s = 40.236850%** of the event-on median, well above 10%.
  Prefill medians change **27.768384686 -> 16.779376102 s** and decode
  marginal medians **25.853503525 -> 14.597984860 s**.  All six proofs are
  accepted and clean, and their operation calls, 39,201 host-output syncs,
  12,656,708 B H2D, 81,518,420 B D2H, D2D/device-generated/device-zeroed
  bytes, allocator and arena counters are identical.  Each counter-only
  session has zero timing records, elapsed queries and aggregate event API
  calls; each event session has 126,438 timing records, 158,305 elapsed
  queries and 617,381 aggregate CUDA-event API calls.

  Per the pre-registered threshold, **wall-only+counters is now the sole
  official P7b gate-run observation policy**.  Full CUDA-event attribution is
  confined to separately labelled diagnostic runs and cannot be selected by
  the official-result validator.  Counter-only event-derived H2D, D2H,
  kernel, coarse and residual fields remain `null`, while wall, bytes,
  calls, synchronization host wall and reasons remain fail-closed.  This is
  an observation-policy selection at the existing backend seam; it does not
  fork protocol execution, proof bytes, challenges, communication or the
  verifier and therefore does not introduce a permanent proving variant.

  Immutable raw files (SHA-256 in event r1/r2/r3 then counters r1/r2/r3
  order) are:
  `9e47e573d3dca0751181b66e428d622e28246f7ba22db1d0a70aacec8132c43e`,
  `c36966f0b08d242161b5239c6c16c69eb238ff8f310adbc9e85c371dcf4b424e`,
  `d5cfd3385d671dc84547f1082ff78810459fa836aebb59729240429aa9670478`,
  `114e0e9d2b2094d07be93d6a548ab49815fdecc488a790252635c380dbd90b8c`,
  `cae49bdcb2b48f6fbd56b75386a8b557a3c011bb0a2437f6c893c98734af574d`,
  and
  `ac20849f387f43820dfe9c32a396c8d22145ca438329d714ff1c768857f7eae2`.

  **Phase 0b flat-wall closure and corrected cost model (2026-07-14)**:
  the old `bf66c8f -> 61aafe8` wall delta closes exactly without inventing a
  missing seven seconds.  In the non-overlapping event attribution identity,
  H2D changes **-0.014745801 s**, D2H **-4.938606840 s**, non-coarse device
  interval **-0.657179939 s**, the newly introduced coarse interval
  **+8.211153792 s**, and host residual **-3.029339138 s**; their sum is the
  observed wall **-0.428717926 s**.  Thus a new coarse event interval --
  explicitly documented as including remote launch-submit gaps -- relabelled
  8.211 s and numerically masked the 8.640 s reduction in the other identity
  terms.  It is not evidence of 8.211 s of new compute.

  Explicit `synchronization_s` is an overlapping diagnostic, not another
  addend in that wall identity.  Its measured change is **-3.492065594 s**.
  Multiplying 22,487 removed calls by the later 312.777645 us/call gives the
  invalid **7.033430911 s** projection; the remaining **3.541365317 s** is
  exactly the non-stationarity error from applying the later per-call value
  to all 61,688 baseline calls (255.369960 us/call at baseline).  The A/B
  proves why neither event-on value is a structural RTT: at identical work,
  median event-on synchronization wall is 12.689342499 s
  (**323.699459 us/boundary**), but timing-off synchronization wall is only
  0.441633804 s (**11.265881 us/boundary**).

  The 31,529 fewer elapsed queries also cannot be priced as independent wall
  savings from this A/B: the policy removes 459,076 event-record calls as
  well as 158,305 elapsed queries.  Dividing the aggregate 21.932 s tax by
  queries gives 138.543 us/query only as a blended normalization (and would
  predict 4.368 s for the query-count delta), while division by all 617,381
  event API calls gives 35.524 us/call; neither quotient identifies an
  elapsed-query RTT.  The event-arm median residual, 20.267596203 s, being
  close to the 21.932043538 s aggregate tax supports the instrumentation-tax
  diagnosis but does not make residual and sync/coarse event intervals
  additive.  Finally, the historical wall delta of 0.429 s is smaller than
  the new event-arm MAD of 0.817 s, so it carries no improvement claim beyond
  remote-run dispersion.

  The corrected timing-off host-output model is
  `C_boundary = C_memcpyAsync_D2H_host + C_required_sync_host`, plus payload
  dependence, with optional event instrumentation excluded entirely.
  `C_required_sync_host` is measured here as **11.265881 us/boundary**.  The
  event-derived D2H interval (**541.215569 us/boundary** at the new median)
  is a device-timeline interval and is **not** `C_memcpyAsync_D2H_host`; the
  current schema does not time that host API call in counter-only mode.
  Therefore no Phase-1 prediction may reuse 514.8 us as a D2H RTT or 312.8 us
  as a sync RTT.  The D2H host-call term must be measured without extra CUDA
  calls (or retained as an explicit unknown), and Phase 1 remains unstarted
  at this reporting checkpoint rather than iterating coalescing against a
  contaminated cost model.

  **Phase 0c preparation checkpoint (2026-07-14; explicit stop)**: no
  non-Thunder host has been provisioned, enrolled or accessed.  The one-off
  control is pinned to the exact 0a commit `098b2f1`; its prepared Git bundle
  is `/tmp/volta-zk-098b2f1.bundle`, SHA-256
  `64076288e251ea45194dd6b442e8f09f0862c3c64692734c2d6770b0f3a6ba77`.
  `docs/p7b-colocated-control-runbook.md` records the checksum-matched source
  and weight inputs, CUDA `sm_80` build/test commands, isolated quick and
  full wall-only+counters invocations, clean-tree staging and the complete
  expected-output checklist.  It requires a non-Thunder result to serialize
  `p7b_machine_eligible:false` and `p7b_gate_evaluated:false`; the artifact
  can inform attribution only and can never replace a Thunder verdict.  Work
  stops here pending user-supplied access to an already-provisioned
  co-located A100.  Phase 1 has not started.

  **Phase 0c execution result (2026-07-14; attribution only, no gate
  verdict)**: after the user supplied an already-provisioned RunPod endpoint,
  the exact `098b2f1` bundle ran on a co-located NVIDIA A100-SXM4-80GB
  (RunPod `mkhzglt1crcain`, `eur-is-1`, driver 580.159.04, CUDA 12.8,
  Ubuntu 24.04.3, AMD EPYC 7713).  The CUDA differential suite is **33/33**
  green.  The clean quick timing-off control is accepted at prefill
  **1.876885173 s**, response prover **3.115895127 s**, decode marginal
  **1.239009954 s**, and response-session wall **3.767662096 s**, with flat
  ratio **0.909699393**.  Its 39,201 syncs, 12,656,708 B H2D and 81,518,420 B
  D2H exactly match Thunder; event records/queries/API calls are zero.

  The clean full T=100+50/Q=200 control uses 1 warmup + 3 measured
  repetitions and is accepted with golden decode and flat ratio
  **1.470336027**.  Upper medians are prefill **7.672741861 s**, response
  prover **14.370455789 s**, decode marginal **6.697713928 s**, and full
  response-session wall **15.650884654 s**.  It has 59,868 syncs and
  28,594,644 B H2D.  These values numerically pass the prefill and H2D
  thresholds but miss decode and sync; more importantly the JSON correctly
  carries `p7b_machine_eligible:false` and `p7b_gate_evaluated:false`, so none
  of those comparisons is a gate verdict.  Quick/full JSON SHA-256 values are
  respectively
  `f18b06e7f40a7f4a4f323be5762d1e98823600f0a51d88f8c492289d290ca0f4`
  and
  `2849c0a16b235bf729700c934156b4becda09b2379b5c2db4b05711f7dc93370`.

  Against the Thunder counter-only quick median at the same source and
  counters, RunPod reduces session wall **32.575313301 -> 3.767662096 s**
  (delta **28.807651205 s**, 8.65x) and response proving
  **31.265796314 -> 3.115895127 s** (delta **28.149901187 s**, 10.03x).
  Explicit synchronization host wall accounts for only
  **0.441633804 -> 0.064483303 s**, a **0.377150501 s** provider delta
  (11.265881 -> 1.644940 us/sync).  The remaining **28.430496814 s** is a
  combined host CUDA-call, D2H, kernel/provider and CPU/platform term.  The
  different CPU/provider makes this a strong attribution result, not a
  component-exact subtraction; dividing all 28.430 s by the 39,201 outputs
  would invent a 725.249 us D2H RTT and is explicitly forbidden.

  **Phase-0b host-call closure addendum (pre-registered before implementation
  or another Thunder measurement)**: Phase 1 still needs the numeric
  `C_memcpyAsync_D2H_host` term required by its stop prediction.  ABI 28 may
  add host-only call counts and `steady_clock` wall nanoseconds immediately
  around the already-required resident H2D/D2H `cudaMemcpyAsync` calls.  It
  must add no CUDA call, event, barrier or protocol branch; the same wrapper
  and operation path serves both observation policies.  Counter-only phase
  attribution remains unavailable/null, while these explicitly named host
  API-call fields are available because they are ordinary CPU clocks, like
  `synchronization_s`.  Tests must prove identical bytes/output/sync/operation
  counters, exact transfer-call accounting and zero event API calls.

  On Thunder, run one clean quick counter-only diagnostic at a single pinned
  SHA with 0 warmups and 3 measured repetitions.  Define the corrected
  boundary cost as the median across repetitions of
  `resident_d2h_host_call_s / resident_d2h_host_calls +
  synchronization_s / synchronizations`; publish both terms and dispersion.
  The D2H call count must equal the 39,201 host-output boundaries in every
  repetition.  If it does not, or the three values do not support a stable
  numeric model, stop diagnosis.  Only after this lands may Phase 1 publish
  its exact `SchedulePlan` bound and use removed D2H calls and explicit syncs
  as separate projected savings.  This instrumentation is removable
  observation state at the backend ABI, not protocol or scheduler debt.

  **Phase-0b host-call diagnostic result and mandatory stop (2026-07-14)**:
  ABI 28 landed at clean `c5265b5`; host clocks wrap only the already-issued
  resident `cudaMemcpyAsync` calls, add no CUDA call or protocol branch, and
  the Thunder CUDA suite is **33/33** green.  The clean Thunder quick
  counter-only 0+3 JSON is accepted and non-gating, with zero event API calls
  and response-session walls **31.981356794, 30.601558430,
  31.252483604 s** (median **31.252483604 s**, MAD **0.650925174 s**).
  Its SHA-256 is
  `a0e71cb2734a7e5e44af3726bd5b6086ca5902934c941d16c2d48b91692af322`.

  The measured host-call terms are stable for the calls they cover: 9,529
  resident H2D calls in every repetition at median **12.935167 us/call**
  (MAD 0.140461 us), 7,335 resident D2H calls at median
  **484.398616 us/call** (MAD 13.304263 us), and 39,201 synchronizations at
  median **11.153362 us/call** (MAD 0.134363 us).  However, the
  pre-registered coverage gate fails: resident D2H call count is **7,335**,
  not the required **39,201** host-output boundaries.  Only **18.71%** of
  boundaries use the explicit resident-transfer entry point; **31,866**
  host-output syncs are paired with D2H issued inside other CUDA primitive
  paths and are not covered by this counter.

  Therefore `484.399 + 11.153 us` is valid only for the covered resident D2H
  subset and must not price all removed Phase-1 boundaries.  The diagnostic
  stop condition is triggered exactly as registered: Phase 1 remains
  unstarted, no SchedulePlan performance projection is published, and no
  further coalescing is attempted.  Covering the remaining D2H sites would
  require a new, broader single-wrapper host-call instrumentation decision;
  it is not silently folded into ABI 28.  The incomplete coverage exposes the
  pre-existing mixed resident/legacy host-output surface that Phase 1 was
  intended to remove; it is not debt introduced by the observation seam.

- **2026-07-13 (P7b target re-registration — resident GPU gate redefined;
  user decision)**: the preregistered rho_proof targets (<=10 prefill /
  <=2 decode) against the same-host native-GPU denominator are **retired for
  GPT-2-small batch-1**: the denominator (17.342 ms prefill) is
  launch-latency-bound (<1% A100 utilization), so rho<=10 implies a 173 ms
  full proof — below the 5.998 s of measured pure kernel time. This is a
  property of the degenerate denominator at 124M/T=100, not of the provider
  or implementation. The <=10/<=2 aspiration moves to a compute-bound
  denominator (phase-X scale, or batched-session throughput rho), per the
  scaling-note thesis. **P7b resident gates, pre-registered now**: prefill
  core **<=10 s** and decode marginal **<=4 s** (respectively 2.04x and
  3.59x faster than the same-host CPU prover: 20.421 s / 14.344 s from the
  `p6-2026-07-11-f72e4dd` baseline),
  blocking synchronizations **<=5,000/session**, session H2D **<=100 MB**.
  Stretch ("ottimo"): prefill <=6 s / decode marginal <=2.5 s. The measured
  kernel floors are 3.138 s prefill and 2.860 s decode marginal (5.998 s for
  the whole response-session scope), so decode stretch also requires
  kernel-level gains (Goldilocks mul limbing / occupancy).

  **Attribution audit before implementation**: Thunder Compute is
  GPU-over-TCP, but 343 us is only the aggregate 72.652 s / 211,709 and must
  not be treated as a uniform synchronization RTT. Of the 211,709 barriers,
  170,367 correspond to CUDA primitive calls whose profiling path executes a
  `cudaStreamSynchronize` after every operation; the other 41,342 are explicit
  uploads/downloads. The current transcript is an interactive DV mock with
  verifier-side, message-independent ChaCha8 challenges — explicitly not
  Fiat--Shamir — so device-side BLAKE3 transcript hashing is **rejected** as
  incompatible with unchanged proof/verifier/formal assumptions. RLC round
  batching likewise remains a separately preregistered protocol change, not a
  byte-identical optimization. The first protocol-neutral levers are deferred
  session timing, stable buffer reuse, persistent/D2D PCS commitments,
  coalesced proof-message reads, and device-side generation of mock-PCG/PCS
  masks without exposing the verifier challenge seed. The 945,442,180 B H2D
  is not mostly PCG masks: about 755 MB is static PCS weights plus pads rebuilt
  inside each measured response. For accounting hygiene, report both cold
  setup and warm-response H2D; the <=100 MB gate remains attached to the
  existing full response-session scope (including PCS work), so moving bytes
  outside the measurement alone cannot satisfy it. Provider stays Thunder
  (user decision, 2026-07-13); a 30-min launch/sync/D2H/graph microbench on
  the instance is the mandatory first step before any refactor.

  **Microbench preregistration**:
  use the same A100 instance and a clean tree; measure host wall for (a) one
  empty-kernel launch plus one device synchronization, (b) N direct launches
  followed by one synchronization, separating enqueue and final-barrier time,
  for N in {1, 8, 64, 512, 4096}, (c) a blocking 8-byte D2H copy, and (d)
  construction, instantiation and replay-plus-sync of a linear CUDA graph with
  the same N empty kernels. A fifth diagnostic measures 8-byte cudaMalloc and
  cudaFree separately because the run reports 271,567 allocation calls and
  allocator churn can serialize independently of explicit transcript reads.
  The full harness targets 1,800 s across the timed cases and reports
  count/median/MAD/p95/min/max plus per-launch amortization; quick mode is
  smoke-only. Operationally, direct launches count as
  "pipelined" only if both max-N enqueue and total time amortize to <=10% of
  the one-launch-plus-sync median. A max-N graph replay is a material lever at
  >=1.2x lower total wall than the direct burst. These classifications choose
  implementation order only; they are not prover performance claims. The
  first clean quick attempt produced no JSON: after the required cases had
  passed, repeated replay of the 4,096-node graph stalled inside the provider
  runtime (a separate 7-sample compile smoke had completed). Before the full
  run, graph replay is therefore capped at 7 quick / 31 full samples per N;
  graph build and instantiate remain measured, and the 1,800 s budget is
  distributed over launch/sync, direct bursts, D2H and allocator probes. This
  is a logged harness deviation driven by a provider-stability observation,
  not a discarded performance sample; the failed quick emitted no result.

  **Mandatory microbench result (closed before any prover refactor)**: clean
  SHA `8b5d177`, full measurement wall **1,802.864 s**, append-only result
  `benchmarks/results/p7b-thunder-cuda-rtt-2026-07-13-8b5d177.json`
  (SHA-256 `4063bfa6f4cb22622fd1500201fd767ec867a4dd7d74720976eb8c3be7283107`;
  local/remote checksum identical, `git_dirty:false`). The smoke companion is
  `p7b-thunder-cuda-rtt-quick-2026-07-13-8b5d177.json` (SHA-256
  `241f10d169eea9acaddbd6836a097348114203a58b55f4b353c40964207f489c`).
  Full medians: empty launch+sync **3.709 us** (p95 8.883 us, with a provider
  outlier of 1.473 s); blocking 8-byte D2H **301.208 us** (p95 350.633 us);
  8-byte `cudaMalloc` **1.149 us**, `cudaFree` **2.593 us**. A direct
  4,096-kernel burst takes **7,956.171 us**, of which **7,953.301 us** is
  enqueue time: **1.942 us/kernel** total, far above the preregistered
  0.371-us "pipelined/free" threshold. Replaying the corresponding fixed CUDA
  graph takes **17.945 us**, a **443.36x** reduction, but construction costs
  1.429 s and instantiation 38.484 ms, so graphs must be retained/replayed and
  cannot be rebuilt per proof. Decision branch is therefore exactly
  `coarsen-launch-surface-and-eliminate-blocking-d2h`: stable/generational
  buffer ownership first, removal of profiling barriers and coalescing of
  true host outputs second, then retained graphs for fixed device-only
  segments. Eliminating D2H alone is not the selected branch.

  **Formal audit gate before round-RLC batching — scalar implementation gap
  and abstract shared-round theorem closed (2026-07-13); concrete scheduler
  still gated**: the proposed
  batching is a real M3 extension, not a byte-identical refactor. The audit
  found that Rust `zero_batch_{prover,verify}` and `prod_batch_*` weight a
  closed list by powers `chi^(j+1)` of one scalar challenge, whereas the
  generic Lean `zeroBatch_sound` / `prodBatch_sound` theorems quantify an
  independently uniform coefficient vector `Fin T -> F`. The concrete Rust
  format is now covered directly: `card_scalarRlc_zero_le` proves at most `T`
  roots for a nonzero scalar-RLC list of length `T`;
  `zeroBatch_sound_scalar` gives `(T+1)/|E|`;
  `prodBatch_sound_scalar` gives `(T+2)/|E|`; and
  `blind_sumcheck_sound_scalar` gives
  `(Σ d_i + n + 2)/|E|` for its `n+1` closing claims. The M4 map is now
  explicit rather than documentary: `kv_cache_sound_scalar` and
  `authenticated_cache_sound_scalar` cover Rust's one-`χ` cache closure
  with upper bound `(T+1)/|E|`. Full `lake build` passes (2,572 jobs), and
  the expanded named audit checks 16 generic and
  implementation-mapped theorems, each depending only on `propext`,
  `Classical.choice`, and `Quot.sound`; no `VoltaZk.Ideal` assumption enters
  the boundary. This closes the pre-existing scalar code/theorem mismatch.

  The separate aggregate prerequisite is now
  `VoltaZk/BatchSumcheckSound.lean`:
  `outer_scalar_batch_blind_sumcheck_sound` fixes `K` claimed/true totals
  before a fresh outer `β`, uses weights `β^(k+1)`, and proves bad-tape
  count `(K + Σ d_i + n + 2)|E|^(n+2)` out of `|E|^(n+3)` — the
  `K/|E|` collapse plus scalar M3. Importantly, after `β` the aggregate
  round strategy is fully malicious; the proof does not assume honest
  execution of the linear combiner. `scalar_batch_blind_sumcheck_sound`
  instantiates that boundary for `FixedSumcheckBatch`, while
  `HasCommonPoint` names the scheduler invariant.

  **Pre-registered implementation boundary (not silently discharged by the
  theorem)**: cohort membership and all `K` initial claims are closed before
  `β`; a cohort is homogeneous in round count and public degree vector; all
  members consume the identical `r`/prefix history; `β` is fresh and
  domain-separated from `Δ`, `r`, and the inner scalar `χ` (no challenge
  reuse); the aggregate final opening remains public-linear and
  VOLE-authenticated. The interactive transcript must account for the extra
  field challenge, so this is not a byte-identical protocol refactor even if
  total communication decreases. Rust enablement still requires a CPU
  reference differential for the new transcript, an explicit interleaving
  state-machine/common-point assertion, LogUp layer-end alignment, and exact
  domain/correlation-counter tests. Cross-cohort/session soundness is an
  explicit union bound. No verifier seed or future challenge schedule may be
  exposed to the prover/GPU as a shortcut.

  **Post-attribution scheduler decision (2026-07-13; preregistered before
  implementation)**: exact full-run structure contains 58,205 interactive
  round readbacks (51,122 LogUp + 5,400 blind product + 1,683 Hadamard), plus
  433 LogUp roots and 6,639 layer/split boundaries. Local root/split batching
  cannot reach 5,000 while instances remain sequential. The first scheduling
  lever is therefore **proof-format/communication-neutral** round-synchronous
  co-scheduling, not RLC: it is an explicitly logged transcript-scheduling
  change, while every instance retains its own message, independent challenge,
  fold, proof bytes, and verifier path. One contiguous mailbox D2H serves all
  jobs ready in the same public epoch. Cohorts and initial claims are sealed before
  enqueue, challenges are drawn only after the complete epoch returns, no job
  may join after sealing, public depth/path controls membership, and canonical
  `SiteId` order (never completion order) binds all roots/splits.

  Prefill and deferred-decode phase-2 jobs may share a cohort only after both
  phase-1/auth/shared-alpha/KV domain states are already fixed; decode phase 2
  has no value dependency on prefill phase 2. A public `SchedulePlan` must
  prove an exact upper bound before the full run. Current shape projection is
  about 2,450 LogUp critical-path epochs and 3,100--4,200 total explicit
  barriers including non-LogUp/global/table/PCS work. This is a projection,
  not a gate result. Scheduled epochs must also replace or reserve beyond the
  512-record timing ring: co-scheduling roughly 24 layer jobs can otherwise
  inject a timing flush inside a sealed cohort. The scalar-RLC theorem remains
  the second lever only if exact co-scheduling fails the gate; CUDA graphs are
  subsequent device-only replay work and may not cross challenge barriers.

  **Schedule/transcript semantics fixed before Rust enablement**: "proof
  unchanged" means the existing proof structs, correction labels, message
  count and communication bytes are unchanged; it does **not** mean that a
  multi-job scheduled proof has the same field values as the historical
  sequential proof at the same deterministic mock-verifier seed. The current
  `Transcript::append` is accounting-only and the verifier challenge stream
  is global. In a scheduled epoch P first sends every active SiteId's message,
  then V returns the same number of fresh challenges in canonical SiteId
  order. Consequently CPU-scheduled and GPU-scheduled proofs must be byte
  identical to each other, while scheduled-vs-legacy values normally differ.
  Per-SiteId challenge substreams are rejected: they add a second transcript
  semantics without reducing barriers and would require separately routing
  every global chi/rho/finalizer challenge.

  `SiteId` v1 is a stable packed `(version, public section, round family,
  public lane)`, never a `Debug` string or runtime completion index. A sealed
  `SchedulePlan` is built from public geometry and both parties preflight exact
  membership, family, depth and reserved correlation range before consuming a
  transcript byte or one-time correlation. The active set may only shrink;
  missing/extra/duplicate jobs, refill and partial retry are errors. Product,
  degree-3 and LogUp messages may share one heterogeneous mailbox epoch, but
  every instance retains an independent challenge and verifier recursion.
  The public plan publishes mailbox bounds, but no CUDA timing metadata.
  Resident LogUp's private, deterministic preparation chunks are the sole
  source of truth for profiler-ring capacity; the last chunk reserves two
  additional records for the coarse mailbox interval and its D2H. These
  chunks never split protocol membership or add a proof-message epoch. An
  automatic timing flush inside the sealed epoch remains forbidden and cannot
  be hidden from the <=5,000 count.

  The first byte-identical mechanism before cross-instance scheduling
  coalesces already-independent scalar buffers at each local boundary: two
  LogUp roots, four normal splits, aux q0/q1/column splits, and final
  product/Hadamard scalars use one D2H mailbox per boundary. Exact full
  structure projects **19,932 fewer response-session barriers** (10,434
  prefill, 9,498 decode), about 6.00 s at the measured 301.208-us median
  8-byte D2H RTT, with unchanged D2H/H2D and about 0.45 MB extra D2D. This is a
  mechanism projection pending measurement and remains far above 5,000 by
  itself. The audited role-antichain LogUp plan is 2,446 epochs (873 FFN +
  1,573 attention; max 1,573 when those independent phase-2 branches are
  interleaved), validating the ledger's earlier ~2,450 projection without a
  coroutine or cross-layer mutable-context redesign.

  **P7b architecture-hygiene checkpoint (2026-07-13; no timing claim)**:
  before changing the round schedule, the resident allocation registry was
  replaced by an opaque generational `(generation, slot)` arena. Active-ID
  lookup and stale rejection are O(1); inactive physical allocations use
  best-fit reuse; logical free issues no CUDA call; explicit trim releases
  only inactive capacity after a classified allocator barrier. ABI 19 reports
  physical `cudaMalloc`/`cudaFree` separately from logical alloc/reuse/free,
  partitions every explicit stream synchronization into host-output,
  upload-lifetime, timing-flush, legacy-profiling, or allocator-flush, and
  enforces that the reason sum equals the total. Device memory is partitioned
  exactly into primitive workspace, active resident capacity, and cached
  resident capacity. The report records both pre-trim high water and
  post-trim teardown and accepts a schema-4 run of record only when both
  accounting invariants hold. Clean-tree detection now includes untracked
  files and treats a failed `git status` as dirty.

  PCS commit/open temporaries now have exhaustive RAII cleanup on every early
  return. Compound matrix teardown preflights all context ownership before it
  consumes a handle; a wrong-context error returns the complete matrix so the
  caller can retry with its owner. On Thunder A100, the rebuilt monolithic
  backend passes all **16/16** `volta-accel --features cuda` tests, including
  best-fit/no-alias, stale and double-free rejection, logical bounds, trim and
  reason accounting; all **3/3** resident PCS CUDA differentials pass,
  including injected partial-commit and cross-context opening failures.
  The legacy host-barrier timing fallback was also corrected to attribute its
  three barriers to H2D/kernel/D2H causes rather than labelling all of them as
  profiling.

  **Deferred resident profiling checkpoint (2026-07-13)**: ABI 20 adds a
  resident-only fixed ring of 512
  lazily allocated CUDA-event records. Device-only primitives and pageable
  H2D uploads now enqueue without a host barrier; D2H host outputs, a full
  ring, explicit stats/measurement completion, reset, and physical
  reclamation flush the stream with the existing reason accounting. The ring
  retains metadata only (no shadow upload payload or host-RSS growth), and a
  flush queries the complete batch before committing attribution. Failed
  calls abort the active record, while destroy/reset/reclaim preserve stream
  ordering. New exact counters report records, event queries, pending high
  water, and non-empty flushes; report rows expose all four. Empty H2D/D2H
  phases do not issue elapsed-time queries (a remote CUDA API call): a
  device-only primitive needs one query, not three. `synchronizations` and the
  <=5,000 gate count explicit backend stream barriers; pageable-H2D staging
  wall remains visible in end-to-end wall/residual rather than being
  mislabelled as an explicit barrier.

  The pageable-H2D lifetime assumption is load-bearing and is therefore a
  measured platform contract: on Thunder A100, immediate source mutation
  after a 4 MiB upload, source drop followed by generational free/reuse of the
  same physical allocation, and a 513-record ring-wrap all pass. The full
  rebuilt backend passes **19/19** CUDA tests and the resident PCS suite passes
  **3/3**; the local Rust workspace is green. Hybrid mode remains on the
  legacy timing path, and runtimes without usable event elapsed time retain
  the synchronous host-barrier fallback.

  Clean quick diagnostic at SHA `956f81f` (T=16+8, Q=200, one repetition;
  not the preregistered T=100+50 gate): immutable
  `benchmarks/results/p7-integrated-resident-quick-2026-07-13-956f81f.json`
  (SHA-256
  `bed809772fb926cf2328502a0572011a3dc2cca9696aaec2cc6c72af5c087a8a`,
  `git_dirty:false`) is accepted and flat-cost passes at **1.05**. Prefill
  proof is **28.599 s** and response proof **50.363 s** (decode marginal
  **21.764 s**); these quick-shape values are diagnostic, not gate results.
  The response-session attribution is **52.208 s** wall, **4.684 s** kernels,
  873,917,300 B H2D and 81,516,788 B D2H. Explicit barriers fall to
  **61,675**, all host-output; legacy profiling and upload-lifetime barriers
  are both zero. Prefill has 32,851 barriers = 32,819 host-output + 32
  allocator. Thus deferred timing closes exactly the profiling-barrier lever
  but misses the <=5,000 sync gate by 12.3x even at quick geometry: the next
  required lever is cross-instance host-output coalescing/RLC, not cheaper
  synchronization. The arena records only 239 physical allocations for
  181,021 logical requests (180,783 reuse hits). Empty-phase suppression
  reduces session elapsed-time queries to 189,426 for 151,835 records, but
  per-kernel queries remain a measured remote-call surface.

  A standalone CUDA implementation of the exact `rand_chacha 0.3.1`
  ChaCha8 stream layout plus Goldilocks rejection sampling is now available
  for device-side prover-owned pads/masks. It explicitly excludes verifier
  challenges and `Delta`. CUDA 13.2 / sm_80 results are byte-identical to the
  Rust `FpStream` oracle in the clean immutable result
  `benchmarks/results/p7b-chacha8-fp-diff-2026-07-13-32653fd7e076.json`
  (source SHA `32653fd`, `git_dirty:false`, result SHA-256
  `21207d234e32b8eec56545e0e652e2c97f56787c62ab4e138b361c67f3c97906`)
  on A100-SXM4-80GB. The Fp multi-block case has stdout SHA-256
  `1570f825215b0e38da4857fc32b40a97b8bf0efed7f90f6c44431e801b7c2634`
  and the Fp2/high-64-bit-domain multi-block case has stdout SHA-256
  `90abbd2a0773f9c455313a3eab8172a1647a2c7cea152fa71324ef996c220051`.
  Both raw stdout and parsed structures match. This checkpoint validates the
  generator and ownership boundary only; H2D savings are not claimed until
  it is integrated into the PCS kernels and measured in the full session.

  **Device-source PCS integration checkpoint (ABI 21; 2026-07-13)**:
  resident commitments no longer flatten or re-upload layer/embedding
  weights. Checked, aligned tensor placements copy the already-resident
  `CAttnProof`, projection, FFN and embedding views into a zeroed packed
  target via explicit D2D row copies. Row pads and padded Fp2 opening masks
  use the byte-identical device ChaCha8 expansion; `c` powers, block-row
  coefficients and all `s_g` row dots are also materialized on device. The
  pad seed remains a prover-secret of the static weight registration (not a
  response nonce); the ephemeral mask seed is response-fresh and separated
  by role/instance. Neither path receives a transcript challenge, a shared
  mock-PCG/correlation seed, or `Delta`. The public report calls the new
  counter `explicit_d2d_copy_bytes`: it covers these explicit row-copy APIs,
  not every internal kernel/workspace movement. H2D remains the complete
  backend payload counter used by the gate.

  On the designated Thunder A100, ABI-21 passes **21/21** accelerator tests
  (including a real Goldilocks rejection-sampling vector) and **5/5** resident
  PCS tests. The latter check CPU/GPU-identical commitment roots, full proof
  objects, transcript ledgers and correlation counts, two-placement padded
  geometry, wrong-context/overlap/failure cleanup, and response-fresh mask
  proofs with unchanged size and successful verification. Resident report
  schema 5 serializes the P7b observations explicitly: timing gates use the
  upper median across measured repetitions, count/traffic gates use the
  maximum measured session, and quick runs set `p7b_gate_evaluated:false`.

  Dirty-tree quick diagnostic only (never a gate claim):
  `p7-integrated-resident-quick-2026-07-13-8b5d177-1.json`, SHA-256
  `d9d06071355e4428cc3878eb952ada87bc8e30c36f4b7d029d31869f878866d0`,
  is accepted with all 13 Q=200 PCS openings and flat-cost 1.0003. Session
  H2D falls from the preceding quick checkpoint's 873,917,300 B to
  **24,909,172 B** (-849,008,128 B, -97.15%); D2H is 81,518,420 B. Explicit
  D2D copies are 313,339,392 B, device zeroing 702,652,416 B and device
  generation 115,302,400 B. Synchronizations are **61,688**, all
  `host_output`: the 13 new batched `s_g` scalar reads add exactly 13 to the
  prior 61,675, so this checkpoint closes the H2D mechanism but deliberately
  does not claim the <=5,000 scheduler gate. PCS commit/open/verify are
  0.181/0.592/0.296 s; total kernels are 4.458 s. Core wall (31.262 s prefill,
  26.756 s decode marginal) regressed under remote variance despite the lower
  kernel total and is not compared as a performance result. A clean immutable
  checkpoint is required before promoting the traffic observation.

  The immutable rerun now satisfies that hygiene gate:
  `p7-integrated-resident-quick-2026-07-13-bf66c8f.json` (source `bf66c8f`,
  `git_dirty:false`, SHA-256
  `1b405aa54237aab45425eedb3648c6a855ad89b9e0d4f85e9e10d929d63b59da`).
  It is accepted, all 13 Q=200 PCS openings verify, flat cost is 0.9882, and
  the traffic/count observations reproduce exactly: **24,909,172 B H2D**,
  81,518,420 B D2H, 313,339,392 B explicit D2D copies, 702,652,416 B device
  zeroing, 115,302,400 B device generation, and **61,688 host-output
  synchronizations**. PCS commit/open/verify are 0.174/0.566/0.349 s; kernel
  total is 4.839 s. Core prefill is 27.868 s and decode marginal 23.425 s.
  Because this is T=16+8 quick geometry, schema 5 correctly records
  `p7b_gate_evaluated:false`; it validates the implementation and H2D
  mechanism, not any of the T=100+50 official verdicts. The full-geometry H2D
  projection remains about 96.43 MB and must be confirmed, not inferred, by
  the later clean gate run.

  **P7b iteration-2 orchestration checkpoint (ABI 26 / report schema 6;
  implementation and correctness only, no timing claim)**: deferred CUDA
  timing now retries an elapsed-time query that returns success without
  writing its output, using one complete first pass followed by at most three
  exact retry sweeps and failing closed if a record remains unresolved.
  Separate attempt, successful-query and no-write counters must balance
  exactly. Measurement reset synchronizes and discards
  pre-window records without querying elapsed time before zeroing statistics;
  in-window records retain exact attribution. Aborting a coarse scope after
  any accounted primitive now poisons the measurement: statistics and finish
  fail closed until an explicit synchronizing reset, so discarded event
  intervals cannot reappear as host residual. Checked coarse timing scopes
  cover device-only cohort work, while segmented host outputs use one coarse
  mailbox scope and one D2H. None of these paths fabricates a duration or
  relabels remote CUDA calls as CPU work. The C ABI independently rejects
  mock-auth mask domains entering reserved bits 61--63 rather than relying on
  the safe Rust wrapper alone; ABI and `RawStats` layout remain version 26.

  Schema 6 retains the upper-median timing and maximum-session traffic/count
  rules from schema 5, but emits only `P7b-*` CUDA milestone names and makes
  an official verdict conditional on Thunder provider metadata, an A100,
  clean-tree checks both before benchmarking and before serialization, and
  one identical nonempty full Git SHA across that complete window,
  T=100+50/Q=200, at least one warmup and at least three measured repetitions.
  Acceptance, golden/flat checks, the 200 MB envelope and no growth in the
  P7 transcript, PCS-opening, packed-logits and packed-response components are
  mandatory alongside the four P7b gates. Mock-PCG is serialized with
  `pcg_production_ready:false`; the harness cannot present it as production.
  The Python selector independently reconstructs upper medians and maximum
  session counts from the raw repetitions and rechecks every invariant and
  exact threshold; a coherent measured failure remains an official verdict,
  while a missing or self-inconsistent boolean cannot become one.

  Correlation ownership is now sealed through exact, disjoint full-correlation
  range reservations and exact submask-row reservations before transcript or
  one-time stream consumption. Reservation failure is atomic, and unused
  reserved draws are released on error. Prover authentication masks may be
  expanded on device only for the named deterministic mock backend, using the
  byte-identical ChaCha8/Goldilocks stream and host-owned domain counters. The
  pooled/real-PCG backend retains its host-produced authenticated masks and is
  never silently routed through this device generator; mock remains explicitly
  non-production. Thunder A100 differentials for the ABI-26 substrate and
  fault injection, pre-window reset, segmented mailbox, device mock-auth mask,
  resident product batch and heterogeneous LogUp batch are green.

  The scheduling implementation now includes coalesced local scalar
  mailboxes; one canonical round mailbox for the twelve attention heads in
  each W·V and Q·K product cohort; and a generic heterogeneous-depth LogUp
  batch with sealed `SiteId`, exact correlation-role ranges and all-site
  `TableBank` manifests. Its leaf path keeps and folds only q0/q1; public
  p0/p1=1 values are reconstructed on the host rather than copied or assigned
  correlations. Existing proof structs, correction labels, message counts
  and communication bytes are preserved; CPU-scheduled and resident-scheduled
  outputs are the required exact differential, not scheduled-vs-legacy field
  values under a globally reordered challenge stream.

  GELU is the first response call-site integration: all twelve prefill layers
  and all twelve layers of every deferred decode band are preflighted into one
  response-wide manifest before table-bank finalization or scheduled-root
  mutation, then each public band runs one CPU/resident/verifier cohort. For
  the official one-T=100-prefill +
  one-q=50-band geometry this projects **3,993 fewer blocking
  synchronizations** than twelve sequential GELU sites; it is a geometry
  projection, not a measurement or gate result. A latent resident decode
  `SiteId` mismatch was also fixed: attention product sites had used the
  physical layer index where CPU/verifier used the public decode-domain
  section. Canonical ordering had masked the mismatch; the resident path now
  derives the same public section and has a dedicated regression test.

  The final architecture audit also made verifier entry and resident cleanup
  fail closed. `verify_response` validates public dimensions, every indexed
  phase-1 proof shape, table cardinalities, the at-most-five-chunk namespace
  and checked position arithmetic before consuming a challenge or correlation
  key. Greedy decoding now binds the first token of every later chunk to the
  final logits row of its predecessor; malformed calls leave transcript bytes,
  transcript ledger, allocation digest and verifier counters unchanged. The
  FFN scheduler, generic LogUp cohort and resident blind-sumcheck batch perform
  exhaustive ownership sweeps and propagate the first release error ahead of
  the operational error. In particular, a timing-capacity failure on LogUp's
  second preparation chunk can no longer strand the first 56 device owners.

  The implementation evidence remains separate from the performance verdict:
  CPU full-response e2e at T=12 plus one q=4 decode band is green; the full
  local workspace (including 80 protocol tests after the cleanup regressions),
  the five report tests, the five Python selector tests and the CUDA-feature
  `--no-run` build are green. The A100 ABI-26 accelerator suite is 32/32; on
  the clean `61aafe8` checkpoint the device-auth, product-sumcheck,
  heterogeneous-LogUp, attention, band-layer and full-response differentials
  are green; the scheduled proof remains byte-identical to its CPU path, the
  verifier accepts it and replay rejection remains green.

  The first clean call-site-scheduler measurement is the append-only quick
  diagnostic
  `benchmarks/results/p7b-integrated-resident-quick-2026-07-13-61aafe8.json`
  (full source SHA `61aafe8f8d8a1db6dded82266ad10a040715e8f7`, SHA-256
  `fe12b8efc77137587e08a11c6a41a2157520ab90cef182e14c8c6ad53e9a6a25`).
  It was run from an isolated clean clone of a checksum-matched bundle;
  before-benchmark and before-serialization trees are clean at the same full
  SHA, and the Thunder/A100 metadata is complete. The response is accepted,
  all 13 Q=200 PCS openings verify, chunked verification passes, flat cost is
  0.9872 and the packed 82,281,642 B response remains inside the communication
  envelope. Explicit resident bytes are zero after cleanup; cache trim leaves
  only the 14,286,896 B workspace. Mock-PCG is explicitly non-production.

  At T=16+8, response-session H2D is **12,656,708 B**, D2H is 81,518,420 B
  and blocking host-output synchronizations are **39,201**. Relative to the
  clean `bf66c8f` quick baseline this removes 12,252,464 B H2D (-49.19%) and
  22,487 synchronizations (-36.45%); D2H is unchanged. The single-sample core
  times are 27.154 s prefill, 50.782 s response and 23.628 s decode marginal,
  with 52.146 s response-session wall. ABI-26 coarse intervals include device
  idle gaps while the host submits remote work, so their 12.393 s aggregate is
  not comparable to the old per-call 4.839 s kernel total.

  Because this diagnostic has T=16+8, zero warmups, one measured repetition
  and no golden check, schema 6 correctly records
  `p7b_gate_evaluated:false`: **none of the <=10 s / <=4 s / <=5,000 sync /
  <=100 MB official gates is evaluated or claimed**. The 39,201 sync count is
  already 7.84x the numeric gate at smaller geometry, so an expensive official
  full run is deliberately withheld until another blocking-output batching
  step; this is a readiness decision, not an official failure verdict. The
  next protocol-neutral lever is further coalescing of dependent host-output
  boundaries, especially non-GELU LogUp and blind sumchecks.

- **2026-07-13 (P7 publication artifact closed)**: clean aggregate
  `benchmarks/results/p7-2026-07-13-2c836b3.json` (SHA-256
  `6aa5d6927e8f511b4d9ca7881ac4e6c50ffd32b8fb48fbb9badc764dcc9aa78a`)
  joins the resident proof only to its exact same-instance native anchor and
  records `measured_same_host_targets_fail`; the historical hybrid result
  remains a separate attribution artifact. `docs/p7-artifact.md` contains the
  quick/full A100 commands and claim boundary;
  `artifact/p7/hardware-a100.json` pins hardware, CUDA/Rust, workload and raw
  checksums. `scripts/p7_artifact_outputs.py` regenerates the checked-in
  result table, rho SVG, response-attribution SVG and shape CSV and has a
  strict `--check` mode. All eight Python artifact/report tests pass. The
  frozen Lean project builds (2571 jobs) and `scripts/audit_lean.sh` confirms
  all eight audited M1--M9 theorems depend only on `propext`,
  `Classical.choice` and `Quot.sound`; the four named external assumptions do
  not enter that boundary. P7 is complete with a negative performance
  verdict, not deferred or relabeled as production-ready.

- **2026-07-13 (post-e2e synthetic shape/memory sweep complete; no new
  frontend or e2e claim)**: clean append-only result
  `benchmarks/results/p7-shape-memory-sweep-2026-07-13-797f499.json`
  (SHA-256 `59df28891f7a5c024a98e66f1bb1d470cf8d7909d334dbcd92190076b5fec42a`)
  evaluates sequence lengths 150/512/2048/8192 for exactly three declared
  profiles: the measured GPT-2-small shape, a representative Llama-class 8B
  dense/GQA shape and the documented gpt-oss-20b/MoE-active planning shape.
  The frozen GPT-2 manifest closes exactly at 124,701,952 i16 elements /
  249,403,904 B; the analytic Llama shape is 8,030,261,248 parameters with
  GQA KV fraction 1/4; gpt-oss uses 20.9B total / 3.6B active parameters,
  hence 41.8/7.2 GB i16 total/active weight bytes. Linear state rows are
  monotone, GQA reduces KV as expected and active MoE weights remain below
  committed total weights. The JSON links the measured 5,405,147,708 B
  GPT-2 proof peak but explicitly projects neither non-GPT proof time nor
  proof peak memory. `ModelConfig`, Llama/gpt-oss frontends and non-GPT e2e
  remain out of scope.

- **2026-07-13 (`P7-integrated-resident` full run and same-host native anchor
  complete; performance gates failed)**: clean immutable full run
  `benchmarks/results/p7-integrated-resident-2026-07-13-1fd5195.json`
  (SHA-256 `02538a48511354f7ce92ba0602240edab9eede344aa30e351b7c03d338679c6b`)
  uses the workload of record T=100+50, Q=200, one warmup and three measured
  repetitions on A100-SXM4-80GB/CUDA 13.2. All three proofs accept; the full
  golden decode is exact, verifier and 13 stacked PCS openings pass, flat
  last/first is 0.950 <=1.5, and packed response download is 144,820,930 B
  inside the 150--200 MB envelope. Explicit resident bytes return to zero;
  104,988,720 B of reusable context workspace remain named, and peak device
  memory is 5,405,147,708 B. Peak RSS is 2.226 GiB.

  Protocol-core medians (MAD) are 64.295793 (0.329496) s prefill,
  121.155759 (0.372825) s response and 57.295866 (0.808726) s decode
  marginal. Online-accounted response is 121.774353 s and online marginal is
  57.924561 s; the complete single-process response-session wall is
  123.927768 s. PCS commit/open/verify are separately
  0.765752/0.610145/0.370512 s and accounted in that wall; accounted verifier
  is 1.044615 s. Resident witness generation is 0.111155 s for prefill and
  0.247386 s for the T=150 response, yielding measured resident pipeline
  totals of 64.406948 s (prefill inference + core), 122.021740 s (response
  inference + online-accounted prover) and 124.175155 s including the full
  local response session.

  The same-host exact native anchor
  `benchmarks/results/p7-gpu-native-inference-2026-07-13-1fd5195.json`
  (SHA-256 `73ce54cf8759b7b91b5a032098a1d5eb77bd8c804256ce9c5c8eba2820556c9f`)
  is golden-exact over seven repetitions: prefill 0.017341642 s (MAD
  0.000062169) and KV decode50 0.599345878 s (MAD 0.000989627), with weights
  resident and per-token logits D2H/argmax timed. Thus preregistered
  rho_proof is **3707.595 >10 FAIL** prefill and **95.597 >2 FAIL** decode;
  gaps to target are 370.760x and 47.799x. The online-accounted decode rho is
  96.646.

  Attribution explains why this is not a near miss: the representative
  response session has 5.998 s CUDA kernels, 89.055 s CPU residual,
  945,442,180 B H2D, 138,488,436 B D2H and 211,709 synchronizations (72.652 s
  synchronization wall). Even eliminating all measured host/transfer cost
  would leave kernel time far above the 173 ms prefill proof budget. The
  result therefore closes the requested e2e measurement honestly; it does
  **not** support a production-ready or target-meeting claim. Reaching the
  targets requires a new coarse-grained GPU protocol architecture (device
  transcript/challenge batching and materially fewer proof passes), not a
  local benchmark tweak. Mock-PCG remains the named baseline and its
  two-party/parameter hardening blockers remain unchanged.

- **2026-07-13 (`P7-integrated-resident-quick` clean ABI-v17 harness gate
  passed; full remains mandatory)**: immutable clean-tree run
  `benchmarks/results/p7-integrated-resident-quick-2026-07-13-1fd5195.json`
  (SHA-256 `630629287213978f8dd6aa5e46703e962d5fe2226ca843e5050bd5f048f7ddc1`)
  on A100-SXM4-80GB/CUDA 13.2 accepts the resident proof, all 13 Q=200 PCS
  openings, the unchanged verifier and the two-chunk flat-cost session at
  T=16+8. Protocol-core wall is 46.874 s prefill and 85.853 s response;
  online-accounted response (core + PCS open + closure) is 86.585 s, and the
  complete single-process response session is 88.354 s. PCS commit/open/
  verify are 0.851/0.724/0.311 s, flat last/first is 0.995 <=1.5, packed
  download is 82,281,642 bytes and peak device memory is 4,991,265,544 bytes.
  After dependency-ordered cleanup, total live equals the reusable workspace
  exactly (14,286,896 bytes) and explicit resident allocations are zero.

  Attribution is intentionally retained: the response session performs
  151,835 synchronizations, 873,917,300 B H2D, 81,516,788 B D2H, 4.002 s of
  kernels and 61.541 s of host residual. This exposes substantial remaining
  orchestration/transfer cost rather than relabeling device-resident witness
  storage as a fully GPU-saturated prover. Quick skips the full golden-decode
  gate and has one repetition, so its rho must not be quoted. Proceed with the
  preregistered T=100+50, one-warmup/three-repetition run before deciding the
  resident targets.

- **2026-07-13 (`P7-integrated-resident-quick` cleanup-accounting gate caught
  a workspace/ownership ambiguity; no JSON emitted)**: the first clean quick
  attempt from `634c59c` completed the resident proof, all 13 PCS openings,
  verification and the flat-cost curve, then deliberately aborted before
  serialization because total live CUDA memory was 14,286,896 bytes rather
  than zero. Audit shows these bytes are the 16 context-owned primitive
  workspace slots, which `ensure()` grows and intentionally retains for
  reuse; every explicit `DeviceBuffer` is tracked separately in the same
  total. Treating reusable workspace capacity as a witness leak would violate
  the preregistered persistent-workspace design.

  ABI v17 therefore adds a read-only memory breakdown computed from the CUDA
  context's workspace slots and opaque resident-allocation registry, with an
  internal invariant that their sum equals total live bytes. Report cleanup
  now requires **zero explicit resident bytes** and total live bytes equal to
  reusable workspace bytes; both values are serialized. No allocation is
  hidden or released merely to improve the number, and context destruction
  still frees both classes. The failed attempt produced no raw result and its
  observed quick timings are not a benchmark claim. The clean quick must be
  rerun from the ABI-v17 checkpoint before the full gate starts.

- **2026-07-13 (`P7-integrated-resident` e2e report harness landed; clean
  measurement still pending)**: the existing `p6_report` now selects the
  internal resident backend explicitly and consumes one persistent uploaded
  model, a resident prefill witness, a resident T=150 response witness and
  D2D-derived decode bands. The unchanged `ModelProof` is verified through
  the existing `verify_response`; the same 13 PCS commitments/openings are
  executed through resident matrices. Repetitions reuse the same context and
  buffers, while all owned allocations are released in dependency order and
  a zero-explicit-resident-bytes assertion closes the run (persistent CUDA
  workspace capacity is reported separately). CPU remains the default;
  asking for resident CUDA still fails explicitly if the feature/library is
  unavailable.

  Timing schema v3 preserves the preregistered protocol-core
  `t_prove_*`/rho fields, but also records per-repetition (a) online-accounted
  core + PCS opening + final closure exchange, (b) the complete one-process
  response-session wall including offline PCS commitment and verifier, and
  (c) PCS commitment/open/verify separately. Resident witness, proof and PCS
  accelerator scopes retain kernel, CPU residual, H2D/D2H, synchronization,
  allocation and peak/live-device attribution. The aggregate joins a full
  resident run only to a clean exact native-GPU anchor with the same cloud
  instance id and exposes resident inference + proving separately. Mock-PCG
  remains named and is never presented as production-grade. This is reporting
  and resource-lifecycle plumbing only: transcript, proof bytes, verifier,
  Q=200, quantization and Lean-facing assumptions are unchanged. No resident
  performance claim is registered by this entry; quick smoke and then the
  clean 1-warmup/3-repetition T=100+50 run are still required.

- **2026-07-13 (`P7-integrated-resident` stacked-response correctness gate
  landed; publication timing remains open)**: checkpoint `b0088f2` extends the
  existing square resident prover rather than introducing a parallel
  protocol. `prove_model_resident` remains the compatibility wrapper over one
  `prove_response_resident` core. Prefill and all decode bands bind their
  resident lookup columns before a single shared-alpha table-bank finalize,
  then contribute to the same model-wide product/zero batches and unchanged
  `ModelProof`. K/V plaintext is folded directly from the full contiguous
  device cache; Rust retains only ordered `(domain, rows)` prefix metadata.
  Band seams, embedding, final LayerNorm, public-logits claim and selection
  use checked resident operations with transactional ownership cleanup. The
  only host inputs unique to a chunk are public tokens and public logits,
  already required by the protocol/verifier.

  On A100 `instance-3d0rtrml-main` with CUDA 13.2, the release gate proves a
  real GPT-2 response at T=3 plus one Q=3 deferred chunk. Against the same
  seeds, CPU and resident paths match exactly for the entire proof, 96 weight
  claims, six embed claims, byte/lookup/correlation counters, all table
  closures, product/zero rows and transcript accounting. The existing
  `verify_response` accepts, including public greedy checks and true-weight
  resolution; global product and zero batches close. A second proof on the
  same CUDA context is identical with stable live device bytes, while a
  replayed chunk-K correction is rejected. The CUDA error word stays zero and
  resident LogUp/GEMM paths report no operation-local CPU residual. The CPU
  `volta-proto` suite remains 56/56. This 150.77-second test deliberately
  includes CPU reference, two resident proofs and verification; it is a
  correctness artifact, not a benchmark sample, JSON of record or rho.

- **2026-07-13 (`P7-integrated-resident` authenticated-prefix decode-band
  layer proof landed; stacked-response gate still open)**: checkpoint
  `0c56c66` generalizes the existing resident layer proof over the sealed
  `ResidentLayerView` and consumes the complete K/V cache through one
  contiguous device view plus a list of `(domain, rows)` segments. Prefix
  plaintext never returns to the host: Rust retains only the authentication
  domains needed to derive the matching MAC tags. The same phase-1/phase-2
  proof structs, transcript labels, verifier format and byte/count formulas
  are used for square and band shapes; runtime `(t0,q,seq)` geometry replaces
  any model-specific accelerator constant.

  On the replacement A100 `instance-3d0rtrml-main` (A100-SXM4-80GB, sm_80,
  CUDA toolkit 13.2), the new release differential proves layer 0 at
  `(t0,q)=(2,3)` after authenticating the two-row K/V prefix under separate
  domains. CPU and resident paths match exactly for the complete layer proof,
  four weight claims, byte and lookup breakdowns, table closures,
  product/zero batches, all domain/correlation counters and the transcript
  ledger; the CUDA sticky-error word remains zero and LogUp/GEMM report no
  operation-local CPU residual. This was a development correctness test, not
  a clean-tree benchmark or JSON of record. Full-response verifier,
  anti-replay, context-reuse and timing gates remain mandatory before any
  resident rho is recorded.

- **2026-07-12 (`P7-integrated-resident` full square-layer/model proving
  correctness gate landed; timing not yet permitted)**: ABI v15 connects the
  real T=3 square/prefill witness to both layer phases and to the complete
  twelve-layer model prover without materializing a host `ModelWitness`.
  Embedding, every block, final LayerNorm and logits are consumed through
  checked resident views; Rust retains challenges, transcript ordering,
  correlation domains and the unchanged proof representation. Generic
  resident requant-column and vector-repeat operations take runtime shapes;
  no GPT dimension was added to the accelerator interface. Failure cleanup is
  transactional, including the phase boundary where an FFN failure precedes
  attention ownership transfer.

  The clean detached checkpoint `c1486b8` was built as CUDA ABI v15 on A100
  `instance-3mq19up4-main` (sm_80, CUDA toolkit 13.0). All 15 accelerator
  tests passed, followed by the real-weight full-layer and full-model gates.
  With identical seeds the CPU and resident paths produce byte-identical
  proof objects, public claims, proof byte/count breakdowns, lookup and
  correlation counters, product/zero batches and transcript ledgers; the
  unchanged verifier accepts. Two model proofs reuse one CUDA context with
  stable live allocation bytes, and a CUDA-derived correction fault is
  rejected. This closes square/prefill proving correctness only: it is not a
  T=100 timing sample, has no JSON of record and carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` decode-band witness gate landed;
  band proving still open)**: ABI v16 adds one sealed, shape-parametric D2D
  strided-row compaction operation. A `ResidentBandModelWitness` borrows all
  contiguous q-row windows from a longer resident response witness, owns only
  the seven non-contiguous causal/head layouts, retains the complete K/V
  prefix as checked device views, and derives band final-LN/logits on device.
  It supports an arbitrary valid `(t0,q)` window, including a non-suffix band,
  so the P6 5x10 flat-cost curve can be derived from one resident T=150
  forward without host witness copies.

  On the same A100, clean checkpoint `5a571f1` passed all 15 CUDA accelerator
  tests and the dedicated T=6, `(t0,q)=(2,3)` differential. Every wire of all
  twelve layers, embedding rows, final LayerNorm and logits equals the CPU
  band bit-for-bit over repeated use of one context; live bytes are stable and
  the online transfer boundary is only the four-byte sticky-error init/result.
  This is a resident witness/dataflow result, not yet a decode proof or timing
  result. No resident rho may be quoted until band/full-response proof
  equivalence and the preregistered repeated A100 report are green.

- **2026-07-12 (`P7-integrated-resident` complete square-attention proof
  checkpoint; layer/model orchestration still open)**: ABI v13 materializes
  the proof-only attention view directly from the causal-packed resident
  witness: shared rectangular score/exp/weight columns, stable-softmax
  `is_max`, padded row tables, full and sparse-above QK accumulators, and the
  padded/permuted QKV range columns. One checked owner exposes only typed
  column views. The builder takes runtime q/s/head geometry, shifts and pad
  pairs; it contains no GPT-2 dimension or model configuration. Phase 1
  consumes these views for five lookup families/global histograms and
  authenticates LN vectors plus denom/recip/above/row-shift data without a
  host witness mirror. The real T=3 layer-0 differential checks every column
  in order against `build_attn_wires`, then matches all corrections, global
  multiplicities, alphas, counters and transcript exactly.

  ABI v14 adds the remaining reusable algebra: base-to-Fp2 lift/broadcast,
  a shape-parametric above-causal mask over a device equality row, weighted
  base-vector reduction, and strided-window MLE. Rust still generates every
  challenge and owns transcript/MAC orchestration. The resident attention
  phase 2 now covers projection, AV head splits, twelve W·V GEMMs, causal
  blind sumcheck, softmax normalization/row sums/row-max, twelve QK GEMMs,
  QKV and LN1. Mock-PCG boundary tags remain host-generated, while all
  plaintext folds and witnesses stay device-resident. The proof permutation
  of `c_attn` is prepared once in the internal GPT-2 model upload (setup), not
  embedded in the accelerator API.

  On A100 `3mq19up4`, the complete real `AttnBlockProof`, both PCS-bound
  weight claims, table closures, product/zero rows, theoretical counters,
  correlation consumption and transcript ledger are byte-for-byte equal to
  CPU. The unchanged verifier accepts after real-weight claim resolution and
  final batch closures. New primitive tests cover non-power-of-two window
  MLE, base broadcast, arbitrary weighted sums and above-mask indexing.
  CPU/default entry points and proof format are unchanged. This result is the
  full **square/prefill attention subgraph**, not yet a full layer/model or
  decode-band resident result and therefore carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` attention substrate checkpoint;
  attention proof still open)**: ABI v12 generalizes the resident matrix fold
  to a checked column window with an explicit physical row stride. This is
  the internal operation needed to fold per-head Q/K/V views without a
  gathered buffer; the accelerator receives only runtime geometry and a
  sealed scalar/axis tag. The original whole-matrix API remains a wrapper,
  so existing CPU/CUDA call sites and ownership rules are unchanged.
  `prove_gemm_act_chained_resident` consumes already-folded opaque device
  vectors and mirrors the existing activation×activation proof exactly:
  Rust still owns challenges, transcript messages, correlation domains and
  the caller-provided boundary MAC tag; only compressed round values and the
  final two field scalars cross D2H. Error paths consume both folds, and no
  new verifier or proof representation was introduced.

  CUDA 13.0/sm_80 on A100 `3mq19up4` validates the strided non-power-of-two
  fold bit-for-bit. A separate activation-GEMM differential compares the
  complete `ChainedGemmProof`, wire claim, bound point, transcript ledger and
  correlation counters with CPU over two uses of one context; all are exact
  and live device bytes remain stable. This checkpoint is intentionally a
  reusable attention substrate, **not** an attention/layer/e2e result and
  carries no resident rho.

- **2026-07-12 (`P7-integrated-resident` complete FFN proof checkpoint;
  attention/model orchestration still open)**: ABI v11 adds only
  shape-parametric proof-data operations: canonical base-vector padding,
  zero-padded matrix MLE evaluation, typed pair columns for i16/i64/Fp
  sources, signed/nonnegative LUT histograms, a resident degree-3 triple
  product round, and broadcast Hadamard-factor construction. None embeds a
  GPT dimension or changes a protocol message. The mock correlation provider
  still supplies masks/tags on the host; witness values never cross D2H.
  `ResidentFfnP1` retains all five bound lookup-column allocations across the
  alpha boundary, authenticates the four padded LN vectors, and contributes
  its histograms directly to the global resident `TableBankP`. Phase 2 then
  consumes those columns, resident boundary openings, two resident committed
  GEMMs and a D2D-folded LN Hadamard proof. All owned phase-1 buffers are
  released transactionally on success or error. The existing verifier and
  proof structs are shared literally with CPU.

  On A100 `3mq19up4`, primitive tests cover non-power-of-two matrix MLE,
  nonzero vector pads, signed pair indices, LN inputs above i16 range,
  triple-product rounds and every padded LN factor bit-for-bit. The standalone
  Hadamard prover matches CPU proof/claims/product/zero rows, correlation
  counts and transcript across context reuse. The real layer-0 T=3 FFN gate
  uses frozen weights and biases: phase-1 corrections/global multiplicities,
  the complete `FfnBlockProof`, both PCS-bound weight claims, table closures,
  product/zero batches, theoretical counters, correlation consumption and
  transcript ledger equal CPU byte-for-byte. The unchanged verifier accepts
  the resident proof after true-weight claim resolution and both final batch
  closures. CPU `volta-proto` remains 56/56 and the CPU-default accelerator
  tests remain 3/3. This is a full FFN subgraph result, **not** yet a resident
  layer/e2e result; attention, layer/model seams, embedding/final-LN and PCS
  orchestration remain to be connected before reporting rho.

- **2026-07-12 (`P7-integrated-resident` explicit LayerNorm-accumulator
  checkpoint; no protocol change)**: the dataflow audit found that every
  LayerNorm affine accumulator is consumed by a requant proof but was not a
  first-class `LayerWitness` field; the CPU prover reconstructed it from the
  boundary/statistics/gain/bias values. ABI v10 removes that architectural
  asymmetry. The frozen CPU witness now records `ln1_acc`, `ln2_acc` and the
  final/band LN accumulator, while retaining the same recomputation as a
  prover-side consistency assertion for the already-logged LN-statistics
  deviation. The CUDA LayerNorm kernel writes the identical i64 accumulator
  in the same pass that emits mean, variance, rsqrt and requantized output;
  resident layouts expose it as a checked typed slice. Persistent model
  parameters also gain typed field selectors for later proof consumption,
  without exposing addresses, backend model constants or a `ModelConfig`.

  CUDA 13.0/sm_80 ABI v10 builds on A100 `3mq19up4`. The full non-power-of-two
  T=3 forward differential now checks both new accumulators in all 12 layers
  plus the final LN accumulator, alongside every pre-existing wire and full
  logits, bit-for-bit against CPU. Two context-reuse passes, forced-overflow
  rollback and recovery remain green; the measured online transfer boundary
  is unchanged (tokens/error initialization H2D, four-byte sticky error D2H).
  Quantization, proof/verifier formats, transcript and lookup counts are
  unchanged. This is a witness-contract correction required by resident
  proving, not a resident layer/e2e timing result.

- **2026-07-12 (`P7-integrated-resident` global table-bank checkpoint;
  layer wiring still open)**: the P6 one-vector-per-table-content construction
  now has a resident ownership mode inside the existing `TableBankP`, not a
  second protocol implementation. Per-site device histograms are accumulated
  D2D into one opaque `u32` allocation per `TableKey`. At phase-1 close, the
  replaceable mock-correlation seam supplies canonical masks H2D and only the
  existing 8-byte correction vector returns D2H; alpha ordering, domains and
  transcript labels are unchanged. At phase 2 the public table is uploaded,
  while its negative-multiplicity fraction tree and the global multiplicity
  MLE remain resident. A generic typed resident-MLE helper builds equality
  weights from the small transcript point on device and returns one scalar;
  the shared fraction-sum/cross-check tail is literally the CPU function.
  Error paths consume and release all owned multiplicity buffers, so a failed
  bank cannot leak allocations into context reuse.

  The A100 `3mq19up4` differential accumulates two padded range sites under
  the same content key, authenticates/finalizes them, proves both resident
  lookup instances, closes the resident table side, and repeats the full
  sequence on one context. Both site proofs, the complete `TableCloseProof`,
  product/zero rows, theoretical counters, correlation consumption and
  transcript ledger equal CPU exactly; live device bytes are stable across
  reuse and both caller-owned source buffers are freed exactly once. All 56
  CPU `volta-proto` tests remain green. This closes global multiplicity and
  table-side ownership, but is not yet a layer/e2e result: the FFN and
  attention phase-1 builders still construct their lookup sites from host
  `LayerWitness` vectors.

- **2026-07-12 (`P7-integrated-resident` device lookup-instance checkpoint;
  table-bank/layer integration still open)**: ABI v9 replaces the last
  host-built lookup-side inputs with shape-parametric resident operations.
  Requantization sites emit column-major proof columns directly from their
  accumulator/output buffers (single and chained forms), pair-LUT sites emit
  their two columns, and device histograms can be accumulated without a
  round-trip. A typed `DeviceLookupColumns` owns the allocation and exposes
  checked borrowed views; the protocol layer can pack `alpha_0 - f`, split
  every base column into even/odd Fp2 aux halves, and run the existing resident
  LogUp engine from that view. The source stays caller-owned. No raw pointer,
  GPT-2 dimension, transcript challenge, proof byte or verifier-format change
  enters the accelerator API.

  On A100 `3mq19up4`, the primitive differential covers single/chained range
  columns (including padded entries), pair columns, histograms plus in-device
  accumulation, packed leaves and aux deinterleaving bit-for-bit. The new real
  `blind_instance_prove_resident` gate uses a padded two-column range instance
  with a non-empty externally authenticated aux claim: proof object, roots,
  every open claim, product/zero rows, arithmetic counters, correlation
  consumption and transcript ledger equal the CPU path exactly. A second run
  reuses the same source/context with stable live allocation bytes; freeing the
  source subtracts exactly its allocation while the context's intentional
  workspace remains persistent. The earlier host-fed LogUp differential also
  remains green, as do all 56 CPU `volta-proto` tests (full frozen model,
  response proof and anti-replay included). This closes the lookup-side
  resident input seam, **not** a layer/e2e gate: global table multiplicities
  and table-side proofs still need resident ownership before wiring FFN and
  attention.

- **2026-07-12 (`P7-integrated-resident` protocol-algebra + chained-GEMM
  checkpoint; layer integration still open)**: ABI v8 introduces a sealed,
  typed resident field-algebra seam rather than GPT-specific proof kernels:
  subfield-auth correction generation for i16/i64/Fp inputs, Fp2-weighted
  matrix folds along either axis with power-of-two output padding, Fp2 dot
  reduction, compressed product-sumcheck rounds and D2D vector folds. Rust
  retains transcript challenges, correlation-domain allocation and proof
  construction; only the two compressed round values and final scalar claims
  cross D2H. Input matrices and every intermediate fold stay in opaque
  context-owned buffers. Scalar-kind tags and fold axes are sealed/validated
  on the Rust side, so downstream crates cannot forge an ABI layout.

  All 13 `volta-accel` CUDA tests pass on A100 `3mq19up4`, including signed
  conversion, non-power-of-two matrix shapes, both fold axes, padding,
  correction identities, Fp2 dot/product rounds and context ownership. The
  resident blind product-sumcheck is byte-for-byte equal to CPU for all round
  corrections, points, authenticated claims, correlation counts and
  transcript ledger, with stable live memory across reuse. Building on that
  shared primitive, the first real protocol path — a non-power-of-two
  committed chained GEMM — produces identical `ChainedGemmProof`, X/W claims
  and Π_Prod messages on CPU and CUDA across repeated use. Proof/verifier
  formats and CPU entry points are unchanged. This remains a substrate
  checkpoint: FFN/attention derived columns, LogUp leaf handles and model
  orchestration are not yet wired to it, so no layer/e2e resident result or
  rho is recorded.

- **2026-07-12 (`P7-integrated-resident` full forward + witness checkpoint;
  prover integration still open)**: ABI v7 adds shape-parametric fixed-point
  primitives for embedding, LayerNorm, biased GEMM/requant/residual, QKV
  split, causal-packed scores and softmax, AV, LUT application, seam requant
  and batched logits. The accelerator API receives runtime geometry and
  shifts only; GPT-2 constants and orchestration remain in `volta-gpt2`, and
  no `ModelConfig`, product CLI or stable public API is introduced.
  `ResidentGpt2Model` owns one persistent typed weight/LUT allocation;
  `ResidentModelWitness` owns packed i16/i64 allocations for every
  proof-relevant wire but deliberately has no lookup traces, which the
  protocol already recomputes from those wires. Accumulators, requantized
  values and residual boundaries remain distinct device regions, so later
  proving does not need to reconstruct or download them. A borrowed
  `DeviceSlice` carries only context-owned buffer identity, element offset
  and length, never a raw pointer.

  The CUDA 13.0/sm_80 library compiles on A100 `3mq19up4`. With the frozen
  weight artifact checksum-verified, the non-power-of-two T=3 differential
  compares embedding, all fields of all 12 layers, final-LN and the complete
  logits vector against the CPU `ModelWitness` bit-for-bit. It repeats the
  full forward twice on one context and returns live device bytes to the
  post-model-upload baseline after each explicit witness free. A forced
  fixed-point overflow additionally exercises transactional rollback: the
  call fails explicitly, every allocation made by that call is released,
  and a subsequent valid forward on the same context remains bit-exact.
  Inside the
  measured forward the only D2H boundary is the four-byte sticky
  no-clamp/domain error flag; online H2D is the token vector plus its
  four-byte initialization. The entire CPU workspace, including golden,
  full-proof and anti-replay tests, remains green without CUDA. This is a
  forward/witness contract checkpoint, **not** a resident e2e result: the
  current block/model prover still reads host `Vec` wires, so no resident rho
  is recorded and the report's `cuda-resident` guard remains in place.

- **2026-07-12 (`P7-integrated-resident` PCS family device path landed;
  model-witness integration still open)**: ABI v6 adds resident padded message
  construction, batched Fp/Fp2 NTT, row combinations and mask addition,
  selected-column gathers, and complete BLAKE3 Merkle trees/paths. Merkle
  parent nodes preserve the protocol's exact `blake3(left || right)`
  semantics (not BLAKE3's internal parent-compression flag), and Fp2 mask
  leaves support partial final hash blocks. `ResidentProverMatrix` is a
  separate internal type owning weight/pad/encoding/tree handles; public
  `Commitment`, `MultiOpenProof`, verifier and CPU/hybrid entry points are
  unchanged. During an opening, D2H is restricted to the mask root,
  u-vectors, queried data/mask columns and sibling paths already present in
  the proof format.

  On A100 `3mq19up4`, the primitive differential covers padded message rows,
  Fp/Fp2 NTT, combined rows, mask addition, gathers, every sibling path and
  roots, including a 48-byte Fp2 leaf with a partial BLAKE3 block. The PCS
  integration test passes CPU, hybrid and resident paths with
  `VOLTA_REQUIRE_CUDA=1`: commitment roots and full proof objects are equal,
  correlation counters/transcript ledgers match, the verifier accepts, a
  faulted queried column is rejected, and a repeated resident opening leaves
  live device bytes unchanged. All 11 CPU PCS tests also pass. This closes
  the PCS kernel family (mask rows, row combinations, NTT, gather and Merkle)
  for a host-fed checkpoint. Deterministic mask rows are still generated on
  the host before one upload, and weights/pads enter `commit_resident` from
  host slices; both are explicitly outside the final no-host-witness claim.

- **2026-07-12 (`P7-integrated-resident` LogUp family device path landed;
  host-witness upload still open)**: ABI v5 adds the degree-3 aux-leaf path.
  Aux columns and per-claim equality rows are packed once into resident
  buffers; equality rows are generated on device from the small transcript
  points, and q/column/eq folds remain device-to-device. Each aux round
  returns exactly `[g(0), g(2), g(3)]`; the only final D2H values are q
  splits and the two consolidated claims per aux column, all required by the
  existing protocol. Table/upper-tree behavior from the prior checkpoint is
  unchanged. The GPU uses uniform Fp2 leaf vectors while Rust preserves the
  original specialized theoretical E-mult counters exactly; transcript,
  proof format and verifier are unchanged.

  CUDA 13.0/sm_80 tests on A100 `3mq19up4` pass with
  `VOLTA_REQUIRE_CUDA=1`: all 11 `volta-accel` tests plus the blind-tree
  CPU/hybrid/resident differential. The aux differential now includes a
  non-empty, correctly opened external claim (therefore exercises batched
  eq-row generation and weighted aux accumulation), and repeats both table
  and aux trees on the same resident context. Proof objects, products,
  zero rows, counters, correlation consumption and transcript ledger equal
  CPU byte-for-byte; live device bytes are stable across reuse. This closes
  the progressively integrated LogUp kernel family, including aux leaves,
  rounds/folds and blind corrections. It is still **not** the resident e2e
  gate: `LeafQ`/aux columns originate as host vectors in the current prover
  entry point and are uploaded once. The device-witness entry point must
  supply those handles directly before paper measurement.

- **2026-07-12 (`P7-integrated-resident` LogUp core checkpoint; aux leaf
  still open)**: ABI v4 keeps the complete fraction tree, upper-layer round
  vectors, folds and suffix-equality tables in context-owned device buffers.
  Even/odd child separation and suffix tables are constructed by device
  kernels from the resident tree and the small transcript challenges; Rust
  receives only the two roots, four round accumulators and four final split
  claims required by the protocol. The table-side/non-aux leaf is
  materialized as resident Fp2 `(p,q)` from base-field leaves and uses the
  same device round/fold engine. The specialized CPU E-mult accounting is
  preserved exactly even though the GPU uses a uniform representation.

  On A100 `3mq19up4`, the targeted `volta-accel` residency test and
  `cuda_blind_tree_and_aux_proofs_match_cpu_byte_for_byte` pass with
  `VOLTA_REQUIRE_CUDA=1`: roots, proof, correlation products/zeros, counters
  and transcript ledger equal CPU. The aux case in that differential still
  executes its degree-3 leaf round and column/eq folds on the host; the test
  already exercises resident tree and upper layers around it. Consequently
  this is a progressive-kernel checkpoint, **not** the completed LogUp
  family and not a resident e2e gate. Next is the aux-leaf/column fold with
  only its three transcript evaluations and final column claims crossing
  D2H.

- **2026-07-12 (`P7-integrated-resident` ABI-v3 substrate landed; gate still
  open)**: the staged ABI could not preserve a value across calls because its
  16 workspace slots are freely resized and every primitive performs its own
  H2D/D2H. ABI v3 therefore adds context-owned opaque resident allocations,
  typed non-cloneable Rust handles, explicit alloc/upload/download/free
  boundaries, runtime cross-context rejection, and device-to-device GEMM plus
  fused requant/MAC-correction entry points. The API is shape-parametric and
  internal; it introduces no `ModelConfig`, public stable API or GPT-2
  constants. Persistent allocations are separate from reusable staged
  workspace and remain counted in live/peak device memory. Explicit resident
  transfers are timed and counted; resident kernels add no H2D/D2H bytes.

  The isolated A100 checkout on `3mq19up4` built the CUDA 13.0/sm_80 shared
  object and passed all 10 `volta-accel` tests with
  `VOLTA_REQUIRE_CUDA=1`. New gates cover non-zero buffer offsets,
  bit-exact i64 GEMM and fused outputs/corrections, measurement closure,
  zero kernel-time transfers, deterministic context reuse, live-byte return
  to zero after explicit frees, and rejection of a handle by a foreign CUDA
  context. CPU-only and `--features cuda` workspace checks compile locally.
  This is deliberately **not** a `P7-integrated-resident` result: forward and
  proving do not consume these handles yet, and no rho is recorded. Next
  checkpoints must keep LogUp/PCS/witness intermediates resident and expose
  only protocol messages to Rust.

- **2026-07-12 (same-host corrected native GPU anchor landed)**: clean
  schema-v2 run
  `benchmarks/results/p7-gpu-native-inference-2026-07-12-faa7667.json` on
  `3mq19up4`, explicitly paired with
  `p7-integrated-hybrid-2026-07-12-706d067.json`. The corrected timer excludes
  cache-seeding prefill from decode and times exactly 50 append-only steps,
  including 20,103,000 bytes logits/error D2H and host argmax; weights remain
  resident and their 249,403,904-byte one-time upload is excluded. Seven
  prefill samples give **20.929 ms median, 0.389 ms MAD** (19.252--21.465 ms);
  seven decode50 samples give **770.045 ms median, 8.648 ms MAD**
  (726.182--785.886 ms). All outputs are deterministic, prefill argmax 835
  and all 50 tokens match the frozen golden sequence, with no fixed-point
  error. Same-host CPU/native GPU speedups are 53.542x prefill and 2.901x
  decode. Persistent device allocation is 258,181,700 bytes and peak process
  RSS is 732,692,480 bytes.

  Combining this denominator with the *hybrid* proof medians yields
  rho_proof,prefill **2008.584** and rho_proof,decode **28.537**; absolute
  inference+proof is 42.0595/22.7448 s. These numbers quantify why staged
  materialization is not the paper result; they do not decide the preregistered
  resident <=10/<=2 gates. The 2026-07-11 native JSON remains immutable with
  its older timer semantics and machine fingerprint; comparisons must name
  which anchor they use. Clean refreshed aggregate
  `benchmarks/results/p7-2026-07-12-a5d4fa5.json` pairs runs by cloud
  `instance_id`, reports hybrid target gaps 200.858x/14.268x, and recommends
  `proceed-to-device-resident-prover-integration`.

- **2026-07-12 (same-host native GPU anchor rerun — pre-registered harness
  correction)**: before quoting rho for `3mq19up4`, rerun the exact fixed-point
  native GPU anchor against the clean CPU-native samples embedded in
  `p7-integrated-hybrid-2026-07-12-706d067.json`. Audit found that the prior
  CUDA harness performed the documented untimed cache-seeding prefill and
  then called `decode50()`, which performed a second prefill *inside* the
  decode timer. Retain the 2026-07-11 JSON unchanged, but correct the harness
  so `decode50` consumes the argmax/cache produced by the untimed prefill and
  times exactly 50 append-only decode steps including logits D2H + host
  argmax. One warmup + 7 repetitions, frozen 50-token golden equality and
  determinism remain mandatory. Schema v2 must retain raw prefill/decode
  samples plus median/MAD/min/max, live/peak device allocation estimate and
  process peak RSS; the baseline path is explicit rather than selected by
  machine-global filename heuristics. This is measurement-only: no Rust
  witness, proof, transcript, PCS, correlation or communication change.

- **2026-07-12 (`P7-integrated-hybrid` full attribution gate complete)**:
  clean schema-v2 run
  `benchmarks/results/p7-integrated-hybrid-2026-07-12-706d067.json` on
  Thunder `3mq19up4` (A100-SXM4-80GB, Xeon Platinum 8352Y, 7.92-core quota,
  CUDA toolkit 13.0 / UMD 13.3), workload T=100+50 stacked decode and Q=200.
  One warmup plus three measured repetitions all verify and match the frozen
  50-token golden sequence. Proof-only prefill samples are
  31.3637/42.0386/43.4575 s (median **42.0386**, MAD 1.4190); response samples
  are 52.6792/64.0133/71.7773 s (median **64.0133**, MAD 7.7640); paired
  decode marginals are 21.3155/21.9747/28.3198 s (median **21.9747**, MAD
  0.6592). The same-host CPU ABBA medians are 1.1206 s prefill and 2.2337 s
  decode50, hence the JSON's CPU-relative rho is 37.514/9.838; this is not
  the resident paper rho. Against the previous same-SKU native GPU anchor
  only as a cross-instance diagnostic, proof/native would be about
  2380.0/34.67; a fresh same-host native anchor is required before quoting
  final ratios.

  The representative second accelerator session closes exactly:
  100.850131590 s = 6.868208756 H2D + 25.432895559 D2H + 0.109572774
  kernels + 68.439454501 CPU. Each repetition transfers 17,812,501,992 H2D
  and 5,560,199,968 D2H bytes and executes 8,763 explicitly counted
  host-barrier timing synchronizations; peak live device allocation is
  4,312,989,696 bytes and peak RSS is 8.637 GiB. This is the intended hybrid
  diagnosis: staged transfers and Rust/CPU residual dominate, not CUDA
  arithmetic. PCS commitment/open/verify medians are 24.236/9.365/0.365 s;
  response verification is 0.979 s. Flat-cost last/first is 1.363 <= 1.5,
  packed response download is 144,820,930 bytes, and correlation counts stay
  8,479,926 sub + 176,880 full. The hybrid gate changes no proof/transcript/
  verifier/communication semantics and is not the P7 go/no-go; next is the
  device-resident witness/proving gate (the same-host native denominator has
  now landed separately above).

- **2026-07-12 (`P7-integrated-hybrid-quick` repeated attribution gate
  complete)**: clean schema-v2 run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-f45b220.json`
  retains every raw repetition and reports upper median/MAD/min/max. Three
  measured response-proof samples are 9.3162/8.2017/8.8064 s (median
  **8.8064 s**, MAD 0.5098); prefill-proof samples are
  6.4059/5.8868/5.9967 s (median **5.9967 s**, MAD 0.1099), giving paired
  decode marginals 2.9103/2.3149/2.8097 s (median **2.8097 s**, MAD 0.1006).
  PCS commitment/open/verify medians are 24.995/8.905/0.401 s. Every proof,
  PCS opening and flat-cost session is accepted; correlation counts,
  transcript ledgers and communication are identical across seeds 64--66;
  flat last/first is 0.965 and the packed quick response is 82,281,642 bytes.
  Each accelerator session closes exactly. The representative third sample
  is 44.353781742 s = 6.600317999 H2D + 13.758055079 D2H + 0.103830098
  kernels + 23.891578566 CPU, with 7,791 counted host barriers and
  4,311,678,976 peak live device bytes. This closes the hybrid quick gate and
  unblocks the full T=100+50/Q=200 hybrid measurement; it is still not the
  resident paper result and its quick-shape rho must not be quoted.

- **2026-07-12 (`P7-integrated-hybrid-quick` whole-session attribution
  landed)**: clean run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-d0de22c.json`
  closes the accelerator measurement exactly: 98.721858941 s wall =
  25.086696863 s H2D + 46.569393394 s D2H + 1.293115331 s kernels +
  25.772653353 s CPU residual. The latter is explicitly split into 2.130 s
  local to staged operations and 23.643 s Rust work outside backend calls;
  the JSON declares its scope as `response-session-including-pcs-and-verifier`
  to prevent double counting with the separate verifier lines. The run is
  accepted, Q=200 communication is unchanged, flat last/first is 1.039, and
  peak live device allocation is 4,311,678,976 bytes. This satisfies the
  hybrid quick correctness/attribution purpose, not the paper e2e gate.
  Same-host D2H phase time changed from 21.985 s in the immediately preceding
  clean quick to 46.569 s here (H2D 6.655 -> 25.087 s), while bytes and calls
  were identical. Therefore a single full sample would be non-publishable:
  add per-repetition raw times plus median/dispersion before running the full
  T=100+50 hybrid workload. Quick-shape rho remains explicitly non-record.

- **2026-07-12 (`P7-integrated-hybrid-quick` ABI-v2 phase timing landed;
  whole-session residual open)**: clean rerun
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-8f0eb17.json`
  is accepted with flat-cost 0.765 and the same Q=200 proof/communication
  accounting. A minimal same-host probe showed that Thunder's CUDA runtime
  returns `cudaSuccess` from `cudaEventElapsedTime` without writing its
  output. ABI v2 now detects that condition instead of emitting zero and
  declares `timing_method: host-barrier-wall`: each H2D, kernel and D2H phase
  is closed with an explicitly counted stream barrier. The witness reports
  69.4 ms H2D + 18.7 ms kernels + 404.8 ms D2H + 145.2 ms operation-local
  CPU across 336 GEMMs and 1,008 barriers. The staged proving/PCS session
  reports 6.655 s H2D + 0.331 s kernels + 21.985 s D2H + 2.177 s
  operation-local CPU, 7,791 barriers, 17.763/5.538 GB H2D/D2H and 4.312 GB
  peak live device bytes. The extra barriers are part of this hybrid
  attribution run and make it incomparable to a CUDA-event machine unless
  the timing method is shown. **Remaining accounting blocker**: those phase
  totals cover 31.147 s, while sequential proof + PCS commit/open/verify +
  response verify lines total about 54.171 s; Rust protocol/PCS work outside
  backend calls is not yet represented in `cpu_residual_s`. Add the complete
  begin/finish measurement wall and an unattributed-host closure, rerun quick,
  then permit the full hybrid workload. Quick rho remains non-paper evidence.

- **2026-07-12 (`P7-integrated-hybrid-quick` correctness landed;
  attribution timing blocked)**: clean-tree run
  `benchmarks/results/p7-integrated-hybrid-quick-2026-07-12-54822a7.json`
  on Thunder `3mq19up4` (A100-SXM4-80GB, Xeon Platinum 8352Y, 7.92-core
  quota, CUDA toolkit 13.0 / UMD 13.3) is accepted at T=16+8 and Q=200;
  the two-chunk flat-cost curve is 1.030 <= 1.5, all 13 PCS openings verify,
  and the full `VOLTA_REQUIRE_CUDA=1` workspace suite passed beforehand,
  including bit-exact non-power-of-two/padding/aux/mask-row differentials,
  same-seed full-proof accounting, persistent-context reuse, CUDA-derived
  fault rejection, golden decode and KV anti-replay. Online proof timing is
  10.430 s prefill and 13.746 s response; PCS is reported separately at
  40.395 s commitment, 18.510 s opening and 0.395 s verification. The
  proving measurement counts 17,763,091,112 H2D bytes, 5,538,170,272 D2H
  bytes, 2,597 synchronizations (33.2 ms), 8.402 s CPU residual and
  4,311,678,976 peak live device bytes. **Instrumentation blocker**: all
  CUDA kernel, H2D and D2H time fields are zero because the integrated ABI
  currently reports counts/bytes but does not time those operations. The
  immutable JSON is therefore a correctness/accounting artifact only; do
  not quote its quick-shape rho or relabel it as e2e attribution. No full
  hybrid run is allowed until event/wall timing lands and a second clean
  quick run demonstrates nonzero, internally consistent attribution.

- **2026-07-11 (`P7-integrated-resident` — pre-registered)**: after the
  hybrid attribution gate, add a CUDA-resident path in which fixed-point
  forward, witness construction and proving share persistent device buffers;
  the complete `ModelWitness` must not be materialized on the host. Rust keeps
  transcript/challenge orchestration and transfers only protocol messages.
  Run the paper workload (GPT-2 small, prompt 100 + 50 stacked decode, Q=200)
  with one warmup and repeated timed samples on the A100 machine of record.
  Report native GPU inference, proof-only prefill, proof-only decode marginal,
  inference+proving, PCS commitment/opening, PCG setup/expansion and verifier
  separately. Hard gates: golden prefill/decode bit-exact; same-seed proof
  bytes, transcript/accounting counters and verifier result equal to CPU;
  fault-injected device output is rejected; decode last/first <=1.5; packed
  response <=150--200 MB; rho_proof,prefill <=10 and rho_proof,decode <=2.
  Every JSON records per-repetition times and dispersion, CPU residual,
  H2D/D2H, synchronization, peak RSS/device memory, full byte breakdown,
  hardware/software fingerprint, commit and dirty state. This gate, not the
  standalone spikes or the hybrid gate, determines the P7 GPU go/no-go.

- **2026-07-11 (`P7-integrated-hybrid` — pre-registered)**: introduce an
  internal optional CUDA backend while leaving CPU as the default. CUDA is
  feature-gated, owns persistent context/stream/buffers/workspace, accepts
  runtime shapes, and returns an explicit unavailable error when requested;
  there is no silent CPU fallback. Preserve the existing CPU APIs as wrappers
  around backend-explicit entry points. Integrate, in order, fused GEMM /
  requant / MAC corrections; LogUp tree, aux leaves, rounds/folds and blind
  corrections; PCS mask rows, row combinations, NTT, gather and Merkle. The
  first gate may upload an existing host `ModelWitness`, but timing must include
  all upload/download, synchronization and CPU-residual work. Hard correctness
  gate: on identical inputs/seeds, CPU and CUDA produce identical outputs,
  correlation counts/allocation digest, transcript accounting, proof bytes and
  verifier outcome, including padding, non-power-of-two domains, aux leaves and
  mask rows. Repeated-context and injected-fault tests must detect correlation
  reuse/state leakage and verifier rejection. This is an attribution and
  integration gate only; it is not an e2e rho result for the paper.

- **2026-07-11 (P7 prefill objective revised)**: the general GPU objective is
  now **ρ_prefill ≤ 10**, while **ρ_decode ≤ 2** is unchanged. On the
  `6mprfo7p` baseline this gives a **176.631 ms proof-only prefill budget**,
  required relative prover/native speedups **2.05125× prefill / 4.14684×
  decode**, and required integrated prover GPU/CPU speedups **115.616× /
  11.3141×**. `scripts/report.py` is the source of current targets. Existing
  JSONs and preregistered microkernel gates (including 5.48× screens) remain
  historical screening evidence; they are neither lowered nor reinterpreted
  as relative prover/native or e2e speedups.

- **2026-07-11 (P7 native fixed-point GPU inference anchor landed)**: clean
  exact run `benchmarks/results/p7-gpu-native-inference-2026-07-11-c06f323.json`
  on Thunder `6mprfo7p`. With the 238 MB quantized weights and all LUTs
  resident, the standalone sm_80 path executes the full 12-layer frozen
  semantics: embedding/LN/QKV/causal softmax/AV/projections/FFN/seams/final
  LN/logits for prefill and true append-only K/V decode. Prefill argmax and
  all 50 generated tokens match the accepted P6 golden sequence in every
  repetition; no fixed-point saturation/domain error occurred. Median of 7:
  prefill **17.663 ms**, 56.364x versus same-box CPU 0.99556 s; decode50
  **633.895 ms**, 2.728x versus CPU 1.72949 s. Decode timing includes a
  402,056-byte logits D2H and host argmax per token; one-time weights upload
  is excluded as preregistered. Combining those native accelerations with
  the same-box relative requirements 4.1025x/4.1468x means the integrated
  GPU prover must achieve **231.23x prefill / 11.31x decode speedup versus
  its CPU proving times**. Existing microkernel speedups cannot be divided
  into these numbers to claim rho; an integrated proving measurement is now
  the decision-critical next step. No Rust witness, protocol, proof, PCS,
  transcript, correlation or communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-18c3fea.json`
  (`git_dirty:false`, recommendation
  `proceed-to-integrated-gpu-prover-measurement`).

- **2026-07-11 (P7 native fixed-point GPU inference anchor —
  pre-registered)**: implement a standalone sm_80 CUDA anchor over the exact
  frozen `gpt2s-q.bin` semantics, not a GEMM-only or FP16 proxy. Prefill must
  execute embedding, both layer norms, biased QKV, causal score/row-max/exp/
  reciprocal/softmax, AV, attention projection + residual, FFN up + GELU,
  FFN down + residual, seams, final LN and tied-WTE logits for T=100 across
  all 12 layers. Decode must seed all 12 K/V caches from that prefill and run
  50 true incremental steps at positions 100..149, including logits D2H and
  host argmax before the next token. Arithmetic is exact i16*i16->i64 with
  the frozen chained round-half-up requant and LUT tables; weights/LUTs stay
  device-resident and their one-time upload is outside timing. Time one
  warmup + 7 GPU prefill and decode repetitions, median wall time with a
  completion/logits D2H barrier; reset cache via an untimed prefill before
  each decode repetition. Hard gates: prefill argmax and all 50 generated
  tokens match `golden-p6.bin`, repeated runs are deterministic, timing is
  sane, and no saturation/assertion is hidden. Report absolute prefill/decode
  time and acceleration versus the clean same-box P6 native baselines
  0.995562859/1.729492698 s. This anchor changes neither the Rust witness nor
  the proving path and makes no GPU-rho claim by itself; final rho still
  requires integrated proving timings. No protocol, proof, PCS, transcript,
  correlation or communication change.

- **2026-07-11 (P7 replacement-instance P6 baseline landed)**: clean full
  run `benchmarks/results/p6-2026-07-11-f72e4dd.json` on Thunder
  `6mprfo7p` (A100-SXM4-80GB, Xeon Platinum 8470, 7.92-core quota) is
  accepted, golden decode exact, and preserves the 144,820,930-byte packed
  response. ABBA native prefill is 0.9956 s and native 50-token decode is
  1.7295 s (28.91 tok/s). Proving prefill is 20.4215 s; full response
  34.7653 s with decode marginal 14.3439 s, hence CPU rho prefill **20.512**
  and decode **8.294**. The replacement-instance relative prover/native
  acceleration requirements are therefore **4.1025x prefill** for rho<=5
  and **4.1468x decode** for rho<=2. Verify 0.710 s; PCS commit/open/verify
  5.920/1.164/0.204 s; flat-cost last/first 1.249 <=1.5 and anti-replay
  gates remain accepted; peak RSS 3.53 GiB. These requirements supersede
  5.48x/3.97x only on `6mprfo7p`; older-instance measurements remain
  historical and must retain their own denominators. This is still a CPU
  fixed-point baseline, not the native GPU inference anchor.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-0ea449a.json`
  (`git_dirty:false`, recommendation
  `proceed-to-proving-path-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU blind LogUp general-layer plumbing landed)**: clean
  pinned-barrier run of record
  `benchmarks/results/p7-gpu-logup-blind-rounds-2026-07-11-534dcad.json`
  on replacement Thunder instance `6mprfo7p` (A100-SXM4-80GB, Xeon Platinum
  8470, CUDA toolkit 13.2 / UMD 13.3). At N=2^22, every accumulator, folded
  element and all **848 bytes** of root/22-round/split/product corrections
  match the 7-thread CPU reference, with the existing 22 round barriers and
  zero extra transcript rounds. Median CPU blind 265.26 ms vs GPU blind
  **41.30 ms = 6.423x**, passing >=5.48; paired clear 45.71 ms gives
  blind/clear 0.903, treated only as overhead <=1.05 (not as a claimed
  acceleration). Reusable pinned 64-byte destinations were load-bearing on
  Thunder; the pre-fix failures remain recorded below. The quick N=2^16 run
  was correct but launch dominated at 1.55x and is retained. Scope excludes
  aux-leaf/column corrections and Rust proving-path integration. Because the
  CPU model changed, this spike passed the fixed preregistered screen before
  the replacement P6 denominator landed; the subsequent baseline above gives
  4.10x/4.15x requirements, which it also passes. No protocol or
  communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-e4e0772.json`
  (`git_dirty:false`, recommendation
  `proceed-to-proving-path-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU blind LogUp plumbing — first full runs failed;
  pinned-barrier follow-up authorized)**: all blind root/round/split/product
  corrections (848 bytes), every round accumulator and every folded element
  were exact, with zero extra transcript rounds, but the preregistered
  performance gates did not pass. On Thunder `nc1k4a0g`, the first driver
  used four separate 16-byte final split copies and reported CPU 383.75 ms,
  GPU blind 133.76 ms = 2.87x and blind/clear 1.077; the unchanged clear
  control on the same commit later ran at 44.56 ms = 8.92x, identifying the
  micro-copy path as invalid for a single 64-byte split message. After packing
  that message, a clean run on replacement instance `6mprfo7p` (same A100,
  Xeon Platinum 8470, CUDA toolkit 13.2 / UMD 13.3) reported CPU blind
  258.70 ms, GPU blind 54.60 ms = **4.738x**, blind/clear **1.098**: both
  >=5.48x and <=1.05x gates still fail. The unchanged clear control there was
  CPU 259.83 ms, GPU 58.29 ms = 4.457x. Thus the new CPU is materially faster
  while GPU absolute latency is comparable; the old instance's 5.48x
  sensitivity is not a portable rho denominator, but the fixed preregistered
  gate is still recorded as failed. Preserve all diagnostic JSONs. One
  implementation follow-up is authorized before stopping this lever: replace
  pageable stack destinations for the 22 round messages plus one split
  message with reusable CUDA pinned-host buffers, then rerun the same quick/
  full protocol and unchanged gates. This changes no arithmetic, mask,
  correction, message, challenge, proof byte or transcript round. A final rho
  claim on `6mprfo7p` still requires a fresh native P6 baseline on that box.

- **2026-07-11 (P7 GPU blind LogUp correction plumbing — pre-registered)**:
  extend the already-passed `N=2^22` general-round spike without changing its
  arithmetic or challenge order. Keep the 64-byte device-to-host barrier at
  every one of the 22 rounds. Immediately after each round message reaches
  the host, subtract two pre-expanded one-time F_p^2 masks, account the
  resulting 32 correction bytes, and only then consume the next independent
  verifier challenge. Also generate the layer's two root, four split and
  three product corrections around the same sequence, for **848 bytes total**
  (`32 + 22*32 + 64 + 48`), exactly the current Rust transcript layout.
  Compare every root/round/split/product correction and every folded element
  against an independent 7-thread CPU implementation outside timing. Use one
  warmup + 7 GPU and 3 CPU repetitions. Hard gates: correctness, timing
  sanity, blind whole-sequence GPU/CPU speedup >=5.48x, and paired blind/clear
  GPU overhead <=1.05x. Resident masks are charged to the separate PCG budget;
  no correction-only GPU kernel or extra transcript round is allowed. Scope
  is one general fraction-tree layer: aux-leaf/column corrections and the
  Rust proving-path FFI remain follow-ups. No proof bytes, challenge order,
  domains, PCS, Q/rate, communication formula or protocol change.

- **2026-07-11 (P7 GPU PCS column gather + BLAKE3/Merkle landed)**:
  clean run of record
  `benchmarks/results/p7-gpu-blake3-merkle-2026-07-11-3b0a916.json` on
  Thunder `nc1k4a0g`, exact `P4_LAYER` geometry (1024 rows x 32768 encoded
  columns, 8192-byte leaves, 256 MiB resident row-major matrix). The fused
  gather + unkeyed BLAKE3 leaf pass and full 2^15-leaf Merkle tree match the
  optimized Rust `blake3` root; the independent host implementation also
  matches every leaf and internal node. Median Rust/Rayon reference 43.779 ms
  vs GPU **1.407 ms = 31.10x**, passing the <=75 ms absolute gate. Together
  with the measured 6.386 ms NTT, the measured GPU NTT + hash path is
  **7.793 ms** (71.44x versus the corresponding 556.71 ms CPU components).
  The quick 32x1024 case was also correct and passed at 0.541 ms, retained as
  `p7-gpu-blake3-merkle-quick-2026-07-11-3b0a916.json`. Scope still excludes
  mask-row hashing, selected-column serialization and proving-path
  integration; no hash, root, PCS layout, proof bytes, Q/rate, transcript or
  protocol change. Next: blind correction plumbing, native GPU inference
  anchor and integrated e2e gates.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-b971a93.json`
  (`git_dirty:false`, recommendation
  `proceed-to-blind-integration-and-native-gpu-anchor`).

- **2026-07-11 (P7 GPU PCS column gather + blake3/Merkle — pre-registered)**:
  at `P4_LAYER` geometry, hash all 32768 encoded columns of 1024 Goldilocks
  values directly from the resident row-major matrix (gather fused into the
  BLAKE3 leaf kernel), then build the full 2^15-leaf Merkle tree on GPU. Use
  exact unkeyed BLAKE3 flags/tree semantics and cross-check the final root
  against the optimized Rust `blake3` crate; additionally compare every leaf
  and internal hash against an independent host implementation outside the
  timed region. Time 1 warmup + 7 GPU runs with a forced 32-byte root D2H;
  time the actual Rayon/Rust gather+blake3+Merkle reference for 3 runs.
  Because scalar host code is not a fair denominator, the hard performance
  gate is absolute: GPU gather+hash+tree <=75 ms. Together with the measured
  6.39 ms NTT this keeps the P4 layer commitment below 81.4 ms, i.e. >=5.5x
  versus the ~0.45 s cloud CPU commitment. Correctness and timing sanity are
  hard gates. This does not change the hash, commitment root, PCS layout,
  proof bytes, Q/rate, transcript or protocol; mask-row hashing and selected
  column serialization remain integration work.

- **2026-07-11 (P7 GPU PCS row/global arithmetic landed)**: clean run of
  record `benchmarks/results/p7-gpu-pcs-arithmetic-2026-07-11-366ec4a.json`
  on Thunder `nc1k4a0g`, exact `P4_LAYER` geometry. Batched 1024x32768
  Goldilocks NTT (bit reversal + 15 stages, 251.7 M butterflies) matches every
  symbol: CPU 0.51293 s vs GPU 0.006386 s = **80.33x**. `combine_rows` data
  block over 1024x16384 weights matches u_q/u_c exactly: CPU 0.14593 s vs
  GPU 0.001918 s = **76.10x**. Both independently pass >=5.48. Quick small
  geometry was correct but launch dominated and failed, retained as
  `p7-gpu-pcs-arithmetic-quick-2026-07-11-366ec4a.json`. Scope excludes pad
  tail, mask rows, column gather, blake3/Merkle and proving integration; no
  parameter, proof-size or protocol change. Next authorized spike is
  blake3/Merkle plus representative column gathering.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-1b99864.json`
  (`git_dirty:false`, recommendation `proceed-to-blake3-merkle-spike`).

- **2026-07-11 (P7 GPU PCS row/global arithmetic — pre-registered)**:
  implement two exact sm_80 spikes at `P4_LAYER` geometry. (A) Batched
  Goldilocks forward NTT for 1024 rows x 2^15 code symbols, including
  bit-reversal and all 15 butterfly stages with the same root/twiddles as
  `NttPlan`; immutable resident messages are zero-padded at msg_len=16896.
  (B) `combine_rows` data block for 1024x16384 base-field weights, producing
  both u_q and u_c via F_p² x F_p operations. Use 1 warmup + 7 GPU and 3
  7-thread CPU repetitions, forced small D2H completion barriers, and compare
  every output limb bit-for-bit. Hard gates for **each** pass: correctness,
  timing sanity, GPU/CPU speedup >=5.48x. Report bytes, operation counts and
  checksums. This excludes pad-tail addition, fresh mask-row encoding, column
  gather and blake3/Merkle; those remain explicit PCS follow-ups. No PCS
  shape, rate, Q, opening bytes, transcript or protocol change.

- **2026-07-11 (P7 GPU LogUp general rounds/folds landed)**: clean run of
  record `benchmarks/results/p7-gpu-logup-rounds-2026-07-11-e4470bf.json`
  on Thunder `nc1k4a0g`, N=2^22, 22 transcript-ordered rounds, reports every
  round accumulator and every folded element bit-exact. Median CPU 0.38660 s
  vs GPU 0.05714 s = **6.766x >=5.48 PASS**, but only 1.23x headroom over the
  stricter prefill requirement; treat this as a live risk, not a wide pass.
  Quick N=2^16 was correct but round/launch dominated at 1.409x and is kept
  as `p7-gpu-logup-rounds-quick-2026-07-11-e4470bf.json`. The result includes
  a 64-byte D2H message barrier before every challenge/fold and therefore
  does not elide interaction. Blind correction generation and proving-path
  integration remain open; no transcript or proof-byte change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-fd67e64.json`
  (`git_dirty:false`, recommendation `proceed-to-pcs-hash-spikes`).

- **2026-07-11 (P7 GPU LogUp general round/fold — pre-registered)**:
  implement the exact P4 `run_general_rounds` hot loop over four F_p²
  vectors at representative N=2^22: per pair compute the four Gruen round
  accumulators (10 F_p² multiplications), reduce them, force a 64-byte D2H
  round-message barrier, then fold p0/p1/q0/q1 by the deterministic challenge
  (4 F_p² multiplications/pair) and continue to length one. The per-round
  barrier is load-bearing and models the actual transcript challenge order;
  it may not be fused away across rounds. Use 1 warmup + 7 GPU repetitions
  and 3 same-host CPU repetitions. Outside timing, compare every round
  accumulator and every folded element at every depth bit-for-bit. Hard
  gates: correctness, timing sanity, whole-sequence GPU/CPU speedup >=5.48x.
  This clear arithmetic spike excludes blind correction generation and does
  not integrate the Rust proving path; those remain explicit follow-up work.
  No transcript, challenge order, proof bytes, lookup count or protocol change.

- **2026-07-11 (P7 GPU LogUp lookup-tree build landed)**: clean run of
  record `benchmarks/results/p7-gpu-logup-tree-2026-07-11-5f7b443.json`
  on Thunder `nc1k4a0g`, N=2^24, exact P4 structured first combine and all
  general F_p² levels. Every p/q element at every level matches the CPU
  reference; checksum `0x0350749ee82bd237`. Median CPU 0.18934 s vs GPU
  0.002864 s = **66.12x >=5.48 PASS**. The valid quick run at N=2^18
  (`p7-gpu-logup-tree-quick-2026-07-11-5f7b443.json`) was launch-dominated
  and intentionally failed performance at 2.19x while retaining exact
  correctness; this confirms batching at P6 scale is load-bearing. Scope is
  tree build only: sumcheck evaluation/folds, blind correction plumbing and
  proving-path integration remain open. No protocol or communication change.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-959b40b.json`
  (`git_dirty:false`, recommendation `proceed-to-logup-rounds-and-pcs-spikes`).

- **2026-07-11 (P7 GPU LogUp fraction-tree build — pre-registered)**:
  implement the exact dominant lookup-side (`LeafP::Ones`) P4 tree build at
  N=2^24: structured base-field first combine from `LeafQ {a, alpha1}`, then
  every general `(p1*q2+p2*q1, q1*q2)` F_p² level through the root. Inputs
  and all intermediate layers remain GPU-resident during timing; one forced
  32-byte root D2H read is the completion barrier. Use 1 warmup + 7 GPU
  repetitions and 3 CPU repetitions on the same 7-thread quota. Outside the
  timed region, compare **every p/q element at every level** against the CPU
  Goldilocks reference and record root/checksum/counts. Hard gates:
  correctness, sane timing, GPU/CPU tree-build speedup >=5.48x (the stricter
  cloud prefill requirement). This covers tree construction only; LogUp
  sumcheck round-evaluation/fold kernels, blind corrections and proving-path
  integration remain separate open work and must not be implied by a pass.
  No transcript, lookup, soundness, correlation or communication change.

- **2026-07-11 (P7 GPU fused GEMM-MAC epilogue landed)**: clean run of
  record `benchmarks/results/p7-gpu-fused-epilogue-2026-07-11-bde5d7d.json`
  on Thunder `nc1k4a0g`, sm_80, resident pre-expanded PCG masks. Full
  i16xi16->i64 GEMM, frozen requant and same-kernel `delta=x-r` corrections
  match the CPU reference for every output. ABBA medians: shape
  100x768x768 native/fused 0.392/0.396 ms (`rho=1.009`), x2304
  0.517/0.515 ms (`rho=0.996`), x3072 0.579/0.569 ms (`rho=0.983`);
  weighted **`rho_kernel=1.003` <=1.30 PASS**. Corrections remain exactly
  8 bytes/output and there is no correction-only kernel. Valid quick:
  `p7-gpu-fused-epilogue-quick-2026-07-11-bde5d7d.json`. This remains a
  P1-equivalent standalone spike: the Rust proving path is unchanged, PCG
  expansion/setup stays separately budgeted, and e2e GPU rho is still open.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-27cc9a8.json`
  (`git_dirty:false`, recommendation `proceed-to-logup-pcs-kernel-spikes`).
  Next authorized spike is a representative LogUp fraction tree.

- **2026-07-11 (P7 GPU fused GEMM-MAC epilogue — pre-registered)**:
  implement a measurement-only sm_80 CUDA kernel for the three P1 GPT-2
  shapes (100x768x{768,2304,3072}), with exact i16xi16->i64 accumulation and
  frozen round-half-up/clamp requantization. Compare one native kernel
  (requantized i16 output) against the identical GEMM with a **same-kernel**
  fused epilogue that reads a resident F_p mask and writes the 8-byte
  correction `delta=x-r`; no correction-only follow-up pass is allowed.
  Resident masks model the already separate PCG pool/setup budget and do not
  hide any response bytes. Use 2 paired warmups + 9 ABBA rounds, a forced
  16-byte D2H completion read per launch (Thunder trap above), and report
  medians plus weighted `rho_kernel`. Validate every native/fused i16 output
  and every reconstructed field value bit-for-bit against a same-host CPU
  reference. Hard gates: correctness; fused/native weighted rho <=1.30; no
  output/correction layout or count change. This spike does not yet replace
  Rust inference/proving code and cannot by itself establish e2e GPU rho.

- **2026-07-11 (P7 A100 Goldilocks/F_p² roofline landed)**: run of record
  `benchmarks/results/p7-gpu-roofline-2026-07-11-a43d105.json` on replacement
  Thunder instance `nc1k4a0g` (same A100-SXM4-80GB / CPU quota as the
  pre-registered box), clean tree, sm_80, reports full bit-for-bit CPU/GPU
  agreement and timing sanity. Stream 2^24: CPU 0.10688 s, GPU 0.001926 s,
  **55.48x**, 418.0 GB/s and 8.71 G F_p²-mul/s. Dependent chain
  2^20 x 256: CPU 1.9617 s, GPU 0.006518 s, **300.94x** and 41.18 G
  F_p²-mul/s. The raw arithmetic screening gate passes by wide margin over
  5.48x/3.97x, but this is not an e2e go decision. Thunder trap: CUDA events
  and `cudaDeviceSynchronize` returned before provider-observable completion,
  producing an invalid early quick diagnostic
  `p7-gpu-roofline-quick-2026-07-11-5ead965.json` (0 s / impossible
  5.2 TB/s). Timings of record therefore force a 16-byte D2H read after every
  kernel and reject stream bandwidth above 2.5 TB/s; valid quick
  `p7-gpu-roofline-quick-2026-07-11-a43d105.json` passed before the full run.
  Clean refreshed aggregate: `benchmarks/results/p7-2026-07-11-14bafb8.json`
  (`git_dirty:false`, recommendation `proceed-to-fused-kernel-spikes`).
  Next authorized spike is the fused GEMM-MAC epilogue; no proving-path or
  protocol change has landed yet.

- **2026-07-11 (P7 GPU Goldilocks/F_p² roofline — pre-registered)**:
  add a standalone CUDA 13 / sm_80 microbenchmark plus a Python JSON
  harness; this is measurement-only and does not enter the proving path.
  Two resident-data kernels mirror `volta-field` exactly: (1) an F_p²
  stream multiply over 2^24 elements (5 base-field multiplications per
  output) to expose the memory/integer-pipeline roofline; (2) a dependent
  chain over 2^20 elements with 256 F_p² multiply-add rounds to expose
  compute throughput. Use 1 warmup + 7 GPU repetitions and 3 same-host CPU
  repetitions, median timing; compile explicitly for `sm_80`; validate every
  output limb bit-for-bit against the CPU Goldilocks reference and report a
  deterministic checksum. JSON must carry the cloud fingerprint, clean-tree
  status, CUDA/device properties, absolute throughput/bandwidth and same-code
  GPU/CPU speedups. Correctness is a hard gate. Performance is a screening
  gate: raw stream and chain speedups must show plausible headroom against
  the measured 5.48x prefill / 3.97x decode requirements before building the
  fused proving kernels; passing it is not itself an end-to-end go decision.
  No protocol, transcript, Q, PCS, correlation, or communication change.

- **2026-07-11 (P7 cloud A100 P6 CPU baseline + sensitivity landed)**:
  clean ABBA run `benchmarks/results/p6-2026-07-11-11e5630.json`
  (`git_dirty:false`, accepted, golden decode true, 7 rayon threads) reports
  native prefill 1.164 s and native decode 2.544 s / 50 tokens; proving
  prefill 31.878 s and response 52.060 s, hence `rho_prefill=27.38` and
  `rho_decode=7.93`; verify 1.056 s; flat-cost last/first 0.970 <=1.5;
  PCS open 1.762 s and verify 0.325 s; peak RSS 3.56 GiB. Communication is
  invariant at 144,820,930 packed response bytes. Post-run inspection found
  no competing process or OOM and only 11.3 s cumulative cgroup throttling
  across 3,221 s CPU usage, so the slower CPU result is retained rather than
  discarded as load contamination. Aggregate
  `benchmarks/results/p7-2026-07-11-11e5630.json` updates the required
  relative prover-vs-native GPU speedup to **5.48x prefill / 3.97x decode**
  for this instance. These values supersede the 3.67x/2.60x local-VM
  sensitivity when judging this A100 box; the old values remain historical,
  not portable gates.

- **2026-07-11 (P7 cloud A100 P1 CPU baseline landed)**: clean run
  `benchmarks/results/p1-2026-07-11-64a8ead.json` on the pre-registered
  Thunder A100 instance (`git_dirty:false`, linux x86_64, 7 worker threads
  visible under the 7.92-core quota). ABBA P1 result: weighted fused-MAC
  `rho_kernel=1.043`; native throughput 29.9--34.9 GMAC/s across the GPT-2
  shapes; epilogue 1.6--2.0 ns/output; verifier fused scan 66.4 ms per 2^20
  values (63.3 ns/value, 0.715 s prefill-100 extrapolation). This is the
  required cloud-host CPU anchor; the A100 was idle and no GPU acceleration
  is claimed by this run.

- **2026-07-11 (P7 cloud A100 baseline — pre-registered before measured
  runs)**: target instance is Thunder Compute `bdthpmts`, provider region
  not exposed by the instance-list API, base template / Ubuntu 22.04.5,
  NVIDIA A100-SXM4-80GB (Thunder `A100XL`), driver 610.43.02, CUDA UMD
  13.3, Intel Xeon Platinum 8352Y with 792000/100000 cgroup CPU quota
  (`nproc=8`), 64 GiB RAM and 100 GB primary disk. Before any quoted rho:
  full workspace tests must pass; P1 and P6 must run from a clean tracked
  tree; P6 native prefill/decode denominators use ABBA paired timing; every
  cloud JSON carries this fingerprint. GPU spike order remains Goldilocks/
  F_p2 roofline, fused GEMM-MAC epilogue, LogUp fraction trees, then PCS
  row/global passes plus blake3. Go/no-go gates remain relative
  prover-vs-native GPU speedup >=3.67x prefill and >=2.60x decode, with
  golden decode, flat-cost <=1.5 and anti-replay unchanged. This entry does
  not change protocol, soundness parameters, Q=200, or communication.

- **2026-07-07 (P7 real-PCG phase B — measurement CORRECTED; supersedes the
  1.602 s entry below)**: review found two defects in the landed phase B.
  (1) **Accounting error**: the phase-B path derived the noise leaves
  directly from the setup digest, silently dropping the GGM PPRF leaf
  expansion — the dominant cost phase A measured — so phase B totalled
  1.602 s, i.e. *faster than phase A despite adding setup*, which is
  impossible for the real protocol. Fixed (commit `a7a2a85`): phase B
  reuses the phase-A GGM expansion with a setup-bound root and reports
  `t_ggm_pprf_s`. (2) **Label overstatement**: `base_vole:"real"` renamed
  to `"setup-cost-model"` — the group operations and bytes are real, but
  both parties run in one process from a shared seed and the base VOLE is
  still dealer-derived; a two-party execution remains future hardening.
  Corrected clean measurement
  `benchmarks/results/p7-real-pcg-2026-07-07-a7a2a85.json`
  (`git_dirty:false`): **total 4.408 s** = base OT 0.021 + OT ext 0.008 +
  base-VOLE 0.016 + **GGM PPRF 1.934** + LPN 2.186 + checks 0.240;
  `setup_comm_bytes` unchanged at 1,081,408 B; consistency `ok:true`;
  `production_ready:false`. The 2026-07-07 numbers of record for the PCG
  line are therefore: expansion ≈ 3.2–4.4 s CPU single-thread
  (load-sensitive VM, trap #6.7), setup compute ≈ 0.05 s, setup comm
  ≈ 1.08 MB/session. Aggregate `benchmarks/results/p7-2026-07-07-a7a2a85.json`.

- **2026-07-07 (P7 real-PCG phase B, pre-registered)**:
  implement `p7_pcg_report --backend phase-b` as an opt-in setup
  measurement: real public-key base OT dependency (`curve25519-dalek`),
  measured OT-extension/GGM-delivery bytes, transcript-bound consistency
  challenge after setup binding, and JSON `base_vole:"real"` with
  `setup_comm_bytes`. This is not a default/backend flip. Production status
  remains false until the WYKW malicious checks and the LPN code/parameters
  are tied to cited WYKW/Ferret tables; docs stay limited to this ledger
  entry plus measured JSON.

- **2026-07-07 (P7 real-PCG phase B clean measurement)**:
  clean run `benchmarks/results/p7-real-pcg-2026-07-07-ec6e4f7.json`
  (`git_dirty:false`) reports `base_vole:"real"`, `setup_comm_bytes:
  1,081,408` B = 16,384 base OT + 1,064,960 GGM OT-extension + 64
  consistency, total **1.602 s** = base OT 0.021 s + OT extension 0.008 s
  + base-VOLE derivation 0.016 s + LPN 1.323 s + checks 0.231 s, peak RSS
  0.361 GB, consistency `ok:true`, `production_ready:false`. Aggregate:
  `benchmarks/results/p7-2026-07-07-ec6e4f7.json`. Remaining blockers are
  exactly the phase-B hardening items above: paper-level malicious checks
  and table-derived LPN/code parameters.

- **2026-07-07 (P7 real-PCG phase A, pre-registered)**:
  implement the §4.4 phase-A backend in-repo before cloud GPU spend. Scope:
  add `volta-pcg` with a WYKW/Wolverine-style Goldilocks subfield VOLE
  expansion model: trusted-dealer base sVOLE stub from the shared seed,
  GGM single-point noise generation, regular-noise local-linear LPN
  expansion, and transcript-invisible consistency-check arithmetic. Mock
  remains the default proving backend and regression baseline; phase A is
  selected explicitly by `p7_pcg_report --backend real`. Pre-registered
  phase-A profile: `p7-phase-a-goldilocks-regular-lpn-v1`, security target
  128 bits, one sub-equivalent output batch covering the P6 volume
  (`8,479,926` sub + `2*176,880` full limbs = `8,833,686` sub-equivalent
  VOLEs), base length `k+t+1`, `k=589,760`, regular noise weight
  `t=1,280`, local-linear fanout `10`, one GGM PPRF single point per
  regular-noise block, GGM depth `ceil(log2(ceil(n/t)))`, and two F_p²
  random-linear consistency checks. Full-field correlations are two
  subfield sVOLEs sharing the same Δ and combined F_p-linearly. JSON must
  be `benchmarks/results/p7-real-pcg-<date>-<sha>.json` with
  `is_real_pcg:true`, `base_vole:"mock-stub"`, setup vs expansion vs check
  timing split, corrs/s for both sides, peak RSS, `setup_comm_bytes`, and
  the LPN parameters. PCG/setup bytes are a separate counted category and
  are not response download. Formal position: Lean still consumes ideal
  VOLE; this PCG is an external LPN/PPRF realization assumption, same
  status as PCS binding in M9; no Lean work in phase A.

- **2026-07-07 (P7 real-PCG phase A landed, dirty local measurement)**:
  new `volta-pcg` crate implements the phase-A Goldilocks PCG expansion
  path and `p7_pcg_report --backend real` measured the P6 volume from
  `p6-2026-07-07-515bb1c.json`: `8,479,926` subfield + `176,880`
  full-field correlations (`8,833,686` sub-equivalent limbs). JSON
  `benchmarks/results/p7-real-pcg-2026-07-07-995bfb7.json`
  (`git_dirty:true`, implementation tree) reports `is_real_pcg:true`,
  `base_vole:"mock-stub"`, `setup_comm_bytes:0`, profile
  `p7-phase-a-goldilocks-regular-lpn-v1`, and consistency `ok:true`.
  Timing: **3.240 s** total = setup stub 0.016 s + GGM PPRF 1.977 s +
  LPN expand 1.017 s + full combine 0.002 s + consistency checks 0.228 s;
  joint throughput 2.73 M sub-equivalent correlations/s; peak RSS
  0.361 GB; expanded pools are 209.2 MB prover + 138.5 MB verifier.
  `scripts/report.py --write-json` refreshed
  `benchmarks/results/p7-2026-07-07-995bfb7.json`, whose
  `real_pcg_spike.status` is now `phase_a_measured_mock_stub`.
  Correctness gate: `p6_report --quick --pcg-backend real` accepted and
  wrote `benchmarks/results/p6-quick-realpcg-2026-07-07-995bfb7.json`
  (`accepted:true`, flat-cost 1.022, `pcg_mock_prepass_counters_match:true`,
  `pcg_allocation_hash_match:true`). Mock remains the default backend;
  phase B still needs real base OTs / OT extension and measured setup
  communication.

- **2026-07-07 (P7 real-PCG phase A clean checkpoint rerun)**:
  after checkpoint `fe4857b`, reran phase A on a clean tracked tree
  (untracked result files ignored by the report's `git_dirty` check).
  Clean JSON `benchmarks/results/p7-real-pcg-2026-07-07-fe4857b.json`
  reports `git_dirty:false`, same P6 volume and parameters as above,
  **3.709 s** total = setup stub 0.019 s + GGM PPRF 2.177 s + LPN expand
  1.279 s + full combine 0.002 s + consistency checks 0.231 s; peak RSS
  0.361 GB; consistency `ok:true`; setup communication remains 0 B because
  base VOLE is still `mock-stub`. Clean correctness gate
  `benchmarks/results/p6-quick-realpcg-2026-07-07-fe4857b.json` reports
  `git_dirty:false`, `accepted:true`, flat-cost 0.993,
  `pcg_mock_prepass_counters_match:true`, and
  `pcg_allocation_hash_match:true`. Refreshed clean aggregate report:
  `benchmarks/results/p7-2026-07-07-fe4857b.json`.

- **2026-07-07 (P7 decision — real-PCG becomes an in-repo implementation,
  supersedes the "cost spike only" scope)**: user decision. Instead of a
  proxy measurement on a foreign field (emp-zk Mersenne-61 / ocelot), a
  WYKW/Wolverine-style subfield VOLE over Goldilocks (m = k + r·Δ, Δ ∈
  F_p², full-field corrs as two sVOLEs sharing Δ) is implemented in a new
  `volta-pcg` crate as the eventual production backend — same rationale as
  the in-house Ligero decision (P3.5 #1). Two phases, each with its own
  pre-registration: **A** (GGM PPRF + LPN expansion, base sVOLE stubbed
  from the mock seed — real expansion cost of record, required before
  cloud GPU spend) and **B** (real base OTs + OT extension + malicious
  consistency checks; first public-key dep, allowed since the "no curves"
  invariant binds the PCS/proof path only). Hard constraints: mock backend
  stays default until measured phase-B parity; CorrIndex domain separation
  and one-time-use counting unchanged; PCG/setup bytes are a NEW counted
  category (`setup_comm_bytes`), never folded into response download; no
  proving-path/transcript change. LPN parameters (≥128-bit) are a security
  assumption to pre-register, same status as PCS binding in M9; no Lean
  work expected (optional future M10 interface lemma). Full work item:
  handoff spec §4.4.

- **2026-07-07 (P7 pre-cloud local complete)**:
  clean full P6 rerun with transcript-label accounting landed as
  `benchmarks/results/p6-2026-07-07-382bb56.json` (`git_dirty:false`,
  accepted, golden decode ✓, flat-cost gate 1.17). It preserves the P6
  communication totals (transcript 137.4 MB, PCS 66.733 MB, packed download
  144.8 MB) and adds `comm_*_by_label`. Decode marginal is
  **22,253,392 B = 445,067 B/token**, with top non-PCS labels:
  `auth_corrections` 20,902,016 B, `logup_round_corrections` 671,168 B,
  `logup_split_corrections` 202,624 B, `logup_prod_corrections` 151,968 B,
  `logup_aux_round_corrections` 141,936 B. This confirms the next
  transcript lever is the formal-touching correction packing / seam reuse
  family, not another PCS-only tweak. The refreshed filtered P7 aggregate
  report `benchmarks/results/p7-2026-07-07-d0812a7.json` carries
  `git_dirty:false`, keeps one measured PCS profile per shape/Q, and includes
  the full decode breakdown. Local P7 work before cloud is complete except
  for a real Ferret/silent-VOLE measurement, which is unavailable in this
  repo and remains an explicit cloud/external budget item.

- **2026-07-07 (P7 decode marginal breakdown, pre-registered)**:
  add transcript-label snapshots to `p6_report` so the 445 KB/token decode
  marginal can be decomposed before any optimization. Scope is accounting
  only: clone the existing `Transcript` byte ledger, snapshot PCS labels
  around the real opening, and report response / prefill / PCS /
  decode-non-PCS marginal by label. No transcript message, challenge order,
  proof content, or communication byte count changes.

- **2026-07-07 (P7 mock-PCG lower-bound spike, pre-registered)**:
  no real Ferret/silent-VOLE implementation or dependency is present in the
  repo. Add a local `p7_pcg_report` binary that reads a P6 JSON's counted
  `corr_sub_corrs` / `corr_full_corrs` and measures the current mock-PCG
  ChaCha expansion over the same element volume. This is explicitly a lower
  bound / plumbing measurement, **not** the real-PCG spike required for the
  final go/no-go; the ledger and JSON must say so. It does not affect any
  proof path or correlation semantics.

- **2026-07-07 (P7 mock-PCG lower-bound landed)**:
  `cargo run --release -p volta-bench --bin p7_pcg_report` measured the
  current mock ChaCha expansion for the clean P6 correlation volume
  (`8,479,926` subfield + `176,880` full-field correlations) and wrote
  `benchmarks/results/p7-mock-pcg-2026-07-07-d16a69c.json` (dirty tree).
  Expanded both prover and verifier sides in **0.351 s** total: prover sub
  0.172 s, verifier sub keys 0.170 s, prover full 0.0046 s, verifier full
  keys 0.0052 s; peak RSS 0.19 GB. This is a lower-bound/plumbing number
  only (`is_real_pcg:false` in JSON), because no Ferret/silent-VOLE
  implementation is present locally. The final P7 go/no-go still requires
  a real-PCG setup+expansion measurement or an explicit external budget.
  `scripts/report.py` now includes these mock lower-bound rows under
  `real_pcg_spike.mock_pcg_lower_bounds`; refreshed report
  `benchmarks/results/p7-2026-07-07-d16a69c.json`.

- **2026-07-07 (P7 Q=150 exploratory profile, pre-registered)**:
  add a non-default `p6_report --pcs-q <Q>` switch to measure the PCS query
  count lever without changing the run-of-record parameters. The default
  remains Q=200 and ~80-bit query error. The exploratory profile uses
  Q=150 at the existing rate/distance, giving ~60.0-bit query error under
  the same `(1-δ/2)^Q` model; `pad=512` still covers the one-response
  hiding headroom. This is **not** an adopted production soundness parameter
  and does not change `P4_LAYER`, `GPT2_FULL`, transcript structure, claim
  stacking, or verifier logic. Any adoption of Q=150 as default requires a
  separate ledger decision and final report update.

- **2026-07-07 (P7 Q=150 exploratory quick measurement landed)**:
  `cargo run --release -p volta-bench --bin p6_report -- --quick --pcs-q
  150` accepted and wrote
  `benchmarks/results/p6-quick-q150-2026-07-07-fa40a1d.json` (dirty tree,
  quick workload only). The JSON records `pcs_n_queries=150`,
  `pcs_query_error_bits=60.013`, and the real PCS path verified with
  `pcs_opening_bytes_total=57,822,904` B vs 66,733,504 B at Q=200 (the
  exact P7 projection). Packed quick-response download was 73.4 MB vs
  ~82.3 MB for the prior Q=200 quick profile on the same schema. The
  default constants remain Q=200; this measurement only validates the
  lever plumbing and byte model.

- **2026-07-07 (P7 report updated with measured PCS profiles)**:
  `scripts/report.py` now includes `measured_pcs_profiles`, so the P7 JSON
  distinguishes modeled scenarios from actual P6/P6-quick measurements.
  Updated local report `benchmarks/results/p7-2026-07-07-5390144.json`
  includes the Q=150 quick profile (`57,822,904` B PCS, `60.013` query-error
  bits) alongside the Q=200 profiles. The P7 go/no-go recommendation is
  unchanged: communication headroom is credible, but final decision still
  requires real-PCG and cloud GPU measurements.

- **2026-07-07 (P7 next step, pre-registered)**: add Rust-side
  accounting-only support for the static-query-cache PCS lever. Scope:
  expose a `MultiOpenProof` byte breakdown and a
  `cached_query_marginal_bytes` count in `volta-pcs`, then thread those
  numbers into future `p6_report` JSONs. This does **not** change
  `open_multi_zk`, `verify_multi_open`, challenge order, transcript bytes,
  proof contents, or soundness parameters; it only computes the marginal
  bytes that would remain if raw data columns plus their commitment Merkle
  paths were served from a verifier cache keyed by the static commitment
  root. Any actual split of setup/per-response proof remains a separate
  protocol-design entry.

- **2026-07-07 (P7 static-query-cache accounting landed)**:
  `MultiOpenProof::byte_breakdown()` now exposes the measured byte
  decomposition of the real PCS proof, and `p6_report` writes
  `opening_cached_query_cut_bytes`, `opening_cached_query_marginal_bytes`,
  and `pcs_cached_query_marginal_bytes_total`. Dirty quick schema check
  `benchmarks/results/p6-quick-2026-07-07-2b3beab.json` accepted the
  response and confirmed the same full-scale PCS accounting as P7 report:
  layer opening 4,293,216 B with a 1,734,400 B conservative static-cache
  cut, embed opening 15,214,912 B with a 13,203,200 B cut, total PCS
  **66,733,504 B → 32,717,504 B marginal**. This is still accounting-only:
  proof contents and transcript bytes are unchanged.

- **2026-07-07 (P7 local report landed)**: `scripts/report.py --write-json`
  produced `benchmarks/results/p7-2026-07-07-754626f.json` (dirty tree:
  ledger/script/test changes plus the pre-existing handoff-spec edit). The
  report consumes the clean P6 run of record
  `p6-2026-07-07-515bb1c.json` and the P7-prep dirty packing source
  `p6-2026-07-07-d71e339.json`; `tests/test_report.py` verifies that the
  PCS formula reproduces the measured 66,733,504 B exactly (4,293,216 B per
  layer opening ×12 + 15,214,912 B embed). Current packed download is
  **144.8 MB**. Projection-only PCS levers: same-rate Q=150 for ~60-bit
  query error → **135.9 MB** packed response; per-tensor RLC 8→4 / 6→3
  claims → **130.9 MB**; Q=150+RLC → **122.0 MB**; embed 2^12-row shape
  → **140.1 MB**; static-query verifier cache marginal → **110.8 MB** and
  cache+RLC marginal → **96.9 MB**. No proving path changed and no
  soundness parameter was adopted. GPU rho sensitivity: CPU P6 rho implies
  the GPU proof kernels must beat native-inference GPU speedup by **4.62×**
  for prefill and **2.54×** for decode to hit rho≤5/≤2. Local
  recommendation is conditional cloud spikes only; final P7 go/no-go remains
  blocked on real-PCG cost and actual GPU roofline/native-baseline
  measurements.

- **2026-07-07 (P7 local plan, pre-registered)**: scope for this VM pass is
  deliberately conservative. Add `scripts/report.py` plus focused tests: it
  consumes `benchmarks/results/*.json`, uses the clean P6 run of record for
  proof/PCS timing and the P7-prep dirty P6 run only for the measured
  public-logits packing delta, writes a non-overwriting `p7-*.json`, and
  prints the rho / communication / PCS-lever tables. PCS changes here are
  projections only: Q/rate alternatives, per-tensor RLC claim merging,
  static-query verifier caching, and embed shape are modeled from the
  checked `MultiOpenProof::bytes()` formula, not enabled in the proving
  path. No Q/rate soundness parameter, commitment layout, PCS transcript, or
  Lean-facing invariant changes in this pass. Real-PCG and cloud CUDA remain
  unmeasured local blockers; the report records the counted correlation
  volume and a conditional go/no-go/sensitivity model instead of pretending a
  GPU run happened.

- **2026-07-07 (P7 prep — public-logits bit-packing landed, measured)**:
  handoff spec §4.6.E implemented: the public band logits (i64, true range
  ≪ 2^64) travel bit-packed (per-row min + fixed-width offsets, "VLPK1"
  codec in `volta-bench/src/logits_pack.rs`); the verifier consumes the
  DECODED matrix (asserted bit-exact) inside `p6_report`'s e2e session, so
  the packed size is the real download and the codec sits on the accepted
  path. Transport-only — nothing enters the transcript, no protocol or
  soundness surface touched. Measured at the P6 workload (accepted e2e,
  golden decode ✓, flat-cost gate 1.18): **public logits 20.50 → 7.41 MB
  (2.77×), total response download 157.9 → 144.8 MB**. JSON schema gains
  `public_logits_packed_bytes` + `total_response_download_packed_bytes`
  (old fields keep their meaning). Dirty-tree measurement
  `p6-2026-07-07-d71e339.json`; the clean-tree run of record lands with
  the commit checkpoint. The §4.2 is_max argmax argument stays logged as
  the deeper lever (would remove the remaining 7.4 MB at ~2.5 M lookups).

- **2026-07-07 (P7 prep — two notes for the record, CLOSED, no P7 action)**:
  1. **Chunking trade is a closed decision.** 5×10 decode chunks prove 23.1 s
     vs 18.7 s for the single deferred Q=50 chunk (+23%, per-chunk fixed
     instance costs). The single deferred chunk is the mode of record
     (`p6_report` run of record; the 5×10 curve exists only as the flat-cost
     gate). Chunking stays available as a latency/streaming knob — never
     per-token (P4 dev. #8) — and is NOT a P7 work item; do not revisit
     unless a streaming product requirement lands.
  2. **`layer_rejects_lying_row_max` dev-profile behavior is documented and
     robust, not a bug.** Pre-existing since P5 (reproduced at commit
     `18e883d`, dev profile): the wires tamper trips the honest-prover
     `debug_assert` in `hadamard_prove` before any proof exists — dev builds
     cannot emulate this cheating prover at the wires level (P4 dev. #10
     caveat). The test (`volta-proto/src/block_proof.rs`) wraps the case in
     `catch_unwind` and counts a prover-side panic as detection; release
     builds exercise the verifier-side reject. No action needed; do NOT
     "fix" by removing the library debug_asserts.

- **2026-07-06 (P6 plan, pre-registered)**: scope, design decisions and gate,
  fixed before implementation (user constraints: still the 11 GB / 4-core VM;
  P7 moves to cloud CUDA; comm up to ~150–200 MB/response acceptable as a
  post-response download, but every saved MB counts):
  1. **Two-phase shared-α LogUp restructure** (the deferred ÷12 amortization,
     P5 closing #2, unified with cross-token batching): phase 1 binds ALL
     element-wise auths model-wide — boundaries, LN/attn vectors, and ONE
     global multiplicity vector per **table content** (content key =
     `Range(shift)` for requant/remainder tables, `Pair(lut)` for exp / gelu /
     ln_rsqrt / softmax_recip; equal-shift range tables merge across sites,
     layers AND phases — the ledger 2026-07-06 #6 freebie). One α per content
     is drawn only after phase 1 (strictly later than every binding it
     depends on — a strengthening of the current per-instance ordering).
     Phase 2 runs the per-site lookup-side trees with the shared α (no
     per-site table side, no per-site mult auth), collecting authenticated
     root fractions per content; per content, ONE table-side tree against the
     global multiplicity vector + an authenticated fraction-sum chain
     (running (P,Q), 3 Π_Prod rows + 3 full corrs per site) ties
     Σ_sites p_s/q_s = p_t/q_t, closed by the existing root cross-check.
     Expected effect at T=100: multiplicity corr 59.4 MB → ~10 MB (one 8 B
     vector per content, ~20 contents), table-side E-mults ÷(sites/content).
  2. **Decode = deferred stacked chunk proving** (P4 dev. #8 verbatim
     constraint): witness generation is autoregressive (prompt 100 + 50
     greedy-argmax tokens, KV cache append-only), proving is deferred to end
     of response and covers each decode chunk (default ONE chunk of Q=50) as
     a batch of Q rows — never per-token instances, never per-token PCS
     claims. Attention generalizes to a **rectangular offset-causal band**:
     queries = the chunk's Q rows (positions t0..t0+Q), keys/values = the
     full cache S = t0+Q, mask `j ≤ t0+i`, rect domains h_pad×Q_pad×S_pad
     (prefill = the degenerate band t0=0, Q=S=T — same code path). All
     row-local machinery (LN, FFN, requant sites, seams, embed requant +
     selection with the wpe window at offset t0) runs unchanged at t=Q.
  3. **Authenticated KV cache across phases** (mirror of M4): decode K/V rows
     are authenticated once per chunk under fresh position-separated domains;
     the band's K̃/Ṽ full-cache openings resolve as weighted streamed MAC
     openings over BOTH segments (prefill auth + chunk auths). Anti-replay
     gate: reusing / mixing a cache row's corrections across positions or
     layers must fail verification (smoke test, cheating-prover emulation).
  4. **Logits at every decode position**: final-LN runs as a t=Q batch on the
     last layer's decode rows; the public logits matrix (Q×V) is bound at one
     random (ρ_v, ρ_q) and reduced by one blind matvec sumcheck to one wte
     claim (same machinery as P5's single-row logits claim); token sampling
     is then a PUBLIC argmax check per position. The response tokens are
     public output, so decode selection S(z) stays public.
  5. **Gate (architectural, CPU)**: per-token proving cost ~flat as the cache
     grows — measured with a chunked run (5 chunks × 10 tokens, cache
     100→150): cost/chunk may grow only by the O(S·d) attention term, never
     O(S²); anti-replay smoke passes; golden check (numpy decode reference,
     50 tokens bit-exact). Recorded, not gated: ρ_decode, verified tokens/s,
     bytes/token with breakdown, PCS opening with stacked prefill+decode
     claims (~2× prefill claims), peak RSS ≤ 11 GB.
  6. Out of scope, logged for P7: real-PCG spike (pre-registered P5 agenda),
     PCS commitment consolidation / query-count levers, per-tensor RLC
     merging of prefill+decode weight claims (the batch opening at
     2.3 ms/claim absorbs ~100 claims fine on CPU).

- **2026-07-07 (P6 CLOSED — run-of-record decisions and open levers)**:
  1. **Gate passed** (see milestone row). Architectural claim confirmed on
     CPU: per-token proving cost is ~flat as the cache grows (chunk curve
     0.236 → 0.263 s/token over cache 100→150 — the O(seq·d) attention term
     only; an O(seq²) design would have doubled immediately). The decode
     marginal ratio ρ_decode = 5.07 (marginal prove / native KV-decode wall)
     is ~4.6× BETTER than ρ_prefill (23.1): decode proving batches 50 rows
     into one stacked chunk while native decode is matvec-bound.
  2. **One code path for prefill and decode**: attention generalized to the
     offset-causal band (`BandShape`, prefill = t0 0 square band) — the P4/P5
     regression suite validates the band machinery directly. Cross-phase
     cache openings are segmented streamed MAC openings (`CacheSegP/K`);
     anti-replay holds by position-separated domains (smoke-tested).
  3. **Chunking trade measured**: 5×10 chunks prove 23.1 s vs 18.7 s for the
     single Q=50 chunk (+23% — per-chunk fixed instance costs). Deferred
     single-chunk proving is the mode of record; chunking is a
     latency/streaming knob, never per-token (P4 dev. #8 upheld: claims per
     response = 2× prefill, one stacked PCS opening).
  4. **Band logits are public response output** (20.5 MB for 50 positions):
     each sampled token is checked as a PUBLIC argmax of the previous
     position's logits row inside `verify_response`. Counted in the download
     total, not in the proof transcript. Lever if it ever matters: an is_max
     argmax argument (P5's row-max machinery reused per vocab row) would
     replace 20.5 MB with ~2.5 M lookups — logged, not scheduled.
  5. **Comm decomposition at 150 tokens: 157.9 MB total download** = 48.4
     (prefill corrections/transcript) + 22.3 (decode marginal, 445 KB/token)
     + 66.7 (PCS opening, 102 claims over 13 commitments) + 20.5 (public
     logits). The PCS opening replaced multiplicity vectors as the single
     largest lever (P7: commitment consolidation, query count, per-tensor
     RLC claim merging — the 2.3 ms/claim model held: open 1.05 s).
  6. Final-LN/logits machinery now runs on ALL band rows (t=q batch) — the
     P5 t=1 duplicated-row deviation stays prefill-only.
  7. Witness-side: band witnesses are SLICES of one full causal re-forward
     (prefix-consistency, asserted bit-exact vs the KV-cached incremental
     decode and vs numpy over 50 tokens); prover accumulators (LN affine,
     gelu multiplicities) are recomputed from boundaries + stats, so bands
     carry no lookup traces.

- **2026-07-07 (P6 in progress — shared-α restructure landed, measured)**:
  the two-phase pipeline (P6 plan #1) is implemented on the prefill path and
  re-measured at T=100 on the frozen artifact
  (`benchmarks/results/p5-2026-07-07-9a19662.json`, accepted e2e with the 13
  real PCS openings): **multiplicity corr 59.4 MB → 2.85 MB** (beats the
  ~10 MB estimate — equal-shift range tables merge more than 12×), **total
  comm 159.6 MB → 101.2 MB/prefill** (projected response 154 MB), prove
  11.2 → 10.1 s, verify 0.65 → 0.32 s, E-mult all-in 100.6 → 93.6/budget
  lookup, peak RSS 2.82 GB. Structural changes: `TableKey` content keys,
  `TableBankP/V` (phase-1 global mult auth + per-content α + per-content
  table side with an authenticated fraction-sum chain over all site roots),
  `prove/verify_layer` split into phase1/phase2, per-instance table sides and
  mult vectors deleted. PCS numbers in this JSON are noisier than the run of
  record (embed commit 6.5 s vs 3.5 s — background load; PCS code untouched).
  Also observed (pre-existing, reproduced at the P5 commit `18e883d` in dev
  profile): `layer_rejects_lying_row_max` trips the honest-prover
  `debug_assert` in `hadamard_prove` before the proof exists — the wires
  tamper cannot be emulated in dev builds; the test now counts a prover-side
  panic as detection (release exercises the verifier reject).

- **2026-07-06 (P5 plan, pre-registered)**: pre-P5 assessment closed with the
  user: **no CPU optimization cycle before P5** — the remaining LogUp/PCS
  levers (helper-column family, padding layout, NEON/lazy reduction) are
  design trade-offs whose payoff depends on the GPU cost model (P7 decides),
  and P5's own amortizations (÷12 tables, batched PCS claims) change the
  numbers first; the dev loop (~10 s/prefill prove) is iterable. Scope:
  1. Work items: (a) `scripts/export_gpt2.py` — one-off HF safetensors
     download, per-tensor pow-2 scales calibrated on the golden prompt, the
     12 LUTs at real scales, `cattn_permuted` weight layout (dev. 2026-07-05
     #7), fixed prompt-token file, quantized format read by Rust via memmap2;
     (b) numpy fixed-point reference (~200 lines, bit-exact vs the Rust
     witness generator; golden check = logits/argmax at the last position);
     (c) full-model driver: embedding, 12 chained layers with x_in
     authenticated once per seam (fixes the single-layer double-count,
     dev. #9), final LN + logits row; (d) **one multiset argument per table
     per model** — table-side LogUp and multiplicity binding lifted from
     per-layer to per-model (÷12, pre-registered in dev. #4); (e) one batched
     PCS opening for all 49 claims, committed-W mode by default;
     (f) `scripts/run_prefill.sh` + `p5_report` — one command, full JSON.
  2. Report schema additions (pre-registered): **PCS opening bytes** (absent
     from the P4 JSON) and **total communication per response** as a
     first-class measured number, broken down (auth corrections /
     LogUp+sumcheck transcripts / multiplicity vectors / PCS opening).
     Analytic estimate to confirm or kill: ≈49 MB corrections with mult ÷12,
     plus opening — the ~55 MB/response ballpark is a product constraint.
  3. Saturation contingency (dev. #5): calibration first tries exponents with
     zero saturations on the golden prompt; if the no-clamp assert fires on
     real weights, the **saturation side-table becomes the first P5 work
     item** (clamp-range side lookup), not a redesign.
  4. **New convention (user)**: prover time may be bought with verifier time
     (verifier is currently cheap, ~NanoZK-level: 0.041 s/layer) but **never
     with final proof size** — communication is already the binding product
     constraint. Applies to all P5+ design choices.
  5. Gate unchanged from the plan of record: one-command reproducible run,
     complete JSON, golden check green; counts vs P0 budget <20% or explained;
     peak RSS ≤ 11 GB. ρ_prefill is recorded and analyzed, not gated (GPU
     target, P7).
  6. Agenda items logged here, NOT P5 scope: (a) real-PCG (silent VOLE)
     setup/expansion cost spike **before the P7 go/no-go**; (b) the P6
     interface requirement is extended from PCS claims to **cross-token
     batching of lookups** (per-model tables already amortize the table side
     across tokens; the lookup-side instances must batch too — never fixed
     per-token instance cost).

- **2026-07-06 (P5 CLOSED — run-of-record decisions and open levers)**:
  1. **Gate passed** (see milestone row). Fixed-point fidelity on real weights
     confirmed end-to-end: numpy reference, Rust witness and the proved
     computation agree bit-for-bit on the full logits vector.
  2. **Table amortization (÷12) DEFERRED to the P6 restructure — motivated
     deviation from the pre-registration.** Merging table-sides per table
     content requires a SHARED LogUp α across instances, i.e. a two-phase
     pipeline (bind all layers' multiplicity vectors before any α). That is
     the same restructure the P6 cross-token lookup batching (already a
     ledger interface requirement) needs — doing it twice would be waste.
     Measured cost of deferring: multiplicity corr 59.4 MB/prefill vs ≈5 MB
     amortized (the single largest comm lever, −54 MB), plus table-side
     E-mults. P6 does both at once.
  3. **PCS cost model updated**: the P3.5 model (0.12 s + 2.3 ms/claim)
     assumed ONE commitment; the 13-commitment baseline pays 13 fixed passes
     → measured open 0.73 s for 51 claims (12 × ~0.035 s + embed 0.30 s).
     Levers: commitment consolidation (needs the non-pow2-rows Ligero
     variant or >11 GB RAM) and session-level batching. Verify stays cheap
     (0.07 s).
  4. **Comm 159.6 MB/prefill measured** (the ~55 MB ballpark is missed 2.9×;
     JSON total = the Transcript byte ledger — corrections and PCS bytes are
     inside it, an earlier draft double-counted). Path back: −54 MB mult
     amortization (P6), −6.9 MB x_in auth reuse, then the 52.8 MB opening
     (query count / rate / consolidation — P7 levers). Product constraint
     stays under watch, not yet killed.
  5. **Selection-identity bug found by the run of record and fixed**: the
     embedding-selection's wpe term must be MASKED to real rows (committed
     block rows t..1023 are nonzero); a direct point claim only worked at
     power-of-two T. Fix: dedicated masked sumcheck (G(w) = [w<t]·eq public).
     The e2e regression now runs at non-pow2 T=20. Lesson logged: pad-domain
     identities must be tested at t ≠ t_pad.
  6. New instances beyond the P0 budget (embed requant, 11 seams, final-LN,
     logits, selection, is_max machinery) are outside `ModelOut.lookups` and
     the budget formulas — noted in the JSON (`embed_lookups_note`),
     E-mult all-in 100.6/budget lookup (P4 layer-only: ≈90).

- **2026-07-06 (P5 in progress — quantization semantics for real weights)**:
  three spec amendments forced by real GPT-2 ranges, decided at export time
  (quantization-spec.md updated in the same commit):
  1. **Stable softmax (shifted exp)**: real attention scores reach ±20+, so a
     direct base-e `exp` LUT saturates. New semantics: `s' = s − c_row` with
     `c_row := max` of the causal row (spec definition; softmax is invariant
     to any row shift in exact arithmetic), exp LUT is base-e, faithful on
     `x ≤ 0`, and its **table content only covers the nonpositive domain** —
     LogUp membership itself range-checks `s' ≤ 0`. Soundness that `c_row` is
     the true max (a malicious shift could saturate/flatten attention):
     `s' ≤ 0` from the table domain + **per-row product-zero check**
     `Π_j s'_j = 0` via the existing Π_Prod machinery (M7/M8) proves
     `c_row = max`. `c_row` itself is bound linearly (`c = s − s'` per entry).
     Pad pairs unchanged (exp[0x8000] = 0 stays the least-index zero); the
     product-zero rows are the real (unpadded) rows only — pad rows are
     excluded by the same public row-selector approach as the causal mask.
  2. **Embedding requant (13th table)**: `wte` is tied (embedding + logits
     weight) and needs its own scale `f_wte` ≫ the residual-stream scale
     `f_res` (real residual maxima are orders larger than |wte|). New
     `requant_embed` table: `embed_out = (wte[tok] + wpe[pos]) >> shift_embed`
     (round-half-up), T·d = 76,800 extra lookups per prefill — a new LogUp
     instance at model level, not in the P0 budget (explained deviation).
  3. **GEMM biases (real GPT-2 has them, P4 synthetic didn't)**: quantized at
     the OUTPUT scale of their op and folded linearly into the accumulator
     (`acc += b << shift_op`) before the requant lookup — same pattern as the
     P4 LN bias. Biases and LN gain/bias are **public** verifier inputs in P5
     (extends P4 deviation #6; the private tensors are the four big matrices
     + wte/wpe via PCS).
  Also fixed: ONE global shift/LUT set for all 12 layers (per-layer scales
  would break the one-multiset-per-table amortization); weight exponents are
  per tensor-type (max |w| across layers); calibration = float ranges on the
  golden prompt + headroom bits, verified by a strict no-clamp fixed-point
  pass (saturation ⇒ side-table contingency, pre-registered).

  **Iteration 2 (same day, measured failure)**: with a single global residual
  scale the calibrated f_res is 1 (late-layer outlier channels reach ~1e3
  while the embedding is ~1e-1) and the fixed-point argmax broke on the
  golden prompt (float ' way' vs fixed '\n') — no saturation, pure precision
  loss in the early layers. Amendments (spec updated):
  4. **Per-layer residual scales** `f_res[l]`, monotone non-increasing, with
     **seam requants** between layers (`x_in(l+1) = ffn_block_out(l) >>
     seam_shift`, shift 0 = free). Only the residual-facing sites go per
     layer (attn_proj/ffn_down requant shifts + seams + embed); LN is
     scale-free w.r.t. its input scale (`dev_int·r_int = x̂·2^R` for any f),
     so the ln_rsqrt table, LN path, qkv/scores/softmax/gelu tables all stay
     global. Extra lookups ≤ 11·T·d ≈ 845k/prefill (~5%).
  5. **Chained requant for shift > 16** (real params already produce 18–19):
     `requant(acc, s) := requant(requant(acc, s−16), 16)` — double-round
     semantics by definition; keeps every remainder table ≤ 2^16 (the naive
     2^19 table would cost a 4 MB multiplicity vector alone).
  6. Amortization freebie (for the P5 prover): remainder range tables with
     equal shift are content-identical ACROSS sites/layers — the multiset
     argument merges per table *content*, so the per-layer shift lists cost
     few distinct tables, not 12× per site.
  7. **PCS memory decision**: one full-model commitment needs a 2^28 message
     (48 layer blocks 163.6M + wte 2^26 + wpe 2^20 → pow2 232M; ≈4 GB encoded
     — over the 11 GB VM with the rest of the pipeline). P5 baseline: **12 ×
     P4_LAYER (2^24) layer commitments + 1 × GPT2_FULL (2^27) embedding
     commitment (wte+wpe, `layout_gpt2_embed`)**, 13 batched openings per
     response. Prover cost is ~unchanged (the dominant fixed cost is the
     O(|W|) proximity pass — same total data either way); consolidation and
     the verifier-side 13× column checks are levers to re-measure, not
     requirements.
  8. **Implementation state (2026-07-06, evening)**: the full-model proof is
     e2e green on the frozen artifact (t=16 smoke): (A) GEMM biases as public
     transport corrections; (B) chained requant (2-stage range sites,
     shift_ln_norm=20 and shift_attn_proj 17/19 exercised); (C) stable
     softmax per #9 below; (D) model driver — 12 layers + seam requants +
     embed requant + final-LN + logits claim + embedding-selection sumcheck,
     ONE model-wide Π_Prod/Π_ZeroBatch closure; 51 committed-tensor claims
     (48 layer + 2 wte + 1 wpe), nothing pending. Known accepted deviations:
     final-LN at t=1 runs as a duplicated-row t=2 batch (machinery needs ≥2
     rows; dup row bound to nothing — sound); x_in is re-authenticated per
     layer (double-auth ≈ +6.9 MB corr vs the budget's once-per-seam
     counting — explained, reuse is a lever); `verify_model` takes the whole
     Gpt2Model but reads only public fields (biases/LN params/luts/tokens) —
     prototype interface, not a leakage.
  9. **Row-max soundness design (stable softmax, refines #1)**: the shared
     scores/exp wire becomes s′ = s − c_row; c_row is an authenticated
     h_pad×T_pad row table; the scores-instance acc transport gains an
     authenticated public-coefficient fold 2^s·⟨gc, c⟩ (gc_i = Σ_{causal y ∈
     row i} eq(pt,y), same cost class as P4's pad-mask term). Existence of
     the row zero (c = max, given s′ ≤ 0 from the table domain): witness
     indicator wire `is_max` carried as a non-membership column of the exp
     instance, with (a) one hadamard-with-claim-0 row (ĩs_max ∘ s̃′ ≡ 0) and
     (b) one rowsum identity (row sums of is_max = 1 on real rows, the
     denominator-rowsum trick). No per-row product gates, no element auth of
     wires; booleanity of is_max is not needed ((a)+(b) already force a zero
     per row).

- **2026-07-05 (P4)**: one full transformer layer (attention + FFN fused
  blocks, LogUp instances, chained GEMMs, hadamard, real Ligero opening)
  proved + verified e2e at T=100. Gate passed; decisions and deviations:
  1. **E-mult gate missed, motivated**: measured 12.20 E-mult/lookup
     lookup-side vs pre-registered target ≤8–10. Attribution (matches the
     cost model to <5%): leaf layers ≈2.8 (base-field + round-0 prescale) +
     upper tree layers ≈7.0 (structural — Gruen doesn't touch the fraction
     combines) + tree build ≈1.7 + suffix eq tables ≈0.5. The 8–10 target is
     unreachable in this protocol family within the bandwidth budget:
     helper-column LogUp reaches 2–4 E-mult but adds 16 B/lookup corrections
     (≈48 MB/prefill — rejected); recounting mul-by-7 as shift-add would
     game the pre-registered `emult_equiv = fp2 + base/5` convention
     (rejected). Convention (pre-registered with the user): gate is
     lookup-side only; table side reported raw (L=1) and /12-amortized.
  2. **Full instance cost of record**: 126.5 M E-mult/layer for the 14 LogUp
     instances all-in (≈42/padded lookup, ≈90/budget lookup) — the bare
     fraction-tree floor (12.2) plus table-side trees, deg-3 aux-claim
     folding, in-field packing closures and multiplicity bindings. Chain
     cost outside instances: 2.2 M E-mult/layer. Wall: prove 0.805 s/layer
     ≈ 23.7× native forward on 4 cores (naive ×12 ≈ 9.7 s prefill vs 0.41 s
     native — the GPU-target ρ story is P7's job, not P4's).
  3. **Rectangular padding (pre-registered)**: witness lookup streams match
     the P0 budget exactly (1,412,000/layer, 0%); the LogUp instances run on
     padded domains (3,016,960/layer, 2.14×) — attention instances expand
     causal-packed wires to h_pad(16)×T_pad(128)×T_pad rectangles with valid
     pad pairs, and pow2 padding elsewhere. Exp pad pair = least LUT index
     with output exactly 0 (0x8000 at default scales), so rectangular row
     sums equal causal ones and the denominator rowsum identity
     `deñoms(ρ) = 2^rb·ẽxp(½..½,ρ)` needs no pad correction.
  4. **Multiplicity binding (not in the P0 budget)**: multiplicity vectors
     are authenticated element-wise per instance — 3.87 MB/layer, the
     largest correction stream (boundary auth is 3.07 MB). Tables are shared
     across the 12 layers ⇒ P5 amortizes to **one multiset argument per
     table per model** (÷12), pre-registered.
  5. **No-clamp assert (pre-registered with the user)**: the synthetic
     witness is asserted at runtime to never saturate any requant; the
     saturation side-table is P5 scope.
  6. **Small-vector simplifications (pre-registered)**: LN per-row stats
     (mean, var, rsqrt_in/out — 8·T_pad values/layer) and attention row
     tables (denoms, recip_in, recips — 3·16·T_pad) are authenticated
     element-wise instead of proved via rowsum/centering sumchecks; the LN
     requant lookup, rsqrt/recip LUT membership, denominator=rowsum and the
     hadamard bilinear step ARE proved. `recip_in = denoms >> 6` is bound
     only by element auth of both vectors (P4-DEVIATION(recip-in) in code).
     LN gain/bias are public verifier inputs in P4 (weights private via PCS).
  7. **c_attn is committed on a permuted layout**: the single qkv requant
     instance runs on a T×4096 domain with `col' = third·1024 + head·64 + l`
     (third/head become bit fields; K/V thirds close via boundary MAC
     openings with boolean selectors, q third via the 12 head aux claims).
     Its chained GEMM therefore claims W̃ on the permuted 768×4096 tensor
     (`cattn_permuted`); `layout_gpt2_layer` commits exactly that layout
     (same 2^22 block, offsets unchanged). One claim per tensor holds:
     4/layer, point lengths 22/20/22/22.
  8. **PCS re-projection (measured P3.5 cost model, 0.12 s + 2.3 ms/claim)**:
     49 prefill claims (4×12 + logits) → **0.233 s**; per-response with
     deferred decode ≈ 2×49 claims → **0.345 s** — replaces P3.5's 220-claim
     0.70 s projection (the per-layer wiring delivered lever (a): 1 claim
     per tensor instead of q_avg≈3.4). Measured at layer scale (2^24):
     open 0.041 s, verify 0.007 s. **P6 constraint (verbatim)**: i
     weight-GEMM del decode si differiscono e si provano impilati a fine
     risposta (claims/risposta ≈ claims/prefill), mai claim PCS per-token.
     P5 girerà e2e in modalità committed-W di default.
  9. Boundary auth measured 5 tensors/layer (x_in, K, V, attn/ffn_block_out)
     vs budget's 4 — x_in is the previous layer's output (embed_out at layer
     0), authenticated once per seam in the full model; a single-layer
     report double-counts it. LUTs are Rust-built at synthetic scales; the
     numpy reference + real weight export land in P5.
  10. Causal-mask soundness is a dedicated blind product sumcheck row
     (public maskAbove·eq(τ) table); the reject test is a wires-level
     cheating-prover emulation (library debug_asserts force witness-honest
     provers, so tampering is injected at the derived-wire layer).

- **2026-07-04 (P3.5)**: static weight PCS implemented and measured at full
  scale (2^27 synthetic i16 coefficients — no weight export yet, that is P5;
  PCS cost is data-independent). Decisions and findings:
  1. **Library decision (closes the open "repo evaluation" risk)**: in-house
     minimal Ligero in new crate `volta-pcs` (~700 lines: Goldilocks NTT,
     blake3 Merkle — the only new external dep — ZK opening, batching). No
     external library (Plonky3 / Binius / p3-basefold) provides the delicate
     part, the ZK opening that resolves into a DV MAC (M9); they would only
     supply NTT+Merkle, each ~150 lines here. Binius is binary-field,
     off-target for Goldilocks.
  2. **Opening architecture iterated once, in-milestone**: the generic
     multi-point → single-point reduction (blind sumcheck over 2^27, path A)
     measured **5.8 s** — E-field O(|W|) work dominates everything. Replaced
     by the **row-local multi-eval opening** (path B, pipeline of record):
     block-aligned claims need masked row combinations over only their
     tensor's Ligero rows; all claims share one column-query set and resolve
     via a single Π_ZeroBatch. **0.70 s** (8.4×), no reduction sumcheck.
  3. **Gate FAILED and re-understood**: 0.70 s = 230% of native prefill
     (gate ≤15%), 38% per 600-tok response (gate ≤3%). Attribution: the
     design-note estimate assumed ONE O(|W|) pass at ~native throughput.
     Measured: (1 + q_avg)·O(|W|) `mul_base` passes with q_avg ≈ 3.4
     claims/tensor; the single global pass alone is 0.11 s = 36% (u64 field
     mults are ~3–5× slower than i16 MACs). **Cost model**: opening ≈ fixed
     0.12 s (proximity pass + columns) + **2.3 ms per claim** (block pass +
     mask row). The "~3% amortized" story therefore holds only if
     claims-per-response stays O(prefill count): naive decode adds ~49
     claims/token ⇒ **cross-token claim reduction is a P6 interface
     requirement**, not an optimization.
  4. **Iteration levers (before/with P4–P6)**: (a) fewer claims/tensor
     upstream (share the q=3 RLC opening points where sound: 220 → ~64
     claims ⇒ ~0.35 s, 21 MB); (b) P6 cross-token claim accumulation;
     (c) session-level batching (fixed part shared over k responses);
     (d) NEON/lazy-reduction engineering of the mul_base passes;
     (e) fallback knob: per-user MAC-auth (option B) breakeven is ~1.4
     responses/GB-of-setup at current numbers — still a deployment knob.
  5. **Leakage**: smoke passed (transcript structure identical across weight
     sets, masked rows uniform, columns pad-randomized). Known limitation
     pre-registered: pad=512 covers ONE opening's ≤200 distinct columns;
     repeated openings accumulate column exposure → larger pad or periodic
     re-commit (P7 line item).
  6. **Soundness parameters pre-registered**: rate 0.516, δ≈0.48, Q=200,
     error ≈ (1−δ/2)^Q ≈ 2^-81 (d/3-style analysis would need Q≈312; pad
     keeps hiding headroom). PCS binding is the explicit M9 hypothesis.
  7. Verifier stays cheap (0.12 s incl. 442 NTT encodes); commit one-off
     3.3 s / 2 GB encoded matrix in RAM; peak RSS 7.3 GB (fits 11 GB).
  8. Correlation use: 220 full corrs (claims) + 220 (s_g) + 1 (ZeroBatch);
     opening communication 73.8 MB (u_g rows dominate), vs 30.1 MB auth
     corrections — drops linearly with claim reduction (lever a).
  P4 does not depend on PCS speed; PCS claim-count levers land with P4's
  per-layer wiring and P6's decode design.

- **2026-07-04 (private weights — supersedes the "no PCS" note of 2026-07-03)**:
  the public-weights assumption was implicit and is now retired: the target
  deployment is a provider that does NOT reveal W. Decision (full analysis in
  `docs/private-weights-pcs.md`): static public commitment `C_W` via a
  field-native code-based PCS (Ligero/Brakedown/Basefold family over
  Goldilocks) + **one batched ZK opening per response** resolving into a
  VOLE-authenticated value (never a cleartext `W̃(r)` ⇒ no per-query weight
  leakage). Per-response cost O(|W|) mults ≈ 1–3 % of native work for
  realistic responses, model-size-independent as a ratio — the prover
  advantage does not erode at 20B. Per-user weight MAC-auth (Mystique-style,
  option B) rejected as architecture (O(|W|)/user correction bandwidth,
  ~160 GB at 20B) but kept as a deployment knob. Consequences: new milestone
  **P3.5**; formal phase reopens for one interface lemma (**M9**,
  opening-into-MAC, composing with M3) — open, not yet scheduled; P0 budget
  and P7 extrapolation gain a PCS line.

- **2026-07-03 (plan amendment, pre-P2)**: risk re-read after P1 — the open
  risk is prover *constant factors* (sumcheck + LogUp), not tensor
  authentication (structurally 0.044% of native work, kernel confirmed by P1).
  Two amendments to the plan of record: (1) new **P2.5** — clear-LogUp
  constant-factor spike (synthetic 16-bit LUT, ~10M lookups, real shapes),
  pulled forward from P4, independent of P2/P3, informative gate
  (ns/lookup, E-mult/lookup pre-registered); (2) **P3 gate decomposed** — the
  clear reference sumcheck is timed, and protocol ρ is recorded as
  t(clear)/t(GEMM) and t(blind)/t(clear) separately, so a bad number is
  attributable to sumcheck itself vs IT-blinding (incl. lazy m_r expansion).
  Milestone order unchanged: P2 remains next (P3 consumes it). Note: phase P
  has **no PCS** — DV setting with public GPT-2 weights; a committed-weights
  variant would be a scope change to be logged separately if pursued.

- **2026-07-04 (P2.5)**: clear-LogUp prover constant measured at 23.2
  E-mult/lookup — ~5× the budget's "O(1) ≈ 4–5" estimate, past the 2×
  iteration trigger. Per the informative gate this does NOT block P3; the
  **iteration plan (before P4)**: (a) Gruen eq-factor split (pull eq out of
  the cubic round evals — saves ~1/3), (b) exploit base-field leaf structure
  (α−f has constant c1; first 2–3 layers can run mostly in F_p — the leaf
  combine already does, extend to their sumchecks), (c) rayon over the round
  loops (spike was single-thread; native anchor uses 4 cores, so wall-ratio
  15.6 → ~4 with parallelism alone). Target ≤ 8–10 E-mult/lookup measured
  in P4's real LogUp. Note the *verifier* is already cheap (0.10 s @ 2^23).
- **2026-07-03 (P1)**: naive sequential timing showed ρ<1 (frequency drift on
  the M2 VM); replaced with ABBA paired timing (`time_paired`), which is the
  measurement of record. Criterion benches kept for CIs.
- **2026-07-03 (P1)**: epilogue draws only the mask `r` (8 B ChaCha) at auth
  time — prover tags `m_r` (16 B/value) are expanded lazily at *opening* time
  (P3), not in the GEMM epilogue. Their cost must be counted in P3's prover
  budget, not here.
- **2026-07-03 (P0)**: correction bandwidth re-based from 2 B to 8 B per value
  (7.5 → 30.1 MB per prefill-100). Reason: M5 covers `F_p`-typed corrections
  (subfield of `E=F_p²` is Goldilocks itself); the 16-bit packing claim in
  `sota/initial-brainstorming.md` needs mod-2^16 masks + an authenticated
  carry bit — deferred, not silently assumed.

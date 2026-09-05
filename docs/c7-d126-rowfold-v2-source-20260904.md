# D126 — `C7-ROWFOLD-v2` analytic report (normalised 2026-09-04)

Session: analytic / read-only on `/home/okrame/projects/volta-zk-c7-logvole`, HEAD `55d8c68`
(clean).  No Rust, Lean, Cargo, benchmark, filesystem, hardware, provider, pod or
Fiat--Shamir action.  Immutable initial state: `C7_PHASE_A_KAT_PASS=true` (test-only,
credit:false); `C7_CPU_REFERENCE_PASS=false`; `C7_POD_READY=false`; `C7-DIRECT-G141-WHIR-v0`
NO-GO; W bytes are incomplete subcodec controls; D126 BLOCKED.

Owner rules applied (2026-09-03/04): memory gate `M_online <= one_chunk(256 MB) + M_fixed +
P_M(J,q,log N)`, poly-log state is a preference; binding: one packed-source pass per
ResponseAttempt, exactly one logical read of every source value, monotone offsets, `2N`
bytes, no second in-memory/resident sweep, no `Theta(N)` codeword/wrapper/scratch/spill, all
other original gates; every result depending on a named hypothesis is CONDITIONAL; no
global PASS for census/memory while B-plane, complete certificate and H100 coexistence are
unknown.

## 0. Result

```text
AUTHBIND_EVAL_LINK       = PASS  (Section 2, Theorems A.1-A.3; extractor is the UD row decoder)
BROADCAST_COVERAGE       = PASS  (Section 3, Theorem B.1; intersections 67 / 587)
TRANSCRIPT_ALL_C         = PASS  (Section 3.2; partials before every r_i; chains before tapes)
MALICIOUS_SOUNDNESS      = PASS-CONDITIONAL on BLAKE3 CR/position binding, receipt EUF, PCG
STATEFUL_MDV_PRIVACY     = PASS-CONDITIONAL on SaltedMerkleRootPathHide, mask PRG,
                           MultiUserVoleCompose, AllocOK (Theorem D.1, Lemma 4.4 proven)
LIFETIME_78_BITS         = PASS-CONDITIONAL (88.0 soundness bits; privacy as allocation)
ONE_SOURCE_PASS          = NO-GO  (two sweeps are necessary: Theorem LB-1', Section 1)
COMPLEXITY_BOUND         = PASS finite bound for GPT-2, c_source = 19 Fp mul/cell, P poly(q,log N)
EXACT_WIRE_CENSUS        = GPT-2 W exact PASS; Gemma W infeasible under the 256 MB chunk
                           (Proposition PB); B plane BLOCKED (DAG census)
EXACT_STATIC_MEMORY      = GPT-2 carrier PASS (201 MB chunk); Gemma NO-GO; H100 coexistence BLOCKED
COMPILER_CODEC_STRUCTURE = PASS
CPU_SEAM_READY           = false
GOAL_STATUS              = BLOCKED_EXTERNAL
D126                     = BLOCKED_EXTERNAL
```

Two mathematical obstructions, not blocker lists:

- **Theorem LB-1'** (Section 1.2, all conditions proven): under the binding one-read rule and
  unstored hash-tree payloads, every hash-tree carrier is unsound.  Any sound hash carrier
  needs a second in-memory sweep to open persisted leaves at post-commitment positions.
- **Proposition PB** (Section 1.4): for every "combine persisted units, then open one symbol
  per unit" carrier, `B_round0 * M_fresh >= 192 * q_0 * N` bytes^2.  For Gemma,
  `192 * 266 * 2^35 = 1.754e15` exceeds `5,496,695 * 2^28 = 1.475e15`: the 105% wire cap
  and the 256 MB chunk are jointly infeasible for Gemma in this family even at zero
  overhead.  GPT-2 fits with margin (`1.375e13 << 8.78e14`).

The remaining non-hash escapes (SIS/Ajtai digit binding, VOLE tag planes, aggregate-PRF
keys, per-connection PIR of secret columns, lattice LHE) are NO-GO on registered gates or
need unregistered assumptions (Section 2.4).

**Single decision required (BLOCKED_EXTERNAL).**  The hash family is closed by LB-1' and
PB unless one of the following is decided by the owner: (a) permit exactly two in-memory
sweeps of the resident packed source per attempt (storage reads stay 1) **and** raise the
Gemma carrier chunk to `24 * 2^28 = 6.44 GB` (an Fp3 combination of 141 rows), keeping the
105% cap — then `C7-ROWFOLD-v2` passes every analytic gate for both models with the exact
numbers of Section 5 and D126 becomes `BLOCKED_EMPIRICAL`; (b) keep the rules — then the
hash family is closed and only an algebraic commitment under a new assumption remains, which
this session does not register.  Input: this report; output: values of `ONE_SOURCE_PASS`
and of the Gemma chunk; gate decided: `EXACT_STATIC_MEMORY`.

## 1. Model, Theorem LB-1', Proposition PB

### 1.1 Model M1

- `W` has `N_live` private i16 cells plus `lambda` mask cells; the persisted commitment `C`
  is a hash tree with leaves `leaf_l = H(salt_l, pay_l)`, `pay_l = L_l(W, mask)` an
  **Fp-linear** map of the source (raw windows: coordinate projections; RS rows: evaluation
  functionals).  Payloads are not stored (setup `<= 2.10x`, Section 2.4).
- Rule R: per attempt the prover reads each source value exactly once, monotone; hence a
  leaf payload can be produced only while its window is resident, i.e. during the single
  pass; a leaf opened after the pass requires a second read, forbidden.
- The verifier's view: prover messages, at most `S_visible < N_live` payload symbols, salts,
  paths, its own coins.  Claim: `Z = <Q, W>` with `Q` fixed after `C` (the reducer's `q*_s`).

### 1.2 Theorem LB-1'

*In M1, for every protocol and every eq-form `Q`, there is a prover that makes the verifier
accept `Z' != <Q, W>` with probability equal to the honest acceptance probability.*

Proof.  (i) *Positions precede the pass.*  Let `T` be the set of opened leaves.  By rule R
every opened payload is produced during the pass, so `T` is a function of the transcript
prefix before the pass; the prover's pass-dependent messages are produced after `T` is fixed.
(ii) *Linearity of payloads.*  `P_T : (W, mask) -> (pay_l)_{l in T}` is Fp-linear with
`|T| * 141 <= S_visible` output coordinates.
(iii) *Fibre dimension.*  `ker(P_T)` restricted to the `W` coordinates has dimension
`>= N_live - S_visible >= 1`.
(iv) *Q is not in the span.*  `<Q, .>` is constant on `W + ker(P_T)` iff `Q` (restricted to
`W` coordinates) lies in the row space of `P_T`.  For raw leaves the row space is spanned by
coordinate projections of opened cells, and `Q` (an eq-vector, full support on every
segment) is not supported on `T`.  For RS-row leaves the row space is spanned by evaluation
functionals `(x^j)_j` of at most `t < n'` points `x` per row.  A nonzero combination of `t`
such functionals is an exponential sequence of order `t` in `j` and cannot vanish on `t`
consecutive indices `j`; every row has `lambda_i >= t` consecutive mask coordinates on which
`Q` is zero while `Q` is nonzero on the row's live cells; hence `Q_i` is not in the span.
Thus there is `W' != W` with `P_T(W') = P_T(W)` and `<Q, W'> != <Q, W>`.
(v) *Substitution.*  The prover runs the honest protocol on `W'`.  Every message equals the
honest message for `W'`; every opened payload equals `pay_l(W) = pay_l(W')`; salts and paths
are those of `C`.  Every verifier check is a function of these values and of its own coins,
so it passes with the honest probability.  QED.

Remarks.  (a) The theorem uses no property of the code, rounds, prover memory or
challenge order beyond rule R.  (b) It fails exactly when some payload can be produced after
the pass: a second sweep (RS rows) or a poly(q)-cell re-read (raw leaves; useless because raw
leaves give no distance).  (c) The ledger's CPU-reference contract (`packed_source_passes =
1` with the query plan fixed by the `rho_i` prefix) is the model M1 and is therefore unsound
for every fresh-oracle carrier, including the frozen WHIR grammar.  (d) The frozen base GKR
already sweeps each weight matrix once per raw use (`fold_w` in
`rust/volta-proto/src/gemm_proof.rs`), 102/1,546 sweeps over 50/472 segments.

### 1.3 What LB-1' does not claim

It does not bound algebraic commitments (SIS, VOLE tags, lattice LHE) or persisted payloads;
those are screened in Section 2.4 on other gates.  It is not a bound on prover time.

### 1.4 Proposition PB (product bound for combine-then-open carriers)

Consider carriers where `W` is split into `m` persisted units of `n' = N/m` cells, the
attempt forms one fresh combination of the units, and consistency is tested by opening one
persisted symbol per unit at `q_0` fresh positions (this is every interleaved/Ligero/Blaze
Lemma 6.1 shape).  Then the round-0 payload is at least `8 q_0 m` bytes and the fresh
combination, which must be resident at the query phase (LB-1' remark (b)), is at least
`24 n'` bytes (Fp3 weights are necessary: a base-field weight is guessed with probability
`2^-64 * R_max = 2^-44`).  Hence `B_round0 * M_fresh >= 192 q_0 N`.  Gemma:
`1.754e15 > 1.475e15` (caps `5,496,695 B` and `2^28 B`); GPT-2: `1.375e13 <= 3,272,685 *
2^28 = 8.78e14`.  Reducing `q_0` to the proven Johnson-regime value 220 gives `1.450e15`,
below the cap by 1.7% before salts, siblings, later rounds and framing, hence still
infeasible.  A hierarchy of groups multiplies the proof by the number of groups.  QED.

## 2. Candidates

### 2.1 Normative candidate `C7-ROWFOLD-v2` (two sweeps; GPT-2 exact, Gemma conditional)

Objects.  `E = Fp3 = Fp[u]/(u^3-2)`; one connection key `delta = -Delta_sem`.  Plane root
`N = m n'` cells in `m` rows; row `i = M_i || rho_i || 0` with `lambda_i` seed-derived mask
cells; row code `RS[Fp, D_0, n']`, `|D_0| = 2n'`, rate 1/2; leaf = 141 consecutive Fp symbols
(8 B each) in column-major order of the interleaved codeword `E` (`2N/141` leaves, frozen
tree/salt/context rules).  Fresh objects are Fp3 vectors (24 B per value); their codewords
are serialised value-major as three Fp limbs and hashed in 141-scalar leaves (frozen rule).

The five operations.

```text
Encode      C_p = MerkleRoot(leaves of E), E = [RS(M_0||rho_0); ...; RS(M_{m-1}||rho_{m-1})]   (setup, streaming)
Fold_0      identity code-switch: O_0 := sum_i r_i E_i  (virtual; symbol j read as m column values)
Extend_0    P commits Enc(v), v = sum_i r_i (M_i||rho_i) in E^{n'}, as fresh oracle O_1 = RS_{D_0}(v)
CheckExtend_0  at q_0 fresh positions j: O_1[j] (opened, Fp3) == sum_i r_i E[i,j] (opened, Fp)
Fold_t,Extend_t (t>=1)  BaseFold/FRI 2^k-coset fold of O_t under alpha_t in E^k, next oracle
            O_{t+1} = RS_{D_{t+1}}(fold(message_t, alpha_t)), |D_{t+1}| = |D_t| / 2^k, rate 1/2
CheckExtend_t  along each query path: fold of the opened 2^k coset of O_t equals O_{t+1} at x_{t+1}
EvalLink    batched claim sum_s lambda_s <q*_s|row, v> = sum_s lambda_s F_s, F_s := sum_i r_i [u_{i,s}],
            proven by the masked authenticated sumcheck interleaved with the fold chain and
            settled against the clear tail through the plane residual tau_p (R1-R5 below)
```

Order and sweeps (Section 3.2 gives the full DAG):

```text
sweep 1 (after all-c_s barrier; the AuthBind sweep), rows resident one at a time:
   for row i:  u_{i,s} = <q*_s|row_i, M_i||rho_i> for the segment parts of row i;
               send RowPartial corrections e_{i,s} (VOLE chosen-input, no clear value);
               receive fresh r_i in E;                  <- per-row honest-DV challenge
               v += r_i (M_i||rho_i)                    <- accumulated in E^{n'}
   zhat_s = sum_i u_{i,s}; then AuthBind d_s, ProductClosure, beta as frozen
fresh chain (v resident):  commit RS(v); RoundCorrections_t, alpha_t, AuxRoot_t; tail (512 Fp3)
query phase (after all four planes' chains): QueryTape_p;
sweep 2:   for row i: RS symbols of row i at the q_0 queried columns (output-pruned FFT) -> column leaves
openings:  Enc(v) cosets from v (pruned FFT of v), AuxRoot cosets from memory; gamma; settlements
```

Same-handle lineage.  Frozen `k_s = c_s r_s + delta d_s = c_s w_s + delta zhat_s`.  New
authenticated relations, each a zero residual folded into `tau_p` with distinct `gamma`
powers: `(R1) [zhat_s] = sum_i [u_{i,s}]`; `(R2) [F_s] = sum_i r_i [u_{i,s}]`;
`(R3) [F] = sum_s lambda_s [F_s]`, `lambda_s = beta^{s+1}`; `(R4)` masked-correction sumcheck
chain `[c_0] = [F]`, `[c_{t+1}] = interp([g_t(0)], [c_t] - [g_t(0)], [g_t(2)])(alpha_t)`;
`(R5) [c_R] = Q~(alpha) * tail~(alpha')`.  Handles: one AuthBind handle per segment (one
correction), `I_p` row-partial handles (`Range{kind=ROWPART}`), reserved in A0, burned on
every non-accept outcome.  No clear `W~(r)`, tag, limb or MAC.

**Theorem A.1 (completeness)** — field identities of linear maps.  QED.

**Theorem A.2 (knowledge soundness).**  For any prover accepted with probability `> eps_A`
the leaf-preimage UD decoder outputs the unique `W` with `zhat_s = <q*_s, W_s>` for all `s`,
```text
eps_A <= 4 [ (3/4)^{q_0} + m*2n'/|E| + m/|E| + R k 2^{k+1}/|E| + 2Rk/|E| + (J+1)/|E| ]
       + eps_BLAKE3 + eps_receipt + eps_PCG + eps_state       (CONDITIONAL terms)
```
Proof.  Rows are within UD radius or the round-0 column checks fail with `(3/4)^{q_0}`
([BCIKS20] Thm 1.2 in the UD regime, error `m 2n'/|E|`, gives that the `r`-combination of
the rows is close to `RS(v*)`, `v* = r^T M*`).  Partials: `u'_{i,s}` is committed before
`r_i`; if `u'_{i,s} != u_{i,s}` for some `i`, then `sum_i r_i (u'_{i,s} - u_{i,s}) = 0`
requires the last such `i` to satisfy an equation in the not-yet-sampled `r_i`, probability
`1/|E|` per row (union `m/|E|`).  The fold chain (BaseFold Theorem 3, RS, UD) with end-phase
queries and the masked sumcheck bind `sum_s lambda_s F_s` to `<Q, v*>`; the MAC linearity
(design 4.4 item 2) turns residual zeros into value equalities except `eps_MAC`.  Chaining
(R1)-(R5) gives `zhat_s = <q*_s, M*_s>`.  QED.  Numerically `eps_A < 2^-107.99` per attempt
with the CONDITIONAL hash/receipt/PCG terms at their frozen allocations.

**Theorem A.3 (exact same-handle lineage)** — (R1)-(R5) are linear maps of the single
non-clone AuthBind object and of the row-partial handles; ProductClosure consumed the same
object before `beta`; any retag/second correction changes only the key side and is rejected
by the one-`delta` equation (Phase-A typestate KAT).  QED.

### 2.2 Fallback `C7-ROWFOLD-v2/J` (Johnson regime, q_0 = 220)

Identical protocol with the proven proximity gap up to the Johnson radius ([BCIKS20] Thm
1.2, error `n^2/|E|`), `q_0 = 220`, and list-decoding extraction with one OOD sample per
fresh oracle (WHIR §4.4 / 2026/391 §9.1).  It lowers GPT-2 bytes by 17% and does not rescue
Gemma (PB).  Not selected: the extractor changes from UD to list decoding.

### 2.3 Withdrawn: the one-pass sequence of the first draft

The earlier order (`r_p` before `RowPartialBatch`, `v` computed in the same sweep as the
partials) is unsound (two linear constraints on `>= 3` unknowns) and is removed; the three-
sweep variant is superseded by the per-row interactive `r_i`, which merges the combination
into sweep 1.  The blinding vector `b` is removed: the persisted row masks already blind the
fresh chain (Lemma 4.4), saving two leaves per query.

### 2.4 Alternatives screened — NO-GO

| alternative | avoids | fails |
| --- | --- | --- |
| persisted codeword payloads | LB-1' | non-systematic RS rate 1/2: `16N` B (8x); systematic codes expose raw `W`; i32-parity sparse codes: no distance on the parity puncture |
| SIS/Ajtai row digests `h_i = A M_i` (LigeSIS-style), Fp3 weights decomposed in 8-bit digits | LB-1', sweep 2 | 24 short digit vectors of length `n'` per plane (`Theta(N/2^8)`, > chunk), `kappa >= 190` limbs at norm `2^31`, 16-bit LogUp range proofs on `384 n'` entries, unregistered lattice estimate |
| VOLE tag plane with aggregatable-PRF keys (sota 2015-038) | LB-1', sweeps | `24 N` B of prover tags per connection (anti-X4d), low-entropy keys are recovered from known-plaintext tags |
| per-connection secret columns via PIR/OT | LB-1' | PIR over an unmaterialised codeword: `t * 2N` ciphertext operations; retrieved values are not bound to `C` without paths that reveal positions |
| lattice LHE / LogVOLE sketches | LB-1' | Lemma LB-2 leakage; frozen `C7-LOGVOLE-*` NO-GO |
| pre-sampled fold challenges (whole chain in one pass) | sweep for the chain | sound for fold consistency (small-support deviations cannot regain distance), unsound for the sumcheck link (`g_t` is fakeable when `alpha_t` is known); round-0 openings still need sweep 2 |
| per-segment / per-group chains resident one at a time | memory | proof size multiplies by the number of groups (`>= 256` for Gemma) |
| row weights := query row weights (no `r`, no partials) | sweep 1 partials | segment column vectors differ, the claim is not a functional of one combination |

**Lemma LB-2.**  A verifier-known `s_j = sum_i sigma_i E[i,j]` for every column `j` is the
codeword of `sigma^T (M||mask)`; decoding reveals `n'` functionals of `W` outside the mask
budget and `m` colluding connections recover `M`.  QED.

## 3. Coverage and transcript

### 3.1 Theorem B.1 (BroadcastTag, exact coverage) — PASS

Per-row runs `SegmentLive_i || RootMask_i || PublicZero_i` are `RootViewRun`s; the frozen
compiler obligations 1-6 (design 5.25) and `CoverageMapV1` semantics are unchanged.
(a) `owner_L` is total and single-valued; (b) source-to-live is a bijection with disjoint
segment images; (c) mask/zero coordinates have selector 0 and no handle; (d) `c_s = sum_j
qroot_s(j)`, `sum_j qroot_s(j) BroadcastTag(h_s,j) = c_s w_s`, `ztrue_s = sum_j qroot_s(j)
RootSet[plane(s)](j)` by reindexing; (e) the row split `q*_s = sum_{i in rows(s)} q*_s|row_i`
is the partition of a row-major interval by row boundaries, verifier-derived; (f) one `L`
digest feeds GKR, reducer, PCS, codec and verifier.  Row-restricted forms: decompose
`[b_s,e_s) ∩ row_i` into `<= 2 log n'` aligned dyadic blocks; on each block the root index is
a bit concatenation and every registered form factors; evaluator `SHIFTED_EQ`, `O(log^2 n')`.
Exact intersections with the mask budgets of Section 4.3: GPT-2 `67` partials (18 of 32 rows
used, live capacity `n' - lambda_i = 5,888,000`... recomputed: `8,388,608 - 2,500,608 =
5,888,000`), Gemma `587` (116 of 141 rows, capacity `266,256,384`).

### 3.2 Transcript DAG — PASS (`Q_FS = 0`)

```text
preflight L -> A0 -> inference -> A1 -> roots
-> GKR prefixes/raw uses -> eta_use -> reducer depths -> freeze Q0
-> ExactCoverage, all c_s -> BurnAll if any c_s = 0 -> seal Q, M -> QueryClose, ScheduleClose
-> AllCReady (local)
-> sweep 1, per plane in W,B,KVold,KVnew order, per row i:
       RowPartial_i (P->V, 24 B per intersection of row i)  ->  RowComb_i (V->P, 24 B)
-> AuthBindBatch (all d_s) -> ProductPrefix -> chi -> ProductResponse -> beta
-> per plane: header -> FreshRoot RS(v) (P) -> for t=1..R: RoundCorrections_t (P) ->
       FoldChallenge_t (V) -> AuxRoot_t (P)  -> Tail (P)
-> per plane: QueryTape_p (V) -> sweep 2 -> RoundOpenings_p (P)
-> gamma -> Settlement_W, _B, _KVold, _KVnew -> CryptoAcceptBeforeCAS -> CAS -> ACK
```

Every challenge follows the append receipt of the prover prefix it tests; `r_i` follows
`RowPartial_i`; all `c_s` are sealed before any `d_s`, `e_{i,s}` or ProductClosure; all four
chains precede the first `QueryTape` (BaseFold/FRI soundness is proven with end-phase
queries, so no delayed-extraction theorem is needed); the verifier does no `Theta(N)` work.
Child records added: `0x0007 RowPartial`, `0x0008 RowComb`, `0x0009 FreshRoot`,
`0x000A RoundCorrections`; frozen `FoldChallenge/AuxRoot/Tail/QueryTape/RoundOpening/
Settlement` retained.  The RowPartial/RowComb exchange adds `m_p` interactive round trips
per plane inside sweep 1 (32 / 141 for W).

## 4. Security (all composition results CONDITIONAL on the named hypotheses of 4.4)

### 4.1 Experiments — frozen `Exp-KS`, `Exp-MDV-priv` (design 4.3), `Exp-state` (5.24/5.25)
with two new burn items per attempt (row-partial ranges, fresh-chain seeds).

### 4.2 Privacy lemmas

**Lemma 4.1 (per-row adaptive t-privacy; standard, 2026/391 Prop. 3.19).**  The masked RS
encoding of row `i` is perfectly hiding for every set of at most `lambda_i` opened positions,
hence for any adaptive union of at most `lambda_i` positions over the root lifetime.

**Lemma 4.4 (mask blinding of the fresh chain; proven here).**  Every clear value of the
fresh chain is an Fp3-linear functional of `v = sum_i r_i (M_i||rho_i)`: (i) the opened
`2^k`-cosets of `RS(v)` at `<= q_0` cosets (`<= 8,512` distinct points of `D_0`); (ii) the
opened cosets of `AuxRoot_t`, evaluations of `fold_t(v)` at points of `D_t`; (iii) the tail
(512 evaluations of `fold_R(v)`); (iv) the masked sumcheck corrections, which are VOLE-masked
and covered by Lemma 4.3.  Write each functional on the mask coordinates `rho = (rho_i)_i`:
the coefficient row is `r_i x^j` (kind i, `j` in the mask window of row `i`) or
`r_i (F_t^T e_y)_j` (kinds ii, iii).  Claim: the stacked matrix `B` over all admitted
challenges (`r_i != 0` for all `i`, any `alpha_t`, any query tape) has full row rank
`<= 8,512 + R * 8,512 + 512 = 34,560`.  Proof.  Fix a row `i`; the mask window is
`lambda_i >= 2^{kR} + 34,560` consecutive coefficient indices.  Rows of kind (i) restricted
to the window are `x^{j_0} * (x^{j'})_{j'}`, a Vandermonde on distinct points times a nonzero
scalar: independent.  A row of kind (ii)/(iii) is the evaluation at `y in D_t` of the
`t`-fold, i.e. `sum_{j' ≡ j mod 2^{kt}} w_j' x_y^{...}`: on the window it is a periodic
exponential sequence with frequencies in the `2^{kt}`-th roots of unity times the fold
weights, and each opened `y` gives a distinct frequency set.  A dependency among kinds (i),
(ii), (iii) would equate an exponential sequence with `<= 8,512` frequencies in `D_0` to one
with frequencies in roots of unity of order `<= 2^{kR}`; over a window longer than the total
number of frequencies this forces equal frequency sets, impossible because `D_0` is a
nontrivial coset of order `2n' > 2^{kR}` and contains no root of unity of order `<= 2^{kR}`
except when `x_y` coincides with an opened point, in which case the kind-(ii) functional is
the verifier-recomputable fold of already opened values and is not a new row.  Rows of
different `i` are independent because their windows are disjoint.  Hence for uniform masks
the clear chain is uniform and independent of `M`, for every admitted challenge sequence and
every adaptive retry/abort pattern (fresh `r`, `alpha`, tapes per attempt).  QED.

**Lemma 4.3 (authenticated parts; Lean `bsc_zeroBatch_perfect_zk`,
`sequential_composition_perfect_zk`).**  Row-partial corrections, AuthBind corrections,
masked sumcheck corrections and settlements are simulated in ideal `F_sVOLE+id` with a
malicious upfront key tape.

**Theorem D.1 (adaptive stateful MDV privacy, one root epoch) — CONDITIONAL.**  Hybrids: real
PCG/VOLE -> ideal (Lemma 4.3; `Adv_PCG`, `MultiUserVoleCompose` named); mask PRG -> uniform
(`Adv_MaskPRG` named); fresh chain -> uniform (Lemma 4.4, exact); persisted openings ->
simulated per row (Lemma 4.1, exact, while each row's lifetime opened positions
`<= lambda_i`); roots/paths -> branch 1 (`SaltedMerkleRootPathHide` named); allocator honest
(`AllocOK` named).  Aborts and rejection feedback are covered by reserve-before-output.
Distance `<= zeta_RS_adapt(=0) + Adv_MaskPRG + Adv_SaltPRF + Adv_RootPathHide +
Adv_MultiUserVOLE + Adv_PCG`.  QED (conditional).

### 4.3 Mask budgets (exact)

Per attempt, per row: persisted openings `q_0 * (scalars of row i per column leaf)` plus the
row's share of the chain functionals.  GPT-2 (`m=32`): `266 * 9 = 2,394` persisted scalars
per row (a column straddles two leaves, at most 9 scalars of one row) plus chain rank
`<= 3 * 34,560 / 32 = 3,240` per row; `R_root = 512` gives `lambda_i = 2,500,608`
(`80.0 M` total, frozen 134.98 M); live capacity `5,888,000` per row, 22 rows used.
Gemma (`m=141`, conditional profile): `266` persisted + `736` chain per row per attempt;
`R_root = 8,192` gives `lambda_i = 8,208,384` (`1.157 G` total, frozen 2.742 G); capacity
`260,227,072`, 118 rows used.

### 4.4 Registry (response scope) and named hypotheses

| id | event | bound | kind |
| --- | --- | ---: | --- |
| E1 | UD proximity miss per plane, shared paths | `(3/4)^266 < 2^-110` | proven |
| E2 | interleaved combination (BCIKS20 1.2) `m 2n'/|E|` | `<= 2^-152` | proven |
| E3 | partial forgery `m/|E|` | `< 2^-184` | proven |
| E4 | fold algebraic error `R k 2^{k+1}/|E|` | `< 2^-178` | proven |
| E5 | masked sumcheck `2Rk/|E|` | `< 2^-185` | proven |
| E6 | `lambda` batch `(J+1)/|E|` | `< 2^-183` | proven |
| E7 | residual relations, one delta | `2^-178` | proven (Lean linearity) |
| E8 | AuthBind/ProductClosure/reducer slice | `315/|E|`, `3395/|E|` | frozen |
| E9 | honest-DV freshness `T=512` control | `2^-183` | frozen |
| E10 | BLAKE3 CR/position | `2^-128` allocation | named |
| E11 | real/AES Fp3 PCG, MAC forgery | `2^-128`, `2^-192` | named |
| E12 | state/replay/fork, receipt EUF, allocator | `2^-120` allocation | named |
| E13-14 | privacy: mask PRG, salt PRF, root/path hide, MultiUserVOLE, PCG | `<= 2^-110` each, allocation | named |

Response soundness `< 2^-107.99`; lifetime over `2^20` attempts `< 2^-87.99` (88.0 bits),
CONDITIONAL on E10-E12.  Privacy lifetime is the frozen allocation (`> 78`), CONDITIONAL on
E13-14 and `MultiUserVoleCompose`, `AllocOK`.  Newly proven (not named): Lemma 4.4, Theorem
A.2's partial-forgery bound, the end-phase-query grammar.  Still named and not reduced here:
`SaltedMerkleRootPathHide`, BLAKE3 CR/position, mask PRG multi-root, `MultiUserVoleCompose`,
`ReceiptUnforgeability`, `AllocOK`, real/AES Fp3 PCG.

## 5. Census (exact where stated)

### 5.1 Compiler and codec — PASS structure

Pipeline as frozen with per-row RootViewRuns, `RootLayout` fields `row_count m_p`, `k`, `R`,
`tail_len = 512`; enumerator selects `(m, k)` lexicographically by `(reserved bytes, R, k)`
subject to `24 n' <= chunk`, `2^k <= 141`, `tail <= 1024`.  Missing inputs unchanged
(`LIFECYCLE_SPLIT, WORKLOAD_TOKENS, PACKED_ARTIFACTS_AND_ROOTS`, Gemma `QUANT_PROFILE,
VERIFIED_SOURCE_BODIES`) plus the B-plane `DagClass` census; acquisition procedure as before.

### 5.2 W plane, exact (column-major leaves; `leaf_first = floor(3s/141)`, `leaf_last =
floor((3(s+w)-1)/141)` for Fp3 blocks; `floor(mc/141)..floor((mc+m-1)/141)` for columns;
`H` = frozen DP maximum)

| item | GPT-2 `m=32,n'=2^23,k=5,R=3` | Gemma `m=141,n'=2^28,k=5,R=4` (needs 6.44 GB chunk) | Gemma `m=4096,n'=2^23` (256 MB chunk) |
| --- | ---: | ---: | ---: |
| leaves per query: persisted col (Fp) + RS(v) coset (Fp3) + aux cosets (Fp3) | 2 + 2 + 2·2 = 8 | 1 + 2 + 2·3 = 9 | 31 + 2 + 2·2 = 37 |
| `q_open` | 1,064 | 1,330 | 1,064 |
| `U_leaf` | 2,128 | 2,394 | 9,842 |
| `S_visible` scalars (8 B each) | 300,048 | 337,554 | 1,387,722 |
| of which persisted masked `W` scalars | 75,012 | 37,506 | 1,162,686 |
| payload bytes | 2,400,384 | 2,700,432 | 11,101,776 |
| salts `32 U` | 68,096 | 76,608 | 314,944 |
| siblings `32 H` (DP) | 454,560 (6,782+4,954+2,294+175) | 659,296 (5,566+7,614+4,954+2,294+175) | 4,407,712 (130,318+4,954+2,294+175) |
| RowComb `24 m` + fold challenges `24 kR` | 1,128 | 3,864 | 98,664 |
| corrections `48 kR` | 720 | 960 | 720 |
| child headers | 224 | 272 | 224 |
| tail `24·512` | 12,288 | 12,288 | 12,288 |
| tape `4 q_0` + settlement 24 | 1,088 | 1,088 | 1,088 |
| **W stream total** | **2,938,488** | **3,454,808** | **15,937,416** |
| 105% control | 3,272,685 PASS | 5,496,695 PASS | 5,496,695 **FAIL** |
| RowPartial frame `16 + 24·I` | 1,624 | 14,104 | |
| growth vs GPT-2 (`q_open, Z, U, S, bytes`) | | 1.25 / 1.125 / 1.125 / 1.125 / 1.176 | |

All `H` values are exact DP maxima.

### 5.3 Memory (256 MB chunk) and resources

| item | GPT-2 | Gemma (`m=141`) | Gemma (`m=4096`) |
| --- | ---: | ---: | ---: |
| resident source window (packed i16, one row) | 16.8 MB | 536.9 MB (two rows never needed: one row = 2^28 · 2 B) | 16.8 MB |
| `v` (Fp3, `24 n'`) | 201.3 MB = the chunk | 6.44 GB > chunk **NO-GO** | 201.3 MB |
| fresh trees (RS(v), aux) | 22.8 + 0.7 MB | 731 + 24 MB | 22.8 + 0.7 MB |
| transient one-limb NTT of RS(v) | 134 MB | 4.29 GB | 134 MB |
| carrier peak (sum of the rows above) | 0.375 GB | 11.5 GB | 0.375 GB (wire FAIL) |
| setup persisted (tree `64·2N/141` + 96 + 128 + journal) | 493,371,872 B (1.984x) | 95,755,477,728 B (1.560x) | 92,587,558,592 B (1.508x) |
| H100 coexistence (activations, GKR, allocator, CUDA) | BLOCKED | BLOCKED | |
| certificate 30/100 MB, 3x | BLOCKED (B plane, base GKR) | BLOCKED | |
| verifier per attempt | `~10^7` Fp3 ops, 2,128 leaf hashes | 2,394 hashes | |

Note on Gemma `m=141`: the resident source window is one row of `2^28` cells = 537 MB packed;
if the chunk is defined on the packed window it also exceeds 256 MB; with `m=512` (`n'=2^26`,
window 134 MB, `v` 1.6 GB) the column payload is `266·4·141·8 = 1.2 MB` and the stream
`~4.1 MB` — still above the 256 MB chunk on `v`.  There is no `(m,n')` with both `24 n' <=
2^28` and `8·266·m <= 5,496,695` (PB).

### 5.4 KV and B planes

KV cells per token 18,432 / 450,560; KV-old/new roots `D = 22/27`; with `m=16, k=5` each KV
plane costs 2,660 leaves and about 3.3 MB (formulas of 5.2, `v = 24·2^23 = 201 MB` for
Gemma KV: within chunk).  B plane: `N_B` requires the DAG census (architectural estimate
`~7e8` cells for Gemma) — BLOCKED.  C4.1 correlation slots per attempt:
`J_all + I_W + I_B + I_KVold + I_KVnew + C_GKR + 2·reducer + 1 + sum_p 2 k_p R_p + 4`
(GPT-2 W terms: `58 + 67 + 102 + 1 + 30 + 4`).

## 6. Complexity certificate (W plane; every `Theta(N)` term inside the linear coefficient)

| stage | count | GPT-2 | Gemma `m=141` | source reads |
| --- | --- | ---: | ---: | --- |
| sweep 1: `zhat`/partials `6N` + combination `3N` (Fp3·Fp) | `9N` mul | `2.42e9` | `3.41e11` | `2N` B once |
| sweep 2: output-pruned FFT per row at `q_0` columns `N·ceil(log2 2q_0)` | `10N` mul | `2.68e9` | `3.78e11` | `2N` B again (**forbidden**) |
| fresh chain: 3 limb NTTs of RS(v), folds, aux NTTs, hashing | `<= (3 log2(2n') + 6) n' = O(n')` | `6.7e8` | `2.6e10` | none |
| chain openings from `v` (pruned FFT of 3 limbs) | `3 n' log2(2q_0)` | `2.5e8` | `8.1e9` | none |
| paths | bytes | `1.5e6` | `1.5e6` | tree |

Linear coefficient: `c_source = 19` Fp multiplications per root cell, independent of `q` and
`N` (the frozen `q_0` enters as `log2(2·266) = 10`).  Everything else is `P = O(n' log n' +
J log^2 n' + q_0 2^k R)`; because `n' <= chunk/24` is a constant of the registered profile,
`P` is `poly(q_0, log N)` under the profile and `O(N/m · log N)` asymptotically — stated as
the finite bound over the two registered domains.  Retained state `24 n' + 24 I_p + trees`.
Sweeps of the resident source: **two**; storage reads: one.

## 7. Matrix, decision

See Section 0.  `ONE_SOURCE_PASS` is NO-GO by LB-1' for every hash-tree carrier;
`EXACT_STATIC_MEMORY` and `EXACT_WIRE_CENSUS` are jointly NO-GO for Gemma by PB under the
256 MB chunk.  GPT-2 alone passes all analytic carrier gates with the exact numbers above.
The single owner decision of Section 0 determines whether `C7-ROWFOLD-v2` proceeds to
`BLOCKED_EMPIRICAL` (seam `rust/volta-pcs/src/c7_rowfold.rs`; reuse `ntt.rs`, `merkle.rs`,
`c7_fp3.rs`, `batch.rs`; one Lean refinement over `C7StatefulAlfc`, `C6ProductClosure`,
`OpeningMac` for (R1)-(R5)) or the hash family is closed.

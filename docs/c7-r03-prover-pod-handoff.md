# C7 R0.8e — secret-point butterfly delayed-opening handoff

**State:** `C7_R08E_SPBT_REDUCTION_PASS_DELAYED_OPENING_NO_GO`.

This handoff prepares the order, evidence and stop rules for later C7 work.
Policy 3 remains terminally rejected under its registered gates.  Policy 2 is
active: only masked PCS answers within a cryptographically enforced root-wide
horizon may be public and the terminal evaluation remains VOLE-authenticated.
Strict-UD RS is retained only as an algebraic/security control; its prover is
forbidden.  Both bounded 1.05 closure screens are NO-GO.  R0.8a gives the
tournament two roles: published constructions are exact-cost
baselines/controls, while a co-designed C7 shared circuit is the main research
line. It earns no credit before its four-part screen passes. R0.8b adds only a
carrier-independent policy-2 reference: exact keyed BLAKE3-XOF addressing,
public salted BLAKE3 leaf/tree, canonical one-leaf codec, nonrefundable
attempt accounting, Fp3 terminal and in-memory KV CAS. Its tiny two-leaf test
passes, but it is not a PCS, durable allocator or privacy theorem. Rate 1/2,
`k0=4`, one packed root,
logical `g=141` and
interactive `Q_FS=0` remain fixed.  Fp3 certifies 153.173 response bits and
133.173 after `R_max` on the algebraic-gap axis.  Its g141 opening subcodec
passes all four 1.30 query-growth gates, but the complete codec, malicious-DV
privacy theorem and admitted numeric root capacity remain open.  The corrected
root/codec fixed point makes the selected one-scan generator a terminal gate:
direct evaluation is qN, persistent or materialized codewords fail setup or
memory, and no exact shared circuit survives.  The current RS realization is
NO-GO and no carrier is admitted. The co-designed coset, persisted-parity
and bounded-tail causal shortcuts are also NO-GO for their recorded
soundness, 5x-setup and distance reasons. The RS dimension control also rejects one root for all `R_max`
attempts.  The main root-mask line now persists one private 256-bit seed per
root and declares privacy computational; explicit uniform coefficients remain
the baseline.  `Adv_RootMaskPRG_multi` is part of the 78-bit lifetime budget,
but its concrete primitive/work bound is still open.  Refresh remains untested.
The repository's mock ChaCha8 stream is rejected for this role; AES-128-MMO
and the non-default BLAKE3 GGM path remain quarantined outside their registered
16-byte WYKW node-expansion scope until a C7 multi-root bound exists.
Keyed BLAKE3-XOF is the primary performance/parallelism candidate and the
frozen 64-KiB KMACXOF256-v1 codec is an unpromoted high-margin control.  The
former has only an official 128-bit general target, leaving at most 18 bits of
loss before C7's `2^-110` PRG reserve; neither candidate is admitted until its
exact multi-root bound passes at real `Q_mask_words`.  Failure may reduce the
attempts per root, never the 78-bit connection target.
The owner authorizes `R_root=512/8192` for GPT-2/31B only as a computational
fallback variant,
with a separate 1/8 lifecycle reserve and two fully charged setup seeds.  Their
worst-case `Q_mask_words` caps are 1,619,771,904/32,902,225,920; both fail a
linear `Q/2^128` BLAKE3 proof form at the mainline 110-bit gate.  Across a
global `2^20` fallback horizon, `K_model=2048/128` and model-wide words are
3,317,292,859,392/4,211,484,917,760.  The known mask terms reach
86.407/86.063 bits.  Adding all registered other-term target caps preserves
those rounded values and passes 78 as an allocation, but achieved advantages
remain nonnumeric and the variant remains unadmitted.
The owner confirms that this `2^20` cap is global across every connection.
R0.8 also compiles, but does not promote, `C7-RM-KMACXOF256-v1`: independent
64-KiB chunks preserve ordered CPU/SIMT bytes with 65,848 B per worker and no
persistent mask/codeword.  Two-seed setup controls are 12.958/263.218 GB and
95.699M/1.944B Keccak-f permutations.  A conditional ideal-permutation screen
reaches 152.992/152.647 bits, but the adaptive multi-key reduction,
fixed-Keccak advantage, online one-scan mask-contribution schedule and setup
measurement remain missing.  Current challenges stay interactive with
`Q_FS=0`.  For a future separately budgeted FS design, KMAC is preferred when
margin dominates; BLAKE3 is preferred for throughput only under a tightly
preregistered `Q_FS`.
Adding the same other-term targets gives a conditional 107.415-bit complete
allocation, not a security result.
This document authorizes no PCS prover, SIMT kernel, provider
contact or pod run.  The protocol authority remains
`docs/c7-stateful-authenticated-lfc-design.md` and the active capsule in
`docs/prototype-status.md`.

R0.8c names `C7-DV-SPQ-v0` as the main co-designed research candidate. Its
ideal root holds secret shares, never a clear value, of `F(tau)` and its online
target is `F(tau)-v=(tau-r)Q(tau)` under the shared-`Delta` Fp3 MAC. The
conditional algebraic screen leaves 155/144 bits for the proposed GPT-2/31B
root lifetimes and 135 bits after four roots over global `R_max`; it is not a
security theorem. R0.8d supplies an exact conditional one-scan bridge from the
packed `eq` functional, but rejects its composition with the current public
sequential blind-GKR transcript. Admission still requires a sound operator
transcript bridge, same-`F` enrollment, sublinear-wire malicious
`OpenQuotientIntoMac`, persistent-share import, complete stateful privacy and
an exact codec/resource row. Known algebraic-PRF, OLE/NIIP, Merkle-quotient,
public-power, finite-pool and coset routes fail or remain quarantined for their
recorded setup, wire, scan, challenge-order or theorem gaps.

The exact R0.8d identity is
`eq(r(t),j)=t^j/product_k(1+t^(2^k))` for
`r_k(t)=t^(2^k)/(1+t^(2^k))`. It leaves each packed segment as a raw
univariate coefficient vector and conditionally permits one reverse packed
scan with `N+O(J log N_max)` work and no model-sized transform. It receives no
carrier credit. Public sequential challenges on this curve are
constructively unsound: a lower coordinate reveals future higher powers,
while an adjacent lower power has a two-point square-root fiber. The monic
quadratic through those two points has `P(0)+P(1)=1`, so a malicious prover can
carry a false sumcheck gap and erase it in a legal degree-two round. Any
coordinate order eventually exposes a deterministic ascent or an adjacent
descending pair. Independent challenges, projective basis, full or bounded
univariate skips and opaque challenges supply no complete escape row for the
separately recorded reasons. The current curve/public-GKR composition is
NO-GO; the secret-point primitive remains quarantined research.

R0.8e selects `C7-SPBT-v0` as the main reduction candidate, not as a carrier.
For each ordinary independent GKR coordinate it computes
`Y=(1-r)E+rO` and `Z=E-O`.  The pair matrix has determinant `-1`, so the
recursive output `(Z_1,...,Z_n,y)` is an invertible `M`-coefficient transform
with `y=MLE(W,r)`.  The unrolled degree-`<M` identity is

```text
P_0(X)=D_n(X)y
      +sum_l D_l(X)c_l(X)Z_(l+1)(X^(2^(l+1))).
```

Budget v27 checks the identity and inverse exactly.  If all transform data is
fixed before `tau`, every `tau`-derived query is then fixed before the later
response-wide `beta`, and the algebraic lifetime margins are about 144/137
bits for GPT-2/31B.  A binary carry stack computes the transform
in one monotone packed scan with `M_total-J<2N-J` butterflies and logarithmic
frontier state.

The current realization is nevertheless NO-GO.  `tau` before the transform
root is unsound; retaining the typed dense transform costs `16*M_total` bytes,
at least 9x packed including source; recomputation is a second scan; keeping
`tau` hidden requires a new malicious streaming inner product/OPE into MAC
with sublinear wire and no per-coefficient corrections.  Raw Merkle sampling
has no distance, a rate-1/2 wrapper restores the rejected full codeword, and
two-party sign/square-root orbit preprocessing is at least 25x packed.  This
retains the exact reasons and prevents a heavy XD4-style setup from entering
through SPBT.  `C7-DV-SPQ-v0` is now only the quarantined terminal primitive
for a future delayed-opening carrier.

Checkpoint verification is scoped. Both budget-v27 invocations, the focused
C7 seam, its standalone rustfmt check and `git diff --check` pass. The full
workspace retains one committed out-of-scope C6 source-guard failure in
`native_persistence_source_guard_bypasses_hidden_u_owner`; neither failing
file is part of the C7 diff. This checkpoint does not repair or conceal it.

An eventual online-only process is permitted as a design boundary, not an
implementation: setup must finish and verify under the existing disk/wall
caps before immutable activation; online access is read-only; the full attempt
is reserved before dependent output; the source is read once in the manifest
direction; and every abort burns its slot, masks and correlations. No online
prover is authorized now.

## 1. Authorization boundary

- Local work is limited to the policy-2 design, theorem and executable analytic
  census plus the carrier-independent tiny BLAKE3-XOF/leaf/codec/budget/Fp3/KV
  conformance fixture. Selecting a backend and its
  exact counts requires a recorded design checkpoint before prover work.
- Mainline numeric `Q_root/R_root/K_model/D_model` is forbidden until one coherent
  field/domain/codec/security-amplifier row has a complete provenance-tagged
  Pareto vector.  The sole exception is the explicitly labelled, unadmitted
  BLAKE3 fallback screen above; it grants no implementation or mainline credit.
  The closed strict-UD all-fold audit remains a control baseline; it does not
  authorize an RS prover.  The Fp2 row failed, so the owner
  selected Goldilocks Fp3 with a direct three-Fp-limb terminal/MAC and retained
  78 connection bits.  Two Fp2 repetitions are fallback only and interactive
  PoW remains quarantined.
  The compiler envelope fixes one flat packed weight root, starting rate 1/2,
  first fold `k0=4` and dense logical `g=141`.  It does not select the
  constant-`k=4` tail.  Pure-width search, actual cross-round sharing and the
  bounded different-code-switch set are closed under the original 1.05 gate.
  The selected Fp3 opening subcodec compiles
  `(q,Z,U,S)=(831,29192,1662,234342)/(1055,33848,2110,297510)` and all four
  ratios pass 1.30.  Exact path and known opening bytes are counted, but
  non-oracle/receipt frames remain fail-closed.  Proof wire separately uses
  105% as target with a
  preregistered 125--150% exploratory cap conditional on complete 35/115-MB
  and 3.5x limits.  Setup keeps 2.00/2.10 target/baseline and adds a
  conditional 3x ceiling with absolute disk/setup-wall/refresh-wall caps.
  One-scan and security gates do not change.  Segmentation, another base field
  and persistent row padding neither waive nor inherently repair those gates.
  The bounded online screen rejects the current strict-UD RS realization.
  The authorized tournament may admit only a genuinely new shared
  code-switch/circuit with exact `O(N+poly(q,log N))` accounting and every
  existing gate. Published rows are baseline/control evidence only. The
  co-designed main line must first provide its complete relation/codec, exact
  resource census, stateful soundness/privacy bridge and one-scan proof. SPBT
  supplies only the relation and transform-only scan; its delayed opening,
  codec and privacy rows remain false. Only
  then may the owner authorize a tiny CPU prototype. This does not authorize
  another pure-fold search or any prover.
- Before the first attempt-local provider response byte whose distribution
  depends on `W` or its oracle epoch, the model-owner/provider's authoritative
  global allocator for the complete ordered `omega` root set must
  durably reserve the fixed plane-charge vector and its declared census
  profile.  Its authenticated reservation/assignment receipts, profile and root-set digest enter the
  canonical transcript.  The already-public root is a baseline view element whose
  cross-world replacement is charged to the root-hiding theorem.
  Accept, abort, crash,
  timeout and retry all consume the complete reservation; no suffix is
  refunded or reused.
- The root-wide allocator aggregates every connection, identity, failed
  attempt and colluding designated verifier.  Per-user quotas and rate limits
  may mitigate exhaustion attacks but never replace this counter.
- Each authenticated receipt binds a receipt-free request containing the
  complete connection/nonce/MAC-domain/charge context; appending the receipt
  derives the session binding.  Before emitting receipt/seed commitment the
  provider CASes `Reserved -> InFlight` and caches that first reply.  Replica
  duplicates may return only the cached byte-identical reply for the exact
  transcript state; divergent challenges fail before new witness-dependent
  bytes.
- Exhaustion seals the root; it does not automatically reset the budget.  A
  later rotation needs fresh independent masks/salts, a same-weights bridge,
  a bounded root-epoch/lifetime composition and one atomic activation.  Old
  and candidate epochs reserve typed outbound/inbound/init charges before any
  root/bridge byte; abort burns both, seals the candidate and consumes its
  `K_model` index. Only the weight-epoch counter rotates; the separate
  state-plane ledger and every K/V high-water survive byte-identically.
- Before the first accepted predecessor root is disclosed, `InitKVState(s0)`
  must create and charge its durable map entry.  A carried predecessor without
  that authenticated live entry rejects before a new response.
- No optimized SIMT kernel or GPU scaffold is authorized before the ledger
  records `C7_CPU_REFERENCE_PASS`.
- A complete GPT-2 E2E is never local.  It remains pod-only.
- Pod contact requires both a prior ledger transition to `C7_POD_READY` and a
  later explicit owner GO naming the concrete run.  Readiness is not GO.
- No full-model component benchmark can substitute for the first complete
  serialized case or receive E2E credit.
- Production/provider synchronization uses a clean GitHub HTTPS push/pull and
  exact SHA only.  No `gh`, SSH Git, SCP/rsync, repository archive or exported
  credential is admitted.  Generated weights/setup remain pod-local.

## 2. Gates to `C7_LOCAL_READY`

Every row is fail-closed.  The opening row is **failed/NO-GO** for the RS
control; the dual-track tournament is open but has no admitted entrant. The
co-designed line has no credit and no `BatchOpenBlocks` CPU authorization.
The passing tiny policy-2 seam is component evidence only.

| Gate | Required evidence |
| --- | --- |
| concrete crypto | the reference implements the exact 90-byte `C7-RM-B3XOF-v1` descriptor, six addressed rejection draws, domain/position-bound public salted BLAKE3 leaf/tree and `1296+32h` one-leaf frame. This is codec/KAT evidence, not a BLAKE3 security reduction. Collision binding does not supply root hiding. Root-mask PRG, salt PRF and VOLE PCG are distinct. The unpromoted KMACXOF256 alternative has an exact 64-KiB chunk codec/resource census but no admitted adaptive multi-key reduction. The root-attempt count is reduced if both fail; the 78-bit target cannot move. BLAKE3's stated 128-bit target leaves at most 18 bits of total loss before the `2^-110` component reserve, and neither candidate has an admitted exact multi-root bound. Existing `FpStream`/ChaCha8 is rejected as a mock with unbounded sequential rejection; AES-128-MMO and the non-default BLAKE3 GGM are quarantined because their registered 16-byte WYKW node-expansion role supplies no C7 addressed-mask/multi-root theorem. Distinct `Q_CR/Q_hide/Q_saltPRF/Q_mask_words`, adaptive root/path hiding, `C7-OnlineMDVViewRefine`, joint adaptive t-query ZK, multi-user VOLE/MAC, real PCG/VOLE and the authenticated terminal theorem remain named missing premises; Poseidon2 private-leaf checking is not required by policy 2 |
| canonical compiler | exact causal sampling prelude, response relation and serialized schedule; complete ordered `omega` descriptor, profile/root-budget IDs and authenticated reservation receipt fixed in the prefix; every allowed clear answer is typed as a masked symbol of a declared ZK alphabet, while the terminal evaluation has no clear codec; interleaved rows serialize densely across fixed g141 leaves with every touched leaf charged and no persistent row-alignment padding; one terminal point per physical segment and reject-before-correlation on every mismatch |
| root budget | exact plane-tagged `q_attempt`/`q_response` plus `q_init/q_rotate_in/q_rotate_out` vectors and fixed `(u_W,u_B,u_KV_old,u_KV_new,u_init,u_rotate_in,u_rotate_out)` charges; `u_init+sum u_W+sum u_rotate_in+sum u_rotate_out<=Q_root` componentwise, with lifecycle reserve preserved before service; weight-epoch `Q_root`/`R_root`, per-attempt `Q_B[a]` and per-created-K/V-root `Q_KV[s]`; zero lifecycle charge only from an authenticated-only theorem; `InitKVState(s0)` before first disclosure; durable weight ledger separated from boundary/KV state ledger; every proposed successor is charged, then sealed on abort or keeps the same counter after acceptance; receipt-free request binding plus single-session receipt state machine reserves all components before the first reply, and a no-extension assignment CAS binds pre-burned slots to new roots before disclosure; both old/new rotation records reserve before any bridge/root byte; abort/retry burns and seals every disclosed candidate, which consumes `K_model`; no refund, global aggregation across connections/colluding verifiers and stop-admit rotation carrying state maps byte-identically plus a private same-weights bridge. Proposition 3.19 requires one random coefficient per protected RS query. The conservative current-tree ceilings are 43/11,876 attempts; one root for all `R_max` attempts is NO-GO. These are not admitted service lives until the interleaved g141 load map, lifecycle reserve, privacy margin and numeric PRG bound are proved |
| opening schedule | the GPT-2 root/codec fixed point raises its dimension to `2^28` and schedule to `[4,5,3,3,3,4]`; Gemma stays at `2^35`. The g141 subcodec has `(q,Z,U,S)=(831,29192,1662,234342)/(1055,33848,2110,297510)`, growth 1.269555x/1.159496x/1.269555x/1.269555x, so all four 1.30 gates PASS. Sibling caps are 20,997/39,843. The tiny one-leaf codec test passes but instantiates no code. The bounded online screen finds no complete one-scan RS/co-designed row: direct RS is qN; persistence/materialization fail setup or memory; one structured coset has only one soundness hit and independent amplification restores `tN`; rate-1/2 persisted Fp parity starts at 5x; bounded-tail causal streaming loses distance. The tournament has no entrant and `C7_CPU_REFERENCE_PASS=false` |
| setup | logical `g=141`; selected packed i16 + rate-1/2 compact tree + 64-B metadata + 32-B seed is 491,686,208/92,844,619,328 B, or 1.982606x/1.505927x. Complete codeword persistence would total 4,786,653,504/642,600,433,216 B (19.301x/10.423x) and is rejected. Seeded geometry-only 2.00/2.10/3.00x attempt ceilings remain 616/616/1,761 and 11,876/127,367/127,367; explicit uniform baseline is 43/43/134 and 11,876/11,876/25,596. KMAC two-seed streaming controls remain 12.958/263.218 GB and 95.699M/1.944B permutations. Setup target/hard caps are 900/990 and 5,400/5,940 s; refresh is separate, untested and uncredited. Setup remains false; no X4d-scale plane, codeword or model-sized scratch is allowed |
| certificate | the Fp3 opening subcodec counts payloads, 256-bit salts, exact compact multiproofs, interactive challenge/index frames, auxiliary roots, direct-send tail and a three-limb terminal frame: 2,605,740/3,729,724 known bytes. These fit the 105% weight-wire targets only in isolation. Strict-UD non-oracle sumcheck/OOD messages, authenticated `omega`/profile reservation and plane-assignment receipts, and root-hiding capacity metadata remain unknown, so full reconciliation and the complete 30/100-MB, 3x and exploratory gates are false |
| security | one paired-history model/root-lifetime adaptive malicious-DV game must cover all connections/MAC domains, collusion, concurrency, selective abort and every byte prefix; `D_model` includes weight/KV init, responses and rotations, with burned suffixes in each `J_d`; the carrier-specific `C7-OnlineMDVViewRefine` must reduce the complete codec view to its bounded adaptive queries plus the authenticated terminal; allocator privacy is conditioned on `AllocOK`; current `Q_FS=0`. Mainline root-mask privacy remains `Adv_RootMaskPRG_multi + K_seed_attempts*epsilon_rejection <=2^-110`. The fallback pins one global `2^20` horizon and conditionally reaches 86.407/86.063 bits; adding the owner-approved six `2^-110`, two `2^-120` and exact-refinement allocation still passes 78, but achieved terms are nonnumeric. Frozen KMAC-v1 conditionally reaches 152.992/152.647 PRG bits and 107.415 complete-allocation bits, but is unpromoted pending the exact adaptive multi-key/fixed-permutation reduction. BLAKE3 remains primary. Future FS chooses neither now: KMAC favors margin, BLAKE3 throughput only under tightly preregistered `Q_FS`. Fixed-point Fp3 certifies 160.011/153.173 response bits and 140.011/133.173 after `R_max=2^20`; its Rust codec/KAT and carrier-independent shared-`Delta` equation test pass, but full security remains false pending carrier/PCS/PCG/VOLE refinement, event registry, generator theorem, achieved privacy terms, receipt/transcript soundness and malicious-DV theorem |
| SIMT, if used | only after CPU pass; bit-exact leaves/root/multiproof/MAC/transcript/certificate/journal plus reconciled disk, H2D/D2H/D2D, RSS/VRAM, padding, launch and synchronization counters |
| lifecycle | two incremental responses, accepted predecessor/successor K/V, real finite PCG using only consumed profiles, abort burn and atomic promotion; rotation seals admission, resolves/burns all outstanding receipts, privately proves same-`W`, then atomically cuts over |
| verifier | canonical serialization, reload and full ordinary-CPU verification; mutation, replay, fork, truncation, reordered-prefix and configured-count-plus-one failures |

The four original query quantities are deliberately not one minimum.
`q_attempt[p]` is the fixed maximum census vector for each W/B/KV plane;
`q_response[p]` is the census
actually serialized by an accepted response; `q_init/q_rotate_in/q_rotate_out`
cover weight-epoch lifecycle views; `Q_root` is the total charge covered by
the root-wide privacy theorem; and `R_root` counts durable response-attempt
reservations, including failures and selective aborts.  With one fixed profile,

```text
u_attempt = (u_W,u_B,u_KV_old,u_KV_new)
F_omega = u_init + A_rotate_in*u_rotate_in + A_rotate_out*u_rotate_out
spent_root = F_omega + attempts_reserved*u_W <= Q_root
q_response[p] <= q_attempt[p]                     # componentwise
R_root <= floor((Q_root-F_omega) / u_W).
```

The formula requires `0 < u_W <= Q_root`, fixed finite lifecycle-attempt caps
and componentwise reserve. Every nonzero other component must fit its separate
`Q_B/Q_KV` horizon. A profile that cannot reserve init/lifecycle plus one full
response is invalid. Zero init/bridge charge needs a concrete authenticated-only
zero-visible-query theorem, not an empty ledger cell.

The compiler defines a query atom in the exact ZK alphabet.  Opening a
141-scalar leaf for one sample charges 141 atoms unless the cited theorem
treats that complete block as one alphabet symbol.  Merkle siblings charge no
query atoms but do charge path/hash bytes.  Every attempt therefore records a
vector—not a scalar substitute—of logical PCS samples, visible masked
symbols/limbs, unique leaves, exact multiproof sibling nodes and attempt
reservations, both per transcript and as a per-plane union.  Proof size limits
the per-attempt vector, privacy limits `Q_root/Q_B/Q_KV`, setup limits root
construction/rotation, and online resource gates limit work; their units and
tolerances are not transferable.

The smallest valid local case must execute the whole lifecycle twice.  A
mock-PCG, component-only, analytic or public-WHIR result remains
`credit:false` and cannot establish `C7_LOCAL_READY`.  The future CPU reference
precedes that case and by itself earns no lifecycle/E2E credit.

## 3. CPU-first ladder and SIMT contract

The only currently admitted local executable is the non-PCS seam:

```text
source ~/.cargo/env
cd rust
CARGO_INCREMENTAL=0 cargo test -p volta-pcs \
  c7_policy2_reference::tests::tiny_policy2_codec_budget_terminal_and_state_seam \
  -- --exact
```

It must report exactly one passing C7 test. It creates no benchmark record and
cannot set `C7_CPU_REFERENCE_PASS` or `C7_LOCAL_READY`.

1. Select a policy-2 PCS only after compiling its exact root-wide privacy unit,
   query counts, public salted-Merkle wire bytes, algebraic amplifier and
   soundness floor, setup and rotation schedule.  A query answer count that
   grows materially with `N` fails even if its prover is fast.
2. Implement only the smallest CPU reference for a surviving structured
   algorithm and tiny canonical fixtures.
3. Record `C7_CPU_REFERENCE_PASS` only if code-derived
   `c_source*N+poly(q,log N)` and exact counters agree.
4. Only then implement the admitted SIMT stages and prove byte-exact
   CPU/SIMT equivalence.
5. Only then run scaled local integration; no complete GPT-2 locally.

R0.5 executed the earlier structure screen and a CPU fixture for the one-stage
RA dense exception.  Its counters
and tiny differential test pass the online algorithm shape, but its code
distance and streaming ordered-root gates fail.  Therefore step 3 did not
occur and steps 4--5 remain blocked.  A working component is not a passing PCS.
Its source is a borrowed `&[i16]`, so the one-pass/`2N` values are logical
access counts, not filesystem, RSS or `VmHWM` measurements.

The policy-2 CPU report must additionally prove that every query answer was
fixed by the canonical interactive schedule, came from the committed masked
oracle and was charged before disclosure to the root reservation.  It must
assert one source open/pass, monotonically increasing
offsets, exactly `2*N` packed bytes, no reopen/backward seek, no full codeword,
expanded weights or model-linear scratch, and live memory bounded by
`chunk+140 symbols+poly(q,log N)`.  It separately reports source/query
operations, Fp/Fp2/Fp3/hash/AES/VOLE/MAC/leaf/reduction work, host disk traffic,
scratch and syncs, RSS/`VmHWM`, output/certificate/transcript bytes.  `N,q`
fixtures reconcile the formula; timing trends alone do not pass.

After the CPU pass, reports add per-phase H2D/D2H/explicit-D2D,
device-generated/zeroed bytes, VRAM/pinned peaks, allocation/launch counts,
and synchronizations by reason and wall.  Logical `g=141` is immutable.  Any
wider device tile is temporary zero padding with zero persistent,
`LeafCom`-input, certificate and transcript bytes; its work and peak are
measured.  CPU and SIMT must match masked leaf payloads, opened public salts,
digests/root/multiproof, exact finite-fixture PCG/VOLE values and consumption,
handles/corrections, correlation schedule, every transcript frame/challenge,
all selected Fp2/Fp3 limbs, certificate, CPU-verifier result and journal transition.
Production records store only secret-free digests/counters for internal values.

Any second scan, `qN`, full codeword, model-sized scratch, unassigned transfer,
unclassified barrier or transcript/correlation-order change fails.  Reuse the
existing transcript, correlation-audit, backend-stat and RSS measurement seams;
do not reuse an X4/C6 oracle/backend or add an empty C7 scaffold.

## 4. Required create-new evidence

Do not create empty schema scaffolding.  Once a concrete compiler exists, its
single run-of-record directory must contain create-new artifacts covering:

```text
compiler manifest       layouts, segment IDs, points, roots and transcript order
setup manifest          persistent/temp/refresh bytes and build resource counters
root budget manifest    complete omega/root-set and profile digests, authenticated
                        receipt-free request binding plus single-session
                        receipt lifecycle/cache schema, privacy
                        unit, plane charge vector, q_attempt, q_response,
                        q_init/q_rotate_in/q_rotate_out and typed lifecycle
                        charges/reserves, Q_root, R_root, per-plane Q_B/Q_KV horizons including
                        aborted successors, budget-map high-waters, assignment
                        receipt, InitKVState and rotation carry-forward heads,
                        D_model across init/response/rotation domains, J_d including
                        burned lifecycle correlations, and K_model including
                        disclosed failed candidates
query census            plane-tagged logical samples, masked symbols/limbs, unique leaves,
                        exact sibling/path nodes, q_exposed and attempts; Q_FS=0
certificate census      six B_* components with every byte assigned once
security registry       named theorem/hypothesis, scope, repetitions and epsilon
resource report         passes, bytes read/written, peak RSS/device and wall phases
lifecycle journal       global omega reservation/receipt/high-water mark,
                        Reserved/InFlight/Burned/Accepted CAS and cached replies,
                        W/B/KV maps, pre-burned slot assignment before root
                        disclosure, InitKVState before genesis disclosure, full
                        burn, outstanding-at-seal resolution, private same-W
                        bridge, byte-identical state-map carry at cutover,
                        promotion and replay/fork decisions
verifier/mutation log   reload result and every negative test
checksums                inputs, setup, certificate, journal and reports
```

Each report records `git_sha`, `git_dirty:false`, protocol/compiler version,
field/hash/PCG identifiers, workload, challenge mode and machine identity.
Analytic screens use a different namespace and cannot be promoted later.

## 5. Promotion to `C7_POD_READY`

`C7_POD_READY` is a same-checkpoint ledger/capsule transition only after:

1. every Section 2 gate passes on the complete two-response tiny/scaled case;
2. the exact GPT-2 pod command, immutable inputs, output directory and abort
   policy are preregistered;
3. the run fails closed on a dirty tree, SHA mismatch, existing output,
   missing real PCG, unrecognized hardware, insufficient disk/memory, setup or
   certificate cap, and any verifier/mutation failure;
4. a source-tree checksum before/after proves the run did not modify tracked
   inputs;
5. no automatic/selective retry exists.

There is intentionally no C7 pod runner yet: no concrete compiler, prover or
certificate interface exists.  A placeholder runner would conceal these
gates rather than prepare them.

## 6. Pod order after later owner GO

1. Create a new pod-local run directory and HTTPS-pull the preregistered clean
   SHA; verify it before any setup.
2. Record CPU/GPU/RAM/disk/driver/runtime identity and perform only read-only
   capacity checks.
3. Run the smallest complete serialized production-equivalent case first,
   including reload, CPU verifier, mutations, abort burn and promotion.
4. Stop and record the first failure.  Do not retry or enlarge the case.
5. Only if that complete case passes and the GO explicitly includes it, run
   the full GPT-2 E2E once in a new directory.
6. Persist create-new reports/checksums and append the ledger disposition.
   Large generated weights/setup stay pod-local.

Policy 2 removes the need to verify Poseidon2 privately: a public salted
BLAKE3 leaf/tree function is selected, with every opened payload, salt and path
charged to the certificate.  Its collision assumption does not supply adaptive
root/path hiding or the joint root-wide t-query theorem.  The Fp3 codec/KAT
and carrier-independent shared-`Delta` equation seam now pass; current
blockers are their concrete PCS/PCG/VOLE refinement, an SPBT delayed-opening
carrier, its interleaved-domain theorem, same-`W` transform binding,
persistent-share import, malicious sublinear private stream evaluation into
MAC, complete non-oracle and receipt codec,
`C7-OnlineMDVViewRefine`, complete
plane/root/round query counts, transcript-bound
single-session receipts, branch-derived-view closure, response/K/V privacy
horizons and durable no-extension plane maps, distinct hash-work bounds, the cryptographic global counter,
genesis state-map initialization, rotation carry-forward, multi-user VOLE/MAC
composition and private stop-admit rotation bridge,
authenticated soundness/terminal privacy,
`C7_CPU_REFERENCE_PASS`, the compiled certificate census and all downstream
complete-chain evidence.  No prover, SIMT, provider or pod action is presently
valid.  A complete GPT-2 E2E remains pod-only after `C7_POD_READY` and a later
run-specific owner GO.

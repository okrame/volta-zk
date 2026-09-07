# Current status — C7.1 Gemma-31B

Updated 2026-09-07. This is an editable working summary; Git retains previous
versions. [Documentation index](README.md) · [Design](c7.1-gemma31b-design.md)
· [Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

C7.1 is the active construction: stateful private-weight Gemma-31B with
session VOLE-MAC boundaries and committed-weight evaluations. Earlier lines
are historical; reuse requires checking their hypotheses and counterexamples.
The [active design](c7.1-gemma31b-design.md) defines the relation, model identity,
security games and resource accounting.

**Targets, not measurements:** 45–50 s warm complete prover; 6.4–8.2 s verifier
on four CPU cores of this VM's class; preferred 30 MB, maximum 35 MB complete
certificate. Soundness and malicious-verifier privacy must each exceed 78 bits
lifetime. Up to four packed-W proof reads on the same H100 as inference;
6,442,450,944-byte total temporary arena, GPU peak below 80 billion bytes,
no spill, second weight copy or full codeword. Persistent model setup is capped
at 2.10× packed W. Exact scopes are in design §§1, 7 and 8.

**Preserved choices:** pinned checkpoint, Goldilocks/Fp3, offline classical ROM,
global Q64 and 2^20 attempts. Initial workload 100+50, then continuations through
4,096 total context tokens. ModelSetup is Delta-independent; residency,
connection, finite capacity, roots and attempts have separate costs. Slots and
correlations are never reused. One sequential user, live KV preserved; optional
ACK and distinct first activation do not reset consumption or security limits.

**Authorization:** small local preparation and checks may proceed autonomously.
No owner decision is pending. No provider contact, paid GPU, weight download,
heavy build or E2E is authorized now. Every E2E/heavy run requires authorized
hardware and explicit spending authorization after local preparation. See
[build procedures](procedures/build-and-test.md) and [RunPod procedures](procedures/runpod.md).
The owner's 2026-09-07 request prioritizes a complete algorithm with analytic
feasibility proofs before prover implementation and measurements.
The owner's [revision notes in design §1](c7.1-gemma31b-design.md#1-risultato-da-costruire)
allow future complete measurements to motivate five reads within 45–50 s,
or organized host spill after comparing write/read transfers and avoided
computation. These are not current waivers of four reads/no spill or spending
authorization.

## Evidence and open obligations

- The [G1 feasibility analysis](c7.1-feasibility.md) is concluded; admission
  of a complete algorithm is **not passed**. It defines six testable criteria,
  gives a conditional linear-work screen for the clear Hobbit carrier, and
  rejects two specific direct instantiations: reused split masks without
  cross-proof restrictions, and the fixed-width Fp3 column codec at
  `b_P=2^24`, 357 queries per half (35,094,528 bytes for columns alone).
  Neither result proves C7.1 impossible; base-field and different masking
  constructions remain open. See the dossier for premises and scope.
- [G2: committed MAC opening](c7.1-committed-mac-opening.md) is **active,
  not closed**. The [interactive prefix coupling](c7.1-committed-mac-opening.md#32-proiezione-di-strategie-e-campionamento-interattivo)
  now specifies projection, VC sampling and its scope; commitment–W across
  requests and FS remain open. It does not assume `BindsIntoMac`. The literal codec
  using one 8-byte correction per leaf bit is excluded at 357 queries for
  every power-of-two block: even the arena-maximal block needs 41,674,752
  bytes for those corrections alone. The A2 repair now specifies a grouped
  Goldilocks arithmetic hash and a private 30-round power-layer GKR: its
  endpoint is a linear combination of the same authenticated inputs, with
  no new trace PCS. At `b_P=2^24`, 357 study queries, the outer hash/anchor
  payload is 11,200,376 bytes before framing and other components. This is
  component accounting, not complete-certificate or hash-security credit.
- [A3: bounded RS and private recursion](c7.1-recursive-rs-opening.md)
  specifies the previously missing encoder and inner opening down to 32
  private E cells. A fixed algorithmic block cap proves at most 52 source
  FFT butterflies per padded cell; it is a new carrier, not unchanged Hobbit.
  Its component payload is 13,960,568 bytes, including the A2 hash/anchor.
  Known proof arrays total 6,070,425,696 bytes in a conservative union;
  uncompiled staging and the Gemma witness are not included. The interactive
  fixed-oracle argument binds a unique decoded message, not exact codeword
  well-formedness. Compiling arbitrary private roots into the required
  oracles, the precise model relation and adaptive FS remain open; no honest
  setup assumption or complete feasibility credit is introduced.
- [A3 standard-model compilation audit](c7.1-recursive-rs-opening.md#42-compilazione-ibcs-standard-model-fonte-applicabile-e-limite-concreto)
  now identifies the IBCS theorem of Chiesa et al. (2023/1737, revised
  2024-09-14): position binding can replace a query-observable commitment
  RO for an interactive public-coin IOP, through rewinding. Its sampler
  uses ceil(L/epsilon) continuations, with reduction size O(kL/epsilon)
  times the adversary size. The literal birthday-envelope justification
  at 256 bits cannot meet the target: even a single 2^26-column oracle,
  unit cost and unit hidden constant give a best template bound of only
  67.0817 bits before FS/lifetime. This excludes that admission argument,
  not the protocol or every possible reduction. Stronger hash/VC profiles
  or tighter reductions remain repairs to study. Sampled-parameter and
  adversary/preprocessing assumptions must match the actual fixed hash;
  Q_FS is not its work budget. No root-to-oracle/FS credit is granted.
- [A5: wide hash/anchor candidate](c7.1-wide-hash-opening.md) now specifies
  eight-Fp digests, ten-word groups, a 32-lane checker and an arithmetic
  salted anchor in the same MAC. The pinned parameter calculator nominates
  8 full/31 partial rounds, but does not provide a supported Goldilocks-32
  profile or concrete security. W paired payload is 16,164,144 bytes;
  C_Σ paired is 10,402,496/15,706,688 at N=150/4096, before public anchors,
  framing and other components. Literal enlarged arrays fail; staged hash
  execution, tiled native encoding and pruned caches repair those specific
  schedules. The largest known C_Σ phase is 6,404,645,880 bytes, leaving
  only 37,805,064 before uncompiled Replay/Gamma/runtime and materialized
  public parameters (2,680 bytes per copy in A5-M). The tiled commit
  charges 32 ModelSetup W visits or 16 C_Σ source visits, including all
  repeated native FFT work; warm A4 still uses two source visits.
  ROM constants/final KAT, profile grammar, binding/hiding, IBCS/FS and
  complete liveness remain open. This is not an admitted hash upgrade.
- [A5-P: sampled public parameters](c7.1-wide-hash-opening.md#21-a5-p-parametri-pubblici-dal-rom-con-coupling-finito)
  now gives a finite ordinary-ROM publication and exact joint-tape embedding
  into independently sampled arithmetic-hash keys. A fixed pre-profile,
  no selectable nonce and four u64 proposals at each of 287 fixed addresses
  yield 2,296 bytes of constants from 9,184 derived public bytes. Exhaustion
  aborts, with probability below 2^-119 for that single parameter set;
  revisiting the same addresses is not resampling. A bounded-bit comparison
  generator has explicit density ratios, not an implicit unbounded sampler.
  The result requires initial advice independent of RO and charges every
  post-parameter computation, including preprocessing. Free RO-dependent
  advice can precompute a collision; Q_FS alone does not price that search.
  This repairs only the sampled-parameter interface in the stated model:
  the exact pre-profile, CR/hiding of the sampled family, reduction
  simulation costs, IBCS/FS and complete witness/liveness remain unproved.
- [A5-M: explicit matrix candidate](c7.1-wide-hash-opening.md#22-a5-m-matrici-nominate-garanzie-finite-e-limite-della-larghezza)
  now fixes the twentieth pinned Grain diagonal, proves permutation
  invertibility for every constant vector, and checks degree-32 irreducible
  minimal polynomials for powers 1–64. The primary subspace-trail theorem
  excludes infinite trails of period at most 64, not all periods. A synthetic
  KAT agrees with the pinned reference; actual ROM-profile KAT remains open.
  Crucially, the external matrix at width 32 has branch number exactly 10:
  two opposite blocks disprove extrapolating the published formula to 12.
  Poseidon2's stated range stops at width 24. This excludes that numerical
  extrapolation, not the complete hash; its cryptanalysis must be rebuilt.
  No production implementation, hash-security bits or G2 admission follow.
- [A5-D: fixed-characteristic screen](c7.1-wide-hash-opening.md#23-a5-d-caratteristica-prefissata-e-limite-del-trasferimento)
  repairs the active-S-box count at branch 10: four disjoint pairs of actual
  full rounds give at least 40 active boxes. For one input pair and complete
  differential characteristic fixed before the uniform round constants,
  the exact Markov law gives probability below 2^-2456. These are not hash
  security bits. Exhaustive toy checks separate this law from collision
  hulls, post-parameter input choice and repeated use of the same key.
  Even honest chained hash inputs can depend on the constants. The screen
  does not require increasing the nominated rounds; it does not justify
  reducing them or supply the missing adaptive CR/hiding/IBCS/FS bound.
- [Ideal MAC/FS simulation](c7.1-committed-mac-opening.md#31-simulatore-ideale-fs-nessuna-programmazione-delloracolo)
  now has a straight-line coupling proof for the actual public correction
  prefixes, including aborts and adaptive attempts. It needs no oracle
  programming and no added FS simulation error, conditional on fresh ideal
  correlations, NoPeek, public schedules and honest valid products/residuals.
  Anchor hiding, real malicious-secure PCG and implementation refinement
  remain open. A3 also fixes bounded query/field sampling and counts its
  718 E challenges; this is not the complete lifetime query census.
  Primary BCS/AROM sources expose why replacing the commitment hash by an
  independent RO while retaining its concrete private checker is invalid.
  The classical ROM requirement remains unchanged.
- The [W-cut witness analysis](c7.1-cut-witness.md) proves a conditional
  replay equivalence: checkpoint raw private-matrix accumulators, weighted
  norm products and embedding lookups; regenerate the rest without W.
  For 100+50 these packed checkpoints occupy 5,143,044,096 bytes, independent
  of old KV length. This requires the declared integer lowering and proofs
  of every cut/KV equality, not trusted checkpoints. Holding all of B through
  A3's literal first W-recursion sumcheck exceeds the arena; a conditional
  B-opening array schedule identifies where B could instead be released.
  GKR weight folding still needs source access: adding its matrix scan to
  the four unfused generic reduction/PCS passes does not fit the read limit.
- [W-cut P0](c7.1-cut-witness.md#6-p0-tutte-le-uguaglianze-verso-w-non-il-gkr-intero)
  now emits all 773 W-dependent cohorts, physical cut offsets and input
  producers. Matrix, cubic broadcast-norm and aggregate embedding protocols
  use one W read and 300,646,400 bytes of compact operands; their payload is
  863,040 bytes before framing/shared closures. The conditional fixed-boundary
  lemma does not prove the 772 input-evaluation links to W-free Replay,
  C/B openings or integer ranges. The known B/tree/P0 union is 5,714,441,824
  bytes, before uncompiled Replay workspace and runtime.
- [P0 input routing](c7.1-cut-witness.md#7-dai-772-input-p0-ai-produttori-w-free-forme-e-riduzione)
  now derives exact head/prefix/decision selectors and reduces the 772
  initial input demands to 602 producer-point obligations in the same MAC.
  A four-state carry/borrow evaluator handles shifted rows in logarithmic
  verifier work. This seed prelude adds 122 degree-2 sumchecks and 187,392
  payload bytes, with no W reads or new private products. Its transfer lemma
  does not prove the producers: integer requantization, nonlinear kernels,
  later Gamma consumers, B/KV and ranges remain open.
- [R1: byte-bound requantization](c7.1-requantization.md) gives exact
  ties-to-even/overflow polynomials and a conditional MAC sumcheck for
  i48→symmetric-i16, plus a separate byte-range proof. A tamper case
  disproves relying on scalar reconstruction alone. R1 changes the B
  commitment source to its existing biased bytes, without a second B copy.
  The literal six-row/full-tree byte PCS is excluded by size/arena;
  four-row groups and a staged internal-node-only tree cache remove that
  specific exclusion. A dyadic virtual byte layout now gives explicit
  forms for the 781 known P0/RNE/range/padding claims. Reusing A4 opens
  them together in two B visits after commitment, with no X1 regeneration
  or new W reads; it adds 99,888 payload bytes over A3 and a conditional
  4951/|E| bound before A3/MAC/FS. The physical B stays unchanged;
  gather traffic and prefix-recomputation work are counted separately.
  Concrete shifts, later Gamma consumers and complete liveness remain
  uncompiled. The byte-range path now uses eight degree-3 GKR layers,
  with one affine endpoint alias into that same B opening, no trace PCS,
  28,608 payload bytes and a conditional 917/|E| transfer bound. Its honest
  public tables/weighted histograms give an explicit 95-B-visit schedule,
  zero new W reads and a 6,148,794,256-byte known local union. The direct
  high-degree RNE remains a comparison; the current RNE uses R2 below.
- [R2: source-bound RNE indicators](c7.1-rne-indicators.md) replaces the
  degree-1531 RNE sumcheck with degree 7 and a degree-3 P/S tree. Linearity
  in the public function removes the 256-function axis from GKR. The proof
  returns six endpoints to the same B opening, with no trace PCS. It costs
  86,424 payload bytes and has conditional error (t+1143)/|E| for t output
  claims, before range/B/MAC/FS. Explicit replay uses 113 matrix-cut visits,
  no W reads, and a 6,353,297,296-byte local union before K1/Gamma. Caching eight lane
  tails exceeds the arena; the two dummy lanes are instead public constants.
  The known partial payload before K1 is 30,833,200 bytes. Large work constants,
  concrete shifts, remaining Gamma consumers and complete liveness stay open;
  no full-certificate, memory or timing admission follows from these screens.
- [K1: KV transition](c7.1-kv-transition.md) now gives exact temporal
  views and a conditional concatenation/prefix reduction in the same MAC.
  It transfers 120 new-tail claims to k_rope/v_norm; those producers and
  the joint predecessor/candidate KV openings are still unproved. The
  first state needs only same-wire aliases (2,880 payload bytes); the
  continuation core adds 120 quadratic sumchecks (180,000 bytes), before
  read routers/PCS/framing/shared closures. It uses one fused KV visit
  and no W reads. Full-array view routing exceeds the arena with B/cache;
  one streaming prefix bit halves those arrays with two KV visits. The
  known subtotal including the first-state core, before T1, is 30,836,080 bytes,
  still without KV PCS, remaining Gamma or full liveness. Small tamper
  checks cover prefix/append/terminal/padding, future-slot reads and
  choosing a root after the state probe. This is not full state proof credit.
  The earlier q_rope source name was incorrect: the pinned append consumes
  k_rope, with G KV heads, not the 32-head query tensor. K1 records the
  correction and its source-provenance regression; the generic algebra
  and storage counts did not establish that erroneous producer link.
- [T1: attention products](c7.1-attention-products.md) specifies raw QK/PV
  reductions over whole-request cohorts, with exact rectangular views and
  GQA grouping. An eight-state public selector handles prefill/decode;
  shared groups have cubic rounds. QK uses weighted key prefixes and two
  K visits; PV uses one V visit and two visits of one layer's i16 probability
  cache. Its private contraction is explicitly linked back to softmax,
  without a new trace PCS. For one normalized raw output point per kernel
  and layer, payload is 260,400/312,240 bytes at N=150/4096; T1 supplies
  120 KV endpoints and makes the K1 two-point routers concrete in that
  case (174,240/208,800 additional bytes). Local arrays avoid the excluded
  query×key×lane expansion. Output normalization, raw↔i16 links,
  Q/softmax generation, KV PCS and complete liveness remain uncompiled;
  these component bounds do not admit the whole algorithm or its timing.
- [R3: auxiliary witness bridge](c7.1-auxiliary-witness.md) specifies a
  candidate common byte source C_Σ for B and all raw QK/PV rectangles,
  with 120 fresh post-root probes and exact raw/six-lane RNE pullbacks.
  Pruning masked raw scores can hide overflow; keeping the complete source
  in memory would require 12,665,316,096 bytes at capacity. The candidate
  retains only physical B and regenerates auxiliary values from W-free
  Replay, conditional on the complete reader/lowering still to be compiled.
  A striped execution of the identical RS encoder costs 64 source visits
  to commit; a height-3 outer cache and staged internal C1 cache retain
  A4's two postcommit visits. The largest listed phase is 6,362,991,432
  bytes before remaining Replay/Gamma/runtime, not a full memory bound.
  RNE uses prefixes 18/11 and 122 RQ visits; byte range uses 95 visits.
  The C_Σ PCS component is 9,810,600/15,708,840 bytes at N=150/4096.
  This requires a new common profile/layout and rerouting every consumer;
  previous C_B subtotals are reference screens, not R3 totals. Output
  normalizers/shifts, all Gamma forms, honest source generation, KV PCS,
  full liveness/costs and root-to-oracle/FS remain open; G2 stays active.
- [A4: paired RS opening](c7.1-paired-rs-opening.md) fuses the paired
  reduction and RS opening into **two W reads together**. It checks the
  existing arbitrary row fold instead of converting it to a new W point;
  this proof retains a separate fresh proximity fold. The local fixed-oracle
  proof adds 4142/|E| and the component payload is 14,060,600 bytes.
  A 3,156-tile virtual layout supports tensor/lookup forms without per-axis
  padding or a second W copy. With P0, three reads are specified
  for the W-dependent subsystem, but the complete caller, W range/padding
  and B/KV schedule are not instantiated; the A3 concrete-hash/FS gap remains open.
- The [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py) and
  [focused tests](../tests/test_c7_1_gemma_plan.py) check paired-fold
  arithmetic, service accounting, candidate integer/Fp3 decompositions,
  the two-proof masking counterexample, exact carrier/bit-codec counts,
  the product-check identity and simulator with the C7.1 MAC sign, and A2's
  degree-8/9 round reduction, single input endpoint and resource counts.
  A3 adds small FFT/form/recursion identities and a malformed-codeword
  counterexample distinguishing proximity from exact well-formedness.
  The focused checks also cover finite query sampling, exact ideal
  simulation distributions, the excluded independent-RO hybrid, W-cut
  counts/replay/mutations, finite-field matrix folds, A4's arbitrary-fold
  distance/encoding identities and dyadic layout/form evaluation. P0 adds
  cohort coverage/offsets/producers, malformed model inventories, cubic
  broadcast norms and tied lookup with duplicates and terminal absorption.
  Input-route tests cover shifted/prefix selectors, head reshape, bounded
  fanout reduction and cancellation if its batch challenge is sent too early.
  R1 adds exact Fraction comparisons, all shift classes/ties/overflow,
  Lagrange roots and non-Boolean degree checks, a malformed byte and
  scoped resource exclusions. Byte-opening checks cover unique physical
  coverage, live-support bias, public forms, the same SC/PCS endpoint and
  a nonzero padding byte that passes the alphabet test but fails its link.
  Arbitrary-fold forms and reconstructed paths check the A4 reuse and
  internal-tree cache; this is not a Poseidon2 security test or KAT.
  The range product tree adds complete small eight-layer reductions,
  cubic coefficients, the affine source alias, non-byte Fp inputs,
  altered products, early-challenge cancellation and histogram/prefix
  equivalence without assuming that folded values remain bytes.
  R2 adds P/S linearity, lifted degree seven, complete small eight-layer
  reductions to six source planes, dummy-lane pruning and dense replay
  comparisons. The direct RNE/overflow regressions still use the same formulas.
  R3 adds common-source coverage and all six RQ pullbacks, masked overflow,
  the necessity of a pre-probe source, identical striped RS codewords and
  reconstructed lower subtrees with staged digest buffers.
  The IBCS audit checks valid-position resampling by finite enumeration
  and the cube-root-loss identity with exact fractions; it tests a bound
  template, not an extractor or hash-security claim.
  A5 adds the 32-lane algebra instance, fresh wide accounting, and symbolic
  tiled/pruned-tree checks with absolute indices. A5-M adds matrix
  irreducibility/finite-period checks, a synthetic permutation KAT and dense
  comparison, canonical/tamper cases, the branch-12 counterexample and a
  31-round passive difference. No concrete hash-security test is claimed.
  A5-D exhausts all 14,641 keys of a two-lane/two-round F11 toy, checks
  the complete characteristic distribution and demonstrates the separate
  collision-hull/adaptive-input/key-reuse obligations.
  A5-P adds exact joint distributions of embedded keys/public rejection
  tapes, finite comparison-generator domination, fail-closed boundaries,
  descriptor grinding and the excluded free oracle-dependent advice case.
  The broader 86 non-native Python checks passed during the main integration
  (`bce620f`). They do not prove full cryptography or hardware feasibility.
- The complete carrier/blind MAC/PCS composition and four-read full-prover
  schedule remain unproved. GKR and witness regeneration must fit the same
  source-read and memory accounting; output-bound FS constrains folding order.
  The literal generic Hobbit wrapper with trace replay requires at least
  seven source-recomputing traversals. The new W-cut removes replay's W
  dependence under its lowering premises, but does not prove a complete
  physical schedule or remove GKR's weight-evaluation scan.
- `C71FsLifetimeSound`, adaptive soundness transfer and complete
  malicious-verifier privacy still need their runtime premises and complete
  lifetime event/query census; the ideal online simulation step is proved above.
  Existing conditional Lean lemmas do not discharge these obligations.
- Complete certificate compilation, the physical live-memory schedule and
  full Gemma prover/verifier measurements remain outstanding. No C7.1 E2E,
  security, certificate-size, timing or memory credit is claimed.

## Next work

Follow [design §10](c7.1-gemma31b-design.md#10-ordine-del-lavoro-dopo-lautorizzazione-a-quattro-letture):
continue from [G2 §3.2](c7.1-committed-mac-opening.md#32-proiezione-di-strategie-e-campionamento-interattivo):
move source extraction before caller claims and prove the precise
commitment–W relation across requests, then compose the binding argument with the concrete
hash/PCS assumptions and FS. A3's finite inner recursion and hash checker
must not import BCS's extraction from an oracle that the concrete checker
does not access. The new IBCS audit supplies a standard-model theorem but
excludes the literal 256-bit birthday-envelope bound even under favorable
costs. Seek a tighter concrete reduction or a stronger hash/VC profile;
compile its parameter/adversary assumptions, complete reduction costs and
adaptation to the actual public-coin/MAC/FS transcript. A5 now supplies a
structural wide hash/anchor codec, checker and resource recount, not an
admitted hash profile. A5-M now supplies explicit matrices and a synthetic
KAT; its width-32 branch number is 10, not the extrapolated 12. A5-D fixes
the single pre-parameter characteristic screen, not the collision-hull or
post-parameter input-search bound. Complete
the actual ROM constants/KAT and public profile grammar, justify the
concrete binding/hiding assumptions and
compile the actual reduction. A5-P now supplies a finite sampled-parameter
embedding in ordinary ROM: instantiate its fixed pre-profile with those
matrices and the sampled family's actual assumptions, then price RO simulation and
rewinding, including preprocessing. Neither that coupling nor a p^8 output
space supplies collision/hiding bits. Its C_Σ margin is narrow;
the full reader/Gamma workspace must be included before claiming a fit.
The A3 opening stages add no W reads after queried source columns exist;
they do not supply the missing Gemma witness. The static model anchor keeps PCS openings private,
without reusing G1's public split mask. Setup hash work remains substantial;
the bounded encoder and known grouped-commitment arrays occupy 5,637,144,576
bytes, before uncompiled runtime staging. Alongside it, use the W-cut theorem
to complete the GKR/form schedule against A4's two-read interface. P0 covers
the W-dependent cohorts; its 772 input demands now route to 602 producer
points. R1 specifies a conditional raw-B requantization kernel and the
byte-source forms/reducer for the known claims. Complete Gamma's consumers
and their single final B barrier, fix exact shifts, and reduce the explicit
work cost before treating it as feasible. R2 now gives the source-bound
RNE Lagrange reduction and its replay schedule; include its endpoints in
the remaining Gamma consumers and reduce the explicit computation cost.
K1 now supplies the temporal view and append/prefix reduction, with
explicit first-state aliases and bounded-memory read routing. Instantiate
its joint KV PCS and k_rope/v_norm producers. T1 now supplies raw QK/PV
and their same-state endpoints. R3 now supplies the common-source raw/byte
bridge and RNE pullbacks: compile output normalizers/shifts and every
consumer in that new layout, the actual W-free reader with its costs and
workspace, and the softmax input to PV. Recompute the complete payload
and phase schedule; the old C_B subtotals do not describe C_Σ.
Generating Q/probabilities and the remaining W-free kernels is not closed
by either local transfer lemma.
Bind cuts and KV, discharge late B consumers, and include W range/padding
without exceeding four W reads. The A4 fusion no longer requires a new
common MLE point for all W terminals; its public-form conditions must hold.
Complete the relation, both lifetime
proofs and full certificate/resource accounting before admitting prover
implementation. Then prepare the small checks and, after hardware/spending
authorization, the complete composition case and real Gemma workloads.
The [remaining G2 obligation](c7.1-committed-mac-opening.md#7-prossimo-obbligo-e-controlli)
specifies the required mathematical deliverable; no new owner decision is pending.

## Documentation decision

On 2026-09-07 the owner chose a minimal C7.1 wiki: editable status/design,
immutable evidence, and separate build/RunPod procedures. C7 was merged into
main (`bce620f`), eight missing research files were versioned (`4f7edf0`), and
the C7 worktree was closed before this reorganization. The pre-wiki ledger is
preserved byte-for-byte in the linked historical snapshot. Routine checks
belong in commit/task validation; this page changes when the working state does.

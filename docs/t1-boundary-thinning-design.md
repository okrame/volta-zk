# T1 boundary thinning — amended Phase-1 design

**Status (2026-07-19): T1 CLOSED; G1/G2/G3/G4 PASS; M11 GREEN.**  The M11
package required by §6 is proved and audited: full `lake build`, zero
`sorry`/new axioms, and `#print axioms` coverage for every new theorem.  The
Rust implementation and both clean schema-10 records are closed at the exact
reference in §10.  R1 is not part of this closure and remains deferred to
Kimi3 by the product-owner decision recorded in the ledger.

The target remains GPT-2 small, prompt `T=100`, one deferred decode chunk
`Q=50`, `L=12`, `d=768`, PCS `Q_pcs=120`, and the immutable C3b response
reference `105,717,632 B` at `161fc59`.  T1 does not change witness generation,
quantization, PCS parameters, the real-PCG tuple, or one-time correlation
semantics.  It does not remove or reuse any existing challenge role, but it
inserts fresh verifier draws at injective public schedule positions as stated
in §5; every later position in the verifier stream consequently shifts.  The
earlier blanket statement that challenge order would be unchanged is therefore
amended, not silently retained.

## 1. Measured correction split — the gate starts here

The requested `59,545,008 B` stream is the clean C1/core value in
`benchmarks/results/c1-2026-07-15-2a3d731.json`.  The current C3b record
`benchmarks/results/c3b-cpu-real-2026-07-18-161fc59.json:381-490` reports
`59,545,520 B`, exactly `512 B` more from the C3b selected-row authentication.
The split below is an exact accounting against those immutable measurements;
no new benchmark or pod run was needed.

| Stream | Values | C1/core bytes | Current C3b bytes | T1 treatment |
| --- | ---: | ---: | ---: | --- |
| residual/block seams | 3,110,400 | 24,883,200 | 24,883,200 | thinnable, subject to M11 |
| K/V cache authentication | 2,764,800 | 22,118,400 | 22,118,400 | **not thinnable** |
| other | 1,567,926 / 1,567,990 | 12,543,408 | 12,543,920 | unchanged |
| **total** | **7,443,126 / 7,443,190** | **59,545,008** | **59,545,520** | |

The residual count is not a blind `/k` estimate.  C1 authenticates all 12
attention-block outputs, all 12 FFN-block outputs, and three fresh `x_in`
matrices per phase (layer 0 and the two nonzero requant seams):

```text
(12 ABO + 12 FBO + 3 X) * 150 rows * 768 columns = 3,110,400 values.
```

K and V are `2 * 12 * 150 * 768 = 2,764,800` values.  They are persistent
side outputs: later attention and later chunks read every layer's cache
through `CacheSeg`, at independently sampled points.  The domains and cached
keys are explicit at `rust/volta-proto/src/block_proof.rs:7196-7217`, the
bindings at `:7320-7359`, and cross-chunk orchestration at
`rust/volta-proto/src/model_proof.rs:2307-2341`.  Removing them would change
M4, and is outside T1.

The split reconciles to the byte, with no unexplained residual:

```text
C1/core: 24,883,200 + 22,118,400 + 12,543,408 = 59,545,008 B
C3b:     24,883,200 + 22,118,400 + 12,543,920 = 59,545,520 B
delta:                                               512 B
```

The entire 512-B delta is the C3b selected-row authentication already listed
under `other` (`64` Fp corrections at 8 B); residual and K/V are identical.

The `22,118,400 B` K/V share is architecture-specific context, not a reason to
relax this GPT-2 gate.  GPT-2 uses full MHA, so K/V width equals query width.
For a same-query-width GQA 64/8 architecture such as the phase-X gpt-oss
target, K/V authentication width — and therefore this non-thinnable stream —
is about one eighth of MHA.  T1 remains pinned to the measured GPT-2 split;
the X0 scale budget separately applies the GQA dimensions.

The C1/core `other` stream reconciles exactly as follows; C3b adds the final
`512 B` selected-row term.

| Other component | Bytes |
| --- | ---: |
| embedding/final boundary i16 values | 1,253,376 |
| shared TableBank multiplicities | 2,847,216 |
| per-layer LN vectors | 147,456 |
| attention row/mask/above vectors | 8,293,248 |
| final-LN small vectors | 2,112 |
| C3b selected-row authentication | 512 |
| **current C3b other** | **12,543,920** |

The phase split is likewise exact:

| Phase | Residual seams | K/V | Other | `auth_corrections` |
| --- | ---: | ---: | ---: | ---: |
| prefill 100 | 16,588,800 | 14,745,600 | 10,073,392 | 41,407,792 |
| decode 50 | 8,294,400 | 7,372,800 | 2,470,528 | 18,137,728 |
| **response** | **24,883,200** | **22,118,400** | **12,543,920** | **59,545,520** |

## 2. Exhaustive soundness-blocker census

The would-be fused chain cannot identify two evaluations merely because the
honest Rust witness uses one array.  Every unauthenticated fan-out must first
be reduced to one evaluation point, and that one claim must then be carried
upstream.  The complete residual-state census is:

| Tensor / seam | Independently sampled uses today | Evidence | k=4 disposition |
| --- | --- | --- | --- |
| every `A_l = attn_block_out[l]`, `l=0..11` | FFN residual at the FFN-down point; LN2 centering at its Hadamard point; its attention-residual producer is at a third point | FFN `rust/volta-proto/src/block_proof.rs:3321-3325,3464-3469`; LN2 call `:3406-3419,3539-3553` and actual open `:2764-2778`; attention residual `:5161-5169`; verifier mirrors `:2932-2956,4029-4034,4140-4146,6791-6797` | remove all 12 auths; **12 two-point reductions per phase** |
| internal `X_l = x_in[l]`, `l in {1,2,3,5,6,7,9,10,11}` | attention residual; LN1 centering; preceding seam producer is at another point | attention `block_proof.rs:5161-5169`; LN1 call `:5698-5712` and open `:2764-2778`; resident `:5794-5819,6603-6616`; verifier `:6791-6797,7138-7139`; seam producers `model_proof.rs:3148-3177,3502-3533` | remove auth; **9 two-point reductions per phase** |
| internal `F_l = ffn_block_out[l]`, `l in {0,1,2,4,5,6,8,9,10}` | FFN-residual producer and the following seam use different points | residual `block_proof.rs:3464-3469,4140-4146`; seam `model_proof.rs:3155-3175,4375-4387` | no second fan-out reduction; the downstream single claim must be injected into the residual at the same point |
| residual range-output bridges | `prove_range_site` drains aux claims into its OUT column, which is `ffn_down_q` or `attn_proj_q`, **not** FBO/ABO; a downstream F or reduced A point therefore needs the corresponding q evaluation | aux contract `block_proof.rs:2314-2331`; FFN relation `:3321-3325,3462-3469`; attention relation `:5161-5169`; aux eq fold `logup.rs:695-731` | at 9 internal FFN points and all 12 attention points per phase, evaluate q at the downstream point, authenticate that scalar once, bind it as the single aux claim, then derive A=F-q or X=A-q by M1 |
| nonzero seams after layers 0 and 1 | range/requant relation between `F_l` and `X_(l+1)` | seam range path `model_proof.rs:3148-3177`; zero shift is not accepted by the helper at `block_proof.rs:2026-2057,2232-2242` | feed the reduced X claim into the existing range auxiliary-claim path and emit one F claim |
| zero-shift internal seams | identity between two honest arrays, currently checked at a fresh point | C1 aliases `block_proof.rs:7400-7410,7458-7488`, verifier `:7850-7895`; frozen shifts `docs/prototype-status.md:1120-1131` | one canonical polynomial/wire; never two unauthenticated arrays plus an after-the-fact equality |
| `X_0`, `X_4`, `X_8` | each has the same two consumers as X above | model entry equality `model_proof.rs:3185-3196`; C1 alias paths above | stay authenticated; X4/X8 reuse retained F3/F7 auth, so repeated openings are sound |
| `F_3`, `F_7`, `F_11` | group exit, next group entry, or final LN | final link `model_proof.rs:3209-3220` | stay authenticated |
| K/V | QKV outputs plus repeated QK/WV/cache consumers across positions and chunks | `block_proof.rs:5262-5269,5585-5666,6442-6450,6533-6562`; `model_proof.rs:3437-3475,4522-4565` | stay authenticated; outside thinning |

There are no further residual fan-out pairs.  Embed and final-LN endpoints
remain authenticated in `other`; K/V are intentionally retained; existing
P4-internal wires already live inside their fused block chains.  Internal FBO
is nevertheless a binding/scheduling blocker: merging the next X pair is not
enough if the resulting point is later compared to an independently sampled
FBO point.

Three additional implementation obligations follow from the census:

1. The current proof order runs scheduled layer proofs before model seams
   (`model_proof.rs:3115-3130` before `:3148-3177`; resident `:1761-1835`).
   The FFN scheduler also runs producers before tails/attention
   (`rust/volta-proto/src/ffn_schedule.rs:310-369,409-461`).  Phase 2 must use
   downstream-to-upstream pending claims within each four-layer group; adding
   reductions after the current schedule would remain unsound.
2. Padding is part of the statement.  T1 uses the existing LSB-first
   `columns || rows` MLE, tensor zero padding, and the exact real-row mask;
   current opening semantics are at `block_proof.rs:1206-1238`, and range
   output padding at `:2026-2057`.
3. TableBank multiplicities prove table membership, not positional seam
   equality.  They cannot replace the pointwise chain.  Honest-prover
   recomputation/assertions are also not proof obligations.

## 3. k=4 seam schedule and C1 alias retirement

Each prefill or decode chunk is independently split into groups
`[0..3]`, `[4..7]`, `[8..11]`.  A chain never crosses a chunk boundary.
Per phase/chunk T1 keeps exactly four authenticated residual matrices:

- fresh `X_0` at chunk/model entry;
- `F_3`, `F_7`, and `F_11` at group exits;
- `X_4` and `X_8` are canonical aliases of the retained F3/F7
  authentication and send no new correction.

It removes all 12 ABO matrices, nine internal FBO matrices, and the two fresh
nonzero-seam X matrices: 23 matrices per phase.  The nine C1 identity aliases
are coherently subsumed: retain X4/F3 and X8/F7 as authenticated group-entry
aliases; retire internal X3, X5, X6, X7, X9, X10, and X11 into the fused claim
chain.  The public domain tombstones remain so unrelated K/V/TableBank/domain
numbering is not silently shifted.

The exact correction result is therefore

```text
removed values       = 23 * 150 * 768 = 2,649,600
removed bytes        = 2,649,600 * 8  = 21,196,800
retained residual    = 4 * 150 * 768  =   460,800 values = 3,686,400 B
T1 auth corrections  = 59,545,520 - 21,196,800 = 38,348,720 B.
```

Against the requested C1/core value, the corresponding result is
`38,348,208 B`; Phase-2 gates use the current C3b value `38,348,720 B`.

## 4. Chosen multi-point -> single-point reduction

Suppose two downstream relations have already sealed claims
`(u,a)` and `(v,b)` for the same `n`-variate multilinear tensor `S`.  The
verifier then samples a fresh affine challenge `beta` and the prover runs the
degree-two eq sumcheck

```text
a + beta*b
  = sum_{z in {0,1}^n} S(z) * (eq(u,z) + beta*eq(v,z)).
```

Let `g_beta(z)=eq(u,z)+beta*eq(v,z)`.  The sumcheck samples one terminal point
`rho`, authenticates only the scalar `S(rho)` with an existing full-field
correlation, and appends the public-linear terminal row

```text
sumcheck_claim(rho) - g_beta(rho) * [S(rho)] = 0
```

to the existing response-wide `Pi_ZeroBatch`.  Because `g_beta(rho)` is
public, this is a linear authenticated relation: **no `Pi_Prod` claim or new
correlation type is needed**.  The same `(rho,S(rho))` claim, not a new random
point, becomes the input to the preceding seam/residual relation.

For each group, reverse dataflow is: start from its authenticated FBO exit;
reduce the FFN relation; merge the two ABO claims; continue through the
attention relation; merge the two internal X claims; drain that claim through
the preceding identity/requant seam; repeat upstream.  A four-layer group has
`k=4` ABO reductions and `k-1=3` internal-X reductions, hence `2k-1=7`.
Three groups give 21 reductions per phase and 42 in the record response.

“Inject the claim” has an exact, non-free meaning.  At each of the nine
internal FFN residuals per phase, evaluate `ffn_down_q(u)` at the downstream F
point `u`, authenticate the Fp2 scalar with one fresh full correlation, bind
it to the range OUT column via the existing aux eq fold, and derive
`A(u)=F(u)-q(u)` by MAC linearity.  At all 12 attention residuals, do the same
for `attn_proj_q(r)` at the reduced A point and derive `X(r)=A(r)-q(r)`.
Group-exit F3/F7/F11 can instead open their retained matrix authentication at
the range instance's own point; the two nonzero seam aux claims already arrive
authenticated.  Thus the response needs exactly 42 new scalar evaluations,
full correlations, and 16-byte corrections (672 B), in addition to the 42 eq
reducers.  This does not add a witness field; it evaluates existing q columns.

This is a claim-driven rewrite, not 42 extra checks layered on top of the old
boundary checks.  Once a relation emits its input claim at the reducer's
terminal point, its old authenticated-boundary zero row is retired.  The
exact response-wide `Pi_ZeroBatch` row map is:

| Direct boundary row family | C3b rows | T1 rows | Reason |
| --- | ---: | ---: | --- |
| FFN residual / ABO | 24 | 0 | emits the ABO consumer claim upstream |
| attention residual / X | 24 | 6 | only authenticated group entries X0/X4/X8 retain a direct comparison |
| LN2 input / ABO | 24 | 0 | emits the second ABO consumer claim |
| LN1 input / X | 24 | 6 | only authenticated group entries X0/X4/X8 retain a direct comparison |
| C1 zero-shift identity aliases | 18 | 0 | canonical fused wire, including the retained X4/F3 and X8/F7 aliases |
| nonzero-seam boundary equalities | 8 | 0 | reduced X claim enters the range auxiliary path, which emits the F claim |
| eq-reducer terminal rows | 0 | 42 | one public-linear terminal row per fan-out pair |
| **affected rows** | **122** | **54** | **net -68** |

All unaffected closure rows remain byte-for-byte present.  Consequently the
exact projected global counter is `closure_zero_claims = 8,238 - 68 = 8,170`,
not 8,280.  `closure_prod_claims` stays 21,667: the terminal coefficient is
public and the reducer introduces no secret product.  Removing rows does not
save correlations (the response-wide zero batch already uses one mask), and
no transcript-byte credit is taken for deleting them.

### Rejected alternative: force both consumers into one common-point instance

This is not strictly simpler.  The residual point is produced by a
range/LogUp path, while the LN point is produced later by a degree-three
Hadamard chain.  They have heterogeneous round counts, degrees, and dependency
histories.  Combining them would require a selector circuit plus rewrites to
both chains and TableBank scheduling.  The P7 shared-round theorem explicitly
requires homogeneous claims and one common point and does not bless different
histories (`docs/protocol-sketch.md:177-196`,
`lean/VoltaZk/BatchSumcheckSound.lean:154-200`).  The local eq reducer is the
smaller protocol surface and is exactly the sound alternative recorded in the
2026-07-15 ledger §4.1.4 correction.

## 5. Transcript, domains, and invariants

For every reducer the binding order is load-bearing:

1. both downstream points, scalar claims, membership, tensor id, phase/chunk,
   layer, and real/padded shape are transcript-bound;
2. sample a fresh verifier `beta` at the reducer's unique public schedule
   position (never reuse TableBank `alpha`);
3. in each round, seal the two masked degree-two coefficients before sampling
   that round's `rho_i`;
4. after the terminal point, authenticate `S(rho)` once and append the linear
   zero row;
5. start the upstream consumer with that exact point/value;
6. after all response claims are fixed, use the existing single global
   scalar-power `Pi_ZeroBatch` challenge.

Claim transport into the 23 affected LogUp/range instances per phase has a
second fixed-before-challenge boundary.  The external point, authenticated
claim, column/site id and public list membership are sealed **before the
entire fraction-tree instance starts**: before its root and every upper-layer
`lambda`/round/child coin (`logup.rs:1433-1473`; resident `:993-1004`).  At
the aux leaf, the exact local order is `lambda_leaf`, the new `mu`, the
compressed degree-three `[g(0),g(2),g(3)]` messages and leaf-round `rho`
draws, and finally the shared child-bit `t` (`logup.rs:699-710,1887-1913,
1957-1966`; verifier `:2263-2290,2355-2360`).  Thus the record response adds
46 fresh `mu` draws at injective public schedule positions; `lambda`, `rho`
and `t` already exist.  The new draws send zero proof bytes and consume zero
correlations, but no role may reuse the schedule position of `beta`,
`lambda`, TableBank `alpha`, any round `rho`, `t`, or the final scalar-batch
challenge.

At each of the 21 q-bridge sites per phase, the evaluation `Q(u)`, its fresh
authentication/correction, and the linearly derived residual claim
`A=F-Q` or `X=A-Q` are all fixed before the whole fraction-tree instance.  No
consuming upstream relation may draw a challenge until the aux leaf has completed its
`(lambda,mu,rho,t)` schedule and emitted the consolidated claim.  More
strictly, M11 conditions on the complete root/upper-layer/base tape as fixed
prior tape when analyzing the new leaf `mu`.  This is the exact
interleaving required by the reverse-dataflow schedule in §2; a producer-first
or overlapping consumer schedule is outside the preregistration.

These are interactive-verifier coins, not Fiat--Shamir hashes and not
individually labelled transcript domains: the current harness draws them from
the verifier-side ChaCha stream (`rust/volta-mac/src/transcript.rs:1-8,20-38`).
The sound requirement is freshness plus an injective, version-bound public
schedule.  No existing challenge role is removed or reused, but every inserted
`beta`, reducer-round `rho`, or aux `mu` shifts all later stream positions;
that is the explicit challenge-order amendment.  Full-correlation
domains are public, proof-shape-derived, disjoint for every reducer/round,
and bound to connection, response nonce, phase/chunk, group, layer, tensor,
and role.  The verifier rejects proof-selected keep/remove schedules, wrong
lengths, padding changes, duplicate domains, trailing rows, and a chain that
crosses a chunk.  The current five-chunk id-space cap
(`model_proof.rs:242-250`) remains an engineering limit to remove later, not
a product limit.

Witness generation stays byte-for-byte unchanged.  The reducer evaluates an
existing witness tensor during proof generation; it does not add a witness
field or alter fixed-point semantics.  Correlation masks remain fresh,
one-time, monotonically allocated, and burned by the existing connection
lifecycle.

## 6. M1--M10 coverage and the required M11

| Formal item | What it covers here | What it does not cover |
| --- | --- | --- |
| M1 MAC linearity | affine `[1,beta]` claim and public `g_beta(rho)` scaling | recursive meaning of a late terminal scalar |
| M2 scalar `Pi_ZeroBatch` + Counting | one global terminal zero list (net -68 rows); `card_linearForm_zero_le` gives the one-root affine-collapse algebra for a fixed false coefficient | recursive claim transport or the concrete LogUp-aux true semantics |
| M3 blind sumcheck | masked degree-two reducer rounds and the already-present degree-three aux-leaf round/deviation method | its theorem assumes a pre-bound final-opening functional; it does not prove the non-empty aux fraction-tree semantics (`BlindSumcheckSound.lean:65-79,125-165,393-403`) |
| M4 | retained K/V write-log and replay protection | residual thinning (intentionally not used) |
| M5 | unchanged 8-byte Fp boundary corrections | reducers use existing full-field correlations |
| M6 | perfect-ZK sequential composition of the extra blind windows with fresh offsets | sequential **soundness** |
| M7/M8 | unchanged secret-product closures inside the LogUp leaf terminal | not the fraction-tree/late-claim compatibility statement |
| M9 | unchanged weight PCS-to-MAC seam | no activation-chain claim |
| M10 | response-domain noncollision, fresh offsets and shared-Delta hiding; generic `response_bad_card_le` / `connection_soundness_union_bound` at `Connection.lean:118-157` lift any established response-slice bound without independence | it needs M11 to supply that T1 response-slice bound first |

Thus M1--M10 do **not** prove the chosen recursive claim reduction.  The gap
has three inseparable faces: M3's final opening is a public-linear functional
of a witness fixed before `rho`, whereas T1 seals a scalar after `rho`; M3's
existing `clear_of_claims_zero` blind-to-clear bridge is tied to that pre-bound
`openingAuthed`; and the 46 newly non-empty LogUp aux paths need a concrete
affine-claim/fraction-tree final-compatibility theorem.  P7's outer batching
theorem is not that theorem: it requires homogeneous members and one common
point (`BatchSumcheckSound.lean:170-200`).  The only repository declaration
that otherwise names general LogUp-GKR soundness is the ideal-model boundary,
not a proved M1--M10 result, and may not be imported as an axiom.  M11 must
therefore cover both degree-two fan-out reducers and the degree-three aux-leaf
instantiation.  Treating either bridge or aux compatibility as a hypothesis
without proving its concrete instantiation would merely rename the gap.

No existing Lean type can express this gap: `MaliciousProver.wit` is fixed
before `rho`, while T1's terminal pairs are created after `rho`; Lean also has
no concrete model of `layer_leaf_ones_aux`.  Pretending that one scalar
`baseAtom` represents the whole terminal would be unsound.  The minimal
**M11 package** must therefore introduce two definitional interfaces (not
axioms) before proving the statements below:

- `LateRowProver F n d J` contains `sigma`, prefix-adaptive authenticated
  round wire pairs, post-`rho`/pre-later-coin authenticated terminal pairs
  `late : eta -> rho -> Fin J -> F × F`, and their public coefficients.  None
  of these functions accepts `Delta` or a later coin.  `lateRoundPoly`
  reconstructs the unique bounded-degree polynomial from the exact compressed
  wire form: degree two sends `[g(0),g(2)]`, degree three sends
  `[g(0),g(2),g(3)]`, and in both cases the verifier derives
  `g(1)=live_claim-g(0)` before interpolation.
- `lateClaimAt` is the exact `n+1`-row analogue of M3's `claimAt`.  Writing
  `A_i(t)` for the public-linear authenticated evaluation of round `i` and
  `L(rho)=sum_j coeff_j(rho)*late_j(rho)`, its rows are exactly
  `A_0(0)+A_0(1)-sigma`,
  `A_i(0)+A_i(1)-A_(i-1)(rho_(i-1))`, and
  `A_(n-1)(rho_(n-1))-L(rho)`.  `lateClaimAt` is built only with
  `authedOfPair`, public scaling and addition/subtraction, so M1 must prove
  every row `Valid Delta`; its verifier key formula must be proved
  pointwise, not assumed.

The compressed wire construction makes the first and middle plaintext rows
identically zero: `g(1)=live_claim-g(0)` supplies the first identity and each
updated live claim supplies the next.  They are logical rows for M11a, not new
entries in the response-wide M2 list.  Only the final late-terminal row is a
live closure row.  Each explicit eq reducer therefore adds exactly one such
row (42 per response); an activated LogUp aux claim extends the leaf's existing
terminal row and adds none.  This is the formal-to-counter map behind the
`8,238 -> 8,170` accounting.

With those exact definitions, the required blind-to-clear statement is:

```lean
/-- M11a: zero plaintexts of the exact authenticated late-row schema imply
    the existing clear verifier with the post-rho terminal functional. -/
theorem clear_of_late_claims_zero
    {F : Type*} [Field F]
    {n J : ℕ} {d : ℕ → ℕ}
    (hn : 0 < n) (P : LateRowProver F n d J)
    (eta : F) (rho : Fin n → F)
    (hz : ∀ j : Fin (n + 1),
      (lateClaimAt hn P 0 eta rho (j : ℕ)).x = 0) :
    clearAccepts hn (lateRoundPoly P eta) (P.sigma eta)
      (fun r => ∑ j : Fin J,
        P.coeff eta r j * (P.late eta r j).1) rho
```

This statement is not the former tautological `hfirst/hstep/hlast` wrapper:
the premise names the custom authenticated rows themselves.  The M11 proof
must also expose `lateClaimAt_valid` and the verifier-key mirror needed to
apply the existing scalar M2 closure; otherwise M11a is not accepted.

```lean
theorem lateClaimAt_valid
    {F : Type*} [Field F]
    {n J : ℕ} {d : ℕ → ℕ}
    (hn : 0 < n) (P : LateRowProver F n d J)
    (Delta eta : F) (rho : Fin n → F) (j : Fin (n + 1)) :
    (lateClaimAt hn P Delta eta rho (j : ℕ)).Valid Delta
```

The key-mirror companion must state equality between each
`lateClaimAt ... .k` and the verifier's public-linear reconstruction from the
same round/late correlation keys; it may not take a prover-supplied key or
`Delta`-dependent pair as a hypothesis.

The clear-level counting core is vector-valued.  Its types enforce the timing:
`claimed` and `truth` are fixed before `eta`; round `i` sees only the truncated
prefix passed by `clearAccepts`; terminal atoms may depend on `(eta,rho)` but
not on the later tape `omega`.

```lean
/-- M11b: affine compression to a post-rho terminal vector, followed by a
    later sound chain. -/
theorem affine_late_atoms_then_chain_sound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {n m J Bup : ℕ} {d : ℕ → ℕ}
    (hn : 0 < n) (hm : 0 < m)
    (claimed truth : Fin 2 → F)
    (hfalse : claimed ≠ truth)
    (roundPoly : F → ℕ → (Fin n → F) → Polynomial F)
    (TR : F → TrueRounds F n d)
    (atom atomTrue coeff : F → (Fin n → F) → Fin J → F)
    (upAccept : F → (Fin n → F) → Finset (Fin m → F))
    (hdeg : ∀ eta i pre, (roundPoly eta i pre).natDegree ≤ d i)
    (htotal : ∀ eta,
      (TR eta).total = truth 0 + eta * truth 1)
    (hfinal : ∀ eta r,
      (TR eta).finalEval r =
        ∑ j : Fin J, coeff eta r j * atomTrue eta r j)
    (hup : ∀ eta r,
      atom eta r ≠ atomTrue eta r →
        (upAccept eta r).card ≤
          Bup * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega :
        F × ((Fin n → F) × (Fin m → F)) =>
      clearAccepts hn (roundPoly Omega.1)
        (claimed 0 + Omega.1 * claimed 1)
        (fun r => ∑ j : Fin J,
          coeff Omega.1 r j * atom Omega.1 r j)
        Omega.2.1 ∧
      Omega.2.2 ∈ upAccept Omega.1 Omega.2.1)).card ≤
      (1 + (Finset.range n).sum d + Bup) *
        Fintype.card F ^ (n + m)
```

Its tape denominator is `|F|^(n+m+1)`.  An eq reducer instantiates `J=1`,
`d_i=2`, terminal atom `S(rho)`, and coefficient
`eq(u,rho)+eta*eq(v,rho)`, giving the exact new numerator `1+2n+Bup`.
M11a plus M1/M2 maps the authenticated compressed transcript to this clear
event; no pre-bound `openingAuthed` or ideal LogUp axiom is permitted.
The instance must prove the live-claim identity
`P.sigma beta = a + beta*b`; it is not inferred from the true-total equation.

The LogUp child step needs a separate vector lemma.  It uses **all** pairs
fixed before the one shared child challenge, not just the target output pair:

```lean
/-- M11c: one shared fresh t collapses any finite vector of fixed pairs with
    at most one root, independent of the vector length. -/
theorem shared_pair_collapse_then_chain_sound
    {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {C m B_after : ℕ} (hm : 0 < m)
    (pair pairTrue : Fin C → Fin 2 → F)
    (hfalse : pair ≠ pairTrue)
    (after : F → Finset (Fin m → F))
    (hafter : ∀ t,
      (fun c => pair c 0 + (pair c 1 - pair c 0) * t) ≠
        (fun c => pairTrue c 0 +
          (pairTrue c 1 - pairTrue c 0) * t) →
      (after t).card ≤
        B_after * Fintype.card F ^ (m - 1)) :
    (Finset.univ.filter (fun Omega : F × (Fin m → F) =>
      Omega.2 ∈ after Omega.1)).card ≤
      (1 + B_after) * Fintype.card F ^ m
```

The concrete M11 Rust-mirror instantiation is part of the proof obligation,
not a hypothesis named `B.trueFinal`.  At every affected leaf it must set
`C=2+n_cols` and enumerate exactly
`[p0,p1]`, `[q0,q1]`, and every
`[col_half0[ci],col_half1[ci]]`, including at least the range `rem` and `out`
columns.  It must prove by unfolding `layer_leaf_ones_aux` that

- every reconstructed aux round polynomial has degree at most three, its
  `[g(0),g(2),g(3)]` wire form derives `g(1)` from the live claim, and the
  resulting round recursion is exactly `clearAccepts`;
- the malicious/live initial claim is definitionally
  `P.sigma mu = base_claim + mu*external_claim`, while the true total is
  `total_base + mu*MLE(col,point)`; these are distinct obligations;
- the fixed-before-`mu` total and post-`rho` terminal equations are exactly

```text
total(mu) = total_base + mu * MLE(col, point)
terminal = cpref * (lambda * (z0 + z1) + z2)
         + eq(point_tail, rho) *
             (mu*(1-point_0)*col_half0
              + mu*point_0*col_half1)
child[c] = pair[c][0] + t*(pair[c][1]-pair[c][0])
```

For M11b, the affine claimed pair is `(base_claim, external_claim)` and the
true pair is `(base_total, MLE(col,point))`; falsity of the external claim
makes these functions unequal even when the malicious base claim is also
wrong, so no `base_claim=base_total` hypothesis is allowed.  Its terminal
atom vector is the flattened full `pair` vector (plus the existing `z` atoms),
and its `upAccept` bound is discharged by M11c together with M7/M8/M2.
The last displayed line must be proved to be the LSB-first MLE at `(t,rho)`.
M7/M8 cover the
three existing `z` products and M2 covers their terminal zero rows; neither
may substitute for equality of the whole pre-`t` pair vector.  The absolute
new-aux leaf term is therefore `1_mu + 3l + 1_t + B_after`; the current
empty-aux leaf already has `3l + 1_t + B_after`, so the T1 delta is exactly
one `mu` root per activated leaf.  There are 46 such leaves: delta 46, not 92.

If M11a--c or this concrete full-vector instantiation cannot be proved without
`Ideal.LogUpGKRSound`, the hard stop remains; no axiom may be added.

Recursing M11 through the fused chain gives linear, not exponential,
accumulation.  M2 separately charges the exact resulting shared scalar-power
zero list.  Once M11 supplies the full response-slice statement, M10's generic
fixed-rest theorem lifts it across connection responses without independence.
The proof and standard `#print axioms` audit must precede Rust, exactly as for
M10.

For the record response, `n_prefill=ceil(log2(100))+ceil(log2(768))=17`
and `n_decode=16`.  The 42 explicit degree-two reducers add

```text
21*(2*17+1) + 21*(2*16+1) = 735 + 693 = 1,428
```

to the **incremental T1** bad-tape numerator.  Claim-driven plumbing retires 55 legacy
zero rows and adds 21 reducer terminal rows per phase, so the response-wide
M2 list changes by `2*(-55+21) = -68`: `8,238 -> 8,170` claims, with scalar
numerator `8,171`.  The unchanged product list has `21,667` claims and
numerator `21,669`.  Activating one previously empty external-claim list in
46 LogUp leaves adds one outer affine-collapse root per leaf.  The leaf's
degree-three rounds, child-bit collapse and downstream base chain already
belong to its existing M3/M7/M8/M2 term; the incremental M11 charge is
therefore `1,428 + 46 = 1,474`.  The tracked closure-plus-T1 subtotal is

```text
21,669 + 8,171 + 1,474 = 31,314
```

versus C3b's corresponding closure subtotal
`21,669 + 8,239 = 29,908`, an exact net change of `+1,406/|E|`.  The
31,314 subtotal alone is 113.065480 bits over `E=Goldilocks^2`, versus
113.131756 bits for the corresponding C3b subtotal.  It deliberately omits
the pre-existing per-leaf `3l+1_t+B_after` terms and the other unchanged M3/
base terms, so it is **not** an absolute protocol bound.  The PCS response
term remains the separately pinned 78.809-bit bound.

More generally a full k-layer group at one shape contributes explicit-reducer
numerator `(2k-1)*(2n+1)`, plus one affine-collapse root for every newly
non-empty external aux-claim list.  Its M2 delta must be derived from the exact
row-replacement map; it is not automatically `+(2k-1)` because old direct
boundary rows are retired.  If `B_C3b` denotes the complete already-accounted
C3b scalar numerator including those omitted base terms, the amended slice is
bounded by `(B_C3b + 1,406)/|E|`; across `R` equal-geometry responses M10 gives
`R*(B_C3b+1,406)/|E|`.  Equivalently, the exact T1 increment is
`R*1,406/|E|`.  No independence is claimed, and M11 must identify `B_C3b`
from the pinned base proof rather than setting it to 29,908 or 31,314.

## 7. Cost model and exact response projection

The straightforward reducer builds two eq tables, forms their affine
combination, and runs the existing blind product sumcheck.  Under the current
counter convention it charges `5N-4` E-mult equivalents; including both fold
streams, actual vector work is `7N-6`.  The transcript is `32n+16 B` (two
Fp2 round corrections plus one terminal scalar correction), and it consumes
`2n+1` existing full correlations.

| Phase | reducers | n / N | Bytes each / total | Full corrs each / total | charged E-mults | fold-inclusive E-mults |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| prefill | 21 | 17 / 131,072 | 560 / 11,760 | 35 / 735 | 13,762,476 | 19,267,458 |
| decode | 21 | 16 / 65,536 | 528 / 11,088 | 33 / 693 | 6,881,196 | 9,633,666 |
| **response** | **42** | | **22,848** | **1,428** | **20,643,672** | **28,901,124** |

Claim-driven transport also retargets existing relation outputs.  Per phase it
adds 9 internal-FBO claims to FFN-down, 12 reduced-ABO claims to attention
projection, and two nonzero-seam X/F claims: 23 external auxiliary claims.
Those LogUp/range instances already execute `blind_instance_prove_*_aux` with
an empty claim list (`rust/volta-proto/src/logup.rs:2611-2645`), so activating
the aux fold itself adds no round correction, correlation, synchronization
epoch, or proof instance.  Preparing 21 of those values per phase does require
the q-scalar authentication identified in §4:

| Phase | fresh q claims | Scalar corrections | Full corrs | MLE-eval E-mults (`N-1` each) |
| --- | ---: | ---: | ---: | ---: |
| prefill | 21 | 336 B | 21 | 2,752,491 |
| decode | 21 | 336 B | 21 | 1,376,235 |
| **response** | **42** | **672 B** | **42** | **4,128,726** |

The aux fold adds real work in `layer_leaf_ones_aux` (`logup.rs:710-835`).
The preregistered counter expression was `11*N/2 + 2*(n-1) - 6` E-mults.
Phase-2 instrumentation found that the shared-child root operations were
already included before that subtraction, so `-6` double-counted the saving.
The measured Rust mirror is `11*N/2 + 2*(n-1)`; the table preserves both the
preregistered and reconciled numbers.

| Phase | aux claims | N | prereg each / total | reconciled each / total |
| --- | ---: | ---: | ---: | ---: |
| prefill | 23 | 131,072 | 720,922 / 16,581,206 | 720,928 / 16,581,344 |
| decode | 23 | 65,536 | 360,472 / 8,290,856 | 360,478 / 8,290,994 |
| **response** | **46** | | **24,872,062** | **24,872,338** |

The preregistered complete charged delta was **49,644,460 E-mults**
(1.788523%); the reconciled delta is **49,644,736** (1.788533% of
C3b's `2,775,723,398.8` instance reference); the fold-inclusive vector-work
delta moves from preregistered **57,901,912** (2.086012%) to reconciled
**57,902,188** (2.086022%).  The two existing report buckets must not
be conflated: auxiliary-root work changes `ctr_instances` from
`2,775,723,398.8` to **`2,800,595,736.8`**, while reducer plus q-evaluation
work changes `ctr_other` from `90,080,563.2` to **`114,852,961.2`**.  Their
deltas, `24,872,338 + 24,772,398`, reconcile exactly to `49,644,736`.
A full T=100+50/Q=120 development instrumentation run measured every one of
these values exactly; the clean records remain the sources of record for gate
closure.  No GPU utilization benefit is credited: the
deeper reverse dependency can split the current model-wide cohorts into group
wavefronts.  If all 21 sites of each phase batch by round, reducers add exactly
17 prefill plus 16 decode challenge/readback epochs.  A conservative kernel
census is about 2,079 product/fold bodies + 126 eq setup/affine launches + 759
aux row-build/fold launches + 693 q-evaluation folds = **3,657 new launches**,
below 0.26% of C3b's 1,423,901.  Aux transport adds no round epoch.  At
unchanged aggregate throughput, the pod wall projection is about
`+0.075..0.087 s` on the 4.183011-s response.
New public point/control H2D is conservatively below 0.1 MB, so the 100-MB
absolute gate retains headroom, but only Phase 2 could measure it; the binding
sync gate remains the absolute 0.150-s maximum, not a launch-count proxy.

On CPU, proportional scaling of the charged/fold-inclusive work gives about
`+0.354..0.413 s`.  Charging all 49.644M counted E-mults at the conservative
observed C3b L4 rate gives about `+0.791 s` (`+0.527 s` prefill and `+0.264 s`
decode after rounding).  The preregistered paired ceiling remains
**T1/C3b median prove-response <= 1.05** in a same-process ABBA run: against
the historical 19.801130069-s scale only, its 0.990057-s allowance is 1.25x
the conservative projection and yields a 20.791186572-s ceiling.  The actual
Phase-2 denominator must be its fresh paired C3b baseline.  The trade buys
21.173 MB of response communication.

The exact communication projection is:

| Component | Current C3b | T1 delta | T1 reference |
| --- | ---: | ---: | ---: |
| prefill | 42,897,312 | -14,131,200 + 11,760 + 336 | 28,778,208 |
| decode marginal (50) | 19,546,432 | -7,065,600 + 11,088 + 336 | 12,492,256 |
| PCS | 43,273,888 | 0 | 43,273,888 |
| **response** | **105,717,632** | **-21,196,800 + 22,848 + 672** | **84,544,352** |

The projected decode marginal is `249,845.12 B/token`.  Subfield correlations
fall from `7,443,190` to `4,793,590`; full correlations rise from `180,463`
to `181,933`.  At two sub-equivalent limbs per full correlation, response
demand falls from `7,804,116` to `5,157,456`.  The stage-3
`110,918,718`-entry capacity would therefore move from about 2.13k to about
3.23k 150-row token-equivalents, subject to Phase-2 exact allocation digests.

**The honest result does not clear ~75 MB.**  The immutable K/V and other
streams leave a 34,662,320-B correction floor before retained group seams,
and PCS remains 43,273,888 B.  T1 clears only its derived reference of
84.544352 MB; the approximately 9.54-MB gap to 75 MB is not hidden or assigned
to a blind `/4` projection.

## 8. Preregistered Phase-2 gates — approved 2026-07-18

- **G1 communication.** `auth_corrections <= 38,348,720 B`; binding total
  response gate `<= 85,000,000 B`, with the exact projected reference
  `84,544,352 B` to be replaced only by the exact measured reference pinned at
  closure; reducer transcript exactly `22,848 B`; q-scalar transport
  corrections exactly `672 B`; PCS exactly `43,273,888 B`.  Any change to
  Q/rate or publication policy is a deviation, not a T1 fix.
- **G2 prover/provider.** Same-process CPU ABBA T1/C3b median prove-response
  `<=1.05`, with phase walls and exact E-mult/correlation counters reported.
  Pod absolute contract is unchanged: prefill `<=10 s`, decode marginal
  `<=4 s`, H2D `<=100,000,000 B`, maximum absolute synchronization wall
  `<=0.150 s`, flat last/first `<=1.5`.  Larger fused chains receive zero
  unmeasured utilization credit.
- **G3 correctness/adversarial.** Golden 50-token decode remains bit-exact;
  all acceptance, malicious, replay, leakage, non-power-of-two-T, mock/real
  parity, and full workspace suites are green.  A permanent cheating-prover
  test forges an internal unauthenticated layer state and is rejected by the
  fused chain; chunk-boundary seam substitution also rejects.  Counters must
  match the amended budget exactly, including `closure_zero_claims=8,170`,
  `closure_prod_claims=21,667`, `corr_sub_corrs=4,793,590`, and
  `corr_full_corrs=181,933`.
- **G4 record/profile.** Append-only `t1-*.json`: clean CPU T=100+50/Q=120
  ABBA record and, only after separate user confirmation before paid use, a
  fresh pod wall-only+counters record.  A new profile version binds the exact
  `84,544,352 B` response reference; historical profiles and records are not
  rewritten.

## 9. Lean-first stop disposition

M11a--c and the concrete full-vector leaf instantiation are proved and audited
in `lean/VoltaZk/BoundaryThinningSound.lean`; the corresponding rows are in
`docs/protocol-sketch.md`.  The prerequisite stop is therefore discharged.
Phase 2 must still stop on a gate FAIL.  On 2026-07-19 the product owner
removed R1 from this package's operational plan because the implementing
assistant does not have the required trusted-access posture; the review is
deferred to Kimi3 and confers no assurance on the T1 closure.  The handoff is
recorded in `docs/r1-kimi3-handoff.md` and the ledger.

## 10. Phase-2 closure (2026-07-19)

The exact measured reference is the preregistered value, now pinned by both
clean records at `b14577e12f35276c31482cf24dba41b6478905f9`:

- response `84,544,352 B <= 85,000,000 B`; authentication corrections
  `38,348,720 B <= 38,348,720 B`; reducer transcript `22,848 B`; q-scalar
  transport `672 B`; PCS `43,273,888 B`;
- the post-thinning correction split is exactly residual seams `3,686,400 B`
  + non-thinnable K/V `22,118,400 B` + other `12,543,920 B` =
  `38,348,720 B`;
- CPU same-process ABBA is `38.317683641 / 38.118634535 = 1.005221832`,
  PASS against `1.05`;
- A100 v4 is prefill `2.4120642 s`, decode marginal `1.618844210 s`, H2D
  `67,618,556 B`, maximum absolute synchronization `0.117210172 s`, and flat
  `1.231125469`; every absolute gate passes;
- exact counters are sub/full `4,793,590 / 181,933`, product/zero closures
  `21,667 / 8,170`, `ctr_instances=2,800,595,736.8`, and
  `ctr_other=114,852,961.2`.

The append-only records are
`benchmarks/results/t1-cpu-real-2026-07-19-b14577e.json` (SHA-256
`7fe5eeaec1601ab3af9951129a7684de6bdf81b8ec8ac4afe94fc8369fe6febb`)
and `benchmarks/results/t1-a100-realpcg-v4-2026-07-19-b14577e.json`
(SHA-256
`1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`).
Both pass `scripts/report.py --validate-t1-official`.  The workspace,
malicious/replay/non-power-of-two tests and both explicit production-size
two-weight-set leakage smokes are green.  No historical record or validator
reference was rewritten.

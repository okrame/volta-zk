# C2 — Packed16 typed-lane real-PCG design

**Status (2026-07-15): preregistered design only; mandatory user-review hard
stop.**  This document selects a construction for a future fase-C
implementation.  It authorizes no Rust, CUDA, Lean, PCG, proving-path, or C1
Phase-2 work.  The mock backend remains the default and C1 Phase 2 remains
**BLOCKED**.

The C1 §3.4 review decision is now fixed: the frozen correlation semantics are
the MAC equation, verifier-only `Delta`, one-time use, domain separation, and
exact counting.  The plaintext-distribution catalogue is extensible, and the
typed `(uniform u16, uniform bit)` `Packed16Corr` lane is authorized.  The
current fase-B real backend still realizes only the `F_p` lanes.

## 1. Contract and threat model

Let `F = F_p` be the Goldilocks prime field and `E = F_p^2`.  The prover `P`
holds each plaintext/share pair `(x, m) in F x E`; the verifier `V` holds
`k in E` and the one session key `Delta in E`.  Every final typed correlation
must satisfy

```text
k = m + Delta * x  in E.
```

For the two typed lanes, `x` is restricted as follows:

| Typed lane | Required plaintext distribution | Final relation |
| --- | --- | --- |
| packed u16 mask | exactly uniform on `{0,...,2^16-1}` | `k_a = m_a + Delta*a` |
| packed carry pad | exactly uniform on `{0,1}` | `k_b = m_b + Delta*b` |

As for every PCG realization, “uniform” means computationally
indistinguishable from this ideal distribution under the registered
assumptions.  “Exactly” fixes the support and rules out modulo/truncation
bias; it does not claim information-theoretic randomness from a finite seed.

The same verifier-sampled session `Delta` is used by both fase-B `F_p` shards,
all typed outputs, and the typed-lane check masks.  It is never serialized or
derivable from a role seed.  The binary COT engine has a separate internal
XOR correlation `delta_bin`; `delta_bin` is not `Delta` and is never exposed as
a protocol correlation.

The security target is static malicious security with abort, matching the
fase-B setup boundary.  Before any adversarial abort decision, and in every
session that reaches the sealed typed output without deviation:

- `P` cannot select the typed plaintexts or learn an unchosen COT branch;
- `V` cannot bias the typed plaintexts, even if it learns or influences the
  COT receiver choices allowed by the Ferret leakage model;
- `V` alone knows `Delta`, and the arithmetic lift does not reveal it to `P`;
- all outputs are fresh, domain-separated, exactly counted, and used once.

As in any two-party protocol without fairness, either corrupt party can abort
after learning its own view.  Fase-C therefore claims “cannot bias except by
abort,” not fairness of the distribution conditioned on a malicious party's
decision to complete.  The verifier must issue one single-use response
authorization nonce and permanently consume it on success **or abort**; it
must reject reconnect, resume, or a new PCG session for the same response
request.  A genuinely new application request starts a fresh session with
fresh role entropy and a fresh `Delta`.  The complete aborted-session
identifier, allocations, generated COTs, typed outputs, and unused headroom
are burned.  Without this lifecycle precondition, repeated selective aborts
could bias the set of completed sessions and fase-C must fail capability
preflight.

Against a corrupt prover, malicious COT security protects the unchosen branch
and `Delta`, while the transcript-bound arithmetic check and downstream MAC
verification protect authenticity.  Against a corrupt verifier, receiver
privacy and the hidden honest coin seed protect the typed plaintexts; a
designated verifier can always deny service or corrupt its own keys, which is
represented only as abort in the ideal functionality, never as an accepted
honest-verifier proof.

### 1.1 Allocation digest and counters

The C1 §5 public accounting labels and values remain canonical and are not
renamed:

```text
ordinary F_p sub correlations  = 1,913,526
packed u16 mask correlations   = 5,529,600
packed carry-pad correlations  = 5,529,600
new sub-equivalent total       = 12,972,726
full correlations              =   176,880
fresh carry-domain rows        =     7,200
removed identity-x_in draw rows =    1,350
net fresh rows                 =     5,850
identity-seam aliases (N_reuse) = 1,036,800
```

Each typed allocation is keyed by the existing
`(session, phase/chunk, layer, tensor, row)` identity plus a mandatory typed
lane tag.  Internal constituent bits additionally carry `bit_position=0..15`;
carry pads carry `bit_position=carry`.  The public allocation digest includes,
in canonical order:

1. the exact ordinary, typed, and full counts above;
2. all 7,200 u16 rows and all 7,200 carry-pad rows;
3. the nine legal identity-seam aliases and their 1,350 removed draw rows;
4. the COT batch/index and constituent-bit mapping for every typed output;
5. the six internal typed-lane check masks; and
6. the generated, consumed, and burned capacities below.

The external lane tags are fixed as `packed16/u16-mask` and
`packed16/carry-pad`.  Every internal hash, RNG, COT, and check domain includes
the session identifier, single-use response nonce, allocation digest, and one
of the following disjoint labels:

```text
c2/fp-shard/{0,1}
c2/ferret/setup
c2/ferret/main/{batch}
c2/choice-commit/{batch}/{P,V}
c2/choice-pad/{batch}
c2/lift/{lane}/{row}/{element}/{bit_position}
c2/check/{lane}/{repetition}
c2/seal
```

No prefix may be shortened, shared, or inferred from a mutable counter.

Both roles preflight the complete schedule and compare the allocation digest
before consuming a correlation.  C1's ordinary/packed/carry/reuse counters
retain these exact labels and values.  C2 adds setup-audit counters, without
changing those logical counters:

```text
packed16_source_bit_corrs = 94,003,200
cot_generated             = 100,000,000
cot_consumed              =  94,003,200
cot_burned_headroom        =   5,996,800
fp_main_shards             =           2
fp_usable_capacity         =  20,428,334
packed_lane_check_masks    =           6
```

Counters, the allocation digest, the channel digest, and the final seal must
agree on both parties.  A mismatch is a fail-closed session abort, never a
fallback to uniform-`F_p`, truncation, the mock backend, or a different proof.
Composition consumes each of the sixteen source-bit correlations once and
does not expose it as a second allocatable value.  Each final u16/carry
correlation is then consumable exactly once by its named C1 cell; seal,
success, abort, reconnect, and unused headroom all advance to terminal states.

## 2. Volumes and capacity preregistration

### 2.1 Exact typed demand

The required binary source count is not “about 94 million”; it is exactly

```text
u16 constituent bits = 16 * 5,529,600 = 88,473,600
carry-pad bits        =      5,529,600
total source bits     =     94,003,200.
```

Fase-C reserves ten Ferret-Uni output batches of 10,000,000 usable COTs, for
100,000,000 COTs total.  The documented binary headroom is therefore
5,996,800 COTs, or 6.379% above demand (5.9968% of capacity).  The last batch
is only partly allocated; every unused output is nevertheless counted and
burned at session seal.  There is no cross-session inventory.

### 2.2 Literal closure of the fase-B shortfall

C1 conservatively counts the 176,880 full correlations as two subfield limbs:

```text
logical correlations                         = 12,972,726
plus two limbs for 176,880 full correlations =    353,760
conservative sub-equivalent demand           = 13,326,486
current one-shard usable capacity            = 10,214,167
recorded shortfall                            =  3,112,319.
```

Fase-C does not erase that shortfall by relabelling typed outputs.  Its session
profile reserves **two complete, independent fase-B main shards**, each with
the already-measured usable capacity `n-k-t-2 = 10,214,167`, under the same
session `Delta` and distinct transcript/domain labels.  It therefore has
20,428,334 `F_p` sub-equivalent slots.  Reserving six fresh full-field mask
correlations for the three malicious checks on each typed lane gives

```text
required conservative capacity = 13,326,486 + 6 = 13,326,492
two-shard capacity              =                20,428,334
documented headroom             =                 7,101,842
```

This is 53.29% headroom above the conservative requirement.  Before the six
check masks, the added shard closes the recorded 3,112,319 deficit and leaves
7,101,848 slots.  The selected construction actually sources typed values from
the COT lane, so most `F_p` capacity is unused; that output is destroyed at
seal.  The deliberate double reservation makes the recorded capacity defect
truly closed and gives a measured, conservative cost model instead of relying
on an unmeasured resized LPN tuple.

Each shard retains the fase-B tuples and fanout exactly:

```text
recursive setup: (k0,n0,t0) = (25,000, 642,048, 2,508)
main stage:      (k,n,t)    = (589,760, 10,805,248, 1,319)
```

Fresh role seeds, base OTs, LPN noise, GGM trees, sacrifices, and malicious
checks are required per shard.  Only the verifier's session `Delta` is shared.
No base correlation, output, or check challenge is shared between shards.

## 3. Candidate constructions

### 3.1 Candidate A — malicious COT, arithmetic lift, then linear composition

**Selected, subject to user review.**  This is a new auxiliary binary lane.
The 2026-07-07 “not Ferret” decision rejected Ferret for the **main `F_p`
sVOLE**; it did not evaluate or forbid an auxiliary authenticated-bit source.
Fase-C explicitly proposes that new decision and leaves the main `F_p` lane on
fase-B.

The binary source is the malicious **Ferret-Uni** construction of Yang et al.,
[*Ferret: Fast Extension for coRRElated oT with Small
Communication*](https://eprint.iacr.org/2020/924).  The selected paper tuples
are

```text
one-time setup: (k,n,t) = (37,248,   616,092, 1,254)
main batch:     (k,n,t) = (588,160, 10,616,092, 1,324)
usable output per main batch = 10,000,000 COTs.
```

The protocol for each of the ten batches is:

1. Run the paper's malicious Ferret-Uni COT protocol, including its base-OT,
   consistency, and malicious-correlation checks.  Abstractly, `V` has
   `(q_i, delta_bin)` and `P` has `t_i = q_i XOR u_i*delta_bin`.  Nothing is
   released to the typed interface yet.
2. Freeze the complete pre-coin batch transcript as `T_j`.  `P` frames a
   commitment to a fresh uniform 256-bit `alpha_j`; `V` then frames a
   commitment to a fresh uniform 256-bit `beta_j`; `P` opens and `V` opens.
   Both commitments bind the role, session, batch, allocation digest, and the
   same `T_j`.  Failed or noncanonical openings burn the full session.
3. Both derive `s_j = XOF("c2/choice-pad", T_j, commitments, openings,
   alpha_j XOR beta_j)` and set
   `b_i = u_i XOR s_i`.  `V` locally replaces
   `q_i` by `q'_i = q_i XOR s_i*delta_bin`; then
   `t_i = q'_i XOR b_i*delta_bin` still holds.  If either party is honest,
   its seed was hidden until both commitments were fixed, so `b_i` is
   computationally uniform before an abort decision even when `u_i` was
   adversarially chosen or leaked.  Selective abort consumes the single-use
   response authorization and burns rather than retries.
4. For each `i`, use a domain-separated random-oracle/hash-to-field expansion
   with canonical rejection sampling to derive
   `h_i^0, h_i^1 in E` from the two COT branches
   `q'_i` and `q'_i XOR delta_bin`.  `P` can derive only `h_i^{b_i}`.  Every
   64-bit candidate field coordinate must be `< p`; rejection draws the next
   XOF block, so there is no modulo bias.
5. `V` sends one canonical `E` correction

   ```text
   c_i = h_i^0 - Delta - h_i^1.
   ```

   `V` keeps `k_i = h_i^0`; `P` sets
   `m_i = h_i^{b_i} + b_i*c_i`.  Thus

   ```text
   b_i = 0: m_i = h_i^0           and k_i = m_i
   b_i = 1: m_i = h_i^0 - Delta   and k_i = m_i + Delta.
   ```

   This is an exact arithmetic MAC under the existing session `Delta`.  The
   unknown COT branch is a one-time pad on `Delta`; learning both branches
   would break malicious COT security.  The generic arbitrary-abelian-group
   correlated-OT treatment in Scholl,
   [*Extending Oblivious Transfer with Low Communication via
   Key-Homomorphic PRFs*](https://eprint.iacr.org/2018/036), motivates this
   active group-correlation lift.  Fase-C uses the explicit correction above,
   not Scholl's LWE key-homomorphic PRF, so it adds no LWE assumption.
6. Consume disjoint groups of sixteen authenticated bits for every u16:

   ```text
   a   = sum_{r=0}^{15} 2^r b_r       in F
   m_a = sum_{r=0}^{15} 2^r m_r       in E
   k_a = sum_{r=0}^{15} 2^r k_r       in E.
   ```

   Therefore `k_a = m_a + Delta*a`.  Because `0 <= a <= 65,535 < p`, this
   field value is the unique 16-bit integer, not a wrapped representative.
   Sixteen independent uniform bits make `a` exactly uniform on the u16
   domain.  The disjoint seventeenth source bit is the uniform carry pad.

The ten-batch schedule bounds live state; a batch is lifted and assigned in
canonical allocation order before its storage is released.  The final partial
batch still burns all unallocated COTs.  Parallel workers may compute branch
hashes and field arithmetic, but frames are committed to the transcript in
batch/row/index order.

#### Malicious checks and fail-closed seal

The Ferret malicious check is retained verbatim and binds its challenges to
the complete framed binary-PCG transcript.  The arithmetic lift then receives
its own check after **all** correction frames have entered the transcript.
For each typed lane and each repetition `ell=0,1,2`, the verifier derives fresh
`chi_i in F` from a new framed verifier challenge, the frozen transcript,
session, lane, repetition, and allocation digest.  A fresh fase-B mask
correlation `(r*,m*,k*)` under the same `Delta` hides the opening:

```text
P -> V: B = r* + sum_i chi_i*x_i       in F
        M = m* + sum_i chi_i*m_i       in E

V:     K = k* + sum_i chi_i*k_i
        accept this repetition iff K = M + Delta*B.
```

`r*` makes `B` uniform in `F`, so the check does not reveal a typed plaintext
aggregate.  Any nonzero relation-error vector fixed before the challenge
passes one repetition with probability at most `1/p`; three independent
repetitions give at most `1/p^3`, approximately `2^-192`, per lane.  The
outputs become consumable only after all six checks pass and both roles record
the same seal `(session, allocation_digest, channel_digest, counters)`.  Bad
lengths, kinds, canonical encodings, commitments, COT checks, arithmetic
checks, digests, counters, EOF, duplicate frames, or trailing bytes abort and
burn the session.

The channel discipline is exactly fase-B's explicit
`kind:u8 || length:u64_le || payload` framing.  Both roles hash header and
payload into their own transcript copy and maintain exact directional and
per-phase byte counters.  `P` and `V` are independent state machines: no
shared seed, memory object, trusted dealer, or out-of-band correlation may
cross the role boundary.  `Delta`, `delta_bin`, branch seeds, and private role
seeds are forbidden message fields.  Every `E` correction is two canonical
little-endian `F_p` coordinates (16 bytes).  The deployment supplies an
authenticated, ordered point-to-point transport bound to the response nonce;
confidentiality of framed protocol messages is not used as a substitute for
the cryptographic checks.

### 3.2 Candidate B — `F_p` sVOLE plus decomposition/range checking

**Rejected for fase-C.**  One could use fase-B to authenticate prover-supplied
field values, coin-mask them after commitments, prove every constituent is a
bit with `z(z-1)=0`, and linearly compose sixteen checked bits.  More elaborate
truncation protocols could instead decompose an authenticated uniform `F_p`
value and prove a 16-bit remainder, as in the edaBit/conversion techniques of
Baum et al., [*Appenzeller to Brie*](https://eprint.iacr.org/2021/750).

This route has three concrete defects here:

1. Reducing a uniform Goldilocks element modulo `2^16` is not exactly uniform:
   `p` is not divisible by `2^16`.  Unchecked truncation or rejection is
   therefore forbidden by the typed interface.
2. A prover-supplied candidate is biasable until bitness/range and coin-order
   checks complete.  Those checks must be transcript-bound and fail closed;
   the fase-B MAC check alone proves only a field relation, not membership in
   `{0,1}` or the u16 interval.
3. The existing proof discipline authenticates `z(z-1)=0` through product
   machinery that itself consumes corrections/full correlations.  There are
   94,003,200 bitness constraints.  Even the optimistic charge of one full
   correlation per bit is 94,003,200 full correlations, or **188,006,400
   sub-equivalent limbs**, before authenticating the candidates, equality
   constraints, masks, or truncation quotient.  This exceeds the entire C1
   conservative demand by more than 14x and recursively asks the deficient
   correlation pool to prove that its replacement is well typed.

If all bitness checks did pass, a committed public XOR pad unknown when the
candidate bits were fixed would make each resulting bit uniform, and sixteen
independent checked bits would make the u16 uniform.  The objection is not to
that distribution argument; it is that establishing its premise consumes the
same correction/product resource being constructed.

Malicious security would require the fase-B sacrifice/WYKW checks, committed
coin masks, all bitness/range product checks, and a final transcript-bound
batch equality check.  Any failure would burn the session.  That is a valid
research direction only after an independent, non-circular preprocessing
source and its correction budget are preregistered.  It is not a cheaper
fallback for this design.

### 3.3 Candidate C — directly cited small-domain/subfield VOLE

**Rejected as a direct realization over the frozen MAC field.**  Guo et al.,
[*Half-Tree: Halving the Cost of Tree Expansion in COT and
DPF*](https://eprint.iacr.org/2022/1431), give COT and subfield-VOLE
constructions in the random-permutation model.  A subfield VOLE over
`F subset K` authenticates coefficients from the subfield `F`.  Taking
`F=F_2` supplies bits only when the extension field also has characteristic
two.  There is no embedding of `F_2` as a subfield of the odd-characteristic
`E=F_p^2`; taking the actual subfield `F_p` merely recreates uniform-`F_p`
fase-B output.

Consequently this family cannot emit `k=m+Delta*b` in the frozen `F_p^2`
MAC with `b in {0,1}` without an additional cross-characteristic conversion.
Such a conversion returns to Candidate A's OT correction or Candidate B's
range/conversion machinery.  Even before choosing a malicious wrapper, the
algebraic precondition fails, so no Half-Tree parameter set or hardness claim
is adopted and no LPN estimator number is claimed for it.

In a characteristic-two protocol, uniform subfield-VOLE coefficients would
give uniform bits.  Any malicious realization would still have to add or
retain sender/receiver consistency checks, bind every challenge to the
serialized transcript, and seal only checked output.  Here the capability
preflight detects the field mismatch before allocation and fails closed; that
is the only malicious-safe behavior.  Changing the MAC field to make the
candidate fit is outside C2.

### 3.4 Selection rationale

Candidate A is selected because it is the only evaluated route that gives
exactly uniform typed plaintexts, keeps the existing `F_p^2` MAC and session
`Delta`, has an actively checked COT source with concrete public parameters,
and avoids asking the proof/range machinery to manufacture its own
correlations.  Its cost is intentionally not hidden: the generic arithmetic
lift sends one 16-byte `E` correction for every source bit, so the COT core is
fast but setup communication is large.  User review must accept that trade
before any implementation is authorized.

## 4. Assumptions and pinned concrete estimates

### 4.1 Ferret-Uni LPN estimate

The adopted COT theorem is Ferret's malicious security under uniform/exact
binary LPN with the paper's static functional-leakage model, its malicious
consistency check, secure base OT, a secure PRG/fixed-key permutation, and a
correlation-robust hash/random oracle.  Base OT uses the same Ristretto255 DDH
boundary already registered for fase-B; the underlying active-OT lineage is
documented by Chou--Orlandi,
[*The Simplest Protocol for Oblivious Transfer*](https://eprint.iacr.org/2015/267).
The outer commitments, transcript, choice-pad XOF, and hash-to-field use
domain-separated BLAKE3 and model it as a collision/preimage-resistant random
oracle; the primitive is pinned by the
[BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
Production entropy must supply independent uniform 256-bit role seeds.

The public estimator is the
[Code Estimators suite](https://github.com/1234wangtr/Code_estimators) at
commit `969ef60c30cb84c25502d6b7c968f43a362bb438`, also published through
[lpnestimator.com](https://lpnestimator.com/).  The runs use its exact/uniform
noise path over `q=2`:

```text
analysisfor2(616092,   37248, 1254)  # Ferret-Uni setup
analysisfor2(10616092, 588160, 1324) # Ferret-Uni main
```

| Tuple | Minimum known attack | Bits | Margin over 128 |
| --- | --- | ---: | ---: |
| Uni setup `(37,248,616,092,1,254)` | BJMM | 142.658999 | 14.658999 |
| Uni main `(588,160,10,616,092,1,324)` | BJMM | 153.876937 | 25.876937 |
| ten main instances, subtract `log2(10)` | conservative multi-instance floor | 150.555009 | 22.555009 |
| one setup plus ten main instances | summed-work-factor floor | 142.652955 | 14.652955 |

For auditability, the setup sweep also reported Gauss `155.460100`, SD
`241.313506`, SD2 `240.336631`, and SD-ISD `146.469085`; the main sweep
reported Gauss `162.542106`, SD `236.935652`, SD2 `236.873531`, and SD-ISD
`155.199681`.  These are estimates against public known attacks, not a
reduction.  Ferret's static-functional-leakage LPN assumption remains an
external theorem assumption.

Ferret-Reg was evaluated and is not silently substituted.  At the same
estimator commit and `q=2`, the regular-noise call
`analysisfor2regular(10805248,589760,1319)` gives a 149.896647-bit minimum for
the paper main tuple, but the hybrid attack on its paper setup tuple
`(n,k,t)=(609728,36288,1269)` gives only **126.591702 bits**, below the
128-bit target by 1.408298 bits.  Candidate A therefore pins Ferret-Uni.
Changing either tuple, noise model, number of batches, leakage model, field,
or estimator commit reopens preregistration.

### 4.2 Two-shard fase-B estimate

Both `F_p` shards retain the ledger-pinned regular-LPN estimates from the same
public estimator at `log2(q)=64`: 140.646864 bits for the recursive setup and
149.477334 bits for the main tuple.  A conservative two-instance subtraction
gives 139.646864 and 148.477334 bits respectively.  Summing both setup and
both main work factors gives 139.643698 bits, an 11.643698-bit margin over
128.  The adopted hardness and malicious-check assumptions remain those of
Weng et al., [*Wolverine*](https://eprint.iacr.org/2020/925), and the fase-B
ledger entries; C2 changes only the number of independently seeded shards and
their common private session `Delta`.

No hardness assumption is assigned to Candidates B or C: they are rejected
before instantiation.  Any later attempt to revive an LPN-, LWE-, or
small-field-based variant requires its own cited, pinned estimator run and
margin before code.

## 5. Cost model over the measured fase-B baseline

The baseline is one measured fase-B setup:

```text
wall             = 22.483177 s
setup_comm_bytes = 31,261,434 B
```

It remains setup, not proof/response traffic.  The C2 planning model is:

| Component | Setup wall contribution | Setup communication |
| --- | ---: | ---: |
| Existing first fase-B shard | 22.483177 s measured | 31,261,434 B measured |
| Second independent fase-B shard | +22.483177 s conservative measured replay | +31,261,434 B |
| Ferret-Uni: 100 M usable COTs | +3.786 s literature projection | ~10,635,000 B |
| Arithmetic lift for 94,003,200 bits | +5--20 s engineering allowance | **1,504,051,200 B exact** |
| 14,400 typed-row frame headers | included above | 129,600 B exact |
| commitments/check/control reserve | included above | 1,048,576 B reserved headroom |
| **Sequential component-time subtotal** | **53.752354--68.752354 s** | **~1,578,387,244 B** |
| **Delta over one-shard baseline** | **+31.269177--46.269177 s** | **~+1,547,125,810 B** |

The exact arithmetic-lift payload is
`94,003,200 * 16 = 1,504,051,200 B`, all verifier-to-prover.  Of this,
1,415,577,600 B authenticates the u16 constituent bits and 88,473,600 B
authenticates carry pads.  The Ferret projection uses the paper's malicious
Ferret-Uni figures at 50 Mbps: approximately 33 ns/COT and 0.73 bit/COT,
plus about 0.486 s and 1.51 MB one-time setup.  Thus 100 M COTs contribute
about 3.3 s + 0.486 s and 9.125 MB + 1.51 MB.  Those figures come from a
different CPU/network and are projections, not VOLTA measurements.  The
5--20 s lift allowance covers batched branch hashing/rejection, field
arithmetic, composition, and the six final streamed checks; it must be
replaced by measurement before implementation can be called a parity result.

The displayed total communication is a planning envelope: the two fase-B
numbers and arithmetic correction are exact, while the Ferret paper uses
decimal aggregate figures and the explicit 1 MiB reserve covers control/frame
variance.  A future implementation must report exact P->V, V->P, category,
and total serialized counts; it may not report the envelope as a measurement.
The two fase-B shards alone project 57,628,168 B prover-to-verifier and
4,894,700 B verifier-to-prover.  The exact arithmetic lift adds
1,504,051,200 B verifier-to-prover.  Ferret's directional split and all
control bytes remain to be measured rather than guessed.

Raw serialization alone has the following lower bounds, before latency or
computation:

| Link rate | Full C2 setup envelope | Increment over baseline |
| --- | ---: | ---: |
| 50 Mbps | 252.542 s | 247.540 s |
| 1 Gbps | 12.627 s | 12.377 s |
| 10 Gbps | 1.263 s | 1.238 s |

For an intentionally conservative, non-overlapped deployment projection,
remove the 10,635,000 Ferret bytes whose 50-Mbps transport is already present
in the cited Ferret wall, then add the remaining transport floor to the
component-time subtotal:

| Link rate | Projected setup wall | Delta over 22.483177 s baseline |
| --- | ---: | ---: |
| 50 Mbps | 304.593--319.593 s | +282.110--297.110 s |
| 1 Gbps | 66.294--81.294 s | +43.811--58.811 s |
| 10 Gbps | 55.007--70.007 s | +32.523--47.523 s |

This second table is a conservative serialization model, not a claim that
computation and transport cannot overlap.  The raw-throughput table above is
the topology-independent lower bound; a future run replaces both projections.

The two `F_p` shards and the Ferret engine can run concurrently after the
session identity/allocation digest is fixed, subject to CPU and memory
contention.  Branch hashing and arithmetic lift are parallelizable within a
batch after its commit/open choice pad, while canonical frame emission stays
ordered.  The final transcript freeze, verifier challenge, six checks, and
seal are serialized.  No parallel number is claimed as a gate: the
53.75--68.75 s figure is the conservative sequential component-time subtotal,
and network transport must be accounted separately without double-counting
the Ferret paper's 50-Mbps timing.

Every byte above remains `pcg_setup_comm_bytes`.  It is **never** included in
response download, proof bytes, PCS opening bytes, or rho.  This separation is
accounting, not permission to hide the operational cost: a future clean run
must expose setup wall and setup traffic prominently, and product review must
accept them before any mock-to-real flip.

## 6. What fase-C does not change

This design changes only the future real-PCG setup capability.  It does not
change or authorize changes to:

- the proving or verification path;
- proof bytes, response bytes, PCS bytes, or the 150--200 MB response product
  constraint;
- the C1 response wire format, Packed16 payload, carry bitmap, or identity
  aliases;
- proof-transcript challenge order or any C1/M2--M9 equation;
- the mock backend default or current `pcg_production_ready:false` state;
- CPU/CUDA witness semantics, GPU kernels, orchestration, or resident state;
- `runpod-a100-v1`, any provider profile, gate, historical reference, or
  verdict; or
- Rust, CUDA, Lean, generated artifacts, benchmarks, or golden outputs in
  this task.

The frozen 144,820,930 B response remains the current reference.  C1's
104,040,130 B number remains a design projection only.  Fase-C setup traffic
is a separate category and changes neither number.

## 7. Review stop and future implementation preconditions

The design decision proposed for review is: adopt Candidate A with
Ferret-Uni, ten 10-million-COT batches, commit/reveal choice hardening, the
explicit 16-byte arithmetic lift, linear u16 composition, three masked
transcript-bound checks per typed lane, and two fase-B capacity shards under
one private session `Delta`.

Even after this file and its ledger entry exist, C1 Phase 2 remains
**BLOCKED pending user review**.  Approval of the design would authorize only
a separately scoped fase-C implementation task.  Mock-to-real criterion (6)
is not satisfied until that implementation exists, passes malicious/channel,
uniformity, exact-counter, allocation-digest, non-reuse, and clean full-session
tests, records a new append-only result, receives review, and lands at a
milestone checkpoint.  No part of C1 Phase 2 starts in the present task.

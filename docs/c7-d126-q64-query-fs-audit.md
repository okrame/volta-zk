# D126 Q64 query-amplification and tight-Fiat--Shamir audit

Date: 2026-09-04

This is the active analytic design for the D126 continuation.  It supersedes
the old D126 challenge-mode and context-cap choices.  Historical evidence in
`c7-stateful-authenticated-lfc-design.md` remains evidence only.

No protocol implementation, benchmark, hardware action, provider contact or
pod use is authorized by this audit.

## 1. Owner decisions and exact meaning

- The operational Gemma context cap is 4,096 tokens.  This is distinct from
  the model configuration's architectural maximum of 262,144 tokens.
- The attacker is not restricted to `Q_FS <= 2^30`.
- The theorem must use one global bound `Q_FS_global <= 2^64`.  That one bound
  includes local unobserved queries, concurrent sessions, failed attempts,
  aborts, retries and the complete `2^20`-`ResponseAttempt` lifetime.
- The current security thresholds are:
  - 76 bits: owner-authorized minimum;
  - 78 bits: preferred operating objective;
  - 84 bits: optimistic project objective and the meaning of `SECURITY_84`.
- Classical ROM, no online challenge during the proof, at most two packed-W
  HBM sweeps, one storage acquisition, one 80,000,000,000-byte H100, no spill,
  no full codeword, no second weight copy and no `qN` workspace remain fixed.

`N` is the source length, `q` is a query count and
`h=ceil(log2(N))`.  They are variables, not “profile constants”.  Lowering
the context cap does not remove any term that depends on `N`.

## 2. Security ledger

### 2.1 Global-query rule

For a rate-one-half strict-unique-decoding phase, define

```text
miss(ell) = (1 + 2^-ell)/2
epsilon[p,r] = miss(ell[p,r])^q[p,r].
```

Here `p` is one of `W`, `B`, `KV-old`, `KV-new`, and `r` is one
internal proximity phase.  The correct global contribution is

```text
epsilon_query_global
  <= (Q_FS_global+1) * sum_p sum_r epsilon[p,r].
```

The extra one covers an output whose final oracle value was not explicitly
queried.  At the owner bound the multiplier is therefore `2^64+1`.
`Q_FS_global` already covers the complete lifetime.  Multiplying this term by
`2^20` again would count the same attempts twice.  Non-FS attempt-local events
still need their own `2^20` union.

The complete target is

```text
epsilon_total
  = epsilon_query_global
  + epsilon_GKR
  + epsilon_PCS_gap
  + epsilon_mask
  + epsilon_MAC
  + epsilon_PCG
  + epsilon_hash
  + epsilon_state_replay
  + epsilon_abort_timing
  + epsilon_codec
  + every other named event
  <= 2^-lambda.
```

The event registry does not yet provide every numerator, denominator,
frequency and scope in this sum.  Therefore no complete 76-, 78- or 84-bit
claim exists today.

### 2.2 The requested q controls

The following is only the quick first-rate control requested by the owner.  It
does **not** include the internal-round union.  The four-term column treats the
four planes equally.  The five-term column adds one equally large stress term;
it is not a derived GKR bound.  It uses the prudent `2^64+1` multiplier; the
extra one changes none of the displayed six-decimal values.

| first-rate q | one term after Q64 | four equal terms | five-term stress control |
| ---: | ---: | ---: | ---: |
| 347 | 80.018012 | 78.018012 | 77.696084 |
| 350 | 81.263125 | 79.263125 | 78.941197 |
| 357 | 84.168387 | 82.168387 | 81.846459 |
| 362 | 86.243575 | 84.243575 | 83.921647 |

Thus `q=347` has only 1.696 bits above the new 76-bit floor in the
five-term stress control.  It has already fallen below the preferred 78-bit
objective before any additional event.  The value 77.696 is useful as a
warning, not as a complete security result.

Query-only uniform minima in this simplified control are:

| target | four terms | five terms |
| ---: | ---: | ---: |
| 76 bits | 343 | 343 |
| 78 bits | 347 | 348 |
| 84 bits | 362 | 363 |

### 2.3 Exact W internal-round control

The current W **fold-width** schedules `k_r` are `[4,5,3,3,3,4]` for GPT-2
and `[4,3,3,3,4,4,4,4]` for Gemma.  They are not the `ell` values in
`miss(ell)`.  Starting from `ell_0=1`, the inverse-rate exponent evolves as
`ell_(r+1)=ell_r+k_r-1`, giving `[1,4,8,10,12,14]` and
`[1,4,6,8,10,13,16,19]`.  Here the control `q` is the first-round count and
the later values are its registered balanced companions.  They are initial
probes, not global byte minima.  Summing every internal phase with its derived
`ell_r` and applying the global `2^64+1` factor once gives:

| first q | GPT-2 per-round q | Gemma per-round q | GPT query bits | Gemma query bits |
| ---: | --- | --- | ---: | ---: |
| 347 | `[347,158,145,145,145,145]` | `[347,158,148,145,145,145,145,145]` | 77.8796 | 77.5522 |
| 350 | `[350,159,146,146,146,146]` | `[350,159,149,146,146,146,146,146]` | 78.9114 | 78.5749 |
| 357 | `[357,163,149,149,149,149]` | `[357,163,152,149,149,149,149,149]` | 82.0064 | 81.6412 |
| 362 | `[362,165,151,151,151,151]` | `[362,165,154,151,151,151,151,151]` | 83.9919 | 83.6242 |

The isolated W response-gap term is 160.0113/153.1735 bits before the global
query factor, or 96.0113/89.1735 bits after it.  Adding that term and the
W-mask term under the explicitly conditional linear-BLAKE model gives:

| first q | GPT known-W bits | Gemma known-W bits | residual of 76-bit budget | residual of 78-bit budget | residual of 84-bit budget |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 347 | 77.87447 | 77.54655 | 72.727% / 65.767% | exhausted | exhausted |
| 350 | 78.90096 | 78.56346 | 86.612% / 83.083% | 46.447% / 32.332% | exhausted |
| 357 | 81.91738 | 81.54619 | 98.345% / 97.860% | 93.382% / 91.440% | exhausted |
| 362 | 83.66370 | 83.27656 | 99.507% / 99.355% | 98.027% / 97.420% | exhausted |

Each residual pair is GPT-2/Gemma and means the unused fraction of the stated
total error budget, not extra “security bits”.  Thus `q=347` is above 76 only
for W and has little useful room; `q=350` is above 78 for W but leaves only
46.447%/32.332% of that budget; `q=357` is the first requested control with a
useful W-only margin for attempting 78.  The displayed `q=362` companion
vectors do not reach 84, but that does not exclude a better internal
allocation with the same first-round count.

#### Exact W-only non-uniform byte minima

For each target below, every integer round count was varied.  The objective is
minimum offline-FS W `P_to_V` bytes, subject to the exact round union, the
all-fold gap, the conditional linear-BLAKE mask term and the prudent `Q+1`
factor.  These are global W-only minima inside the stated model, not complete
four-plane parameters.

| target/model | byte-minimizing per-round q | known-W bits | q sum / Z / U / S / H | P to V | V to P | offline-FS W floor | 105% margin | partial certificate |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 76 GPT | `[341,156,144,143,143,144]` | 76.016095 | 1,071 / 37,664 / 2,142 / 302,022 / 26,287 | 3,327,872 | 4,924 | 3,331,836 | -59,151 | 3,332,404 |
| 76 Gemma | `[342,156,146,144,144,144,144,144]` | 76.033087 | 1,364 / 43,824 / 2,728 / 384,648 / 50,513 | 4,783,000 | 6,296 | 4,826,028 | +670,667 | 4,826,596 |
| 78 GPT | `[346,158,146,145,146,145]` | 78.001579 | 1,086 / 38,152 / 2,172 / 306,252 / 26,619 | 3,373,296 | 4,984 | 3,377,260 | -104,575 | 3,377,828 |
| 78 Gemma | `[347,158,148,146,146,146,146,146]` | 78.001343 | 1,383 / 44,432 / 2,766 / 390,006 / 51,169 | 4,848,072 | 6,372 | 4,891,100 | +605,595 | 4,891,668 |
| 84 GPT | `[362,166,152,152,151,151]` | 84.000484 | 1,134 / 39,896 / 2,268 / 319,788 / 27,685 | 3,518,768 | 5,176 | 3,522,732 | -250,047 | 3,523,300 |
| 84 Gemma | `[362,166,155,153,152,152,153,153]` | 84.002279 | 1,446 / 46,448 / 2,892 / 407,772 / 53,349 | 5,063,992 | 6,624 | 5,107,020 | +389,675 | 5,107,588 |

`Z` is the unstacked Fp atom count, `U` the number of opened leaves,
`S=141*U` the visible Fp count, and `H` the exact compact-tree sibling count.
The 76/78/84 GPT floors retain
564,217/518,793/373,321 B under 125% and
1,343,428/1,298,004/1,152,532 B under 150%.  The Gemma floors retain
1,717,657/1,652,585/1,436,665 B under 125% and
3,026,394/2,961,322/2,745,402 B under 150%.

After the complete known-W conditional sum, the unused fractions of the
matching error budgets are respectively 1.109443%/2.267327% at 76 bits,
0.109368%/0.093077% at 78 bits and 0.033522%/0.157842% at 84 bits for
GPT/Gemma.  These percentages are security-error room, not byte room.  The
partial-certificate Gemma/GPT growth is 1.448383x, 1.448170x and 1.449660x.

The search enumerated the following inclusive boxes; individual soundness
lower bounds exclude smaller entries, while the cost of the displayed
candidate excludes larger ones:

```text
GPT 76: [338..352,154..168,141..155,141..155,141..156,141..156]
GPT 78: [343..358,156..170,143..157,143..158,143..158,143..158]
GPT 84: [357..375,163..180,149..166,149..167,149..167,149..167]
Gemma 76: [338..360,154..175,144..166,141..163,141..163,141..164,141..164,141..165]
Gemma 78: [343..365,156..177,146..168,143..165,143..165,143..166,143..166,143..167]
Gemma 84: [357..385,163..190,152..180,149..177,149..178,149..178,149..179,149..179]
```

The enumeration is exact over those boxes using meet-in-the-middle rational
sums.  It minimizes, in order, `(P_to_V bytes, q sum, q vector)`.  A coordinate
below its box cannot meet the target even if it were the only query term; a
coordinate above its box cannot beat the best feasible byte cost after adding
the minimum costs of all other coordinates.

The 84-bit W minima leave only about 0.034%/0.158% of the 84-bit error budget
for GPT/Gemma.  Any positive B, KV or GKR term therefore forces a different
allocation and normally larger counts.  The optimistic four-W-like proxy of
about first q369/372 remains only a search seed, not a replacement for the
missing B/KV layouts.

For every model the required residual table is:

```text
b_W       = -log2(e_W)
b_after_B = -log2(e_W + e_B)
b_after_KVold = -log2(e_W + e_B + e_KVold)
b_after_KVnew = -log2(e_W + e_B + e_KVold + e_KVnew)
b_after_GKR   = -log2(e_W + e_B + e_KVold + e_KVnew + e_GKR)
b_final       = -log2(the complete named sum).
```

The cumulative ledger stops at the first missing value, rather than silently
calling it zero:

| cumulative step | available quantity | residual after the step |
| --- | --- | --- |
| W queries + W response gap | exact for the rows above | included above |
| + W root-mask PRG | exact query volume; linear-BLAKE bound is only a named conditional assumption | included above, no theorem credit |
| + B query/gap/mask | B layout, folds and event numerator absent | **BLOCKED** |
| + KV-old query/gap/mask | KV-old layout, reuse horizon and folds absent | **BLOCKED** |
| + KV-new query/gap/mask | KV-new layout, creation horizon and folds absent | **BLOCKED** |
| + base GKR | exact round/degree/event registry absent | **BLOCKED** |
| + true-PCS gap/link events | carrier relation and event numerator absent | **BLOCKED** |
| + VOLE-MAC forgery | theorem-backed numerator and lifetime scope absent | **BLOCKED** |
| + production AES-PCG | concrete multi-session reduction and draw scope absent | **BLOCKED** |
| + hash/collision events | complete domains, call counts and assumptions absent | **BLOCKED** |
| + durable state/replay | bad-event numerator across concurrency and recovery absent | **BLOCKED** |
| + abort/timing leakage | adaptive observation model and bound absent | **BLOCKED** |
| + codec/canonicality | complete decoder event registry absent | **BLOCKED** |

This is why no complete 76-, 78- or 84-bit margin is reported.  A numeric
value after B, KV or GKR today would be invented, not conservative.

The old conditional allocation, before proving its premises, is exactly

```text
(2^20 * 64 * 2^-110) + 3*2^-128 + 2^-120
  = 17592186044675 / 2^128
```

or 83.99999999997876 bits.  It has about 8 bits over 76 and 6 bits over 78,
but is already strictly below 84 before adding another positive term.  The
current allocation therefore cannot make `SECURITY_84` pass unchanged.

### 2.4 Non-uniform q allocation

Let `E` be the exact remaining error budget after GKR and all non-query terms
have been subtracted.  It must be positive.  Index `i=(plane,round)`.  If that
entry's byte cost were linear, `cost_i(q_i)=c_i*q_i`, define
`a_i=-ln(miss(ell_i))`.  The continuous optimum would allocate error in
proportion to cost divided by amplification rate:

```text
epsilon_i = E*(c_i/a_i) / sum_j(c_j/a_j)
q_i = ceil( ln((2^64+1)/epsilon_i) / a_i ).
```

Only when all entries are first-rate `ell=1` does every
`a_i=ln(4/3)`, reducing the allocation to `epsilon_i` proportional to `c_i`.

The real codec is stepwise because leaf collisions and Merkle frontiers change
at integer boundaries.  The exact procedure is therefore:

1. compile `bytes_i(q)`, masks, correlations, prover work and verifier work for
   every integer q in the admitted range;
2. reject rows that violate any independent gate;
3. enumerate the remaining integer tuples;
4. keep only tuples whose exact rational error sum is at most `E`;
5. minimize complete certificate bytes, with work and memory as independent
   tie-breaking gates fixed before looking at the winner.

The B/KV layouts, their internal schedules and exact GKR error are absent.
Consequently the minimum per-plane tuple and its non-uniform optimum are
`BLOCKED`.  The values 347/350/357/362 remain initial probes only.

## 3. Exact W subcodec recompilation

The tables below use the non-uniform round vectors in Section 2.3.  They
exactly recompile the frozen **interactive control** Merkle/query subcodec.
They deliberately show prover-to-verifier and verifier-to-prover bytes
separately: offline FS keeps the former and rederives the latter.  For `R`
rounds the exact identities are

```text
P_to_V = 16
       + sum_r[16 + 8*S_r + 32*U_r + 4 + 32*H_r]
       + (R-1)*48
       + (16+1536)
       + (16+24)

V_to_P = sum_r[16 + 24*k_r]
       + (16 + 4*sum_r q_r).
```

The FS byte floor below removes every `V_to_P` byte.  It still omits the
unimplemented
`Encode/Fold/Extend/CheckExtend/EvalLink`, OOD, sumcheck, mask/base-case and
receipt messages.  It is an exact partial slice, not a complete W proof or a
complete FS transcript compiler.

### GPT-2 W

| first q | q_open | Z atoms | leaves U | visible Fp S | siblings H | P to V | V to P | stream total |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 347 | 1,085 | 38,120 | 2,170 | 305,970 | 26,597 | 3,370,272 | 4,980 | 3,375,252 B |
| 350 | 1,093 | 38,384 | 2,186 | 308,226 | 26,773 | 3,394,464 | 5,012 | 3,399,476 B |
| 357 | 1,116 | 39,240 | 2,232 | 314,712 | 27,283 | 3,464,144 | 5,104 | 3,469,248 B |
| 362 | 1,131 | 39,752 | 2,262 | 318,942 | 27,613 | 3,509,504 | 5,164 | 3,514,668 B |

### Gemma W

| first q | q_open | Z atoms | leaves U | visible Fp S | siblings H | P to V | V to P | stream total |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 347 | 1,378 | 44,216 | 2,756 | 388,596 | 51,009 | 4,831,352 | 6,352 | 4,837,704 B |
| 350 | 1,388 | 44,528 | 2,776 | 391,416 | 51,355 | 4,865,624 | 6,392 | 4,872,016 B |
| 357 | 1,417 | 45,456 | 2,834 | 399,594 | 52,361 | 4,965,096 | 6,508 | 4,971,604 B |
| 362 | 1,436 | 46,064 | 2,872 | 404,952 | 53,017 | 5,030,168 | 6,584 | 5,036,752 B |

The logical leaf counts, independent of q, are
`[3,807,596, 5,711,393, 2,855,697, 1,427,849, 713,925, 356,963]`
for GPT-2 and
`[487,372,176, 731,058,264, 365,529,132, 182,764,566, 91,382,283,
45,691,142, 22,845,571, 11,422,786]` for Gemma.  The exact verifier Merkle
hash counts are:

| first q | internal hashes GPT/Gemma | including opened-leaf hashes GPT/Gemma |
| ---: | ---: | ---: |
| 347 | 28,761 / 53,757 | 30,931 / 56,513 |
| 350 | 28,953 / 54,123 | 31,139 / 56,899 |
| 357 | 29,509 / 55,187 | 31,741 / 58,021 |
| 362 | 29,869 / 55,881 | 32,131 / 58,753 |

The known fixed W records split as 3,964/43,028 B `P_to_V` and
1,424/15,912 B challenge `V_to_P`.  Removing all `V_to_P` bytes, then adding
only the fixed `P_to_V` records while leaving every missing true-PCS message
at zero gives the following offline-FS record-byte floors.  The authoritative
allocations and caps are 3,116,843/5,234,948 B,
3,272,685/5,496,695 B at 105%, 3,896,053/6,543,685 B at 125%, and
4,675,264/7,852,422 B at 150%.

| first q | GPT FS W floor | % allocation | margin 105% | margin 125% | margin 150% |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 347 | 3,374,236 | 108.258132% | -101,551 | 521,817 | 1,301,028 |
| 350 | 3,398,428 | 109.034302% | -125,743 | 497,625 | 1,276,836 |
| 357 | 3,468,108 | 111.269897% | -195,423 | 427,945 | 1,207,156 |
| 362 | 3,513,468 | 112.725216% | -240,783 | 382,585 | 1,161,796 |

| first q | Gemma FS W floor | % allocation | margin 105% | margin 125% | margin 150% |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 347 | 4,874,380 | 93.112291% | 622,315 | 1,669,305 | 2,978,042 |
| 350 | 4,908,652 | 93.766968% | 588,043 | 1,635,033 | 2,943,770 |
| 357 | 5,008,124 | 95.667120% | 488,571 | 1,535,561 | 2,844,298 |
| 362 | 5,073,196 | 96.910151% | 423,499 | 1,470,489 | 2,779,226 |

Therefore the current GPT-2 schedule violates 105% for every requested
control, before missing positive byte terms.  Dropping to the minimum
W-only 76-bit row does not fix it: the exact minimizing vector is
`[341,156,144,143,143,144]`, `P_to_V=3,327,872 B`, and after the 3,964-B
fixed prover records its FS W floor is 3,331,836 B, still 59,151 B over 105%.
The 105% branch is therefore `NO-GO` even after deleting every online
challenge byte.  The known rows fit 125% and 150%, but one exact cap in that
band must be preregistered before the complete measurement.

Turning the W-only AuthBind into the required all-plane AuthBind adds 192 B:
`24*(J_all-J_W)=24*8`.  Adding the fixed 376-B certificate container gives:

| first q | partial GPT FS certificate floor | partial Gemma FS certificate floor | growth |
| ---: | ---: | ---: | ---: |
| 347 | 3,374,804 | 4,874,948 | 1.444513x |
| 350 | 3,398,996 | 4,909,220 | 1.444315x |
| 357 | 3,468,676 | 5,008,692 | 1.443978x |
| 362 | 3,514,036 | 5,073,764 | 1.443857x |

These partial floors pass 30/100 MB and 3x, but cannot pass the full
certificate gate because all missing records are nonnegative.

The counters also give exact partial work: the prover supplies `S` masked Fp
occurrences and `U` salts; the verifier parses those values and performs the
Merkle hashes counted above.  The known new correlation slice is 161/1,787
Fp3 correlations in total, of which 153/1,779 are W-only, or 483/5,361 base-
field slots.  The known challenge-scalar count is 77/686 before base GKR and
B/KV; it is not a count of sequential protocol rounds.  Exact true-PCS field
operations and complete prover/verifier work remain unknown because their
omitted messages and checks are not zero-cost.

## 4. Mask lifetime

For the W control the conservative charge is `S_visible_Fp` per attempt.  The
current lifecycle reserve is one eighth of the service count.  The current
RootMask dimensions are 134,980,992/2,741,852,160 coefficients; service counts
are 512/8,192 and root epochs per lifetime are 2,048/128.  For one root:

```text
mask_cells = (R_service + R_service/8) * S
mask_cells <= RootMask_dimension.
```

The exact W-only security minimizers from Section 2.3 propagate as follows.
This table prevents the requested first-q probes from being mistaken for the
actual 76/78/84 W minima.  It still excludes every B/KV mask.

| target/model | exact W q vector | Alt. 1 cells / unused | generator B/root | conditional PRG bits | Alt. 2 required cells / result | Alt. 3 rank saving |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| 76 GPT | `[341,156,144,143,143,144]` | 86,982,336 / 47,998,656 | 8,350,304,256 | 86.040818 | 173,964,672 / `2^29`, setup NO-GO | 22.408964% |
| 76 Gemma | `[342,156,146,144,144,144,144,144]` | 1,772,457,984 / 969,394,176 | 170,155,966,464 | 85.691933 | 3,544,915,968 / `2^35`, 117,477,120 cells left | 22.653959% |
| 78 GPT | `[346,158,146,145,146,145]` | 88,200,576 / 46,780,416 | 8,467,255,296 | 86.020753 | 176,401,152 / `2^29`, setup NO-GO | 23.480663% |
| 78 Gemma | `[347,158,148,146,146,146,146,146]` | 1,797,147,648 / 944,704,512 | 172,526,174,208 | 85.671976 | 3,594,295,296 / `2^35`, 68,097,792 cells left | 23.716558% |
| 84 GPT | `[362,166,152,152,151,151]` | 92,098,944 / 42,882,048 | 8,841,498,624 | 85.958356 | 184,197,888 / `2^29`, setup NO-GO | 26.719577% |
| 84 Gemma | `[362,166,155,153,152,152,153,153]` | 1,879,013,376 / 862,838,784 | 180,385,284,096 | 85.607709 | 3,758,026,752 / v1-forbidden `2^36` | 27.040111% |

For GPT, the residual space in the `2^29` coefficient domain after the
required RootMask and PublicZero regions is respectively
238,587,776/236,151,296/228,354,560 cells.  The domain is large enough, but
the setup-byte cap is not.  For Gemma the 76/78 rows still fit `2^35`; the
84 row does not.  “Conditional PRG bits” assumes the unproved linear-BLAKE
model and therefore receives no theorem credit.

### Alternative 1: fewer attempts per root

Keep the present domains, halve the power-of-two service counts to 256/4,096,
and double the root epochs to 4,096/256 so that service lifetime remains
`2^20`.  The reserve becomes 32/512.  A failed disclosed root consumes another
epoch.

| first q | GPT mask cells / unused | Gemma mask cells / unused |
| ---: | ---: | ---: |
| 347 | 88,119,360 / 46,861,632 | 1,790,650,368 / 951,201,792 |
| 350 | 88,769,088 / 46,211,904 | 1,803,644,928 / 938,207,232 |
| 357 | 90,637,056 / 44,343,936 | 1,841,329,152 / 900,523,008 |
| 362 | 91,855,296 / 43,125,696 | 1,866,018,816 / 875,833,344 |

The one-slot persistent setup remains 493,371,840/92,587,558,592 B.  The
minimum packed-read plus tree-write traffic per build is
492,323,264/92,586,510,016 B; over the success-only lifetime it is exactly
2,016,556,089,344/23,702,146,564,096 B.  Refreshes become 4,095/255 instead
of 2,047/127.  Worst-case two-seed, six-draw generator traffic per root and q
row is:

| first q | GPT generator bytes/root | Gemma generator bytes/root |
| ---: | ---: | ---: |
| 347 | 8,459,458,560 | 171,902,435,328 |
| 350 | 8,521,832,448 | 173,149,913,088 |
| 357 | 8,701,157,376 | 176,767,598,592 |
| 362 | 8,818,108,416 | 179,137,806,336 |

This option changes geometry and doubles refresh frequency; it does not reduce
the lifetime PRG exposure because `epochs*service_attempts` is unchanged.  A
new layout digest and a complete multi-root PRG theorem are required.

### Alternative 2: larger domain

Keep 512/8,192 service attempts and 2,048/128 epochs, but enlarge RootMask as
needed.

| first q | GPT required cells | Gemma required cells | required coefficient domain |
| ---: | ---: | ---: | --- |
| 347 | 176,238,720 | 3,581,300,736 | GPT `2^29`; Gemma still `2^35` with 81,092,352 PublicZero cells left |
| 350 | 177,538,176 | 3,607,289,856 | GPT `2^29`; Gemma still `2^35` with 55,103,232 left |
| 357 | 181,274,112 | 3,682,658,304 | GPT `2^29`; Gemma `2^36` |
| 362 | 183,710,592 | 3,732,037,632 | GPT `2^29`; Gemma `2^36` |

GPT's exact one-tree, metadata, footer and journal floor is 737,057,920 B,
2.964394x packed W.  It exceeds the 2.10x setup cap by 214,920,372 B and is
only 8,852,864 B below 3x: this is `NO-GO`.  Gemma q347/q350 keep the current
92,587,558,592-B setup.  q357/q362 need a codec change because v1 forbids
domains above `2^35`; a hypothetical `2^36` setup is 123,779,377,792 B,
2.016125x packed W, 989,996,672 B above 2x but 5,149,472,384 B below 2.10x.

Refresh counts remain 2,047/127.  Success-only build traffic is
1,507,347,136,512 B for GPT's `2^29`, 11,851,073,282,048 B for Gemma's
unchanged `2^35`, and 15,843,626,139,648 B for a hypothetical Gemma `2^36`.
The same PRG and adaptive-leakage theorems remain missing.

### Alternative 3: adaptive multi-session rank theorem

Keep the old domains, RootMask sizes, service counts and epochs.  The theorem
must prove per-attempt adaptive rank at most 234,342/297,510, requiring:

| first q | GPT rank saving from S | Gemma rank saving from S |
| ---: | ---: | ---: |
| 347 | 23.410% | 23.440% |
| 350 | 23.971% | 23.991% |
| 357 | 25.538% | 25.547% |
| 362 | 26.525% | 26.532% |

For every reachable adaptive transcript, including colluding sessions,
unobserved local queries, retries, feedback from aborts and root rotations, it
must prove both `Im(G_message|T) subseteq Im(G_mask|T)` and
`rank_load(T)<=t`.  Fixed-set honest-verifier ZK is insufficient.  Setup and
refresh would remain unchanged, but if the rank is understated the verifier
learns an exact unmasked linear relation; this is structural leakage, not a
small probability loss.  No such theorem exists, so this alternative is
`BLOCKED`.

For Alternatives 1 and 2, the two-seed, six-draw W lifetime volumes and the
conditional linear-BLAKE bounds are:

| first q | GPT/Gemma 64-bit words | conditional bits GPT/Gemma |
| ---: | ---: | ---: |
| 347 | 4,331,242,782,720 / 5,500,877,930,496 | 86.0221 / 85.6772 |
| 350 | 4,363,178,213,376 / 5,540,797,218,816 | 86.0115 / 85.6668 |
| 357 | 4,454,992,576,512 / 5,656,563,154,944 | 85.9814 / 85.6369 |
| 362 | 4,514,871,508,992 / 5,732,409,802,752 | 85.9622 / 85.6177 |

The separate six-draw rejection-failure control is about 152.6/152.2 bits.
Neither row is a proved BLAKE3 multi-session PRG theorem.  Generating the old
full RootMask after halving attempts would double exposure and is forbidden;
Alternative 1 must actually resize the generated mask.

All three alternatives above are exact only for W.  B/KV mask consumption is
unknown until their generated layouts and query schedules exist.  Therefore
`MASK_LIFETIME` is `BLOCKED`.

## 5. Complexity and two HBM sweeps

The required identity is

```text
C(N,q,h) = c_source*N + P(q,h),
```

where `c_source` is independent of both `N` and `q`.  With two allowed packed
source sweeps it may be written as

```text
c_source = c_sweep_1 + c_sweep_2,
```

provided neither sweep count nor per-source work grows with q.  `N log q`,
`qN` and `N log N` are forbidden.

For Gemma, one storage acquisition is exactly 61,394,690,560 B and two HBM
reads of packed W are exactly 122,789,381,120 B.  This gate applies to the
proof subsystem; ordinary inference GEMM traffic is reported separately, as
in the active ledger.  If “two sweeps” instead means the entire
inference-plus-proof attempt, the frozen 50-step autoregressive decode needs
repeated weight reads and the gate is immediately `NO-GO`.  That alternative
meaning requires an owner correction; it is not silently assumed here.

The repository contains no selected output-pruned transform.  The available
realizations allocate or persist complete transforms/codewords, perform
`Theta(N log N)`, or use direct `qN` evaluation.  Merkle path pruning removes
duplicate sibling hashes only; it is not an output-pruned encoder.

For clarity, the direct dense evaluator's exact FMA control is
`(N_W+Q_root)*282*first_q`.  The two values in each cell are Alternative 1's
reduced-attempt geometry and Alternative 2's enlarged RootMask geometry:

| first q | GPT-2 FMA control | Gemma FMA control |
| ---: | ---: | ---: |
| 347 | 20,787,890,829,696 / 29,410,722,683,136 | 3,179,080,326,139,392 / 3,354,302,627,249,664 |
| 350 | 21,031,741,382,400 / 29,793,250,368,000 | 3,207,847,733,529,600 / 3,385,867,487,923,200 |
| 357 | 21,640,432,020,480 / 30,765,226,996,224 | 3,275,798,509,767,168 / 3,461,172,480,815,616 |
| 362 | 22,067,882,115,840 / 31,444,838,152,704 | 3,324,198,460,376,064 / 3,514,689,125,188,608 |

This table diagnoses the present code path; it is not a lower bound on a
future protocol.  Its dependence on `q*N` directly violates the requested
identity.  The exact partial verifier Merkle work is in Section 3; the true
PCS and base-GKR prover/verifier operations are absent and therefore
`BLOCKED`.

The selected WHIR control alone needs a `2^36`-Fp initial Gemma codeword, or
549,755,813,888 B, and is a direct `NO-GO` under the full-codeword and memory
rules.  Because no replacement carrier supplies the required identity,
`COMPLEXITY_BOUND` and `TWO_HBM_SWEEPS` remain globally `BLOCKED`; the current
full-transform branches are `NO-GO`.  Fiat--Shamir changes challenge delivery,
not this source algorithm, so this gate applies unchanged to Branch A and
Branch B.

## 6. H100 static fit at context 4,096

The exact known resident values are:

```text
packed W                         61,394,690,560 B
KV = 450,560 i16/token * 2 B/i16 * 4,096
                                   3,690,987,520 B
known base                       65,085,678,080 B
strict room for everything else <14,914,321,920 B
```

The best conditional control is one physical KV arena: KV-old is a prefix
view and KV-new extends the same stable family, so the two logical names never
imply two full copies.  This saves 3,690,987,520 B, but it still needs a static
liveness proof.  Without that proof, two physical KV arenas make the known
base 68,776,665,600 B and leave strictly less than 11,223,334,400 B.

In the historical 256,000,000-byte staging scenario, with 480 terminal Fp3 values
(11,520 B), the one-arena interpretation leaves strictly less than
14,658,310,400 B; two arenas leave strictly less than 10,967,322,880 B.  The
remaining objects need a proved liveness allocation.  Interval colouring of
one arena is one option; several non-overlapping pools are also valid if their
combined peak is counted.  This is the only numerical allocation optimization
justified by the current data; choosing overlap without the lifetime graph
would hide a second copy.

This audit provisionally interprets `v` as the active design's 480 terminal
`v_j` values:

- the terminal payload is 11,520 B;
- if `v` instead means one Fp3 value per private weight, it costs
  736,736,286,720 B and the known minimum becomes 801,821,964,800 B, a direct
  H100 `NO-GO` by 721,821,964,800 B.

The exact B buffer, all chain buffers, GKR/reducer liveness, activation peak,
CUDA context, runtime modules, allocator reserve/fragmentation and every
chosen-kernel workspace are not present.  The complete strict
`peak_allocated < 80,000,000,000` inequality is therefore `BLOCKED` in the
terminal-value interpretation.  Context 4,096 creates room; it does not prove
that the unknown live set fits.

The context reduction cannot rescue the current full-codeword WHIR branch:
codeword plus W plus KV is at least 614,841,491,968 B, exceeding the H100 by
534,841,491,968 B before any other allocation.

## 7. Wire and certificate gates

For each plane/round the current subcodec reservation is derived from exact
`q`, `U`, `S=141*U` and compact-tree `H`; it does not use `U*h` as a path
substitute.  B, KV-old and KV-new have no selected layout/schedule, and the
true PCS messages plus complete GKR, QueryClose, receipts and output records
are missing.

The persisted certificate is exactly

```text
certificate_bytes = 376 + record_bytes.
```

Selected targets are:

```text
GPT <= 30,000,000
Gemma <= min(100,000,000, 3*GPT).
```

The optional preregistration is:

```text
GPT <= 35,000,000
Gemma <= min(115,000,000, 3.5*GPT),
with one exact W cap chosen in [125%,150%] before measurement.
```

Current partial offline-FS W growth is about 1.444x for the requested probes
and 1.448--1.450x for the exact W-only minima.  It does not violate certificate
growth by itself.  Missing nonnegative records prevent `EXACT_WIRE_CENSUS` or
`FULL_CERTIFICATE` credit.  Both verdicts are `BLOCKED`.

## 8. Branch B: tight Fiat--Shamir

### 8.1 Property that would be needed

Canonical serialization is not enough.  For the current bad-set argument, the
property that would be sufficient to replace the linear Q factor by one is
`Challenge-Prefix Uniqueness`:

> For every fixed statement, session, attempt, round, predecessor, public
> state and earlier challenge sequence, at most one canonical random-oracle
> input `Encode(domain || all those fields || prover prefix)` may pass all
> checks independent of the next challenge and still admit an accepting
> continuation.

The prefix must be fixed before `H_FS(prefix)` is known, and the property must
hold recursively for all rounds.  If there are `m` eligible distinct prefixes
and each has at most `T` favorable challenges, independent RO answers give

```text
Pr[success] <= 1-(1-T/|F|)^m <= m*T/|F|.
```

Removing `Q_FS` by this argument therefore requires `m=1`.  If uniqueness is
only computational, its failure probability `epsilon_prefix_unique` is a new
addend in `epsilon_total`; it is not free.  Other tight reductions might use a
different technique, so this is not claimed as a universal necessity.  A
unique opening only fixes the suffix for a commitment and point already
selected.  It does not force the attacker to select one commitment or one
prefix.

### 8.2 Constructive failure in the current reducer

Before `rho`, the prover sends masked corrections for `p(0)` and `p(2)`, while
`p(1)` is constrained by `p(0)+p(1)=C`.  Let `g(X)` be the honest round
polynomial for the real incoming claim `C0=g(0)+g(1)`, and let the malicious
prover carry a different claim `C`.  Write

```text
D = C-C0 != 0.
d_r(X) = D * X*(X-r)/(1-r),  r != 1.
p_r(X) = g(X)+d_r(X).
```

Then `p_r(0)+p_r(1)=C`, but `p_r(r)=g(r)`.  Distinct values of `r` produce
distinct `p_r(2)` and distinct canonical correction prefixes.  A malicious
prover can hash those prefixes locally, keep the one whose `rho` equals its
chosen `r`, and then continue honestly from `g(r)`.  Even with one fixed mask
`u_2`, the transmitted corrections `p_r(2)-u_2` are distinct.  With `m` local
trials this concrete family has `T=1` and success
`1-(1-1/p^3)^m`, approximately `m/p^3` while `m` is small relative to the
field.  CAS and replay logic see only the winner.  No nonce reuse or hash
collision is required.

The same general issue remains for randomized commitments, root-mask seeds,
roots, auxiliary roots and prover randomness.  Binding can give one opening
for a fixed root; it cannot give one root.  Deterministic honest-prover coins do
not constrain a malicious prover unless the relation checks that determinism.

The prefix audit is exhaustive over the requested degrees of freedom:

| item varied by the malicious prover | why uniqueness/canonical encoding does not stop many prefixes |
| --- | --- |
| commitments and roots | binding fixes an opening only after one root is chosen; it does not force a unique root |
| salts and root-mask seeds | canonical derivation is unique only after a seed is fixed; a malicious prover can choose many seeds unless their derivation is proved in the relation |
| corrections | the polynomial family above gives distinct valid pre-challenge corrections |
| auxiliary roots | each distinct auxiliary commitment is another prefix; present checks do not derive one unique root from public state |
| openings | a canonical opening may be unique for one fixed root and query set, while many earlier roots/prefixes remain eligible |
| prover randomness | the honest algorithm's deterministic convention does not restrict malicious coins unless it is a checked statement |
| nonce | one nonce can be reused across local RO trials and only the winning transcript is sent; collision resistance is never invoked |

[Attema, Fehr and Klooß](https://eprint.iacr.org/2021/1377) improve the generic
multi-round loss from a power of Q to `(Q+1)*kappa`, but also explain the real
attack obtained by trying distinct prefixes.  [Ganesh et
al.](https://eprint.iacr.org/2021/511) use unique response for
simulation-extractability, while their concrete knowledge-soundness still has
q-dependent terms.  [Ganesh et al.](https://eprint.iacr.org/2023/147) also
show why randomized later commitments defeat the strong unique-response form;
their weaker property has a different simulation-extractability goal.  None
of these results proves Q-independent direct FS for C7.

### 8.3 Generic linear-Q64 and invalid unique-prefix controls

With Goldilocks `p=2^64-2^32+1`, Fp3, `T=512` and the prudent `(Q+1)` factor,

```text
epsilon_FS_linear_Q64 = (2^64+1)*512/p^3
```

is 118.999999998992 bits.  Its isolated margins are about 43/41/35 bits over
76/78/84.  This is already global and is not multiplied by `2^20` again.
It is precisely the generic **linear-Q** control: it covers up to `2^64`
multi-prefix grinding trials, including the attack above, but it is not the
tight Q-independent theorem requested in Branch B.

If perfect Challenge-Prefix Uniqueness actually held, the corresponding
single-input control would instead be

```text
epsilon_FS_unique_prefix = 512/p^3,
```

or about 183 bits.  That premise is false for the current transcript; a
computational version would additionally pay `epsilon_prefix_unique`.

The tight-Q-independent branch is `NO-GO` for the current transcript.  Ways to
enforce the property would change at least one frozen object:

- a trusted online signer/TEE could authorize one complete independently
  grindable prefix;
- A0 could bind a deterministic future-message function, which needs a
  response tree, functional commitment or recursive proof;
- Fischlin, commit-and-open or another transform would change the transcript
  and work;
- AGM/state-restoration assumptions would change the model or still retain
  q-dependent loss.

These are declared redesigns, not hidden fixes.

## 9. Final verdicts

| Gate | Verdict | Reason |
| --- | --- | --- |
| `SECURITY_84` | **BLOCKED globally; current allocation NO-GO** | the registered conditional sum is already strictly below 84 bits, but larger q and a new complete allocation have not been excluded |
| owner floor 76 | **BLOCKED** | W has quantified room at q350/q357, but B/KV/GKR and the named assumptions are absent |
| preferred 78 | **BLOCKED** | q357 is the first requested W control with useful room; the complete sum is absent |
| `FS_Q64` | **NO-GO for tight Q-independent FS; BLOCKED for amplified linear-Q FS** | current prefixes are not unique; the linear branch lacks the complete carrier/event theorem |
| `MASK_LIFETIME` | **BLOCKED** | W controls are exact; B/KV loads and the adaptive multi-root theorem are absent |
| `COMPLEXITY_BOUND` | **BLOCKED globally; current transforms NO-GO** | no admitted `c_source*N+P(q,h)` carrier exists |
| `TWO_HBM_SWEEPS` | **BLOCKED globally; current transforms NO-GO** | no selected algorithm proves two scans without forbidden materialization |
| `EXACT_WIRE_CENSUS` | **BLOCKED** | only the W Merkle/query slice is exact |
| `FULL_CERTIFICATE` | **BLOCKED** | B/KV/GKR/PCS/receipt records are missing |
| `H100_STATIC_FIT` | **BLOCKED**, or **NO-GO** for a weight-long v | only 65.086 GB of the full live set is known |
| `D126` | **BLOCKED** | scoped branches fail, but no universal impossibility is proved |

The provisional design point for the preferred 78-bit objective is q357: W
alone leaves 93.382%/91.440% of the 78-bit error budget for all later terms and
the GPT offline-FS W floor has 427,945 B left under the 125% cap.  The 76-bit
fallback is q350: it leaves 86.612%/83.083% of the 76-bit budget and 497,625 B under
GPT's 125% cap.  These numbers quantify future room but do not prove that B,
KV, GKR and the true PCS will fit it.  q347 is not selected because its W-only
margin is too narrow.  The requested balanced q362 probes miss 84, while the
exact W-only q362 optimizers cross it by only 0.000484/0.002279 bit for
GPT/Gemma.  That razor-thin W-only margin cannot absorb any positive B, KV or
GKR term.  The 84-bit target may be reopened only with a complete, jointly
optimized allocation and normally larger counts.

## 10. Deterministic resume procedure

1. Freeze `operational_context_cap=4096` separately from the architectural
   model maximum, the four lifecycle classes and the exact predecessor and
   response token lists.
2. In a separately authorized artifact-ingest batch, select `GemmaQuantV1`
   and `LUT_TABLE_SCHEMA`, verify every pinned shard hash and tensor offset,
   export packed i16/LUT/golden/root artifacts, then compile the canonical
   two-model L manifests and every B/KV `RootLayout.RoundCap`.  Those emitted
   rows, rather than a copied W schedule, supply the missing extents, folds
   and mask charges.
3. Select a carrier with complete `Encode/Fold/Extend/CheckExtend/EvalLink`
   messages and a source-linear, two-sweep algorithm without full output.
4. Emit every per-plane/per-round `q,U,S,H`, correction, correlation and
   prover/verifier operation from that compiler.
5. Build one global ROM registry containing every query from every session and
   attempt, and prove the bad-set bound for every adaptive prefix.
6. Build the complete event registry, showing whether a new term replaces or
   adds to an old 64-slot allocation; compute every cumulative margin in exact
   rational arithmetic.
7. Choose any 125--150% W cap before measuring, then serialize maximal complete
   GPT-2 and Gemma certificates and apply absolute and growth gates.
8. Produce a static device-liveness map for every H100 allocation and selected
   CUDA workspace.  A later hardware measurement requires a new owner GO and
   must not use a pod under the present decision.

## 11. Gemma-31B full-response planning heuristics

These numbers answer the owner's request for a realistic planning view, but
they are not upper/lower bounds or confidence intervals.  There is no complete
C7/Gemma/H100 run, the B/KV/GKR compiler and exact workload are missing, and no
admitted carrier exists.  For comparability only, the calculation assumes the
historical 100-token predecessor plus 50-token response.  Root setup and
refresh remain separate frequencies and are not hidden in response time.
Here `MB` is decimal: 1 MB = 1,000,000 B.

### Branch A: query amplification

The working estimate uses first `q=357` as a **preferred-78-bit W planning
point**, Alternative 1 for mask geometry, one resident KV arena, and a future
carrier that actually satisfies `c_source*N+P(q,h)` and two sweeps.  It is not
a complete 78-bit result and is not the optimistic 84-bit point.

As an optimistic one-weight-read-per-step roofline, one prefill read plus 50
decode reads is `51*61,394,690,560 = 3,131,129,218,560` B.  It is an
assumption, not a measured Gemma traffic counter.  The two proof sweeps add
exactly 122,789,381,120 B.  Repository A100 stream controls of
119.513--418.038 GB/s turn that combined traffic into 7.78--27.23 seconds.
Applying the registered dimensionless historical `rho_cpu_decode` controls of
about 0.816--0.946, plus the slow 3.139 control, gives only an arithmetic
sensitivity of about 6.35--85.5 seconds.  It is not an H100/C7 prediction and
the missing Fp3, GKR, host and durability work can put the real value outside
that band.  The 50-second point below is therefore a judgement call, not a
fitted result.

| Gemma Branch-A quantity | central heuristic | sensitivity band, not a bound | confidence |
| --- | ---: | ---: | --- |
| prover, inference start through durable proof, warm-resident W | about 50 s | arithmetic control 6--86 s; real upper edge unknown | very low |
| hypothetical certificate placeholder | about 30 MB | 25--39 MB conditional arithmetic | very low |
| weak four-vCPU verifier, lot preparation through verdict | about 20 s | 10--30 s heuristic only | very low |

The 39-MB planning edge selects the 125% W band: its registered, uncompiled GPT
allocation control is 13,164,773 B, so the main 3x arithmetic gives
39,494,319 B.  It is not a compiled certificate cap.  Selecting 150% would
instead give 41,831,952 B and is not silently included in this working range.

If the single storage acquisition is charged to each response, rather than to
model residency, the registered 3.2-GB/s control adds 19.186 seconds.  This is
reported separately, not silently overlapped.

The proof-size point comes from a transparent proxy, not a fitted constant:

```text
offline-FS W floor at q357              5,008,124 B
three conditional D31 plane streams    3 * 3,683,592 B
illustrative compute/base-GKR budget   9,379,670 B
MAC plus framing budget                   75,248 B
proxy subtotal                         25,513,818 B
```

The D31 B/KV schedule is not selected and true-PCS/receipt bytes are absent,
so 25.514 MB is neither a lower nor an upper bound; 30 MB is the practical
planning point.  For verifier time, existing complete GPT-2 rows are
0.731--0.932 seconds on a different x86 host.  The displayed heuristic scales
by the exact raw-use ratio `1,554/110=14.127` and assumes, without measurement,
roughly a twofold thread penalty for four instead of about eight threads.  It
is not a transferred AArch64 rate; the required paired weak-verifier baseline
is absent.  Reading and hashing roughly 30 MB is secondary; lot preparation,
base GKR and the 1,554 raw uses are expected to dominate.

For the optimistic 84-bit four-plane search seed, first q372 gives Gemma W
vector `[372,169,158,155,155,155,155,155]`, offline-FS W floor 5,203,340 B
and a four-plane proxy of about 26.144 MB.  The planning time points remain
roughly 50/20 seconds for prover/verifier because q changes only `P(q,h)`, not
inference or the two source sweeps.  This sensitivity does not make
`SECURITY_84` pass: the real B/KV/GKR errors are still absent.

If an engineering placeholder is unavoidable, use four minutes of H100 wall,
39 MB of output and 30 seconds of verifier wall until real measurements exist;
these are deliberately arbitrary capacity placeholders, not safe maxima.  A
39--45 MB stress range belongs only to the
optional 3.5x exploratory envelope and requires its explicit preregistration;
it is not part of the main 3x heuristic.  The W-only byte growth must not be
mistaken for a bound on the complete prover.

### Branch B: tight Fiat--Shamir

For the current transcript the only honest complete estimate is **N/A**:
the branch is `NO-GO`, so there is no admissible prover, proof or verifier to
time.  The old interactive W subtotal is 3,788,680 B, split as 3,767,708 B
P-to-V and 20,972 B V-to-P.  A direct FS conversion could remove at most those
20,972 B (0.554%) before adding its own metadata; at least 686 known challenge
scalars must be derived before base GKR and B/KV.  This scalar count is not a
count of sequential prefix rounds.  Those partial values do not
identify a complete performance range.  Even a hypothetical tight theorem
would mainly reduce the q-dependent opening work; source scans, inference and
GKR would remain, so an order-of-magnitude speedup over Branch A is not
credible.

A trusted online signer/TEE would violate the frozen offline/trust model.  It
would need a durable single-issuance rule authorizing exactly one prefix per
`(connection,attempt,round,predecessor)`, and derive
`rho=H(domain || prefix || token)`; signing only after `H(prefix)` does not
stop local grinding.  If the exact number of such prefix points is
`R_prefix`, token bytes are `R_prefix*(signature_bytes+framing_bytes)` and
sequential added latency is `R_prefix*(RPC_latency+sign_latency)`.  The
repository has no `R_prefix` census, so even this redesign has no numerical
complete cost.  Functional-commitment, recursive and commit-and-open redesigns
likewise have no C7 operation or byte census; assigning them seconds or
megabytes would be fabricated.

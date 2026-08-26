# C6.4 — joint cache/residual authenticated sketch

**Status:** R2 AUTHENTICATED TERMINAL LINK PASS; HARD STOP BEFORE PRODUCTION
STREAMING, SIMT OR POD.

**Branch:** `agent/c64-joint-residual-sketch`.

## 0. Objective and authority

C6.4 is a separate recovery line from the clean C6.3 closure checkpoint.  It
does not change the fixed-point forward pass or reuse any C7 result.  Its
objective is two complete GPT-2 certificates, `0 -> 150` and `150 -> 200`,
with each response-specific prover below `20.000 s` on one A100 and each
complete certificate at most `35,000,000 B`.  `30,000,000 B` remains the
diagnostic engineering threshold.

Local design, exact census, tiny/scaled references and implementation are
authorized.  No provider contact, pod use or production-size run is
authorized until this document and `prototype-status.md` record
`C64_POD_READY`; a later run-specific owner GO is still required.

C6.3 measurements remain historical evidence only.  C6.4 receives no
certificate, timing, verifier, memory, security or end-to-end credit from
them.

## 1. Selected minimum change

C6.3 successfully replaced the dense K/V-cache wrapper but left the inherited
response-local residual wrapper.  That wrapper expanded into a
`17,179,869,184-B` encoded oracle and retained `19,629,343,144 B`.  C6.4
removes that wrapper rather than optimizing its allocation.

The replacement reuses the existing C6.3 sparse construction and the existing
compact C6RSC3 residual relation:

```text
cache corrections ----------------+
                                   +--> one D23 x 16 private table
complete private residual owner --+        |             |
                                            H       one authenticated
                                             |       terminal link
                                      one D20 sketch      |
                                             |             |
                              replacement D23/D20 WHIR lanes
```

The eight tape/limb WHIR bodies are replaced, not supplemented.  Adding a
ninth body or retaining the old D23 residual wrapper is forbidden.

The terminal link reuses the existing authenticated quadratic sumcheck. No new
proof engine, generic table abstraction, mask plane or persistent response
oracle is admitted.

## 2. Exact private row boundary

The existing paired residual leaf has seven `Fp2` columns:

```text
common plaintext,
tape-0 base mask, tag, correction,
tape-1 base mask, tag, correction.
```

R0's four-public-correction layout was sufficient for the sparse differential
but insufficient for the complete C6RSC3 statement. The selected table is
private. Cache rows keep their sixteen one-time corrections and are the only
rows the systematic-opening API can expose. Residual rows pack leaf slots
0--6 and compact closure slot 7 as eight `Fp2` values; auxiliary live prefixes
continue in the unused cell suffix. Tail cells are canonical zeros.

The row frame binds protocol version, response nonce, epoch, segment kind,
source ordinal, live lengths and both source-schedule/allocation digests.
Changing a row kind, offset, length, tape order or limb order rejects.

The row frame binds protocol version, response nonce, epoch, source schedule,
allocation, exact live lengths and all table roots. The verifier samples one
weight after the 48 pending descriptors and joint roots are fixed. A
27-round authenticated inner-product reduction binds the weighted claims to
one opening of this same D23 table. No residual plaintext, mask, tag or raw
prover authentication value is serialized.

The production capacity census is:

| Response | cache rows | leaf rows | closure rows | auxiliary `Fp2` | packed-cell headroom | live bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0 -> 150` | 460,800 | 5,119,131 | 399,140 | 399,076 | 44,140,680 | 645,096,528 |
| `150 -> 200` | 614,400 | 1,992,912 | 365,180 | 365,116 | 91,770,504 | 313,534,080 |

Virtual-zero cells are not host payload. Production streaming must show
whether a transient device zero-tail allocation is required and count it
explicitly; it may not become a retained or encoded response oracle.

## 3. Required protocol identities

Production admission requires all of these identities. R2 closes items 1--6
at scaled/reference level; production streaming and codec replay must preserve
them exactly.

1. **Privacy.** Only cache corrections and public shape may be exposed by a
   systematic opening. Every residual row is private and inaccessible through
   the row API.
2. **Source binding.**  The residual correction rows are exactly those
   consumed by the existing paired source cursor, in the same finite
   correlation allocation and order.  No digest-only equality substitutes
   for this relation.
3. **Residual binding.** All 48 C6RSC3 terminal pending values, not only the
   two correction slots, enter the descriptor-ordered authenticated link. The
   batching challenge occurs after descriptors and roots are fixed.
4. **Sparse relation.**  The committed sketch is exactly `H` applied to the
   canonical joint rows; cache and residual contributions may be computed
   separately and added only because a differential checks the same final
   values and transcript.
5. **Authenticated closure.**  Every final value resolves into the existing
   two VOLE-authenticated tapes.  No clear residual evaluation or raw prover
   tag is serialized.
6. **Distance and soundness.**  The exact D23-to-D20 socket ensemble receives
   a new finite-size distance calculation and complete event union.  The C6.3
   D22 result is evidence, not an automatic theorem transfer.

Any identity requiring a fresh full-size random mask table, a clear residual
row or a second response-local proof family closes C6.4 as a NO-GO.

## 4. Admission gates

The early gates deliberately leave margin for composition error:

| Gate | Required result |
| --- | ---: |
| joint cache/residual subsystem on A100 | `<=9.640596167 s` |
| residual extraction + joint-sketch increment | `<=5.000 s` diagnostic subgate |
| projected complete prover before pod | `<=17.000 s` |
| complete serialized certificate | diagnostic `<=30,000,000 B`; hard `<=35,000,000 B` |
| complete `pi_final` | `<4,500,000 B` |
| four-thread CPU verifier | `<5.000 s` |
| verifier additional RSS | `<=8,000,000,000 B` |
| A100 device high-water | `<=45,818,576,864 B` |
| response-local dense encoded oracle | exactly `0 B` |
| complete per-certificate soundness | `>=78.00 bits` |

The executable structural screen preserves the C6.3 105-bit query counts.
Its D23/D20 bodies occupy `9,322,048 B` and the four transition openings
`1,257,332 B`, increases of `282,720 B` and `62,800 B`.  A direct D23
systematic multiproof for 4,420 queries is at most `2,100,878 B` under the
selected canonical framing.  Substituting those three components into the
historical C6.3 composition plus the `1,816-B` terminal link projects
`29,116,783 B`: it passes the 30-MB diagnostic by `883,217 B` and remains
`5,883,217 B` below the 35-MB hard limit. This is
`credit:false` structural evidence; complete codec bytes are still unknown
until the new public argument serializes and reloads.

The exact D23 finite-distance certificate gives at least 186 bits. Adding the
terminal batching (`47/|Fp2|`), 27 degree-two rounds (`54/|Fp2|`) and two
terminal authentication checks to the inherited complete union gives
`78.019023202616...` bits per certificate. This passes the 78-bit gate with
little margin; no term may be removed without a new exact union.

The historical compact C6RSC3 CPU result (`17.401844 s`, `573,299,712 B`)
proves capacity only.  It receives no C6.4 time credit.  SIMT means executing
the same fixed operation over many rows; it is admitted only after the scaled
CPU joint identity and exact counters pass.

## 5. Two-profile setup and two-proof campaign

The first campaign consumes exactly two installed profiles:

```text
context-000   proof 0 -> 150
context-150   proof 150 -> 200
```

C6.4 introduces a versioned two-profile setup bundle whose encoded profile
identifiers are exactly `[0, 150]`.  Missing, duplicate, reordered, symlinked
or extra profile directories reject.  The C6.2 seventeen-profile bundle is
not accepted, and profiles are never duplicated to satisfy an old array
length.

The first pod setup generates only these two profiles.  A third profile is
YAGNI for a two-proof campaign; adding proof `200 -> 250` later requires a
new setup-bundle version and a separately authorized create-new campaign.

The two proofs run in one session.  Proof two starts only after proof one is
serialized, reloaded, fully verified and atomically promoted.  There is no
automatic or selective retry.  A target miss is recorded and may continue;
a protocol, resource, correlation or state failure stops before the next
proof.

## 6. Diagnostics and finite resources

Before the first witness-dependent byte, each attempt reserves the exact
subfield, full-field and raw correlation ranges for both tapes.  Reservation
reports requested, granted, consumed, remaining and burned counts by named
phase.  Any underflow, extension after reservation or nonzero unassigned
suffix fails before proof work; an abort burns the complete reserved range.

The record separates, for both proofs:

- response construction and residual-source extraction;
- joint-row packing, sparse update and both roots;
- every sequential D23 and D20 WHIR lane;
- C6RSC3, authenticated closure and output link;
- real/AES correlation generation/consumption;
- serialization, synchronization, disk replay and four-thread verification;
- process RSS/high-water, cgroup state, disk read/write and transient bytes;
- host-to-device, device-to-host and device-to-device bytes;
- device allocations, peak live bytes, kernel launches and synchronization
  wall by reason;
- exact component/frame/certificate bytes and transcript digests.

Production records contain no masks, tags, secret rows or correlation values.
All paths and reports are create-new.  Large pod-local setup and weights stay
pod-local; tracked source/evidence synchronizes only through GitHub HTTPS.

## 7. Local ladder and pod stop

1. Exact capacity/byte calculator and scaled row-layout differential.
2. Scaled source-binding, privacy-codec and C6RSC3 terminal-link differential,
   including one mutation for every boundary above.
3. Exact D23/D20 WHIR structural bytes, soundness and finite-correlation
   census. Unknown fields fail closed. **R2 complete analytically.**
4. Small complete serialized two-response lifecycle with finite real PCG,
   reload, verifier, mutation, burn and promotion.
5. Only after a scoped clean checkpoint: SIMT implementation and byte-exact
   CPU/SIMT differential with full traffic counters.
6. Only after all admission gates: ledger transition to `C64_POD_READY` and a
   later run-specific owner GO.

No full GPT-2 benchmark runs locally.  Local Cargo commands use only
`rust/target`; before a broad build the host must have at least 60 GiB free.
After checks, `rust/target` and ignored nested targets are removed.  Retaining
a local build cache requires explicit owner approval.

## 8. Current disposition

R2 selects the complete private layout and exact two-profile campaign. Scaled
execution folds the real 48 pending claims into one authenticated link to the
packed table and rejects content, key, order, point and private-row mutations.
The link reuses one existing proof codec (`1,816 B`) and consumes 54 full
correlations per tape. Exact D23 capacity, 186-bit finite distance, complete
78.019-bit soundness and two-profile correlation allocations pass. A distinct
versioned setup bundle admits only `[0,150]`. Production streaming/SIMT,
strict complete certificate serialization/reload, real-PCG two-proof state
promotion and all measured clocks remain open. Therefore no provider, pod or
performance claim is yet authorized.

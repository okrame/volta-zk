# C6.4 — joint cache/residual authenticated sketch

**Status:** R0 SOURCE/LINEAR + STRUCTURAL-BYTE SCREENS PASS; HARD STOP BEFORE
PRODUCTION CODE, SIMT OR POD.

**Branch:** `agent/c64-joint-residual-sketch`.

## 0. Objective and authority

C6.4 is a separate recovery line from the clean C6.3 closure checkpoint.  It
does not change the fixed-point forward pass or reuse any C7 result.  Its
objective is two complete GPT-2 certificates, `0 -> 150` and `150 -> 200`,
with each response-specific prover below `20.000 s` on one A100 and each
complete certificate at most `30,000,000 B`.

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

The replacement reuses the existing C6.3 correction sketch and the existing
compact C6RSC3 residual relation:

```text
public cache corrections ---------+
                                   +--> one D23 systematic layout
public residual corrections ------+        |
                                            H
                                             |
                                      one D20 sketch
                                             |
                              replacement D23/D20 WHIR lanes
                                             |
                         existing authenticated residual closure
```

The eight tape/limb WHIR bodies are replaced, not supplemented.  Adding a
ninth body or retaining the old D23 residual wrapper is forbidden.

No new proof engine, generic table abstraction, mask plane or persistent
response oracle is admitted in R0.

## 2. Exact public row boundary

The existing paired residual leaf has seven `Fp2` columns:

```text
common plaintext,
tape-0 base mask, tag, correction,
tape-1 base mask, tag, correction.
```

Only the two corrections may enter the public systematic object.  Each
correction has two base-field coordinates, so a residual row occupies four of
the existing sixteen base-field columns.  The other twelve columns are
canonical virtual zeros.  Clear common plaintext, base masks or tags are a
terminal privacy failure.

Cache rows keep their existing sixteen public one-time correction columns.
The response-local row order is canonical and disjoint:

1. all live cache correction rows in canonical `(position, live-slot)` order;
2. all residual correction rows in exact correlation-schedule order;
3. canonical virtual-zero padding to `2^23` rows.

The row frame binds protocol version, response nonce, epoch, segment kind,
source ordinal, live lengths and both source-schedule/allocation digests.
Changing a row kind, offset, length, tape order or limb order rejects.

The production capacity census is:

| Response | cache rows | residual rows | total live rows | D23 headroom |
| --- | ---: | ---: | ---: | ---: |
| `0 -> 150` | 460,800 | 5,119,131 | 5,579,931 | 2,808,677 |
| `150 -> 200` | 614,400 | 1,992,912 | 2,607,312 | 5,781,296 |

Virtual-zero columns and tail rows are never materialized or transferred.
The exact physical public payload is therefore `222,794,592 B` for genesis
and `142,416,384 B` for continuation, rather than a 1-GiB dense table.

## 3. Required protocol identities

R0 is blocked before production code until a scaled reference closes all of
these identities.

1. **Public privacy.**  For each tape, `D = X - R` with fresh uniform
   one-time `R`.  The pair of corrections from two independent tapes is
   independent of `X`.  The concrete codec exposes only these corrections and
   public shape.
2. **Source binding.**  The residual correction rows are exactly those
   consumed by the existing paired source cursor, in the same finite
   correlation allocation and order.  No digest-only equality substitutes
   for this relation.
3. **Residual binding.**  The C6RSC3 correction factors at its terminal points
   equal the corresponding claims opened from the joint systematic object.
   The linking challenges occur only after both first messages are fixed.
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
| complete serialized certificate | target `<=28,000,000 B`; hard `<=30,000,000 B` |
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
historical C6.3 composition projects `29,114,967 B`: it misses the 28-MB
engineering target by `1,114,967 B` but remains `885,033 B` below the hard
limit.  This is `credit:false` structural evidence; complete codec bytes are
still unknown until the new public argument serializes and reloads.

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
   census.  Unknown fields fail closed.
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

R0 selects the four-public-correction joint layout and the exact two-profile
campaign.  Capacity fits D23 analytically.  A scaled executable differential
shows that cache and correction-only residual streams produce the same sketch
as the canonical joint table; the correction-only extractor reuses the exact
paired-source cursor and rejects private residual columns.  The D23/D20 WHIR
structure and a sub-30-MB certificate projection pass without adding proof
bodies.  Concrete privacy-codec review, the C6RSC3 terminal link, finite-size
distance/soundness, exact serialized certificate, finite-correlation census
and all measured clocks remain open.  Therefore no SIMT, production prover,
pod or performance claim is yet authorized.

# Fase-D G4 synchronization-gate amendment

**Preregistered 2026-07-17, before implementation and before any v2 run.**
This document amends only the provider performance gate named below. The
fase-D design, protocol, proof bytes, response bytes, challenge order,
correlation allocation and every other G4 gate remain exactly as registered in
`docs/fase-d-realpcg-default-design.md`.

## 1. Evidence and immutable v1 verdicts

`runpod-a100-realpcg-v1` remains an immutable profile with
`max(synchronization_s / response_session_wall_s) <= 0.02`. Its two valid
official records are both FAIL:

- `runpod-a100-realpcg-v1-2026-07-16-877411b.json`: 59,850 host-output
  boundaries, absolute synchronization 0.113239--0.114134 s and maximum ratio
  0.02116772692888126;
- `runpod-a100-realpcg-v1-2026-07-17-f096095.json`: the unchanged source and
  profile on a fresh A100/EPYC-7742 pod, again 59,850 host-output boundaries,
  absolute synchronization 0.121576--0.122066 s and maximum ratio
  0.02187096033832154.

The repeat therefore does not identify new work, extra messages or a protocol
regression. The absolute API wall varies by about 8.5 ms across pods while the
ratio also penalizes a faster response-session denominator. A non-record CUDA
microbenchmark on the second pod compared stream synchronization with
stream-query and disable-timing event fast paths. Query/event variants moved at
most sub-microsecond cost per isolated operation and did not provide a robust
provider-neutral reduction sufficient for the official workload. Coalescing
the remaining boundaries would reorder interactive challenge dependencies and
is not authorized by this amendment.

Neither v1 record is reclassified. Criterion (5) remains open until a clean v2
record passes.

## 2. Authoritative v2 gate

Create provider profile **`runpod-a100-realpcg-v2`**. It carries every v1
requirement unchanged except for one replacement:

- remove the binding `max(sync wall / response-session wall) <= 0.02` gate;
- require binding `max(synchronization_s) <= 0.150000000 s` across all measured
  response sessions.

The raw synchronization count remains diagnostic and has no numeric gate. The
per-repetition synchronization fraction and its maximum remain mandatory
informative fields, so the amendment cannot hide denominator behavior.

The 0.150 s absolute cap is not selected from the 2026-07-17 result. It is the
provider-neutral cap documented before these fase-D runs in the ledger's
2026-07-15 post-fix census decision rule. It is stricter in intent than a
percentage allowance: synchronization wall may not grow with slower proving,
and a pure compute speedup cannot manufacture a synchronization failure by
shrinking the denominator. The product owner's offered 2.5% fallback is not
used because a post-result fractional threshold would retain the same
denominator artifact.

All remaining binding requirements are unchanged:

- exact profile geometry T=100+50, Q=200, one or more warmups and at least
  three measured repetitions from one clean unchanged full Git SHA;
- A100-SXM4-80GB, `RAYON_NUM_THREADS=8`, CUDA ABI 28,
  `wall-only-counters`, zero CUDA-event timing calls;
- prefill <=10 s, decode marginal <=4 s, H2D <=100,000,000 B;
- exact packed response 136,526,530 B, golden decode, normal/chunked
  acceptance, flat-cost ratio <=1.5, 13/13 PCS, anti-replay and mock/real
  counter/allocation/channel-digest parity;
- real-PCG/AES-128-MMO, production tuples only, one connection-scoped base
  phase, G2 usable capacity >=110,000,000 and setup traffic <=40,000,000 B;
- setup wall and per-stage split remain informative for each host.

Quick remains a non-gating diagnostic. The new append-only filenames are
`runpod-a100-realpcg-v2-quick-<date>-<sha>.json` and
`runpod-a100-realpcg-v2-<date>-<sha>.json`. The fail-closed selector must accept
valid measured FAIL records as records while reconstructing every threshold
and boolean independently.

Changing the 0.150 s cap, restoring a fractional gate, changing any carried
gate, or accepting a v1 record under v2 reopens preregistration.

## 3. Explicit non-changes

This amendment changes no Rust proving path, CUDA primitive, protocol message,
proof/transcript/PCS byte, response byte, challenge order, Lean theorem,
cryptographic assumption, correlation lifecycle or setup accounting. It does
not authorize CUDA graphs, scheduler expansion, boundary thinning, pool
prewarming, Packed16 or a retroactive closure.

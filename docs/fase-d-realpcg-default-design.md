# Fase-D design — real-PCG default, recursive scaling, and connection lifecycle

**Status:** preregistered on 2026-07-16, before Lean M10 and before Rust
implementation. This document and the matching `docs/prototype-status.md`
entry are the Part-A contract. Part B alone may run the clean records, write
the closure, enact criterion (5), or set `pcg_production_ready:true`.

## 1. Product decision and package boundary

The product-owner resolution is authoritative. The criteria resolution is
recorded verbatim:

> The mock→real default flip is APPROVED. Flip criterion (1) — independent
> external cryptographic review — is REMOVED from the criteria list by
> explicit product-owner decision. Record the removal as a decision; do not
> record any replacement review obligation. Criterion (4) is ACCEPTED with
> the measured costs (8.451–8.609 s setup, 31,261,434 B setup traffic on the
> 4-core aarch64 VM). Criteria (2)/(3) are already satisfied
> (flip-readiness-2026-07-15-117df7d.json). Criterion (5) — the ledger
> decision + checkpoint enacting the flip — happens in Part B, after clean
> runs, NOT in this part.

Consequently Part A implements the real backend as the default selection for
current binaries, benches and e2e reports, makes mock an explicit diagnostic
or unit-test selection, and refuses mock in record-producing modes. It does
**not** claim the production flip has closed: every Part-A artifact records
`pcg_production_ready:false`. Criterion (5) remains a Part-B action after the
clean gates below. Criterion (1) has been removed, with no substitute review
criterion or obligation. Criteria (2) and (3) are closed by the named record,
and criterion (4) is accepted at the named measured cost.

Fase-D comprises exactly four related changes:

1. a third regular-LPN recursion stage and a bounded refill chain;
2. AES-128-MMO for GGM node expansion only;
3. host-measured Rayon tuning of expansion and malicious checks; and
4. one `Delta` and one base phase per durable connection, with multiple
   separately authorized responses and terminal whole-connection burn on any
   abort.

## 2. Pinned regular-LPN stage 3

### 2.1 Tuple, capacity, and refill count

The production tuple is:

```text
(k3, n3, t3) = (6,520,000, 117,440,512, 1,792)
noise          = regular Goldilocks noise
block size     = 65,536 = 2^16
GGM depth      = 16
n3 / k3        = 18.01234846625767...
```

Each of the `t3=1,792` disjoint blocks contains exactly one uniformly located,
uniform nonzero `F_p` error. The stage produces

```text
U3 = n3 - k3 - t3 - 2 = 110,918,718 usable raw sub-VOLEs.
```

The tuple consumes `k3=6,520,000` LPN base VOLEs, below the existing main
stage's `U2=10,214,167`. The implementation must actually reserve the complete
input split

```text
B3 = k3 + t3 + 2 = 6,521,794 raw sub-VOLEs
```

because the `t3` beta inputs and two `F_p^2` check limbs are not response
material. `B3` is also below `U2`.

One connection preprovisions exactly six stage-3 path-OT slices during its one
IKNP extension. The public stage-plan digest chooses one of two plans before
any response allocation:

- `terminal-one`: activate one stage-3 instance, reserve no child base, expose
  all `U3=110,918,718` outputs, and burn the five unused path-OT slices at
  terminal close; this is the G2/G2b plan.
- `chain-six`: activate at most six instances in order, reserving `B3` outputs
  from instances 1 through 5 before any response can see them; this is the G3
  plan. A shorter close burns every remaining reservation and unused slice.

For the six-stage chain, exact capacity is:

```text
main residual after first B3 reserve       3,692,373
six stage-3 outputs (gross)              665,512,308
five inter-stage B3 reserves              32,608,970
allocatable stage-3 outputs              632,903,338
total allocatable incl. main residual    636,595,711
```

The maximum of six LPN stage-3 instances is a security and traffic parameter,
not a tuning default. A seventh instance is forbidden by production preflight.
Changing the tuple, regular-noise model, six-instance bound, or estimator
commit reopens preregistration.

### 2.2 Pinned estimator run and conservative accounting

The estimator is the public
[`1234wangtr/Code_estimators`](https://github.com/1234wangtr/Code_estimators)
suite at commit
`969ef60c30cb84c25502d6b7c968f43a362bb438`, using its regular-noise
large-field path with the literal final argument `64`, the established
fase-B convention for the `log2(q)=64` model. The control calls reproduce the ledger values
`140.64686430760642` bits for `(25,000,642,048,2,508)` and
`149.4773339537398` bits for `(589,760,10,805,248,1,319)`.

The exact stage-3 call is:

```python
analysisforqregular(117_440_512, 6_520_000, 1_792, 64)
```

At this new size the pinned Python implementation cannot execute literally:
its HYB expression constructs `G3 * 2**try_comp` before taking `log2` and
overflows, its legacy AGB loop includes the invalid endpoint `mu=beta`, and
AGB2 allocates two dense caches totalling about 5.64 GB. The audit execution
uses only the following formula-preserving numerical shims:

1. evaluate `log2(G1 + G2 + G3*2^c)` with base-2 log-sum-exp;
2. enforce the estimator's mathematical domain `mu < beta` rather than
   evaluating `0*log(0)` at `mu=beta`;
3. replace AGB2's dense zero caches by sparse caches with identical keys,
   values, and access order; and
4. vector-scan the same finite legacy-AGB candidate set, then re-evaluate the
   minimizing candidate with the upstream 170-digit `Decimal` formula.

No attack formula, candidate range, comparison, truncation rule, field model,
or search result is changed. The unmodified control tuples and the stabilized
paths agree. These execution shims are part of this pin; changing them also
reopens preregistration.

The checked-in reproduction commands pin NumPy 2.5.1 and SciPy 1.18.0.
Their versioned artifacts and SHA-256 values are:

- `scripts/estimators/fase_d_hybrid_logsumexp.patch`:
  `98d2c4039c80c13823727d9a72d9ce11d6dd0b58f8f3025c11d1529e5b1cbdc3`;
- `scripts/estimators/fase_d_agb_vectorized.py`:
  `5daf8bf296c168e385367029083c0252b3ebee9c3a670db4f67ec34890a4bdeb`;
- `scripts/estimators/fase_d_agb2_sparse.py`:
  `97794af52be3fa4837b30bec0d8f500c3ad5cdbe496bb7c6afae1d7effb2e05e`;
- `scripts/estimators/fase_d_remaining.py`:
  `5db2bc81f2fa635536d56070d7fa444b3ed9c6b6de0cc5849ee5ea94b24704d8`.

The HYB source is upstream Git blob `c888328e2a6d2de4c1164c7e9763065071c67585`
(file SHA-256
`eed439b6e27a3aa4993f3bd6120ca255905ccb7d66b667891f7f3c3fb26a7a71`);
after the versioned patch its file SHA-256 is
`76202433a78bd8fb035defa2c9f6cef2954b46818eaf02e2ca6d9e8768ae42dd`.
`scripts/estimators/README.md` is the reproduction procedure; changing an
artifact, dependency version, or execution split reopens preregistration.

The exact output for the selected tuple is:

| Estimator category | Bits |
| --- | ---: |
| algebraic (AGB) | 213.85 |
| ISD minimum | 208.85010924741465 |
| — SD-ISD | 208.85010924741465 |
| — pooled Gauss | 211.05112818053500 |
| — statistical decoding | 317.97467674286350 |
| — statistical decoding 2.0 | 317.97303744165540 |
| hybrid (HYB) | **199.59980442282708** |
| regular ISD | 227.92519270931604 |
| AGB2 | 213.85 |
| **minimum known attack** | **199.59980442282708** |

The legacy-AGB full sweep minimizes at `(f,mu)=(1792,2141)`, degree 2;
the 170-digit `Decimal` re-evaluation is
`213.846752631460719897576401...` bits and the suite reports `213.85`.

For the maximum six stage-3 instances, conservative multi-instance accounting
subtracts `log2(6)` and gives **197.01484192210592 bits**, a
69.01484192210592-bit margin over 128. Treating all eight LPN instances in a
maximum connection as if each had only the weakest single-instance estimate
gives the still-more-conservative crude floor
`140.64686430760642-log2(8)=137.64686430760642` bits, 9.64686430760642 bits
over 128. The summed-work-factor floor using each stage's actual estimate is

```text
-log2(2^-140.64686430760642
      + 2^-149.4773339537398
      + 6 * 2^-199.59980442282708)
= 140.64369866606756 bits.
```

This includes one recursive setup instance, one main instance, and all six
authorized stage-3 instances. It has a 12.64369866606756-bit margin over 128.
The estimates are public known-attack estimates and external assumptions, not
reductions or gate verdicts.

### 2.3 One base phase and exact stage schedule

At connection open, derive the regular-noise choices under
`(connection_id, stage_kind, ordinal)`, concatenate exactly

```text
recursive setup: 2,508 *  8 = 20,064 choices
main:            1,319 * 13 = 17,147 choices
six stage 3: 6 * 1,792 * 16 = 172,032 choices
total                            209,243 choices
```

and run base OT, COPEe and IKNP exactly once. The one global malicious IKNP
check covers the concatenated extension. Selected aggregates are retained as
stage-labelled slices; path-OT keys are erased. A later stage activation takes
`B3` raw outputs from its predecessor, performs its beta/GGM corrections and a
fresh ordinal-domain WYKW check, and publishes output only after acceptance.
It never starts another base OT, COPEe, or IKNP extension.

With 16-byte GGM nodes, the preregistration serialization model is

```text
M = six stage-3 path-OT slices preprovisioned at open
A = number of stage-3 expansions actually activated

total = 30,070,682 + 1,376,256*M + 43,247*A bytes
P->V  = 28,814,084 +   458,752*M + 14,411*A bytes
V->P  =  1,256,598 +   917,504*M + 28,836*A bytes
```

Thus `M=6,A=1` projects 38,371,465 B for G2 and `M=6,A=6` projects
38,587,700 B for G3. The full-chain planning breakdown is base OT 16,411 B,
OT extension 38,217,099 B, GGM corrections 350,040 B, and checks 4,150 B;
directionally it is 31,653,062 B prover-to-verifier and 6,934,638 B
verifier-to-prover. These are preregistration calculations, **not measured
numbers or frozen assertions**. Fase-D defines new exact directional and
per-category assertions only when the Part-B records measure them. The frozen
31,261,434 B assertion remains attached solely to fase-B records.

Using 32-byte GGM nodes would project 45,283,476 B for the full chain and fail
G2's 40 MB envelope; 16-byte AES blocks are therefore binding. A seventh
preprovisioned stage would project 40,007,203 B even with 16-byte nodes and is
forbidden.

### 2.4 Batched expansion and memory

`t3=1,792` GGM blocks are processed in exactly two canonical execution batches
of 896 blocks. Each batch covers 58,720,256 LPN rows. GGM trees within a batch
may use smaller Rayon windows, but tree, row and allocation order are always
lifted to canonical `(stage_ordinal,row)` order before the batch storage is
released. Changing the two-batch split is preregistration-significant.

The live prover-side correlation-buffer cap is exactly **4,000,000,000 B**,
accounted at 24 B per raw/final sub correlation plus actual GGM/noise scratch.
For reference, a stage has `B3*24=156,523,056 B` of base material,
`U3*24=2,662,049,232 B` of output, and `n3*16=1,879,048,192 B` of noise tags.
Naive simultaneous noise/output materialization is 4,541,097,424 B; adding
the LPN base raises it to at least 4,697,620,480 B even before a duplicate pool
conversion. This is forbidden. The implementation must stream GGM/noise
windows, avoid a second `bases_to_pools` copy, publish only after the complete
stage WYKW check, record the observed high-water mark, and fail closed before
exceeding the cap.

For the 600M informative run, canonical allocation/counter/digest lifting uses
a release sink: it retains only the next `B3` reservation and material actually
needed by a response, then releases completed batch storage. It must not return
a 15+ GB flat pool. Digest-and-release still counts every generated,
reserved-as-base, consumed and burned item and is not permission to reuse or
skip a correlation.

## 3. AES-128-MMO GGM assumption and configuration

Fase-D registers the fixed-key random-permutation/correlation-robustness
assumption of Guo--Katz--Wang--Yu,
[*Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers*](https://eprint.iacr.org/2019/074).
Only GGM node expansion changes. BLAKE3 remains the primitive for transcripts,
KDFs and root derivation, commitments, coin/choice pads, hash-to-field, and
public LPN-matrix derivation.

GGM node seeds and AES blocks are exactly 128 bits. Let

```text
K    = 000102030405060708090a0b0c0d0e0f   # public fixed AES-128 key
tau0 = 00000000000000000000000000000000
tau1 = 01000000000000000000000000000000   # bit 0 in canonical LE encoding
pi(x)    = AES-128_K(x)
sigma(x) = pi(x) XOR x
child_b(s) = sigma(s XOR tau_b)
G(s) = child_0(s) || child_1(s)
```

Stage roots remain BLAKE3-KDF outputs truncated to 16 bytes and are separated
by connection identity, stage kind, stage ordinal and tree ordinal. The public
stage-plan digest is bound into both local role transcripts. Leaf-to-field
conversion remains domain-separated BLAKE3. No AES output is used directly as
a transcript hash, KDF, commitment, pad, field hash, or LPN matrix seed.

Runtime detection records one of `aes-ni`, `armv8-ce`, or `portable` and the
logical CPU core count. The AES configuration does not silently become
BLAKE3 when acceleration is absent. The non-default BLAKE3 GGM path remains
available only through an explicit configuration/CLI selection. Every result
JSON, including diagnostic JSON, contains exactly

```text
ggm_prg: "aes128-mmo" | "blake3"
```

and records the detected AES feature. Both paths are tested. Binding fase-D
record modes require the real backend with the default `aes128-mmo` path.

Rayon covers independent tree construction/reconstruction, batched LPN rows
and per-stage malicious-check products while every collected result is restored
to canonical stage/tree/row order. Each JSON records the effective Rayon thread
count, detected logical CPU count and host identity. Wall time is compared only
within a host/profile; the 4-core aarch64 and pod-CPU splits are reported
separately and neither is presented as portable speedup evidence.

## 4. Delta-per-connection lifecycle

### 4.1 Durable connection open

A connection is bound to an explicit 256-bit `connection_id` and authenticated
channel identity. Before entropy or correlations are generated, a
`ConnectionStore` atomically creates an append-only connection record with the
same `create_new`, file `fsync`, and directory `fsync` discipline as
`ResponseAuthorizationStore`. The public stage plan and its digest are part of
the record.

The prover and verifier then take fresh, independent 256-bit `OsRng` role
samples. The verifier samples one fresh private `Delta`. The one base OT,
COPEe and concatenated IKNP extension described in §2.3 runs for the
connection. `Delta`, delta-equivalents and role seeds are never message fields.
An existing open record without a terminal marker is a crash/kill poison on
reopen: recovery appends and syncs a crash-burn marker, rejects resume, and
requires a brand-new connection and full base phase.

### 4.2 Per response

Each response supplies a verifier-issued single-use authorization nonce.
`ResponseAuthorizationStore` burns it durably before allocation; it remains
burned on success and on every error. Response success does **not** burn the
connection.

The logical correlation namespace is

```text
(connection_id, response_nonce, layer, head, position, tensor_tag).
```

Each response has a fresh challenge/mask/correction context, its own canonical
allocation digest and its own channel-ledger digest. A connection-level digest
chains the ordered response digests. The real and explicit mock backends share
this logical allocator so counter and digest parity is PRG-independent. Every
correlation remains one-time and counted.

### 4.3 Refill and counters

A refill consumes only the predecessor's already reserved raw sub-VOLEs under
the same connection `Delta` and its preprovisioned path-OT slice. It uses the
stage label `stage3/<ordinal>`, runs a fresh per-stage WYKW malicious
consistency check, and cannot publish output before acceptance.

Every stage records at least:

- `generated` usable outputs;
- `consumed` response allocations;
- `reserved_as_base` outputs, terminally excluded from every response;
- `burned` unused outputs at abort/close/TTL; and
- live `available` plus child-side `base_inputs_consumed` for reconciliation.

At a terminal state, for each producing stage,
`generated = consumed + reserved_as_base + burned`. A base reservation remains
classified `reserved_as_base` even after the child consumes it, so it can
never re-enter an allocatable pool. Counters and allocation digests are checked
on both roles and are part of the terminal record.

### 4.4 Abort, close, TTL, and channel

Any abort is terminal for the entire connection: malicious-check failure,
malformed frame, length/kind/order error, digest/counter mismatch, unexpected
EOF, entropy/store failure, process kill, explicit abort, or proof/protocol
failure after allocation. The handler appends and syncs a terminal connection
marker and burns all pools, reservations and unused base/path material. If the
process dies before writing it, recovery performs the durable crash-burn before
rejecting reopen. No response or PCG session can resume.

Explicit close and TTL expiry use the same terminal path, burn all residual
material, and record the count. Reconnection always creates a new connection,
new identities, new role entropy, new `Delta`, and pays the full base phase.

The wire remains exactly

```text
kind:u8 || length:u64_le || payload
```

with no secret identity fields. The channel-secrecy test reparses complete
multi-response connection transcripts and rejects any occurrence of `Delta`, a
delta-equivalent, or either role seed.

## 5. Part-B gates preregistered now

All official records require a clean unchanged SHA and append-only JSON. Part
A runs only tests and quick non-record sanity checks.

### G1 — binding CPU correctness/default gate

Run full `T=100+50`, PCS `Q=200`, with real as the **default** backend. Require:

- frozen 50-token golden decode;
- normal and chunked acceptance;
- 13/13 PCS verifications and protocol closure;
- the complete malicious suite;
- packed response exactly **136,526,530 B**;
- mock/real logical-counter, allocation-digest and channel-digest parity; and
- `ggm_prg:"aes128-mmo"` with the host AES feature, detected physical/logical
  core inventory and effective PCG Rayon worker count recorded.

### G2 — binding capacity/traffic gate

Use one `terminal-one` connection with all six path-OT slices preprovisioned
and at least one stage-3 activation. Require at least **110,000,000 usable raw
sub correlations** and **total serialized setup traffic <=40,000,000 B**. The
byte gate is machine-independent. Report exact directional and per-category
bytes. Report setup/main/stage-3 wall splits on both the 4-core aarch64 host and
the pod host as informative, host-specific measurements. Each report includes
detected physical/logical cores and `pcg_setup_rayon_threads`; this worker count
is independent of any Rayon setting used by the prover. The 38,371,465 B
calculation in §2.3 is not a gate result.

### G2b — binding functional connection gate

Serve at least three accepted responses inside one connection. Responses 2
through n repeat **zero base-OT and zero OT-extension bytes**. In a separate
case, inject an abort on response 2; require terminal whole-connection burn and
prove that durable reopen cannot resume it.

### G3 — informative scale run

Use `chain-six` to generate approximately 600,000,000 correlations through the
two-batch-per-stage release sink while respecting the 4,000,000,000 B cap.
Report wall, stage splits, traffic, exact counters/digests, generated/reserved/
burned counts, and observed buffer high-water. Failure is logged with the
exact obstruction and does not block the package.

### G4 — binding pod gate

Create the new provider profile **`runpod-a100-realpcg-v1`**. Carry forward
from `runpod-a100-v1` only:

- prefill core <=10 s, wall-only;
- decode marginal <=4 s;
- H2D <=100,000,000 B;
- maximum synchronization wall / response-session wall <=2%; and
- the wall-only plus counters timing policy, with no CUDA-event timing.

Require packed response exactly **136,526,530 B** (the C1 reference; the old
profile's 144,820,930 B binding is not reused), golden decode, chunked
flat-cost ratio <=1.5, anti-replay, mock/real digest parity, and real-PCG setup
on the pod host CPU with its core count recorded. Setup wall, stage split and
traffic are the informative first-run baseline for this host class. Record
detected physical/logical cores and `pcg_setup_rayon_threads` explicitly; no
setup wall gate is preregistered on unmeasured hardware.

## 6. What fase-D does not change

Fase-D changes PCG generation, backend selection and connection lifecycle. It
does not change or authorize changes to:

- the proving or verification path;
- proof bytes, proof transcript bytes, response bytes, PCS bytes, or the
  150--200 MB response product constraint;
- the governing trade rule: prover time may be traded for verifier time,
  never for final proof/response bytes or communication;
- the packed response reference **136,526,530 B**;
- correction encoding: corrections remain canonical 8-byte `F_p` elements;
- PCS `Q=200`, rate, commitment shapes, claim count, one batched opening per
  response, or challenge order;
- the rule that a PCS opening resolves into VOLE-authenticated values rather
  than cleartext weight evaluations;
- prefill/decode witness semantics, fixed-point quantization, golden outputs,
  CUDA proof kernels, operation counts, or transcript schedule;
- deferred stacked decode proving or the prohibition on per-token proof
  instances and per-token PCS claims;
- boundary thinning or prewarming pools;
- Packed16 / C1 Phase 2, which remains blocked/shelved;
- `runpod-a100-v1`, its 144,820,930 B historical binding, any old result,
  profile, validator or verdict; or
- `pcg_production_ready:false` during Part A.

BLAKE3 remains unchanged everywhere except that it is no longer the default
GGM node-expansion PRG. Setup traffic remains `pcg_setup_comm_bytes`, separate
from response download and rho, but it is always reported prominently.

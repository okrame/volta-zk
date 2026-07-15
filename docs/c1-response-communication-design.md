# C1 response-communication reduction — Phase 1 design

**Status (2026-07-15): Packed16 rejected; identity-seam reuse authorized.**
The 2026-07-15 C2 review in `docs/prototype-status.md` supersedes the original
two-lever Phase-1 proposal below.  Sections 1.1--3.5 and the Packed16 rows in
§5--6 remain historical design/costing only: they authorize no implementation,
new correlation lane, or Lean work.  The surviving C1 scope is exactly §4.
Its full-response projection is 136,526,530 B, its post-reuse sub-correlation
demand is 7,443,126, and the adapted acceptance contract is the ledger entry.
This note is retained so the rejected packing path is not rediscovered or
silently reintroduced.

## 1. Frozen baseline and scope

The clean P6 accounting record
`benchmarks/results/p6-2026-07-07-382bb56.json` and the clean P6 run of record
`p6-2026-07-07-515bb1c.json` agree exactly on their shared communication and
correlation fields.  The later CPU, resident-A100, and official RunPod records
preserve those counts.  At T=100+50 and PCS Q=200:

| Item | Bytes |
| --- | ---: |
| Response transcript | 137,413,808 |
| of which PCS opening | 66,733,504 |
| Packed public logits | 7,407,122 |
| **Packed response download** | **144,820,930** |
| `auth_corrections` inside the transcript | 67,839,408 |

The derivation uses `LayerBytes::boundary` and the
`8 * 5 * (t * D)` formula in `rust/volta-proto/src/block_proof.rs`, the
per-label snapshots and response formula in
`rust/volta-bench/src/bin/p6_report.rs`, and the independent
`comm_response_bytes + public_logits_packed_bytes` reconstruction in
`scripts/report.py`.  The official clean RunPod record
`p7b-integrated-resident-wall-only-counters-2026-07-14-ab3a03f.json`
reproduces the same fields byte-for-byte.

C1 uses only two levers: §4.6.B packed i16 boundary corrections and §4.3
identity-seam `x_in` authentication reuse.  It does not change PCS Q/rate,
commitment shape, challenge order, public-logit policy, quantization, or the
MAC equation.  §4.6.A cached columns, §4.1.4 linear RLC merging, §4.2 argmax,
GPU kernels, provider profiles, and the real-sVOLE default are excluded.

### 1.1 Exact packing eligibility

The first packed format is deliberately narrow.  It applies to these four
`i16` matrices in every one of the 12 layers, for both the 100-row prefill and
the 50-row deferred decode band:

- `K`;
- `V`;
- `attn_block_out`;
- `ffn_block_out`.

These are the four P0 boundary streams.  Their existing byte formula is

```text
N_pack = 4 * 12 * (100 + 50) * 768 = 5,529,600 values
raw     = 8 * N_pack                 = 44,236,800 B
```

The following remain on the existing 8-byte F_p correction format in C1:

- all `x_in` streams (the sound identity-seam subset is removed by §4; the
  layer-0 and two nonzero-requant seam inputs remain raw);
- embedding and final-LN special boundary auths;
- multiplicity vectors, LN statistics, attention row tables, and sparse
  accumulators authenticated by `auth_fp_vec_p`;
- every F_p² round, claim, LogUp, PCS, mask, and zero-batch correction.

This exclusion is load-bearing: an `Fp` value is not packable merely because
an honest run happens to fit in 16 bits.  The measured `auth_corrections`
identity is

```text
44,236,800  eligible four-boundary raw bytes
+11,059,200 all x_in raw bytes
+ 1,253,376 embedding/final-LN i16 raw bytes
+11,290,032 other F_p auth bytes
=67,839,408 measured auth_corrections bytes.
```

## 2. Packed16 wire and authenticated carry

Let `B = 2^16` and `H = 2^15`.  A packed correlation at index `i` contains
two independently generated, valid MAC-authenticated plaintexts under the
same session `Delta`:

1. `a_i`, uniform in `[0,B)`; and
2. `b_i`, a uniform bit.

Both retain the ordinary invariant `k = m + Delta*x` in F_p².  They are fresh,
one-time, and use distinct typed correlation domains.  This is **not** obtained
by truncating the low 16 bits of the current uniform-F_p `SubCorr`; that would
lose the MAC relation and is forbidden.

For an eligible signed `x_i : i16`, define the biased unsigned value
`z_i = x_i + H`, so `z_i` lies in `[0,B)`.  The prover computes

```text
d_i = (z_i - a_i) mod B                         // u16
c_i = 1 iff a_i + d_i >= B                      // the true carry
e_i = c_i xor b_i                               // public masked carry
```

The response sends `d_i` and `e_i`, never `c_i`.  Given public `e_i`, both
parties derive an authenticated carry by the affine identity

```text
c_i = e_i + (1 - 2*e_i) * b_i  in F_p.
```

They then derive the existing F_p-authenticated boundary value as

```text
x_i = a_i + d_i - B*c_i - H  in F_p.
```

If `(m_a,k_a)` and `(m_b,k_b)` are the two correlation shares and
`lambda = 1 - 2*e_i`, the concrete local updates are

```text
m_c = lambda*m_b
k_c = e_i*Delta + lambda*k_b
m_x = m_a - B*m_c
k_x = k_a + Delta*(d_i - H) - B*k_c.
```

No verifier challenge and no extra interactive round is introduced.

### 2.1 Canonical wire format

The versioned outer proof schema supplies every batch length; C1 adds no
per-batch header.  An eligible batch of `N` row-major values is encoded as:

```text
delta16_le : 2*N bytes
carry_otp  : ceil(N/8) bytes
```

`delta16_le[2*i..2*i+2]` is canonical little-endian `d_i`.  Bit `i` of
`carry_otp` is `e_i`, least-significant bit first in each byte.  Unused high
bits in the last byte must be zero; wrong length or nonzero padding fails
before any challenge or correlation consumption.  All C1 batches have 768
columns, hence `N` is divisible by eight and the projected format has no pad
bits.

The exact C1 packed payload is therefore

```text
2*N_pack + N_pack/8 = 11,750,400 B,
```

a **32,486,400 B** response reduction versus the 44,236,800 B raw payload.

## 3. Correctness, privacy, and soundness

### 3.1 Integer and field correctness

Because `a,d,z` are in `[0,B)`, `a+d` is at most `2B-2`.  There is a unique
`c in {0,1}` such that `z = a+d-Bc`; the comparison above computes exactly
that bit.  Thus

```text
a+d-Bc-H = z-H = x
```

as an integer, and therefore after the signed embedding into Goldilocks F_p.
No mod-p/mod-2^16 ambiguity remains.  The implementation must form `a+d` in
at least `u32`; the endpoints `x=-32768` and `x=32767` are explicit tests.
Encoding a value outside the Rust `i16` type is a hard error, never a wrap or
clamp.

The converse is the range guard needed for malicious soundness.  For any
canonical `a,d in [0,B)` and bit `c`, the integer
`x' = a+d-Bc-H` is in `[-98304,98302]`, and

```text
x' in [-32768,32767]  iff  c = 1[a+d >= B].
```

Thus a wrong carry selects `x' = x+B` or `x-B`; it cannot alias a different
signed-i16 value.  Goldilocks has characteristic far above this interval, so
these representatives also remain distinct after the F_p embedding.  The
Lean plan states this range equivalence over the integers and uses an explicit
characteristic lower-bound hypothesis for the embedding step.

### 3.2 Perfect hiding

For fixed `z`, uniform `a in Z/(2^16)` makes `d` uniform and independent of
`z`.  Conditioned on `a,d` (and hence on the true carry), independent uniform
`b` makes `e=c xor b` uniform.  Consequently `(d,e)` is exactly uniform on
`Z/(2^16) x {0,1}` for every eligible plaintext.  The clear carry is never
sent.  Reusing either `a` or `b` would expose relations between witnesses and
is a fatal one-time-use violation.

### 3.3 MAC soundness and malformed values

Substitution of the two validity equations into the local update gives
`k_x = m_x + Delta*x`; the result is the same F_p-typed authenticated value
consumed by M3/M4/M7/M8.  A wire adversary that flips the masked-carry bit
changes the already-bound plaintext by exactly `B`; changing `d` applies the
corresponding public field offset.  Making the altered verifier key agree with
the original prover tag/value is an ordinary Delta forgery.

As with existing `Pi_Auth`, the primitive authenticates the value selected by
the correction; it is not itself a proof that a malicious prover selected the
honest witness.  A prover that constructs a noncanonical carry is instead
bound to the out-of-i16 representative characterized in §3.1, never to a
second in-range value.  The four eligible streams remain closed against their
existing requant/residual model relations, so accepting that representative
requires breaking those closures (or an existing model-range assumption),
not exploiting mod-2^16 aliasing.  Phase 2 must test a prover-generated wrong
carry with recomputed local shares as well as a post-generation wire flip.
It must not promote the run if the composition audit finds a new unproved
range assumption.  Downstream zero-open and zero-batch soundness remains over
F_p², not over the 16-bit ring.

The typed-correlation precondition is part of the statement: `a` must be a
uniform 16-bit value and `b` a uniform bit.  A backend may not satisfy it by
mask truncation, by an unchecked prover-chosen value, or by reusing a bit
pad.  A backend without the capability fails closed.

### 3.4 Correlation-realization boundary

`Packed16Corr` is an extension of the ideal correlation interface, not a
claim that the closed phase-B generator already emits restricted masks.  Its
MAC equation, Delta ownership, one-time use, and domain/allocation-digest
semantics are unchanged; its plaintext distribution and counters are named
separately.  The mock backend can exercise the functional path, but remains
non-production.  The current real phase-B parity candidate does not realize
this typed lane and C1 does not reopen or resize it.  `--pcg-backend real`
must therefore reject packed C1 rather than truncate masks or silently fall
back to a different proof.  A real realization requires a later, separately
preregistered PCG decision.

This is the explicit Phase-1 review point.  If “no change to correlation
semantics” freezes the current `SubCorr.r` distribution (uniform F_p), then
§4.6.B cannot proceed: its field correction is uniform over F_p and cannot be
losslessly encoded in 16 bits.  This design interprets the frozen semantics as
the MAC equation, Delta ownership, freshness, domain separation, and exact
counting, while adding the typed `(u16, bit)` distribution required by the
already-requested M5 extension.  User approval of that interpretation is a
precondition to Phase 2.  If it is rejected, Packed16 stops and only the
separately accounted identity-seam reuse remains eligible.

### 3.5 Named Lean extension of M5

Phase 2 must add only `lean/VoltaZk/PackedCorrection.lean`, imported by the
formal audit, with no `sorry`, `admit`, or new axiom.  The planned statements
are:

- `packed16_reconstruct`: the unique carry identity above commutes with the
  signed-i16 embedding into F_p;
- `packed16_carry_iff_signedRange`: over the integers, the decoded value is in
  `[-2^15,2^15-1]` exactly when the supplied bit is the unique overflow carry;
- `packed16_correct_valid`: two valid typed correlations and the canonical
  `(d,e)` update produce a valid `SubAuthed Fp E` for `x`;
- `packed16_wire_uniform`: fresh uniform `a` and `b` make `(d,e)` independent
  of `x` with the exact product-uniform distribution;
- `packed16_zeroOpen_sound`: the derived value transfers through
  `SubAuthed.toAuthed`, so a nonzero forged opening is accepted for at most
  one `Delta`, exactly as `sub_zeroOpen_sound`.

`packed16_correct_valid` is the named M5 extension required before Rust
enablement.  The field-facing statements carry an explicit characteristic
bound sufficient to inject the integer interval above; they do not silently
generalize the claim to characteristic-two or a small field.
`scripts/audit_lean.sh` must audit it, the range theorem, and the uniformity
theorem with only `propext`, `Classical.choice`, and `Quot.sound`.  No other
Lean file may change except imports/audit enumeration needed to expose these
theorems.

## 4. Sound `x_in` reuse

The frozen artifact has seam shifts `[3,2,0,0,0,0,0,0,0,0,0]`.  Therefore
only nine layer seams are byte-identical.  At each public `shift==0` seam,
the consumer `layer[l+1].x_in` uses a typed reference to the already
authenticated `layer[l].ffn_block_out`; it sends no second correction and
draws no second correlation.  The two nonzero seams remain fresh: their
`x_in` is a different requantized value, and eliminating it would require a
new fused seam proof outside C1.

The existing public domain slot is retained as a tombstone so unrelated K/V
and layer-domain numbering does not shift.  The alias carries the producer's
full `(session, phase/chunk, layer, tensor, row)` authentication identity.
Both parties preflight the public seam shift, shape, source layer, and exact
row interval before consuming transcript or correlation state.  Aliases may
not cross prefill/decode, chunks, sessions, layers other than `l -> l+1`, or
positions.  This is one authenticated write with two in-session readers, not
correlation reuse; the M4 mirror remains a duplicate-free write log with a
canonical read.  A replay or source swap produces a nonzero authenticated
difference and is covered by the existing scalar zero-batch anti-replay bound.

The exact full-response reduction is

```text
N_reuse = 9 * (100 + 50) * 768 = 1,036,800 values
saving  = 8 * N_reuse           = 8,294,400 B.
```

The handoff's `-6.9 MB` was a pre-decode, all-seams planning estimate.  It
must not be quoted as an exact C1 formula: the real artifact has two nonzero
seams, while the response includes 50 decode rows.  The formula above is the
sound current-workload number.

## 5. Projected accounting and cost

The two scopes do not overlap: C1 does not pack `x_in`.  From the frozen
144,820,930 B reference:

| Change | Delta (B) |
| --- | ---: |
| Four-boundary Packed16 payload | -32,486,400 |
| Nine identity-seam `x_in` aliases | -8,294,400 |
| **Projected packed response** | **104,040,130** |

Equivalently, the projected transcript is 96,633,008 B and the packed logits
remain 7,407,122 B.  PCS remains exactly 66,733,504 B.  This code-derived
projection is slightly better than the earlier approximate 105--113 MB
outlook; it is not a verdict or a replacement reference until a clean Phase-2
run measures it.

Logical correlation accounting changes as follows:

```text
ordinary F_p sub correlations  = 8,479,926 - 5,529,600 - 1,036,800
                                = 1,913,526
packed u16 mask correlations   = 5,529,600
packed carry-pad correlations  = 5,529,600
new sub-equivalent total       = 12,972,726  (old 8,479,926)
full correlations              = 176,880     (unchanged)
```

There are 7,200 fresh carry-domain rows and 1,350 removed identity-`x_in`
draw rows, net `+5,850`; both parties' allocation digests must include the
typed lane and aliases exactly.  Conservatively charging each carry pad as
one subfield correlation gives 13,326,486 sub-equivalent limbs including
the unchanged full correlations, 3,112,319 above the current phase-B usable
capacity.  This is why the real backend cannot be claimed for C1 without a
separate PCG preregistration.

The allowed trade direction is bytes for bounded prover/verifier work.  The
measured mock prover sub-expansion rate projects about `+0.091 s` for the net
4,492,800 extra logical correlations.  P3's lazy-tag measurement projects
about `+0.082 s` per additional streamed tag pass after the reuse credit.
Encoding is integer subtraction/comparison plus bit packing.  The honest
Phase-2 expectation is therefore `+0.2--0.6 s` prover wall (about 1--3% of
the 18.7 s CPU response record), with verifier work reported separately.
This is a projection, not a performance gate: a measured increase above 10%
requires a ledger review before a run is promoted, and no implementation may
recover time by increasing response bytes or weakening soundness.

## 6. Preregistered Phase-2 acceptance contract

After explicit user approval, Phase 2 must satisfy all of the following:

1. Land the named Lean M5 extension first; `lake build` and the named-axiom
   audit pass.  No other formal scope opens.
2. Frozen prefill and 50-token greedy decode are bit-identical to the current
   golden artifacts.  Normal acceptance, chunked acceptance, PCS verification,
   and protocol closure all pass.
3. Soundness smoke rejects a changed `d`, changed carry-OTP bit, a
   prover-generated noncanonical carry with recomputed local shares, nonzero
   pad bit, swapped mask/carry lane, reused typed correlation, illegal alias,
   nonzero-seam alias, cross-position/chunk/session replay, and allocation
   digest mismatch.  Honest endpoint and overflow vectors pass; the
   composition audit introduces no new range assumption.
4. New ordinary/packed/carry/reuse counters and byte-label formulas reconcile
   exactly on prover and verifier.  PCS Q=200, rate, claims, challenge order,
   correction/correlation one-time semantics, and all non-C1 proof labels are
   unchanged.
5. CPU and CUDA-resident paths use the same proof representation and are
   byte-identical for the packed payload, carry bitmap, counters, transcript
   ledger, and verifier outcome.  They are updated in the same checkpoint;
   there is no backend-dependent raw fallback.
6. Run the clean full T=100+50/Q=200 CPU report, with frozen golden decode,
   and write one new append-only `benchmarks/results/c1-<date>-<gitsha>.json`.
   It records the measured packed response, complete old/new byte formulas,
   prover/verifier cost deltas, typed-correlation counts, PCG capability, full
   SHA, and `git_dirty:false`.  No old JSON is overwritten.
7. C1 deliberately re-baselines the communication reference.  Historical
   `runpod-a100-v1` results remain bound to exactly 144,820,930 B.  Rust and
   Python validators must be updated together only after the clean C1 number
   lands, and any later official GPU run requires a separately preregistered
   gate profile with the new measured transcript/packed-response reference.
   It may not mutate or retroactively reinterpret the old profile.

Phase 2 stops without a milestone verdict if any item fails.  No §4.6.A,
§4.1.4, Q/rate, argmax, GPU-kernel, real-sVOLE default, or provider-profile
work may be folded into the retry.

# C5 — Packed16 over inline Ligero rate-8

**Status (2026-07-28): Phase 1 stopped at the binding typed-PCG feasibility
gate. No cited construction satisfies the frozen security interface and
`56,645,065-B` combined-setup ceiling. No Lean/Rust/CUDA protocol
implementation, pod contact or production verdict exists.**

C5 keeps the inline C4 Ligero geometry `rate=1/8,Q=97` and changes only the
wire strategy for a closed set of response-boundary authentication
corrections. It does not use deferred settlement. Every response remains
weight-certified before acceptance.

## 1. Owner ruling and immutable C4 history

The product owner adopts the C4 rate-8 result as the product baseline for C5.
This adoption accepts the historical candidate's marginal session and
synchronization observations for the purpose of starting a new experiment.
It does not rewrite the immutable C4 raw or paired records:

- C4 remains an overall raw **FAIL** at `e99a1e5`;
- the recorded complete-session ratio remains
  `1.0508166380856931 >1.05`;
- the recorded maximum synchronization wall remains
  `0.155717607 s >0.150 s`;
- no selective retry of C4 is authorized or performed.

The comparison document may label the existing column “product-owner adopted
base for C5,” but must retain the original raw verdict beside that label.
C5 uses fresh records, a new design digest, a same-build raw-rate8/Packed16
pair and the robust measurement rule in section 7.

## 2. Scope and frozen invariants

C5 changes:

1. the correlation interface by adding exact-uniform authenticated `u16` and
   authenticated bit lanes;
2. the correction encoding for the eligible values;
3. the allocation digest, codec and report schema required to bind and count
   those lanes.

C5 does not change:

- fixed-point inference, quantization, witness values or golden output;
- T1 chain geometry or the existing identity-`x_in` aliases;
- C4 weights/embed layouts, code length, `Q=97`, commitments or `96+6`
  opening claims;
- Ligero query freshness, challenge order, Merkle grammar or statistical
  expression;
- the VOLE-MAC equation `k=m+Delta*x` in `Fp2`;
- one-time use, domain separation, connection abort/burn or verifier-only
  `Delta`;
- GKR, LogUp, sumcheck, PCS authenticated-output semantics or final
  acceptance;
- the rule that production uses the real/AES backend and fails closed rather
  than falling back to mock or CPU.

M1--M11 remain frozen. A separately named C5 Lean addendum must prove the new
correction algebra before Rust protocol code begins.

## 3. Exact post-T1 census and byte target

The eligible values are exactly:

```text
K/V values                         = 2*12*150*768 = 2,764,800
T1 four-layer-chain exit values    =   3*150*768 =   345,600
eligible Packed16 cells            =               3,110,400
```

The chain entry is the already-aliased `x_in` seam and is not packed. Lookup
fractions, multiplicities, masks, PCS values, reducer scalars and every
remaining `Fp`-typed correction are not packed.

For each eligible cell, the old payload is one canonical eight-byte field
element. The new payload is one canonical two-byte little-endian word plus
one bit in a canonical carry bitmap:

```text
old eligible payload     = 8 * 3,110,400       = 24,883,200 B
u16 payload              = 2 * 3,110,400       =  6,220,800 B
carry bitmap             =     3,110,400 / 8   =    388,800 B
new eligible payload                               6,609,600 B
exact saving                                      18,273,600 B
```

The binding response formula is:

```text
current C4 auth corrections       = 38,348,720 B
new auth corrections              = 20,075,120 B
other non-PCS transcript          =  2,921,744 B
new non-PCS transcript            = 22,996,864 B
C4 rate-8 PCS                     = 38,296,040 B
expected C5 response              = 61,292,904 B
response ceiling                  = 70,000,000 B
```

Both equality to `61,292,904 B` and the `<=70,000,000-B` product ceiling are
binding. A missing frame is not a byte saving.

## 4. Packed correction relation

Let `B=2^16`, `H=2^15`, and let an eligible signed witness value be
`x in [-H,H-1]`. Define `z=x+H in [0,B)`. The typed-PCG supplies independent,
fresh authenticated plaintexts under the connection's existing `Delta`:

```text
a uniform in {0,...,B-1},  k_a = m_a + Delta*a
b uniform in {0,1},        k_b = m_b + Delta*b.
```

The prover sends:

```text
d = (z-a) mod B
c = 1 iff a+d >= B
e = c xor b.
```

The verifier and prover use the public `d,e` and their authenticated shares to
derive an ordinary `Fp`-typed authentication of

```text
z = a+d-B*c
x = z-H.
```

The factor `B` is interpreted canonically in `Fp`; no ring-valued
authentication is introduced. The carry bit is sent only as the one-time-pad
masked `e`. Noncanonical two-byte/bitmap encodings, nonzero unused bitmap bits,
wrong lane identities and duplicate consumption fail closed.

## 5. Typed-PCG feasibility gate and local result

The 2026-07-15 C2 construction is not an implementation candidate. Its
per-source-bit `Fp2` arithmetic lift is the cost being screened out, not an
architecture to rename.

Before Lean or Rust protocol edits, one cited two-party construction must
close all of the following:

- malicious security with abort, without a trusted dealer;
- exact-uniform `u16` and bit plaintext distributions;
- the existing odd-characteristic `Fp2` MAC and verifier-only connection
  `Delta`;
- no truncation of uniform-`Fp` values and no unchecked prover-chosen typed
  masks;
- no 16-byte arithmetic correction per constituent bit;
- domain-separated, one-time outputs with durable allocation and burn;
- five response inventories in one connection:

  ```text
  packed u16 outputs = 5 * 3,110,400 = 15,552,000
  carry-bit outputs  = 5 * 3,110,400 = 15,552,000;
  ```

- every setup, base-OT, extension, correction, check, frame and control byte
  included in a combined setup total of at most **56,645,065 B**;
- zero repeated base-OT, OT-extension or typed setup bytes for responses 2--5.

The first-exchange identity is binding:

```text
setup_total + 61,292,904 <= 117,937,969 B.
```

The feasibility record distinguishes cited theorem, adopted assumption,
parameter estimator, exact serialized formula, directional traffic, number of
response inventories and engineering projections. If no construction closes
this gate, Phase 1 appends an obstruction record and stops without Lean, Rust,
pod request or product verdict.

### 5.1 Available byte budget

The measured C4 rate-8 setup is `38,371,465 B`. Therefore C5 has exactly

```text
typed setup headroom = 56,645,065 - 38,371,465 = 18,273,600 B
headroom per inventory cell = 18,273,600 * 8 / 15,552,000
                            = 9.4 bits
```

for **both** an independently authenticated uniform-u16 value and an
independently authenticated uniform bit, including every generator and check
byte. The ideal pair contains 17 bits of entropy per cell, but entropy alone
does not impose a 17-bit communication lower bound on a PCG. The `9.4-bit`
figure is instead the exact engineering budget that a cited PCG instantiation
must close.

### 5.2 Construction screen

The local screen reached the following dispositions:

| Family | What the cited construction supplies | C5 disposition |
| --- | --- | --- |
| C2 Ferret-Uni plus arithmetic lift | Malicious binary COT, followed by one explicit 16-byte `Fp2` correction per authenticated source bit | **Security fit, byte FAIL.** Five inventories require `264,384,000` source bits and exactly `4,230,144,000 B` of lift corrections. Even the paper projection of `0.73 bit/COT` for the binary core alone is `24,125,040 B`, already above all typed headroom before lift, base setup or checks. |
| Current odd-prime `Fp` sVOLE plus exact extraction | Uniform authenticated `Fp` values under the right `Delta` | **Exact but byte FAIL.** Section 5.3 gives a constructive, bias-free conversion whose optimistic public quotient payload is `217,728,000 B`. |
| SoftSpokenOT, Half-Tree and newer subfield-OLE PCGs | Small-subfield coefficients inside an extension field of the **same characteristic** | **Algebraic mismatch.** `F2` is not a subfield of odd-characteristic `Fp2`; choosing the actual subfield `Fp` restores full-field masks. A cross-characteristic conversion is still required. |
| Mystique zk-edaBits / arithmetic-Boolean conversion | A full-field arithmetic value plus its bits authenticated under distinct arithmetic and Boolean keys, with conversion protocols | **Interface mismatch.** It does not directly produce exact-uniform u16 and bit plaintexts under VOLTA's single verifier-only `Fp2 Delta`; importing it adds a second MAC domain and conversion protocol. |
| Scholl low-communication random OT | Sublinear random `1-out-of-p_i` OTs; its arbitrary-abelian-group correlated OTs are the **base** `k` OTs | **No scalable group-COT output.** Converting the extended random OTs to messages differing by the connection `Delta` requires per-output chosen-message/correction traffic and returns to the arithmetic lift. |
| EA-code and quasi-abelian PCG/PCF families | Uniform-ring OLE/degree-two/authenticated correlations from a correlated key generator | **No cited typed instantiation.** Authenticated outputs and MAC keys live in the same ring as the sampled variables; the papers do not supply a dealerless malicious generator for bounded u16/bit variables under an externally held odd-prime `Fp2 Delta` with a serialized cost below this gate. |
| BarnOwl silent daBits/edaBits | Silent mixed-circuit preprocessing | **Trust-model mismatch.** The construction is three-party with honest majority, not VOLTA's dealerless two-party designated-verifier setting. |
| Bounded-integer/ring VOLE | VOLE and authenticated computation over an integer/RSA-type ring | **Protocol-field mismatch.** It requires changing the frozen `Fp2` MAC and downstream proof algebra. |

Primary references used by the screen are Ferret
([Yang et al., ePrint 2020/924](https://eprint.iacr.org/2020/924)),
SoftSpokenOT
([Roy, ePrint 2022/192](https://eprint.iacr.org/2022/192)),
Half-Tree
([Guo et al., ePrint 2022/1431](https://eprint.iacr.org/2022/1431)),
Mystique
([Weng et al., ePrint 2021/730](https://eprint.iacr.org/2021/730)),
low-communication OT
([Scholl, ePrint 2018/036](https://eprint.iacr.org/2018/036)),
EA-code PCGs
([Boyle et al., ePrint 2022/1014](https://eprint.iacr.org/2022/1014)),
newer subfield-OLE PCGs
([ePrint 2025/169](https://eprint.iacr.org/2025/169)), and BarnOwl
([ePrint 2022/800](https://eprint.iacr.org/2022/800)). The
bounded-integer/RSA-ring disposition uses the malicious constant-rate 2PC
construction
([ePrint 2024/283](https://eprint.iacr.org/2024/283)).

The screen does not claim a general cryptographic impossibility theorem.
Instead it records that none of the cited families instantiates the complete
C5 functionality and byte formula. A future revival needs a new concrete
construction, security reduction, parameter set and exact serializer; a
generic “PCG can be succinct” statement is not sufficient.

### 5.3 Exact current-sVOLE conversion and why it still fails

The Goldilocks prime is

```text
p = 2^64 - 2^32 + 1
p - 1 = 2^32 * (2^32 - 1).
```

This permits an exact construction, so the rejection of current sVOLE is not
based merely on the usual modulo-bias warning. For a uniform authenticated
`r in Fp`, reject only `r=p-1` and prove that rejected equality through the
existing MAC. An accepted value is uniform on `[0,p-2]`.

For a u16 mask, write

```text
r = a + 2^16*q,
0 <= a < 2^16,
0 <= q < (p-1)/2^16 = 281,474,976,645,120.
```

The product interval is exact, hence honest public `q` and hidden `a` are
independent and `a` is exactly uniform. A canonical 48-bit `q` lets both roles
derive the authentication of `a` affinely from the authentication of `r`.
This costs six public bytes per output. The analogous honest bit construction
writes `r=b+2*q` and needs a canonical 63-bit quotient, serialized in eight
bytes.

Malicious security additionally requires a batch proof that every hidden
remainder is in its claimed u16/bit range. With that range statement the
quotient is unique, `r=p-1` has a quotient one past the permitted bound, and a
false rejection must open the authenticated equality. Without it a corrupt
prover could send a smaller `q` and leave an out-of-range authenticated
remainder. The byte calculation below deliberately prices this proof, its
rejection headroom and its checks at zero: it is a lower envelope, not a
complete selected protocol. Abort would burn the allocation as usual.

One `SubCorr` authenticates one affine combination. It cannot yield two
independently consumable typed MAC equations merely by interpreting several
low limbs of the same `r`; splitting those limbs requires another correlated
share or public correction. Thus the optimistic existing-backend cost for
five inventories is:

```text
u16 quotient bytes = 15,552,000 * 6 =  93,312,000 B
bit quotient bytes = 15,552,000 * 8 = 124,416,000 B
typed increment                              217,728,000 B
combined setup       = 38,371,465 + 217,728,000
                     =                         256,099,465 B
first exchange       = 256,099,465 + 61,292,904
                     =                         317,392,369 B
```

This is already an optimistic lower envelope: the current setup has enough
otherwise burned full-field capacity, so it charges no new sVOLE expansion,
framing, rejection headroom or checks. It nevertheless exceeds the setup gate
by **199,454,400 B**. It is therefore not an implementation candidate.

### 5.4 Gate disposition

No candidate simultaneously satisfies exact typed distributions, the existing
one-sided `Fp2` MAC/`Delta`, dealerless malicious security, five inventories
and the setup formula. C5 Phase 1 therefore records
`HARD_STOP_TYPED_PCG_OBSTRUCTION` in
`benchmarks/results/c5-typed-pcg-obstruction-2026-07-28-0309320.json`.

The exact `61,292,904-B` response remains a **wire projection conditional on
an unrealized typed-PCG**, not a measured result. No performance or product
gate is evaluated. Sections 6, 7 and 9 remain a frozen conditional
implementation/campaign contract for a future separately preregistered
revival; they are not entered by this checkpoint.

## 6. Ordered local implementation, not entered

1. Append the selected construction and complete security/cost derivation to
   this document and the ledger.
2. Prove the C5 Lean addendum: integer reconstruction, canonical signed
   mapping, MAC preservation, masked-carry privacy, malformed-carry binding,
   lane separation and one-time consumption. The full build and named-axiom
   audit must pass without modifying M1--M11.
3. Extend the correlation contract with separately named `PackedU16` and
   `PackedCarry` outputs. Mock remains diagnostic; production requires the
   selected real/AES construction and fails closed.
4. Implement canonical two-byte corrections and carry bitmaps on CPU and
   CUDA-resident paths. The raw rate-8 compatibility profile remains
   byte-identical to C4.
5. Extend allocation/channel digests and counters for generated, reserved,
   consumed and burned typed outputs. Crash, abort, TTL and explicit close
   remain terminal for the connection.
6. Add exact response/setup/first-exchange reconstruction to the Rust report,
   Python validator and negative validator suite.

## 7. Phase-2 performance and resource gates

Phase 2, if separately authorized, uses one unchanged build and nine
same-host pairs:

- `A`: raw C4 rate-8 compatibility profile;
- `B`: rate-8 plus Packed16;
- one excluded warm-up per profile;
- fixed design-digest-derived alternating `AB/BA` order;
- fresh response authorizations and disjoint correlation allocations;
- no selective retry.

For response proof and complete response-session walls:

1. nominal target: paired median `B/A <=1.05`;
2. accepted measurement band: paired median `B/A <=1.06`;
3. at least eight of nine paired ratios must be `<=1.075`;
4. a paired median above `1.06` is FAIL.

The validator reports every pair, medians, MAD and a fixed-seed bootstrap
interval. The interval is descriptive; it cannot replace the closed rule.

For synchronization:

- at least eight of nine candidate samples are `<=0.150 s`;
- every candidate sample is `<=0.175 s`.

This rule tolerates one marginal observation but not repeated tail growth or
a large outlier. It applies only to C5 and does not rewrite the C4 maximum.

Other conjunctive gates:

- exact response `61,292,904 B` and ceiling `<=70,000,000 B`;
- combined setup `<=56,645,065 B`;
- first exchange `<=117,937,969 B`;
- PCS exactly `38,296,040 B`;
- rate-8 statistical soundness at least `78.86651649674867` bits, plus the
  C5 typed-correction theorem;
- device live bytes `<40,000,000,000`;
- response H2D `<=100,000,000 B`;
- decode last/first `<=1.5`;
- five accepted responses with zero repeated setup categories after the
  first;
- golden, normal/chunked acceptance, cap, tamper, stale-root, freshness,
  abort/burn, codec, correlation, leakage and settlement-free weight
  certification suites all green.

Setup wall and directional traffic are reported in full. Setup wall is
informative because the owner explicitly permits heavy one-off computation;
the byte and first-exchange gates remain binding.

## 8. Local obstruction record, documents and hard stop

All C5 records use create-new append-only paths. Local records state:

```text
pod_contacted=false
production_pair_started=false
gate_verdict=false
```

At this local checkpoint:

- no Lean, Rust, CUDA, codec or proof-path file is changed;
- the analytic obstruction record and its formula validator pass;
- the existing workspace and report validators remain green;
- `docs/prototype-status.md`, this design, relevant current C1/C2 pointers and
  `docs/gpt2-comparison-WIP.md` are reconciled;
- historical records and recorded design digests remain unchanged.

Then **HARD STOP**. Because the implementation precondition failed, this
checkpoint does not request an A100. Pod/provider contact requires both a new
typed-PCG design that closes section 5 and a new explicit owner GO after its
own clean local checkpoint.

## 9. Future admitted A100 profile

The future profile, not yet authorized, is:

- one selected A100-SXM4-80GB (`sm_80`) with at least 40,000,000,000 B free;
- at least 64 GiB host RAM;
- at least 80,000,000,000 B free local non-FUSE storage;
- at least 13 effective CPUs, with Rayon exactly eight;
- CUDA toolkit and the fail-closed production backend.

After an authorized campaign, the comparison table keeps the C4 rate-8 raw
verdict visible, marks its C5 owner adoption, and places the measured C5
Packed16 column immediately after it. The pod is stopped from the control
plane at session end and the SSH endpoint is independently checked.

# X4 folding-PCS amended preregistration and Phase-2 statement freeze

**Status (2026-07-21): R1B AMENDMENTS 1--2 FROZEN; AMENDMENT 2 CORRECTS THE
DIRECT-MASK GOOD-TAPE PREMISE; PRODUCT OWNER AUTHORIZED LEAN-FIRST PHASE 2
AND THE SUBSEQUENT PLAN SUBJECT TO THE EXISTING HARD STOPS.**

This document is the Phase-1 preregistration for X4. It replaces the original
X4 premise in `docs/scaling-note.md`: lever A (cache/reuse fixed query rows)
is recorded UNSOUND and receives no credit. The replacement is a folding-PCS
package, co-designed with D3 per-layer commitments and canonical per-expert
blocks. This X4 package contains design only. It changes no Lean declaration
or proof, X4 Rust code, benchmark reference or gate verdict.

The amended candidate profile is named **`x4-zkdeepfold-ud-e29-v2`**. It
supersedes `x4-zkdeepfold-v1`, which remains below as immutable Phase-1
history. All parameters, byte thresholds, measurements and failure rules are
preregistered before implementation. A later change to a security parameter,
block map, byte codec or gate requires an append-only deviation before the
affected run; a failed result may not be tuned into a pass.

Historical Section 5.1 is the product-owner-requested mitigation addendum for the
10.7008-TB first-oracle screen. It adds conditional paper-only alternatives
and an honest irreducibility boundary. R1b Amendment 1 below selects the
previously unexamined `2^29` block split and therefore supersedes conflicting
field, geometry, seam, storage and hierarchy text in Sections 1.1, 2.1, 3,
3.1, 4, 5, 5.1, 5.3--5.4, 6 and 8. Every gate or invariant not explicitly
amended remains in force.

## 0. R1b Amendment 1 (normative override)

This section is the amended plan of record. The old `K=F_p^4`, `mu_max=30`,
1,658-block, 3,316-claim and `2*B_touch+1`-transfer profile is historical.
This amendment adopts R1b MINOR-3 before any X4 code or proof.

### 0.1 Disposition and amended parameters

Each independently padded `2^30` embedding or unembedding tensor is split on
its highest Boolean variable into two ordered `2^29` physical blocks. If
`z = z_lo || z_hi`, coefficient order is `W_0 || W_1` and the normative
reconstruction identity is

```text
W_tilde(z_lo || z_hi)
  = (1-z_hi) * W_0_tilde(z_lo) + z_hi * W_1_tilde(z_lo).
```

The prefix bit, half ordinal and parent tensor id are statement data. A half
cannot be dropped, duplicated, reordered or substituted. No other gpt-oss
block changes shape.

The canonical padded orientation of both global matrices is vocabulary-major
`262,144 x 4,096`.  The split therefore produces two
`131,072 x 4,096 = 2^29` blocks per parent.  At the pinned logical vocabulary
201,088, half 0 has 131,072 source rows and half 1 has 70,016 source rows;
both have 131,072 padded rows.  Those logical/padded dimensions and the
parent ordinal are descriptor fields, so zero padding cannot be relabeled as
source data.

| Parameter | Amended `x4-zkdeepfold-ud-e29-v2` value |
| --- | ---: |
| PCS, evaluation and VOLE-MAC field | `E = F_p[phi]/(phi^2-7)` (`Fp2`) |
| symbol width | 16 bytes, two canonical little-endian Goldilocks limbs |
| code-field tower | none; `K` and `psi` are removed |
| original physical-block variables | `14 <= mu_b <= 29` |
| maximum extended weight domain | `2^(29+1)/(1/8) = 2^33` |
| `v2(|E|-1)` | `33`, exactly sufficient |
| Reed--Solomon rate `rho` | `1/8` |
| strict unique-decoding relation | distance `< (1-rho)/2 = 7/16`; equality is the far/reject branch |
| independent queries `s` | `128`, uniform with replacement from exact fresh bits |
| auxiliary variables | `ell_b = ceil(log2(s*mu_b^2+1)) <= 17` |
| algebraic ZK check | `2^17 = 131,072 > 128*29^2 = 107,648` |
| statistical target | at least `78.809294874` response-wide bits |
| hash assumption | BLAKE3 collision resistance/non-invertibility, separate from the statistical bound |

The maximum initial weight-codeword length is exactly `2^33`, so no
`F_p^4` tower is needed. The GKR claims, PCS arithmetic, mask, MAC transfer
and ZeroBatch all now live in the same field `E`. Limb decoding rejects
either base-field limb `>=p`; host, Montgomery and non-canonical encodings are
not transcript values.

The gpt-oss inventory becomes:

```text
per-layer physical blocks              = 69
layer physical blocks                  = 24*69 = 1,656
global physical blocks                 = 4  (two halves each for embed/unembed)
B_max                                  = 1,660
stacked phase claims, G_max            = 2*B_max = 3,320
expected analytic claims               = 3,314.06 + 4 = 3,318.06
```

The two extra physical blocks and four extra stacked claims are mandatory in
the communication formula. GPT-2 has no block above `2^26`, so its physical
block and 102-claim geometry is unchanged; it uses the amended field and
format without exercising the split.

For unpadded i16 source bytes `S`, the materialized first-oracle identity is

```text
F0(S) = S * 16/(1/8) = 128*S.
```

Thus the gpt-oss floor is **5.3504 TB** for `S=41.8 GB`, exactly half the
historical 10.7008-TB screen. For the measured GPT-2 source
`S=249,403,904 B`, it is **31,923,699,712 B** (31.924 GB, 29.731 GiB) before
block padding, auxiliary/fold oracles and Merkle nodes. The explicit random
extension alone is 334.4 GB at gpt-oss sizing; source plus random coefficients
is 376.2 GB before padding. Streaming changes peak memory, not these logical
volumes.

The optional `mu_shard<=25` transport hierarchy now splits each of the four
`mu=29` global halves into 16 shards. It still has 1,720 transport slots, but
the delta is now `+60` over 1,660 (`+3.614457831%`), not historical `+62` over
1,658. At amended `E`, rate `1/8`, a `mu=25` shard has an 8-GiB raw first
oracle. This hierarchy remains conditional and gives no soundness, byte or
storage credit until its separate shared-mask theorem is proved.

### 0.2 Cohorts, split claims and direct masked seam

Layer cohorts are unchanged. The global initial-weight cohort now has four
ordered `mu=29` slots: embedding half 0, embedding half 1, unembedding half
0, unembedding half 1. The same four-slot order is used for the auxiliary
cohort. At a queried outer coordinate the inner multiproof authenticates only
touched slots; the outer path authenticates the inner root. All four global
halves are normally touched, so splitting doubles slot count while halving
symbol width; the initial symbol payload is unchanged and the outer path is
one level shorter. Roots, descriptors and the two extra auxiliary polynomials
remain explicit overhead.

Each original global-tensor claim is deterministically expanded into two
half-claims, scaled by `(1-z_hi)` and `z_hi`, before the per-block blind claim
reduction challenge. For every physical block, at most two already-fixed
phase claims are reduced to one canonical point using the existing scalar
blind-sumcheck theorem. Claim order, split parent, point and scaling
coefficient are transcript-bound before the challenge.

For each touched physical block `b`, the commitment still contains `Wext_b`
and a one-use auxiliary polynomial `g_b`, now both over `E`. Define the same
canonical `u_b` and

```text
v_b = W_b_tilde(z_b)
s_b = g_b_tilde(u_b)
h_b = v_b + s_b in E.
```

Only `h_b` is public. The prover authenticates `s_b` with one ordinary full
`E` correlation. One response ZeroBatch checks
`v_b + s_b - h_b = 0` for every touched block. There is no tower
decomposition, no upper-component equation and no `psi`-free embedding trick:
the entire tower seam disappears. The exact PCS allocation is therefore

```text
B_touch mask transfers + 1 response ZeroBatch mask = B_touch + 1 full correlations.
```

At the all-touched gpt-oss point this is 1,661, versus 3,317 in the
superseded profile. The PCG generator, tuple, setup, spool, pool, reuse and
connection lifecycle remain untouched. The one-response-per-commitment-epoch
rule remains mandatory because `g_b` is a one-time evaluation pad.

### 0.3 Specialized unique-decoding soundness expression

DeepFold Theorem 2 states its finite-field term only as
`poly(|L0|)/|F|`; that asymptotic placeholder is not used as a number here.
The amended profile instead preregisters the following conservative explicit
VOLTA bound for proof in Lean. It specializes to the strict unique-decoding
relation, assigns no list-decoding credit, and deliberately unions over every
active weight/auxiliary polynomial even though the response uses a shared
envelope.

Let

```text
p       = 2^64 - 2^32 + 1 = 18,446,744,069,414,584,321
q       = |E| = p^2
        = 340,282,366,762,482,138,490,186,164,457,219,031,041
B       = 1,660                         maximum touched physical blocks
G       = 3,320                         maximum fixed GKR claims
P       = 2*B = 3,320                   Wext and g polynomials
mu      = 29
d       = mu+1 = 30                     maximum extended weight variables
ell     = 17
n_W     = 2^d/rho = 2^33                maximum weight first oracle
n_g     = 2^ell/rho = 2^20              maximum auxiliary first oracle
Delta   = 7/16                          strict-UD far-branch distance
s       = 128.
```

The named terms are

```text
epsilon_prox  = P * (1-Delta)^s
              = 3,320 * (9/16)^128

C_fold        = P * ((n_W-1) + (n_g-1))
              = 28,522,064,111,120

C_claim       = B * (G_per_block + 3*mu + 2),  G_per_block=2
              = 151,060

C_mpoint      = P + 3*d + 2
              = 3,412

C_M9          = B + 1
              = 1,661

C_total       = C_fold + C_claim + C_mpoint + C_M9
              = 28,522,064,267,253

epsilon_X4    = epsilon_prox + C_total/q.
```

`C_fold` is intentionally conservative: it charges a scalar-root event for
every active committed polynomial at every point in both complete geometric
fold chains. Hence it covers the cohort same-size combination and the
unique-decoding distance-preservation events without relying on the paper's
unspecified `poly`. `C_claim` is the existing scalar blind-sumcheck bound
`K + (sum d_i + n + 2)` with `K=2`, `sum d_i=2*mu` and `n=mu` for every
block. `C_mpoint` applies the same theorem once to the `P` fixed masked
weight/auxiliary evaluations at a common `d`-round point. `C_M9` is the
existing scalar ZeroBatch bound for `B` equations. Split reconstruction is
an exact linear identity and contributes no probabilistic term. Merkle/hash
binding is computational and is not disguised as a statistical summand.

Exact high-precision evaluation gives

```text
epsilon_prox  = 3.4420843757872683744986440971558333e-29
C_total/q     = 8.3818813588896498295265533026818019e-26
epsilon_X4    = 8.3853234432654370979010519467789577e-26
-log2(epsilon_X4)
              = 83.30226403378921 bits.
```

The exact rational inequality frozen for Lean is
`epsilon_X4 < 1/2^83`. It is stronger than the required
`78.809294874` bits by **4.49296915978921 bits** (the evaluated error is
22.5174 times below the target epsilon). Therefore `rho=1/8` and `s=128`
are retained; no further parameter amendment is needed. Failure to prove any
term with these coefficients triggers the preregistered hard stop. It may not
be replaced by the conjectural list-decoding radius or an unnamed
`poly(|L0|)` term.

The algebraic masked-sum hiding error is zero: at the fixed nonzero evaluation
functional, every `s in E` has exactly `q^(2^ell-1)` auxiliary coefficient
preimages, and translation by `v` preserves that count. Full transcript ZK
still requires the selected zkDeepFold simulator and the separate hash
assumption; neither is folded into `epsilon_X4`.

### 0.4 Normative frame grammar (N4(ii) and R1b NOTE-5)

The v2 grammar below is normative before implementation. No serializer may
add native padding, a map with unspecified iteration order, an untagged hash
input or an alternate integer representation.

Every frame is

```text
header = magic[8] || schema:u16 || kind:u8 || flags:u8 || body_len:u32
magic  = ASCII "VOLTAX42"
schema = 2
flags  = 0
frame  = header || body[body_len]
```

Integers are unsigned little-endian. A boolean is one byte (`0` or `1`). An
`E` symbol is exactly `c0:u64 || c1:u64`, with both limbs `<p`. A digest is
32 bytes. A vector is `count:u32` followed by exactly `count` canonical
items. Decoders reject unknown enum values, nonzero reserved/flag bits,
overflow, duplicate or unsorted set entries, a length mismatch and trailing
bytes. Text strings never occur on wire; static names are represented by
pinned numeric ids or 32-byte digests. `profile_digest` is exactly the
ordinary 32-byte BLAKE3 digest of the ASCII bytes
`x4-zkdeepfold-ud-e29-v2` (no NUL or length prefix). A nested `*_frame` is a
complete canonical frame including its 16-byte header, and the enclosing
`body_len` includes every nested byte.

| `kind` | value | body (in exact order) |
| --- | ---: | --- |
| descriptor | `0x01` | `profile_digest, model_config_digest, weights_digest, namespace_kind:u8, namespace_index:u8, tensor_id:u16, block_kind:u8, block_ordinal:u16, split_prefix:u8, mu:u8, ell:u8, rate_log2:u8, source_rows:u32, source_cols:u32, padded_rows:u32, padded_cols:u32, logical_coeffs:u64, padded_coeffs:u64, cohort_id:u32, slot:u16, slot_count:u16, n_W:u64, n_g:u64, transfer_template_digest` |
| PCS leaf | `0x02` | common prefix `cohort_id:u32, tree_role:u8, oracle_kind:u8, fold_round:u8, outer_index:u64`; if `tree_role=inner`: `descriptor_digest, slot:u16, present:u8, symbol_count:u16, symbols`; if `tree_role=outer`: `inner_root_digest` |
| PCS node | `0x03` | `cohort_id:u32, tree_role:u8, oracle_kind:u8, fold_round:u8, outer_index:u64, level:u8, node_index:u64, left_digest, right_digest` |
| manifest leaf | `0x04` | `descriptor_digest, root_count:u16, ordered_roots` |
| manifest node | `0x05` | `manifest_id_digest, level:u8, node_index:u64, left_digest, right_digest` |
| cohort multiproof | `0x06` | `cohort_id:u32, oracle_kind:u8, fold_round:u8, query_count:u16, sorted_outer_indices, touched_slot_count:u16, sorted_touched_slots, opened_leaf_count:u32, ordered_opened_leaf_frames, aux_node_count:u32, sorted(tree_role,outer_index,level,index,digest)` |
| response envelope | `0x07` | `profile_digest, model_root, epoch:u64, descriptor_count:u16, ordered_descriptor_digests, manifest_frame_count:u32, ordered_manifest_frames, claim_count:u32, ordered_claim_frames, masked_count:u16, ordered_h_symbols, fold_frame_count:u32, ordered_fold_frames, query_frame_count:u32, ordered_query_frames, m9_frame_count:u16, ordered_m9_frames, zero_batch_frame` |
| reduced claim | `0x08` | `descriptor_digest, parent_claim_digest, phase:u8, phase_ordinal:u16, point_len:u8, point_symbols, affine_scale, auth_domain:u64` |
| fold commitment | `0x09` | `cohort_id:u32, oracle_kind:u8, fold_round:u8, input_log2:u8, output_log2:u8, root_digest, message_symbol_count:u16, ordered_message_symbols` |
| M9 transfer | `0x0a` | `descriptor_digest, mask_correction_symbol` |
| response ZeroBatch | `0x0b` | `claim_count:u16, mask_correction_symbol, opened_tag_symbol` |

`namespace_kind` is `0=global, 1=layer`; `namespace_index` is `255` for the
global namespace and `0..23` for a layer namespace. `block_kind` is
`0=fixed, 1=attn_q, 2=attn_k, 3=attn_v, 4=attn_o, 5=router,
6=expert_gate_up, 7=expert_down, 8=embedding_half,
9=unembedding_half`. `split_prefix` is `0/1` for a split half and `255` for
unsplit. `tree_role` is `0=inner, 1=outer`.
`oracle_kind` is `0=Wext, 1=aux`; `fold_round=0` denotes the first oracle.
`phase` is `0=prefill, 1=decode`.  Inner absent slots have `present=0`,
`symbol_count=0` and no symbol bytes; present inner PCS leaves require the
descriptor-pinned symbol count. Outer PCS leaves carry exactly one inner-root
digest and no descriptor/slot/symbol branch. For an inner node,
`outer_index` identifies that inner tree; for an outer node it is exactly
`u64::MAX`. A reduced claim contains metadata only: `auth_domain` identifies
the already-authenticated GKR claim, and no cleartext weight evaluation or
digest of one is serialized. Its `point_len` is descriptor `mu`, and split
sibling claims have the same parent/phase/ordinal with the two pinned affine
scales. Multiproof outer indices and slots are strictly increasing. Opened
leaf frames are strictly ordered by `(outer_index, outer-before-inner, slot)`;
auxiliary nodes are strictly ordered by their complete tuple. The query
indices and all expected leaf/fold symbol counts are derived from the profile
and descriptors; a merely self-consistent alternate count is rejected.

Every admitted descriptor has `rate_log2=3`, `14<=mu<=29`,
`padded_coeffs=2^mu`, `logical_coeffs<=padded_coeffs`,
`ell=ceil(log2(128*mu^2+1))`, `n_W=2^(mu+4)` and `n_g=2^(ell+3)`.
Its source/padded axis products must equal the corresponding coefficient
counts.  These equalities are checked with overflow-safe integer arithmetic;
they are not trusted fields.

Within a response envelope, manifest frames are only kinds `0x04/0x05`,
claim frames are only `0x08`, fold frames only `0x09`, query frames only
`0x06`, M9 frames only `0x0a`, and the final frame is exactly one `0x0b`.
The ordered M9 transfers and earlier `h` vector have identical descriptor
order and count; an `h` symbol is serialized only in that earlier vector.
`claim_count<=3320`, `masked_count=m9_frame_count<=1660`, and the
ZeroBatch `claim_count` equals that same masked count. Every other count must
equal the descriptor/profile-derived schedule, not merely fit its integer
width.

Typed hashing uses BLAKE3 derive-key mode with the v2 contexts

```text
volta-zk/x4/descriptor/v2
volta-zk/x4/pcs-leaf/v2
volta-zk/x4/pcs-node/v2
volta-zk/x4/manifest-leaf/v2
volta-zk/x4/manifest-node/v2
volta-zk/x4/manifest-id/v2
volta-zk/x4/transfer-template/v2
```

Descriptor, PCS-leaf/node and manifest-leaf/node hashes take the complete
canonical frame as input. `descriptor_digest` is therefore the descriptor-
context hash of the complete descriptor frame. `manifest_id_digest` is the
manifest-id-context hash of
`profile_digest || model_config_digest || weights_digest || epoch:u64`.
`transfer_template_digest` is the transfer-template-context hash of
`count:u16 || ordered_domain_ids:u64`; these ids are strictly increasing and
the implementation must reproduce that exact list before consuming a
correlation. All other named digests are either the corresponding canonical
Merkle-frame hashes above or statement inputs already defined by the model
profile; no generic untyped hash is accepted in their place.

The transcript fixes model root, epoch, descriptors, ordered claims and every
public `h_b` before any claim-reduction, cohort-combination, fold or query
challenge. Fold commitments precede exact-bit query sampling; answers and
canonical multiproofs precede M9 corrections and the single response
ZeroBatch. EOF/truncation remains a deployment-channel boundary, but any
malformed in-process frame is a verifier rejection. The grammar itself is a
G2 test oracle; all N4 leaf/node/type/depth/index substitutions remain
mandatory permanent rejects.

The live designated-verifier protocol emits and consumes the child frames at
those challenge boundaries. The response envelope is the canonical packed
record assembled from that already ordered interaction; it neither sends
future prover messages before verifier challenges nor applies Fiat--Shamir.
Its decoder replays and checks the same child-frame order and transcript
digest before accepting the packed artifact.

### 0.5 Final pre-code Lean statement freeze

The following are proposition shapes, not proofs or new axioms. Definitional
scaffolding may add namespaces and implicit arguments, but theorem names,
quantifier order, hypotheses, conclusions and numeric coefficients may not be
weakened without a new ledger amendment. Every theorem enters
`lean/Audit.lean` before Rust.

```lean
-- Concrete amended field and domain facts; no tower field is admitted.
theorem goldilocks_fp2_card :
    Fintype.card E =
      340282366762482138490186164457219031041

theorem goldilocks_fp2_two_adicity :
    2^33 ∣ (Fintype.card E - 1) ∧
      ¬ 2^34 ∣ (Fintype.card E - 1)

theorem goldilocks_fp2_domain_root
    (hlog : logN <= 33) :
    ∃ omega : E, orderOf omega = 2^logN

-- The strict radius, not a list-decoding conjecture, gives uniqueness.
theorem rs_rate_eighth_unique_decode
    (hc0 : RSCodeword E (1/8) c0)
    (hc1 : RSCodeword E (1/8) c1)
    (h0 : relativeDistance received c0 < 7/16)
    (h1 : relativeDistance received c1 < 7/16) :
    c0 = c1

-- Split geometry; the highest Boolean variable selects the canonical half.
theorem split_block_eval
    (W0 W1 : (Fin (2^mu) -> E)) (z : Fin mu -> E) (hi : E) :
    mle (W0 ++ W1) (snoc z hi) =
      (1 - hi) * mle W0 z + hi * mle W1 z

-- Direct-field masked relation (no E -> K embedding and no tower component).
theorem masked_aux_eval
    (hWext : Wext (snoc z 0) = W z)
    (hs : s = mle g (auxPoint z ell))
    (hh : h = W z + s) :
    h = Wext (snoc z 0) + mle g (auxPoint z ell)

-- Equal-size fibers for the published masked value.
theorem masked_aux_hiding_count
    [Fintype E] [Field E] (hell : 0 < ell)
    (z : Fin ell -> E) (hfunc : EvalFunctionalNonzero z) (v h : E) :
    Fintype.card {g : (Fin (2^ell) -> E) // h = v + mle g (auxPoint z ell)} =
      Fintype.card E ^ (2^ell - 1)

theorem one_opening_per_epoch
    (hfirst : acceptOpening st epoch transcript1 = some st1)
    (hsecond : acceptOpening st1 epoch transcript2 = some st2) :
    False

theorem masked_aux_perfect_zk
    (hone : OneOpeningPerEpoch epoch transcript)
    (hpaper : ZkDeepFoldSimulator E params)
    (hframes : NoIndividualEvalFields transcript) :
    RealMaskedTranscript E params epoch =
      SimMaskedTranscript E params epoch publicH

-- Canonical v2 grammar and N4-separated Merkle/cohort binding.
theorem x4_frame_decode_encode (f : X4FrameV2) :
    decodeX4FrameV2 (encodeX4FrameV2 f) = some f

theorem x4_frame_decode_canonical
    (h : decodeX4FrameV2 bytes = some f) :
    encodeX4FrameV2 f = bytes

theorem x4_frame_kind_encoding_disjoint
    (a b : X4FrameV2) (hkind : a.kind ≠ b.kind) :
    encodeX4FrameV2 a ≠ encodeX4FrameV2 b

theorem cohort_opening_binding
    (hhash : CollisionFreeOn X4V2Hash committedFrames)
    (ha : VerifyCohortOpening root descriptor point slot openA)
    (hb : VerifyCohortOpening root descriptor point slot openB) :
    openA.symbols = openB.symbols

-- At most two fixed phase claims per physical block, common-point scalar M3.
theorem blind_claim_reduce_sound
    (hfixed : ClaimsFixedBeforeChallenge claims)
    (hcount : claims.length <= 2) (hmu : mu <= 29) :
    badTapeCard (BlindClaimReduce claims) <=
      (claims.length + 3*mu + 2) * fieldTapeCard E

-- Different-point Wext/aux claims; no cross-point naive RLC.
theorem folding_different_point_batch_sound
    (hfixed : MaskedClaimsFixed claims) (hP : claims.length <= 3320)
    (hcommon : HasCommonPoint schedule) (hd : rounds <= 30) :
    badTapeCard (DifferentPointBatch claims schedule) <=
      (claims.length + 3*rounds + 2) * fieldTapeCard E

-- Strict unique decoding plus conservative cohort/fold accounting.
theorem ud_cohort_folding_sound
    (hUD : RSEighthStrictUniqueDecode E)
    (hsample : ExactUniformQueriesWithReplacement params 128)
    (hbranch : WrongCandidateIsAtDistanceAtLeast params (7/16))
    (hP : activePolys <= 3320)
    (hnW : weightOracleLength <= 2^33)
    (hng : auxOracleLength <= 2^20) :
    statisticalError (UDFoldingCohorts params) <=
      activePolys * (9/16)^128 +
      activePolys * ((2^33 - 1) + (2^20 - 1)) / Fintype.card E

-- Concrete PCS binding is separate from ZK and batching.
theorem x4_ud_pcs_binding
    (hframe : CanonicalCohortLayoutV2 statement)
    (hmerkle : CollisionFreeOn X4V2Hash committedFrames)
    (hud : UDFoldingAccepts statement proof) :
    BoundToUniqueCommittedBlocks statement proof

theorem x4_masked_zk
    (hcount : MaskedAuxEqualFiberCounts statement)
    (hone : OneOpeningPerEpoch epoch transcript)
    (hpaper : ZkDeepFoldSimulator E params)
    (hframes : NoIndividualEvalFields transcript) :
    X4WeightOpeningZK statement transcript

theorem x4_batch_sound
    (hfixed : MaskedClaimsFixed claims)
    (horder : CanonicalClaimOrder claims)
    (hcommon : HasCommonPoint schedule)
    (hreduce : FoldingDifferentPointBatchBound claims schedule) :
    X4WeightBatchSound claims schedule

-- One E-valued mask transfer and one response scalar ZeroBatch.
theorem direct_mask_transfer
    (hs : Valid (authS : Authed E))
    (hz : Valid (authV + authS - authPublic h)) :
    authV.x = h - authS.x

def MaskedBatchBindsIntoMac [Fintype Omega]
    (P : MaskedBatchOpening E Omega)
    (epsPCS : Nat) : Prop :=
  Fintype.card {omega : Omega //
    P.accepts omega ∧ P.committedEvalWrong omega} <= epsPCS

theorem masked_batch_opening_mac_sound
    (hbind : MaskedBatchBindsIntoMac P epsPCS)
    (hB : touchedBlocks <= 1660) :
    statisticalError (P.acceptsAndTransfersWrong touchedBlocks) <=
      epsPCS / Fintype.card Omega +
      (touchedBlocks + 1) / Fintype.card E

theorem masked_batch_transfers_evals
    (hgood : P.accepts omega)
    (hnotbad : ¬ P.committedEvalWrong omega)
    (hzero : ResponseZeroBatchAccepts P omega) :
    ∀ b : TouchedBlock P,
      ValidCommittedAuthEval P b omega

-- Full response theorem and exact rational stop rule.
def x4ResponseError : Rat :=
  (3320 : Rat) * ((9 : Rat) / 16)^128 +
  (28522064267253 : Rat) /
    (340282366762482138490186164457219031041 : Rat)

theorem x4_wrong_response_event_cover
    (hframes : CanonicalFramesAndOrderV2 statement proof)
    (hhash : CollisionFreeOn X4V2Hash committedFrames)
    (hcohort : CohortOpeningsBind statement proof)
    (hpcs : BoundToUniqueCommittedBlocks statement proof)
    (htransfer : MaskedM9TransfersAllTouchedEvals statement proof) :
    X4WrongResponseCoveredByNamedEvents statement proof

theorem x4_response_soundness
    (hcover : X4WrongResponseCoveredByNamedEvents statement proof)
    (hfold : statisticalError (X4FoldBad statement proof) <=
      (3320 : Rat) * ((9 : Rat) / 16)^128 +
      (28522064111120 : Rat) /
        (340282366762482138490186164457219031041 : Rat))
    (hclaim : statisticalError (X4ClaimReduceBad statement proof) <=
      (151060 : Rat) /
        (340282366762482138490186164457219031041 : Rat))
    (hbatch : statisticalError (X4DifferentPointBatchBad statement proof) <=
      (3412 : Rat) /
        (340282366762482138490186164457219031041 : Rat))
    (hm9 : statisticalError (X4M9Bad statement proof) <=
      (1661 : Rat) /
        (340282366762482138490186164457219031041 : Rat)) :
    statisticalError (X4AcceptsWrongResponse statement proof) <=
      x4ResponseError

theorem x4_response_error_lt_two_pow_neg_83 :
    x4ResponseError < (1 : Rat) / 2^83

theorem x4_response_error_meets_registered_target :
    ((x4ResponseError : Rat) : Real) <
      Real.rpow 2 (-((78809294874 : Real) / 1000000000))
```

MINOR-1 and MINOR-2 are **DISCHARGE-TIME constraints**, not permission to
keep a bundled PCS theorem or assume an unrealized UC functionality.  The
current Ligero boundary and the new X4 boundary each require three separately
audited results; UC composition separately requires both ideal-functionality
realizations:

```lean
theorem ligero_binding_discharge
    (h : LigeroCommitmentBinding implementedLigeroParams) :
    CurrentWeightCommitmentBinding

theorem ligero_blinded_zk_discharge
    (hmask : VoltaLigeroMaskSimulator implementedLigeroParams) :
    CurrentWeightOpeningZK

theorem ligero_multi_point_batch_discharge
    (hfixed : ClaimsFixedBeforeChallenge claims)
    (hcommon : HasCommonPoint schedule) :
    CurrentWeightBatchSound claims schedule

theorem uc_composition_of_realizations
    (hsvole : UCRealizes PiSVOLE FSVOLE)
    (hpcs : UCRealizes PiPCS FPCS)
    (hhybrid : UCHybridRealizes PiVOLTA FVDec FSVOLE FPCS) :
    UCRealizes (compose PiVOLTA PiSVOLE PiPCS) FVDec

theorem logup_gkr_sound_of_char_gt
    [Field F] {p lookupCount : Nat} [Fact (Nat.Prime p)] [CharP F p]
    (hchar : lookupCount < p)
    (hlogup : LogUpSoundAtCount F lookupCount)
    (hgkr : FractionalGKRCompositionSound F lookupCount)
    (hmac : AuthenticatedTranscriptSound F) :
    LogUpGKRSoundAtCount F lookupCount
```

Citation ownership is also frozen and may not be bundled:

| Obligation | Required source/reduction |
| --- | --- |
| current Ligero binding/proximity | Ligero, CCS 2017 / extended IACR ePrint 2022/1608, specialized to the implemented code and Merkle layout |
| current VOLTA-Ligero blinded ZK | the system-specific mask-row simulator and exposure count; Ligero is background, not a substitute for this theorem |
| current multi-point batch | the repository's scalar blind-sumcheck/common-point reduction; no citation licenses naive cross-point RLC |
| X4 unique-decoding binding | BaseFold, IACR ePrint 2023/1705, plus the explicit cohort-layout reduction above |
| X4 different-size/different-point batch | DeepFold Section 5.1 and Appendix D, IACR ePrint 2024/1595, plus the fixed-order VOLTA reduction |
| X4 ZK | DeepFold Section 5.2, Theorem 3 and Appendix E, plus `masked_aux_hiding_count` and the one-opening epoch theorem |
| LogUp | Haboeck, ePrint 2022/1530; Papini--Haboeck, ePrint 2023/1284, is an informal GKR note; the VOLE-MAC composition is repository-specific and must retain `lookupCount < char(F)` |
| UC | Canetti composition only after explicit `F_sVOLE` and `F_PCS` realizations; Ligero/BaseFold/DeepFold do not by citation alone provide the latter |

### 0.6 Gates, migration and scheduled preflight delta

G1--G6, the `<=4,000,000 B` GPT-2 PCS gate, the absolute
`<=45,270,464 B` response gate, the `<=35,000,000 B` gpt-oss analytic gate,
all CPU/A100 wall ceilings and all inherited pod gates remain verbatim. Their
closed formulas must use `B_max=1,660`, `G_max=3,320`, 16-byte `E` symbols,
the four global blocks, `B_touch+1` M9 transfers and v2 frame bytes. Storage
does not net against communication.

The next pod session's preflight must run the production-size
`c3_weights` leakage smoke that R1b could not execute on the 11-GB review
host. Its command, peak RSS/VRAM, exit status and leakage verdict are recorded
before any X4 GPT-2 commit/opening run. It is a mandatory provenance smoke,
not retrospective independent review assurance.

The amended phase order is:

```text
Amendment 1 + expression + final Lean statements (this section) -> HARD STOP
after explicit approval: Lean proofs/audit -> checkpoint -> HARD STOP if any statement fails
after later authority: normative-v2 implementation and CPU synthetic records
then stop for A100 pod provisioning before GPT-2 records
```

No Lean proof, Rust X4 implementation, benchmark/reference mutation or X5
work is authorized by this amendment.

### 0.7 Amendment 2: direct-mask good-tape premise (normative override)

On 2026-07-21, before any repository Lean proof or X4 Rust code, the product
owner approved this explicit theorem-statement correction.  The Amendment 1
shape used `Authed.Valid` alone for the purported response ZeroBatch premise:

```lean
(hz : Valid (authV + authS - authPublic h))
```

That proposition is false as a sufficient premise for the stated transfer.
In the existing formal model, `Authed.Valid Delta a` means only
`a.k = a.m + Delta*a.x`; it does not say `a.x=0`.  The generic-field
counterexample is `authS=0`, `authV=authPublic 1`, `h=0`: both MAC-validity
premises hold, while the conclusion would be `1=0`.  A scratch Lean proof of
this counterexample was checked before this amendment, and no repository file
was changed during the hard stop.

The normative predicate and replacement theorem are therefore:

```lean
def ResponseZeroBatchValid (Delta : E) (a : Authed E) : Prop :=
  a.Valid Delta /\ a.x = 0

theorem direct_mask_transfer
    (hs : authS.Valid Delta)
    (hz : ResponseZeroBatchValid Delta
      (authV + authS - Authed.ofPublic Delta h)) :
    authV.x = h - authS.x
```

`ResponseZeroBatchValid` is the deterministic good-tape condition used by
the transfer/completeness lemma.  It must not be confused with bare verifier
acceptance on an adversarial tape.  `masked_batch_opening_mac_sound` separately
bounds accepted bad tapes with the existing scalar ZeroBatch theorem, while
`masked_batch_transfers_evals` may invoke `direct_mask_transfer` only after its
good-tape hypotheses establish this predicate.  Thus the correction adds the
missing zero-plaintext fact; it does not weaken the conclusion, assume away a
soundness event or introduce an ideal axiom.

No field, rate, query count, block/claim geometry, frame byte, correlation
allocation or soundness coefficient changes.  In particular `C_M9=B+1=1661`,
`C_total=28,522,064,267,253`, `x4ResponseError`, the exact `<2^-83` stop rule
and the evaluated **83.30226403378921-bit** bound remain unchanged.

The product owner's 2026-07-20 Phase-2 approval and 2026-07-21 Amendment-2
approval authorize the following existing order: prove and audit every named
Lean theorem, checkpoint, then implement the normative v2 grammar and X4
protocol, then produce CPU synthetic records.  Any other unprovable frozen
statement still triggers an immediate hard stop without weakening or axiom
smuggling.  After the CPU records, work stops for provisioning of the pinned
A100 pod before the production-size `c3_weights` preflight and GPT-2 records.

### 0.8 Implementation clarification I1: aggregate-fold and query-set semantics

This clarification was registered on 2026-07-21 after the Lean checkpoint and
before the affected Rust folding code.  It fills two schedule details already
represented by the frozen v2 fields; it changes no frame byte, field, rate,
query count, block/claim geometry, soundness coefficient, allocation or gate.

`fold_round=0` is the static first oracle with the descriptor-pinned cohort
slots.  Once the transcript-bound same-size challenge combines the touched
slots, each `fold_round>=1` oracle is the one shared aggregate for that cohort.
Its inner tree has exactly one structural slot, numbered zero and carrying the
cohort's canonical slot-zero descriptor digest; that digest is an identity
anchor, not a claim that the aggregate is slot zero's polynomial.  The
verifier first recomputes the aggregate at every queried round-zero coordinate
from all touched leaf symbols and only then accepts the transition to this
singleton oracle.  Changing the touched descriptor order, challenge, cohort,
oracle kind or round therefore changes the checked relation or root.

For a transition from round `i-1` to `i`, the `fold commitment` has
`fold_round=i`, commits the output oracle root, and its ordered message symbols
are the two values of the parallel multilinear claim-reduction line.  The last
transition additionally appends the final scalar.  The rate-`1/8` final
constant codeword has length eight and remains committed and queried; all its
opened symbols must equal that final scalar.  This deliberately explicit last
root costs bytes but avoids an untyped sentinel root.

The verifier still samples exactly `s=128` indices independently with
replacement from exact fresh bits.  Transcript replay retains that ordered
128-element multiset.  Each round's canonical `cohort multiproof` serializes
only the strictly increasing deduplicated set of all `+beta`/`-beta` positions
derived from it (and the correspondingly squared positions in later rounds).
The decoder recomputes that set from the retained multiset; `query_count` is
therefore the number of distinct opened outer indices, not a replacement for
the fixed 128-draw schedule.  Multiplicity still counts in every folding-line
check and in the registered soundness expression; deduplication is only Merkle
authentication compression.

### 0.9 Phase-2 implementation hard stop: auxiliary-to-MAC link is missing

**Status: OPEN SOUNDNESS OBSTRUCTION; no M9 implementation, CPU gate record,
GPT-2 migration or pod run is authorized until an explicit product-owner
amendment supplies and proves a concrete link.**

During the concrete discharge of `MaskedBatchBindsIntoMac`, before writing the
X4 M9 Rust path, the following one-block counterexample was found and checked
by Lean's kernel over `Rat`:

```text
committed W evaluation w = 3
committed auxiliary evaluation g = 5
public masked value       h = w + g = 8
wrong downstream claim    v = 4
prover-chosen MAC value    s = h - v = 4
```

For any MAC key the ordinary full correlation can authenticate the
prover-chosen `s`.  Here the PCS masked-sum relation `h=w+g` holds and the
Amendment-2 residual `v+s-h` is both MAC-valid and zero, yet
`h-s=4 != w=3` and `s=4 != g=5`.  Thus a malicious prover can compensate an
arbitrary wrong downstream weight claim by changing the plaintext carried by
the one scalar mask transfer.  The attack is deterministic; it is not covered
by the registered `1/|E|` ZeroBatch term.

The frozen Lean theorems are not inconsistent.  They deliberately take
`MaskedBatchBindsIntoMac` / `not committedEvalWrong` as explicit premises.
The counterexample proves that the currently specified public relation plus
one ordinary scalar correlation cannot discharge those premises.  In
particular, naming the MAC plaintext `s_b` does not prove that it equals the
committed `g_b(u_b)`.  The R1b report's design-level sentence that the two are
bound is therefore overturned by concrete discharge evidence; its honest
AI/no-independent-assurance label remains material.

Any repair must add a concrete zero-knowledge binding argument from the
committed auxiliary evaluation to the MAC-authenticated plaintext.  Revealing
`s` is forbidden because it reveals `v=h-s`; asserting witness equality,
adding an ideal axiom, reusing the same masked-sum equation, or silently
charging extra correlations is not a repair.  A candidate authenticated-output
PCS, vector-authenticated auxiliary commitment, or other construction changes
the seam and potentially the frame bytes, correlation allocation,
communication and soundness expression.  It therefore requires a new
append-only amendment and Lean-first theorem set before implementation resumes.

The already implemented canonical v2 codec, N4 cohort Merkle tree, `E` NTT and
public strict-UD folding core remain diagnostic partial work only.  They confer
no X4 gate verdict and are not wired into the production response path.

---

## Historical Phase-1 baseline (superseded where Section 0 conflicts)

## 1. Decision and primary sources

X4 selects **zkDeepFold-UD**: the zkDeepFold protocol and batching layer,
specialized back to a proved unique-decoding radius instead of relying on
DeepFold's conjectural list-decoding radius. It is a BaseFold-family
Reed--Solomon multilinear PCS. It is selected because it has:

- a field-agnostic BaseFold commitment with linear/quasilinear prover work
  and polylogarithmic proof and verifier work;
- a published batch construction for different-sized polynomials and an
  explicit reduction for evaluations at different points; and
- an explicit statistical zero-knowledge layer rather than an assumed
  hiding wrapper.

The normative cryptographic references are:

1. [BaseFold: Efficient Field-Agnostic Polynomial Commitment Schemes from
   Foldable Codes](https://eprint.iacr.org/2023/1705), IACR ePrint
   2023/1705 (CRYPTO 2024). BaseFold supplies the field-agnostic multilinear
   PCS and the folding/proximity architecture.
2. [DeepFold: Efficient Multilinear Polynomial Commitment from Reed--Solomon
   Code and Its Application to Zero-knowledge
   Proofs](https://eprint.iacr.org/2024/1595), IACR ePrint 2024/1595, and the
   [published USENIX Security 2025
   version](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei).
   DeepFold supplies different-size batching, the different-point reduction
   and Section 5.2's `zkDeepFold` construction.
3. [Zero-Knowledge BaseFold Polynomial Commitments over Binary
   Fields](https://eprint.iacr.org/2025/1015), IACR ePrint 2025/1015, is
   corroborating work on BaseFold-family zero knowledge. It is not the
   selected instantiation because VOLTA's authenticated-value seam is over
   the Goldilocks extension, not a binary field.

[BrakingBase](https://eprint.iacr.org/2024/1825) is not selected. It has an
attractive linear-prover/polylog-verifier profile, but its stated scope does
not provide the zero-knowledge layer required for private weights. X4 will
not manufacture that missing property from an informal mask.

The references are protocol specifications, not implementation assurance.
Their external security claims remain assumptions until the exact selected
theorems and parameter arithmetic have been checked against the implementation
and connected to VOLTA's M9 seam.
The unique-decoding specialization, cohort Merkle layout and masked-sum
public relation are VOLTA adaptations, not claims copied from the paper;
Phase 2 must prove their reductions before any implementation authority.

### 1.1 Pinned conservative parameter screen

The initial profile is:

| Parameter | `x4-zkdeepfold-v1` value |
| --- | ---: |
| authenticated/evaluation field | `E = F_p[phi]/(phi^2-7)` (current `Fp2`) |
| PCS code/folding field | `K = E[psi]/(psi^2-phi)` (`F_p4`) |
| original block-variable range | `14 <= mu_b <= 30` |
| maximum original block variables `mu` | `30` |
| maximum extended RS domain | `2^(mu+1)/rho = 2^34` |
| Reed--Solomon rate `rho` | `1/8` |
| distance credited without a conjecture | unique-decoding radius `(1-rho)/2 = 7/16` |
| independent proximity queries `s` | `128` |
| ZK auxiliary variables | `ell_b = ceil(log2(s*mu_b^2 + 1))`, at most `17` |
| query term used in the screen | `(9/16)^128 = 1.0367724023455627e-32` |
| query-term bits | `106.24959981538402` |
| response-wide statistical target | at least `78.809294874` bits |
| hash | BLAKE3, computational binding accounted separately |

Here `phi` is a nonsquare in `E` because its norm is `-7`, a nonsquare in
`F_p`; the tower is therefore a field. Moreover,
`v2(|K|-1) = v2(p-1)+v2(p+1)+v2(p^2+1) = 32+1+1 = 34`, so the maximum
`2^34` multiplicative domain exists. The largest gpt-oss logical block has
`mu=30`; zkDeepFold's one-variable random extension makes it 31-variate and
rate `1/8` makes the first codeword length `2^34`. These identities are
pre-code unit and proof obligations, not assumptions to skip in Rust.

The GKR and VOLE-MAC boundary stays in `E`. Weight coefficients and the
opening point lie in `E` and are embedded canonically into `K`; all internal
RS, folding and PCS challenges lie in `K`. The public masked value is
canonically decomposed into two `E` tower components; two ordinary `E` MAC
transfers and the response ZeroBatch connect those components to the GKR
claim. This adds no `K`-valued PCG correlation.

Canonical `K` wire order is `(k0.c0, k0.c1, k1.c0, k1.c1)` for
`k0 + psi*k1`, four canonical little-endian Goldilocks limbs and exactly 32
bytes. Decoding rejects every limb `>=p`; no Montgomery or host-native
representation is transcript data.

All FRI/PCS query domains have power-of-two length. Query indices are sampled
uniformly with replacement from exactly the required number of fresh
verifier bits under the X4 transcript domain; they are not obtained by field-
element modulo reduction. Thus the historical Ligero modulo-bias boundary is
not inherited by the new profile.

The widely advertised small-query DeepFold figures use a conjectural
Reed--Solomon list-decoding radius. They are **not** a VOLTA input and no gate
or projection may quote the paper's approximately 34-query/304-KB point as a
VOLTA result. Before code, the complete published soundness expression must
be specialized to the unique-decoding regime and instantiated for `K`, the
maximum batch and all union terms. The blind-reduction, MAC and ZeroBatch
terms remain over `E`. Their response-wide composition must
meet the response-wide target corresponding to the current pinned Ligero
level (`1.8881578818430648e-24`, or `78.809294874` bits), in addition to the
separately stated BLAKE3 assumption. If `rho=1/8, s=128` does not do so under
the proved expression, X4 stops and preregisters a new profile; it does not
silently increase `s` after a benchmark.

The profile uses the paper's statistical ZK construction: extend each
committed multilinear coefficient vector by an equal-size random vector in
one extra Boolean variable, and commit to the auxiliary small random
multilinear polynomial required by `zkDeepFold`. For a `mu_b`-variate block,
the paper requires `2^ell_b > s*mu_b^2`; the deterministic formula in the
table gives `ell_b <=17` because
`2^17=131,072 >128*30^2=115,200`. The resulting ZK epsilon is part of the
pre-code security-arithmetic checkpoint.

## 2. Object being committed

X4 retains D3: one commitment namespace per transformer layer, plus a global
namespace, with independently openable blocks inside each namespace. It does
**not** create one public commitment per expert and does not return to a
whole-model monolith.

For every logical block `b`, the canonical descriptor fixes:

- profile/version, model-config digest and weights digest;
- layer/global namespace, block kind and block ordinal;
- logical tensor name, dimensions, row-major coefficient order and padding;
- source quantization type and the deterministic injections into `E` and `K`;
- logical and padded coefficient counts, code rate and oracle lengths;
- the auxiliary-mask and M9 transfer-domain template (never a live
  correlation value); and
- every static extension/auxiliary cohort root and the outer-manifest
  position.

The descriptor is statement data. A prover cannot choose it after seeing a
challenge. Shape validation, disjointness, exact coverage, zero padding and
integer-to-field conversion are checked before transcript consumption.
Tensors smaller than `2^14` coefficients are canonically co-packed into their
layer's fixed block or zero-padded to `mu_b=14`; no standalone smaller block
is allowed. This keeps `ell_b <= mu_b+1`, as required by the auxiliary-point
construction.

### 2.1 Block geometry

The gpt-oss sizing case has 24 layer namespaces and one global namespace. The
canonical analytic block inventory is:

- per layer: four attention blocks, one router block, and two blocks for each
  of 32 experts (aligned gate/up and down), hence `4 + 1 + 2*32 = 69`;
- global: embedding and unembedding, hence two blocks;
- total physical independently openable blocks:
  `24*69 + 2 = 1,658`; and
- at most two stacked phase claims per physical block, hence `3,316` claims.

The pinned sizing geometry has `d=2,880`, expert width `2,880` and vocabulary
`201,088`. The aligned gate/up expert block is at most
`4,096*8,192 = 2^25` coefficients. Each global embedding/unembedding block is
`262,144*4,096 = 2^30` after independent axis padding, establishing the
profile's `mu_max=30`. GPT-2's corresponding largest padded block is at most
`2^26`, so it exercises the same format without setting the field/domain cap.

For the 100-prefill + 50-decode analytic workload the existing expected
claim count is `3,314.06`, almost the maximum. X4 therefore claims no useful
expert-sparsity wall-time reduction for that workload. Block openability is a
communication and proportionality property; the workload may touch nearly
all expert blocks across its many tokens.

GPT-2 is the migration and measured validation case. It retains the existing
13 namespace roots and the existing 96-prefill + 6-decode claim geometry,
but receives new X4 block descriptors and new roots. Equality is required for
semantic weight evaluations and all downstream proof claims, not for the
commitment bytes.

### 2.2 Cohort commitment and one response envelope

X4 logically commits each block separately but physically shares Merkle
authentication within a layer. Blocks are partitioned by namespace, oracle
kind and padded variable count into canonical cohorts. For every codeword
coordinate in a cohort, an inner Merkle tree commits the ordered block-slot
symbols; an outer Merkle tree commits the ordered inner roots across codeword
coordinates. The cohort roots and exact block descriptors are leaves of the
layer manifest. The 24 layer manifests and one global manifest are then
leaves of one model manifest.

This two-dimensional layout is part of the PCS, not an accounting trick. At
one queried codeword coordinate, touched blocks reveal their `K` symbols with
one canonical inner multiproof and one outer path. Unopened block symbols are
not sent. An absent block slot has a distinct canonical leaf and cannot be
shifted or substituted. Hash binding of the cohort tree binds every member
codeword; the pre-code concrete binding theorem must cover this replacement
of DeepFold's one-tree-per-polynomial presentation.

Different points are never combined by a naive random linear combination.
For each touched block, a VOLE-blind batched sumcheck first reduces the
already fixed GKR weight claims to one claim at a canonical `E` point. A
transcript-bound random combination then combines same-size touched blocks
at the opened initial-codeword coordinates; the verifier recomputes that
combination from the multiproof symbols. Subsequent fold oracles are shared
per touched cohort. DeepFold's proved different-size batch reduction combines
the cohorts. Claims, cohort membership and block order are bound before
either reduction's challenge.

A response carries one response-wide opening envelope and only the symbols
and authentication material for touched blocks. It does not carry a fresh
fixed proof per namespace, expert or token. The cost is still linear in the
number of touched blocks at the initial-query layer; it is not falsely
described as independent of `B_touch`.

## 3. Private evaluation and the M9 seam

The standard PCS relation exposes an evaluation, while VOLTA must never
publish `W_tilde(r)`. X4 uses zkDeepFold's already-required small random
polynomial as a one-time evaluation pad, then transfers its value through the
existing `E`-valued VOLE-MAC interface. The public model root commits to
static `W` plus prover-secret ZK randomness; it contains no session/PCG
secret.

For every static block `b`, the one-off commitment does exactly the
zkDeepFold construction over `K`:

- embed `W_b` from `E` into `K`;
- append an equal-size uniform `K` coefficient vector to obtain the
  `(mu_b+1)`-variate `Wext_b`, with
  `Wext_b(z_b || 0) = W_b(z_b)`; and
- sample and commit a uniform `ell_b`-variate `K` polynomial `g_b`, where
  `2^ell_b > s*mu_b^2`.

Both roots are bound inside the block/cohort/layer manifest. For the single
permitted response opening:

1. Existing GKR relations produce fixed authenticated claims about `W_b`.
   The blind different-point reduction over `E` produces one authenticated
   `v_b = W_b_tilde(z_b)` at a canonical `z_b in E^mu_b`.
2. Define the paper's canonical auxiliary point
   `u_b = suffix_(ell_b-1)(z_b) || 0 in E^ell_b` and
   `s_b = g_b_tilde(u_b) in K`. The prover publishes only
   `h_b = embed(v_b.plaintext) + s_b in K`; it never publishes either
   summand. All `h_b`, source roots and claim order are fixed before batch,
   fold and query challenges.
3. The response-wide zkDeepFold-UD proof jointly opens `Wext_b` and `g_b`
   using DeepFold's different-size batching, but its public relation is the
   single masked equation
   `h_b = Wext_b(z_b || 0) + g_b(u_b)`. Same-size block batching is applied
   only after the individual roots and masked equations are fixed. Initial
   cohort query symbols and every subsequent fold are checked against those
   roots.
4. Write the canonical tower decomposition `s_b = s0_b + psi*s1_b` and
   `h_b = h0_b + psi*h1_b`, with all four components in `E`. The prover
   consumes two existing full-field correlations, sends the ordinary
   corrections for `s0_b` and `s1_b`, and thereby authenticates both
   components. No `K`-valued correlation or PCG primitive is introduced.
5. One fresh response ZeroBatch checks both
   `v_b + s0_b - h0_b = 0` and `s1_b - h1_b = 0` for every touched block.
   The verifier therefore obtains the committed authenticated weight
   evaluation as `Auth(h0_b) - Auth(s0_b)`, while the second equation proves
   that the public upper component is entirely mask. `W_b_tilde(z_b)` never
   appears in clear.

Uniform `g_b` makes `s_b`, and hence `h_b`, uniform in `K` at the nonzero
evaluation functional. The static commitment binds `Wext` and `g`; the
folding proof binds their masked sum; the two existing VOLE MACs bind the
tower components of `s`; and ZeroBatch ties the authenticated GKR evaluation
to `h-s`. The complete hiding proof must simulate the cohort-batched
transcript given only `h`. Citing zkDeepFold's theorem while still sending
the individual evaluations is not sufficient.

The exact PCS transfer allocation is `2*B_touch + 1` full correlations: two
mask components per touched block plus one response ZeroBatch mask. It
replaces the current PCS evaluation-transfer allocation and is counted in the
X4 rebaseline. At the two-phase upper sizing point,
`K_claim=2*B_touch`, so it receives no correlation-count saving. This is a
PCS-seam count/formula change, not a generator, tuple, setup, spool, pool,
reuse or lifecycle change. No other proof-path correlation budget changes.

The lifetime boundary remains the current one: **one response opening per
static commitment epoch**. `g_b` is a one-time pad, and X4 does not claim that
repeated zkDeepFold transcripts for the same static ZK randomness are jointly
zero knowledge. Recommitment/pad refresh, persistent multi-response serving
and correlation lifetime changes remain out of scope. A commitment epoch
rejects a second response opening; it may not rely on operator discipline.
“One-off commit” below means once per permitted model-commitment epoch under
the existing benchmark convention, not a new multi-response durability
claim.

### 3.1 What reopens in M9

The historical Ligero-specific M9 theorem package remains an immutable record.
X4 reopens only the abstract PCS-to-authenticated-evaluation seam. Before any
Rust implementation, a new Lean module (planned name
`VoltaZk/FoldingOpeningMac.lean`) must state and prove at least:

- `masked_aux_eval`: the semantic identities
  `Wext(z || 0) = W(z)` and `h = embed(W(z)) + g(u)` for the canonical
  auxiliary point;
- `masked_aux_hiding_count`: for fixed `W,z`, uniform auxiliary coefficient
  tapes give equal-size fibers for every published `h in K`; the individual
  `W(z)` and `g(u)` are not transcript fields;
- `pcs_subfield_eval`: embedding an `E`-coefficient MLE and an `E` point into
  `K` preserves its evaluation and gives zero upper tower component;
- `tower_mask_transfer`: the two authenticated `E` components of `g(u)` and
  the two ZeroBatch equations recover an authenticated `W(z)` without
  revealing it;
- ordered `BlockPCSClaim` and `BatchPCSOpening` statement types whose block,
  point, root and claim order are transcript-bound;
- `folding_batch_reduce_sound`: after claims are fixed, the blind
  different-point reduction leaves at most one canonical claim per block,
  with its exact finite-field failure term;
- `MaskedBatchBindsIntoMac`: a concrete counting predicate for accepting
  tapes on which a static/auxiliary masked equation, folded evaluation or
  transferred mask component is wrong;
- `masked_batch_opening_mac_sound`: acceptance of the folding opening and the
  response ZeroBatch while any authenticated weight evaluation disagrees
  with the committed block is bounded by the exact sum/union of PCS,
  reduction and MAC/ZeroBatch errors;
- `masked_batch_transfers_evals`: on a good tape, each downstream M3
  hypothesis receives the required authenticated `W_tilde(r)`; and
- a response-level composition theorem that accounts for every touched block
  and proves the preregistered statistical target without treating BLAKE3 as
  an information-theoretic event.

Names may change only in the pre-code theorem preregistration, but the
properties may not weaken. Every new theorem is added to `lean/Audit.lean`;
the derived audit must remain zero-sorry/zero-admit, standard-axiom-only and
must introduce no fifth `Ideal.lean` axiom. The concrete zkDeepFold binding
property remains an explicit hypothesis at the seam, ultimately discharging
the existing global `Ideal.WeightPCSBinding` boundary rather than being
declared as a new ideal axiom.

The sequence is the same proof-before-code discipline used for M10/M11:
freeze statements and exact error arithmetic, make Lean build and the audit
green, checkpoint and ledger it, then and only then authorize Rust. This
Phase-1 package performs none of those Lean or Rust steps.

## 4. N4(ii): new Merkle commitment format

All X4 roots use leaf/internal-node domain separation. The new format uses
BLAKE3 derive-key mode with these exact context strings:

```text
volta-zk/x4/pcs-leaf/v1
volta-zk/x4/pcs-node/v1
volta-zk/x4/manifest-leaf/v1
volta-zk/x4/manifest-node/v1
```

A PCS leaf frame is canonical little-endian and includes the schema/profile,
tree/oracle kind, namespace, cohort and block-slot identity, descriptor
digest, fold round, outer codeword index, inner block index,
logical/padded/code lengths, symbol count/type and symbol bytes. An internal
frame includes the schema/profile, tree identity, inner/outer role, level,
node index and ordered left/right child digests. Manifest frames separately
bind the full block/cohort descriptor and its root; PCS nodes cannot be
reinterpreted as manifest nodes or leaves.

Every inner and outer path depth is derived exactly from the committed
descriptor. Verification rejects a short or long path, an out-of-range
index, a non-canonical sibling order, a duplicated/missing multiproof node
and a node or leaf replayed across tree kind, cohort, block, oracle or fold
round. The new codec deliberately changes
all commitment roots. Historical C3/C3b/T1 roots, records and references are
never regenerated, relabeled or compared byte-for-byte to X4 roots.

## 5. Honest cost model

Let:

- `N_total` be all padded committed coefficients;
- `N_touch` be padded coefficients of touched blocks;
- `A_total = sum_b 2^ell_b` and `A_touch` its touched-block auxiliary
  subset;
- `B_touch` be touched physical blocks;
- `K_claim` be fixed evaluation claims before the one-per-block reduction;
- `n_max` be the largest touched padded block; and
- `s=128` be the pinned query count.

The preregistered asymptotic model is:

| Operation | Required model |
| --- | --- |
| one-off commit | `O(sum_b (N_b log N_b + 2^ell_b*ell_b))` field/code/hash work, implemented block/cohort-streaming |
| per-response open | `O(N_touch + A_touch)` folding/code work plus batch-reduction work |
| serialized opening | `O(s log^2 n_max + s*sum_c MP(B_c,M_c) + s*B_touch + K_claim)`; no term linear in `N_total` or `N_touch` |
| verifier | the same polylog/cohort-query expression in field/hash work |
| manifest auth | proportional to touched manifest paths, canonically deduplicated |

Here `M_c` and `B_c` are the total and touched block slots in cohort `c`, and
`MP(B_c,M_c)` is the exact canonical inner-Merkle multiproof hash count. The
closed byte formula must instantiate those counts; big-O is not accepted in
a gate record. Neither `N_touch` nor `A_touch` appears as a linear serialized-
byte term.

“Polylog PCS” refers to opening bytes and verifier work. It does **not** mean
polylog prover work. A response touching almost every expert block still
scans almost every relevant coefficient.

The storage expansion must be reported, not hidden. Coefficients and code
symbols in `K` take 32 bytes, the ZK extension doubles the coefficient vector
and rate `1/8` expands the first encoded oracle. The raw first-oracle screen
is therefore
`2 * N * 32 / (1/8) = 512*N` bytes, or 256 times an i16 source, before later
folding oracles, auxiliary polynomials and Merkle nodes. This is about 64 GB
for a 250-MB GPT-2 i16 source. Multiplying the unpadded 41.8-GB gpt-oss source
by 256 gives a **10.7008-TB source-equivalent floor**, not an upper bound;
independent axis padding can make the exact oracle larger. The largest
`ell=17` auxiliary polynomial alone has a 33,554,432-byte raw rate-1/8 first
oracle before its Merkle nodes; applying that maximum to all 1,658 blocks
would add 55.633248256 GB, while the gate uses the exact per-block
`sum_b 2^ell_b` instead. An implementation
may stream/recompute/deduplicate data if its root is identical, but it must
measure persisted bytes, bytes read per opening, recomputation wall, peak RSS
and peak VRAM. It may not claim a resident-A100 win by omitting host or disk
traffic.

### 5.1 First-oracle floor mitigation addendum

This addendum is design only. It distinguishes logical encoded-oracle volume,
persisted storage, bytes moved and peak memory; reducing one does not confer
credit for another.

#### 5.1.1 Fixed-profile floor and the only parameter levers

Let `S=2*N` be the unpadded i16 source bytes for `N` coefficients, `b` the
canonical byte width of one PCS-field symbol and `rho` the RS code rate.
zkDeepFold appends `N` uniform field coefficients, and BaseFold/DeepFold
commits to the RS encoding. Therefore the logical first oracle is

```text
F0(S; b, rho) = (2*N/rho)*b = S*b/rho.
```

For the frozen `K`, 32-byte, rate-`1/8` profile this is `256*S`, hence
`10.7008 TB` for the unpadded 41.8-GB sizing source. This number is
**irreducible for a materialized first oracle at those fixed parameters**.
It is not an information-theoretic persistent-storage lower bound: storing
coefficients and regenerating the codeword uses less space, at the cost of
re-encoding and rebuilding Merkle authentication. Neither cohort streaming
nor a tree hierarchy changes `F0`; only changing `b` or `rho`, or changing
the cited PCS/ZK construction, changes the multiplier. No generic compression
ratio is credited, and representing the uniform extension by a short PRG
seed would replace the selected statistical-ZK statement with a computational
one and is outside this profile.

The following parameter alternatives preserve at least the frozen
`106.24959981538402`-bit *query term* so that a storage reduction is not
obtained by silently spending that margin. Here `Delta=(1-rho)/2`,
`ell_max=ceil(log2(s*30^2+1))`, `field` is the initial field-payload multiplier
`s*b/(128*32)`, and `query/hash` is the query-count multiplier `s/128` before
accounting for the shorter exact paths at higher rates.

| Paper screen | PCS field / bytes | `rho`, `Delta` | `s`, `ell_max` | query-term bits | `F0/S`; 41.8-GB `F0` | initial cost vs frozen (`field`; `query/hash`) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| frozen `K-1/8` | `K` / 32 | `1/8`, `7/16` | 128, 17 | 106.249600 | `256x`; 10.7008 TB | `1.000000`; `1.000000` |
| `K-1/4` | `K` / 32 | `1/4`, `3/8` | 157, 18 | 106.457289 | `128x`; 5.3504 TB | `1.2265625`; `1.2265625` |
| `K-1/2` | `K` / 32 | `1/2`, `1/4` | 256, 18 | 106.249600 | `64x`; 2.6752 TB | `2.000000`; `2.000000` |
| `E-1/8` | `E` / 16 | `1/8`, `7/16` | 128, 17 | 106.249600 | `128x`; 5.3504 TB | `0.500000`; `1.000000` |
| `E-1/4` | `E` / 16 | `1/4`, `3/8` | 157, 18 | 106.457289 | `64x`; 2.6752 TB | `0.61328125`; `1.2265625` |
| `E-1/2` | `E` / 16 | `1/2`, `1/4` | 256, 18 | 106.249600 | `32x`; 1.3376 TB | `1.000000`; `2.000000` |

The maximum raw auxiliary first oracle is respectively 33,554,432 B for
`K-1/8` and `K-1/4`, 16,777,216 B for `K-1/2`, `E-1/8` and `E-1/4`, and
8,388,608 B for `E-1/2`. These are per-block maxima before Merkle nodes, not
opening bytes.

These rows are not interchangeable implementation parameters. `E` has
`v2(|E|-1)=33`: `E-1/4` and `E-1/2` fit the maximum extended domain exactly
or with one bit to spare, while `E-1/8` requires `mu_shard<=29`. More
importantly, all `E` rows must re-run the complete algebraic, batch and union
error expression in the 128-bit-cardinality field; retaining the query-term
bits alone does not prove the response-wide `78.809294874`-bit target. They
also replace the two-component `K` mask at M9 with a one-component `E` seam.
No security or correlation/byte saving from that change is credited until
new lemma statements prove it. A failure rejects the row.

The **35,000,000-B gate is unchanged for every row**. Before a row can replace
the frozen profile, its closed byte formula must separately count field
symbols, BLAKE3 digests, exact shorter path/fold depths, descriptors, masked
evaluations and M9 closure and prove `<=35,000,000 B` at 3,316 claims. The
table's multipliers are screens, not a proof-size postdiction. `K-1/4` raises
both query-count-driven terms by 22.65625%; `E-1/4` lowers field payload but
raises hash/query multiplicity by the same 22.65625%; `E-1/2` doubles that
multiplicity and is therefore the highest-risk byte screen despite its
smallest floor.

If a paper-only comparison is authorized, the first balance point to screen
is `E-1/4` with the `mu_shard=25` hierarchy below. `E-1/8` is the fallback if
the extra hash queries break the byte gate; the `K` rows preserve the larger
security field if the exact `E` arithmetic fails. This is evaluation order,
not candidate selection. Rate above `1/2` is not a further knob in this
power-of-two RS profile: the next inverse-power-of-two rate is 1, which has
zero distance. A non-power-of-two rate is a new folding construction and
receives no credit here.

#### 5.1.2 Per-cohort streaming: peak mitigation, not floor mitigation

The commitment can be generated namespace/cohort at a time and, within a
cohort, in canonical outer-coordinate strips. A concrete strip cap of `2^18`
outer coordinates holds at most
`69 slots * 32 B * 2^18 = 578,813,952 B` (552 MiB) of raw `K` symbols for
the full frozen/`H25` per-layer inventory, or 276 MiB with `E`. The formula
is `M_c*b*2^18`; the `H24` contingency's 101-slot layer would use 808 MiB or
404 MiB respectively. Inner-tree nodes
and encoder/FFT scratch are streamed separately and remain exact G6 counters;
the strip cap is not a claimed total-RSS bound. The incremental Merkle
frontier produces the identical cohort root, so this schedule adds no
transcript field and changes serialized opening bytes by exactly zero.

There are two honest storage modes:

- **Persist encoded artifacts.** Peak working memory is bounded by the strip
  schedule, but the first-oracle byte volume remains at least 10.7008 TB in
  the frozen profile, before padding, later oracles and Merkle nodes. Merely
  writing that floor inside the current A100 `15 s` comparison ceiling would
  require 713.386667 GB/s; the CPU `180 s` ceiling would require
  59.448889 GB/s, before code or hash work.
- **Persist coefficients and recompute.** For the unpadded frozen sizing
  source, the explicit random extension alone is 668.8 GB, so source plus
  extension is already 710.6 GB before block padding. Adding the deliberately
  loose all-1,658-block `ell=17` auxiliary-coefficient screen gives
  `41.8 + 668.8 + 6.954156032 = 717.554156032 GB`; the exact padded cache can
  be larger and must be derived from the block inventory. With only
  coefficients and roots, the
  cited Merkle construction supplies no stateless sublinear path-generation
  algorithm for post-commit unpredictable queries; an opening must budget a
  rebuild of the queried cohort codeword/tree. At the near-all-touched sizing
  point, rebuilding the frozen first-oracle floor inside the current `1.50 s`
  A100 comparison ceiling would require 7.133867 TB/s of generated oracle
  bytes before RS, fold or hash work.

These throughput figures compare scale volume to the current GPT-2 X4
ceilings; Section 5.4 deliberately has no gpt-oss wall gate, and they are not
gpt-oss FAIL verdicts. X5 would need a separately preregistered wall envelope.
Both modes leave the 35-MB serialization formula unchanged. The first can
fail G4/G6 on write volume and storage in the GPT-2 migration; the second can
fail them on recomputation and reads. A mixed cache must report the exact
split and gets no assumed locality credit because the expected workload
touches 3,314.06 of 3,316 claims. The one-opening commitment epoch also
forbids amortizing these costs over undeclared later responses.

#### 5.1.3 Two-level logical-block/transport-shard hierarchy

To cap the largest independently processed oracle, a conditional format may
place deterministic transport shards below each unchanged D3 logical block.
Level 1 remains the logical layer/global block named by GKR and M9. Level 2
commits ordered high-prefix shards, each with its own cohort position and
exact path depth. `logical_block_id`, `shard_prefix`, `mu_shard` and shard
count are included in the existing N4-separated manifest/PCS frames. All
shards are reassembled inside one PCS reduction before the one logical M9
masked evaluation; there is still one response envelope and no per-shard GKR
or per-token proof instance.

| Hierarchy screen | Deterministic split | transport slots | shard-linear slot factor | max raw shard first oracle, frozen `K-1/8` / `E-1/4` | 35-MB impact |
| --- | --- | ---: | ---: | ---: | --- |
| `H25`, `mu_shard<=25` | each of two `mu=30` global blocks -> 32 shards | 1,720 (`+62`) | `1.037394451` | 16 GiB / 4 GiB | shard-linear symbol/path terms include `+3.739445%`; global fold depth drops by five; exact net formula must pass |
| `H24`, `mu_shard<=24` | 768 `mu=25` gate/up blocks -> 2 shards and each global block -> 64 | 2,552 (`+894`) | `1.539203860` | 8 GiB / 2 GiB | shard-linear terms include `+53.920386%`; contingency only, with no pass projection |

Sharding preserves the sum of extended weight-codeword symbols at fixed
`b,rho`; it reduces the largest work unit, not `F0`, and padding/manifests can
only add bytes. `H25` is the only initial hierarchy screen. The closed byte
model must use 1,720 touched transport slots at the all-touched point rather
than hiding the 62 extra paths behind the 1,658 logical-block count.

The cited zkDeepFold theorem gives an auxiliary polynomial per committed
polynomial; it does not by itself prove that transport shards may share one
logical `g_b`. Admission of `H25` therefore requires a pre-code shard-batch ZK
lemma that preserves one logical mask and the frozen `2*B_touch+1` M9 count.
If that lemma is unavailable, the pessimistic `K` accounting adds two mask
transfers per extra shard: `+124` full correlations for `H25` or `+1,788` for
`H24`, plus the corresponding auxiliary roots/proofs. Those costs enter the
35-MB formula; they may not be called implementation metadata.

#### 5.1.4 Floor disposition and stop rule

Within the cited materialized BaseFold/zkDeepFold construction, the frozen
10.7008-TB logical first oracle is honest and irreducible at `K`, 32 B and
rate `1/8`. Streaming and `H25` can make the peak finite but cannot lower that
volume. The most aggressive conditional power-of-two row above still has a
1.3376-TB unpadded logical first oracle and doubles query multiplicity. Thus:

1. no storage mitigation is allowed to relax or net against the
   `<=35,000,000 B` response-opening gate;
2. no row advances unless exact security, byte, wall, storage and traffic
   gates all pass conjunctively on paper before Lean or Rust;
3. if none does, X4 records this BaseFold/zkDeepFold family as unsuitable for
   the product envelope instead of describing a peak-memory optimization as
   removal of the floor; and
4. selecting a PCS family with a genuinely smaller committed-oracle profile
   requires a new cited Phase-1 preregistration.

`x4-zkdeepfold-v1` remains the frozen candidate pending product-owner review.
This addendum authorizes no arithmetic checkpoint, Lean, Rust, benchmark,
reference regeneration or X5 work.

### 5.2 Current measured comparison point

These are immutable current Ligero measurements, not X4 projections:

| Metric | CPU reference | official RunPod A100 reference |
| --- | ---: | ---: |
| one-off PCS commit | `10.785629 s` | `0.202467 s` |
| per-response PCS open | `0.767759 s` | `0.294423 s` |
| PCS verify | `0.080496 s` | `0.079365 s` |
| serialized PCS opening | `43,273,888 B` | `43,273,888 B` |

The current T1 response is `84,544,352 B`; subtracting the PCS component
leaves `41,270,464 B` of unchanged non-PCS response material. X4 cannot claim
that baseline until the same semantic GPT-2 response is reproduced.

### 5.3 Preregistered gates

Gates are conjunctive. A byte pass cannot override a security, correctness,
proportionality, storage or end-to-end failure.

**G1 — formal/security seam.** The exact unique-decoding soundness, modified
masked-relation ZK arithmetic and `E`/`K` composition for the pinned profile
meet at least `78.809294874` statistical bits response-wide; the M9 theorems
and derived Lean audit are green before Rust; no new ideal axiom, clear
`W_tilde(r)`, second opening or Fiat--Shamir claim exists.

**G2 — correctness and adversarial strictness.** GPT-2 fixed-point/golden
outputs, authenticated evaluations and downstream proof claims match T1
semantically. Honest batch verification accepts. Tests reject tampering with
root, manifest, descriptor, block, point, public `h`, either tower-component
mask correction/key/tag, claim add/drop/reorder, reduction transcript, fold
message, query answer, Merkle leaf/node/type/depth/index, auxiliary ZK
commitment and response
ZeroBatch. Cross-domain leaf/internal/manifest substitutions all reject.
The exact PCS transfer count is `2*B_touch+1` full correlations on both roles,
with no other proof-path counter change.

**G3 — GPT-2 communication.** The canonical serialized PCS component is at
most **4,000,000 B per response**. With the frozen non-PCS component this
projects an absolute response ceiling of **45,270,464 B**. The byte counter
must equal the serialized length and itemize roots/manifests, claims,
sumchecks/folds, queries, paths, public masked evaluations and MAC closure.

**G4 — measured isolated wall.** On the pinned 4-thread CPU profile:
one-off commit `<=180 s`, per-response open `<=15 s`, verify `<=0.50 s`.
On official `runpod-a100-v1`: one-off commit `<=15 s`, per-response open
`<=1.50 s`, verify `<=0.25 s`. These deliberately allow prover time to buy
communication, but not an unbounded implementation. The existing full
resident-pod absolute gates also remain conjunctive: prefill `<=10 s`, decode
`<=4 s`, H2D `<=100 MB`, maximum synchronization `<=0.150 s`, flatness
`<=1.5`. Commit is measured separately and never hidden in setup.

**G5 — touched-block proportionality.** A synthetic family with identical
block size and `1, 2, 4, 8, 16` touched blocks records `N_total, N_touch,
B_touch, K_claim`, coefficients read, every byte component and wall. Opening
source-weight reads equal the canonical `N_touch`; encoded, ZK-extension,
auxiliary and fold reads are counted separately. Serialized bytes match the
closed cohort/multiproof formula and have no linear `N_total`/`N_touch` term.
Doubling only unopened blocks may change opening bytes solely through the
exact manifest/cohort-depth formula, and same-process ABBA opening wall ratio
must be `<=1.05`. There is exactly one response envelope.

**G6 — storage and traffic honesty.** Records include source bytes, every
encoded/fold/Merkle/auxiliary artifact byte, persisted bytes, recomputed
bytes, host bytes read/written, H2D/D2H, peak RSS and peak device memory.
Artifact totals reconcile exactly. Block streaming must fit the official
A100 and cannot materialize a hidden whole-model GPU oracle. A storage or
traffic omission is a gate failure, not “instrumentation unavailable.”
For any later-approved Section 5.1 alternative, the record also pins
`field,b,rho,s,ell_max,mu_shard`, logical first-oracle bytes, transport-slot
count and the selected persist/recompute split. A 35-MB byte pass cannot waive
these requirements.

### 5.4 gpt-oss analytic screen (not a verdict)

The sizing case is 24 layers, 32 experts and 41.8 GB of committed i16
weights, with 1,658 physical blocks and at most 3,316 stacked claims. Before a
real export, X4's analytic projection must show:

- serialized PCS opening `<=35,000,000 B` for the upper claim count;
- a closed byte expression with no term linear in the 41.8-GB total;
- marginal block-opening bytes proportional only to touched blocks and
  the exact cohort/manifest multiproof depths; and
- the raw-oracle/storage screen above, including the 10.7008-TB
  source-equivalent first-oracle floor, with an explicit
  Section 5.1 parameter, hierarchy and streaming/recompute disposition.

This screen is deliberately weaker than a measured gate. The expected
3,314.06 claims provide essentially no sparsity discount, and there is no
gpt-oss wall, proof-size or memory result until X5 supplies real artifacts and
an authorized run. Passing the analytic screen confers no X5 or product gate
credit.

## 6. Migration and re-baseline ritual

The migration is append-only and runs only after the proof-before-code
checkpoint authorizes implementation.

1. Create a new format/profile identifier, `x4-zkdeepfold-v1`, and new
   reference names. Never overwrite C3, C3b, T1 or historical root records.
2. Use a clean tree and one Git SHA for both sides of a same-process Ligero
   versus X4 ABBA run. Because `target-cpu=native` is pinned, remeasure Ligero
   on every new CPU/pod rather than importing a ratio.
3. Use the same GPT-2 weights/golden hashes, workload, model configuration,
   block semantics and claim schedule. New commitment roots are expected;
   clear evaluation is allowed only in a test oracle that checks semantic
   equality and is absent from production.
4. Run one untimed warmup and at least three measured ABBA pairs. Gate the
   preregistered upper median. Pin CPU model/thread count and the official
   provider/A100/driver profile.
5. Measure cold one-off commit separately from per-response open and verify.
   Record canonical serialized bytes, every component, peak RSS/VRAM,
   persisted artifacts, host I/O, H2D/D2H and synchronization. Record both
   success and failure; do not rerun away an outlier without a ledgered cause.
6. Append new `benchmarks/results/x4-<date>-<gitsha>.json` records with
   `git_dirty:false`, then add new reference rows. Historical rows and JSON
   remain byte-identical. Cut over the production default only after G1--G6
   and the inherited resident-pod gates all pass.

The initial migration case is GPT-2, not gpt-oss. The latter remains a sizing
case until a separately authorized export/golden package exists.

## 7. Explicitly out of scope

This X4 package does not authorize or claim:

- X5, gpt-oss download/export, frontend integration, weights, goldens or a
  real gpt-oss benchmark;
- any PCG generator, cryptographic assumption, tuple, allocation, spool,
  encryption, lifecycle, pooling, reuse or multi-response change;
- any proof-path change outside the PCS/M9 seam, including corrections,
  boundary thinning, LogUp, routing, fixed-point semantics, witness generation
  or the GKR relations that produce weight claims;
- Fiat--Shamir or a non-interactive public-verifier conversion;
- cached/reused query rows (unsound lever A), per-token proofs, per-token PCS
  claims, clear weight evaluations, Packed16 reinstatement or an MXFP4
  commitment format; or
- Lean statements/proofs or Rust implementation in this Phase-1 package.

## 8. Phase order and hard stop

After product-owner review, a separately authorized phase may perform the
pre-code security arithmetic and M9 Lean checkpoint. Only a later explicit
authorization may implement and benchmark the Rust profile. The order is:

```text
Phase 1 (this document): design preregistration -> HARD STOP
Phase 2: exact security arithmetic + M9 Lean proofs/audit -> checkpoint
Phase 3: Rust implementation + adversarial tests -> checkpoint
Phase 4: clean GPT-2 CPU/A100 measurement + gate disposition
Phase 5: X5/gpt-oss work only under a separate preregistration
```

**HARD STOP: no Lean, Rust, reference, benchmark or X5 work is authorized by
this document.**

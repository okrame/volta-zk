# X0 MoE analytic design package

**Status (2026-07-18): design complete; no MoE implementation authorized.**
X0 fixes the analytic `ModelConfig` budget, decisions D1--D4, the private-
weights deployment target, the Phase-X prerequisite amendment, the long-output
requirement, and the provider-facing envelope.  X1--X3 and X4 are later
packages.  T1 is separately preregistered in
`docs/t1-boundary-thinning-design.md`; Phase 1 is approved and M11 remains the
Lean-first stop before Rust.

The executable source of this design budget is `scripts/budget_moe.py`.  It
uses only the standard library, defaults to prompt 100 plus deferred decode
50, emits text or JSON, and is parameterized by immutable `ModelConfig` and
`Workload` values.  It is an analytic shape model, not a Llama/gpt-oss
frontend, proof, timing claim, or response-byte measurement.

## 1. Pinned profiles and accounting conventions

The gpt-oss-20b point is 24 layers, residual width 2,880, expert width 2,880,
32 experts with public top-4 routing, 64 query / 8 KV heads of width 64,
alternating full and 128-token sliding attention, vocabulary 201,088, clamped
SwiGLU, RMSNorm, RoPE, attention sinks, and 20.9B total / 3.6B active
parameters.  These values are pinned by the repository scaling note and the
[published OpenAI configuration](https://huggingface.co/openai/gpt-oss-20b/blob/2e8f8052ee2aeee907f76e08c08b9fdde8677ca8/config.json).
The dense point is the existing representative Llama-class 8B/GQA profile:
32 layers, width 4,096, FFN width 14,336, 32/8 heads of width 128, and
vocabulary 128,256.

All corrections remain Fp-typed at 8 bytes.  Packed16 receives no credit.
Attention MACs use real causal/window pairs; GQA reduces K/V projection and
authentication width but not query-head QK/AV work.  Decode is one deferred
stacked phase, never per-token proof instances or PCS openings.  Lookup totals
show both logical rows and the analytic power-of-two job padding.  MoE padding
uses balanced public routes because the real route histogram does not exist at
X0; logical totals are route-independent, while padded totals are a planning
projection.

PCS claims are stacked across prefill and decode.  No linear RLC is credited
across distinct points.  For MoE, gate/up is one block and down is a second
independently evaluated block per touched expert.  The upper bound assumes all
experts are touched; the expected count is reported only as a cost model.

## 2. Analytic response budget

Default output of `python3 scripts/budget_moe.py`:

| Quantity, prompt 100 + decode 50 | gpt-oss-20b MoE | Llama-class 8B dense |
| --- | ---: | ---: |
| native integer MACs | 485,359,730,688 | 1,076,133,888,000 |
| committed parameters after i16 export | 41.800 GB | 16.060522 GB |
| authenticated values, current boundaries | 46,485,064 | 77,135,176 |
| corrections, current boundaries | 371.881 MB | 617.081 MB |
| authenticated values, T1 k=4 shape | 18,405,064 | 23,682,376 |
| corrections, T1 k=4 shape | 147.241 MB | 189.459 MB |
| logical lookup rows | 417,267,938 | 408,291,250 |
| padded lookup rows | 687,568,448 | 586,362,944 |
| lookup padding ratio | 1.6478 | 1.4361 |
| exact subfield correlations, current / k=4 | 46,485,064 / 18,405,064 | 77,135,176 / 23,682,376 |
| full-field correlation planning proxy | 2,874,728, **non-gating** | 370,680, **non-gating** |
| per-layer + global commitments | 25 | 33 |
| stacked PCS claims, upper bound | 3,316 | 452 |
| expected stacked claims | 3,314.06 | 452 |

The script also prints per-operator MACs/lookups, attention pair counts,
current/thinned residual, KV and `other` authentication, expected expert
touches, per-token context growth, and the explicit assumptions.  Its
self-checks reproduce P0 GPT-2 MAC/lookups, the exact C1 correction split,
C3b's 512-byte selected-row increment, and the GPT-2 k=4 correction target.

Interpretation:

- active MoE compute remains below the dense point, but gpt-oss commits all
  20.9B parameters under the private-weight deployment target;
- T1 helps the residual stream, not K/V or `other`; it therefore does not make
  large-model correction communication small by itself;
- the full-field counts are intentionally a transparent proxy until X1--X3
  create an exact scheduler/allocation digest;
- no total PCS-opening bytes are projected.  The fixed pass over tens of GB of
  committed i16 weights is precisely the X4 folding-PCS prerequisite, so X0
  does not disguise it behind the retracted cached-column or cross-point-RLC
  projections.

The script's GPT-2 anchor reports `38,348,720 B` corrections and
`84,520,832 B` after correction savings alone.  The amended T1 design adds the
honest `22,848 B` eq-reduction transcript and `672 B` of scalar transport
corrections, yielding the binding Phase-2 reference `84,544,352 B`; see the
T1 document for its formal prerequisite and gate.

## 3. Authoritative MoE decisions D1--D4

### D1 — routing is public response metadata

For every token/layer, the selected expert ids and their canonical order are
public metadata.  Gather, scatter and combine selectors are therefore public
relations in the existing sumcheck class.  X1 must bind the router scores,
top-4 membership, weights and native tie rule before using those selectors;
the prover may not choose a route after a proof challenge.

Accepted leakage is the expert-choice trace, a function of private weights and
known tokens.  This is an explicit product decision, not a claim that routes
are independent of weights.  Scores and unselected expert weights remain
private.  No private-route ORAM/permutation proof is in scope.

### D2 — MXFP4 is exported to calibrated i16 proof semantics

The first implementation path canonically dequantizes the checkpoint's MXFP4
expert blocks offline, applies the frozen symmetric zero-point-0,
power-of-two calibration discipline, and exports private i16 matrices with
explicit per-block shift metadata.  GEMM accumulation is i64; every requant,
round and clamp follows `docs/quantization-spec.md` and must match the
architecture reference bit-for-bit.  The committed proof object is the i16
weight block, not the MXFP4 code.

This decision credits no 4-bit commitment or communication saving.  A future
alternative that commits MXFP4 codes plus authenticated block scales is a new
protocol/cost decision, not an exporter optimization.  It must preserve the
same i16 witness semantics and private-weight target.

### D3 — one commitment per layer, per-expert blocks inside it

Each layer has one commitment whose canonical block map contains attention,
router and aligned expert gate/up and down blocks.  The global embedding/
unembedding material has its own commitment.  This gives 25 commitments for
the 24-layer profile, while retaining independently addressable expert blocks
and one batched opening per response.

There are no per-expert commitments (which would multiply fixed costs) and no
model monolith (which would destroy sparse block openability).  Claims remain
one per independently evaluated block and phase unless a separately proved
multi-point reduction says otherwise.

### D4 — BF16 attention/embed weights use P5-style i16 calibration

BF16 attention, router and embedding/unembedding tensors are exported with
the same offline calibration/golden discipline as P5: symmetric i16 weights,
power-of-two scales, exact i64 accumulation, and per-layer residual scales.
RMSNorm is represented by the existing normalization subset; RoPE and band
edges are public linear/selective terms.  Model onboarding is incomplete
until the exporter and reference forward produce a bit-exact prompt plus
50-token golden decode.  No BF16 arithmetic is silently left inside the proof.

## 4. Private-weights deployment decision

gpt-oss-20b is treated **as if proprietary**, with private weights and the
current PCS-hiding discipline as the design target.  Its actual open-weight
license does not relax the product proof.  The closed product/deployment table
is recorded verbatim:

| Backend | Use case | Comm/response | Assumption |
| --- | --- | ---: | --- |
| PCS hiding (current) | proprietary weights | 105.7 MB | binding |
| Direct evaluation | open weights, client can store | ~62.4 MB | none (info-theoretic) |
| Non-hiding PCS, public root | open weights too large | ~105 MB | binding |

Only the first row drives X0--X5.  The other rows are deployment options, not
implementation authorization or arguments for revealing gpt-oss weights.

## 5. Phase-X prerequisite amendment

The former scaling-note statement that levers A and B were Phase-X
prerequisites is retracted:

- **Lever A, verifier-cached PCS columns, is UNSOUND.**  The 2026-07-15 ledger
  entry shows that revealed consistency queries let later response `u`
  vectors satisfy only the known checked coordinates while encoding a false
  evaluation.  Its response projections remain retracted.
- **Lever B, Packed16, is shelved.**  Its sound realization moves roughly
  1.55 GB/session to save about 32.5 MB/response and was rejected on product
  cost.  It is not an 8-to-2-byte assumption in this budget.

The current scale prerequisites are instead:

1. **T1 boundary thinning** for correction and sub-correlation growth, after
   M11 is proved and audited;
2. **X4 folding PCS** for per-response opening growth over total committed
   weights.

X1--X3 (routing, a synthetic MoE block, and the non-GPT ops pack) and X4 are
later packages.  No gpt-oss end-to-end/X5 claim is eligible until both T1 and
X4 have closed.  `docs/scaling-note.md` is amended in this package so the
stale A/B prerequisite text is not left as a competing plan.

## 6. Arbitrarily long responses are a product requirement

Responses are required to be **arbitrarily long**.  Proof download may grow
linearly in `T_dec`; prover work per generated token may grow linearly with
context for full attention (and stay window-bounded for sliding layers), which
is the same asymptotic shape as native decode.  This does not authorize
per-token proof instances or per-token PCS claims: decode remains deferred,
stacked, and opened once per response/chunk policy.

The required current planning table is:

| Per generated token | Planning budget | Scaling requirement |
| --- | ---: | --- |
| correction/proof marginal | ~445 KB/token | linear in `T_dec` |
| private argmax | ~1.2 KB/token (`57,840/50 = 1,156.8 B`) | linear in `T_dec` |
| **variable download** | **~446.2 KB/token** | **linear in `T_dec`** |
| prover work | linear in context on full-attention layers; window-bounded on sliding layers | same shape as native |

The 445-KB row is the standing conservative product budget inherited from the
P6 decode marginal.  For reconciliation, the immutable C3b exact all-label
decode marginal is `19,546,432/50 = 390,928.64 B/token`; amended T1 projects
`12,492,256/50 = 249,845.12 B/token`.  These refinements do not weaken the
arbitrary-length requirement.

The following are engineering caps to clear later, not product limits:

- decode domain ids permit only five chunks, with
  `layer_dom_base = 16 + 32*c` (`model_proof.rs:242-250`);
- flat-cost behavior has been validated only through context 150;
- one 110M-output production connection represents only about 2.2k current
  token-equivalents (the exact current T1 analysis gives 2.13k before T1 and
  about 3.23k after its projected correlation reduction).

Before long-output closure, the implementation needs an unbounded/versioned
chunk-domain scheme, longer-context flat-cost validation, and transparent
connection rotation/replenishment under the existing nonce durability and
abort-burn lifecycle.  It may not solve those caps by reusing correlations,
wrapping ids, or switching to per-token openings.

## 7. One-page provider envelope

These are the four provider integration quantities.  Decimal MB are used.
The exact current anchor is the clean C3b RunPod A100 record; T1 values are
preregistered projections, not measurements.

| Provider quantity | Exact current anchor | Contract after T1 / onboarding rule |
| --- | --- | --- |
| **1. connection setup** | `48.838774638 s + 38.371465 MB` traffic (`31.581007 MB P->V`, `6.790458 MB V->P`) | setup remains outside response/rho; any tuple/refill change must re-register both seconds and bytes |
| **2. response** | `105.717632 MB` at 100+50; measured marginal `0.39092864 MB/token` | T1 gate `84.544352 MB`, projected marginal `0.24984512 MB/token`; provider streaming/storage must remain linear in `T_dec` |
| **3. rho** | prefill `3.486621672`, decode `0.842661976` against the same-host native GPU anchor | T1 gets no new rho relaxation; absolute pod gates remain prefill 10 s / decode 4 s |
| **4. model onboarding** | `t_export + t_calibration + t_commit`; current GPT-2 pod commit component is `0.202467381 s`, export/calibration were not recorded | every new model must report all three components, exporter/golden hashes, calibration corpus, block map, and one-off commitment root before serving |

The fourth number is intentionally not fabricated: X0 has no gpt-oss exporter
or calibration run, so its honest onboarding total is **unmeasured**.  The
41.8-GB i16 commitment size is an analytic input, not a commitment-time
benchmark.  A provider may integrate the metric now, but may not substitute
the 0.202-s GPT-2 component as a gpt-oss onboarding promise.

Setup is per connection; onboarding is per model/version; response and rho are
per request.  PCS commit remains one-off, PCS opening remains one batched
opening per response, and the response number includes all proof/download
bytes under the private-weight policy.

## 8. X0 exit and hard boundary

X0 is design-only and complete when the script, these decisions, the scaling
note amendment, and the ledger entry agree.  It creates no non-GPT proof or
gate verdict.  T1 Phase 2 is conditionally authorized after a green M11
proof/audit; X1--X4 remain later packages.

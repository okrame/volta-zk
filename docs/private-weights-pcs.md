# Private weights: static PCS design note (decision 2026-07-04)

Status: **decided at design level, pre-registered; implementation = P3.5; formal
coverage = open item "M9" (formal phase reopens for one lemma).** Supersedes the
implicit "weights are public" assumption of the phase-P plan (see ledger
deviation 2026-07-04).

## Problem

VOLTA's target deployment is an LLM API whose provider does **not** reveal
weights. Two naive options, both with real costs:

- **A (naive zk-PCS per query)**: static commitment `C_W`, but every inference
  needs PCS openings; plain openings reveal `W̃(r)` — thousands of queries leak
  a linear-algebra view of W; ZK openings fix leakage but seem to add per-query
  prover cost that could erode the prover advantage.
- **B (per-user MAC-auth of W)**: verifier gets VOLE MACs on all of W at setup,
  never sees W; queries are then native-speed. Setup is O(|W|) **communication**
  (corrections): 8 B/value ⇒ ~1 GB/user at GPT-2, **~160 GB/user at 20B**
  (~40 GB even with the deferred 16-bit sVOLE packing). Compute is fine
  (~one epilogue pass); communication kills it at scale. This is essentially
  Mystique's model (Weng et al., USENIX Sec'21) — the direct VOLE-ZK-ML
  precedent — so B is "publishable but not top-tier-new".

## Resolution: A′ — static code-based PCS, one *batched ZK opening into a MAC* per response

Two structural observations dissolve the dilemma.

**1. The protocol touches W only through O(q·#GEMMs) multilinear evaluations.**
The Thaler matmul sumcheck needs `W̃(r)` at the end of each GEMM sumcheck —
about q=3 × 73 ≈ 220 scalar claims per prefill. All of them RLC-batch (standard
sumcheck batching, same machinery as the planned q=3 opening and the P6
cross-token RLC) into **one** PCS opening **per response** (prefill + all
decode tokens), not per token and not per claim.

**2. One opening is O(|W|) prover work, but native inference is O(2·T·|W|)
MACs — the ratio is ~independent of model size.** The erosion the fear is
about would apply only if we opened per token. Batched per response:

- Opening prover cost (tensor-code PCS, see below): ~|W| Goldilocks mults for
  the row-combination pass. At P1's measured throughputs this is roughly
  10–15 % of native *prefill-100* wall time standalone, and **~1–3 % of a
  realistic full response** (e.g. 100 prefill + 500 decode tokens). The ratio
  is the same at 124M and at 20B, because both numerator and denominator are
  linear in |W|. Session-level batching (one opening per k responses, claims
  accumulated by RLC across responses) drives it toward 0 if needed.
- Commitment is one-off and **public**: same `C_W` for every user. Bonus
  property for the paper: *model accountability* — all users can check they
  are served the same committed model, which per-user option B cannot give.

**PCS choice**: field-native, transparent, hash-based, from the
Ligero/Brakedown/Basefold tensor- and foldable-code family (Goldilocks is
natively supported; BaseFold CRYPTO'24 and BrakingBase are exactly this design
space). No curves, no trusted setup, no field mismatch with the VOLE layer.
W (quantized, 16-bit) is committed as a multilinear over ~2^27 coefficients
for GPT-2 small.

**Zero leakage**: openings are made ZK by the standard masking-row technique
(ZK-Ligero-style random codeword rows), and the opened evaluation is never
revealed in the clear — the opening resolves into a **VOLE-authenticated
value**: V ends up holding a MAC tag on `W̃(r)` under the session Δ, which the
blind sumcheck (M3) consumes exactly like any other authenticated evaluation.
Per-query weight leakage: none beyond `C_W` itself.

## What this costs the project

1. **Formal**: one new interface lemma, "**M9 — opening-into-MAC**": if V
   accepts the (ZK) PCS opening + MAC-transfer step, then the authenticated
   value equals the committed polynomial's evaluation at the challenge, with
   the usual soundness error; composes with M3's blind sumcheck statement. The
   PCS internals themselves (code-based IOP soundness) are *assumed*, not
   formalized — standard, and declared as such. Formal phase reopens for this
   one statement; logged, not yet scheduled.
2. **Prototype**: new milestone **P3.5** (after P3, before P4): implement or
   faithfully mock the static PCS for the GPT-2 weight tensors; measure
   one-off commit time, per-response batched ZK opening time and bytes; gates:
   opening ≤ ~15 % of native prefill-100 standalone (≤ ~3 % amortized per
   600-token response), plus a leakage smoke test (opening transcripts for two
   different weight sets indistinguishable given the same `C_W` structure).
3. **Budget/report**: P0 budget and P7 GPU extrapolation gain a PCS line
   (commit one-off; opening per response, O(|W|) mults + O(√|W|) hashing and
   communication).

## Why this is the right paper story

- The recognized bottleneck in zkML with committed models is exactly
  commitment-checking overhead (Artemis/Apollo, 2024: reduced from ~11.5× to
  ~1.2× in the SNARK setting); solving it in the *designated-verifier VOLE*
  setting with a per-response cost that is model-size-independent relative to
  native work is a clean, new claim.
- Versus Mystique (option B): no O(|W|)/user setup communication, plus public
  model accountability.
- Fallback recorded: for small models or premium single-tenant deployments,
  option B remains a valid *optimization* (skip the per-response opening
  entirely after a 1 GB-scale setup); it is a deployment knob, not the
  architecture.

## References

- Mystique, USENIX Security 2021 — https://eprint.iacr.org/2021/730
- Artemis/Apollo commit-and-prove zkML — https://arxiv.org/abs/2409.12055
- BaseFold, CRYPTO 2024 — https://eprint.iacr.org/2023/1705
- BrakingBase — https://link.springer.com/chapter/10.1007/978-981-95-5116-3_14
- ZK PCS in binary fields (masking-row ZK for code-based PCS, adaptable) —
  https://eprint.iacr.org/2025/1015.pdf

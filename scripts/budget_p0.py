"""Analytic budget for VOLTA-ZK P0: GPT-2 small, prefill T=100 (causal).

Pre-registered counts that P4/P5 measurements are compared against.
Run: python3 scripts/budget_p0.py
"""
T, L, d, h, dh, dff, V = 100, 12, 768, 12, 64, 3072, 50257
caus = T * (T + 1) // 2  # causal positions per head

# ---- native integer MACs (i16 x i16 -> i64 acc) ----
gemm = {
    "qkv_proj": T * d * 3 * d,
    "scores_qkT": h * caus * dh,
    "attn_av": h * caus * dh,  # output row t sums over t+1 positions
    "attn_out_proj": T * d * d,
    "ffn_up": T * d * dff,
    "ffn_down": T * dff * d,
}
per_layer_macs = sum(gemm.values())
logits_macs = 1 * d * V  # last position only (sampling)
native_macs = L * per_layer_macs + logits_macs

# ---- authenticated boundary values (residual stream + K + V; fused-block design:
#      internal wires — Q, scores, exp outputs, GELU in/out, FFN-up — are NOT authenticated)
auth = {
    "embed_out": T * d,
    "attn_block_out": L * T * d,
    "ffn_block_out": L * T * d,
    "K": L * T * d,
    "V": L * T * d,
    "final_ln_out_last_pos": d,
}
auth_total = sum(auth.values())

# ---- communication: corrections are F_p-typed (M5: subfield = Goldilocks inside E=F_p^2),
#      i.e. 8 bytes/value. NOTE the 2-byte (16-bit) packing from the concept note is NOT
#      covered by M5: [0,2^16) is not subtraction-closed in F_p, a mod-2^16 correction
#      needs an authenticated carry bit per value. Open optimization, tracked in ledger.
corr_bytes = auth_total * 8

# ---- lookups by operator (16-bit LUT domain) ----
lk_layer = {
    "ln_rsqrt": 2 * T,
    "ln_norm_requant": 2 * T * d,
    "requant_qkv": T * 3 * d,
    "requant_scores": h * caus,
    "exp": h * caus,
    "softmax_recip": h * T,
    "softmax_norm_requant": h * caus,
    "requant_av": T * d,
    "requant_attn_proj": T * d,
    "requant_ffn_up": T * dff,
    "gelu": T * dff,
    "requant_ffn_down": T * d,
}
lookups_layer = sum(lk_layer.values())
lookups_total = L * lookups_layer

# ---- verifier: one streamed pass over authenticated values per opening point
q = 3  # opening points, shared across claims via RLC
verifier_fp2_mults = auth_total * q

n_gemms = L * len(gemm) + 1

if __name__ == "__main__":
    print(f"causal positions/head:        {caus:>14,}")
    print(f"native MACs total:            {native_macs:>14,}  ({native_macs/1e9:.2f} G)")
    for k, v in gemm.items():
        print(f"  {k:<28}{L*v:>14,}")
    print(f"  logits_last_pos             {logits_macs:>14,}")
    print(f"authenticated values total:   {auth_total:>14,}")
    for k, v in auth.items():
        print(f"  {k:<28}{v:>14,}")
    print(f"correction bytes (F_p, 8B):   {corr_bytes:>14,}  ({corr_bytes/1e6:.1f} MB)")
    print(f"VOLE correlations consumed:   {auth_total:>14,}  (+ ~{n_gemms} GEMM masks + RLC masks, O(10^3))")
    print(f"lookups/layer:                {lookups_layer:>14,}")
    for k, v in lk_layer.items():
        print(f"  {k:<28}{L*v:>14,}")
    print(f"lookups total:                {lookups_total:>14,}")
    print(f"verifier Fp2 mults (q={q}):     {verifier_fp2_mults:>14,}")
    print(f"lookup/native-MAC ratio:      {lookups_total/native_macs:.4f}")
    print(f"auth/native-MAC ratio:        {auth_total/native_macs:.6f}")

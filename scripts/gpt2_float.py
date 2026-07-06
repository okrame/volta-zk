"""Plain float64 GPT-2 forward (picoGPT-style), calibration-only.

Not part of the bit-exact witness path (see gpt2_fixed.py for that). The
`forward_model(tokens, fw)` entry point is the interface contract of
scripts/export_gpt2.py: `fw` is the dict produced by
export_gpt2.gpt2_float_weights — per-layer dicts keyed c_attn, c_attn_bias,
attn_proj, attn_proj_bias, ffn_up, ffn_up_bias, ffn_down, ffn_down_bias,
ln1_gain, ln1_bias, ln2_gain, ln2_bias (float64, same layout as the
fixed-point tensors: c_attn is 768x2304 in-major [Q|K|V]), plus wte, wpe,
lnf_gain, lnf_bias. Output is the range report ('act_max' / 'weight_max')
that calibrate() turns into power-of-two scales, plus the last-position
logits/argmax for the fidelity check.

GELU uses the same tanh-approximation constants as luts.rs so the float
range stats are comparable to what the fixed-point GELU LUT will see.
"""

from __future__ import annotations

import math

import numpy as np

GELU_C0 = 0.7978845608028654
GELU_C1 = 0.044715
LN_EPS = 1e-5


def gelu_f(x: np.ndarray) -> np.ndarray:
    return 0.5 * x * (1.0 + np.tanh(GELU_C0 * (x + GELU_C1 * x**3)))


def softmax_f(x: np.ndarray, axis: int = -1) -> np.ndarray:
    x = x - np.max(x, axis=axis, keepdims=True)
    e = np.exp(x)
    return e / np.sum(e, axis=axis, keepdims=True)


def _mx(cur: float, arr: np.ndarray) -> float:
    return max(cur, float(np.max(np.abs(arr)))) if arr.size else cur


def _layer_norm_f(x: np.ndarray, gain: np.ndarray, bias: np.ndarray, act: dict, per_ln: dict) -> np.ndarray:
    """Row-wise LN (biased variance, eps 1e-5). Feeds the ln_out range, the
    global ln_var extremes, AND the per-LN-site variance lists (call order =
    site order: ln1(0), ln2(0), …, ln1(11), ln2(11), ln_f) — the per-layer
    residual-scale calibration needs the variance range per site."""
    mean = x.mean(axis=-1, keepdims=True)
    var = x.var(axis=-1, keepdims=True)
    act["ln_var_min"] = min(act["ln_var_min"], float(var.min()))
    act["ln_var_max"] = max(act["ln_var_max"], float(var.max()))
    per_ln["min"].append(float(var.min()))
    per_ln["max"].append(float(var.max()))
    out = (x - mean) / np.sqrt(var + LN_EPS) * gain + bias
    act["ln_out"] = _mx(act["ln_out"], out)
    return out


def _forward_layer_f(x_in: np.ndarray, w: dict, n_head: int, act: dict, per_ln: dict, seg_max: list) -> np.ndarray:
    t, d = x_in.shape
    dh = d // n_head
    seg = _mx(0.0, x_in)  # segment l covers x_in(l)/attn_block_out/ffn_block_out

    ln1_out = _layer_norm_f(x_in, w["ln1_gain"], w["ln1_bias"], act, per_ln)

    qkv = ln1_out @ w["c_attn"] + w["c_attn_bias"]
    act["qkv_out"] = _mx(act["qkv_out"], qkv)
    q = qkv[:, 0:d]
    k = qkv[:, d:2 * d]
    v = qkv[:, 2 * d:3 * d]

    causal_mask = np.triu(np.full((t, t), -np.inf), k=1)
    av = np.zeros((t, d))
    for head in range(n_head):
        qh = q[:, head * dh:(head + 1) * dh]
        kh = k[:, head * dh:(head + 1) * dh]
        vh = v[:, head * dh:(head + 1) * dh]
        scores = (qh @ kh.T) / math.sqrt(dh)  # AFTER the /8 for GPT-2 heads
        act["scores"] = _mx(act["scores"], scores[np.tril_indices(t)])
        w_sm = softmax_f(scores + causal_mask, axis=-1)
        av[:, head * dh:(head + 1) * dh] = w_sm @ vh
    act["av_out"] = _mx(act["av_out"], av)

    attn_out = av @ w["attn_proj"] + w["attn_proj_bias"]
    attn_block_out = x_in + attn_out
    act["residual"] = _mx(act["residual"], attn_block_out)
    seg = _mx(seg, attn_block_out)

    ln2_out = _layer_norm_f(attn_block_out, w["ln2_gain"], w["ln2_bias"], act, per_ln)

    ffn_up = ln2_out @ w["ffn_up"] + w["ffn_up_bias"]
    act["ffn_up_out"] = _mx(act["ffn_up_out"], ffn_up)
    g = gelu_f(ffn_up)
    act["gelu_out"] = _mx(act["gelu_out"], g)
    ffn_down = g @ w["ffn_down"] + w["ffn_down_bias"]
    ffn_block_out = attn_block_out + ffn_down
    act["residual"] = _mx(act["residual"], ffn_block_out)
    seg = _mx(seg, ffn_block_out)
    seg_max.append(seg)

    return ffn_block_out


def forward_model(tokens, fw, n_head: int = 12) -> dict:
    """Full float GPT-2 forward + range collection (export_gpt2.py contract).

    Returns:
      'act_max': {'residual', 'ln_out', 'qkv_out', 'scores', 'av_out',
                  'ffn_up_out', 'gelu_out', 'ln_var_min', 'ln_var_max'}
      'weight_max': {'c_attn', 'attn_proj', 'ffn_up', 'ffn_down',
                     'wte_wpe', 'ln_gain'}
      'residual_per_layer': list of L segment maxima —
                     max(|x_in(l)|, |attn_block_out(l)|, |ffn_block_out(l)|),
                     x_in(0) = embed_out (per-layer residual scales)
      'ln_var_min_per_ln' / 'ln_var_max_per_ln': lists of 2L+1 floats in the
                     order ln1(0), ln2(0), …, ln1(L-1), ln2(L-1), ln_f
      'argmax_last': int, 'logits_last': float64 (vocab,).
    """
    t = len(tokens)
    act = {
        "residual": 0.0,
        "ln_out": 0.0,
        "qkv_out": 0.0,
        "scores": 0.0,
        "av_out": 0.0,
        "ffn_up_out": 0.0,
        "gelu_out": 0.0,
        "ln_var_min": math.inf,
        "ln_var_max": 0.0,
    }

    per_ln: dict = {"min": [], "max": []}
    seg_max: list = []

    x = fw["wte"][np.asarray(tokens)] + fw["wpe"][0:t]
    act["residual"] = _mx(act["residual"], x)  # embed_out is on the residual stream

    cur = x
    for lw in fw["layers"]:
        cur = _forward_layer_f(cur, lw, n_head, act, per_ln, seg_max)

    fin = _layer_norm_f(cur[-1:], fw["lnf_gain"], fw["lnf_bias"], act, per_ln)[0]
    logits = fin @ fw["wte"].T

    wmax = {
        "c_attn": 0.0,
        "attn_proj": 0.0,
        "ffn_up": 0.0,
        "ffn_down": 0.0,
        "wte_wpe": max(float(np.max(np.abs(fw["wte"]))), float(np.max(np.abs(fw["wpe"])))),
        "ln_gain": float(np.max(np.abs(fw["lnf_gain"]))),
    }
    for lw in fw["layers"]:
        for key in ("c_attn", "attn_proj", "ffn_up", "ffn_down"):
            wmax[key] = _mx(wmax[key], lw[key])
        wmax["ln_gain"] = max(wmax["ln_gain"], _mx(_mx(0.0, lw["ln1_gain"]), lw["ln2_gain"]))

    return {
        "act_max": act,
        "weight_max": wmax,
        "residual_per_layer": seg_max,
        "ln_var_min_per_ln": per_ln["min"],
        "ln_var_max_per_ln": per_ln["max"],
        "argmax_last": int(np.argmax(logits)),
        "logits_last": logits,
    }


# ---------------------------------------------------------------------------
# Smoke test with random small weights (no real safetensors dependency)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rng = np.random.default_rng(0)
    d, dff, n_head, vocab, n_layer = 8, 16, 2, 37, 2

    def rand_layer() -> dict:
        return {
            "c_attn": rng.normal(0, 0.1, (d, 3 * d)),
            "c_attn_bias": rng.normal(0, 0.1, 3 * d),
            "attn_proj": rng.normal(0, 0.1, (d, d)),
            "attn_proj_bias": rng.normal(0, 0.1, d),
            "ffn_up": rng.normal(0, 0.1, (d, dff)),
            "ffn_up_bias": rng.normal(0, 0.1, dff),
            "ffn_down": rng.normal(0, 0.1, (dff, d)),
            "ffn_down_bias": rng.normal(0, 0.1, d),
            "ln1_gain": np.ones(d) + rng.normal(0, 0.01, d),
            "ln1_bias": rng.normal(0, 0.01, d),
            "ln2_gain": np.ones(d) + rng.normal(0, 0.01, d),
            "ln2_bias": rng.normal(0, 0.01, d),
        }

    fw = {
        "wte": rng.normal(0, 0.1, (vocab, d)),
        "wpe": rng.normal(0, 0.1, (16, d)),
        "layers": [rand_layer() for _ in range(n_layer)],
        "lnf_gain": np.ones(d) + rng.normal(0, 0.01, d),
        "lnf_bias": rng.normal(0, 0.01, d),
    }

    tokens = rng.integers(0, vocab, size=6)
    out = forward_model(tokens, fw, n_head=n_head)
    assert out["logits_last"].shape == (vocab,)
    assert 0 <= out["argmax_last"] < vocab
    assert 0.0 < out["act_max"]["ln_var_min"] <= out["act_max"]["ln_var_max"]
    assert len(out["residual_per_layer"]) == n_layer
    assert len(out["ln_var_min_per_ln"]) == 2 * n_layer + 1
    assert len(out["ln_var_max_per_ln"]) == 2 * n_layer + 1
    assert min(out["ln_var_min_per_ln"]) == out["act_max"]["ln_var_min"]
    assert max(out["ln_var_max_per_ln"]) == out["act_max"]["ln_var_max"]
    print("smoke test OK, argmax_last =", out["argmax_last"])
    print("residual_per_layer:", [round(v, 4) for v in out["residual_per_layer"]])
    print("act_max:")
    for k, v in sorted(out["act_max"].items()):
        print(f"  {k:<12} {v:.6f}")
    print("weight_max:")
    for k, v in sorted(out["weight_max"].items()):
        print(f"  {k:<12} {v:.6f}")

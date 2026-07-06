"""Numpy mirror of the fixed-point GPT-2 forward pass (P4 witness generator).

Every value here must match rust/volta-gpt2/src/layer.rs and
rust/volta-gpt2/src/luts.rs bit-for-bit; see docs/quantization-spec.md for the
arithmetic contract. This module does NOT record lookup streams/multiplicities
(only per-table counts, computed arithmetically) — the Rust `LookupTrace`
machinery is P4 prover-internal and out of scope here.

P5 extensions beyond the current Rust layer (consumed by
scripts/export_gpt2.py, which is the interface contract):
  * per-GEMM biases folded into the accumulator at the requant OUTPUT scale
    (`acc += bias << shift`, linear — no extra lookup);
  * `requant_embed`: embed_out = requant(wte[tok] + wpe[pos], shift_embed)
    (the 13th table, P5 deviation);
  * stable shifted softmax (`p['softmax_row_shift']`): per causal row,
    c = max(s_row), exp is looked up on (s − c) & 0xFFFF. With the flag off
    the P4-mirror behavior is byte-identical to the Rust forward.

Two pitfalls that numpy gets wrong by default, called out because they are
silent bit-flips rather than crashes:
  * `np.round` is banker's rounding; Rust `f64::round()` rounds half AWAY FROM
    ZERO. Use `round_away` (mirrors luts.rs `.round()`).
  * numpy's `>>` on int64 is arithmetic (sign-extending) — same as Rust's `>>`
    on i64 — so plain `>>` is fine for requant, but note it explicitly at each
    call site since getting this wrong is the classic bug.

Stdlib + numpy only (no other deps), per project convention.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# Shape constants (rust/volta-gpt2/src/layer.rs)
# ---------------------------------------------------------------------------

D = 768
H = 12
DH = 64
DFF = 3072

I16_MIN = -32768
I16_MAX = 32767
U64_MASK = 0xFFFF_FFFF_FFFF_FFFF

TABLE_LEN = 1 << 16

# Budget order (layer.rs TableId::ALL / budget_p0.py keys).
TABLE_NAMES = [
    "ln_rsqrt",
    "ln_norm_requant",
    "requant_qkv",
    "requant_scores",
    "exp",
    "softmax_recip",
    "softmax_norm_requant",
    "requant_av",
    "requant_attn_proj",
    "requant_ffn_up",
    "gelu",
    "requant_ffn_down",
]


def round_away(v: float) -> int:
    """Round half away from zero — matches Rust `f64::round()` exactly.

    numpy's `np.round` is banker's rounding (round-half-to-even) and must
    never be used in place of this for LUT construction.
    """
    if v >= 0:
        return math.floor(v + 0.5)
    return math.ceil(v - 0.5)


def div_round(num: int, den: int) -> int:
    """Round-half-up integer division for non-negative operands (luts.rs)."""
    return (num + den // 2) // den


# ---------------------------------------------------------------------------
# LutParams (luts.rs)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LutParams:
    ln_var_shift: int = 7
    ln_rsqrt_log2: int = 18
    shift_ln_norm: int = 16
    exp_in_log2: int = 10
    exp_out_log2: int = 12
    recip_den_shift: int = 6
    recip_log2: int = 26
    gelu_scale_log2: int = 10
    shift_qkv: int = 10
    shift_scores: int = 10
    shift_softmax_norm: int = 14
    shift_av: int = 12
    shift_attn_proj: int = 10
    shift_ffn_up: int = 10
    shift_ffn_down: int = 10


def build_luts_p4(params: LutParams) -> dict:
    """Mirror of luts.rs `build_luts`, exactly, for cross-validation.

    Returns a dict with keys "exp", "gelu", "ln_rsqrt", "softmax_recip"
    (numpy int16 arrays of length 65536) and "params". (The real calibrated
    tables are built by scripts/export_gpt2.py — this one reproduces the P4
    synthetic tables, base-2 exp on the full signed domain.)
    """
    exp_in = float(1 << params.exp_in_log2)
    exp_out = float(1 << params.exp_out_log2)
    gelu_s = float(1 << params.gelu_scale_log2)

    exp_tab = np.zeros(TABLE_LEN, dtype=np.int16)
    gelu_tab = np.zeros(TABLE_LEN, dtype=np.int16)
    ln_rsqrt_tab = np.zeros(TABLE_LEN, dtype=np.int16)
    softmax_recip_tab = np.zeros(TABLE_LEN, dtype=np.int16)

    for u in range(TABLE_LEN):
        x = u - 65536 if u >= 32768 else u  # i16 bit pattern reinterpretation

        # exp[x] = round(2^out * 2^(x/2^in)), saturating at i16::MAX.
        ev = round_away(exp_out * (2.0 ** (x / exp_in)))
        exp_tab[u] = min(ev, I16_MAX)

        # gelu[x] = round(gelu(x/2^s) * 2^s), tanh approximation.
        xr = x / gelu_s
        g = 0.5 * xr * (1.0 + math.tanh(0.7978845608028654 * (xr + 0.044715 * xr * xr * xr)))
        gv = round_away(g * gelu_s)
        gelu_tab[u] = max(I16_MIN, min(I16_MAX, gv))

        # ln_rsqrt[v]: var_back = (v+1) << ln_var_shift; s = isqrt(var_back);
        # div_round(2^R, s), min i16::MAX.
        var_back = (u + 1) << params.ln_var_shift
        s = math.isqrt(var_back)
        ln_rsqrt_tab[u] = min(div_round(1 << params.ln_rsqrt_log2, s), I16_MAX)

        # softmax_recip[v]: den_back = (v << den_shift) + 2^(den_shift-1);
        # div_round(2^R, den_back), min i16::MAX.
        den_back = (u << params.recip_den_shift) + (1 << (params.recip_den_shift - 1))
        softmax_recip_tab[u] = min(div_round(1 << params.recip_log2, den_back), I16_MAX)

    return {
        "exp": exp_tab,
        "gelu": gelu_tab,
        "ln_rsqrt": ln_rsqrt_tab,
        "softmax_recip": softmax_recip_tab,
        "params": params,
    }


# ---------------------------------------------------------------------------
# splitmix64 + synthetic data (layer.rs)
# ---------------------------------------------------------------------------


def splitmix64(state: list[int]) -> int:
    """splitmix64 step. `state` is a 1-element list used as a mutable u64 cell."""
    state[0] = (state[0] + 0x9E3779B97F4A7C15) & U64_MASK
    z = state[0]
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & U64_MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & U64_MASK
    return (z ^ (z >> 31)) & U64_MASK


@dataclass
class LayerWeights:
    c_attn: np.ndarray  # D x 3D, int16
    attn_proj: np.ndarray  # D x D
    ffn_up: np.ndarray  # D x DFF
    ffn_down: np.ndarray  # DFF x D
    ln1_gain: np.ndarray  # D
    ln1_bias: np.ndarray  # D
    ln2_gain: np.ndarray  # D
    ln2_bias: np.ndarray  # D


def synthetic_weights(seed: int) -> LayerWeights:
    """Mirror of layer.rs synthetic_weights. PRNG state is threaded
    sequentially: c_attn, attn_proj, ffn_up, ffn_down (mat closure), then
    ln1_gain, ln2_gain (gains closure), then ln1_bias, ln2_bias (biases
    closure) — order matters, it is one shared stream.
    """
    st = [seed & U64_MASK]

    def mat(length: int) -> np.ndarray:
        return np.array(
            [(splitmix64(st) % 127) - 63 for _ in range(length)], dtype=np.int16
        )

    c_attn = mat(D * 3 * D).reshape(D, 3 * D)
    attn_proj = mat(D * D).reshape(D, D)
    ffn_up = mat(D * DFF).reshape(D, DFF)
    ffn_down = mat(DFF * D).reshape(DFF, D)

    def gains(length: int) -> np.ndarray:
        return np.array(
            [48 + (splitmix64(st) % 33) for _ in range(length)], dtype=np.int16
        )

    ln1_gain = gains(D)
    ln2_gain = gains(D)

    def biases(length: int) -> np.ndarray:
        return np.array(
            [(splitmix64(st) % 256) - 128 for _ in range(length)], dtype=np.int16
        )

    ln1_bias = biases(D)
    ln2_bias = biases(D)

    return LayerWeights(
        c_attn=c_attn,
        attn_proj=attn_proj,
        ffn_up=ffn_up,
        ffn_down=ffn_down,
        ln1_gain=ln1_gain,
        ln1_bias=ln1_bias,
        ln2_gain=ln2_gain,
        ln2_bias=ln2_bias,
    )


def synthetic_input(seed: int, t: int) -> np.ndarray:
    """Mirror of layer.rs synthetic_input. Returns int16 array of shape (t, D)."""
    st = [(seed ^ 0xA5A5A5A5A5A5A5A5) & U64_MASK]
    vals = [(splitmix64(st) % 2048) - 1024 for _ in range(t * D)]
    return np.array(vals, dtype=np.int16).reshape(t, D)


# ---------------------------------------------------------------------------
# Stats + requant helpers
# ---------------------------------------------------------------------------


class SaturationError(Exception):
    pass


def _stat(stats: dict, name: str, max_abs: int, saturated: bool) -> None:
    """Stats entry format is the export_gpt2.py contract:
    stats[site] = {"saturated": bool, "max_abs": int}."""
    e = stats.setdefault(name, {"saturated": False, "max_abs": 0})
    if max_abs > e["max_abs"]:
        e["max_abs"] = int(max_abs)
    e["saturated"] = e["saturated"] or bool(saturated)


def _merge_stats(dst: dict, src: dict) -> None:
    for k, v in src.items():
        _stat(dst, k, v["max_abs"], v["saturated"])


def _params_view(p):
    """Accept a LutParams dataclass or the export_gpt2.py params dict
    (which additionally carries shift_embed, softmax_row_shift, f_*)."""
    if isinstance(p, dict):
        return SimpleNamespace(**p)
    return p


def _round_shift(acc, shift: int):
    """One round-half-up arithmetic shift stage (no range constraint).
    numpy int64 >> and python int >> are both arithmetic/floor — correct."""
    return (acc + (1 << (shift - 1))) >> shift


def requant_chain(acc, shift: int):
    """Requant rounding value (pre-i16-check). shift <= 16: the single
    round-half-up shift, byte-identical to the P4 path. shift > 16: chained
    double-round semantics (spec P5) — stage 1 rounds by (shift - 16) with
    NO i16 constraint on its output, stage 2 rounds by 16 (the usual i16
    check applies to its output only)."""
    if shift <= 16:
        return _round_shift(acc, shift)
    return _round_shift(_round_shift(acc, shift - 16), 16)


def _requant(acc, shift: int, name: str, mode: str, stats: dict):
    """Requant via `requant_chain` + i16 check on the final output. `acc`
    may be a python int or a numpy int64 array. Returns int16 (array or
    python int) matching shape. Always records {saturated, max_abs} into
    stats[name] (one entry per logical site, final output max); in 'strict'
    mode raises SaturationError on out-of-i16-range values (mirrors the
    Rust panic), in 'stats' mode clamps to continue but keeps the true max.
    """
    rounded = requant_chain(acc, shift)
    if isinstance(rounded, np.ndarray):
        lo, hi = int(rounded.min()), int(rounded.max())
    else:
        lo = hi = int(rounded)
    sat = lo < I16_MIN or hi > I16_MAX
    _stat(stats, name, max(abs(lo), abs(hi)), sat)
    if sat:
        if mode == "strict":
            raise SaturationError(
                f"requant saturated in {name} (no-clamp deviation violated): "
                f"min={lo}, max={hi}, shift={shift}"
            )
        rounded = np.clip(rounded, I16_MIN, I16_MAX) if isinstance(rounded, np.ndarray) else max(
            I16_MIN, min(I16_MAX, rounded)
        )
    return rounded.astype(np.int16) if isinstance(rounded, np.ndarray) else int(rounded)


def _residual_add(a: np.ndarray, b: np.ndarray, mode: str, stats: dict) -> np.ndarray:
    s = a.astype(np.int32) + b.astype(np.int32)
    lo, hi = int(s.min()), int(s.max())
    sat = lo < I16_MIN or hi > I16_MAX
    _stat(stats, "residual_add", max(abs(lo), abs(hi)), sat)
    if sat:
        if mode == "strict":
            raise SaturationError("residual add overflows i16 (no-clamp deviation violated)")
        s = np.clip(s, I16_MIN, I16_MAX)
    return s.astype(np.int16)


def _lut_index_checked(idx: int, name: str, mode: str, stats: dict) -> int:
    """u16-domain index sites (ln_rsqrt_index / softmax_recip_index):
    saturated means idx >= 2^16; max_abs is the max index seen."""
    sat = idx >= (1 << 16)
    _stat(stats, name, idx, sat)
    if sat:
        if mode == "strict":
            raise SaturationError(f"{name} exceeds u16 domain: {idx}")
        idx = (1 << 16) - 1
    return idx


# ---------------------------------------------------------------------------
# LayerNorm
# ---------------------------------------------------------------------------


@dataclass
class LnOut:
    mean: np.ndarray  # T, int64
    var: np.ndarray  # T, int64
    rsqrt_in: np.ndarray  # T, int64
    rsqrt_out: np.ndarray  # T, int16
    out: np.ndarray  # T x D, int16


def layer_norm(x: np.ndarray, gain: np.ndarray, bias: np.ndarray, luts: dict, p, t: int, mode: str, stats: dict) -> LnOut:
    """Mirror of layer.rs `layer_norm`, row by row. Per-row scalar reductions
    use python ints (D=768 keeps them well within int64 anyway)."""
    d = x.shape[1]
    means = np.zeros(t, dtype=np.int64)
    variances = np.zeros(t, dtype=np.int64)
    rsqrt_in = np.zeros(t, dtype=np.int64)
    rsqrt_out = np.zeros(t, dtype=np.int16)
    out = np.zeros((t, d), dtype=np.int16)

    ln_rsqrt = luts["ln_rsqrt"]

    for i in range(t):
        row = x[i].astype(np.int64)
        s = int(row.sum())
        m = (s + d // 2) // d  # div_euclid(d) with d>0 == floor division == python //
        dev = row - m
        var_sum = int(np.sum(dev * dev))
        vr = (var_sum + d // 2) // d

        vin = _lut_index_checked(vr >> p.ln_var_shift, "ln_rsqrt_index", mode, stats)
        r = int(ln_rsqrt[vin])
        _stat(stats, "ln_rsqrt", abs(r), False)  # LUT output, always fits i16

        acc = dev * np.int64(r) * gain.astype(np.int64) + (
            bias.astype(np.int64) << p.shift_ln_norm
        )
        out[i, :] = _requant(acc, p.shift_ln_norm, "ln_norm_requant", mode, stats)

        means[i] = m
        variances[i] = vr
        rsqrt_in[i] = vin
        rsqrt_out[i] = r

    return LnOut(mean=means, var=variances, rsqrt_in=rsqrt_in, rsqrt_out=rsqrt_out, out=out)


# ---------------------------------------------------------------------------
# forward_layer
# ---------------------------------------------------------------------------


def forward_layer(
    x_in: np.ndarray,
    w: LayerWeights,
    luts: dict,
    t: int,
    mode: str = "strict",
    p=None,
    c_attn_bias: Optional[np.ndarray] = None,
    attn_proj_bias: Optional[np.ndarray] = None,
    ffn_up_bias: Optional[np.ndarray] = None,
    ffn_down_bias: Optional[np.ndarray] = None,
) -> dict:
    """Mirror of layer.rs forward_layer, value-for-value.

    x_in: (t, D) int16. w: LayerWeights. luts: dict of the 4 int16 tables.
    p: LutParams or the export_gpt2.py params dict; defaults to
    luts["params"] (the build_luts_p4 packaging).
    mode: 'strict' (raise on saturation, mirrors the Rust panic) or 'stats'
    (clamp to continue). Stats {site: {saturated, max_abs}} are collected in
    BOTH modes and returned under "stats".

    P5 extensions (see module docstring): optional biases folded in at the
    requant OUTPUT scale before each requant, and the stable shifted softmax
    when p carries softmax_row_shift=True. With biases None and the flag
    absent/false this reproduces the current Rust exactly; "row_shift" is
    then all zeros (no shift applied).
    """
    assert x_in.shape == (t, D)
    pv = _params_view(p if p is not None else luts["params"])
    # Per-layer shift lists are unpacked by forward_model; a list arriving
    # here means a caller forgot to select its layer's scalar — hard error.
    for _n in ("shift_attn_proj", "shift_ffn_down"):
        assert not isinstance(getattr(pv, _n), (list, tuple)), (
            f"{_n} must be a scalar in forward_layer "
            "(forward_model selects the per-layer entry)"
        )
    row_shift_on = bool(getattr(pv, "softmax_row_shift", False))
    caus = t * (t + 1) // 2
    stats: dict = {}

    # ---- LN1 ----
    ln1 = layer_norm(x_in, w.ln1_gain, w.ln1_bias, luts, pv, t, mode, stats)

    # ---- fused QKV projection ----
    qkv_acc = ln1.out.astype(np.int64) @ w.c_attn.astype(np.int64)  # t x 3D
    if c_attn_bias is not None:
        qkv_acc = qkv_acc + (c_attn_bias.astype(np.int64) << pv.shift_qkv)
    qkv_q = _requant(qkv_acc, pv.shift_qkv, "requant_qkv", mode, stats)
    q = qkv_q[:, 0:D].copy()
    k = qkv_q[:, D:2 * D].copy()
    v = qkv_q[:, 2 * D:3 * D].copy()

    # ---- per-head causal attention ----
    exp_tab = luts["exp"]
    softmax_recip_tab = luts["softmax_recip"]

    denoms = np.zeros((H, t), dtype=np.int64)
    recips = np.zeros((H, t), dtype=np.int16)
    row_shift = np.zeros((H, t), dtype=np.int64)
    av_acc = np.zeros((t, D), dtype=np.int64)
    av_q = np.zeros((t, D), dtype=np.int16)

    scores_acc_list = []
    scores_q_list = []
    exp_out_list = []

    for head in range(H):
        qh = q[:, head * DH:(head + 1) * DH].astype(np.int64)  # t x DH
        kh = k[:, head * DH:(head + 1) * DH].astype(np.int64)  # t x DH
        s_full = qh @ kh.T  # t x t, int64

        w_pad = np.zeros((t, t), dtype=np.int16)

        for i in range(t):
            row_acc = s_full[i, 0:i + 1]
            s_row = np.atleast_1d(
                _requant(row_acc, pv.shift_scores, "requant_scores", mode, stats)
            )
            # Stable shifted softmax (P5): c = row max, exp on (s - c). With
            # c = 0 (flag off) this is byte-identical to the P4 Rust path.
            c = int(s_row.max()) if row_shift_on else 0
            row_shift[head, i] = c
            e_row = exp_tab[((s_row.astype(np.int64) - c) & 0xFFFF)]
            _stat(stats, "exp", int(np.max(np.abs(e_row))), False)

            scores_acc_list.extend(row_acc.tolist())
            scores_q_list.extend(s_row.tolist())
            exp_out_list.extend(e_row.tolist())

            denom = int(np.sum(e_row.astype(np.int64)))
            rin = _lut_index_checked(
                denom >> pv.recip_den_shift, "softmax_recip_index", mode, stats
            )
            rc = int(softmax_recip_tab[rin])
            _stat(stats, "softmax_recip", abs(rc), False)
            denoms[head, i] = denom
            recips[head, i] = rc

            wq_row = np.atleast_1d(
                _requant(
                    e_row.astype(np.int64) * np.int64(rc),
                    pv.shift_softmax_norm,
                    "softmax_norm_requant",
                    mode,
                    stats,
                )
            )
            w_pad[i, 0:i + 1] = wq_row

        vh = v[:, head * DH:(head + 1) * DH].astype(np.int64)
        avh = w_pad.astype(np.int64) @ vh  # t x DH
        av_acc[:, head * DH:(head + 1) * DH] = avh
        av_q[:, head * DH:(head + 1) * DH] = _requant(avh, pv.shift_av, "requant_av", mode, stats)

    scores_acc = np.array(scores_acc_list, dtype=np.int64)
    scores_q = np.array(scores_q_list, dtype=np.int16)
    exp_out = np.array(exp_out_list, dtype=np.int16)

    # ---- attention output projection + residual ----
    proj_acc = av_q.astype(np.int64) @ w.attn_proj.astype(np.int64)
    if attn_proj_bias is not None:
        proj_acc = proj_acc + (attn_proj_bias.astype(np.int64) << pv.shift_attn_proj)
    attn_proj_q = _requant(proj_acc, pv.shift_attn_proj, "requant_attn_proj", mode, stats)
    attn_block_out = _residual_add(x_in, attn_proj_q, mode, stats)

    # ---- LN2 ----
    ln2 = layer_norm(attn_block_out, w.ln2_gain, w.ln2_bias, luts, pv, t, mode, stats)

    # ---- FFN ----
    ffn_up_acc = ln2.out.astype(np.int64) @ w.ffn_up.astype(np.int64)
    if ffn_up_bias is not None:
        ffn_up_acc = ffn_up_acc + (ffn_up_bias.astype(np.int64) << pv.shift_ffn_up)
    ffn_up_q = _requant(ffn_up_acc, pv.shift_ffn_up, "requant_ffn_up", mode, stats)

    gelu_out = luts["gelu"][(ffn_up_q.astype(np.int64) & 0xFFFF)].astype(np.int16)
    _stat(stats, "gelu", int(np.max(np.abs(gelu_out))), False)

    ffn_down_acc = gelu_out.astype(np.int64) @ w.ffn_down.astype(np.int64)
    if ffn_down_bias is not None:
        ffn_down_acc = ffn_down_acc + (ffn_down_bias.astype(np.int64) << pv.shift_ffn_down)
    ffn_down_q = _requant(ffn_down_acc, pv.shift_ffn_down, "requant_ffn_down", mode, stats)
    ffn_block_out = _residual_add(attn_block_out, ffn_down_q, mode, stats)

    lookup_counts = {
        "ln_rsqrt": 2 * t,
        "ln_norm_requant": 2 * t * D,
        "requant_qkv": 3 * t * D,
        "requant_scores": H * caus,
        "exp": H * caus,
        "softmax_recip": H * t,
        "softmax_norm_requant": H * caus,
        "requant_av": t * D,
        "requant_attn_proj": t * D,
        "requant_ffn_up": t * DFF,
        "gelu": t * DFF,
        "requant_ffn_down": t * D,
    }

    return {
        "t": t,
        "x_in": x_in,
        "k": k,
        "v": v,
        "q": q,
        "attn_block_out": attn_block_out,
        "ffn_block_out": ffn_block_out,
        "ln1_out": ln1.out,
        "ln1_mean": ln1.mean,
        "ln1_var": ln1.var,
        "ln1_rsqrt_in": ln1.rsqrt_in,
        "ln1_rsqrt_out": ln1.rsqrt_out,
        "ln2_out": ln2.out,
        "ln2_mean": ln2.mean,
        "ln2_var": ln2.var,
        "ln2_rsqrt_in": ln2.rsqrt_in,
        "ln2_rsqrt_out": ln2.rsqrt_out,
        "qkv_acc": qkv_acc,
        "scores_acc": scores_acc,
        "scores_q": scores_q,
        "exp_out": exp_out,
        "denoms": denoms,
        "recips": recips,
        "row_shift": row_shift,
        "av_acc": av_acc,
        "av_q": av_q,
        "proj_acc": proj_acc,
        "attn_proj_q": attn_proj_q,
        "ffn_up_acc": ffn_up_acc,
        "ffn_up_q": ffn_up_q,
        "gelu_out": gelu_out,
        "ffn_down_acc": ffn_down_acc,
        "ffn_down_q": ffn_down_q,
        "lookup_counts": lookup_counts,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Full-model helpers (P5)
# ---------------------------------------------------------------------------


def embed(tokens, wte: np.ndarray, wpe: np.ndarray, p, mode: str = "strict", stats: Optional[dict] = None) -> np.ndarray:
    """embed_out = requant(wte[tok] + wpe[pos], shift_embed) — the P5
    `requant_embed` table (13th table deviation). shift_embed may be <= 0
    (segment-0 residual scale finer than f_wte): then the op is an exact
    LEFT shift by -shift_embed — linear, no lookup — but the i16 check and
    the 'requant_embed' stats site still apply to the result."""
    if stats is None:
        stats = {}
    pv = _params_view(p)
    t = len(tokens)
    acc = wte[np.asarray(tokens)].astype(np.int64) + wpe[0:t].astype(np.int64)
    s = pv.shift_embed
    if s > 0:
        return _requant(acc, s, "requant_embed", mode, stats)
    shifted = acc << (-s)
    lo, hi = int(shifted.min()), int(shifted.max())
    sat = lo < I16_MIN or hi > I16_MAX
    _stat(stats, "requant_embed", max(abs(lo), abs(hi)), sat)
    if sat:
        if mode == "strict":
            raise SaturationError(
                f"embed left-shift overflows i16: min={lo}, max={hi}, shift={s}"
            )
        shifted = np.clip(shifted, I16_MIN, I16_MAX)
    return shifted.astype(np.int16)


def final_ln_row(x_row: np.ndarray, gain: np.ndarray, bias: np.ndarray, luts: dict, p, mode: str = "strict", stats: Optional[dict] = None) -> np.ndarray:
    """LN of a single row (same math and tables/shift as the layer LN)."""
    if stats is None:
        stats = {}
    pv = _params_view(p)
    d = x_row.shape[0]
    out = layer_norm(x_row.reshape(1, d), gain, bias, luts, pv, 1, mode, stats)
    return out.out[0]


def logits_row(fin_row: np.ndarray, wte: np.ndarray) -> np.ndarray:
    """int64 fin_row @ wte.T -> int64 vector length vocab."""
    return fin_row.astype(np.int64) @ wte.astype(np.int64).T


def forward_model(tokens, model, luts, p, mode: str = "strict") -> dict:
    """Full fixed-point model: embed -> L layers -> final LN (last position)
    -> logits. Interface contract: scripts/export_gpt2.py.

    model: {"layers": [L dicts with keys c_attn, c_attn_bias, attn_proj,
    attn_proj_bias, ffn_up, ffn_up_bias, ffn_down, ffn_down_bias, ln1_gain,
    ln1_bias, ln2_gain, ln2_bias — all numpy i16], "wte", "wpe", "lnf_gain",
    "lnf_bias"}. luts: the 4 int16 tables. p: params dict (LutParams fields
    + shift_embed + softmax_row_shift; f_* entries ignored).

    Per-layer residual scales (P5 iteration 2): p['shift_attn_proj'] and
    p['shift_ffn_down'] may be lists of L (layer l gets its scalar entry);
    p['seam_shifts'] (list of L-1) requants layer l's output down to layer
    l+1's coarser segment scale — seam shift 0 is a free pass-through.

    Returns {"logits": int64 (vocab,), "stats": {site: {saturated, max_abs}}
    merged across layers (seams aggregate under 'seam_requant'), "layers":
    per-layer forward_layer results, "embed_out", "final_ln_out"}.
    """
    t = len(tokens)
    n_layers = len(model["layers"])
    stats: dict = {}
    p_dict = dict(p) if isinstance(p, dict) else p
    seam_shifts = (p_dict.get("seam_shifts") if isinstance(p_dict, dict) else None) or [0] * (n_layers - 1)

    x = embed(tokens, model["wte"], model["wpe"], p, mode, stats)

    layer_results = []
    cur = x
    for l, lw in enumerate(model["layers"]):
        # Select layer l's scalar shifts out of the per-layer lists (scalars
        # pass through unchanged).
        if isinstance(p_dict, dict):
            p_layer = {
                **p_dict,
                **{
                    key: p_dict[key][l]
                    for key in ("shift_attn_proj", "shift_ffn_down")
                    if isinstance(p_dict.get(key), (list, tuple))
                },
            }
        else:
            p_layer = p_dict
        w = LayerWeights(
            c_attn=lw["c_attn"],
            attn_proj=lw["attn_proj"],
            ffn_up=lw["ffn_up"],
            ffn_down=lw["ffn_down"],
            ln1_gain=lw["ln1_gain"],
            ln1_bias=lw["ln1_bias"],
            ln2_gain=lw["ln2_gain"],
            ln2_bias=lw["ln2_bias"],
        )
        res = forward_layer(
            cur,
            w,
            luts,
            t,
            mode=mode,
            p=p_layer,
            c_attn_bias=lw.get("c_attn_bias"),
            attn_proj_bias=lw.get("attn_proj_bias"),
            ffn_up_bias=lw.get("ffn_up_bias"),
            ffn_down_bias=lw.get("ffn_down_bias"),
        )
        _merge_stats(stats, res["stats"])
        layer_results.append(res)
        cur = res["ffn_block_out"]
        # Seam requant to the next segment's coarser residual scale.
        if l < n_layers - 1 and seam_shifts[l] > 0:
            cur = _requant(cur.astype(np.int64), seam_shifts[l], "seam_requant", mode, stats)

    fin = final_ln_row(cur[-1], model["lnf_gain"], model["lnf_bias"], luts, p, mode, stats)
    logits = logits_row(fin, model["wte"])

    return {
        "layers": layer_results,
        "embed_out": x,
        "final_ln_out": fin,
        "logits": logits,
        "stats": stats,
    }

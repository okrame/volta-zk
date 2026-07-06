"""P5 weight export + quantization calibration for GPT-2 small.

Reads `benchmarks/weights/model.safetensors` (HF gpt2, downloaded one-off),
picks power-of-two scales (docs/quantization-spec.md), calibrates the global
shift set on the golden prompt, and freezes the artifact that the Rust prover
and the numpy reference both consume:

  benchmarks/weights/gpt2s-q.bin   raw little-endian i16 tensors + the 4 LUTs
  benchmarks/weights/gpt2s-q.json  manifest: shapes/offsets, LutParams,
                                   exponents, prompt tokens, calibration report

Scale design (all scales are powers of two; `f_*` = fraction bits):
  - ONE shift/LUT set for the whole model — per-layer tables would break the
    one-multiset-per-table-per-model amortization (ledger 2026-07-06 #1d).
  - weight exponents are per tensor-TYPE (max |w| across the 12 layers).
  - biases are quantized at the OUTPUT scale of their op and folded into the
    accumulator as `acc += b << shift` before the requant lookup (linear).
  - wte is tied (embedding + logits weight) and gets its own scale f_wte;
    embed_out = wte[tok] + wpe[pos] is requantized to the residual scale
    f_res through a NEW `requant_embed` table (P5 deviation: 13th table,
    T*d extra lookups).
  - softmax is the STABLE shifted form (P5 deviation): s' = s - c_row with
    c_row = max of the causal row; exp LUT is base-e, faithful on x <= 0 and
    0 on x > 0 (the nonpositive table domain is what the protocol range-checks;
    the row-zero existence check is the prover's job, not the reference's).

Run:  .venv/bin/python scripts/export_gpt2.py [--prompt-file FILE] [--t 100]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
import gpt2_fixed  # noqa: E402  (numpy fixed-point reference, bit-exact mirror)
import gpt2_float  # noqa: E402  (float reference, calibration ranges)

REPO = Path(__file__).resolve().parent.parent
WDIR = REPO / "benchmarks" / "weights"
SAFETENSORS = WDIR / "model.safetensors"

L, D, H, DFF, VOCAB, NPOS = 12, 768, 12, 3072, 50257, 1024

# The golden prompt (public-domain, deterministic). Encoded with tiktoken
# "gpt2" and truncated to exactly --t tokens; the ids are frozen in the JSON,
# so tiktoken is only an export-time dependency.
GOLDEN_TEXT = (
    "It was the best of times, it was the worst of times, it was the age of "
    "wisdom, it was the age of foolishness, it was the epoch of belief, it "
    "was the epoch of incredulity, it was the season of Light, it was the "
    "season of Darkness, it was the spring of hope, it was the winter of "
    "despair, we had everything before us, we had nothing before us, we were "
    "all going direct to Heaven, we were all going direct the other way - in "
    "short, the period was so far like the present period, that some of its "
    "noisiest authorities insisted on its being received, for good or for "
    "evil, in the superlative degree of comparison only."
)


# ---------------------------------------------------------------------------
# safetensors parsing (no torch, no safetensors dep: 8B header len + JSON)
# ---------------------------------------------------------------------------

def load_safetensors(path: Path) -> dict[str, np.ndarray]:
    blob = path.read_bytes()
    (hlen,) = struct.unpack_from("<Q", blob, 0)
    hdr = json.loads(blob[8 : 8 + hlen])
    base = 8 + hlen
    out = {}
    for name, meta in hdr.items():
        if name == "__metadata__":
            continue
        assert meta["dtype"] == "F32", (name, meta["dtype"])
        b0, b1 = meta["data_offsets"]
        arr = np.frombuffer(blob, dtype="<f4", count=(b1 - b0) // 4, offset=base + b0)
        out[name] = arr.reshape(meta["shape"]).astype(np.float64)
    return out


def gpt2_float_weights(st: dict[str, np.ndarray]) -> dict:
    """HF names -> our layout (Conv1D weights are already in-major in x out)."""
    layers = []
    for i in range(L):
        p = f"h.{i}."
        layers.append(
            {
                "ln1_gain": st[p + "ln_1.weight"], "ln1_bias": st[p + "ln_1.bias"],
                "c_attn": st[p + "attn.c_attn.weight"], "c_attn_bias": st[p + "attn.c_attn.bias"],
                "attn_proj": st[p + "attn.c_proj.weight"], "attn_proj_bias": st[p + "attn.c_proj.bias"],
                "ln2_gain": st[p + "ln_2.weight"], "ln2_bias": st[p + "ln_2.bias"],
                "ffn_up": st[p + "mlp.c_fc.weight"], "ffn_up_bias": st[p + "mlp.c_fc.bias"],
                "ffn_down": st[p + "mlp.c_proj.weight"], "ffn_down_bias": st[p + "mlp.c_proj.bias"],
            }
        )
    return {
        "layers": layers,
        "wte": st["wte.weight"], "wpe": st["wpe.weight"],
        "lnf_gain": st["ln_f.weight"], "lnf_bias": st["ln_f.bias"],
    }


# ---------------------------------------------------------------------------
# quantization helpers
# ---------------------------------------------------------------------------

I16MAX = 32767


def round_away(a: np.ndarray) -> np.ndarray:
    """f64 round half away from zero (Rust f64::round / spec convention)."""
    return np.where(a >= 0, np.floor(a + 0.5), np.ceil(a - 0.5))


def frac_bits_for(max_abs: float, headroom_bits: int = 0) -> int:
    """Largest f with max_abs * 2^f <= 32767 / 2^headroom_bits."""
    assert max_abs > 0
    return int(math.floor(math.log2(I16MAX / max_abs))) - headroom_bits


def quantize(a: np.ndarray, f: int, what: str) -> np.ndarray:
    q = round_away(a * float(2**f))
    hi = float(np.max(np.abs(q)))
    assert hi <= I16MAX, f"{what}: quantized max {hi} exceeds i16 at f={f}"
    return q.astype(np.int16)


# ---------------------------------------------------------------------------
# real LUT construction (base-e exp on the nonpositive domain, etc.)
# ---------------------------------------------------------------------------

def build_real_luts(p: dict) -> dict[str, np.ndarray]:
    u = np.arange(1 << 16, dtype=np.int64)
    x = np.where(u >= 1 << 15, u - (1 << 16), u).astype(np.float64)  # i16 reinterp

    # exp: faithful for x <= 0 (stable softmax input s' = s - c_row), 0 for
    # x > 0 — positive entries are OUTSIDE the proved table (protocol range
    # check); writing 0 keeps the array total.
    ev = round_away((2.0 ** p["exp_out_log2"]) * np.exp(x / 2.0 ** p["exp_in_log2"]))
    exp_t = np.where(x > 0, 0.0, np.minimum(ev, I16MAX)).astype(np.int16)

    # gelu (tanh approximation, GPT-2's), in/out at gelu_scale_log2.
    gs = 2.0 ** p["gelu_scale_log2"]
    xr = x / gs
    g = 0.5 * xr * (1.0 + np.tanh(0.7978845608028654 * (xr + 0.044715 * xr**3)))
    gelu_t = np.clip(round_away(g * gs), -32768, I16MAX).astype(np.int16)

    # ln_rsqrt / softmax_recip: integer-only, same formulas as luts.rs.
    ln_t = np.empty(1 << 16, dtype=np.int16)
    rc_t = np.empty(1 << 16, dtype=np.int16)
    for i in range(1 << 16):
        vb = (i + 1) << p["ln_var_shift"]
        s = math.isqrt(vb)
        ln_t[i] = min(((1 << p["ln_rsqrt_log2"]) + s // 2) // s, I16MAX)
        db = (i << p["recip_den_shift"]) + (1 << (p["recip_den_shift"] - 1))
        rc_t[i] = min(((1 << p["recip_log2"]) + db // 2) // db, I16MAX)
    return {"exp": exp_t, "gelu": gelu_t, "ln_rsqrt": ln_t, "softmax_recip": rc_t}


# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------

def calibrate(fw: dict, tokens: list[int]) -> tuple[dict, dict, dict]:
    """Float ranges -> (weight exponents, LutParams dict, float report)."""
    ranges = gpt2_float.forward_model(tokens, fw)  # per-site max |v|, argmax…
    r = ranges["act_max"]      # dict site -> max |value| (across layers)
    wmax = ranges["weight_max"]  # dict tensor-type -> max |w|

    # Weight fraction bits (per type, global across layers). Bias fits are
    # asserted at quantize time (they live at output scales, see below).
    fw_bits = {k: frac_bits_for(v) for k, v in wmax.items()
               if k in ("c_attn", "attn_proj", "ffn_up", "ffn_down", "wte_wpe",
                        "ln_gain")}

    # Activation fraction bits, 1 headroom bit (the strict no-clamp pass is
    # the ground truth; a fired assert bumps headroom manually, ledger #3).
    HB = 1
    f_ln = frac_bits_for(r["ln_out"], HB)
    f_qkv = frac_bits_for(r["qkv_out"], HB)
    f_s = frac_bits_for(r["scores"], HB)      # scores AFTER /8
    f_av = frac_bits_for(r["av_out"], HB)
    f_ffn = frac_bits_for(max(r["ffn_up_out"], r["gelu_out"]), HB)

    # Residual-stream scale is PER LAYER (ledger 2026-07-06, P5 iteration 2):
    # GPT-2 outlier channels make the late-layer residual ~1e3 while the
    # embedding is ~1e-1 — a single scale zeroes the early layers (measured:
    # argmax broke with f_res=1). Segment l covers x_in(l)/attn_block_out(l)/
    # ffn_block_out(l); monotone non-increasing so the seams are right-shift
    # requants (shift 0 = free).
    f_res = []
    for m in ranges["residual_per_layer"]:  # 12 entries, segment maxima
        f = frac_bits_for(m, HB)
        f_res.append(min(f, f_res[-1]) if f_res else f)
    seam_shifts = [f_res[i] - f_res[i + 1] for i in range(L - 1)]

    f_wte = fw_bits["wte_wpe"]
    f_g = fw_bits["ln_gain"]

    # ln_rsqrt table maps var_int -> 2^R/sqrt(var_int) and is scale-free
    # (dev_int·r_int = xhat·2^R for ANY f_res), so ONE table serves all
    # layers; R and the domain shift just need the min/max var_int across
    # layers. Segment scale enters as 4^f_res[l].
    # 25 LN sites: ln1/ln2 of layer l see segment l; ln_f sees segment 11.
    seg_of_ln = [i // 2 for i in range(24)] + [11]
    var_ints = [v * 4.0 ** f_res[seg_of_ln[i]] for i, v in
                enumerate(ranges["ln_var_min_per_ln"])]
    var_ints_max = [v * 4.0 ** f_res[seg_of_ln[i]] for i, v in
                    enumerate(ranges["ln_var_max_per_ln"])]
    var_int_min = max(min(var_ints), 1.0)
    R = int(math.floor(math.log2(I16MAX * math.sqrt(var_int_min)))) - 1
    var_int_max = max(var_ints_max)
    ln_var_shift = max(1, int(math.ceil(math.log2(var_int_max / (1 << 16)))) + 1)

    exp_out = 14
    # denom = sum of causal-row exp <= T * 2^exp_out (row max term is 2^exp_out
    # exactly since s'=0 is in every row).
    t = len(tokens)
    recip_den_shift = max(1, int(math.ceil(math.log2(t * 2.0**exp_out / (1 << 16)))) + 1)
    recip_log2 = 28  # recip <= 2^28 / 2^14 = 2^14 < i16::MAX (denom >= 2^exp_out)
    f_soft = 14

    p = {
        "ln_var_shift": ln_var_shift,
        "ln_rsqrt_log2": R,
        "shift_ln_norm": R + f_g - f_ln,
        "exp_in_log2": f_s,
        "exp_out_log2": exp_out,
        "recip_den_shift": recip_den_shift,
        "recip_log2": recip_log2,
        "gelu_scale_log2": f_ffn,
        "shift_qkv": f_ln + fw_bits["c_attn"] - f_qkv,
        "shift_scores": 2 * f_qkv + 3 - f_s,  # +3 = the 1/sqrt(64)
        "shift_softmax_norm": recip_log2 - f_soft,
        "shift_av": f_soft + f_qkv - f_av,
        "shift_ffn_up": f_ln + fw_bits["ffn_up"] - f_ffn,
        # residual-facing sites are per layer (lists of 12); shifts > 16 run
        # as chained two-stage requants in the reference/witness (spec P5).
        "shift_attn_proj": [f_av + fw_bits["attn_proj"] - f for f in f_res],
        "shift_ffn_down": [f_ffn + fw_bits["ffn_down"] - f for f in f_res],
        "seam_shifts": seam_shifts,  # 11 entries, may be 0 (free)
        # embed_out -> segment-0 scale; may be NEGATIVE = left shift (exact,
        # linear, no lookup).
        "shift_embed": f_wte - f_res[0],
        "softmax_row_shift": True,
        # fraction bits recorded for the quantizer + report (not part of the
        # Rust LutParams, but frozen alongside).
        "f_res": f_res, "f_ln": f_ln, "f_qkv": f_qkv, "f_s": f_s,
        "f_av": f_av, "f_ffn": f_ffn, "f_soft": f_soft, "f_wte": f_wte,
        "f_ln_gain": f_g,
    }
    for k, v in p.items():
        if k.startswith("shift_") and k != "shift_embed":
            vs = v if isinstance(v, list) else [v]
            assert all(x >= (0 if k == "seam_shifts" else 1) for x in vs), \
                f"{k} = {v} (scale algebra broke)"
    assert all(s >= 0 for s in seam_shifts)
    return fw_bits, p, ranges


def quantize_model(fw: dict, fwb: dict, p: dict) -> dict:
    """Quantize everything; biases live at their op's OUTPUT scale."""
    q = {
        "wte": quantize(fw["wte"], p["f_wte"], "wte"),
        "wpe": quantize(fw["wpe"], p["f_wte"], "wpe"),
        "lnf_gain": quantize(fw["lnf_gain"], p["f_ln_gain"], "lnf_gain"),
        "lnf_bias": quantize(fw["lnf_bias"], p["f_ln"], "lnf_bias"),
        "layers": [],
    }
    for i, lw in enumerate(fw["layers"]):
        f_res_i = p["f_res"][i]  # biases into the residual live at the
        q["layers"].append({     # layer's segment scale
            "c_attn": quantize(lw["c_attn"], fwb["c_attn"], f"l{i}.c_attn"),
            "c_attn_bias": quantize(lw["c_attn_bias"], p["f_qkv"], f"l{i}.c_attn_bias"),
            "attn_proj": quantize(lw["attn_proj"], fwb["attn_proj"], f"l{i}.attn_proj"),
            "attn_proj_bias": quantize(lw["attn_proj_bias"], f_res_i, f"l{i}.attn_proj_bias"),
            "ffn_up": quantize(lw["ffn_up"], fwb["ffn_up"], f"l{i}.ffn_up"),
            "ffn_up_bias": quantize(lw["ffn_up_bias"], p["f_ffn"], f"l{i}.ffn_up_bias"),
            "ffn_down": quantize(lw["ffn_down"], fwb["ffn_down"], f"l{i}.ffn_down"),
            "ffn_down_bias": quantize(lw["ffn_down_bias"], f_res_i, f"l{i}.ffn_down_bias"),
            "ln1_gain": quantize(lw["ln1_gain"], p["f_ln_gain"], f"l{i}.ln1_gain"),
            "ln1_bias": quantize(lw["ln1_bias"], p["f_ln"], f"l{i}.ln1_bias"),
            "ln2_gain": quantize(lw["ln2_gain"], p["f_ln_gain"], f"l{i}.ln2_gain"),
            "ln2_bias": quantize(lw["ln2_bias"], p["f_ln"], f"l{i}.ln2_bias"),
        })
    return q


# ---------------------------------------------------------------------------
# artifact emission
# ---------------------------------------------------------------------------

LAYER_TENSORS = [  # (name, shape) — order is the frozen binary layout
    ("c_attn", (D, 3 * D)), ("c_attn_bias", (3 * D,)),
    ("attn_proj", (D, D)), ("attn_proj_bias", (D,)),
    ("ffn_up", (D, DFF)), ("ffn_up_bias", (DFF,)),
    ("ffn_down", (DFF, D)), ("ffn_down_bias", (D,)),
    ("ln1_gain", (D,)), ("ln1_bias", (D,)),
    ("ln2_gain", (D,)), ("ln2_bias", (D,)),
]


def emit(q: dict, luts: dict, p: dict, fwb: dict, tokens: list[int],
         report: dict, src_sha: str) -> None:
    manifest = []
    parts = []
    off = 0

    def put(name: str, arr: np.ndarray):
        nonlocal off
        a = np.ascontiguousarray(arr, dtype="<i2")
        manifest.append({"name": name, "shape": list(arr.shape), "offset_elems": off})
        parts.append(a.tobytes())
        off += a.size

    for i in range(L):
        for name, shape in LAYER_TENSORS:
            arr = q["layers"][i][name]
            assert tuple(arr.shape) == shape, (name, arr.shape)
            put(f"h.{i}.{name}", arr)
    put("wte", q["wte"])
    put("wpe", q["wpe"])
    put("lnf_gain", q["lnf_gain"])
    put("lnf_bias", q["lnf_bias"])
    for tname in ("exp", "gelu", "ln_rsqrt", "softmax_recip"):
        put(f"lut.{tname}", luts[tname])

    bin_path = WDIR / "gpt2s-q.bin"
    bin_path.write_bytes(b"".join(parts))
    meta = {
        "format": "volta-gpt2-q v1 (raw LE i16, offsets in elements)",
        "source_safetensors_sha256": src_sha,
        "model": {"L": L, "d": D, "h": H, "d_ff": DFF, "vocab": VOCAB, "n_pos": NPOS},
        "prompt_text": GOLDEN_TEXT,
        "prompt_tokens": tokens,
        "lut_params": {k: v for k, v in p.items() if not k.startswith("f_")},
        "frac_bits": {k: v for k, v in p.items() if k.startswith("f_")},
        "weight_frac_bits": fwb,
        "calibration": report,
        "tensors": manifest,
        "total_elems": off,
    }
    (WDIR / "gpt2s-q.json").write_text(json.dumps(meta, indent=1))

    # Flat binary sidecar so the Rust loader needs no JSON parser: magic,
    # i32 LE scalars in PARAMS_ORDER order (shift_embed may be negative),
    # then the i32 arrays in ARRAYS_ORDER order (fixed lengths), then the
    # prompt tokens (u32 count + u32 ids). Tensor offsets are NOT stored —
    # the layout above is fixed and the Rust loader recomputes them from the
    # same constant shape list.
    pb = bytearray(b"VGPT2Q2\0")
    for k in PARAMS_ORDER:
        v = p[k] if k in p else fwb[k[3:]]
        pb += struct.pack("<i", int(v))
    for k, n in ARRAYS_ORDER:
        assert len(p[k]) == n, (k, len(p[k]))
        for v in p[k]:
            pb += struct.pack("<i", int(v))
    pb += struct.pack("<I", len(tokens))
    for t in tokens:
        pb += struct.pack("<I", t)
    (WDIR / "gpt2s-q.params").write_bytes(bytes(pb))
    print(f"wrote {bin_path} ({off*2/1e6:.1f} MB) + gpt2s-q.json + gpt2s-q.params")


# i32 field order of gpt2s-q.params (after the 8-byte magic "VGPT2Q2\0").
# The Rust loader (volta-gpt2/src/model.rs) must read exactly this order.
PARAMS_ORDER = [
    "ln_var_shift", "ln_rsqrt_log2", "shift_ln_norm",
    "exp_in_log2", "exp_out_log2", "recip_den_shift", "recip_log2",
    "gelu_scale_log2",
    "shift_qkv", "shift_scores", "shift_softmax_norm", "shift_av",
    "shift_ffn_up", "shift_embed",
    "f_ln", "f_qkv", "f_s", "f_av", "f_ffn", "f_soft", "f_wte", "f_ln_gain",
    "fw_c_attn", "fw_attn_proj", "fw_ffn_up", "fw_ffn_down",  # from fwb
]
ARRAYS_ORDER = [  # (params key, fixed length)
    ("f_res", 12), ("shift_attn_proj", 12), ("shift_ffn_down", 12),
    ("seam_shifts", 11),
]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--t", type=int, default=100)
    args = ap.parse_args()

    import tiktoken
    enc = tiktoken.get_encoding("gpt2")
    tokens = enc.encode(GOLDEN_TEXT)
    assert len(tokens) >= args.t, f"golden text only has {len(tokens)} tokens"
    tokens = tokens[: args.t]

    print("loading safetensors…")
    src_sha = hashlib.sha256(SAFETENSORS.read_bytes()).hexdigest()
    fw = gpt2_float_weights(load_safetensors(SAFETENSORS))

    print("float calibration pass…")
    fwb, p, ranges = calibrate(fw, tokens)
    float_argmax = ranges["argmax_last"]
    print(f"  float argmax(last) = {float_argmax}"
          f"  ({enc.decode([float_argmax])!r})")
    for k in sorted(p):
        print(f"  {k:22s} {p[k]}")

    print("quantizing + building LUTs…")
    q = quantize_model(fw, fwb, p)
    luts = build_real_luts(p)

    print("fixed-point verification pass (strict: no-clamp asserts live)…")
    model = {"layers": q["layers"], "wte": q["wte"], "wpe": q["wpe"],
             "lnf_gain": q["lnf_gain"], "lnf_bias": q["lnf_bias"]}
    res = gpt2_fixed.forward_model(tokens, model, luts, p, mode="stats")
    sat = {k: v for k, v in res["stats"].items() if v["saturated"]}
    if sat:
        print("SATURATION on the golden prompt — side-table contingency "
              "triggers (ledger 2026-07-06 #3). Offending sites:")
        for k, v in sat.items():
            print(f"  {k}: max |rounded| = {v['max_abs']} (i16 max {I16MAX})")
        return 1

    fx_argmax = int(np.argmax(res["logits"]))
    ok = fx_argmax == float_argmax
    top5_fx = list(np.argsort(res["logits"])[-5:][::-1])
    print(f"  fixed argmax(last) = {fx_argmax} ({enc.decode([fx_argmax])!r})"
          f"  match={ok}")
    print(f"  fixed top5 = {[(int(i), enc.decode([int(i)])) for i in top5_fx]}")

    report = {
        "act_max_float": {k: float(v) for k, v in ranges["act_max"].items()},
        "headroom_bits": {k: round(math.log2(I16MAX / max(v["max_abs"], 1)), 2)
                          for k, v in res["stats"].items()},
        "float_argmax_last": int(float_argmax),
        "fixed_argmax_last": fx_argmax,
        "argmax_match": bool(ok),
        "fixed_top5_last": [int(i) for i in top5_fx],
    }
    emit(q, luts, p, fwb, tokens, report, src_sha)
    if not ok:
        print("WARNING: fixed-point argmax deviates from float on the golden "
              "prompt — fidelity review needed before P5 closes (ledger).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

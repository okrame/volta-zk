"""Dump the P5 golden reference for the Rust bit-exactness test.

Loads the frozen artifact `benchmarks/weights/gpt2s-q.{bin,json,params}`
(NOT the float weights — this exercises exactly the bytes Rust will read),
runs the numpy fixed-point forward in strict mode, and writes
`benchmarks/weights/golden-p5.bin`:

  magic "VGOLD1\\0\\0"
  u32 t, u32 argmax_last
  i64 logits[50257]
  i64 checksum(embed_out), i64 checksum(final_ln_out)
  i64 checksum(ffn_block_out[l]) for l in 0..12   (sum of i16 values)
  i64 checksum(row_shift[l])     for l in 0..12

Run:  .venv/bin/python scripts/dump_golden.py [--t 100]
"""

import argparse
import json
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
import gpt2_fixed  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
WDIR = REPO / "benchmarks" / "weights"
L, D, DFF, VOCAB = 12, 768, 3072, 50257


def load_artifact():
    meta = json.loads((WDIR / "gpt2s-q.json").read_text())
    blob = np.fromfile(WDIR / "gpt2s-q.bin", dtype="<i2")
    tensors = {}
    for m in meta["tensors"]:
        n = int(np.prod(m["shape"]))
        tensors[m["name"]] = blob[m["offset_elems"] : m["offset_elems"] + n].reshape(m["shape"])
    p = dict(meta["lut_params"])
    layers = []
    for i in range(L):
        layers.append({k: tensors[f"h.{i}.{k}"] for k in (
            "c_attn", "c_attn_bias", "attn_proj", "attn_proj_bias",
            "ffn_up", "ffn_up_bias", "ffn_down", "ffn_down_bias",
            "ln1_gain", "ln1_bias", "ln2_gain", "ln2_bias")})
    model = {
        "layers": layers,
        "wte": tensors["wte"], "wpe": tensors["wpe"],
        "lnf_gain": tensors["lnf_gain"], "lnf_bias": tensors["lnf_bias"],
    }
    luts = {k: tensors[f"lut.{k}"] for k in ("exp", "gelu", "ln_rsqrt", "softmax_recip")}
    return model, luts, p, meta["prompt_tokens"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--t", type=int, default=100)
    args = ap.parse_args()

    model, luts, p, tokens = load_artifact()
    tokens = tokens[: args.t]
    res = gpt2_fixed.forward_model(tokens, model, luts, p, mode="strict")
    logits = np.asarray(res["logits"], dtype=np.int64)
    assert logits.shape == (VOCAB,)

    out = bytearray(b"VGOLD1\0\0")
    out += struct.pack("<II", args.t, int(np.argmax(logits)))
    out += logits.astype("<i8").tobytes()
    out += struct.pack("<q", int(np.asarray(res["embed_out"], dtype=np.int64).sum()))
    out += struct.pack("<q", int(np.asarray(res["final_ln_out"], dtype=np.int64).sum()))
    for lr in res["layers"]:
        out += struct.pack("<q", int(np.asarray(lr["ffn_block_out"], dtype=np.int64).sum()))
    for lr in res["layers"]:
        out += struct.pack("<q", int(np.asarray(lr["row_shift"], dtype=np.int64).sum()))
    (WDIR / "golden-p5.bin").write_bytes(bytes(out))
    print(f"wrote golden-p5.bin (t={args.t}, argmax={int(np.argmax(logits))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

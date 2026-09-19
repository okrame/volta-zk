#!/usr/bin/env python3
"""Independent OpenSSL/SHAKE KAT for C71 Seed6 AES-COPE."""

import hashlib
import json
import subprocess

P = (1 << 64) - (1 << 32) + 1
DOMAIN = b"C71S6/COPE/fixed-run/leaf/v1/"
SEED = bytes([0x42]) * 32
CONTEXT = b"C71S6-kat"
I = 17
J = 1


def aes256_ecb(key: bytes, blocks: bytes) -> bytes:
    run = subprocess.run(
        ["openssl", "enc", "-aes-256-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
        input=blocks,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert len(run.stdout) == len(blocks)
    return run.stdout


def kat(rows: int, row: int) -> dict:
    height = (rows - 1).bit_length()
    leaf = SEED
    trace = []
    challenge = b"".join(x.to_bytes(16, "little") for x in range(4))
    for depth in reversed(range(height)):
        encrypted = aes256_ecb(leaf, challenge)
        child = 2 * ((row >> depth) & 1)
        leaf = encrypted[16 * child : 16 * (child + 2)]
        trace.append({"depth": depth, "child": child, "leaf": leaf.hex()})
    preimage = (
        DOMAIN
        + CONTEXT
        + I.to_bytes(4, "little")
        + bytes([J])
        + row.to_bytes(8, "little")
        + leaf
    )
    candidates_raw = hashlib.shake_256(preimage).digest(8 * 8)
    candidates = [
        int.from_bytes(candidates_raw[8 * k : 8 * (k + 1)], "little") for k in range(8)
    ]
    accepted = [x for x in candidates if x < P]
    if not accepted:
        raise RuntimeError("bounded Goldilocks sampler exhausted")
    return {
        "rows": rows,
        "height": height,
        "i": I,
        "j": J,
        "row": row,
        "leaf": leaf.hex(),
        "trace": trace,
        "candidates_u64": candidates,
        "output_u64": accepted[0],
        "output_hex_le": accepted[0].to_bytes(8, "little").hex(),
    }


if __name__ == "__main__":
    vectors = [kat(rows, row) for rows in (7, 9) for row in (0, rows - 1)]
    print(json.dumps({
        "openssl": subprocess.check_output(["openssl", "version"], text=True).strip(),
        "domain_ascii": DOMAIN.decode(),
        "seed_hex": SEED.hex(),
        "context_ascii": CONTEXT.decode(),
        "vectors": vectors,
    }, indent=2))

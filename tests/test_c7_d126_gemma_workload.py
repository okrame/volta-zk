from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD = ROOT / "manifests" / "c7-d126-gemma31b-workload-v1.json"


def test_frozen_gemma_workload_and_padding_are_self_consistent() -> None:
    row = json.loads(WORKLOAD.read_text(encoding="utf-8"))
    prompt = row["prompt"]
    lengths = row["lengths"]
    padding = row["padding"]
    token_ids = prompt["token_ids"]

    workload_digest = hashlib.sha256(WORKLOAD.read_bytes()).hexdigest()
    assert workload_digest == "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b"
    assert WORKLOAD.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{workload_digest}  {WORKLOAD.name}\n"
    )
    assert row["schema"] == "volta-c7-d126-gemma31b-workload-v1"
    assert row["model"] == "google/gemma-4-31B"
    assert row["tokenizer"] == {
        "file": "tokenizer.json",
        "bytes": 32_170_070,
        "sha256": "12bac982b793c44b03d52a250a9f0d0b666813da566b910c24a6da0695fd11e6",
        "reference_engine": "huggingface-tokenizers-0.22.1",
        "add_special_tokens": True,
    }
    assert hashlib.sha256(prompt["text"].encode()).hexdigest() == prompt["text_utf8_sha256"]
    assert len(token_ids) == lengths["prompt_tokens"] == 100
    assert token_ids[0] == 2
    assert all(type(token_id) is int and 0 <= token_id < 262_144 for token_id in token_ids)
    raw_ids = b"".join(struct.pack("<I", token_id) for token_id in token_ids)
    assert hashlib.sha256(raw_ids).hexdigest() == prompt["token_ids_u32le_sha256"]

    assert row["generation"] == {
        "decode_tokens": 50,
        "selection": "greedy-argmax-lowest-token-id-on-tie",
        "early_stop_on_eos": False,
        "sampling_randomness": "none",
        "output_token_ids_status": "blocked-until-GemmaQuantV1-bit-exact-forward",
    }
    assert lengths == {
        "prompt_tokens": 100,
        "decode_tokens": 50,
        "live_tokens": 150,
        "context_capacity_tokens": 4096,
        "batch_size": 1,
        "max_concurrent_gpu_responses": 1,
    }
    assert lengths["prompt_tokens"] + lengths["decode_tokens"] == lengths["live_tokens"]
    assert lengths["live_tokens"] <= lengths["context_capacity_tokens"]
    assert padding == {
        "persistent_tokens": 0,
        "packed_source_bytes": 0,
        "certificate_bytes": 0,
        "transcript_bytes": 0,
        "kv_capacity_tokens": 4096,
        "device_lane_padding": "temporary-only-must-be-emitted-and-counted",
    }
    assert row["credit"] == {
        "prompt_token_ids": True,
        "decode_token_ids": False,
        "bit_exact_witness": False,
        "runtime_enforcement": False,
    }
